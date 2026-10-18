using System.Text;
using Siegel.Modell;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge;

/// <summary>
/// CSV-Import (SPEC §8 „CSV-Details“, §18), gleich wie Sources/SiegelCore/Werkzeuge/CSV.swift: Apple Passwörter,
/// Chrome, Firefox, Bitwarden. Grösse prüfen → BOM entfernen → RFC 4180 lesen → Format an der Kopfzeile erkennen
/// (ohne Leerraum am Rand, Gross/Klein und Reihenfolge egal) → abbilden → Grenzen prüfen; jeder Fehler bricht ab.
/// Erkennung (erste passende): Bitwarden (type, name, login_uri, login_username, login_password), Apple (title, url,
/// username, password), Chrome (name, url, username, password), Firefox (url, username, password + guid/httprealm/
/// formactionorigin/timecreated/timelastused/timepasswordchanged).
/// 2FA (Apple OTPAuth, Bitwarden login_totp) kommt nach <see cref="VaultEntry.Totp"/>, wenn <see cref="Totp.Parse"/> ihn
/// annimmt, sonst als „Spalte: Wert“ in die Notizen; ebenso jede andere nicht leere Spalte. Aus Titel, Benutzer, URL
/// werden Steuer- und Bidi-Zeichen entfernt; Passwörter bleiben byte-genau. Feste Fehlercodes in <see cref="ReasonCodes"/>
/// (<see cref="SiegelErrorCode.CsvInvalid"/>, Zeile in <see cref="SiegelException.Line"/>, 0 = ganze Datei).
/// </summary>
public static class CsvImport
{
    internal const int MaximumFileBytes = 16 * 1024 * 1024;
    internal const int MaximumRows = 20_000;
    internal const int MaximumTitleBytes = 2 * 1024;
    internal const int MaximumUsernameBytes = 2 * 1024;
    internal const int MaximumUrlBytes = 2 * 1024;
    internal const int MaximumPasswordBytes = 4 * 1024;
    internal const int MaximumNotesBytes = 256 * 1024;

    /// <summary>Längere Spaltennamen (UTF-8, ohne Leerraum am Rand) haben keine Rolle (v4.8, Befund robust-7): sie werden
    /// weder klein geschrieben noch normalisiert noch auf Doppel geprüft und kommen nur als „Spalte: Wert“ in die Notizen.
    /// Das kanonische Vergleichen langer Folgen von Kombinationszeichen wäre in beiden Kernen quadratisch.</summary>
    internal const int MaximumHeaderLabelBytes = 256;

    /// <summary>Vollständige Liste der reason-Codes.</summary>
    internal static readonly string[] ReasonCodes =
    [
        "csv.fileTooLarge", "csv.empty", "csv.encoding", "csv.quote", "csv.unterminatedQuote",
        "csv.header.unknown", "csv.header.duplicate", "csv.fieldCount", "csv.tooManyRows",
        "csv.field.title", "csv.field.username", "csv.field.url", "csv.field.password", "csv.field.notes",
    ];

    public static CsvImportResult Parse(byte[] data)
    {
        data ??= [];
        if (data.Length > MaximumFileBytes) { throw CsvReader.Invalid(0, "csv.fileTooLarge"); }
        var now = DateTimeOffset.UtcNow;
        var hasBom = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF;
        var reader = new CsvReader(data, hasBom ? 3 : 0);
        try
        {
            if (reader.Next() is not { } header) { throw CsvReader.Invalid(0, "csv.empty"); }
            var layout = new Layout(header);
            // Befund #45: Datensätze nur so breit wie die Kopfzeile lesen (Abbruch während des Lesens)
            reader.MaxFields = layout.Columns.Count;
            reader.TooManyFieldsReason = "csv.fieldCount";

            var entries = new List<VaultEntry>();
            var report = new ImportReport();
            var rows = 0;
            while (reader.Next() is { } record)
            {
                rows++;
                if (rows > MaximumRows) { throw CsvReader.Invalid(record.Line, "csv.tooManyRows"); }
                if (record.Fields.Count != layout.Columns.Count) { throw CsvReader.Invalid(record.Line, "csv.fieldCount"); }
                if (layout.Map(record, now) is not { } mapped) { continue; }
                entries.Add(mapped.Entry);
                if (mapped.HasOtp) { report.WithOtpSecret++; }
                if (mapped.MovedToNotes) { report.MovedToNotes++; }
                if (CsvText.ContainsControlOrBidi(mapped.Entry.Password)) { report.PasswordsWithControlCharacters++; }
                if (mapped.Entry.Password.StartsWith('\'')) { report.ApostrophePrefixed++; }
            }
            report.Added = entries.Count;
            return new CsvImportResult(layout.Format, entries, report);
        }
        finally
        {
            reader.Wipe();
        }
    }

    internal enum Role { Title, Url, Username, Password, Notes, Otp, Created, Modified, Type, Extra }

    internal readonly record struct Column(string Label, Role Role);

    internal sealed record Mapped(VaultEntry Entry, bool HasOtp, bool MovedToNotes);

    internal sealed class Layout
    {
        internal Layout(CsvReader.Record header)
        {
            var labels = new List<string>();
            var normalized = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var offset = 0; offset < header.Fields.Count; offset++)
            {
                var label = SwiftText.Trimmen(header.Fields[offset], SwiftText.IstLeerzeichen);
                if (Encoding.UTF8.GetByteCount(label) > MaximumHeaderLabelBytes)
                {
                    // Zusatzspalte ohne Rolle (leerer Schlüssel passt zu keiner Rolle und zählt nicht als Doppel)
                    labels.Add(label);
                    normalized.Add("");
                    continue;
                }
                // Swift-Set<String> vergleicht kanonisch → Schlüssel in NFC
                var key = SwiftText.Nfc(SwiftText.Klein(label));
                if (key.Length > 0 && !seen.Add(key))
                {
                    throw CsvReader.Invalid(header.Line, "csv.header.duplicate");
                }
                labels.Add(key.Length == 0 ? $"Spalte {offset + 1}" : label);
                normalized.Add(key);
            }
            if (Detect(seen) is not { } erkannt) { throw CsvReader.Invalid(header.Line, "csv.header.unknown"); }
            Format = erkannt.Format;
            var columns = new List<Column>();
            for (var i = 0; i < labels.Count; i++)
            {
                var role = Role.Extra;
                foreach (var (name, mappedRole) in erkannt.Roles)
                {
                    if (name == normalized[i]) { role = mappedRole; }
                }
                columns.Add(new Column(labels[i], role));
            }
            Columns = columns;
        }

        internal CsvFormat Format { get; }
        internal List<Column> Columns { get; }

        private static readonly string[] FirefoxMarkers =
            ["guid", "httprealm", "formactionorigin", "timecreated", "timelastused", "timepasswordchanged"];

        /// <summary>Format und Rollen-Tabelle (normalisierter Spaltenname → Rolle).</summary>
        internal static (CsvFormat Format, (string Name, Role Role)[] Roles)? Detect(HashSet<string> names)
        {
            bool Alle(params string[] n) => n.All(names.Contains);
            if (Alle("type", "name", "login_uri", "login_username", "login_password"))
            {
                return (CsvFormat.Bitwarden, [("name", Role.Title), ("notes", Role.Notes), ("login_uri", Role.Url),
                    ("login_username", Role.Username), ("login_password", Role.Password), ("login_totp", Role.Otp),
                    ("type", Role.Type)]);
            }
            if (Alle("title", "url", "username", "password"))
            {
                return (CsvFormat.ApplePasswords, [("title", Role.Title), ("url", Role.Url), ("username", Role.Username),
                    ("password", Role.Password), ("notes", Role.Notes), ("otpauth", Role.Otp)]);
            }
            if (Alle("name", "url", "username", "password"))
            {
                return (CsvFormat.Chrome, [("name", Role.Title), ("url", Role.Url), ("username", Role.Username),
                    ("password", Role.Password), ("note", Role.Notes)]);
            }
            if (Alle("url", "username", "password") && FirefoxMarkers.Any(names.Contains))
            {
                return (CsvFormat.Firefox, [("url", Role.Url), ("username", Role.Username), ("password", Role.Password),
                    ("timecreated", Role.Created), ("timepasswordchanged", Role.Modified)]);
            }
            return null;
        }

        private static string Lower(string text) => SwiftText.Klein(SwiftText.Trimmen(text, SwiftText.IstLeerzeichen));

        /// <summary>Bildet einen Datensatz ab; null = Datensatz ohne Inhalt (überspringen).</summary>
        internal Mapped? Map(CsvReader.Record record, DateTimeOffset now)
        {
            var line = record.Line;

            // Bitwarden: Typ vorab bestimmen
            var isNote = false;
            for (var i = 0; i < Columns.Count; i++)
            {
                if (Columns[i].Role == Role.Type) { isNote = Lower(record.Fields[i]) == "note"; }
            }

            string title = "", url = "", username = "", password = "", notes = "", totp = "";
            DateTimeOffset? created = null;
            DateTimeOffset? modified = null;
            var extraLines = new List<string>();
            var hasOtp = false;
            var hadOtpValue = false;
            var movedToNotes = false;

            void AddExtra(string label, string value)
            {
                extraLines.Add(label + ": " + value);
                movedToNotes = true;
            }

            for (var i = 0; i < Columns.Count; i++)
            {
                var column = Columns[i];
                var value = record.Fields[i];
                switch (column.Role)
                {
                    case Role.Title:
                        title = value;
                        break;
                    case Role.Notes:
                        notes = value;
                        break;
                    case Role.Url or Role.Username or Role.Password:
                        if (isNote)
                        {
                            if (value.Length > 0) { AddExtra(column.Label, value); }
                        }
                        else if (column.Role == Role.Url) { url = value; }
                        else if (column.Role == Role.Username) { username = value; }
                        else { password = value; }
                        break;
                    case Role.Otp:
                        if (value.Length == 0) { break; }
                        hadOtpValue = true;
                        var trimmed = SwiftText.Trimmen(value, SwiftText.IstLeerzeichenOderUmbruch);
                        if (!isNote && Totp.IsValid(trimmed))
                        {
                            totp = trimmed;
                            hasOtp = true;
                        }
                        else
                        {
                            AddExtra(column.Label, value);
                        }
                        break;
                    case Role.Created or Role.Modified:
                        var zeit = SwiftText.Trimmen(value, SwiftText.IstLeerzeichen);
                        if (zeit.Length == 0) { break; }
                        if (CsvText.DateFromMilliseconds(zeit) is { } date)
                        {
                            if (column.Role == Role.Created) { created = date; } else { modified = date; }
                        }
                        else
                        {
                            AddExtra(column.Label, value);
                        }
                        break;
                    case Role.Type:
                        var kind = Lower(value);
                        if (kind.Length > 0 && kind != "login" && kind != "note") { AddExtra(column.Label, value); }
                        break;
                    default:
                        if (value.Length > 0) { AddExtra(column.Label, value); }
                        break;
                }
            }

            title = CsvText.StrippingControlAndBidi(title);
            username = CsvText.StrippingControlAndBidi(username);
            url = CsvText.StrippingControlAndBidi(url);

            // Ohne Inhalt (nur Metadaten wie reprompt/guid oder ganz leer) → überspringen
            if (title.Length == 0 && username.Length == 0 && url.Length == 0 && password.Length == 0 && notes.Length == 0
                && !hadOtpValue)
            {
                return null;
            }
            if (extraLines.Count > 0)
            {
                var extra = string.Join("\n", extraLines);
                notes = notes.Length == 0 ? extra : notes + "\n\n" + extra;
            }
            if (title.Length == 0 && url.Length > 0)
            {
                title = CsvText.StrippingControlAndBidi(CsvText.TitleFromUrl(url));
            }

            if (Encoding.UTF8.GetByteCount(title) > MaximumTitleBytes) { throw CsvReader.Invalid(line, "csv.field.title"); }
            if (Encoding.UTF8.GetByteCount(username) > MaximumUsernameBytes) { throw CsvReader.Invalid(line, "csv.field.username"); }
            if (Encoding.UTF8.GetByteCount(url) > MaximumUrlBytes) { throw CsvReader.Invalid(line, "csv.field.url"); }
            if (Encoding.UTF8.GetByteCount(password) > MaximumPasswordBytes) { throw CsvReader.Invalid(line, "csv.field.password"); }
            if (Encoding.UTF8.GetByteCount(notes) > MaximumNotesBytes) { throw CsvReader.Invalid(line, "csv.field.notes"); }

            var createdDate = created ?? modified ?? now;
            var modifiedDate = modified ?? created ?? now;
            if (modifiedDate < createdDate) { modifiedDate = createdDate; }
            var entry = new VaultEntry
            {
                Title = title,
                Username = username,
                Password = password,
                Url = url,
                Notes = notes,
                Totp = totp,
                Created = createdDate,
                Modified = modifiedDate,
            };
            return new Mapped(entry, hasOtp, movedToNotes);
        }
    }
}
