using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Siegel.Modell;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge;

public enum TotpAlgorithm { Sha1, Sha256, Sha512 }

/// <summary>
/// Parameter eines 2FA-Geheimnisses (SPEC §18). Das Geheimnis liegt nur in <c>sodium_malloc</c>-Speicher
/// (<see cref="Geheimpuffer"/>) und verlässt das Objekt nie als Kopie: Wie <c>TOTP.Parameters</c> auf dem Mac gibt es nach
/// aussen nur <see cref="SecretByteCount"/> (keine öffentliche Geheimnis-Eigenschaft, die Debugger, Bindungen, Logger oder
/// Serialisierer auswerten könnten, Befund hygiene-4). Intern nur über <see cref="LeiheSchluessel"/>; ein paralleles
/// <see cref="Dispose"/> wirkt erst nach der laufenden Rechnung (Befund hygiene-1).
/// Der Konstruktor prüft alle Grenzen wie auf dem Mac (Geheimnis 10–128 Byte, Ziffern 6/8, Periode 15–120,
/// Aussteller/Konto ohne Steuer- und Richtungszeichen höchstens 256 UTF-8-Bytes) und wirft sonst
/// <see cref="SiegelErrorCode.TotpInvalid"/> mit festem Code. Gleichheit vergleicht das Geheimnis in konstanter Zeit.
/// </summary>
public sealed record TotpParameters : IDisposable
{
    private readonly Geheimpuffer key;

    public TotpParameters(byte[] Secret, TotpAlgorithm Algorithm = TotpAlgorithm.Sha1, int Digits = 6,
        int Period = 30, string Issuer = "", string Account = "")
        : this(Kopieren(Secret), Algorithm, Digits, Period, Issuer, Account)
    {
    }

    /// <summary>Übernimmt <paramref name="key"/> (wird bei einem Fehler freigegeben).</summary>
    internal TotpParameters(Geheimpuffer key, TotpAlgorithm algorithm, int digits, int period, string issuer, string account)
    {
        try
        {
            if (key.Length < Totp.MinimumSecretBytes || key.Length > Totp.MaximumSecretBytes) { throw Totp.Invalid("totp.secret.length"); }
            if (digits is not (6 or 8)) { throw Totp.Invalid("totp.digits"); }
            if (period is < Totp.MinimumPeriod or > Totp.MaximumPeriod) { throw Totp.Invalid("totp.period"); }
            var cleanIssuer = CsvText.StrippingControlAndBidi(issuer ?? "");
            var cleanAccount = CsvText.StrippingControlAndBidi(account ?? "");
            if (Encoding.UTF8.GetByteCount(cleanIssuer) > Totp.MaximumLabelPartBytes
                || Encoding.UTF8.GetByteCount(cleanAccount) > Totp.MaximumLabelPartBytes)
            {
                throw Totp.Invalid("totp.label");
            }
            this.key = key;
            Algorithm = algorithm;
            Digits = digits;
            Period = period;
            Issuer = cleanIssuer;
            Account = cleanAccount;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private TotpParameters(TotpParameters original)
    {
        using (var l = original.key.Lesen()) { key = Geheimpuffer.Kopie(l.Span); }
        Algorithm = original.Algorithm;
        Digits = original.Digits;
        Period = original.Period;
        Issuer = original.Issuer;
        Account = original.Account;
    }

    private static Geheimpuffer Kopieren(byte[] secret)
    {
        if (secret is null || secret.Length < Totp.MinimumSecretBytes || secret.Length > Totp.MaximumSecretBytes)
        {
            throw Totp.Invalid("totp.secret.length");
        }
        return Geheimpuffer.Kopie(secret);
    }

    public TotpAlgorithm Algorithm { get; }
    /// <summary>6 oder 8.</summary>
    public int Digits { get; }
    /// <summary>Sekunden, 15–120.</summary>
    public int Period { get; }
    /// <summary>Aussteller (z. B. „GitHub“), leer wenn unbekannt.</summary>
    public string Issuer { get; }
    /// <summary>Konto (z. B. „anna@example.ch“), leer wenn unbekannt.</summary>
    public string Account { get; }

    /// <summary>Länge des Geheimnisses in Byte (zum Anzeigen, ohne es herauszugeben).</summary>
    public int SecretByteCount => key.Length;

    /// <summary>Lesende Leihe auf das Geheimnis, immer mit <c>using</c> und über die ganze Rechnung gehalten.</summary>
    internal Geheimpuffer.Leihe LeiheSchluessel() => key.Lesen();

    public bool Equals(TotpParameters? other) =>
        other is not null && Algorithm == other.Algorithm && Digits == other.Digits && Period == other.Period
        && string.Equals(Issuer, other.Issuer, StringComparison.Ordinal)
        && string.Equals(Account, other.Account, StringComparison.Ordinal)
        && key.KonstantGleich(other.key);

    public override int GetHashCode() => HashCode.Combine(Algorithm, Digits, Period, Issuer, Account);

    public override string ToString() => $"TotpParameters({Totp.UriName(Algorithm)}, {Digits}, {Period}s, redacted)";

    public void Dispose() => key.Dispose();
}

/// <summary>
/// 2FA-Codes nach RFC 6238 (TOTP) auf Basis von RFC 4226 (HOTP), SPEC §18, gleich wie
/// Sources/SiegelCore/Werkzeuge/TOTP.swift: <c>otpauth://totp/…</c>-URI (strenger Parser mit Grenzen) oder reines
/// Base32-Geheimnis (RFC 4648, tolerant: Leerraum, Kleinbuchstaben, fehlendes Padding). Fehler
/// <see cref="SiegelErrorCode.TotpInvalid"/> mit den 12 festen Codes aus <see cref="ReasonCodes"/>.
/// Grenzen: Eingabe ≤ 2048 UTF-8-Bytes, ≤ 32 Parameter, Geheimnis 10–128 Byte, Aussteller/Konto ≤ 256 Bytes.
/// </summary>
public static class Totp
{
    internal const int MaximumInputBytes = 2048;
    internal const int MaximumParameters = 32;
    internal const int MinimumSecretBytes = 10;
    internal const int MaximumSecretBytes = 128;
    internal const int MaximumLabelPartBytes = 256;
    internal const int MinimumPeriod = 15;
    internal const int MaximumPeriod = 120;

    /// <summary>Alle Codes von <see cref="SiegelErrorCode.TotpInvalid"/> (Referenz für Tests und Oberfläche).</summary>
    internal static readonly string[] ReasonCodes =
    [
        "totp.empty", "totp.tooLong", "totp.uri", "totp.type", "totp.secret.missing", "totp.base32",
        "totp.secret.length", "totp.algorithm", "totp.digits", "totp.period", "totp.duplicate", "totp.label",
    ];

    internal static SiegelException Invalid(string code) => new(SiegelErrorCode.TotpInvalid, code);

    internal static string UriName(TotpAlgorithm algorithm) => algorithm switch
    {
        TotpAlgorithm.Sha256 => "SHA256",
        TotpAlgorithm.Sha512 => "SHA512",
        _ => "SHA1",
    };

    /// <summary><c>otpauth://totp/…</c>-URI oder reines Base32-Geheimnis → Parameter. Leerraum am Rand wird ignoriert.</summary>
    public static TotpParameters Parse(string uriOrSecret)
    {
        var bytes = Encoding.UTF8.GetBytes(uriOrSecret ?? "");
        try
        {
            if (bytes.Length > MaximumInputBytes) { throw Invalid("totp.tooLong"); }
            var start = 0;
            var end = bytes.Length;
            while (start < end && IsWhitespace(bytes[start])) { start++; }
            while (end > start && IsWhitespace(bytes[end - 1])) { end--; }
            if (start >= end) { throw Invalid("totp.empty"); }
            var trimmed = bytes.AsSpan(start, end - start);

            var prefix = "otpauth://"u8;
            if (trimmed.Length >= prefix.Length && StartsWithLowerAscii(trimmed, prefix))
            {
                return ParseUri(trimmed[prefix.Length..]);
            }
            // Andere URI-Schemata (z. B. otpauth-migration://) sind kein Geheimnis.
            if (trimmed.IndexOf("://"u8) >= 0) { throw Invalid("totp.uri"); }
            return new TotpParameters(DecodeBase32(trimmed), TotpAlgorithm.Sha1, 6, 30, "", "");
        }
        finally
        {
            Sodium.Wipe(bytes);
        }
    }

    /// <summary>Wie <see cref="Parse"/>, aber ohne Ausnahme (true = gültig). Das Ergebnis wird sofort freigegeben.</summary>
    internal static bool IsValid(string uriOrSecret)
    {
        try
        {
            using var p = Parse(uriOrSecret);
            return true;
        }
        catch (SiegelException)
        {
            return false;
        }
    }

    /// <summary>Code zum Zeitpunkt <paramref name="at"/> und verbleibende Sekunden der laufenden Periode (1…Period).
    /// Zeiten vor 1970 gelten als 1970 (Zähler 0).</summary>
    public static (string Code, int Remaining) Code(TotpParameters p, DateTimeOffset at)
    {
        if (p is null) { throw Invalid("totp.empty"); }
        var seconds = Math.Max(0L, Math.Min(at.ToUnixTimeSeconds(), 9_000_000_000_000_000L));
        long period = p.Period;
        var counter = (ulong)(seconds / period);
        var remaining = (int)(period - seconds % period);
        // Die Leihe hält den sodium-Speicher über die ganze HMAC-Rechnung (paralleles Dispose → erst danach frei).
        using var schluessel = p.LeiheSchluessel();
        return (Hotp(schluessel.Span, counter, p.Digits, p.Algorithm), remaining);
    }

    /// <summary>HOTP-Wert: HMAC über den Zähler (8 Byte, Big-Endian), dynamische Kürzung, Stellen mit Nullen.</summary>
    internal static string Hotp(ReadOnlySpan<byte> key, ulong counter, int digits, TotpAlgorithm algorithm)
    {
        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(message, counter);
        Span<byte> mac = stackalloc byte[64];
        try
        {
            var length = algorithm switch
            {
                TotpAlgorithm.Sha256 => HMACSHA256.HashData(key, message, mac),
                TotpAlgorithm.Sha512 => HMACSHA512.HashData(key, message, mac),
                // RFC 6238/4226 schreiben HMAC-SHA1 vor (Standard fast aller Dienste); für HMAC ist SHA-1 nicht gebrochen.
#pragma warning disable CA5350
                _ => HMACSHA1.HashData(key, message, mac),
#pragma warning restore CA5350
            };
            if (length == 0) { return new string('0', digits); }
            var offset = mac[length - 1] & 0x0f;
            var binary = ((uint)(mac[offset] & 0x7f) << 24) | ((uint)mac[offset + 1] << 16)
                | ((uint)mac[offset + 2] << 8) | mac[offset + 3];
            uint modulus = 1;
            for (var i = 0; i < digits; i++) { modulus = unchecked(modulus * 10); }
            var value = (binary % modulus).ToString(System.Globalization.CultureInfo.InvariantCulture);
            return new string('0', Math.Max(0, digits - value.Length)) + value;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mac);
        }
    }

    // Parser

    /// <summary>Rest nach <c>otpauth://</c>: <c>typ/label?parameter</c>. Arbeitet auf dem Puffer des Aufrufers.</summary>
    private static TotpParameters ParseUri(ReadOnlySpan<byte> rest)
    {
        if (rest.IndexOf((byte)'#') >= 0) { throw Invalid("totp.uri"); }

        // Typ
        var index = 0;
        while (index < rest.Length && rest[index] != '/' && rest[index] != '?') { index++; }
        if (!EqualsLowerAscii(rest[..index], "totp"u8)) { throw Invalid("totp.type"); }

        // Label
        var labelStart = index;
        var labelEnd = index;
        if (index < rest.Length && rest[index] == '/')
        {
            index++;
            labelStart = index;
            while (index < rest.Length && rest[index] != '?') { index++; }
            labelEnd = index;
        }
        var label = DecodeText(rest[labelStart..labelEnd]);

        // Parameter (das Geheimnis wird nur als Bereich gemerkt und erst unten in sodium-Speicher dekodiert)
        var secretStart = -1;
        var secretEnd = -1;
        string? issuerParameter = null;
        TotpAlgorithm? algorithm = null;
        int? digits = null;
        int? period = null;
        if (index < rest.Length && rest[index] == '?')
        {
            var queryStart = index + 1;
            var items = new List<(int Start, int End)>();
            var itemStart = queryStart;
            for (var k = queryStart; k <= rest.Length; k++)
            {
                if (k == rest.Length || rest[k] == '&')
                {
                    if (k > itemStart) { items.Add((itemStart, k)); }
                    itemStart = k + 1;
                }
            }
            if (items.Count > MaximumParameters) { throw Invalid("totp.uri"); }
            foreach (var (s, e) in items)
            {
                var item = rest[s..e];
                var equals = item.IndexOf((byte)'=');
                if (equals < 0) { throw Invalid("totp.uri"); }
                var name = PercentDecode(item[..equals]);
                for (var k = 0; k < name.Length; k++) { name[k] = LowerAscii(name[k]); }
                var value = item[(equals + 1)..];
                var nameText = Encoding.Latin1.GetString(name);
                switch (nameText)
                {
                    case "secret":
                        if (secretStart >= 0) { throw Invalid("totp.duplicate"); }
                        secretStart = s + equals + 1;
                        secretEnd = e;
                        break;
                    case "issuer":
                        if (issuerParameter is not null) { throw Invalid("totp.duplicate"); }
                        issuerParameter = DecodeText(value);
                        break;
                    case "algorithm":
                        if (algorithm is not null) { throw Invalid("totp.duplicate"); }
                        algorithm = SwiftText.Gross(DecodeText(value)) switch
                        {
                            "SHA1" => TotpAlgorithm.Sha1,
                            "SHA256" => TotpAlgorithm.Sha256,
                            "SHA512" => TotpAlgorithm.Sha512,
                            _ => throw Invalid("totp.algorithm"),
                        };
                        break;
                    case "digits":
                        if (digits is not null) { throw Invalid("totp.duplicate"); }
                        digits = SmallNumber(PercentDecode(value), "totp.digits");
                        break;
                    case "period":
                        if (period is not null) { throw Invalid("totp.duplicate"); }
                        period = SmallNumber(PercentDecode(value), "totp.period");
                        break;
                    default:
                        break;                                  // image, color, lock … werden ignoriert
                }
            }
        }

        if (secretStart < 0 || secretEnd <= secretStart) { throw Invalid("totp.secret.missing"); }
        var key = DecodePercentEncodedBase32(rest[secretStart..secretEnd]);

        // Label: "Aussteller:Konto" oder nur "Konto" (Leerzeichen um das Konto sind erlaubt).
        var issuer = issuerParameter ?? "";
        var account = label;
        var colon = ErstesZeichen(label, ":");
        if (colon >= 0)
        {
            var labelIssuer = label[..colon];
            account = label[(colon + 1)..];
            if (issuerParameter is null) { issuer = labelIssuer; }
        }
        account = SwiftText.Trimmen(account, SwiftText.IstLeerzeichen);
        issuer = SwiftText.Trimmen(issuer, SwiftText.IstLeerzeichen);

        return new TotpParameters(key, algorithm ?? TotpAlgorithm.Sha1, digits ?? 6, period ?? 30, issuer, account);
    }

    /// <summary>UTF-16-Anfang des ersten Character, der genau <paramref name="zeichen"/> ist (Swift firstIndex(of:)).</summary>
    private static int ErstesZeichen(string text, string zeichen)
    {
        var grenzen = Graphemzerlegung.Grenzen(text);
        for (var i = 0; i + 1 < grenzen.Length; i++)
        {
            if (text.AsSpan(grenzen[i], grenzen[i + 1] - grenzen[i]).SequenceEqual(zeichen)) { return grenzen[i]; }
        }
        return -1;
    }

    /// <summary>Prozent-kodiertes Base32: zuerst in eine genullte Rechenfläche dekodieren, dann Base32.</summary>
    private static Geheimpuffer DecodePercentEncodedBase32(ReadOnlySpan<byte> raw)
    {
        using var scratch = Geheimpuffer.Rechenflaeche(raw.Length);
        using var leihe = scratch.Schreiben();
        var ziel = leihe.Span;
        var written = PercentDecode(raw, ziel);
        return DecodeBase32(ziel[..written]);
    }

    /// <summary>Dezimalzahl aus 1–3 ASCII-Ziffern.</summary>
    private static int SmallNumber(byte[] bytes, string code)
    {
        if (bytes.Length is < 1 or > 3) { throw Invalid(code); }
        var value = 0;
        foreach (var b in bytes)
        {
            if (b is < 0x30 or > 0x39) { throw Invalid(code); }
            value = value * 10 + (b - 0x30);
        }
        return value;
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Prozent-dekodiert und als UTF-8 gelesen (Label, Aussteller, Algorithmus).</summary>
    private static string DecodeText(ReadOnlySpan<byte> bytes)
    {
        var decoded = PercentDecode(bytes);
        try
        {
            return StrictUtf8.GetString(decoded);
        }
        catch (DecoderFallbackException)
        {
            throw Invalid("totp.uri");
        }
    }

    /// <summary><c>%XX</c> → Byte. <c>+</c> bleibt <c>+</c> (otpauth kodiert Leerzeichen als <c>%20</c>).</summary>
    internal static byte[] PercentDecode(ReadOnlySpan<byte> bytes)
    {
        var output = new byte[bytes.Length];
        var written = PercentDecode(bytes, output);
        return output[..written];
    }

    /// <summary>Dekodiert nach <paramref name="ziel"/> (mindestens so lang wie die Eingabe); Ergebnis = Länge.</summary>
    private static int PercentDecode(ReadOnlySpan<byte> bytes, Span<byte> ziel)
    {
        var written = 0;
        var index = 0;
        while (index < bytes.Length)
        {
            var b = bytes[index];
            if (b == '%')
            {
                if (index + 2 >= bytes.Length || HexValue(bytes[index + 1]) is not { } high || HexValue(bytes[index + 2]) is not { } low)
                {
                    throw Invalid("totp.uri");
                }
                ziel[written++] = (byte)((high << 4) | low);
                index += 3;
            }
            else
            {
                ziel[written++] = b;
                index++;
            }
        }
        return written;
    }

    /// <summary>RFC 4648 Base32, tolerant (Leerraum, Kleinbuchstaben, fehlendes Padding). Ergebnis in sodium-Speicher.</summary>
    internal static Geheimpuffer DecodeBase32(ReadOnlySpan<byte> input)
    {
        var values = new byte[input.Length];
        var count = 0;
        try
        {
            var padding = 0;
            foreach (var b in input)
            {
                if (IsWhitespace(b)) { continue; }
                if (b == '=')
                {
                    padding++;
                    continue;
                }
                if (padding != 0) { throw Invalid("totp.base32"); }          // Zeichen nach dem Padding
                var upper = b is >= 0x61 and <= 0x7A ? (byte)(b - 0x20) : b;
                if (upper is >= 0x41 and <= 0x5A) { values[count++] = (byte)(upper - 0x41); }       // A–Z → 0–25
                else if (upper is >= 0x32 and <= 0x37) { values[count++] = (byte)(upper - 0x32 + 26); } // 2–7 → 26–31
                else { throw Invalid("totp.base32"); }
            }
            // Gültige Restlängen eines Achterblocks und das dazu passende Padding
            var expectedPadding = (count % 8) switch
            {
                0 => 0,
                2 => 6,
                4 => 4,
                5 => 3,
                7 => 1,
                _ => throw Invalid("totp.base32"),
            };
            if (padding != 0 && padding != expectedPadding) { throw Invalid("totp.base32"); }
            var byteCount = count * 5 / 8;
            if (byteCount is < MinimumSecretBytes or > MaximumSecretBytes) { throw Invalid("totp.secret.length"); }
            var werte = values;
            var anzahl = count;
            return Geheimpuffer.Neu(byteCount, ziel =>
            {
                ulong buffer = 0;
                var bits = 0;
                var written = 0;
                for (var k = 0; k < anzahl; k++)
                {
                    buffer = (buffer << 5) | werte[k];
                    bits += 5;
                    if (bits >= 8 && written < byteCount)
                    {
                        bits -= 8;
                        ziel[written++] = (byte)(buffer >> bits);
                    }
                }
            });
        }
        finally
        {
            Sodium.Wipe(values);
        }
    }

    // Hilfen

    private static bool IsWhitespace(byte b) => b is 0x20 or 0x09 or 0x0A or 0x0D;

    private static byte LowerAscii(byte b) => b is >= 0x41 and <= 0x5A ? (byte)(b + 0x20) : b;

    private static bool StartsWithLowerAscii(ReadOnlySpan<byte> text, ReadOnlySpan<byte> lowerPrefix)
    {
        for (var i = 0; i < lowerPrefix.Length; i++)
        {
            if (LowerAscii(text[i]) != lowerPrefix[i]) { return false; }
        }
        return true;
    }

    private static bool EqualsLowerAscii(ReadOnlySpan<byte> text, ReadOnlySpan<byte> lower) =>
        text.Length == lower.Length && StartsWithLowerAscii(text, lower);

    private static int? HexValue(byte b) => b switch
    {
        >= 0x30 and <= 0x39 => b - 0x30,
        >= 0x41 and <= 0x46 => b - 0x41 + 10,
        >= 0x61 and <= 0x66 => b - 0x61 + 10,
        _ => null,
    };
}
