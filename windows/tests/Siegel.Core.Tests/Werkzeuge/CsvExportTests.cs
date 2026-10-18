using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Tests;

/// <summary>CSV-Export (SPEC §7.9, §8; Port von CSVExportTests.swift).</summary>
public class CsvExportTests
{
    private static VaultEntry Eintrag(string title = "", string username = "", string password = "", string url = "",
        string notes = "", string totp = "") =>
        new() { Title = title, Username = username, Password = password, Url = url, Notes = notes, Totp = totp };

    private static byte[] Export(params VaultEntry[] entries) =>
        CsvExport.Export(entries.Select(e => (e, new EntrySecrets())));

    [Fact]
    public void FormatAlleFelderZitiertCrlfOhneBom()
    {
        var entry = Eintrag("Bank, Privat", "anna", "a\"b", "https://bank.example", "Zeile 1\nZeile 2");
        entry.History = [new PasswordHistoryItem("altes-geheimnis", DateTimeOffset.UtcNow)];
        var data = Export(entry);
        const string expected = "\"name\",\"url\",\"username\",\"password\",\"note\"\r\n"
            + "\"Bank, Privat\",\"https://bank.example\",\"anna\",\"a\"\"b\",\"Zeile 1\nZeile 2\"\r\n";
        Assert.Equal(Encoding.UTF8.GetBytes(expected), data);
        Assert.Equal(0x22, data[0]);
        Assert.DoesNotContain("altes-geheimnis", Encoding.UTF8.GetString(data), StringComparison.Ordinal);
    }

    [Fact]
    public void OhneTotp()
    {
        var text = Encoding.UTF8.GetString(Export(Eintrag("GitHub", "anna", "pw", "https://github.com", "Notiz",
            "otpauth://totp/GitHub:anna?secret=JBSWY3DPEHPK3PXP")));
        Assert.DoesNotContain("JBSWY3DPEHPK3PXP", text, StringComparison.Ordinal);
        Assert.DoesNotContain("otpauth", text, StringComparison.Ordinal);
        Assert.Equal("\"name\",\"url\",\"username\",\"password\",\"note\"\r\n\"GitHub\",\"https://github.com\",\"anna\",\"pw\",\"Notiz\"\r\n", text);
    }

    [Fact]
    public void LeereListeNurKopfzeile()
    {
        Assert.Equal(Encoding.UTF8.GetBytes("\"name\",\"url\",\"username\",\"password\",\"note\"\r\n"), Export());
    }

    [Fact]
    public void GeloeschteNichtExportiert()
    {
        var kept = Eintrag("Bleibt", "u", "p1", "https://a.example");
        var deleted = Eintrag("Weg", "u", "geloescht-pw", "https://b.example");
        deleted.DeletedAt = DateTimeOffset.UtcNow;
        var text = Encoding.UTF8.GetString(Export(kept, deleted));
        Assert.DoesNotContain("Weg", text, StringComparison.Ordinal);
        Assert.DoesNotContain("geloescht-pw", text, StringComparison.Ordinal);
        Assert.Contains("Bleibt", text, StringComparison.Ordinal);
    }

    [Fact]
    public void JedesFeldZitiert()
    {
        var text = Encoding.UTF8.GetString(Export(Eintrag("T"), Eintrag("=1+2", password: "@x")));
        Assert.EndsWith("\r\n", text, StringComparison.Ordinal);
        var lines = text.Split("\r\n")[..^1];
        Assert.Equal(3, lines.Length);
        Assert.Equal("\"T\",\"\",\"\",\"\",\"\"", lines[1]);
        Assert.Equal("\"=1+2\",\"\",\"\",\"@x\",\"\"", lines[2]);
    }

    [Fact]
    public void GeheimteileAusEntrySecrets()
    {
        // Versiegelt (vom Kern gesetzt): nur EntrySecrets zählt; offen: leere Felder aus dem Eintrag
        var offen = Eintrag("Offen", password: "aus-dem-eintrag", notes: "n");
        var text = Encoding.UTF8.GetString(CsvExport.Export([(offen, new EntrySecrets { Password = "aufgedeckt" })]));
        Assert.Contains("\"aufgedeckt\",\"n\"", text, StringComparison.Ordinal);
        var versiegelt = Eintrag("Zu");
        versiegelt.SecretsSealed = true;
        Assert.True(versiegelt.SecretsSealed);
        text = Encoding.UTF8.GetString(CsvExport.Export([(versiegelt, new EntrySecrets { Password = "geheim", Notes = "" })]));
        Assert.Contains("\"Zu\",\"\",\"\",\"geheim\",\"\"", text, StringComparison.Ordinal);
    }

    [Fact]
    public void RundlaufExportImportBytegenau()
    {
        VaultEntry[] entries =
        [
            Eintrag("SBB", "anna@example.ch", "zug,fahrt\"2026", "https://www.sbb.ch/de", "Halbtax\r\nGA nein"),
            Eintrag("Bank, \"Privat\"", "4711", "=SUMME(A1)+'1", "https://bank.example/login?x=1,2", "PIN: im Safe\n\nZweite Zeile"),
            Eintrag("Unicode Zürich", "jürg", "🔑Äöü e\u0301 \u00A0", "https://bücher.de", ""),
            Eintrag("Steuerzeichen im Passwort", "u", "\u0000\t\r\n\u202Ex", "https://c.example", "Tab\tim Text"),
            Eintrag("Leeres Passwort", "nur-name", "", "", "n"),
        ];
        var result = CsvImport.Parse(Export(entries));
        Assert.Equal(CsvFormat.Chrome, result.Format);
        Assert.Equal(entries.Length, result.Entries.Count);
        for (var i = 0; i < entries.Length; i++)
        {
            var original = entries[i];
            var imported = result.Entries[i];
            Assert.Equal(Encoding.UTF8.GetBytes(original.Title), Encoding.UTF8.GetBytes(imported.Title));
            Assert.Equal(Encoding.UTF8.GetBytes(original.Username), Encoding.UTF8.GetBytes(imported.Username));
            Assert.Equal(Encoding.UTF8.GetBytes(original.Password), Encoding.UTF8.GetBytes(imported.Password));
            Assert.Equal(Encoding.UTF8.GetBytes(original.Url), Encoding.UTF8.GetBytes(imported.Url));
            Assert.Equal(Encoding.UTF8.GetBytes(original.Notes), Encoding.UTF8.GetBytes(imported.Notes));
        }
        Assert.Equal(1, result.Report.PasswordsWithControlCharacters);
        Assert.Equal(0, result.Report.MovedToNotes);
        Assert.Equal(0, result.Report.WithOtpSecret);
    }
}
