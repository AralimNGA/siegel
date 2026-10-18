using System.Diagnostics;
using System.Globalization;
using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Tests;

internal static class CsvHilfe
{
    internal static byte[] Csv(string text) => Encoding.UTF8.GetBytes(text);

    internal static CsvImportResult Parse(string text) => CsvImport.Parse(Csv(text));

    internal static void Invalid(int line, string reason, Action action)
    {
        var e = Assert.Throws<SiegelException>(action);
        Assert.Equal(SiegelErrorCode.CsvInvalid, e.Code);
        Assert.Equal(reason, e.Detail);
        Assert.Equal(line, e.Line);
    }

    internal const string ChromeHeader = "name,url,username,password,note\n";

    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    internal static void ReportLeer(ImportReport r)
    {
        Assert.Equal(0, r.Added);
        Assert.Equal(0, r.SkippedDuplicates);
        Assert.Equal(0, r.Conflicts);
        Assert.Equal(0, r.WithOtpSecret);
        Assert.Equal(0, r.MovedToNotes);
        Assert.Equal(0, r.PasswordsWithControlCharacters);
        Assert.Equal(0, r.ApostrophePrefixed);
    }
}

/// <summary>CSV-Import: alle vier Formate (Port von CSVImportTests.swift, erfundene Daten).</summary>
public class CsvFormatTests
{
    [Fact]
    public void Apple()
    {
        const string file = "Title,URL,Username,Password,Notes,OTPAuth\r\n"
            + "example.com (anna@example.com),https://example.com/,anna@example.com,\"Pa,ss\"\"wort\",\"Notiz, mit Komma\",\r\n"
            + "GitHub,https://github.com/login,anna-dev,gh-Geheim-42,\"Zeile 1\nZeile 2\",otpauth://totp/GitHub:anna-dev?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\r\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal(CsvFormat.ApplePasswords, result.Format);
        Assert.Equal(2, result.Entries.Count);
        var first = result.Entries[0];
        Assert.Equal("example.com (anna@example.com)", first.Title);
        Assert.Equal("https://example.com/", first.Url);
        Assert.Equal("anna@example.com", first.Username);
        Assert.Equal("Pa,ss\"wort", first.Password);
        Assert.Equal("Notiz, mit Komma", first.Notes);
        var second = result.Entries[1];
        Assert.Equal("GitHub", second.Title);
        Assert.Equal("Zeile 1\nZeile 2", second.Notes);
        Assert.Equal("otpauth://totp/GitHub:anna-dev?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", second.Totp);
        Assert.Equal("", first.Totp);
        Assert.Equal(1, result.Report.WithOtpSecret);
        Assert.Equal(0, result.Report.MovedToNotes);
        Assert.Equal(2, result.Report.Added);
        Assert.NotEqual(first.Id, second.Id);
    }

    [Fact]
    public void Chrome()
    {
        const string file = "name,url,username,password,note\n"
            + "accounts.google.com,https://accounts.google.com/signin/v2,anna.muster@gmail.com,G00gle!Pass,\n"
            + "www.sbb.ch,https://www.sbb.ch/de/login,anna,\"zug,fahrt\"\"2026\",Halbtax bis 12/2027\n"
            + ",https://www.digitec.ch/login,anna@example.ch,dg-pass,\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal(CsvFormat.Chrome, result.Format);
        Assert.Equal(["accounts.google.com", "www.sbb.ch", "digitec.ch"], result.Entries.Select(e => e.Title));
        Assert.Equal("zug,fahrt\"2026", result.Entries[1].Password);
        Assert.Equal("Halbtax bis 12/2027", result.Entries[1].Notes);
        Assert.Equal("", result.Entries[0].Notes);
        Assert.Equal(0, result.Report.WithOtpSecret);
        Assert.Equal(0, result.Report.MovedToNotes);
    }

    [Fact]
    public void Firefox()
    {
        const string file = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\r\n"
            + "\"https://www.mozilla.org\",\"anna\",\"fx-Pass-1\",\"\",\"https://www.mozilla.org\",\"{0e5a3b8c-4f2d-4a7e-9c11-2b7d3f6e8a90}\",\"1700000000000\",\"1700000500000\",\"1700000300000\"\r\n"
            + "\"https://auth.example.net\",\"bob@example.net\",\"x\"\"y,z\",\"Example Realm\",\"\",\"{11111111-2222-3333-4444-555555555555}\",\"1690000000123\",\"\",\"1690000000123\"\r\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal(CsvFormat.Firefox, result.Format);
        Assert.Equal(2, result.Entries.Count);
        var first = result.Entries[0];
        Assert.Equal("mozilla.org", first.Title);
        Assert.Equal("https://www.mozilla.org", first.Url);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), first.Created);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_300), first.Modified);
        Assert.Equal("formActionOrigin: https://www.mozilla.org\nguid: {0e5a3b8c-4f2d-4a7e-9c11-2b7d3f6e8a90}\ntimeLastUsed: 1700000500000",
            first.Notes);
        var second = result.Entries[1];
        Assert.Equal("auth.example.net", second.Title);
        Assert.Equal("x\"y,z", second.Password);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1_690_000_000_123), second.Created);
        Assert.Equal("httpRealm: Example Realm\nguid: {11111111-2222-3333-4444-555555555555}", second.Notes);
        Assert.Equal(2, result.Report.MovedToNotes);
    }

    [Fact]
    public void FirefoxZeitstempel()
    {
        var before = DateTimeOffset.UtcNow;
        const string file = "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
            + "https://a.example,anna,pw,,,,abc,,\n"
            + "https://b.example,bob,pw,,,,1700000000000,,1600000000000\n"
            + "https://c.example,carl,pw,,,,,,\n";
        var result = CsvHilfe.Parse(file);
        var after = DateTimeOffset.UtcNow;
        Assert.Equal("timeCreated: abc", result.Entries[0].Notes);
        Assert.InRange(result.Entries[0].Created, before, after);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), result.Entries[1].Created);
        Assert.Equal(result.Entries[1].Created, result.Entries[1].Modified);
        Assert.Equal("", result.Entries[2].Notes);
        Assert.InRange(result.Entries[2].Created, before, after);
    }

    [Fact]
    public void Bitwarden()
    {
        const string file = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            + "Social,1,login,Mastodon,,,0,https://mastodon.social,anna,md-Pass-9,JBSWY3DPEHPK3PXP\n"
            + ",,login,Bank,PIN-Brief im Ordner,\"Kundennummer: 12345\nFrage: Haustier\",,https://bank.example.ch,4711,bk-Pass,\n"
            + ",,note,WLAN Zuhause,\"SSID: Muster\nSchlüssel: geheim\",,0,,,,\n"
            + ",,,,,,0,,,,\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal(CsvFormat.Bitwarden, result.Format);
        Assert.Equal(3, result.Entries.Count);
        var mastodon = result.Entries[0];
        Assert.Equal("Mastodon", mastodon.Title);
        Assert.Equal("https://mastodon.social", mastodon.Url);
        Assert.Equal("anna", mastodon.Username);
        Assert.Equal("md-Pass-9", mastodon.Password);
        Assert.Equal("folder: Social\nfavorite: 1\nreprompt: 0", mastodon.Notes);
        Assert.Equal("JBSWY3DPEHPK3PXP", mastodon.Totp);
        Assert.Equal("PIN-Brief im Ordner\n\nfields: Kundennummer: 12345\nFrage: Haustier", result.Entries[1].Notes);
        var note = result.Entries[2];
        Assert.Equal("WLAN Zuhause", note.Title);
        Assert.Equal("", note.Url);
        Assert.Equal("", note.Username);
        Assert.Equal("", note.Password);
        Assert.Equal("SSID: Muster\nSchlüssel: geheim\n\nreprompt: 0", note.Notes);
        Assert.Equal(1, result.Report.WithOtpSecret);
        Assert.Equal(3, result.Report.MovedToNotes);
    }

    [Fact]
    public void BitwardenNotizMitWerten()
    {
        const string file = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            + ",,note,Notiz,Text,,,https://x.example,user,pw,\n"
            + ",,card,Karte,,,,,,kartenpw,\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal("", result.Entries[0].Password);
        Assert.Equal("Text\n\nlogin_uri: https://x.example\nlogin_username: user\nlogin_password: pw", result.Entries[0].Notes);
        Assert.Equal("kartenpw", result.Entries[1].Password);
        Assert.Equal("type: card", result.Entries[1].Notes);
    }

    [Fact]
    public void KopfzeileTolerant()
    {
        var apple = CsvHilfe.Parse(" TITLE , url,UserName,PASSWORD,notes,otpauth\nT,https://t.example,u,p,n,\n");
        Assert.Equal(CsvFormat.ApplePasswords, apple.Format);
        Assert.Equal("T", apple.Entries[0].Title);
        Assert.Equal("n", apple.Entries[0].Notes);

        var chrome = CsvHilfe.Parse("PASSWORD,Note,Name,URL,Username\npw,nn,Titel,https://c.example,user\n");
        Assert.Equal(CsvFormat.Chrome, chrome.Format);
        Assert.Equal("pw", chrome.Entries[0].Password);
        Assert.Equal("Titel", chrome.Entries[0].Title);
        Assert.Equal("nn", chrome.Entries[0].Notes);

        var bitwarden = CsvHilfe.Parse("Folder,Favorite,Type,Name,Notes,Fields,Reprompt,Login_URI,Login_Username,Login_Password,Login_TOTP\n,,login,B,,,,https://b.example,u,p,\n");
        Assert.Equal(CsvFormat.Bitwarden, bitwarden.Format);

        var firefox = CsvHilfe.Parse("URL,USERNAME,PASSWORD,GUID\nhttps://f.example,u,p,{1}\n");
        Assert.Equal(CsvFormat.Firefox, firefox.Format);
        Assert.Equal("GUID: {1}", firefox.Entries[0].Notes);
    }

    [Fact]
    public void Zusatzspalten()
    {
        var file = "name,url,username,password,note,Kategorie,,Leer\n"
            + "Shop,https://shop.example,anna,pw,Kundin seit 2019,Einkauf,ohne Namen,\n"
            + "Zweiter,https://z.example,bob,pw2,,,,\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal("Kundin seit 2019\n\nKategorie: Einkauf\nSpalte 7: ohne Namen", result.Entries[0].Notes);
        Assert.Equal("", result.Entries[1].Notes);
        Assert.Equal(1, result.Report.MovedToNotes);
    }

    [Fact]
    public void KopfzeileFehler()
    {
        CsvHilfe.Invalid(1, "csv.header.unknown", () => CsvHilfe.Parse("foo,bar\n1,2\n"));
        CsvHilfe.Invalid(1, "csv.header.unknown", () => CsvHilfe.Parse("url,username,password\nx,y,z\n"));
        CsvHilfe.Invalid(1, "csv.header.duplicate", () => CsvHilfe.Parse("name,url,username,password,NAME\n"));
        CsvHilfe.Invalid(2, "csv.header.unknown", () => CsvHilfe.Parse("\nfoo,bar\n"));
        // Kanonisch gleiche Spaltennamen sind doppelt (wie Swift-Set<String>)
        CsvHilfe.Invalid(1, "csv.header.duplicate", () => CsvHilfe.Parse("name,url,username,password,notizé,notize\u0301\n"));
    }

    [Fact]
    public void NurKopfzeile()
    {
        var result = CsvHilfe.Parse("name,url,username,password,note\r\n");
        Assert.Equal(CsvFormat.Chrome, result.Format);
        Assert.Empty(result.Entries);
        CsvHilfe.ReportLeer(result.Report);
    }
}

/// <summary>2FA nach totp (SPEC §18).</summary>
public class CsvTotpTests
{
    [Fact]
    public void Zuordnung()
    {
        var file = "Title,URL,Username,Password,Notes,OTPAuth\n"
            + "A,https://a.example,u,p,,\"  otpauth://totp/A:u?secret=JBSWY3DPEHPK3PXP&period=60 \"\n"
            + "B,https://b.example,u,p,Alt,otpauth://hotp/B:u?secret=JBSWY3DPEHPK3PXP&counter=3\n"
            + "C,https://c.example,u,p,,steam://ABCDEFGH\n"
            + "D,https://d.example,u,p,,otpauth://totp/D?secret=JBSWY3DP\n"
            + "E,https://e.example,u,p,,\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal(["otpauth://totp/A:u?secret=JBSWY3DPEHPK3PXP&period=60", "", "", "", ""], result.Entries.Select(e => e.Totp));
        using (var p = Totp.Parse(result.Entries[0].Totp)) { Assert.Equal(60, p.Period); }
        Assert.Equal("", result.Entries[0].Notes);
        Assert.Equal("Alt\n\nOTPAuth: otpauth://hotp/B:u?secret=JBSWY3DPEHPK3PXP&counter=3", result.Entries[1].Notes);
        Assert.Equal("OTPAuth: steam://ABCDEFGH", result.Entries[2].Notes);
        Assert.Equal("OTPAuth: otpauth://totp/D?secret=JBSWY3DP", result.Entries[3].Notes);
        Assert.Equal("", result.Entries[4].Notes);
        Assert.Equal(1, result.Report.WithOtpSecret);
        Assert.Equal(3, result.Report.MovedToNotes);
    }

    [Fact]
    public void BitwardenTotp()
    {
        var file = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            + ",,login,Roh,,,,https://r.example,u,p,jbsw y3dp ehpk 3pxp\n"
            + ",,login,URI,,,,https://u.example,u,p,otpauth://totp/U?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8\n"
            + ",,note,Notiz,Text,,,,,,JBSWY3DPEHPK3PXP\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal("jbsw y3dp ehpk 3pxp", result.Entries[0].Totp);
        using (var a = Totp.Parse(result.Entries[0].Totp))
        using (var b = Totp.Parse("JBSWY3DPEHPK3PXP"))
        {
            Assert.Equal(b, a);
        }
        using (var c = Totp.Parse(result.Entries[1].Totp)) { Assert.Equal(8, c.Digits); }
        Assert.Equal("", result.Entries[2].Totp);
        Assert.Equal("Text\n\nlogin_totp: JBSWY3DPEHPK3PXP", result.Entries[2].Notes);
        Assert.Equal(2, result.Report.WithOtpSecret);
        Assert.Equal(1, result.Report.MovedToNotes);
    }

    [Fact]
    public void NurZweiFaktor()
    {
        var result = CsvHilfe.Parse("Title,URL,Username,Password,Notes,OTPAuth\n,,,,,JBSWY3DPEHPK3PXP\n,,,,,kein-geheimnis\n");
        Assert.Equal(2, result.Entries.Count);
        Assert.Equal("JBSWY3DPEHPK3PXP", result.Entries[0].Totp);
        Assert.Equal("OTPAuth: kein-geheimnis", result.Entries[1].Notes);
    }
}

/// <summary>Spaltengrenze (Befund #45).</summary>
public class CsvSpaltenTests
{
    [Fact]
    public void BreiteKopfzeile()
    {
        var data = new byte[16 * 1024 * 1024];
        var kopf = CsvHilfe.Utf8("name,url,username,password,note");
        kopf.CopyTo(data, 0);
        Array.Fill(data, (byte)0x2C, kopf.Length, data.Length - kopf.Length);
        var uhr = Stopwatch.StartNew();
        CsvHilfe.Invalid(1, "csv.header.unknown", () => CsvImport.Parse(data));
        Assert.True(uhr.Elapsed < TimeSpan.FromSeconds(1), $"{uhr.Elapsed}");
    }

    [Fact]
    public void BreiteDatenzeile()
    {
        var anfang = CsvHilfe.Utf8(CsvHilfe.ChromeHeader + "A,https://a.example,u,p,\n");
        var data = new byte[anfang.Length + 1_000_000 + 1];
        anfang.CopyTo(data, 0);
        Array.Fill(data, (byte)0x2C, anfang.Length, 1_000_000);
        data[^1] = 0x0A;
        var uhr = Stopwatch.StartNew();
        CsvHilfe.Invalid(3, "csv.fieldCount", () => CsvImport.Parse(data));
        Assert.True(uhr.Elapsed < TimeSpan.FromSeconds(1), $"{uhr.Elapsed}");
    }

    [Fact]
    public void Grenze256()
    {
        var extra = Enumerable.Range(6, 251).Select(i => $"x{i}").ToList();
        var header = string.Join(",", new[] { "name", "url", "username", "password", "note" }.Concat(extra));
        Assert.Equal(256, header.Split(',').Length);
        var row = string.Join(",", new[] { "T", "https://t.example", "u", "p", "" }.Concat(extra.Select(_ => "")));
        Assert.Single(CsvHilfe.Parse(header + "\n" + row + "\n").Entries);
        CsvHilfe.Invalid(1, "csv.header.unknown", () => CsvHilfe.Parse(header + ",x257\n" + row + ",\n"));
        CsvHilfe.Invalid(2, "csv.fieldCount", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "\"A\",\"b\",\"c\",\"d\",\"e\",\"f\""));
    }
}

/// <summary>RFC 4180.</summary>
public class CsvRfcTests
{
    [Fact]
    public void Zeilenenden()
    {
        string[] variants =
        [
            "name,url,username,password,note\r\nA,https://a.ch,u1,p1,\r\nB,https://b.ch,u2,p2,n\r\n",
            "name,url,username,password,note\nA,https://a.ch,u1,p1,\nB,https://b.ch,u2,p2,n\n",
            "name,url,username,password,note\rA,https://a.ch,u1,p1,\rB,https://b.ch,u2,p2,n\r",
            "name,url,username,password,note\r\nA,https://a.ch,u1,p1,\nB,https://b.ch,u2,p2,n",
            "name,url,username,password,note\n\nA,https://a.ch,u1,p1,\r\n\r\nB,https://b.ch,u2,p2,n\n\n\n",
        ];
        foreach (var text in variants)
        {
            var result = CsvHilfe.Parse(text);
            Assert.Equal(["A", "B"], result.Entries.Select(e => e.Title));
            Assert.Equal(["p1", "p2"], result.Entries.Select(e => e.Password));
            Assert.Equal(["", "n"], result.Entries.Select(e => e.Notes));
        }
    }

    [Fact]
    public void Zitiert()
    {
        var file = CsvHilfe.ChromeHeader
            + "\"a,b\",\"https://x.example/?q=1,2\",\"\",\"\"\"\",\"\"\"start und ende\"\"\"\n"
            + "\"Mehr\nzeilig\",https://y.example,\"u\",\"p\r\nw\",\"Notiz\r\nmit CRLF\"\n"
            + "Leer,https://z.example,,,\n";
        var result = CsvHilfe.Parse(file);
        Assert.Equal(3, result.Entries.Count);
        Assert.Equal("a,b", result.Entries[0].Title);
        Assert.Equal("https://x.example/?q=1,2", result.Entries[0].Url);
        Assert.Equal("", result.Entries[0].Username);
        Assert.Equal("\"", result.Entries[0].Password);
        Assert.Equal("\"start und ende\"", result.Entries[0].Notes);
        Assert.Equal("Mehrzeilig", result.Entries[1].Title);
        Assert.Equal(CsvHilfe.Utf8("p\r\nw"), CsvHilfe.Utf8(result.Entries[1].Password));
        Assert.Equal(CsvHilfe.Utf8("Notiz\r\nmit CRLF"), CsvHilfe.Utf8(result.Entries[1].Notes));
        Assert.Equal("", result.Entries[2].Password);
        Assert.Equal("", result.Entries[2].Username);
        Assert.Equal(1, result.Report.PasswordsWithControlCharacters);
    }

    [Fact]
    public void KeinTrimmen()
    {
        var result = CsvHilfe.Parse(CsvHilfe.ChromeHeader + " Titel ,https://x.example, anna ,  pw  , n \n");
        Assert.Equal(" Titel ", result.Entries[0].Title);
        Assert.Equal(" anna ", result.Entries[0].Username);
        Assert.Equal("  pw  ", result.Entries[0].Password);
        Assert.Equal(" n ", result.Entries[0].Notes);
    }

    [Fact]
    public void Bom()
    {
        var data = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(CsvHilfe.Utf8("name,url,username,password,note\r\nA,https://a.example,u,p,\r\n")).ToArray();
        var result = CsvImport.Parse(data);
        Assert.Equal(CsvFormat.Chrome, result.Format);
        Assert.Single(result.Entries);
        CsvHilfe.Invalid(0, "csv.empty", () => CsvImport.Parse([0xEF, 0xBB, 0xBF]));
    }

    [Fact]
    public void AnfuehrungszeichenFehler()
    {
        CsvHilfe.Invalid(3, "csv.quote", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "A,https://a.example,u,p,\nB,https://b.example,u,p\"w,\n"));
        CsvHilfe.Invalid(2, "csv.quote", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "\"A\"x,https://a.example,u,p,\n"));
        CsvHilfe.Invalid(2, "csv.quote", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "A, \"https://a.example\",u,p,\n"));
        CsvHilfe.Invalid(5, "csv.quote", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "A,https://a.example,u,p,\"Zeile 1\nZeile 2\nZeile 3\"\nB,x\"y,u,p,\n"));
        CsvHilfe.Invalid(3, "csv.unterminatedQuote", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "A,https://a.example,u,p,\nB,https://b.example,u,\"offen\nbis zum Ende,\n"));
    }

    [Fact]
    public void Feldanzahl()
    {
        CsvHilfe.Invalid(2, "csv.fieldCount", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "A,https://a.example,u,p\n"));
        CsvHilfe.Invalid(2, "csv.fieldCount", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "A,https://a.example,u,p,n,zuviel\n"));
        CsvHilfe.Invalid(4, "csv.fieldCount", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + "A,https://a.example,u,p,\"zwei\nZeilen\"\nB,https://b.example\n"));
    }

    [Fact]
    public void Leer()
    {
        CsvHilfe.Invalid(0, "csv.empty", () => CsvImport.Parse([]));
        CsvHilfe.Invalid(0, "csv.empty", () => CsvHilfe.Parse("\r\n\n\r\n"));
    }

    [Fact]
    public void Kodierung()
    {
        var bad = CsvHilfe.Utf8(CsvHilfe.ChromeHeader + "A,https://a.example,u,").Concat(new byte[] { 0xC3, 0x28 })
            .Concat(CsvHilfe.Utf8(",\n")).ToArray();
        CsvHilfe.Invalid(2, "csv.encoding", () => CsvImport.Parse(bad));
        var utf16 = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("name,url,username,password,note\n")).ToArray();
        CsvHilfe.Invalid(1, "csv.encoding", () => CsvImport.Parse(utf16));
        // Überlange Kodierung und kodierte Surrogate sind kein gültiges UTF-8 (wie String(validating:))
        foreach (var falsch in new[] { new byte[] { 0xC0, 0xAF }, [0xED, 0xA0, 0x80], [0xF4, 0x90, 0x80, 0x80] })
        {
            var datei = CsvHilfe.Utf8(CsvHilfe.ChromeHeader + "A,").Concat(falsch).Concat(CsvHilfe.Utf8(",u,p,\n")).ToArray();
            CsvHilfe.Invalid(2, "csv.encoding", () => CsvImport.Parse(datei));
        }
    }

    [Fact]
    public void KeinTeilimport()
    {
        var file = new StringBuilder(CsvHilfe.ChromeHeader);
        for (var i = 0; i < 100; i++) { file.Append(CultureInfo.InvariantCulture, $"T{i},https://t{i}.example,u,p,\n"); }
        file.Append("kaputt\",x,u,p,\n");
        CsvHilfe.Invalid(102, "csv.quote", () => CsvHilfe.Parse(file.ToString()));
    }

    [Fact]
    public void LeereDatensaetze()
    {
        var result = CsvHilfe.Parse(CsvHilfe.ChromeHeader + ",,,,\r\nA,,,,\r\n,,,,\r\n  \t\r\n");
        Assert.Single(result.Entries);
        Assert.Equal("A", result.Entries[0].Title);
    }
}

/// <summary>Grenzen und Hygiene.</summary>
public class CsvLimitTests
{
    [Fact]
    public void Dateigroesse()
    {
        CsvHilfe.Invalid(0, "csv.fileTooLarge", () => CsvImport.Parse(new byte[16 * 1024 * 1024 + 1]));
    }

    [Fact]
    public void Zeilenzahl()
    {
        var file = new StringBuilder(CsvHilfe.ChromeHeader, 700_000);
        for (var i = 0; i < 20_000; i++) { file.Append(CultureInfo.InvariantCulture, $"T{i},https://x.example,u,p,\n"); }
        file.Append("\n\n");
        Assert.Equal(20_000, CsvHilfe.Parse(file.ToString()).Entries.Count);
        file.Append("Zuviel,https://x.example,u,p,\n");
        CsvHilfe.Invalid(20_004, "csv.tooManyRows", () => CsvHilfe.Parse(file.ToString()));
    }

    [Fact]
    public void Feldgrenzen()
    {
        var twoKiB = new string('ä', 1024);
        var fourKiB = new string('x', 4096);
        var notesMax = new string('n', 256 * 1024);
        var ok = CsvHilfe.Parse(CsvHilfe.ChromeHeader + $"{twoKiB},https://a.example/{new string('p', 2048 - 18)},{twoKiB},{fourKiB},{notesMax}\n");
        Assert.Equal(2048, Encoding.UTF8.GetByteCount(ok.Entries[0].Title));
        Assert.Equal(2048, Encoding.UTF8.GetByteCount(ok.Entries[0].Url));
        Assert.Equal(4096, Encoding.UTF8.GetByteCount(ok.Entries[0].Password));
        Assert.Equal(262_144, Encoding.UTF8.GetByteCount(ok.Entries[0].Notes));

        CsvHilfe.Invalid(2, "csv.field.title", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + $"{twoKiB}a,https://a.example,u,p,\n"));
        CsvHilfe.Invalid(2, "csv.field.username", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + $"T,https://a.example,{twoKiB}a,p,\n"));
        CsvHilfe.Invalid(2, "csv.field.url", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + $"T,https://a.example/{new string('p', 2048)},u,p,\n"));
        CsvHilfe.Invalid(2, "csv.field.password", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + $"T,https://a.example,u,{fourKiB}x,\n"));
        CsvHilfe.Invalid(2, "csv.field.notes", () => CsvHilfe.Parse(CsvHilfe.ChromeHeader + $"T,https://a.example,u,p,{notesMax}n\n"));

        const string appleHeader = "Title,URL,Username,Password,Notes,OTPAuth\n";
        CsvHilfe.Invalid(2, "csv.field.notes", () => CsvHilfe.Parse(appleHeader + $"T,https://a.example,u,p,{new string('n', 262_140)},otpauth://totp/x\n"));
        var withTabs = new string('a', 2048) + "\t\t\t";
        Assert.Equal(2048, Encoding.UTF8.GetByteCount(CsvHilfe.Parse(CsvHilfe.ChromeHeader + $"\"{withTabs}\",https://a.example,u,p,\n").Entries[0].Title));
    }

    [Fact]
    public void Steuerzeichen()
    {
        var allControls = new StringBuilder();
        for (var v = 0; v <= 0x1F; v++) { allControls.Append((char)v); }
        allControls.Append("\u007F\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069");
        var quoted = allControls.ToString().Replace("\"", "\"\"", StringComparison.Ordinal);
        var file = CsvHilfe.ChromeHeader
            + "\"Bank\u202Eexe.pdf\u0007\",\"https://bank.example/\u2066x\u2069\u007F\",\"\tanna\u200F\",\"pw\twith\u202Ebidi\",\"Notiz\tmit Tab\"\n"
            + $"\"X{quoted}Y\",https://b.example,\"{quoted}u\",'=SUMME(1),\n"
            + "Nul,https://c.example,u,\"\u0000nul\",\n"
            + "Normal,https://d.example,u,e\u0301\u00A0x,\n";
        var result = CsvHilfe.Parse(file);
        var bank = result.Entries[0];
        Assert.Equal("Bankexe.pdf", bank.Title);
        Assert.Equal("https://bank.example/x", bank.Url);
        Assert.Equal("anna", bank.Username);
        Assert.Equal(CsvHilfe.Utf8("pw\twith\u202Ebidi"), CsvHilfe.Utf8(bank.Password));
        Assert.Equal("Notiz\tmit Tab", bank.Notes);
        Assert.Equal("XY", result.Entries[1].Title);
        Assert.Equal("u", result.Entries[1].Username);
        Assert.Equal("'=SUMME(1)", result.Entries[1].Password);
        Assert.Equal(new byte[] { 0x00, 0x6E, 0x75, 0x6C }, CsvHilfe.Utf8(result.Entries[2].Password));
        Assert.Equal(CsvHilfe.Utf8("e\u0301\u00A0x"), CsvHilfe.Utf8(result.Entries[3].Password));
        Assert.Equal(2, result.Report.PasswordsWithControlCharacters);
        Assert.Equal(1, result.Report.ApostrophePrefixed);
    }

    [Fact]
    public void TitelAusHost()
    {
        Assert.Equal("example.com", CsvText.TitleFromUrl("https://www.example.com/login"));
        Assert.Equal("example.com", CsvText.TitleFromUrl("example.com/path"));
        Assert.Equal("sub.example.com", CsvText.TitleFromUrl("https://user:pw@Sub.Example.COM:8443/"));
        Assert.Equal("bücher.de", CsvText.TitleFromUrl("https://bücher.de/x"));
        Assert.StartsWith("xn--", CsvText.TitleFromUrl("https://аpple.com/"), StringComparison.Ordinal);
        Assert.Equal("com.example.app", CsvText.TitleFromUrl("android://abc==@com.example.app/"));
        Assert.Equal("kein url", CsvText.TitleFromUrl("kein url"));
        // weitere Fälle, gemessen mit Foundation (macOS 26)
        Assert.Equal("bücher.de", CsvText.TitleFromUrl("https://xn--bcher-kva.de"));
        Assert.Equal("äöü.ch", CsvText.TitleFromUrl("https://ÄÖÜ.ch"));
        Assert.Equal("example.com", CsvText.TitleFromUrl("https://ｅｘａｍｐｌｅ.com"));
        Assert.Equal("xn--r8jz45g.jp", CsvText.TitleFromUrl("https://例え.jp"));
        Assert.Equal("[fd00::1]", CsvText.TitleFromUrl("https://[fd00::1]:8443"));
        Assert.Equal("example.com", CsvText.TitleFromUrl("https://%65xample.com"));
        Assert.Equal("c.com", CsvText.TitleFromUrl("https://a@b@c.com"));
        Assert.Equal("https://exa mple.com", CsvText.TitleFromUrl("https://exa mple.com"));
        Assert.Equal("https://", CsvText.TitleFromUrl("https://"));

        var result = CsvHilfe.Parse(CsvHilfe.ChromeHeader + ",https://www.galaxus.ch/de,anna,p,\n,,bob,p,\n");
        Assert.Equal("galaxus.ch", result.Entries[0].Title);
        Assert.Equal("", result.Entries[1].Title);
    }

    [Fact]
    public void ReasonCodes()
    {
        Assert.Equal(CsvImport.ReasonCodes.Length, CsvImport.ReasonCodes.Distinct(StringComparer.Ordinal).Count());
        Assert.All(CsvImport.ReasonCodes, c =>
        {
            Assert.StartsWith("csv.", c, StringComparison.Ordinal);
            Assert.True(c.All(char.IsAscii));
        });
    }
}
