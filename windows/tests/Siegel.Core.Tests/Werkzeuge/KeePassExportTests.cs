using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Tests;

internal static class KdbxHilfe
{
    /// <summary>Testschalter: Argon2id t = 1, 64 KiB (wie kdbxTestKDF auf dem Mac).</summary>
    internal static readonly KdbxKdf TestKdf = new(1, 64 << 10);

    /// <summary>20 Zufallszeichen: erfüllt die Master-Passwort-Regel (gilt auch für das Export-Passwort).</summary>
    internal const string Passwort = "kV7#pQ2$mZ9!xR4@tL8&";

    internal static byte[] Export(IEnumerable<(VaultEntry, EntrySecrets)> items, string? passwort = null) =>
        KeePassExport.Kdbx(items, passwort ?? Passwort, TestKdf, DateTimeOffset.UtcNow);

    internal static VaultEntry Eintrag(string title = "", string user = "", string password = "", string url = "",
        string notes = "", string totp = "", EntryProtection protection = EntryProtection.Normal) =>
        new() { Title = title, Username = user, Password = password, Url = url, Notes = notes, Totp = totp, Protection = protection };

    /// <summary>Erfundene Einträge mit allem, was im XML schwierig ist (wie kdbxBeispielEintraege).</summary>
    internal static List<(VaultEntry, EntrySecrets)> Beispiele()
    {
        (VaultEntry, EntrySecrets) E(string title, string user, string password, string url, string notes, string totp = "")
        {
            var e = Eintrag(title, user, password, url, notes, totp);
            e.Created = DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_700);
            e.Modified = DateTimeOffset.FromUnixTimeSeconds(1_760_000_000);
            return (e, new EntrySecrets { Password = password, Notes = notes, Totp = totp });
        }
        return
        [
            E("Bank <Privat> & Co", "anna\"o'neil", "Pa$$w0rd <&> \"'", "https://bank.example.ch/login?a=1&b=2",
                "Zeile 1\r\nZeile 2\nZeile 3\r", "otpauth://totp/Bank:anna?secret=JBSWY3DPEHPK3PXP&issuer=Bank"),
            E("Zürich Velo 🚲", "jürg", "🔑Äöü e\u0301 \u00A0", "https://bücher.de", "«Guillemets» — ‹›", "jbsw y3dp ehpk 3pxp"),
            E("Steuer\u0007zeichen", "u\u001F", "\u0000\t\r\n\u202Ex", "", "Nul\u0000im Text\uFFFF"),
            E("", "", "", "", ""),
            E("   ", "", "  ", "", "\t", "kein-geheimnis"),
            E("]]> <![CDATA[ x ]]>", "&amp;", "&#13;", "<!-- -->", "<?xml?>"),
        ];
    }

    internal static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
}

/// <summary>KeePass-Export KDBX 4.1 (SPEC §19; Port von KeePassExportTests.swift).</summary>
public class KeePassRundlaufTests
{
    [Fact]
    public void AlleFelderBytegenauPasswordUndOtpGeschuetzt()
    {
        var items = KdbxHilfe.Beispiele();
        var datei = KdbxLeser.Lesen(KdbxHilfe.Export(items), KdbxHilfe.Passwort);
        Assert.Equal(0x0004_0001u, datei.Version);
        Assert.Equal("Siegel", datei.Gruppe);
        Assert.Equal(items.Count, datei.Eintraege.Count);
        for (var i = 0; i < items.Count; i++)
        {
            var (entry, secrets) = items[i];
            var gelesen = datei.Eintraege[i];
            Assert.Equal(KeePassExport.UuidBytes(entry.Id), gelesen.Uuid);
            Assert.Equal(entry.Id.ToString("D").Replace("-", "", StringComparison.Ordinal), Convert.ToHexStringLower(gelesen.Uuid));
            Assert.Equal(KdbxHilfe.Utf8(entry.Title), KdbxHilfe.Utf8(gelesen.Werte.GetValueOrDefault("Title", "-")));
            Assert.Equal(KdbxHilfe.Utf8(entry.Username), KdbxHilfe.Utf8(gelesen.Werte.GetValueOrDefault("UserName", "-")));
            Assert.Equal(KdbxHilfe.Utf8(secrets.Password), KdbxHilfe.Utf8(gelesen.Werte.GetValueOrDefault("Password", "-")));
            Assert.Equal(KdbxHilfe.Utf8(entry.Url), KdbxHilfe.Utf8(gelesen.Werte.GetValueOrDefault("URL", "-")));
            Assert.Equal(KdbxHilfe.Utf8(secrets.Notes), KdbxHilfe.Utf8(gelesen.Werte.GetValueOrDefault("Notes", "-")));
            Assert.Contains("Password", gelesen.Geschuetzt);
            Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(entry.Created.ToUnixTimeSeconds()), gelesen.Erstellt);
            Assert.Equal(entry.Modified, gelesen.Geaendert);
        }
        var e = datei.Eintraege;
        Assert.Equal("otpauth://totp/Bank:anna?secret=JBSWY3DPEHPK3PXP&issuer=Bank", e[0].Werte["otp"]);
        Assert.Equal("otpauth://totp/Z%C3%BCrich%20Velo%20%F0%9F%9A%B2?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1",
            e[1].Werte["otp"]);
        using (var gelesen = Totp.Parse(e[1].Werte["otp"]))
        using (var basis = Totp.Parse("JBSWY3DPEHPK3PXP"))
        using (var erwartet = TotpHilfe.MitLabel(basis, "", "Zürich Velo 🚲"))
        {
            Assert.Equal(erwartet, gelesen);
        }
        Assert.Equal("kein-geheimnis", e[4].Werte["otp"]);
        Assert.False(e[2].Werte.ContainsKey("otp"));
        Assert.False(e[3].Werte.ContainsKey("otp"));
        Assert.Contains("otp", e[0].Geschuetzt);
        Assert.Equal(["Password", "Title", "UserName", "Notes"], e[2].Geschuetzt);
        Assert.Equal(["Password", "Title", "Notes", "otp"], e[4].Geschuetzt);
        Assert.Equal(["Password", "otp"], e[0].Geschuetzt);
        Assert.DoesNotContain("Pa$$w0rd", datei.Xml, StringComparison.Ordinal);
        Assert.DoesNotContain("JBSWY3DPEHPK3PXP", datei.Xml, StringComparison.Ordinal);
        Assert.Contains("Bank &lt;Privat&gt; &amp; Co", datei.Xml, StringComparison.Ordinal);
        Assert.Contains("Zeile 1&#13;\nZeile 2", datei.Xml, StringComparison.Ordinal);
    }

    [Fact]
    public void Kopf()
    {
        var data = KdbxHilfe.Export(KdbxHilfe.Beispiele());
        Assert.Equal(new byte[] { 0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x01, 0x00, 0x04, 0x00 }, data[..12]);
        var datei = KdbxLeser.Lesen(data, KdbxHilfe.Passwort);
        Assert.Equal(KdbxLeser.ChaCha20, datei.KopfFelder[2]);
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, datei.KopfFelder[3]);
        Assert.Equal(32, datei.KopfFelder[4].Length);
        Assert.Equal(12, datei.KopfFelder[7].Length);
        Assert.Equal(new byte[] { 0x0D, 0x0A, 0x0D, 0x0A }, datei.KopfFelder[0]);
        Assert.Equal(new HashSet<byte> { 0, 2, 3, 4, 7, 11 }, datei.KopfFelder.Keys.ToHashSet());
        Assert.Equal(KdbxLeser.Argon2id, datei.Kdf["$UUID"]);
        Assert.Equal(16, datei.Kdf["S"].Length);
        Assert.Equal(new byte[] { 1, 0, 0, 0 }, datei.Kdf["P"]);
        Assert.Equal(new byte[] { 0x13, 0, 0, 0 }, datei.Kdf["V"]);
        Assert.Equal(KeePassExport.Le(64UL << 10), datei.Kdf["M"]);
        Assert.Equal(KeePassExport.Le(1UL), datei.Kdf["I"]);
        Assert.Equal(new Dictionary<string, byte> { ["$UUID"] = 0x42, ["S"] = 0x42, ["P"] = 0x04, ["M"] = 0x05, ["I"] = 0x05, ["V"] = 0x04 },
            datei.KdfTypen);
        Assert.Equal(3u, datei.InnererStromId);
        Assert.Equal(2, datei.Bloecke);
        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile>", datei.Xml, StringComparison.Ordinal);
    }

    [Fact]
    public void ZweiExporteUnterscheidenSichVollstaendig()
    {
        var items = KdbxHilfe.Beispiele();
        var a = KdbxHilfe.Export(items);
        var b = KdbxHilfe.Export(items);
        Assert.NotEqual(a, b);
        Assert.Equal(a.Length, b.Length);
        var a1 = KdbxLeser.Lesen(a, KdbxHilfe.Passwort);
        var b1 = KdbxLeser.Lesen(b, KdbxHilfe.Passwort);
        Assert.NotEqual(a1.KopfFelder[4], b1.KopfFelder[4]);
        Assert.NotEqual(a1.KopfFelder[7], b1.KopfFelder[7]);
        Assert.NotEqual(a1.Kdf["S"], b1.Kdf["S"]);
        for (var i = 0; i < a1.Eintraege.Count; i++)
        {
            Assert.Equal(a1.Eintraege[i].Werte, b1.Eintraege[i].Werte);
            Assert.Equal(a1.Eintraege[i].Uuid, b1.Eintraege[i].Uuid);
        }
    }

    [Fact]
    public void MehrereBloecke()
    {
        var notiz = string.Concat(Enumerable.Repeat("Notiz mit viel Text. ", 12_000));
        var items = Enumerable.Range(0, 6).Select(i =>
            (KdbxHilfe.Eintrag($"Eintrag {i}", $"u{i}", $"pw-{i}", "", notiz), new EntrySecrets { Password = $"pw-{i}", Notes = notiz })).ToList();
        var datei = KdbxLeser.Lesen(KdbxHilfe.Export(items), KdbxHilfe.Passwort);
        Assert.Equal(3, datei.Bloecke);
        Assert.All(datei.Eintraege, e => Assert.Equal(notiz, e.Werte["Notes"]));
        Assert.Equal(Enumerable.Range(0, 6).Select(i => $"pw-{i}"), datei.Eintraege.Select(e => e.Werte["Password"]));
    }

    [Fact]
    public void LeereListe()
    {
        var datei = KdbxLeser.Lesen(KdbxHilfe.Export([]), KdbxHilfe.Passwort);
        Assert.Empty(datei.Eintraege);
        Assert.Equal("Siegel", datei.Gruppe);
    }
}

public class KeePassRegelnTests
{
    [Fact]
    public void AuswahlOhneGeloeschteSchutz45UndVerlauf()
    {
        var geloescht = KdbxHilfe.Eintrag("Gelöscht", password: "weg");
        geloescht.DeletedAt = DateTimeOffset.UtcNow;
        var maximal = KdbxHilfe.Eintrag("Maximal", password: "nie-exportieren", protection: EntryProtection.Maximal);
        var festung = KdbxHilfe.Eintrag("Festung", password: "nie-exportieren-2", protection: EntryProtection.Festung);
        var hoch = KdbxHilfe.Eintrag("Hoch", password: "hoch-pw", protection: EntryProtection.Hoch);
        var mitVerlauf = KdbxHilfe.Eintrag("Verlauf", password: "neu");
        mitVerlauf.History = [new PasswordHistoryItem("altes-geheimnis", DateTimeOffset.UtcNow)];
        var items = new List<(VaultEntry, EntrySecrets)>
        {
            (geloescht, new EntrySecrets { Password = "weg" }), (maximal, new EntrySecrets { Password = "nie-exportieren" }),
            (festung, new EntrySecrets { Password = "nie-exportieren-2" }), (hoch, new EntrySecrets { Password = "hoch-pw" }),
            (mitVerlauf, new EntrySecrets { Password = "neu", History = mitVerlauf.History }),
        };
        var datei = KdbxLeser.Lesen(KdbxHilfe.Export(items), KdbxHilfe.Passwort);
        Assert.Equal(["Hoch", "Verlauf"], datei.Eintraege.Select(e => e.Werte["Title"]));
        Assert.Equal(["hoch-pw", "neu"], datei.Eintraege.Select(e => e.Werte["Password"]));
        Assert.DoesNotContain("<History>", datei.Xml, StringComparison.Ordinal);
        Assert.Contains("<History/>", datei.Xml, StringComparison.Ordinal);
        Assert.DoesNotContain("altes-geheimnis", datei.Xml, StringComparison.Ordinal);
    }

    [Fact]
    public void GeheimteileAusEntrySecrets()
    {
        var offen = KdbxHilfe.Eintrag("Offen", password: "aus-dem-eintrag", notes: "Notiz", totp: "JBSWY3DPEHPK3PXP");
        var datei = KdbxLeser.Lesen(KdbxHilfe.Export([(offen, new EntrySecrets())]), KdbxHilfe.Passwort);
        Assert.Equal("aus-dem-eintrag", datei.Eintraege[0].Werte["Password"]);
        Assert.Equal("Notiz", datei.Eintraege[0].Werte["Notes"]);
        Assert.StartsWith("otpauth://totp/Offen?secret=JBSWY3DPEHPK3PXP", datei.Eintraege[0].Werte["otp"], StringComparison.Ordinal);
        var versiegelt = KdbxHilfe.Eintrag("Zu", protection: EntryProtection.Fingerabdruck);
        versiegelt.SecretsSealed = true;
        var zweite = KdbxLeser.Lesen(KdbxHilfe.Export([(versiegelt, new EntrySecrets { Password = "aufgedeckt" })]), KdbxHilfe.Passwort);
        Assert.Equal("aufgedeckt", zweite.Eintraege[0].Werte["Password"]);
    }

    [Fact]
    public void ExportPasswortMussRegelErfuellen()
    {
        foreach (var schwach in new[] { "", "kurz", "Passwort1234!", "aaaaaaaaaaaaaaaaaaaa" })
        {
            var e = Assert.Throws<SiegelException>(() => KdbxHilfe.Export([], schwach));
            Assert.Equal(SiegelErrorCode.PasswordTooWeak, e.Code);
            Assert.NotNull(e.Bits);
        }
    }

    [Fact]
    public void FalschesPasswortScheitertAmKopfHmac()
    {
        var data = KdbxHilfe.Export(KdbxHilfe.Beispiele());
        Assert.Equal(KdbxFehler.KopfHmac, Assert.Throws<KdbxLeserException>(() => KdbxLeser.Lesen(data, KdbxHilfe.Passwort + "x")).Fehler);
        Assert.Equal(KdbxFehler.KopfHmac, Assert.Throws<KdbxLeserException>(() => KdbxLeser.Lesen(data, "kV7#pQ2$mZ9!xR4@tL8")).Fehler);
    }

    [Fact]
    public void JedesGekippteByteWirdErkannt()
    {
        var data = KdbxHilfe.Export([KdbxHilfe.Beispiele()[0]]);
        var bytes = (byte[])data.Clone();
        var stellen = Enumerable.Range(0, Math.Min(300, bytes.Length)).Concat(Enumerable.Range(0, (bytes.Length + 6) / 7).Select(k => k * 7))
            .Where(s => s < bytes.Length).Distinct().Order();
        foreach (var stelle in stellen)
        {
            bytes[stelle] ^= 0x01;
            Assert.ThrowsAny<Exception>(() => KdbxLeser.Lesen(bytes, KdbxHilfe.Passwort));
            bytes[stelle] ^= 0x01;
        }
        Assert.Equal(KdbxFehler.Kurz, Assert.Throws<KdbxLeserException>(() => KdbxLeser.Lesen(data[..^1], KdbxHilfe.Passwort)).Fehler);
        Assert.Equal(KdbxFehler.Restbytes, Assert.Throws<KdbxLeserException>(() => KdbxLeser.Lesen([.. data, 0], KdbxHilfe.Passwort)).Fehler);
        Assert.Single(KdbxLeser.Lesen(bytes, KdbxHilfe.Passwort).Eintraege);
    }

    [Fact]
    public void Zeiten()
    {
        Assert.Equal(Convert.ToBase64String(KeePassExport.Le(62_135_596_800UL)), KeePassExport.TimeText(DateTimeOffset.UnixEpoch));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_234_567_890),
            KdbxLeser.Zeit(KeePassExport.TimeText(DateTimeOffset.FromUnixTimeMilliseconds(1_234_567_890_900))));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(-62_000_000_000), KdbxLeser.Zeit(KeePassExport.TimeText(DateTimeOffset.MinValue)));
        // vor 1970: abgerundet wie floor
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(-2), KdbxLeser.Zeit(KeePassExport.TimeText(DateTimeOffset.FromUnixTimeMilliseconds(-1500))));
    }

    [Fact]
    public void UuidInRfcReihenfolge()
    {
        var id = Guid.Parse("6A0B7C1E-3F4D-4E2A-9B8C-1D2E3F405162");
        Assert.Equal(Convert.FromHexString("6A0B7C1E3F4D4E2A9B8C1D2E3F405162"), KeePassExport.UuidBytes(id));
    }
}

/// <summary>Echte Argon2-Parameter (256 MiB, t = 3).</summary>
[Collection("Argon2 gross")]
public class KeePassEchteParameterTests
{
    [Fact]
    public void KdbxNutztArgon2idT3M256P1()
    {
        var items = KdbxHilfe.Beispiele();
        var data = KeePassExport.Kdbx(items, KdbxHilfe.Passwort);
        var datei = KdbxLeser.Lesen(data, KdbxHilfe.Passwort);
        Assert.Equal(KeePassExport.Le(256UL << 20), datei.Kdf["M"]);
        Assert.Equal(KeePassExport.Le(3UL), datei.Kdf["I"]);
        Assert.Equal(new byte[] { 1, 0, 0, 0 }, datei.Kdf["P"]);
        Assert.Equal(items.Count, datei.Eintraege.Count);
    }
}
