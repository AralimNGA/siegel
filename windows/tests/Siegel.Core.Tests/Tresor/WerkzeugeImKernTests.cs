#if DEBUG
using Siegel.Modell;
using Siegel.Werkzeuge;
using Siegel.Werkzeuge.Tests;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Integration Etappe 1: der Kern mit den echten Werkzeugen (ohne Testschalter für die Exporter). CSV-Export über den
/// Tresor → CSV-Import → zweiter Tresor; KeePass-Export über den Tresor → unabhängiger KDBX-Leser; Bericht und
/// Master-Passwort-Regel mit der echten zxcvbn-Schätzung.
/// </summary>
[Collection("EchteProfile")]
public class WerkzeugeImKernTests
{
    private static VaultEntry Eintrag(string title, string user, string password, string url, string notes) =>
        new() { Title = title, Username = user, Password = password, Url = url, Notes = notes };

    [Fact]
    public void Csv_Export_echt_laesst_sich_wieder_importieren()
    {
        using var a = KernVault.Make();
        VaultEntry[] originale =
        [
            Eintrag("Bank, Zürich", "anna@example.ch", "Pw-mit-\"Zitat\",Komma", "https://bank.example.ch/login", "Zeile 1\nZeile \"2\""),
            Eintrag("Grüezi-Shop", "bob", "Ünïcödé-ß-€-漢字", "shop.example", ""),
            Eintrag("Nur Notiz", "", "", "", "Geheime Notiz"),
        ];
        foreach (var e in originale) { a.Vault.Upsert(e); }
        var geloescht = Eintrag("Weg", "x", "geloescht-1", "weg.example", "");
        a.Vault.Upsert(geloescht);
        a.Vault.Delete(geloescht.Id);

        var url = a.Vault.ExportCsv(a.Dir.Sub("Export"), KT.Pw1);
        var data = File.ReadAllBytes(url);
        Assert.Equal(CsvExport.Export(a.Vault.Entries.Select(e => (e, SchutzEntries.SecretsOf(e))).ToList()), data);
        var text = System.Text.Encoding.UTF8.GetString(data);
        Assert.StartsWith("\"name\",\"url\",\"username\",\"password\",\"note\"\r\n", text, StringComparison.Ordinal);
        Assert.DoesNotContain("geloescht-1", text, StringComparison.Ordinal);

        var gelesen = CsvImport.Parse(data);
        Assert.Equal(CsvFormat.Chrome, gelesen.Format);
        Assert.Equal(originale.Length, gelesen.Entries.Count);
        for (var i = 0; i < originale.Length; i++)
        {
            var (o, g) = (originale[i], gelesen.Entries[i]);
            Assert.Equal((o.Title, o.Url, o.Username, o.Password, o.Notes), (g.Title, g.Url, g.Username, g.Password, g.Notes));
        }

        using var b = KernVault.Make(KT.Pw2);
        var report = b.Vault.ImportEntries(gelesen.Entries);
        Assert.Equal(originale.Length, report.Added);
        Assert.Equal(0, report.SkippedDuplicates);
        Assert.Equal(originale.Select(o => (o.Title, o.Url, o.Username, o.Password, o.Notes)),
            b.Vault.Entries.Select(g => (g.Title, g.Url, g.Username, g.Password, g.Notes)));
        // Ein zweiter Import derselben Datei bringt nur Dubletten (Abgleich nach Host + Benutzer + Passwort)
        Assert.Equal(0, b.Vault.ImportEntries(CsvImport.Parse(data).Entries).Added);
    }

    [Fact]
    public async Task KeePass_Export_echt_mit_unabhaengigem_Leser()
    {
        using var t = SchutzTresor.Make();
        var list = new Dictionary<EntryProtection, VaultEntry>();
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var e = SchutzEntries.Make("E" + (int)p, p);
            t.Vault.Upsert(e);
            list[p] = e;
        }
        var url = await t.Vault.ExportKeePassAsync(t.F.Dir.Sub("Export"), KT.Pw1, new FactorSecrets(), KT.Pw4, t.P);
        Assert.Equal([1, 0, 0], t.P.Counts);
        var data = File.ReadAllBytes(url);

        var datei = KdbxLeser.Lesen(data, KT.Pw4);
        Assert.Equal("Siegel", datei.Gruppe);
        var erwartet = new[] { EntryProtection.Normal, EntryProtection.Fingerabdruck, EntryProtection.Hoch }.Select(p => list[p]).ToList();
        Assert.Equal(erwartet.Select(e => e.Title).Order(StringComparer.Ordinal),
            datei.Eintraege.Select(e => e.Werte["Title"]).Order(StringComparer.Ordinal));
        foreach (var o in erwartet)
        {
            var g = datei.Eintraege.Single(e => e.Werte["Title"] == o.Title);
            Assert.Equal(o.Password, g.Werte["Password"]);
            Assert.Equal(o.Username, g.Werte["UserName"]);
            Assert.Equal(o.Url, g.Werte["URL"]);
            Assert.Equal(o.Notes, g.Werte["Notes"]);
            Assert.Contains("Password", g.Geschuetzt);
        }
        // Schutz 4/5 und der Verlauf fehlen ganz
        foreach (var p in new[] { EntryProtection.Maximal, EntryProtection.Festung })
        {
            Assert.DoesNotContain(list[p].Password, datei.Xml, StringComparison.Ordinal);
            Assert.DoesNotContain(list[p].Title, datei.Eintraege.Select(e => e.Werte["Title"]));
        }
        Assert.DoesNotContain("Alt-E1", datei.Xml, StringComparison.Ordinal);

        // Falsches Passwort: der Kopf-HMAC passt nicht
        var falsch = Assert.Throws<KdbxLeserException>(() => KdbxLeser.Lesen(data, KT.Pw1));
        Assert.Equal(KdbxFehler.KopfHmac, falsch.Fehler);
    }

    [Fact]
    public void Bericht_nutzt_die_echte_Staerke()
    {
        using var f = KernVault.Make();
        string[] passwoerter = ["passwort", "123456", "Sommer2024", KT.Pw3, "kQ9#vT2!mZ7@xR4$"];
        var ids = new Dictionary<string, Guid>();
        foreach (var pw in passwoerter)
        {
            var e = KT.Entry("T-" + ids.Count, "user" + ids.Count, pw, "s" + ids.Count + ".example");
            f.Vault.Upsert(e);
            ids[pw] = e.Id;
        }
        var report = f.Vault.SecurityReport();
        var erwartet = passwoerter.Where(pw => PasswordStrength.Estimate(pw).Level < StrengthLevel.Fair).Select(pw => ids[pw]).ToHashSet();
        Assert.Equal(erwartet, report.Weak.ToHashSet());
        Assert.Contains(ids["passwort"], report.Weak);
        Assert.Contains(ids["123456"], report.Weak);
        Assert.DoesNotContain(ids[KT.Pw3], report.Weak);
        Assert.Equal(passwoerter.Length, report.Total);
    }

    [Fact]
    public void Master_Regel_mit_echter_Schaetzung()
    {
        using var dir = new KernTempDir();
        var store = VaultStore.ForTesting(Path.Combine(dir.Path, "Siegel"), new InMemoryRollbackGuard());
        foreach (var pw in new[] { "Passwort1234!", "siegelsiegelsiegel", "qwertzuiopasdfgh" })
        {
            var (bits, ok) = MasterPasswordPolicy.Check(pw);
            Assert.False(ok);
            var e = KT.Throws(SiegelErrorCode.PasswordTooWeak, () => store.Create(pw, KT.Kdf));
            Assert.Equal(bits, e.Bits);
            Assert.True(e.Bits < MasterPasswordPolicy.MinimumBits);
        }
        Assert.False(File.Exists(store.VaultPath));
        var (vault, pending) = store.Create(KT.Pw1, KT.Kdf);
        using (vault)
        {
            Assert.NotNull(pending);
        }
    }
}
#endif
