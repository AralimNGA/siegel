#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Krypto-Befunde vom 18.10.2026 (Windows, Etappe 1): krypto-1 (U+FFFE), krypto-3 (Ersatz-Kennungen beim Import in der
/// Windows-Hello-Art), krypto-4 (Passwort- und Schlüsselvergleich wie Swift-String). Die Swift-Tresore zu krypto-1/2
/// prüft <see cref="SwiftUnicodeTests"/>, den Korpus Swift ↔ C# <c>NormalisierungTests</c>.
/// </summary>
public class KryptoBefundeWindowsTests
{
    private const string Nfd = "Cafe\u0301-Passwort-12";
    private const string Nfc = "Caf\u00E9-Passwort-12";

    // MARK: krypto-1

    /// <summary>Kein Weg durch die öffentliche Schnittstelle wirft bei U+FFFE etwas anderes als SiegelException (vorher:
    /// ArgumentException aus string.Normalize in Create, Unlock, PasswordsMatch, Upsert, Import, Wechsel, Notfall).</summary>
    [Fact]
    public void Fffe_ueberall_ohne_fremde_Ausnahme()
    {
        const string master = "Wq7!vTz#2pLm\uFFFE9@Xc4$Rb8&Hn";
        using var f = KernVault.Make(master);
        Assert.True(VaultStore.PasswordsMatch(master, master));
        Assert.True(f.Vault.Verify(master));
        f.Vault.Upsert(KT.Entry("Eins", password: "abc\uFFFEdef"));
        var e = Assert.Single(f.Vault.Entries);
        e.Password = "neu\uFFFEwert";
        f.Vault.Upsert(e);
        Assert.Equal(["abc\uFFFEdef"], Assert.Single(f.Vault.Entries).History.Select(h => h.Password));
        var r = f.Vault.ImportEntries([KT.Entry("Eins", password: "neu\uFFFEwert"), KT.Entry("Zwei", "bert", "x\uFFFEy")]);
        Assert.Equal((1, 1, 0), (r.Added, r.SkippedDuplicates, r.Conflicts));
        Assert.Empty(f.Vault.MasterPasswordReuse);
        f.Vault.Upsert(KT.Entry("Gleich", password: master));
        Assert.Single(f.Vault.MasterPasswordReuse);
        f.Vault.ChangeMasterPassword(master, "Neu\uFFFE" + KT.Pw2);
        f.Vault.Lock();
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(master));
        var v = KT.Unlocked(f.Store.Unlock("Neu\uFFFE" + KT.Pw2))!;
        v.Lock();
        // Das alte Master-Passwort steht im Eintrag „Gleich“ → als neues abgelehnt (Tag über U+FFFE gerechnet).
        KT.Throws(SiegelErrorCode.MasterPasswordReused, () => f.Store.Recover(f.Code, master, KT.Kdf));
        var neu = f.Store.Recover(f.Code, "Notfall\uFFFE" + KT.Pw1, KT.Kdf);
        Assert.Equal(3, neu.Entries.Count);
        neu.Lock();
    }

    // MARK: krypto-3

    /// <summary>Stufe 4, Windows-Hello-Art: Ersatz-Kennungen bleiben über die Sammelrunden gleich – je neuem Eintrag
    /// genau eine Signatur (vorher 4 Runden × n Abfragen, dann FactorMissing, nichts geschrieben).</summary>
    [Fact]
    public async Task Hello_Import_mit_vergebenen_Kennungen_signiert_je_Eintrag_einmal()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal, hello: true);
        var items = new List<VaultEntry> { KT.Entry("Shop"), KT.Entry("Velo", user: "velo") };
        Assert.Equal(2, (await t.Vault.ImportEntriesAsync(items, t.P)).Added);

        // gleiche Kennungen, anderes Passwort: Konflikt → neuer Eintrag „(Import)“ mit Ersatz-Kennung
        var anders = items.Select(e =>
        {
            var c = e.Copy();
            c.Password = "Anders-456";
            return c;
        }).ToList();
        var vorher = t.P.HelloCount;
        var gen = t.Vault.Generation;
        var report = await t.Vault.ImportEntriesAsync(anders, t.P);
        Assert.Equal((2, 0, 2), (report.Added, report.SkippedDuplicates, report.Conflicts));
        Assert.Equal(vorher + 2, t.P.HelloCount);
        Assert.Equal(gen + 1, t.Vault.Generation);
        var neu = t.Vault.Entries.Where(e => e.Title.EndsWith("(Import)", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, neu.Count);
        Assert.All(neu, e => Assert.DoesNotContain(e.Id, items.Select(i => i.Id)));
        foreach (var e in neu) { Assert.Equal("Anders-456", (await t.Vault.RevealSecretsAsync(e.Id, t.P)).Password); }

        // gleiche Kennung zweimal im selben Import, ohne Konflikt (anderer Host): zwei getrennte Ersatz-Kennungen
        var doppelt = new List<VaultEntry>
        {
            KT.Entry("A", "a", "Pw-a-1", "https://a.example.org"), KT.Entry("B", "b", "Pw-b-1", "https://b.example.org"),
        };
        doppelt[0].Id = doppelt[1].Id = items[0].Id;
        vorher = t.P.HelloCount;
        report = await t.Vault.ImportEntriesAsync(doppelt, t.P);
        Assert.Equal((2, 0, 0), (report.Added, report.SkippedDuplicates, report.Conflicts));
        Assert.Equal(vorher + 2, t.P.HelloCount);
        var a = Assert.Single(t.Vault.Entries, e => e.Title == "A");
        var b = Assert.Single(t.Vault.Entries, e => e.Title == "B");
        Assert.NotEqual(a.Id, b.Id);
        Assert.Equal("Pw-a-1", (await t.Vault.RevealSecretsAsync(a.Id, t.P)).Password);
        Assert.Equal("Pw-b-1", (await t.Vault.RevealSecretsAsync(b.Id, t.P)).Password);
        Assert.Equal(6, t.Vault.Entries.Select(e => e.Id).Distinct().Count());
    }

    /// <summary>Die Ersatz-Kennung hängt an (Original, Stelle) und bleibt im selben HelloSealing gleich.</summary>
    [Fact]
    public void Ersatz_Kennung_stabil_je_Original_und_Stelle()
    {
        using var h = new HelloSealing();
        var id = Guid.NewGuid();
        var erste = h.ReplacementId(id, 0);
        Assert.Equal(erste, h.ReplacementId(id, 0));
        Assert.NotEqual(erste, h.ReplacementId(id, 1));
        Assert.NotEqual(erste, id);
    }

    // MARK: krypto-4

    /// <summary>Bestand „Café“ in NFD, Import in NFC mit gleichem Host und Benutzer: Swift überspringt (gemessen:
    /// skipped = 1), C# legte vorher „Shop (Import)“ an.</summary>
    [Fact]
    public void Import_haelt_NFD_und_NFC_fuer_dasselbe_Passwort()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("Shop", "anna", Nfd, "https://shop.example.ch"));
        var r = f.Vault.ImportEntries([KT.Entry("Shop", "anna", Nfc, "https://shop.example.ch")]);
        Assert.Equal((0, 1, 0), (r.Added, r.SkippedDuplicates, r.Conflicts));
        Assert.Equal(["Shop"], f.Vault.Entries.Select(e => e.Title));
        // Innerhalb desselben Imports ebenso
        r = f.Vault.ImportEntries([KT.Entry("Velo", "bert", Nfc, "https://velo.example.ch"), KT.Entry("Velo", "bert", Nfd, "https://velo.example.ch")]);
        Assert.Equal((1, 1, 0), (r.Added, r.SkippedDuplicates, r.Conflicts));
    }

    /// <summary>Auch der Doppel-Schlüssel (Host + Benutzer) vergleicht kanonisch: „Jörg“ in NFD und NFC.</summary>
    [Fact]
    public void Import_haelt_NFD_und_NFC_fuer_denselben_Benutzer()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("Bank", "Jo\u0308rg", "Konto-Pw-77", "https://bank.example.ch"));
        var r = f.Vault.ImportEntries([KT.Entry("Bank", "J\u00F6rg", "Konto-Pw-77", "https://bank.example.ch")]);
        Assert.Equal((0, 1, 0), (r.Added, r.SkippedDuplicates, r.Conflicts));
        r = f.Vault.ImportEntries([KT.Entry("Bank", "J\u00F6rg", "Anderes-Pw-88", "https://bank.example.ch")]);
        Assert.Equal((1, 0, 1), (r.Added, r.SkippedDuplicates, r.Conflicts));
        Assert.Contains("Bank (Import)", f.Vault.Entries.Select(e => e.Title));
        // Leerzeichen bildet Swift dabei nicht ab: U+00A0 ≠ U+0020
        r = f.Vault.ImportEntries([KT.Entry("Bank", "J\u00F6rg", "Konto-Pw\u00A077", "https://bank.example.ch")]);
        Assert.Equal((1, 0, 1), (r.Added, r.SkippedDuplicates, r.Conflicts));
    }

    /// <summary>Dasselbe Passwort in NFC neu gespeichert: kein Verlaufseintrag (Swift: history = 0, gemessen); die
    /// gespeicherten Bytes sind die neuen (NFC), wie in Swift.</summary>
    [Fact]
    public void Upsert_mit_kanonisch_gleichem_Passwort_ohne_Verlauf()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("Shop", password: Nfd));
        var e = Assert.Single(f.Vault.Entries);
        e.Password = Nfc;
        f.Vault.Upsert(e);
        e = Assert.Single(f.Vault.Entries);
        Assert.Empty(e.History);
        Assert.Equal(Nfc, e.Password);
        // Verlauf mit einem kanonisch gleichen Wert wird um ihn bereinigt (removeAll mit ==)
        e.Password = "Ganz-Neu-1";
        f.Vault.Upsert(e);
        e = Assert.Single(f.Vault.Entries);
        e.Password = Nfd;
        f.Vault.Upsert(e);
        Assert.Equal(["Ganz-Neu-1"], Assert.Single(f.Vault.Entries).History.Select(h => h.Password));
        // Neuer Eintrag mit einem Verlaufswert, der dem Passwort kanonisch gleicht
        f.Vault.Upsert(new VaultEntry { Title = "Neu", Password = Nfc, History = [new PasswordHistoryItem(Nfd, Clock.Now())] });
        Assert.Empty(Assert.Single(f.Vault.Entries, x => x.Title == "Neu").History);
    }

    [Fact]
    public void ReplacingPassword_und_SetProtection_kanonisch()
    {
        var s = new EntrySecrets { Password = Nfd, History = [new PasswordHistoryItem("Alt-1", Clock.Now())] };
        var gleich = s.ReplacingPassword(Nfc);
        Assert.Equal(Nfd, gleich.Password);                                    // Swift: guard new != password → self
        Assert.Equal(["Alt-1"], gleich.History.Select(h => h.Password));
        var neu = s.ReplacingPassword("Alt-1");
        Assert.Equal(["Cafe\u0301-Passwort-12"], neu.History.Select(h => h.Password));

        using var t = SchutzTresor.Make(SecurityLevel.Standard);
        t.Vault.Upsert(KT.Entry("Shop", password: "Erst-1"));
        var id = Assert.Single(t.Vault.Entries).Id;
        t.Vault.SetProtection(EntryProtection.Normal, id,
            new EntrySecrets { Password = Nfc, History = [new PasswordHistoryItem(Nfd, Clock.Now()), new PasswordHistoryItem("Alt-2", Clock.Now())] });
        Assert.Equal(["Alt-2"], Assert.Single(t.Vault.Entries).History.Select(h => h.Password));
    }

    [Fact]
    public void Vergleich_wie_Swift_String()
    {
        var v = SwiftStringComparer.Instance;
        Assert.True(v.Equals(Nfd, Nfc));
        Assert.Equal(v.GetHashCode(Nfd), v.GetHashCode(Nfc));
        Assert.False(v.Equals("a b", "a\u00A0b"));
        Assert.True(v.Equals("\u212B", "\u00C5"));
        Assert.True(v.Equals("abc\uFFFEdef", "abc\uFFFEdef"));
        var set = new HashSet<string>(v) { Nfd };
        Assert.Contains(Nfc, set);
    }
}
#endif
