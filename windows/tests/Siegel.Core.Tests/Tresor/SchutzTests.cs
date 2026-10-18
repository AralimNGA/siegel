#if DEBUG
using System.Security.Cryptography;
using Siegel.Core.Native;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Eintrags-Schutz (Gegenstück zu KernSchutzTests.swift): versiegeln, aufdecken, Regeln, Notfall, Kit- und
/// Faktorwechsel. Gegenseite: <see cref="SchutzProvider"/> (Software-P-256, feste q/y2).</summary>
public class SchutzTests
{
    internal static void Same(EntrySecrets expected, EntrySecrets got)
    {
        Assert.Equal(expected.Password, got.Password);
        Assert.Equal(expected.Notes, got.Notes);
        Assert.Equal(expected.Totp, got.Totp);
        Assert.Equal(expected.History, got.History);
    }

    internal static EntrySecrets S(VaultEntry e) => SchutzEntries.SecretsOf(e);

    private static string TotpMark(VaultEntry e) => e.Title + "?secret=JBSWY3DPEHPK3PXP";

    [Fact]
    public async Task Schutz_1_bis_5_versiegelt_Aufdecken_ruft_genau_die_Faktoren_der_Maske()
    {
        using var t = SchutzTresor.Make();
        Assert.Equal(FactorSet.All, t.Vault.EnrolledFactors);
        var originals = new Dictionary<EntryProtection, VaultEntry>();
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var e = SchutzEntries.Make("E" + (int)p, p);
            t.Vault.Upsert(e);
            originals[p] = e;
        }
        var json = t.F.JsonOnDisk();
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var o = originals[p];
            var stored = t.Vault.Entries.Single(x => x.Id == o.Id);
            Assert.Equal((o.Title, o.Username, o.Url), (stored.Title, stored.Username, stored.Url));
            Assert.Equal(p, stored.Protection);
            var hidden = p > EntryProtection.Normal;
            Assert.Equal(hidden, stored.SecretsSealed);
            if (hidden) { Assert.True(UnlockedVault.SecretsAreEmpty(stored)); }
            Assert.Equal(!hidden, json.Contains(o.Password, StringComparison.Ordinal));
            Assert.Equal(!hidden, json.Contains(o.Notes, StringComparison.Ordinal));
            Assert.Equal(!hidden, json.Contains(TotpMark(o), StringComparison.Ordinal));
            Assert.Equal(!hidden, json.Contains("Alt-" + o.Title, StringComparison.Ordinal));
        }
        var v = t.Reopen();
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var o = originals[p];
            t.P.Reset();
            Same(S(o), await v.RevealSecretsAsync(o.Id, p == EntryProtection.Normal ? null : t.P));
            var m = p.Factors();
            Assert.Equal([m.Contains(FactorKind.SecureEnclave) ? 1 : 0, m.Contains(FactorKind.Card) ? 1 : 0, m.Contains(FactorKind.SecurityKey) ? 1 : 0],
                t.P.Counts);
        }
        Assert.Equal(originals.Values.Select(x => x.Title).ToHashSet(), v.Entries.Select(x => x.Title).ToHashSet());
    }

    [Fact]
    public async Task Fehlerfaelle_nie_Geheimteile()
    {
        using var t = SchutzTresor.Make(enroll: FactorSet.SecureEnclave);
        var gen = t.Vault.Generation;
        KT.Throws(SiegelErrorCode.FactorMissing, "card", () => t.Vault.Upsert(SchutzEntries.Make("K", EntryProtection.Maximal)));
        KT.Throws(SiegelErrorCode.FactorMissing, "card", () => t.Vault.Upsert(SchutzEntries.Make("F", EntryProtection.Festung)));
        Assert.Equal(gen, t.Vault.Generation);
        Assert.Empty(t.Vault.Entries);
        var e = SchutzEntries.Make("A", EntryProtection.Hoch);
        t.Vault.Upsert(e);
        await KT.ThrowsAsync(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.RevealSecretsAsync(e.Id, null));
        Assert.Equal([0, 0, 0], t.P.Counts);
        KT.Throws(SiegelErrorCode.FactorMissing, "card", () => t.Vault.SetProtection(EntryProtection.Maximal, e.Id, S(e)));
        await KT.ThrowsAsync(SiegelErrorCode.Io, "entry.notFound", () => t.Vault.RevealSecretsAsync(Guid.NewGuid(), t.P));
        foreach (var (verhalten, code, detail) in new[]
                 {
                     (SchutzProvider.Verhalten.Falsch, SiegelErrorCode.WrongPassword, ""),
                     (SchutzProvider.Verhalten.Abbruch, SiegelErrorCode.FactorCancelled, ""),
                     (SchutzProvider.Verhalten.FremderFehler, SiegelErrorCode.FactorUnavailable, "secureEnclave"),
                     (SchutzProvider.Verhalten.NichtVerfuegbar, SiegelErrorCode.FactorUnavailable, "secureEnclave"),
                 })
        {
            t.P.Set(FactorKind.SecureEnclave, verhalten);
            var ex = await KT.ThrowsAsync(code, detail, () => t.Vault.RevealSecretsAsync(e.Id, t.P));
            Assert.DoesNotContain("Geheimnis", ex.Message, StringComparison.Ordinal);
        }
        t.P.Set(FactorKind.SecureEnclave, SchutzProvider.Verhalten.Richtig);
        Same(S(e), await t.Vault.RevealSecretsAsync(e.Id, t.P));
    }

    [Fact]
    public async Task Falsche_Karte_WrongCard_falscher_Schluessel_WrongPassword()
    {
        using var t = SchutzTresor.Make();
        var e = SchutzEntries.Make("F", EntryProtection.Festung);
        t.Vault.Upsert(e);
        t.P.Set(FactorKind.Card, SchutzProvider.Verhalten.Falsch);
        await KT.ThrowsAsync(SiegelErrorCode.WrongCard, () => t.Vault.RevealSecretsAsync(e.Id, t.P));
        Assert.Equal([1, 1, 0], t.P.Counts);
        t.P.Set(FactorKind.Card, SchutzProvider.Verhalten.Richtig);
        t.P.Set(FactorKind.SecurityKey, SchutzProvider.Verhalten.Falsch);
        t.P.Reset();
        await KT.ThrowsAsync(SiegelErrorCode.WrongPassword, () => t.Vault.RevealSecretsAsync(e.Id, t.P));
        Assert.Equal([1, 1, 1], t.P.Counts);
        t.P.Set(FactorKind.SecurityKey, SchutzProvider.Verhalten.Richtig);
        Same(S(e), await t.Vault.RevealSecretsAsync(e.Id, t.P));
    }

    [Fact]
    public async Task Sperren_waehrend_der_Freigabe_keine_Geheimteile()
    {
        using var t = SchutzTresor.Make();
        var e = SchutzEntries.Make("S", EntryProtection.Fingerabdruck);
        t.Vault.Upsert(e);
        var vault = t.Vault;
        t.P.OnAnswer(vault.Lock);
        await KT.ThrowsAsync(SiegelErrorCode.Io, "vault.locked", () => vault.RevealSecretsAsync(e.Id, t.P));
    }

    [Fact]
    public async Task Befund_ablaeufe4_gesperrt_zwischen_zwei_Faktoren()
    {
        using var t = SchutzTresor.Make();
        var e = SchutzEntries.Make("Krypto", EntryProtection.Festung);
        t.Vault.Upsert(e);
        var vault = t.Vault;
        t.P.OnAnswer(vault.Lock);
        await KT.ThrowsAsync(SiegelErrorCode.Io, "vault.locked", () => vault.RevealSecretsAsync(e.Id, t.P));
        Assert.Equal([1, 0, 0], t.P.Counts);
    }

    [Fact]
    public async Task Befund_ablaeufe4_neues_Kit_gesperrt_waehrend_der_ersten_Gruppe()
    {
        using var t = SchutzTresor.Make();
        foreach (var e in new[] { SchutzEntries.Make("B", EntryProtection.Fingerabdruck), SchutzEntries.Make("D", EntryProtection.Maximal),
                     SchutzEntries.Make("E", EntryProtection.Festung) })
        {
            t.Vault.Upsert(e);
        }
        var pending = t.Vault.PrepareRecovery(KT.Pw1);
        var conf = KernStufen.Confirmation(pending);
        var gen = t.Vault.Generation;
        var vault = t.Vault;
        t.P.OnAnswer(vault.Lock);
        await KT.ThrowsAsync(SiegelErrorCode.Io, "vault.locked", () => vault.CommitRecoveryAsync(pending, conf, t.P));
        Assert.Equal([1, 0, 0], t.P.Counts);
        t.P.OnAnswer(null);
        Assert.Equal(gen, t.Reopen().Generation);
    }

    [Fact]
    public async Task Befund_ablaeufe4_Export_gesperrt_waehrend_Argon2()
    {
        using var t = SchutzTresor.Make();
        t.Vault.Upsert(SchutzEntries.Make("B", EntryProtection.Fingerabdruck));
        var vault = t.Vault;
        var dir = t.F.Dir.Sub("Export");
        var observer = new TestHooks.KdfObserver(_ => vault.Lock());
        TestHooks.KdfObserverHook = observer;
        try
        {
            await KT.ThrowsAsync(SiegelErrorCode.Io, "vault.locked", () => vault.ExportCsvAsync(dir, KT.Pw1, new FactorSecrets(), t.P));
        }
        finally
        {
            TestHooks.KdfObserverHook = null;
        }
        Assert.Equal(1, observer.Runs);
        Assert.Equal([0, 0, 0], t.P.Counts);
    }

    [Fact]
    public async Task Upsert_Regeln_Standard_Schutz_offene_Felder_Geheimteile_nur_ueber_SetProtection()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal);
        Assert.Equal(EntryProtection.Fingerabdruck, t.Vault.Policy.DefaultEntryProtection);
        var neu = SchutzEntries.Make("Neu", EntryProtection.Normal);
        t.Vault.Upsert(neu);
        var stored = t.Vault.Entries.Single(x => x.Id == neu.Id);
        Assert.Equal(EntryProtection.Fingerabdruck, stored.Protection);
        Assert.True(stored.SecretsSealed);
        var explizit = SchutzEntries.Make("Explizit", EntryProtection.Hoch);
        t.Vault.Upsert(explizit);
        Assert.Equal(EntryProtection.Hoch, t.Vault.Entries.Single(x => x.Id == explizit.Id).Protection);

        var edit = stored.Copy();
        edit.Title = "Neu umbenannt";
        edit.Username = "jemand";
        var genBefore = t.Vault.Generation;
        t.Vault.Upsert(edit);
        Assert.True(t.Vault.Generation > genBefore);
        var renamed = t.Vault.Entries.Single(x => x.Id == neu.Id);
        Assert.Equal("Neu umbenannt", renamed.Title);
        Assert.True(renamed.SecretsSealed);
        Assert.True(renamed.Modified >= stored.Modified);
        Same(S(neu), await t.Vault.RevealSecretsAsync(neu.Id, t.P));

        var gen = t.Vault.Generation;
        var mitPasswort = renamed.Copy();
        mitPasswort.Password = "anders";
        KT.Throws(SiegelErrorCode.Io, "entry.sealedSecrets", () => t.Vault.Upsert(mitPasswort));
        var mitNotiz = renamed.Copy();
        mitNotiz.Notes = "x";
        KT.Throws(SiegelErrorCode.Io, "entry.sealedSecrets", () => t.Vault.Upsert(mitNotiz));
        foreach (var p in new[] { EntryProtection.Normal, EntryProtection.Hoch, EntryProtection.Festung })
        {
            var anders = renamed.Copy();
            anders.Protection = p;
            KT.Throws(SiegelErrorCode.Io, "entry.protection", () => t.Vault.Upsert(anders));
        }
        KT.Throws(SiegelErrorCode.Io, "entry.sealedSecrets", () => t.Vault.ClearHistory(neu.Id));
        var kopie = renamed.Copy();
        kopie.Id = Guid.NewGuid();
        KT.Throws(SiegelErrorCode.Io, "entry.stale", () => t.Vault.Upsert(kopie));
        KT.Throws(SiegelErrorCode.Io, "entry.stale", () => t.Vault.ImportEntries([kopie]));
        Assert.Equal(gen, t.Vault.Generation);

        t.Vault.SetProtection(EntryProtection.Normal, neu.Id, S(neu));
        var offen = t.Vault.Entries.Single(x => x.Id == neu.Id);
        Assert.Equal(EntryProtection.Normal, offen.Protection);
        Assert.False(offen.SecretsSealed);
        Same(S(neu), S(offen));
        KT.Throws(SiegelErrorCode.Io, "entry.stale", () => t.Vault.Upsert(renamed));

        var hoeher = offen.Copy();
        hoeher.Password = "Neues-Passwort-1";
        hoeher.Protection = EntryProtection.Maximal;
        t.Vault.Upsert(hoeher);
        var sealedAgain = t.Vault.Entries.Single(x => x.Id == neu.Id);
        Assert.Equal(EntryProtection.Maximal, sealedAgain.Protection);
        Assert.True(sealedAgain.SecretsSealed);
        var revealed = await t.Vault.RevealSecretsAsync(neu.Id, t.P);
        Assert.Equal("Neues-Passwort-1", revealed.Password);
        Assert.Contains(revealed.History, h => h.Password == neu.Password);

        var next = revealed.ReplacingPassword("Drittes-Passwort-9");
        Assert.Contains(next.History, h => h.Password == "Neues-Passwort-1");
        Assert.DoesNotContain(next.History, h => h.Password == "Drittes-Passwort-9");
        t.Vault.SetProtection(EntryProtection.Maximal, neu.Id, next);
        t.P.Reset();
        var third = await t.Vault.RevealSecretsAsync(neu.Id, t.P);
        Assert.Equal("Drittes-Passwort-9", third.Password);
        Assert.Equal(next.History.ToHashSet(), third.History.ToHashSet());
        Assert.Equal([1, 1, 0], t.P.Counts);
        t.Vault.SetProtection(EntryProtection.Maximal, neu.Id, new EntrySecrets { Password = third.Password, Notes = third.Notes, Totp = third.Totp });
        Assert.Empty((await t.Vault.RevealSecretsAsync(neu.Id, t.P)).History);
        KT.Throws(SiegelErrorCode.Io, "entry.passwordTooLong", () => t.Vault.SetProtection(EntryProtection.Hoch, neu.Id,
            new EntrySecrets { Password = new string('x', 5000) }));
        Assert.Equal(revealed.Password, revealed.ReplacingPassword(revealed.Password).Password);
    }

    [Fact]
    public async Task Notfall_in_Teilen_entsiegelt_alles_auch_geloeschte()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Festung);
        var kit = t.Kit!;
        Assert.Equal(RecoveryScheme.Shamir2Of3, kit.Scheme);
        VaultEntry[] list =
        [
            SchutzEntries.Make("B", EntryProtection.Fingerabdruck), SchutzEntries.Make("C", EntryProtection.Hoch),
            SchutzEntries.Make("D", EntryProtection.Maximal), SchutzEntries.Make("E", EntryProtection.Festung),
            SchutzEntries.Make("Weg", EntryProtection.Festung),
        ];
        foreach (var e in list) { t.Vault.Upsert(e); }
        t.Vault.Delete(list[4].Id);
        using (var c = t.Vault.ContentForTesting!) { Assert.Equal(3, c.RecoveryGroups.Count); }
        t.Vault.Lock();
        var shares = kit.Shares.Select(s => s.Formatted).ToArray();
        var v = t.Store.Recover([shares[2], shares[0]], KT.Pw2, KT.Kdf);
        Assert.Equal(SecurityLevel.Standard, v.Level);
        Assert.Equal(FactorSet.None, v.EnrolledFactors);
        var all = v.Entries.Concat(v.DeletedEntries).ToList();
        foreach (var o in list)
        {
            var e = all.Single(x => x.Id == o.Id);
            Assert.Equal(EntryProtection.Normal, e.Protection);
            Assert.False(e.SecretsSealed);
            Same(S(o), S(e));
            Same(S(o), await v.RevealSecretsAsync(o.Id, null));
        }
        Assert.Equal([list[4].Id], v.DeletedEntries.Select(x => x.Id));
        using (var content = v.ContentForTesting!)
        {
            Assert.Empty(content.Sealed);
            Assert.Empty(content.RecoveryGroups);
        }
        v.Lock();
        var again = KT.Unlocked(t.Store.Unlock(KT.Pw2))!;
        Assert.All(again.Entries, e => Assert.True(!e.SecretsSealed && e.Protection == EntryProtection.Normal));
        again.Lock();
    }

    [Fact]
    public void Notfallcode_Stufe_2_neues_Master_Passwort_darf_kein_versiegeltes_Eintragspasswort_sein()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Erhoeht);
        VaultEntry[] list =
        [
            SchutzEntries.Make("B", EntryProtection.Fingerabdruck), SchutzEntries.Make("D", EntryProtection.Maximal),
            SchutzEntries.Make("E", EntryProtection.Festung, KT.Pw3),
        ];
        foreach (var e in list) { t.Vault.Upsert(e); }
        t.Vault.Lock();
        var code = t.Kit!.Code.Formatted;
        KT.Throws(SiegelErrorCode.MasterPasswordReused, () => t.Store.Recover(code, KT.Pw3, KT.Kdf));
        var v = t.Store.Recover(code, KT.Pw2, KT.Kdf);
        foreach (var o in list)
        {
            var e = v.Entries.Single(x => x.Id == o.Id);
            Same(S(o), S(e));
            Assert.Equal(EntryProtection.Normal, e.Protection);
        }
        v.Lock();
    }

    [Fact]
    public void Notfallweg_ueber_Sicherungen_entsiegelt_ebenfalls()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Erhoeht);
        VaultEntry[] list = [SchutzEntries.Make("B", EntryProtection.Hoch), SchutzEntries.Make("E", EntryProtection.Festung)];
        foreach (var e in list) { t.Vault.Upsert(e); }
        t.Vault.Upsert(KT.Entry("Danach"));
        var bytes = t.F.FileBytes();
        bytes[bytes.Length / 2] ^= 0x40;
        t.F.WriteFile(bytes);
        t.Vault.Lock();
        var code = t.Kit!.Code.Formatted;
        KT.Corrupt("file.checksum", () => t.Store.Recover(code, KT.Pw2, KT.Kdf));
        var (v, _) = t.Store.RecoverFromNewestReadableBackup(code, KT.Pw2, KT.Kdf);
        Assert.Equal(SecurityLevel.Standard, v.Level);
        foreach (var o in list)
        {
            var e = v.Entries.Single(x => x.Id == o.Id);
            Same(S(o), S(e));
            Assert.False(e.SecretsSealed);
        }
        v.Lock();
    }

    [Fact]
    public async Task Neues_Kit_mit_versiegelten_Eintraegen_eine_Freigabe_je_Gruppe()
    {
        using var t = SchutzTresor.Make();
        VaultEntry[] list =
        [
            SchutzEntries.Make("B", EntryProtection.Fingerabdruck), SchutzEntries.Make("C", EntryProtection.Hoch),
            SchutzEntries.Make("D", EntryProtection.Maximal), SchutzEntries.Make("E", EntryProtection.Festung),
        ];
        foreach (var e in list) { t.Vault.Upsert(e); }
        var altCode = t.F.Code;
        var pending = t.Vault.PrepareRecovery(KT.Pw1);
        var conf = KernStufen.Confirmation(pending);
        var gen = t.Vault.Generation;
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.CommitRecovery(pending, conf));
        await KT.ThrowsAsync(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.CommitRecoveryAsync(pending, conf, null));
        await KT.ThrowsAsync(SiegelErrorCode.RecoveryConfirmationMismatch, () => t.Vault.CommitRecoveryAsync(pending, ["AAAAA", "BBBBB"], t.P));
        Assert.Equal([0, 0, 0], t.P.Counts);
        Assert.Equal(gen, t.Vault.Generation);
        Assert.Equal(RecoveryCodeMatch.Exact, t.Store.CheckRecoveryCode(altCode));
        await t.Vault.CommitRecoveryAsync(pending, conf, t.P);
        Assert.Equal([3, 2, 1], t.P.Counts);
        Assert.Equal(pending.Code.KitId, t.Vault.KitId);
        Assert.True(t.Vault.RecoveryConfirmed);
        foreach (var o in list) { Same(S(o), await t.Vault.RevealSecretsAsync(o.Id, t.P)); }
        t.Vault.Lock();
        Assert.Throws<SiegelException>(() => t.Store.CheckRecoveryCode(altCode));
        var v = t.Store.Recover(pending.Code.Formatted, KT.Pw2, KT.Kdf);
        foreach (var o in list) { Same(S(o), S(v.Entries.Single(x => x.Id == o.Id))); }
        v.Lock();
    }

    [Fact]
    public async Task Stufenwechsel_mit_neuem_Kit_nimmt_versiegelte_Eintraege_mit()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Hoch, FactorSet.SecureEnclave);
        var e = SchutzEntries.Make("H", EntryProtection.Hoch);
        t.Vault.Upsert(e);
        var se = t.K.Secrets(FactorSet.SecureEnclave);
        var shamir = t.Vault.PrepareRecovery(KT.Pw1, se, RecoveryScheme.Shamir2Of3);
        var conf = KernStufen.Confirmation(shamir);
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.ChangeSecurityLevel(SecurityLevel.Maximal, KT.Pw1, se,
            new NewFactorMaterial(Card: t.K.Card), shamir, conf));
        await KT.ThrowsAsync(SiegelErrorCode.WrongPassword, () => t.Vault.ChangeSecurityLevelAsync(SecurityLevel.Maximal, KT.Pw2, se,
            new NewFactorMaterial(Card: t.K.Card), shamir, conf, t.P));
        Assert.Equal([0, 0, 0], t.P.Counts);
        await t.Vault.ChangeSecurityLevelAsync(SecurityLevel.Maximal, KT.Pw1, se, new NewFactorMaterial(Card: t.K.Card), shamir, conf, t.P);
        Assert.Equal([1, 0, 0], t.P.Counts);
        Assert.Equal(SecurityLevel.Maximal, t.Vault.Level);
        Assert.Equal(shamir.Code.KitId, t.Vault.KitId);
        Assert.Equal(FactorSet.SecureEnclave | FactorSet.Card, t.Vault.EnrolledFactors);
        Same(S(e), await t.Vault.RevealSecretsAsync(e.Id, t.P));
        var d = SchutzEntries.Make("D", EntryProtection.Maximal);
        t.Vault.Upsert(d);
        var four = t.K.Secrets(FactorSet.SecureEnclave | FactorSet.Card);
        t.Vault.ChangeSecurityLevel(SecurityLevel.Festung, KT.Pw1, four, new NewFactorMaterial(SecurityKey: t.K.SecurityKey), null, []);
        var single = t.Vault.PrepareRecovery(KT.Pw1, t.K.Secrets(), RecoveryScheme.SingleCode);
        t.P.Reset();
        await t.Vault.ChangeSecurityLevelAsync(SecurityLevel.Hoch, KT.Pw1, t.K.Secrets(), new NewFactorMaterial(), single,
            KernStufen.Confirmation(single), t.P);
        Assert.Equal([2, 1, 0], t.P.Counts);
        Assert.Equal(SecurityLevel.Hoch, t.Vault.Level);
        t.Vault.Lock();
        var v = t.Store.Recover(single.Code.Formatted, KT.Pw2, KT.Kdf);
        foreach (var o in new[] { e, d }) { Same(S(o), S(v.Entries.Single(x => x.Id == o.Id))); }
        v.Lock();
    }

    [Fact]
    public async Task Eintrags_Faktor_ersetzen_nur_ohne_versiegelte_Eintraege()
    {
        using var t = SchutzTresor.Make();
        var fremd = new EntryKeyEnrollment(Guid.NewGuid(), P256.RandomPoint());
        var neueKarte = new CardEnrollment(CardCode.Generate());
        t.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: fremd, Card: neueKarte), KT.Pw1, new FactorSecrets());
        t.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: t.P.EntryKey, Card: t.K.Card), KT.Pw1, new FactorSecrets());
        var b = SchutzEntries.Make("B", EntryProtection.Fingerabdruck);
        t.Vault.Upsert(b);
        var gen = t.Vault.Generation;
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => t.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: fremd), KT.Pw1, new FactorSecrets()));
        // auch nicht durch einen Windows-Hello-Schlüssel (andere Art)
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => t.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: t.P.HelloEntryKey), KT.Pw1,
            new FactorSecrets()));
        t.Vault.EnrollFactors(new NewFactorMaterial(Card: neueKarte), KT.Pw1, new FactorSecrets());
        t.Vault.EnrollFactors(new NewFactorMaterial(Card: t.K.Card), KT.Pw1, new FactorSecrets());
        var d = SchutzEntries.Make("D", EntryProtection.Maximal);
        t.Vault.Upsert(d);
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => t.Vault.EnrollFactors(new NewFactorMaterial(Card: neueKarte), KT.Pw1, new FactorSecrets()));
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => t.Vault.ChangeSecurityLevel(SecurityLevel.Erhoeht, KT.Pw1, new FactorSecrets(),
            new NewFactorMaterial(t.K.SeEnrollment, fremd), null, []));
        t.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: t.P.EntryKey, Card: t.K.Card), KT.Pw1, new FactorSecrets());
        Assert.True(t.Vault.Generation > gen);
        Same(S(d), await t.Vault.RevealSecretsAsync(d.Id, t.P));
    }

    [Fact]
    public async Task Zugangswechsel_rotieren_den_DEK_versiegelte_bleiben_lesbar_auch_aus_Sicherungen()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Erhoeht);
        var e = SchutzEntries.Make("R", EntryProtection.Festung);
        t.Vault.Upsert(e);
        var se = t.K.Secrets(FactorSet.SecureEnclave);
        using var dek1 = t.Vault.DekForTesting();
        byte[] baseKey;
        using (var c = t.Vault.ContentForTesting!)
        using (var l = c.EntryKey!.Key.Borrow())
        {
            baseKey = l.Span.ToArray();
        }
        t.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2, se);
        using (var d = t.Vault.DekForTesting()) { Assert.False(d.ConstantTimeEquals(dek1)); }
        using (var c = t.Vault.ContentForTesting!) { Assert.True(c.EntryKey!.Key.ConstantTimeEquals(baseKey)); }
        Same(S(e), await t.Vault.RevealSecretsAsync(e.Id, t.P));
        var m = SchutzEntries.Make("M", EntryProtection.Hoch, KT.Pw3);
        t.Vault.Upsert(m);
        KT.Throws(SiegelErrorCode.MasterPasswordReused, () => t.Vault.ChangeMasterPassword(KT.Pw2, KT.Pw3, se));
        t.Vault.ChangeSecurityLevel(SecurityLevel.Hoch, KT.Pw2, se, new NewFactorMaterial(), null, []);
        Same(S(e), await t.Vault.RevealSecretsAsync(e.Id, t.P));
        var backup = t.F.LocalBackups().First(b => b.Reason == "stufenwechsel");
        t.Vault.Lock();
        var v = t.Store.RestoreBackup(backup, KT.Pw2, se);
        Assert.Equal(SecurityLevel.Erhoeht, v.Level);
        Same(S(e), await v.RevealSecretsAsync(e.Id, t.P));
        Same(S(m), await v.RevealSecretsAsync(m.Id, t.P));
        v.Lock();
    }

    [Fact]
    public async Task Papierkorb_versiegelte_Eintraege_und_Aufraeumen_der_Gruppen()
    {
        using var t = SchutzTresor.Make();
        var d = SchutzEntries.Make("D", EntryProtection.Maximal);
        t.Vault.Upsert(d);
        t.Vault.Delete(d.Id);
        Assert.True(t.Vault.DeletedEntries[0].SecretsSealed);
        Same(S(d), await t.Vault.RevealSecretsAsync(d.Id, t.P));
        t.Vault.Restore(d.Id);
        Assert.Equal(d.Id, t.Vault.Entries[0].Id);
        t.Vault.Delete(d.Id);
        t.Vault.PurgeDeleted(d.Id);
        using (var c = t.Vault.ContentForTesting!)
        {
            Assert.Empty(c.Sealed);
            Assert.Empty(c.RecoveryGroups);
            Assert.False(c.Meta.ContainsKey(d.Id));
        }
        var e = SchutzEntries.Make("E", EntryProtection.Fingerabdruck);
        t.Vault.Upsert(e);
        t.Vault.Delete(e.Id);
        using (KT.Now(DateTimeOffset.UtcNow.AddDays(31))) { t.Vault.Upsert(KT.Entry("Später")); }
        using (var c2 = t.Vault.ContentForTesting!)
        {
            Assert.Empty(c2.Sealed);
            Assert.Empty(c2.RecoveryGroups);
        }
        Assert.Empty(t.Vault.DeletedEntries);
    }

    [Fact]
    public async Task Importieren_Stufe_4_versiegelt_Dubletten_auch_gegen_versiegelte()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal);
        t.Vault.Upsert(KT.Entry("Bank", "anna", "Konto-123", "https://bank.ch"));
        var report = t.Vault.ImportEntries(
        [
            KT.Entry("Bank", "anna", "Konto-123", "bank.ch"),
            KT.Entry("Bank", "anna", "Anders-456", "https://bank.ch"),
            KT.Entry("Mail", "anna", "Post-789", "https://mail.ch"),
        ]);
        Assert.Equal(2, report.Added);
        Assert.Equal(1, report.SkippedDuplicates);
        Assert.Equal(1, report.Conflicts);
        Assert.Equal(3, t.Vault.Entries.Count);
        Assert.All(t.Vault.Entries, x => Assert.True(x.SecretsSealed && x.Protection == EntryProtection.Fingerabdruck));
        var mail = t.Vault.Entries.Single(x => x.Title == "Mail");
        Assert.Equal("Post-789", (await t.Vault.RevealSecretsAsync(mail.Id, t.P)).Password);
        Assert.Contains(t.Vault.Entries, x => x.Title == "Bank (Import)");
        Assert.Contains(t.F.LocalBackups(), b => b.Reason == "import");

        using var ohne = SchutzTresor.Make(SecurityLevel.Maximal, FactorSet.None);
        Assert.Equal(FactorSet.Card, ohne.Vault.EnrolledFactors);
        var gen = ohne.Vault.Generation;
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => ohne.Vault.Upsert(KT.Entry("A")));
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => ohne.Vault.ImportEntries([KT.Entry("A")]));
        Assert.Equal(gen, ohne.Vault.Generation);
    }

    /// <summary>Gepolsterter Klartext wie <c>sodium_pad</c> (für handgebaute Inhalte).</summary>
    internal static unsafe SecureBuffer Padded(string json)
    {
        var raw = System.Text.Encoding.UTF8.GetBytes(json);
        var n = (raw.Length / PayloadCodec.BlockSize + 1) * PayloadCodec.BlockSize;
        var buf = new byte[n];
        raw.CopyTo(buf, 0);
        nuint result = 0;
        fixed (byte* p = buf)
        {
            Assert.Equal(0, Libsodium.sodium_pad(&result, p, (nuint)raw.Length, PayloadCodec.BlockSize, (nuint)n));
        }
        return SecureBuffer.Copy(buf);
    }

    [Fact]
    public async Task Herabstufen_der_Schutz_Angabe_in_der_Datei_macht_den_Eintrag_unlesbar()
    {
        using var t = SchutzTresor.Make();
        var a = SchutzEntries.Make("A", EntryProtection.Fingerabdruck);
        var b = SchutzEntries.Make("B", EntryProtection.Maximal);
        t.Vault.Upsert(a);
        t.Vault.Upsert(b);
        var code = t.F.Code;
        using var scope = t.Vault.Enter();
        var s = scope.State;
        void Forge(Action<VaultContent> change)
        {
            using var c = s.Content.Clone();
            change(c);
            var (bytes, _) = VaultCrypto.BuildFile(s.Header, s.Slots, s.Generation + 1, s.Dek, c);
            t.F.WriteFile(bytes);
        }
        var ib = s.Content.Entries.FindIndex(x => x.Id == b.Id);
        Forge(c =>
        {
            c.Entries[ib].Protection = EntryProtection.Fingerabdruck;
            var x = c.Sealed[b.Id];
            c.Sealed[b.Id] = x with { Blob = x.Blob with { Factors = x.Blob.Factors with { Card = null } } };
        });
        t.Vault.Lock();
        var v = KT.AnyVault(t.Store.Unlock(KT.Pw1));
        Assert.Equal(EntryProtection.Fingerabdruck, v.Entries.Single(x => x.Id == b.Id).Protection);
        t.P.Reset();
        await KT.ThrowsAsync(SiegelErrorCode.WrongPassword, () => v.RevealSecretsAsync(b.Id, t.P));
        Assert.Equal([1, 0, 0], t.P.Counts);
        Same(S(a), await v.RevealSecretsAsync(a.Id, t.P));
        v.Lock();
        KT.Corrupt("entry.recovery", () => t.Store.Recover(code, KT.Pw2, KT.Kdf));
        using (var inkonsistent = s.Content.Clone())
        {
            inkonsistent.Entries[ib].Protection = EntryProtection.Normal;
            KT.Throws(SiegelErrorCode.Crypto, "entry.sealedState", () => PayloadCodec.Encode(inkonsistent));
        }
        var (padded, _) = PayloadCodec.Encode(s.Content);
        string json;
        using (padded) { json = PayloadCodec.JsonStringForTesting(padded)!; }
        var forgedJson = json.Replace("\"protection\":4", "\"protection\":1", StringComparison.Ordinal);
        Assert.NotEqual(json, forgedJson);
        var gen = s.Generation + 2;
        using var forged = Padded(forgedJson);
        var (nonce, ct) = Aead.Seal(s.Dek, forged, VaultFile.PayloadAdFor(s.Header, s.Slots, gen));
        t.F.WriteFile(new VaultFile(s.Header, s.Slots, gen, nonce, ct).Serialize());
        KT.Corrupt("entry.sealedState", () => t.Store.Unlock(KT.Pw1));
    }
}

/// <summary>Manipulation mit versiegelten Einträgen (SPEC §10 + §16).</summary>
public class SchutzByteKippTests
{
    [Fact]
    public void Datei_mit_versiegelten_Eintraegen_jedes_Byte_und_Angreifer_mit_neuer_Pruefsumme()
    {
        using var t = SchutzTresor.Make();
        foreach (var p in new[] { EntryProtection.Normal, EntryProtection.Fingerabdruck, EntryProtection.Maximal, EntryProtection.Festung })
        {
            t.Vault.Upsert(SchutzEntries.Make("E" + (int)p, p));
        }
        var bytes = t.F.FileBytes();
        using var pw = PasswordNormalizer.SecureBytes(KT.Pw1);
        using var r = RecoveryCodeCodec.Decode(t.F.Code);
        var file = VaultFile.Parse(bytes);
        using (VaultCrypto.OpenWithPassword(file, pw, null, KdfLimits.Testing)) { }
        using (var control = VaultCrypto.OpenWithRecovery(file, r))
        {
            control.Content.UnsealAll(r, file.Header);
            Assert.All(control.Content.Entries, e => Assert.False(e.SecretsSealed));
        }
        var findings = new Findings();
        Parallel.For(0, bytes.Length, i =>
        {
            var b = (byte[])bytes.Clone();
            b[i] ^= 0x01;
            for (var path = 0; path < 2; path++)
            {
                try
                {
                    var f = VaultFile.Parse(b);
                    using var o = path == 0 ? VaultCrypto.OpenWithPassword(f, pw, null, KdfLimits.Testing) : VaultCrypto.OpenWithRecovery(f, r);
                    findings.Add("ok " + i);
                }
                catch (SiegelException e)
                {
                    if (e.Code != SiegelErrorCode.CorruptFile || e.Detail != "file.checksum") { findings.Add(i + ": " + e.Message); }
                }
            }
        });
        var body = bytes.Length - FileFormat.ChecksumBytes;
        Parallel.For(0, body, i =>
        {
            var b = (byte[])bytes.Clone();
            b[i] ^= 0x80;
            var forged = KT.WithFixedChecksum(b);
            try
            {
                var f = VaultFile.Parse(forged);
                using var o = VaultCrypto.OpenWithPassword(f, pw, null, KdfLimits.Testing);
                findings.Add("pw ok " + i);
            }
            catch (SiegelException)
            {
            }
            try
            {
                var f = VaultFile.Parse(forged);
                using var o = VaultCrypto.OpenWithRecovery(f, r);
                o.Content.UnsealAll(r, f.Header);
                findings.Add("rec ok " + i);
            }
            catch (SiegelException)
            {
            }
        });
        Assert.Empty(findings.All);
    }

    [Fact]
    public async Task Versiegelte_Teile_manipuliert_nie_falscher_Inhalt()
    {
        using var t = SchutzTresor.Make();
        var e = SchutzEntries.Make("F", EntryProtection.Festung);
        t.Vault.Upsert(e);
        using var content = t.Vault.ContentForTesting!;
        var entry = content.Entries.Single(x => x.Id == e.Id);
        var x = content.Sealed[e.Id];
        var vid = Bytes.OfGuid(t.Vault.VaultId);
        var keys = content.SealingKeys(vid);
        var header = t.Vault.HeaderForTesting!;
        var group = content.RecoveryGroups.Single(g => g.Mask == FactorSet.All);
        using var r = RecoveryCodeCodec.Decode(t.F.Code);
        using var kitKeys = EntrySealing.KitPrivateKeys(r, header)!;
        using var gk = EntrySealing.OpenGroup(group, kitKeys, vid);
        var expected = SchutzEntries.SecretsOf(e);

        async Task<EntrySecrets?> Reveal(SealedSecrets y)
        {
            try
            {
                var released = await EntrySealing.ReleaseAsync(y.Blob.Factors, e.Id, FactorSet.All, keys.Factors, vid, t.P,
                    EntrySealing.SePart.ForEntries(keys.Factors), CancellationToken.None);
                try
                {
                    using var pt = EntrySealing.Open(y.Blob, e.Id, 5, FactorSet.All, EntrySealing.EntryAd, keys.Base, vid, released);
                    return pt is null ? null : EntrySealing.DecodeSecrets(pt);
                }
                finally
                {
                    foreach (var s in released) { s.Dispose(); }
                }
            }
            catch (SiegelException)
            {
                return null;
            }
        }
        EntrySecrets? ViaRecovery(SealedSecrets y)
        {
            try
            {
                return VaultContent.OpenViaGroup(y, entry, gk, vid);
            }
            catch (SiegelException)
            {
                return null;
            }
        }
        bool Eq(EntrySecrets? a) => a is not null && a.Password == expected.Password && a.Notes == expected.Notes && a.Totp == expected.Totp
            && a.History.SequenceEqual(expected.History);
        Assert.True(Eq(await Reveal(x)));
        Assert.True(Eq(ViaRecovery(x)));

        var variants = new List<(SealedSecrets Y, string Field, bool Reveal, bool Recovery)>();
        void Add(string field, int count, bool reveal, bool recovery, Func<SealedSecrets, int, SealedSecrets> flip)
        {
            for (var i = 0; i < count; i++) { variants.Add((flip(x, i), field, reveal, recovery)); }
        }
        static byte[] Flip(byte[] b, int i)
        {
            var c = (byte[])b.Clone();
            c[i] ^= 0x01;
            return c;
        }
        Add("nonce", x.Blob.Nonce.Length, true, true, (y, i) => y with { Blob = y.Blob with { Nonce = Flip(y.Blob.Nonce, i) } });
        Add("ct", x.Blob.Ciphertext.Length, true, true, (y, i) => y with { Blob = y.Blob with { Ciphertext = Flip(y.Blob.Ciphertext, i) } });
        Add("se", 65, true, false, (y, i) => y with { Blob = y.Blob with { Factors = y.Blob.Factors with { SeEphemeral = Flip(y.Blob.Factors.SeEphemeral!, i) } } });
        Add("card.ctM", RecoveryKem.CtMBytes, true, false, (y, i) => y with { Blob = y.Blob with { Factors = y.Blob.Factors with { Card = y.Blob.Factors.Card! with { CtM = Flip(y.Blob.Factors.Card!.CtM, i) } } } });
        Add("card.ctX", RecoveryKem.CtXBytes, true, false, (y, i) => y with { Blob = y.Blob with { Factors = y.Blob.Factors with { Card = y.Blob.Factors.Card! with { CtX = Flip(y.Blob.Factors.Card!.CtX, i) } } } });
        Add("fido.ctM", RecoveryKem.CtMBytes, true, false, (y, i) => y with { Blob = y.Blob with { Factors = y.Blob.Factors with { Fido = y.Blob.Factors.Fido! with { CtM = Flip(y.Blob.Factors.Fido!.CtM, i) } } } });
        Add("fido.ctX", RecoveryKem.CtXBytes, true, false, (y, i) => y with { Blob = y.Blob with { Factors = y.Blob.Factors with { Fido = y.Blob.Factors.Fido! with { CtX = Flip(y.Blob.Factors.Fido!.CtX, i) } } } });
        Add("rec.ctM", RecoveryKem.CtMBytes, false, true, (y, i) => y with { Recovery = y.Recovery with { Capsule = y.Recovery.Capsule with { CtM = Flip(y.Recovery.Capsule.CtM, i) } } });
        Add("rec.ctX", RecoveryKem.CtXBytes, false, true, (y, i) => y with { Recovery = y.Recovery with { Capsule = y.Recovery.Capsule with { CtX = Flip(y.Recovery.Capsule.CtX, i) } } });
        Add("rec.key", Aead.WrappedBytes, false, true, (y, i) => y with { Recovery = y.Recovery with { Wrapped = Flip(y.Recovery.Wrapped, i) } });

        var findings = new Findings();
        await Parallel.ForEachAsync(variants, async (v, _) =>
        {
            var got = await Reveal(v.Y);
            if (v.Reveal ? got is not null : !Eq(got)) { findings.Add("reveal " + v.Field); }
        });
        Parallel.ForEach(variants, v =>
        {
            var got = ViaRecovery(v.Y);
            if (v.Recovery ? got is not null : !Eq(got)) { findings.Add("recovery " + v.Field); }
        });
        Assert.Empty(findings.All);
    }
}

/// <summary>Feste Testvektoren der Eintrags-Kryptografie (aus KernSchutzVektorTests.swift, mit Python nachgerechnet) und
/// die Bindung von Schutz und Maske an K und AD.</summary>
public class SchutzVektorTests
{
    private static readonly Guid EntryId = Guid.Parse("11111111-2222-4333-8444-555555555555");

    [Fact]
    public void KAT_base_ss_se_K_reuseTag_Kombinierer()
    {
        using var ebk = KT.Secure(KT.Seq(1, 32));
        var id = Bytes.OfGuid(EntryId);
        using var baseKey = EntrySealing.BaseKey(ebk, id);
        Assert.Equal("f2ed345a214a17f411de468e98f4c24b7902992a531684b8c71ce2bccbeb8c69", baseKey.HexForTesting());
        using var ecdh = KT.Secure(KT.Repeat(0x33, 32));
        using var ssSe = EntrySealing.SeSecret(ecdh, id, EntrySealing.SeInfo);
        Assert.Equal("8dd0e9b6ecf256c901194453887d4a38716a47a923b9335bb757298f6156039d", ssSe.HexForTesting());
        using var card = KT.Secure(KT.Repeat(0x44, 32));
        using var fido = KT.Secure(KT.Repeat(0x55, 32));
        using var k5 = EntrySealing.EntryKey([baseKey, ssSe, card, fido], id, 5, FactorSet.All, EntrySealing.KeyInfo);
        Assert.Equal("7458486fbc1ed731ff768c3edcf2c4624f4836ea1e7ce26cfd8bf4d3a0a9ec40", k5.HexForTesting());
        using var k2 = EntrySealing.EntryKey([baseKey, ssSe], id, 2, FactorSet.SecureEnclave, EntrySealing.KeyInfo);
        Assert.Equal("4ecabd6048b4f76db1f1bf01086f10af1b19f06dd474a322d2b7f02f87f723a5", k2.HexForTesting());
        KT.Throws(SiegelErrorCode.Crypto, "entry.key", () => EntrySealing.EntryKey([baseKey], id, 2, FactorSet.SecureEnclave, EntrySealing.KeyInfo));
        using var rk = EntrySealing.ReuseKey(ebk);
        Assert.Equal("23716ae24e05679cdac85914d15aba3857bef530b729432516d0d3d2c9c51dac", rk.HexForTesting());
        Assert.Equal("174f4b195dcaa51999f0192d5dfbd26a", KT.Hex(EntrySealing.ReuseTag(rk, "Passwort-ä")!));
        Assert.Equal(EntrySealing.ReuseTag(rk, "Passwort-ä"), EntrySealing.ReuseTag(rk, "Passwort-ä"));
        Assert.Null(EntrySealing.ReuseTag(rk, ""));
        // v4.4: geschütztes Leerzeichen wie §1.1; der alte Tag (nur NFC) weicht davon ab
        Assert.Equal(EntrySealing.ReuseTag(rk, "a b"), EntrySealing.ReuseTag(rk, "a b"));
        Assert.NotNull(EntrySealing.LegacyReuseTag(rk, "a b"));
        Assert.Null(EntrySealing.LegacyReuseTag(rk, "a b"));
        using var combined = RecoveryKem.Combine(EntrySealing.CardLabel, id, KT.Repeat(0x61, 32), KT.Repeat(0x62, 32), KT.Repeat(0x63, 32),
            KT.Repeat(0x64, 32), KT.Repeat(0x65, 1568), KT.Repeat(0x66, 1568));
        Assert.Equal("56bed5e23780b1f2de4b58ecac2674b2ca957b26be0fa72a88d044f29ef2839f", combined.HexForTesting());
    }

    [Fact]
    public void AD_bindet_vaultID_entryID_Schutz_und_Maske()
    {
        using var t = SchutzTresor.Make();
        using var content = t.Vault.ContentForTesting!;
        var vid = Bytes.OfGuid(t.Vault.VaultId);
        var keys = content.SealingKeys(vid);
        using var plain = EntrySealing.EncodeSecrets(new EntrySecrets { Password = "geheim" });
        var (blob, k) = EntrySealing.Seal(plain, EntryId, 3, FactorSet.SecureEnclave, EntrySealing.EntryAd, keys, null);
        using (k)
        {
            var id = Bytes.OfGuid(EntryId);
            bool Opens(byte[] ad)
            {
                using var o = Aead.Open(k, blob.Nonce, blob.Ciphertext, ad);
                return o is not null;
            }
            Assert.True(Opens(EntrySealing.Ad(EntrySealing.EntryAd, vid, id, 3, FactorSet.SecureEnclave)));
            Assert.False(Opens(EntrySealing.Ad(EntrySealing.EntryAd, vid, id, 2, FactorSet.SecureEnclave)));
            Assert.False(Opens(EntrySealing.Ad(EntrySealing.EntryAd, vid, id, 3, FactorSet.SecureEnclave | FactorSet.Card)));
            Assert.False(Opens(EntrySealing.Ad(EntrySealing.EntryAd, vid, Bytes.OfGuid(Guid.NewGuid()), 3, FactorSet.SecureEnclave)));
            Assert.False(Opens(EntrySealing.Ad(EntrySealing.EntryAd, RandomNumberGenerator.GetBytes(16), id, 3, FactorSet.SecureEnclave)));
            Assert.False(Opens(EntrySealing.Ad(EntrySealing.AnchorAd, vid, id, 3, FactorSet.SecureEnclave)));
            using var b0 = EntrySealing.BaseKey(keys.Base, id);
            using var rnd = SecureBuffer.Random(32);
            using var a = EntrySealing.EntryKey([b0, rnd], id, 3, FactorSet.SecureEnclave, EntrySealing.KeyInfo);
            using var c = EntrySealing.EntryKey([b0, rnd], id, 2, FactorSet.SecureEnclave, EntrySealing.KeyInfo);
            Assert.False(a.ConstantTimeEquals(c));
        }
        // Geheimteil-JSON: sortiert, gepolstert auf 256, Swift-Zahlen
        var s = new EntrySecrets { Password = "a/b", Notes = "n", Totp = "", History = [new PasswordHistoryItem("x", KT.At(1_790_000_000.5))] };
        using var enc = EntrySealing.EncodeSecrets(s);
        Assert.Equal(256, enc.Length);
        using (var l = enc.Borrow())
        {
            var text = System.Text.Encoding.UTF8.GetString(l.Span[..l.Span.IndexOf((byte)0x80)]);
            Assert.Equal("{\"history\":[{\"changed\":1790000000.5,\"password\":\"x\"}],\"notes\":\"n\",\"password\":\"a\\/b\",\"totp\":\"\"}", text);
        }
        var back = EntrySealing.DecodeSecrets(enc);
        Assert.Equal("a/b", back.Password);
        Assert.Equal(s.History, back.History);
    }
}
#endif
