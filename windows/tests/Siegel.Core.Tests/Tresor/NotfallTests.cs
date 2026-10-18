#if DEBUG
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Notfallweg über den Store (Gegenstück zu den Store-Teilen von KernNotfallcodeTests.swift und
/// KernShamirTests.swift sowie zu den Datei-Befunden datei-2 bis datei-4).</summary>
public class NotfallTests
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    private static char Other(char c, int shift = 7) => Alphabet[(Math.Max(0, Alphabet.IndexOf(c, StringComparison.Ordinal)) + shift) % 32];

    private static char[] Chars(string code) => code.Replace("-", "", StringComparison.Ordinal).ToCharArray();

    private static string Grouped(char[] c) =>
        string.Join('-', Enumerable.Range(0, (c.Length + 4) / 5).Select(i => new string(c, i * 5, Math.Min(5, c.Length - i * 5))));

    [Fact]
    public void Rundlauf_Code_aus_Create_oeffnet_ueber_Recover_DEK_und_Salz_neu()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("Bank"));
        var oldFile = f.ParsedFile();
        using var oldDek = f.Vault.DekForTesting();
        f.Vault.Lock();
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(f.Code));
        var v = f.Store.Recover(f.Code, KT.Pw2, KT.Kdf);
        Assert.Equal(["Bank"], v.Entries.Select(x => x.Title));
        var newFile = f.ParsedFile();
        Assert.NotEqual(oldFile.Header.Salt, newFile.Header.Salt);
        using (var d = v.DekForTesting()) { Assert.False(d.ConstantTimeEquals(oldDek)); }
        KT.Corrupt("payload.auth", () => VaultCrypto.DecryptPayload(newFile, oldDek));
        using (var r = RecoveryCodeCodec.Decode(f.Code))
        using (var viaCode = VaultCrypto.OpenWithRecovery(newFile, r))
        using (var d = v.DekForTesting())
        {
            Assert.True(viaCode.Dek.ConstantTimeEquals(d));
        }
        Assert.True(v.RecoveryConfirmed);
        Assert.Equal(f.Pending.Code.KitId, v.KitId);
        v.Lock();
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw2)));
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(KT.Pw1));
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(f.Code));
        Assert.Contains(f.LocalBackups(), b => b.Reason == "notfall");
    }

    [Fact]
    public void Korrektur_ueber_den_Store_und_Fehlerfaelle()
    {
        using var f = KernVault.Make();
        var c = Chars(f.Code);
        c[17] = Other(c[17]);
        Assert.Equal(RecoveryCodeMatch.Corrected(f.Code, [17]), f.Store.CheckRecoveryCode(Grouped(c)));
        Assert.True(VaultStore.RecoveryCodeInputIsComplete(Grouped(c)));
        Assert.False(VaultStore.RecoveryCodeInputIsComplete(f.Code[..20]));
        // recover verlangt den exakten Code
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => f.Store.Recover(Grouped(c), KT.Pw2, KT.Kdf));
        // fremder Tresor: beide Kit-Kennungen
        using var g = KernVault.Make();
        var e = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.CheckRecoveryCode(g.Code));
        Assert.Equal(f.Vault.KitId, e.VaultKit);
        Assert.NotEqual(e.VaultKit, e.CodeKit);
        var e2 = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.Recover(g.Code, KT.Pw2, KT.Kdf));
        Assert.Equal(e.CodeKit, e2.CodeKit);
        // Bitfäule im Kopf (pkX): corruptFile statt erfundener Kit-Kennung (Befund #22)
        var bytes = f.FileBytes();
        bytes[KT.HeaderLength(bytes) - 10] ^= 1;
        f.WriteFile(bytes);
        KT.Corrupt("file.checksum", () => f.Store.CheckRecoveryCode(g.Code));
    }

    [Fact]
    public void Lebenszyklus_create_unbestaetigt_falsche_Gruppen_schreiben_nichts()
    {
        using var f = KernVault.Make();
        Assert.False(f.Vault.RecoveryConfirmed);
        var before = f.FileBytes();
        var wanted = KernStufen.Confirmation(f.Pending);
        string[] wrong = [wanted[0], Other(wanted[1][0]) + wanted[1][1..]];
        KT.Throws(SiegelErrorCode.RecoveryConfirmationMismatch, () => f.Vault.CommitRecovery(f.Pending, wrong));
        KT.Throws(SiegelErrorCode.RecoveryConfirmationMismatch, () => f.Vault.CommitRecovery(f.Pending, [wanted[0]]));
        if (wanted[0] != wanted[1])
        {
            KT.Throws(SiegelErrorCode.RecoveryConfirmationMismatch, () => f.Vault.CommitRecovery(f.Pending, [wanted[1], wanted[0]]));
        }
        Assert.Equal(before, f.FileBytes());
        Assert.False(f.Vault.RecoveryConfirmed);
        f.Vault.CommitRecovery(f.Pending, [.. wanted.Select(w => " " + w.ToLowerInvariant())]);
        Assert.True(f.Vault.RecoveryConfirmed);
        Assert.Equal(2UL, f.Vault.Generation);
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(f.Code));
        f.Vault.Lock();
        Assert.True(KT.Unlocked(f.Store.Unlock(KT.Pw1))!.RecoveryConfirmed);
    }

    [Fact]
    public void Neues_Kit_vorbereiten_laesst_alten_Code_gueltig_commit_macht_ihn_ungueltig()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("Bank"));
        using var oldDek = f.Vault.DekForTesting();
        var oldFile = f.ParsedFile();
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Vault.PrepareRecovery(KT.Pw2));
        var pending = f.Vault.PrepareRecovery(KT.Pw1);
        Assert.NotEqual(f.Pending.Code.KitId, pending.Code.KitId);
        Assert.NotEqual(f.Code, pending.Code.Formatted);
        Assert.Equal(oldFile.Generation, f.ParsedFile().Generation);
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(f.Code));
        Assert.Equal(f.Pending.Code.KitId, f.Vault.KitId);
        KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.CheckRecoveryCode(pending.Code.Formatted));
        KT.Throws(SiegelErrorCode.RecoveryConfirmationMismatch, () => f.Vault.CommitRecovery(pending, ["00000", "00000"]));
        Assert.Equal(oldFile.Generation, f.ParsedFile().Generation);
        var groups = KernStufen.Confirmation(pending);
        f.Vault.CommitRecovery(pending, groups);
        Assert.Equal(pending.Code.KitId, f.Vault.KitId);
        Assert.True(f.Vault.RecoveryConfirmed);
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(pending.Code.Formatted));
        var e = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.Recover(f.Code, KT.Pw2, KT.Kdf));
        Assert.Equal(f.Pending.Code.KitId, e.CodeKit);
        Assert.Equal(pending.Code.KitId, e.VaultKit);
        var newFile = f.ParsedFile();
        using (var d = f.Vault.DekForTesting()) { Assert.False(d.ConstantTimeEquals(oldDek)); }
        using (var oldR = RecoveryCodeCodec.Decode(f.Code))
        using (var oldOpened = VaultCrypto.OpenWithRecovery(oldFile, oldR))
        {
            Assert.True(oldOpened.Dek.ConstantTimeEquals(oldDek));
            KT.Corrupt("payload.auth", () => VaultCrypto.DecryptPayload(newFile, oldOpened.Dek));
        }
        Assert.NotEqual(oldFile.Header.Salt, newFile.Header.Salt);
        f.Vault.Lock();
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw1)));
        var rec = f.Store.Recover(pending.Code.Formatted, KT.Pw2, KT.Kdf);
        Assert.Equal(["Bank"], rec.Entries.Select(x => x.Title));
        Assert.Contains(f.LocalBackups(), b => b.Reason == "neues-kit");
        // erneutes commit desselben (jetzt aktuellen) Kits ist nur eine Bestätigung
        using var dekBefore = rec.DekForTesting();
        rec.CommitRecovery(pending, groups);
        using (var d = rec.DekForTesting()) { Assert.True(d.ConstantTimeEquals(dekBefore)); }
        Assert.Equal(pending.Code.KitId, rec.KitId);
        rec.Lock();
    }

    [Fact]
    public void Passwortwechsel_zwischen_prepare_und_commit_macht_das_Kit_ungueltig()
    {
        using var f = KernVault.Make();
        var pending = f.Vault.PrepareRecovery(KT.Pw1);
        f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2);
        KT.Throws(SiegelErrorCode.Crypto, "recovery.pendingStale", () => f.Vault.CommitRecovery(pending, KernStufen.Confirmation(pending)));
        f.Vault.Lock();
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw2)));
    }

    [Fact]
    public void Shamir_vorbereiten_und_bestaetigen_Stufe_4()
    {
        var (f, k, kit) = KernStufen.Make(SecurityLevel.Maximal);
        using (f)
        {
            var current = k.Secrets(FactorSet.SecureEnclave | FactorSet.Card);
            Assert.Equal(RecoveryScheme.Shamir2Of3, kit!.Scheme);
            var p = f.Vault.PrepareRecovery(KT.Pw1, current, RecoveryScheme.Shamir2Of3);
            Assert.Equal(RecoveryScheme.Shamir2Of3, p.Scheme);
            Assert.Equal([1, 2, 3], p.Shares.Select(s => s.Index));
            Assert.All(p.Shares, s => Assert.Equal(p.Code.KitId, s.KitId));
            Assert.Equal("", p.Code.Formatted);
            Assert.Empty(p.ConfirmationGroups);
            Assert.Equal(3, p.ShareConfirmationGroups.Count);
            Assert.All(p.ShareConfirmationGroups, g => Assert.InRange(g, 0, 10));
            KT.Throws(SiegelErrorCode.WrongPassword, () => f.Vault.PrepareRecovery(KT.Pw2, current, RecoveryScheme.Shamir2Of3));
            KT.Throws(SiegelErrorCode.FactorMissing, "card", () => f.Vault.PrepareRecovery(KT.Pw1, k.Secrets(FactorSet.SecureEnclave), RecoveryScheme.Shamir2Of3));
            var gen = f.Vault.Generation;
            var right = KernStufen.Confirmation(p);
            var wrong = (string[])right.Clone();
            wrong[1] = new string([.. wrong[1].Select(ch => Other(ch))]);
            KT.Throws(SiegelErrorCode.RecoveryConfirmationMismatch, () => f.Vault.CommitRecovery(p, wrong));
            KT.Throws(SiegelErrorCode.RecoveryConfirmationMismatch, () => f.Vault.CommitRecovery(p, right[..2]));
            Assert.Equal(gen, f.Vault.Generation);
            var oldShares = kit.Shares.Select(s => s.Formatted).ToArray();
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], f.Store.CheckRecoveryShares([oldShares[0], oldShares[1]]));
            f.Vault.CommitRecovery(p, [.. right.Select(r => " " + r.ToLowerInvariant())]);
            Assert.Equal(p.Code.KitId, f.Vault.KitId);
            Assert.True(f.Vault.RecoveryConfirmed);
            Assert.Contains(f.LocalBackups(), b => b.Reason == "neues-kit");
            var newShares = p.Shares.Select(s => s.Formatted).ToArray();
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], f.Store.CheckRecoveryShares([newShares[2], newShares[1]]));
            var e = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.CheckRecoveryShares([oldShares[0], oldShares[1]]));
            Assert.Equal(p.Code.KitId, e.VaultKit);
            Assert.Equal(FactorSet.SecureEnclave | FactorSet.Card, f.Vault.HeaderInfo.Factors);
            f.Vault.Lock();
            Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw1, current)));
            Assert.Equal(2, VaultStore.RecoveryShareIndex(newShares[1]));
            Assert.Null(VaultStore.RecoveryShareIndex(newShares[1][..^1] + Other(newShares[1][^1])));
            Assert.True(VaultStore.RecoveryShareInputIsComplete(newShares[0]));
        }
    }

    [Fact]
    public void Kit_mit_anderem_Schema_als_die_Stufe_nicht_direkt()
    {
        using var f = KernVault.Make();
        var p = f.Vault.PrepareRecovery(KT.Pw1, new FactorSecrets(), RecoveryScheme.Shamir2Of3);
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => f.Vault.CommitRecovery(p, KernStufen.Confirmation(p)));
        Assert.Equal(1UL, f.Vault.Generation);
        Assert.Equal(RecoveryScheme.SingleCode, f.Vault.PrepareRecovery(KT.Pw1).Scheme);
    }

    [Fact]
    public void Teile_Korrektur_und_Fehlerfaelle_ueber_den_Store()
    {
        var (f, _, kit) = KernStufen.Make(SecurityLevel.Maximal);
        var (g, _, otherKit) = KernStufen.Make(SecurityLevel.Maximal);
        using (f)
        using (g)
        {
            var s = kit!.Shares.Select(x => x.Formatted).ToArray();
            var t = otherKit!.Shares.Select(x => x.Formatted).ToArray();
            var a1 = Chars(s[0]);
            a1[17] = Other(a1[17]);
            Assert.Equal([RecoveryCodeMatch.Corrected(s[0], [17]), RecoveryCodeMatch.Exact], f.Store.CheckRecoveryShares([Grouped(a1), s[2]]));
            var e = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.CheckRecoveryShares([t[0], t[1]]));
            Assert.Equal(f.Vault.KitId, e.VaultKit);
            KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.CheckRecoveryShares([s[0], t[1]]));
            KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => f.Store.CheckRecoveryShares([s[1], s[1]]));
            KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => f.Store.CheckRecoveryShares([s[1]]));
            KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => f.Store.CheckRecoveryShares([s[0], "ABC"]));
            KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.Recover([t[0], t[2]], KT.Pw2, KT.Kdf));
            var bytes = f.FileBytes();
            bytes[KT.HeaderLength(bytes) - 10] ^= 1;
            f.WriteFile(bytes);
            KT.Corrupt("file.checksum", () => f.Store.CheckRecoveryShares([s[0], s[1]]));
        }
    }

    [Fact]
    public void Recover_mit_jedem_Paar_Teile_bleiben_gueltig_bestehendes_Kit_bestaetigen()
    {
        var (f, _, kit) = KernStufen.Make(SecurityLevel.Festung);
        using (f)
        {
            f.Vault.Upsert(KT.Entry("Bank"));
            var s = kit!.Shares.Select(x => x.Formatted).ToArray();
            f.Vault.Lock();
            string[] pws = [KT.Pw2, KT.Pw3, KT.Pw4];
            foreach (var (i, j) in new[] { (0, 1), (1, 2), (2, 0) })
            {
                var v = f.Store.Recover([s[i], s[j]], pws[i], KT.Kdf);
                Assert.Equal(["Bank"], v.Entries.Select(x => x.Title));
                Assert.Equal(SecurityLevel.Standard, v.Level);
                Assert.Equal(kit.Code.KitId, v.KitId);
                Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], f.Store.CheckRecoveryShares([s[i], s[j]]));
                v.Lock();
                Assert.NotNull(KT.Unlocked(f.Store.Unlock(pws[i])));
            }
            var again = KT.Unlocked(f.Store.Unlock(KT.Pw4))!;
            KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => again.ConfirmExistingRecovery([s[0]]));
            again.ConfirmExistingRecovery([s[1], s[0]]);
            Assert.True(again.RecoveryConfirmed);
            again.Lock();
        }
    }

    [Fact]
    public void Bestehendes_Kit_mit_dem_ganzen_Code_bestaetigen()
    {
        using var f = KernVault.Make();
        using var g = KernVault.Make();
        KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Vault.ConfirmExistingRecovery(g.Code));
        Assert.False(f.Vault.RecoveryConfirmed);
        f.Vault.ConfirmExistingRecovery(f.Code);
        Assert.True(f.Vault.RecoveryConfirmed);
        var gen = f.Vault.Generation;
        f.Vault.ConfirmExistingRecovery(f.Code);
        Assert.Equal(gen, f.Vault.Generation);
    }

    [Fact]
    public void Notfallweg_bei_beschaedigter_Datei_ueber_die_Sicherungen()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        f.Vault.Upsert(KT.Entry("B"));
        f.Vault.Lock();
        var b = f.FileBytes();
        b[b.Length / 2] ^= 1;
        f.WriteFile(b);
        KT.Corrupt("file.checksum", () => f.Store.Recover(f.Code, KT.Pw2, KT.Kdf));
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCodeAgainstBackups(f.Code));
        using var g = KernVault.Make();
        KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => f.Store.CheckRecoveryCodeAgainstBackups(g.Code));
        var (v, used) = f.Store.RecoverFromNewestReadableBackup(f.Code, KT.Pw2, KT.Kdf);
        Assert.Equal(f.Vault.VaultId, used.VaultId);
        Assert.Equal(["A"], v.Entries.Select(x => x.Title));
        Assert.Equal(SecurityLevel.Standard, v.Level);
        Assert.True(v.RecoveryConfirmed);
        v.Lock();
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw2)));
        // die beschädigte Datei liegt als „beschaedigt-…“ in den Sicherungen
        Assert.Contains(FileIO.ListFiles(f.Store.BackupRoot), p => Path.GetFileName(p).StartsWith("beschaedigt-", StringComparison.Ordinal));
    }

    [Fact]
    public void Notfallweg_mit_Teilen_gegen_die_Sicherungen()
    {
        var (f, _, kit) = KernStufen.Make(SecurityLevel.Maximal);
        using (f)
        {
            f.Vault.Upsert(KT.Entry("A"));
            f.Vault.Upsert(KT.Entry("B"));
            var s = kit!.Shares.Select(x => x.Formatted).ToArray();
            f.Vault.Lock();
            var b = f.FileBytes();
            b[b.Length / 2] ^= 1;
            f.WriteFile(b);
            KT.Corrupt("file.checksum", () => f.Store.Recover([s[0], s[1]], KT.Pw2, KT.Kdf));
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], f.Store.CheckRecoverySharesAgainstBackups([s[0], s[1]]));
            var (v, used) = f.Store.RecoverFromNewestReadableBackup([s[1], s[2]], KT.Pw2, KT.Kdf);
            Assert.Equal(f.Vault.VaultId, used.VaultId);
            Assert.Equal(["A"], v.Entries.Select(x => x.Title));
            Assert.Equal(SecurityLevel.Standard, v.Level);
            Assert.True(v.RecoveryConfirmed);
            v.Lock();
        }
    }

    [Fact]
    public void Notfallweg_fuer_eine_gewaehlte_Datei_auf_einem_neuen_Geraet()
    {
        // Sicherung einer Stufe-4-Datei (Faktoren fehlen auf dem neuen Gerät) → Notfallcode bzw. Teile für genau diese Datei
        var (f, _, kit) = KernStufen.Make(SecurityLevel.Maximal);
        using (f)
        {
            f.Vault.Upsert(KT.Entry("Alt"));
            var copy = Path.Combine(f.Dir.Path, "vom-alten-geraet.siegel");
            f.Store.ExportBackup(copy);
            var s = kit!.Shares.Select(x => x.Formatted).ToArray();
            using var neu = new KernTempDir();
            var store = VaultStore.ForTesting(neu.Sub("Siegel"), new InMemoryRollbackGuard());
            // eben angelegter leerer Tresor: bleibt als „vor-notfall“
            var (fresh, _) = store.Create(KT.Pw3, KT.Kdf);
            var freshId = fresh.VaultId;
            fresh.Lock();
            Assert.Equal(RecoveryScheme.Shamir2Of3, VaultStore.InspectHeaderUnverified(copy).RecoveryScheme);
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], store.CheckRecoveryShares([s[0], s[2]], copy));
            KT.Throws(SiegelErrorCode.Io, "backup.missing", () => store.CheckRecoveryShares([s[0], s[2]], Path.Combine(neu.Path, "fehlt.siegel")));
            KT.Throws(SiegelErrorCode.Io, "backup.missing", () => store.RecoverBackup(Path.Combine(neu.Path, "fehlt.siegel"), [s[0], s[2]], KT.Pw2, KT.Kdf));
            var v = store.RecoverBackup(copy, [s[0], s[2]], KT.Pw2, KT.Kdf);
            Assert.Equal(f.Vault.VaultId, v.VaultId);
            Assert.Equal(["Alt"], v.Entries.Select(x => x.Title));
            Assert.Equal(SecurityLevel.Standard, v.Level);
            Assert.Equal(FactorSet.None, v.HeaderInfo.Factors);
            Assert.Contains(store.Backups(), b => b.Reason == "notfall" && b.VaultId == freshId);
            v.Lock();
            Assert.NotNull(KT.Unlocked(store.Unlock(KT.Pw2)));
        }
        // ein einzelner Code gegen eine Datei
        using var g = KernVault.Make();
        var file = Path.Combine(g.Dir.Path, "kopie.siegel");
        g.Store.ExportBackup(file);
        using var other = new KernTempDir();
        var s2 = VaultStore.ForTesting(other.Sub("Siegel"), new InMemoryRollbackGuard());
        Assert.Equal(RecoveryCodeMatch.Exact, s2.CheckRecoveryCode(g.Code, file));
        using var h = KernVault.Make();
        KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => s2.CheckRecoveryCode(h.Code, file));
        KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => s2.RecoverBackup(file, h.Code, KT.Pw2, KT.Kdf));
        var w = s2.RecoverBackup(file, g.Code, KT.Pw2, KT.Kdf);
        Assert.Equal(g.Vault.VaultId, w.VaultId);
        w.Lock();
    }

    [Fact]
    public void Kopf_ungeprueft_bei_beschaedigtem_Inhalt()
    {
        var (f, _, _) = KernStufen.Make(SecurityLevel.Maximal);
        using (f)
        {
            var b = f.FileBytes();
            b[b.Length - 100] ^= 1;
            f.WriteFile(b);
            KT.Corrupt("file.checksum", () => f.Store.Inspect());
            var info = f.Store.InspectHeaderUnverified();
            Assert.Equal(RecoveryScheme.Shamir2Of3, info.RecoveryScheme);
            Assert.Equal(f.Vault.VaultId, info.VaultId);
            File.Delete(f.Store.VaultPath);
            KT.Throws(SiegelErrorCode.VaultMissing, () => f.Store.InspectHeaderUnverified());
        }
    }
}
#endif
