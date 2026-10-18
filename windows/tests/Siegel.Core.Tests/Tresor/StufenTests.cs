#if DEBUG
using System.Security.Cryptography;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Faktoren und Stufen (Gegenstück zu KernStufenTests.swift).</summary>
public class StufenTests
{
    private static NewFactorMaterial WithoutExisting(NewFactorMaterial m, FactorSet existing) => new(
        existing.Contains(FactorKind.SecureEnclave) ? null : m.SecureEnclave,
        existing == FactorSet.None ? m.EntryKey : null,
        existing.Contains(FactorKind.Card) ? null : m.Card,
        existing.Contains(FactorKind.SecurityKey) ? null : m.SecurityKey);

    [Fact]
    public void Fehlende_und_falsche_Faktoren()
    {
        var (f, k, _) = KernStufen.Make(SecurityLevel.Festung);
        using (f)
        {
            f.Vault.Lock();
            var counter = new TestHooks.Counter();
            using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
            {
                foreach (var kind in FactorKindExtensions.AllKinds)
                {
                    var set = FactorSet.All & ~(FactorSet)(byte)kind;
                    KT.Throws(SiegelErrorCode.FactorMissing, kind.Code(), () => f.Store.Unlock(KT.Pw1, k.Secrets(set)));
                }
                KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => f.Store.Unlock(KT.Pw1));
                var wrongCard = k.Secrets();
                wrongCard.Card = CardCode.Generate();
                KT.Throws(SiegelErrorCode.WrongCard, () => f.Store.Unlock(KT.Pw1, wrongCard));
            }
            Assert.Equal(0, counter.Value);
            var wrongSe = k.Secrets();
            wrongSe.SecureEnclave = KernFaktoren.Secret(RandomNumberGenerator.GetBytes(32));
            KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(KT.Pw1, wrongSe));
            var wrongKey = k.Secrets();
            wrongKey.SecurityKey = KernFaktoren.Secret(RandomNumberGenerator.GetBytes(32));
            KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(KT.Pw1, wrongKey));
            KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(KT.Pw2, k.Secrets()));
            var v = KT.Unlocked(f.Store.Unlock(KT.Pw1, k.Secrets()))!;
            Assert.Equal(SecurityLevel.Festung, v.Level);
            Assert.True(v.Verify(KT.Pw1, k.Secrets()));
            Assert.False(v.Verify(KT.Pw1, k.Secrets(FactorSet.SecureEnclave | FactorSet.Card)));
            Assert.False(v.Verify(KT.Pw1));
            v.Lock();
        }
    }

    [Fact]
    public void Aufwaerts_1_bis_5_jede_Stufe_rotiert_und_verlangt_ihre_Faktoren()
    {
        using var f = KernVault.Make();
        var k = new KernFaktoren();
        f.Vault.Upsert(KT.Entry("Bank"));
        var current = FactorSet.None;
        foreach (var level in new[] { SecurityLevel.Erhoeht, SecurityLevel.Hoch, SecurityLevel.Maximal, SecurityLevel.Festung })
        {
            var oldFile = f.ParsedFile();
            using var oldDek = f.Vault.DekForTesting();
            var kit = KernStufen.Change(f.Vault, level, k, current, WithoutExisting(k.Material(level), current));
            var newFile = f.ParsedFile();
            Assert.NotEqual(oldFile.Header.Salt, newFile.Header.Salt);
            using (var d = f.Vault.DekForTesting()) { Assert.False(d.ConstantTimeEquals(oldDek)); }
            KT.Corrupt("payload.auth", () => VaultCrypto.DecryptPayload(newFile, oldDek));
            Assert.Equal(level.Factors(), newFile.Header.Factors);
            Assert.Equal(level.RecoveryScheme(), newFile.Header.RecoveryScheme);
            Assert.Equal(f.Store.Limits.Profile(level), newFile.Header.Kdf);
            Assert.Equal(level, f.Vault.Level);
            Assert.Equal(level.Policy(), f.Vault.Policy);
            Assert.Equal(f.Store.Inspect(), f.Vault.HeaderInfo);
            Assert.Equal(level >= SecurityLevel.Maximal, f.Vault.RecoveryConfirmed);
            if (level == SecurityLevel.Maximal) { Assert.Equal(RecoveryScheme.Shamir2Of3, kit!.Scheme); }
            Assert.Contains(f.LocalBackups(), b => b.Reason == "stufenwechsel" && b.Generation == oldFile.Generation);
            current = level.Factors();
            var again = KT.Unlocked(f.Store.Unlock(KT.Pw1, k.Secrets(current)))!;
            Assert.Equal(["Bank"], again.Entries.Select(x => x.Title));
            Assert.Equal(level, again.Level);
            again.Lock();
        }
        Assert.Equal(FactorSet.All, f.Vault.EnrolledFactors);
        Assert.Equal(k.SeKeyId, f.Vault.HeaderInfo.SeKeyId);
        using var q = FactorSecret.Copy(k.Q);
        Assert.Equal(CardCode.Tag(q, f.Vault.VaultId), f.Vault.HeaderInfo.CardTag!.Value.ToArray());
        Assert.Equal(k.CredentialId, f.Vault.HeaderInfo.FidoCredentialId!.Value.ToArray());
        Assert.Equal(k.Salt, f.Vault.HeaderInfo.FidoSalt!.Value.ToArray());
        Assert.Equal(k.CredentialId, f.Vault.SecurityKeyCredential!.Value.CredentialId.ToArray());
    }

    [Fact]
    public void Abwaerts_5_bis_1_Entsperr_Schluessel_erst_nach_dem_Schreiben_entfernt()
    {
        var (f, k, kit) = KernStufen.Make(SecurityLevel.Festung);
        using (f)
        {
            Assert.Equal(RecoveryScheme.Shamir2Of3, kit!.Scheme);
            f.Vault.Upsert(KT.Entry("A"));
            var a = f.Vault.Entries[0];
            Assert.Equal(EntryProtection.Fingerabdruck, a.Protection);
            Assert.True(a.SecretsSealed);
            f.Vault.SetProtection(EntryProtection.Normal, a.Id, new EntrySecrets { Password = "Geheim-123" });
            FileIO.EnsureDirectory(f.Store.HardwareDirectory);
            var blob = Path.Combine(f.Store.HardwareDirectory, Bytes.GuidText(k.SeKeyId) + ".siegelhw");
            var other = Path.Combine(f.Store.HardwareDirectory, Bytes.GuidText(k.EntryKeyId) + ".siegelhw");
            File.WriteAllBytes(blob, [1, 2, 3]);
            File.WriteAllBytes(other, [4, 5, 6]);
            KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => f.Vault.ChangeSecurityLevel(SecurityLevel.Hoch, KT.Pw1, k.Secrets(),
                new NewFactorMaterial(), null, []));
            var single = f.Vault.PrepareRecovery(KT.Pw1, k.Secrets(), RecoveryScheme.SingleCode);
            KT.Throws(SiegelErrorCode.WrongPassword, () => f.Vault.ChangeSecurityLevel(SecurityLevel.Hoch, KT.Pw2, k.Secrets(),
                new NewFactorMaterial(), single, KernStufen.Confirmation(single)));
            Assert.True(File.Exists(blob));
            f.Vault.ChangeSecurityLevel(SecurityLevel.Hoch, KT.Pw1, k.Secrets(), new NewFactorMaterial(), single, KernStufen.Confirmation(single));
            Assert.Equal(SecurityLevel.Hoch, f.Vault.Level);
            Assert.Equal(FactorSet.SecureEnclave, f.Vault.HeaderInfo.Factors);
            Assert.Equal(RecoveryScheme.SingleCode, f.Vault.HeaderInfo.RecoveryScheme);
            Assert.Equal(single.Code.KitId, f.Vault.KitId);
            Assert.True(File.Exists(blob));
            Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(single.Code.Formatted));
            KernStufen.Change(f.Vault, SecurityLevel.Standard, k, FactorSet.SecureEnclave, new NewFactorMaterial());
            Assert.Equal(FactorSet.None, f.Vault.HeaderInfo.Factors);
            Assert.Null(f.Vault.HeaderInfo.SeKeyId);
            Assert.False(File.Exists(blob));
            Assert.True(File.Exists(other));
            Assert.Equal(FactorSet.All, f.Vault.EnrolledFactors);
            f.Vault.Lock();
            var v = KT.Unlocked(f.Store.Unlock(KT.Pw1))!;
            Assert.Equal(["A"], v.Entries.Select(x => x.Title));
            Assert.Equal(SecurityLevel.Standard, v.Level);
            v.Lock();
        }
    }

    [Fact]
    public void Stufenwechsel_braucht_Passwort_und_alle_aktuellen_Faktoren()
    {
        var (f, k, _) = KernStufen.Make(SecurityLevel.Hoch);
        using (f)
        {
            var gen = f.Vault.Generation;
            var mat = k.Material(SecurityLevel.Hoch);
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => f.Vault.ChangeSecurityLevel(SecurityLevel.Erhoeht, KT.Pw1,
                new FactorSecrets(), new NewFactorMaterial(), null, []));
            KT.Throws(SiegelErrorCode.WrongPassword, () => f.Vault.ChangeSecurityLevel(SecurityLevel.Erhoeht, KT.Pw2,
                k.Secrets(FactorSet.SecureEnclave), new NewFactorMaterial(), null, []));
            var shamir = f.Vault.PrepareRecovery(KT.Pw1, k.Secrets(FactorSet.SecureEnclave), RecoveryScheme.Shamir2Of3);
            KT.Throws(SiegelErrorCode.FactorMissing, "card", () => f.Vault.ChangeSecurityLevel(SecurityLevel.Maximal, KT.Pw1,
                k.Secrets(FactorSet.SecureEnclave), new NewFactorMaterial(), shamir, KernStufen.Confirmation(shamir)));
            var wrong = KernStufen.Confirmation(shamir);
            wrong[2] = wrong[2] == "00000" ? "11111" : "00000";
            KT.Throws(SiegelErrorCode.RecoveryConfirmationMismatch, () => f.Vault.ChangeSecurityLevel(SecurityLevel.Maximal, KT.Pw1,
                k.Secrets(FactorSet.SecureEnclave), mat, shamir, wrong));
            var single = f.Vault.PrepareRecovery(KT.Pw1, k.Secrets(FactorSet.SecureEnclave), RecoveryScheme.SingleCode);
            KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => f.Vault.ChangeSecurityLevel(SecurityLevel.Maximal, KT.Pw1,
                k.Secrets(FactorSet.SecureEnclave), mat, single, KernStufen.Confirmation(single)));
            Assert.Equal(gen, f.Vault.Generation);
            Assert.Equal(gen, f.ParsedFile().Generation);
            Assert.Equal(SecurityLevel.Hoch, f.Vault.Level);
        }
    }

    [Fact]
    public void Faktoren_fuer_Eintraege_einrichten_dieselbe_Karte_oeffnet_spaeter_den_Tresor()
    {
        using var f = KernVault.Make();
        var k = new KernFaktoren();
        using var dekBefore = f.Vault.DekForTesting();
        var saltBefore = f.ParsedFile().Header.Salt;
        Assert.Equal(FactorSet.None, f.Vault.EnrolledFactors);
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Vault.EnrollFactors(new NewFactorMaterial(Card: k.Card), KT.Pw2, new FactorSecrets()));
        f.Vault.EnrollFactors(new NewFactorMaterial(null, k.EntryKey, k.Card, k.SecurityKey), KT.Pw1, new FactorSecrets());
        Assert.Equal(FactorSet.All, f.Vault.EnrolledFactors);
        Assert.Equal(SecurityLevel.Standard, f.Vault.Level);
        Assert.Equal(DeviceKeyKind.SecureEnclaveP256, f.Vault.EntryDeviceKeyKind);
        using (var d = f.Vault.DekForTesting()) { Assert.True(d.ConstantTimeEquals(dekBefore)); }
        Assert.Equal(saltBefore, f.ParsedFile().Header.Salt);
        Assert.Equal(k.CredentialId, f.Vault.SecurityKeyCredential!.Value.CredentialId.ToArray());
        using (var content = f.Vault.ContentForTesting!)
        {
            var vid = Bytes.OfGuid(f.Vault.VaultId);
            using var q = FactorSecret.Copy(k.Q);
            using var y2 = FactorSecret.Copy(k.EntryOutput);
            Assert.Equal(EntryKeyDerivation.CardPublicKeys(q, vid), content.EntryFactors.Card!.Pk);
            Assert.Equal(EntryKeyDerivation.FidoPublicKeys(y2, vid), content.EntryFactors.SecurityKey!.Pk);
            Assert.Equal(k.EntryPublicKey, content.EntryFactors.SecureEnclave!.PublicKey);
        }
        f.Vault.Lock();
        var v = KT.Unlocked(f.Store.Unlock(KT.Pw1))!;
        Assert.Equal(FactorSet.All, v.EnrolledFactors);
        var shamir = v.PrepareRecovery(KT.Pw1, new FactorSecrets(), RecoveryScheme.Shamir2Of3);
        var se = new NewFactorMaterial(k.SeEnrollment);
        KT.Throws(SiegelErrorCode.WrongCard, () => v.ChangeSecurityLevel(SecurityLevel.Maximal, KT.Pw1,
            new FactorSecrets { Card = CardCode.Generate() }, se, shamir, KernStufen.Confirmation(shamir)));
        v.ChangeSecurityLevel(SecurityLevel.Maximal, KT.Pw1, new FactorSecrets { Card = FactorSecret.Copy(k.Q) }, se, shamir,
            KernStufen.Confirmation(shamir));
        using (var q = FactorSecret.Copy(k.Q)) { Assert.Equal(CardCode.Tag(q, v.VaultId), v.HeaderInfo.CardTag!.Value.ToArray()); }
        var current = k.Secrets(FactorSet.SecureEnclave | FactorSet.Card);
        current.SecurityKey = KernFaktoren.Secret(RandomNumberGenerator.GetBytes(32));
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.ChangeSecurityLevel(SecurityLevel.Festung, KT.Pw1, current, new NewFactorMaterial(), null, []));
        current.SecurityKey = KernFaktoren.Secret(k.Output);
        v.ChangeSecurityLevel(SecurityLevel.Festung, KT.Pw1, current, new NewFactorMaterial(), null, []);
        Assert.Equal(k.CredentialId, v.HeaderInfo.FidoCredentialId!.Value.ToArray());
        Assert.Equal(k.Salt, v.HeaderInfo.FidoSalt!.Value.ToArray());
        v.Lock();
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw1, k.Secrets())));
    }

    [Fact]
    public void Einrichten_geprueft_andere_Karte_anderer_Schluessel_ungueltiges_Material()
    {
        var (f, k, _) = KernStufen.Make(SecurityLevel.Festung);
        using (f)
        {
            var gen = f.Vault.Generation;
            KT.Throws(SiegelErrorCode.WrongCard, () => f.Vault.EnrollFactors(new NewFactorMaterial(Card: new CardEnrollment(CardCode.Generate())),
                KT.Pw1, k.Secrets()));
            var otherKey = new SecurityKeyEnrollment(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
                KernFaktoren.Secret(RandomNumberGenerator.GetBytes(32)), RandomNumberGenerator.GetBytes(32), KernFaktoren.Secret(RandomNumberGenerator.GetBytes(32)));
            KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => f.Vault.EnrollFactors(new NewFactorMaterial(SecurityKey: otherKey), KT.Pw1, k.Secrets()));
            f.Vault.EnrollFactors(new NewFactorMaterial(Card: k.Card, SecurityKey: k.SecurityKey), KT.Pw1, k.Secrets());
            Assert.Equal(gen, f.Vault.Generation);
            NewFactorMaterial[] bad =
            [
                new(EntryKey: new EntryKeyEnrollment(Guid.NewGuid(), Enumerable.Repeat((byte)4, 65).ToArray())),
                new(EntryKey: new EntryKeyEnrollment(Guid.NewGuid(), Enumerable.Repeat((byte)4, 33).ToArray())),
                new(EntryKey: new EntryKeyEnrollment(Guid.Empty, P256.RandomPoint())),
                new(EntryKey: EntryKeyEnrollment.WindowsHello(Guid.NewGuid()) with { PublicKey = P256.RandomPoint() }),
                new(SecurityKey: new SecurityKeyEnrollment(new byte[8], RandomNumberGenerator.GetBytes(32), KernFaktoren.Secret(k.Output),
                    RandomNumberGenerator.GetBytes(32), KernFaktoren.Secret(k.EntryOutput))),
                new(SecurityKey: new SecurityKeyEnrollment(RandomNumberGenerator.GetBytes(20), k.Salt, KernFaktoren.Secret(k.Output), k.Salt,
                    KernFaktoren.Secret(k.EntryOutput))),
                new(SecureEnclave: new SEEnrollment(Guid.Empty, KernFaktoren.Secret(k.EcdhSe))),
            ];
            foreach (var m in bad) { KT.Throws(SiegelErrorCode.Crypto, () => f.Vault.EnrollFactors(m, KT.Pw1, k.Secrets())); }
            Assert.Equal(gen, f.Vault.Generation);
        }
    }

    [Fact]
    public void Neue_Faktoren_ersetzen_alte_alter_Entsperr_Schluessel_wird_entfernt()
    {
        var (f, k, _) = KernStufen.Make(SecurityLevel.Maximal);
        using (f)
        {
            FileIO.EnsureDirectory(f.Store.HardwareDirectory);
            var oldBlob = Path.Combine(f.Store.HardwareDirectory, Bytes.GuidText(k.SeKeyId).ToLowerInvariant() + ".siegelhw");
            File.WriteAllBytes(oldBlob, [1]);
            var n = new KernFaktoren();
            f.Vault.ChangeSecurityLevel(SecurityLevel.Maximal, KT.Pw1, k.Secrets(FactorSet.SecureEnclave | FactorSet.Card),
                new NewFactorMaterial(n.SeEnrollment, Card: n.Card), null, []);
            Assert.False(File.Exists(oldBlob));
            Assert.Equal(n.SeKeyId, f.Vault.HeaderInfo.SeKeyId);
            f.Vault.Lock();
            KT.Throws(SiegelErrorCode.WrongCard, () => f.Store.Unlock(KT.Pw1, k.Secrets(FactorSet.SecureEnclave | FactorSet.Card)));
            Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw1, n.Secrets(FactorSet.SecureEnclave | FactorSet.Card))));
        }
    }

    [Fact]
    public void Regeln_der_Stufe_KDF_Profil_und_CSV_Export()
    {
        var (f, k, _) = KernStufen.Make(SecurityLevel.Hoch);
        using (f)
        {
            Assert.Equal(f.Store.Limits.Profile(SecurityLevel.Hoch), f.Vault.Kdf);
            KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw1, k.Secrets(FactorSet.SecureEnclave),
                f.Store.Limits.Profile(SecurityLevel.Standard)));
            f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2, k.Secrets(FactorSet.SecureEnclave));
            Assert.Equal(FactorSet.SecureEnclave, f.Vault.HeaderInfo.Factors);
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => f.Store.Unlock(KT.Pw2));
            Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw2, k.Secrets(FactorSet.SecureEnclave))));
            var target = f.Dir.Sub("Export");
            using (KT.Hook(() => TestHooks.CsvExporter = items => [.. System.Text.Encoding.UTF8.GetBytes("csv:" + items.Count)],
                       () => TestHooks.CsvExporter = null))
            {
                KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => f.Vault.ExportCsv(target, KT.Pw2));
                var path = f.Vault.ExportCsv(target, KT.Pw2, k.Secrets(FactorSet.SecureEnclave));
                Assert.Equal("Siegel-Export.csv", Path.GetFileName(path));
            }
        }
        var (g, gk, _) = KernStufen.Make(SecurityLevel.Maximal);
        using (g)
        {
            var counter = new TestHooks.Counter();
            using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
            {
                KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => g.Vault.ExportCsv(g.Dir.Sub("Export"), KT.Pw1, gk.Secrets(FactorSet.SecureEnclave | FactorSet.Card)));
            }
            Assert.Equal(0, counter.Value);
            Assert.False(g.Vault.Policy.AllowCsvExport);
            Assert.Equal(EntryProtection.Fingerabdruck, g.Vault.Policy.DefaultEntryProtection);
        }
    }

    [Fact]
    public void Sicherungen_einsetzen_braucht_die_Faktoren_der_Sicherung()
    {
        var (f, k, _) = KernStufen.Make(SecurityLevel.Erhoeht);
        using (f)
        {
            f.Vault.Upsert(KT.Entry("A"));
            f.Vault.Upsert(KT.Entry("B"));
            var newest = f.LocalBackups()[0];
            f.Vault.Lock();
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => f.Store.RestoreBackup(newest, KT.Pw1));
            var v = f.Store.RestoreBackup(newest, KT.Pw1, k.Secrets(FactorSet.SecureEnclave));
            Assert.Equal(["A"], v.Entries.Select(x => x.Title));
            Assert.Equal(SecurityLevel.Erhoeht, v.Level);
            Assert.Equal(k.SeKeyId, v.HeaderInfo.SeKeyId);
            v.Lock();
            var b = f.FileBytes();
            b[b.Length / 2] ^= 1;
            f.WriteFile(b);
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => f.Store.RestoreNewestReadableBackup(KT.Pw1));
            var (w, used) = f.Store.RestoreNewestReadableBackup(KT.Pw1, k.Secrets(FactorSet.SecureEnclave));
            Assert.Equal(w.VaultId, used.VaultId);
            Assert.Equal(SecurityLevel.Erhoeht, w.Level);
            var kopie = Path.Combine(f.Dir.Path, "kopie.siegel");
            f.Store.ExportBackup(kopie);
            w.Lock();
            using var dir = new KernTempDir();
            var other = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => other.ImportBackup(kopie, KT.Pw1));
            var imported = other.ImportBackup(kopie, KT.Pw1, k.Secrets(FactorSet.SecureEnclave));
            Assert.Equal(SecurityLevel.Erhoeht, imported.Level);
            Assert.Equal(FactorSet.SecureEnclave, other.Inspect().Factors);
            imported.Lock();
        }
    }

    [Fact]
    public void Notfall_Wiederherstellung_setzt_Stufe_1()
    {
        var (f, _, kit) = KernStufen.Make(SecurityLevel.Maximal);
        using (f)
        {
            var e = KT.Entry("Geschützt");
            e.Protection = EntryProtection.Maximal;
            // Ohne Eintrags-Faktoren lässt sich Schutz 4 nicht versiegeln (Karte ist da, Eintrags-SE fehlt nicht: Material der Stufe)
            f.Vault.Upsert(e);
            Assert.Equal(EntryProtection.Maximal, f.Vault.Entries[0].Protection);
            f.Vault.Lock();
            var shares = kit!.Shares.Select(s => s.Formatted).ToArray();
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => f.Store.Unlock(KT.Pw1));
            var v = f.Store.Recover([shares[2], shares[0]], KT.Pw2, KT.Kdf);
            Assert.Equal(SecurityLevel.Standard, v.Level);
            Assert.Equal(FactorSet.None, v.EnrolledFactors);
            Assert.Equal(EntryProtection.Normal, v.Entries[0].Protection);
            Assert.False(v.Entries[0].SecretsSealed);
            Assert.Equal("Geheim-123", v.Entries[0].Password);
            Assert.Equal(FactorSet.None, v.HeaderInfo.Factors);
            Assert.Equal(RecoveryScheme.Shamir2Of3, v.HeaderInfo.RecoveryScheme);
            Assert.True(v.RecoveryConfirmed);
            v.Lock();
            Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw2)));
        }
    }
}
#endif
