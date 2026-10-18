#if DEBUG
using System.Text.Json;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Die Mac-Beispieldateien über den ganzen Tresor-Weg (<see cref="VaultStore"/>) mit echtem Argon2, seriell
/// (Gegenstück zu KernEchteProfileTests.swift und KernFixtureV2Tests.swift; die Krypto-Ebene prüft BeispielDateiTests).
/// </summary>
[Collection("EchteProfile")]
public class EchteProfileTests
{
    private const ulong V1Generation = 6;
    private const ulong V2Generation = 7;
    private const string V2KitId = "2RMY-XAAA";
    private static readonly KdfParameters Kdf256 = new(3, 256UL << 20);

    private static (KernTempDir Dir, VaultStore Store) Copy(string name)
    {
        var dir = new KernTempDir();
        var store = new VaultStore(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        File.Copy(Fixtures.Mac(name), store.VaultPath);
        return (dir, store);
    }

    /// <summary>Einträge eines geöffneten Tresors gegen referenz/erwartet_v*.json.</summary>
    private static void Check(UnlockedVault v, string reference, int extra = 0)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Fixtures.Referenz(reference)));
        var expected = doc.RootElement.GetProperty("eintraege").EnumerateArray().ToList();
        Assert.Equal(expected.Count + extra, v.Entries.Count);
        foreach (var e in expected)
        {
            var found = Assert.Single(v.Entries, x => x.Title == e.GetProperty("title").GetString());
            Assert.Equal(e.GetProperty("username").GetString(), found.Username);
            Assert.Equal(e.GetProperty("password").GetString(), found.Password);
            Assert.Equal(e.GetProperty("url").GetString(), found.Url);
            Assert.Equal(e.GetProperty("verlauf").EnumerateArray().Select(x => x.GetString()), found.History.Select(h => h.Password));
        }
        Assert.Equal(BeispielDateien.Notiz3, v.Entries.Single(x => x.Title == "Notiz ohne Website").Notes);
    }

    [Fact]
    public void V2_Kopf_Auskunft_ohne_Geheimnis_und_ohne_Argon2()
    {
        var counter = new TestHooks.Counter();
        VaultHeaderInfo info;
        using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
        {
            info = VaultStore.Inspect(Fixtures.Mac("v2_beispiel.siegel"));
        }
        Assert.Equal(0, counter.Value);
        Assert.Equal(2, info.FormatVersion);
        Assert.Equal(BeispielDateien.V2VaultId, Bytes.GuidText(info.VaultId));
        Assert.Equal(FactorSet.All, info.Factors);
        Assert.Equal(RecoveryScheme.Shamir2Of3, info.RecoveryScheme);
        Assert.Equal(Guid.Parse("11111111-2222-4333-8444-555555555555"), info.SeKeyId);
        Assert.Equal("b2fdc001", KT.Hex(info.CardTag!.Value.Span));
        Assert.Equal(KT.Repeat(0x44, 64), info.FidoCredentialId?.ToArray());
        Assert.Equal(KT.Repeat(0x55, 32), info.FidoSalt?.ToArray());
        Assert.Equal(Kdf256, info.Kdf);
        Assert.Equal(V2KitId, info.KitId);
    }

    [Fact]
    public void V2_oeffnet_ueber_Passwort_und_alle_drei_Faktoren_ohne_zu_schreiben()
    {
        var (dir, store) = Copy("v2_beispiel.siegel");
        using (dir)
        {
            var before = File.ReadAllBytes(store.VaultPath);
            using var vault = KT.Unlocked(store.Unlock(BeispielDateien.V2Password, BeispielDateien.V2Factors()))!;
            Check(vault, "erwartet_v2_beispiel.json");
            Assert.Equal(BeispielDateien.V2VaultId, Bytes.GuidText(vault.VaultId));
            Assert.Equal(V2Generation, vault.Generation);
            Assert.Equal(V2KitId, vault.KitId);
            Assert.Equal(SecurityLevel.Festung, vault.Level);
            Assert.Equal(FactorSet.All, vault.EnrolledFactors);
            Assert.Equal(DeviceKeyKind.SecureEnclaveP256, vault.EntryDeviceKeyKind);
            Assert.True(vault.RecoveryConfirmed);
            Assert.Equal(Kdf256, vault.Kdf);
            Assert.Equal(store.Inspect(), vault.HeaderInfo);
            Assert.Equal(SecurityLevel.Festung.Policy(), vault.Policy);
            Assert.Equal(before, File.ReadAllBytes(store.VaultPath));
        }
    }

    [Fact]
    public void V2_fehlender_Faktor_und_falsche_Karte_vor_Argon2()
    {
        var (dir, store) = Copy("v2_beispiel.siegel");
        using (dir)
        {
            var counter = new TestHooks.Counter();
            using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
            {
                foreach (var kind in new[] { FactorKind.SecureEnclave, FactorKind.Card, FactorKind.SecurityKey })
                {
                    var f = BeispielDateien.V2Factors();
                    switch (kind)
                    {
                        case FactorKind.SecureEnclave: f.SecureEnclave = null; break;
                        case FactorKind.Card: f.Card = null; break;
                        default: f.SecurityKey = null; break;
                    }
                    KT.Throws(SiegelErrorCode.FactorMissing, kind.Code(), () => store.Unlock(BeispielDateien.V2Password, f));
                }
                KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => store.Unlock(BeispielDateien.V2Password));
                var wrongCard = BeispielDateien.V2Factors();
                wrongCard.Card = KT.Factor(0x23);
                KT.Throws(SiegelErrorCode.WrongCard, () => store.Unlock(BeispielDateien.V2Password, wrongCard));
            }
            Assert.Equal(0, counter.Value);
        }
    }

    [Fact]
    public void V2_falscher_Faktor_Wert_oder_falsches_Passwort_ist_WrongPassword()
    {
        var (dir, store) = Copy("v2_beispiel.siegel");
        using (dir)
        {
            var wrongSe = BeispielDateien.V2Factors();
            wrongSe.SecureEnclave = KT.Factor(0x12);
            KT.Throws(SiegelErrorCode.WrongPassword, () => store.Unlock(BeispielDateien.V2Password, wrongSe));
            var wrongKey = BeispielDateien.V2Factors();
            wrongKey.SecurityKey = KT.Factor(0x34);
            KT.Throws(SiegelErrorCode.WrongPassword, () => store.Unlock(BeispielDateien.V2Password, wrongKey));
            KT.Throws(SiegelErrorCode.WrongPassword, () => store.Unlock(KT.Pw1, BeispielDateien.V2Factors()));
        }
    }

    [Fact]
    public void V2_ueber_je_zwei_Teile_alle_Paare_beide_Reihenfolgen()
    {
        var s = BeispielDateien.V2Shares;
        foreach (var (a, b) in new[] { (0, 1), (0, 2), (1, 2) })
        {
            var (dir, store) = Copy("v2_beispiel.siegel");
            using (dir)
            {
                Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], store.CheckRecoveryShares([s[a], s[b]]));
                Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], store.CheckRecoveryShares([s[b], s[a]]));
                Assert.Equal(a + 1, VaultStore.RecoveryShareIndex(s[a]));
                using (var vault = store.Recover([s[a], s[b]], KT.Pw2, Kdf256))
                {
                    // Wiederherstellung: Stufe 1, keine Faktoren, Kit (Teile) bleibt gültig.
                    Check(vault, "erwartet_v2_beispiel.json");
                    Assert.Equal(SecurityLevel.Standard, vault.Level);
                    Assert.Equal(FactorSet.None, vault.EnrolledFactors);
                    Assert.True(vault.RecoveryConfirmed);
                    Assert.Equal(V2Generation + 1, vault.Generation);
                    var info = store.Inspect();
                    Assert.Equal(FactorSet.None, info.Factors);
                    Assert.Equal(RecoveryScheme.Shamir2Of3, info.RecoveryScheme);
                    Assert.Equal(V2KitId, info.KitId);
                    Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], store.CheckRecoveryShares([s[a], s[b]]));
                }
                using var again = KT.Unlocked(store.Unlock(KT.Pw2));
                Assert.NotNull(again);
                Assert.Contains(store.Backups(), x => x.Reason == BackupNaming.Reason.Recovery);
            }
        }
    }

    [Fact]
    public void V1_oeffnet_ueber_Passwort_und_Notfallcode_Wiederherstellung_schreibt_v2_mit_angehefteter_Sicherung()
    {
        var (dir, store) = Copy("v1_beispiel.siegel");
        using (dir)
        {
            var before = File.ReadAllBytes(store.VaultPath);
            using (var vault = KT.Unlocked(store.Unlock(BeispielDateien.V1Password))!)
            {
                Check(vault, "erwartet_v1_beispiel.json");
                Assert.Equal(BeispielDateien.V1VaultId, Bytes.GuidText(vault.VaultId));
                Assert.Equal(V1Generation, vault.Generation);
                Assert.Equal(1, vault.HeaderInfo.FormatVersion);
            }
            Assert.Equal(before, File.ReadAllBytes(store.VaultPath));
            Assert.Equal(RecoveryCodeMatch.Exact, store.CheckRecoveryCode(BeispielDateien.V1Code));
            using (var vault = store.Recover(BeispielDateien.V1Code, KT.Pw2, Kdf256))
            {
                Check(vault, "erwartet_v1_beispiel.json");
                Assert.Equal(V1Generation + 1, vault.Generation);
            }
            using (var again = KT.Unlocked(store.Unlock(KT.Pw2))) { Assert.NotNull(again); }
            KT.Throws(SiegelErrorCode.WrongPassword, () => store.Unlock(BeispielDateien.V1Password));
            Assert.Equal(RecoveryCodeMatch.Exact, store.CheckRecoveryCode(BeispielDateien.V1Code));
            Assert.Equal(2, store.Inspect().FormatVersion);
            var pinned = store.Backups().Where(b => b.Reason == BackupNaming.Reason.MigrationV1).ToList();
            Assert.Single(pinned);
            Assert.Equal(V1Generation, pinned[0].Generation);
            Assert.Equal(before, File.ReadAllBytes(pinned[0].Path));
        }
    }

    [Fact]
    public void V1_erstes_Speichern_migriert_ohne_zweites_Argon2_Passwort_und_Code_gelten_weiter()
    {
        var (dir, store) = Copy("v1_beispiel.siegel");
        using (dir)
        {
            var original = File.ReadAllBytes(store.VaultPath);
            Assert.Equal(1, store.Inspect().FormatVersion);
            var counter = new TestHooks.Counter();
            UnlockedVault vault;
            using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
            {
                vault = KT.Unlocked(store.Unlock(BeispielDateien.V1Password))!;
                Assert.Equal(1, vault.HeaderInfo.FormatVersion);
                vault.Upsert(KT.Entry("Neu nach Migration"));
            }
            using (vault)
            {
                Assert.Equal(1, counter.Value);
                var info = store.Inspect();
                Assert.Equal(2, info.FormatVersion);
                Assert.Equal(FactorSet.None, info.Factors);
                Assert.Equal(RecoveryScheme.SingleCode, info.RecoveryScheme);
                Assert.Equal(vault.HeaderInfo, info);
                Assert.Equal(V1Generation + 1, vault.Generation);
                var pinned = store.Backups().Where(b => b.Reason == BackupNaming.Reason.MigrationV1).ToList();
                Assert.Single(pinned);
                Assert.Equal(original, File.ReadAllBytes(pinned[0].Path));
                // Weitere Speicherungen sind normal (keine weitere Migrationssicherung).
                vault.Upsert(KT.Entry("Zweiter"));
                Assert.Single(store.Backups(), b => b.Reason == BackupNaming.Reason.MigrationV1);
            }
            using (var again = KT.Unlocked(store.Unlock(BeispielDateien.V1Password))!)
            {
                Check(again, "erwartet_v1_beispiel.json", extra: 2);
                Assert.Equal(2, again.HeaderInfo.FormatVersion);
            }
            Assert.Equal(RecoveryCodeMatch.Exact, store.CheckRecoveryCode(BeispielDateien.V1Code));
            using var rec = store.Recover(BeispielDateien.V1Code, KT.Pw2, Kdf256);
            Assert.Equal(5, rec.Entries.Count);
        }
    }

    [Fact]
    public void Standardprofil_1_GiB_anlegen_entsperren_falsches_Passwort()
    {
        using var dir = new KernTempDir();
        var store = new VaultStore(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        var (vault, _) = store.Create(KT.Pw1);
        using (vault)
        {
            Assert.Equal(KdfParameters.Standard, vault.Kdf);
            vault.Upsert(KT.Entry("Bank"));
        }
        using (var again = KT.Unlocked(store.Unlock(KT.Pw1))!) { Assert.Equal(["Bank"], again.Entries.Select(e => e.Title)); }
        KT.Throws(SiegelErrorCode.WrongPassword, () => store.Unlock(KT.Pw2));
    }
}
#endif
