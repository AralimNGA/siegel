#if DEBUG
using System.Buffers.Binary;
using Siegel.Modell;
using Siegel.Werkzeuge;

namespace Siegel.Core.Tests.Kern;

/// <summary>Zugangswechsel, KDF-Grenzen, Passwort-Regel (Gegenstück zu KernZugangTests.swift).</summary>
public class ZugangTests
{
    [Fact]
    public void Passwortwechsel_rotiert_DEK_und_Salz_Notfallcode_bleibt()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("Bank"));
        var oldFile = f.ParsedFile();
        using var oldDek = f.Vault.DekForTesting();
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Vault.ChangeMasterPassword(KT.Pw2, KT.Pw3));
        Assert.Equal(oldFile.Generation, f.ParsedFile().Generation);

        f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2);
        var newFile = f.ParsedFile();
        Assert.Equal(oldFile.Generation + 1, newFile.Generation);
        Assert.NotEqual(oldFile.Header.Salt, newFile.Header.Salt);
        Assert.Equal(oldFile.Header.Pk, newFile.Header.Pk);
        Assert.Equal(oldFile.Header.VaultId, newFile.Header.VaultId);
        using var newDek = f.Vault.DekForTesting();
        Assert.False(newDek.ConstantTimeEquals(oldDek));
        KT.Corrupt("payload.auth", () => VaultCrypto.DecryptPayload(newFile, oldDek));
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(KT.Pw1));
        Assert.True(f.Vault.Verify(KT.Pw2));
        Assert.False(f.Vault.Verify(KT.Pw1));
        var again = KT.Unlocked(f.Store.Unlock(KT.Pw2))!;
        Assert.Equal(["Bank"], again.Entries.Select(x => x.Title));
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(f.Code));
        using var r = RecoveryCodeCodec.Decode(f.Code);
        using var viaCode = VaultCrypto.OpenWithRecovery(newFile, r);
        Assert.True(viaCode.Dek.ConstantTimeEquals(newDek));
        var pinned = f.LocalBackups().Where(b => b.Reason == "passwortwechsel").ToList();
        Assert.Single(pinned);
        Assert.Equal(oldFile.Generation, pinned[0].Generation);
        again.Lock();
    }

    [Fact]
    public void Profilwechsel_mit_gleichem_Passwort_rotiert_ebenfalls()
    {
        using var f = KernVault.Make();
        var old = f.ParsedFile();
        f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw1, KT.Kdf2);
        Assert.Equal(KT.Kdf2, f.Vault.Kdf);
        var fresh = f.ParsedFile();
        Assert.Equal(KT.Kdf2, fresh.Header.Kdf);
        Assert.NotEqual(old.Header.Salt, fresh.Header.Salt);
        f.Vault.Lock();
        Assert.Equal(KT.Kdf2, KT.Unlocked(f.Store.Unlock(KT.Pw1))!.Kdf);
    }

    [Fact]
    public void Kdf_Grenzen_beim_Schreiben()
    {
        using var dir = new KernTempDir();
        var prod = new VaultStore(dir.Sub("Prod"), new InMemoryRollbackGuard());
        KdfParameters[] outOfRange =
        [
            new(3, 128UL << 20), new(3, (4UL << 30) + 1024), new(2, 1UL << 30), new(11, 1UL << 30), new(3, (1UL << 30) + 1),
        ];
        foreach (var p in outOfRange) { KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => prod.Create(KT.Pw1, p)); }
        Assert.False(prod.VaultExists);
        KdfLimits.Production.Validate(KdfParameters.Standard);
        KdfLimits.Production.Validate(KdfParameters.Strong);
        KdfLimits.Production.Validate(new KdfParameters(10, 4UL << 30));

        using var f = KernVault.Make();
        foreach (var p in new KdfParameters[] { new(1, 4UL << 10), new(4, 8UL << 10), new(1, (1UL << 20) + 1024), KdfParameters.Standard })
        {
            KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2, p));
            KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => f.Store.Recover(f.Code, KT.Pw2, p));
        }
        Assert.Equal(1UL, f.ParsedFile().Generation);
    }

    [Fact]
    public void Kdf_Grenzen_beim_Lesen_vor_Argon2()
    {
        using var f = KernVault.Make();
        var bytes = f.FileBytes();
        var prod = new VaultStore(f.Store.DirectoryPath, new InMemoryRollbackGuard());
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => prod.Unlock(KT.Pw1));
        byte[] Patched(uint? ops = null, ulong? mem = null)
        {
            var b = (byte[])bytes.Clone();
            if (ops is { } o) { BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(25, 4), o); }
            if (mem is { } m) { BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(29, 8), m); }
            return KT.WithFixedChecksum(b);
        }
        foreach (var v in new[] { Patched(mem: 8UL << 30), Patched(ops: 1000), Patched(ops: 0), Patched(mem: 4UL << 10), Patched(mem: (16UL << 10) + 1) })
        {
            f.WriteFile(v);
            var start = DateTime.UtcNow;
            KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => f.Store.Unlock(KT.Pw1));
            Assert.True((DateTime.UtcNow - start).TotalSeconds < 30);
        }
        f.WriteFile(Patched(ops: 2));
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(KT.Pw1));
    }

    [Fact]
    public void Policy_create_change_recover_werfen_PasswordTooWeak()
    {
        using var dir = new KernTempDir();
        var store = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        foreach (var weak in new[] { KT.Weak, "", "aaaaaaaa", string.Concat(Enumerable.Repeat("Ab1!", 300)) })
        {
            KT.Throws(SiegelErrorCode.PasswordTooWeak, () => store.Create(weak, KT.Kdf));
        }
        Assert.False(store.VaultExists);
        using var f = KernVault.Make();
        var e1 = KT.Throws(SiegelErrorCode.PasswordTooWeak, () => f.Vault.ChangeMasterPassword(KT.Pw1, KT.Weak));
        KT.Throws(SiegelErrorCode.PasswordTooWeak, () => f.Store.Recover(f.Code, KT.Weak, KT.Kdf));
        Assert.Equal(1UL, f.ParsedFile().Generation);
        Assert.Equal(MasterPasswordPolicy.Check(KT.Weak).Bits, e1.Bits);
    }

    [Fact]
    public void Wiederverwendung_masterPasswordReuse_und_Reused()
    {
        using var f = KernVault.Make();
        var same = KT.Entry("Gleich", password: KT.Pw1);
        var viaHistory = KT.Entry("Verlauf", password: KT.Pw1);
        var other = KT.Entry("Anders", password: KT.Pw3);
        var normalized = KT.Entry("Normalisiert", password: "u,F?CfDuMlYWuJASPVQ*6GUG@O");
        f.Vault.Upsert(same);
        f.Vault.Upsert(viaHistory);
        viaHistory.Password = "Neu-Und-Anders-1";
        f.Vault.Upsert(viaHistory);
        f.Vault.Upsert(other);
        f.Vault.Upsert(normalized);
        Assert.Equal(new HashSet<Guid> { same.Id, viaHistory.Id, normalized.Id }, f.Vault.MasterPasswordReuse.ToHashSet());
        KT.Throws(SiegelErrorCode.MasterPasswordReused, () => f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw3));
        KT.Throws(SiegelErrorCode.MasterPasswordReused, () => f.Store.Recover(f.Code, KT.Pw3, KT.Kdf));
        f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2);
        Assert.Empty(f.Vault.MasterPasswordReuse);
        other.Password = KT.Pw2;
        f.Vault.Upsert(other);
        Assert.Equal(new HashSet<Guid> { other.Id }, f.Vault.MasterPasswordReuse.ToHashSet());
        f.Vault.Lock();
        var again = KT.Unlocked(f.Store.Unlock(KT.Pw2))!;
        Assert.Equal(new HashSet<Guid> { other.Id }, again.MasterPasswordReuse.ToHashSet());
        again.Lock();
        using var g = KernVault.Make("t=5:U.+F3mYW O6#O8@s~@~4_q:");
        g.Vault.Upsert(KT.Entry("NBSP", password: "t=5:U.+F3mYW O6#O8@s~@~4_q:"));
        Assert.Single(g.Vault.MasterPasswordReuse);
    }
}

/// <summary>Format v1 → v2 mit selbst gebauten v1-Dateien (Gegenstück zu KernMigrationTests.swift).</summary>
public class MigrationTests
{
    /// <summary>Schreibt eine v1-Datei wie der Kern v3.1 (Kopf v1, KEK = Argon2, Labels „Siegel v1 …“, Inhalt v 1).</summary>
    internal static string WriteV1(VaultStore store, IEnumerable<VaultEntry> entries, string password = KT.Pw1, ulong generation = 5,
        bool confirmed = true)
    {
        var vaultId = Bytes.OfGuid(Guid.NewGuid());
        using var r = SecureBuffer.Random(32);
        var pk = RecoveryKem.DerivePublicKeys(r, vaultId);
        var header = VaultHeader.V1(vaultId, KT.Kdf, Zufall.Bytes(16), pk);
        using var pw = PasswordNormalizer.SecureBytes(password);
        using var kek = Kdf.DeriveKek(pw, header.Salt, header.Kdf, KdfLimits.Testing);
        using var dek = SecureBuffer.Random(32);
        var slots = VaultCrypto.MakeSlots(header, kek, dek);
        using var content = new VaultContent(Clock.Now(), confirmed ? Clock.Now() : null, SecurityLevel.Standard, EntryFactorKeys.None, [.. entries]);
        content.PrepareForSave(Clock.Now());
        var (padded, _) = PayloadCodec.Encode(content, legacyV1: true);
        using (padded)
        {
            var (nonce, ct) = Aead.Seal(dek, padded, VaultFile.PayloadAdFor(header, slots, generation));
            FileIO.EnsureDirectory(store.DirectoryPath);
            FileIO.WriteExclusive(store.VaultPath, new VaultFile(header, slots, generation, nonce, ct).Serialize());
        }
        return RecoveryCodeCodec.Format(r);
    }

    [Fact]
    public void Selbst_gebaute_v1_Datei_ist_wirklich_v1()
    {
        using var dir = new KernTempDir();
        var s = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        WriteV1(s, [KT.Entry("A")]);
        var bytes = File.ReadAllBytes(s.VaultPath);
        Assert.Equal(VaultHeader.V1Size + VaultSlots.Size + 36 + 16_400 + 32, bytes.Length);
        var file = VaultFile.Parse(bytes);
        Assert.Equal(1, file.Header.FormatVersion);
        Assert.Equal(Bytes.Ascii("Siegel v1 payload"), file.Header.Labels.Payload);
        using var pw = PasswordNormalizer.SecureBytes(KT.Pw1);
        using var opened = VaultCrypto.OpenWithPassword(file, pw, null, KdfLimits.Testing);
        Assert.NotNull(opened.MigrationKek);
        using var padded = Aead.Open(opened.Dek, file.Nonce, file.Ciphertext, file.PayloadAd)!;
        var json = PayloadCodec.JsonStringForTesting(padded)!;
        Assert.Contains("\"v\":1", json, StringComparison.Ordinal);
        Assert.DoesNotContain("level", json, StringComparison.Ordinal);
        Assert.DoesNotContain("totp", json, StringComparison.Ordinal);
    }

    public enum Weg { Upsert, Passwort, Notfall, Kit, Stufe, Sicherung }

    [Theory]
    [InlineData(Weg.Upsert)]
    [InlineData(Weg.Passwort)]
    [InlineData(Weg.Notfall)]
    [InlineData(Weg.Kit)]
    [InlineData(Weg.Stufe)]
    [InlineData(Weg.Sicherung)]
    public void Jeder_Schreibweg_migriert(Weg weg)
    {
        using var dir = new KernTempDir();
        var s = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        var code = WriteV1(s, [KT.Entry("A")]);
        var v1Bytes = File.ReadAllBytes(s.VaultPath);
        var password = KT.Pw1;
        string? validCode = code;
        switch (weg)
        {
            case Weg.Upsert:
                KT.Unlocked(s.Unlock(KT.Pw1))!.Upsert(KT.Entry("B"));
                break;
            case Weg.Passwort:
                KT.Unlocked(s.Unlock(KT.Pw1))!.ChangeMasterPassword(KT.Pw1, KT.Pw2);
                password = KT.Pw2;
                break;
            case Weg.Notfall:
                s.Recover(code, KT.Pw2, KT.Kdf).Lock();
                password = KT.Pw2;
                break;
            case Weg.Kit:
            {
                var v = KT.Unlocked(s.Unlock(KT.Pw1))!;
                var p = v.PrepareRecovery(KT.Pw1);
                v.CommitRecovery(p, KernStufen.Confirmation(p));
                validCode = p.Code.Formatted;
                break;
            }
            case Weg.Stufe:
                KT.Unlocked(s.Unlock(KT.Pw1))!.ChangeSecurityLevel(SecurityLevel.Standard, KT.Pw1, new FactorSecrets(), new NewFactorMaterial(), null, []);
                break;
            case Weg.Sicherung:
            {
                var kopie = Path.Combine(dir.Path, "v1.siegel");
                File.WriteAllBytes(kopie, v1Bytes);
                s.ImportBackup(kopie, KT.Pw1).Lock();
                break;
            }
        }
        Assert.Equal(2, s.Inspect().FormatVersion);
        var pinned = s.Backups().Where(b => b.Reason == "migration-v1").ToList();
        Assert.Single(pinned);
        Assert.Equal(v1Bytes, File.ReadAllBytes(pinned[0].Path));
        var again = KT.Unlocked(s.Unlock(password))!;
        Assert.Contains(again.Entries, e => e.Title == "A");
        Assert.Equal(2, again.HeaderInfo.FormatVersion);
        if (validCode is not null) { Assert.Equal(RecoveryCodeMatch.Exact, s.CheckRecoveryCode(validCode)); }
        again.Lock();
        var restored = s.RestoreBackup(pinned[0], KT.Pw1);
        Assert.Equal(["A"], restored.Entries.Select(x => x.Title));
        restored.Lock();
    }

    [Fact]
    public void V1_Pruefsumme_mit_v1_Label()
    {
        using var dir = new KernTempDir();
        var s = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        var code = WriteV1(s, []);
        var b = File.ReadAllBytes(s.VaultPath);
        Assert.Equal(FileFormat.FileChecksum(b.AsSpan(0, b.Length - 32), 1), b[^32..]);
        Assert.NotEqual(FileFormat.FileChecksum(b.AsSpan(0, b.Length - 32), 2), b[^32..]);
        b[100] ^= 1;
        File.Delete(s.VaultPath);
        File.WriteAllBytes(s.VaultPath, b);
        KT.Corrupt("file.checksum", () => s.Unlock(KT.Pw1));
        KT.Corrupt("file.checksum", () => s.CheckRecoveryCode(code));
    }
}
#endif
