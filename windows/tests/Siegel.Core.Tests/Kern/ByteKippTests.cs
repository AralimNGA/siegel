#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Bitfäule und gezielte Manipulation (SPEC §2, §10), mit dem Testschalter-KDF (8 KiB, t = 1), wie
/// KernByteKippTests.swift und KernFormatV2Tests.swift (jedesByteV2, angreiferV2).</summary>
public class ByteKippTests
{
    /// <summary>Format-v1-Datei mit Testschalter-KDF (v1 wird nie mehr geschrieben, hier nur für den Leser).</summary>
    private static (byte[] Bytes, SecureBuffer Password, SecureBuffer R) V1Tresor()
    {
        var vaultId = Zufall.Bytes(16);
        var r = SecureBuffer.Random(32);
        var pk = RecoveryKem.DerivePublicKeys(r, vaultId);
        var header = VaultHeader.V1(vaultId, KT.Kdf, Zufall.Bytes(16), pk);
        var pw = PasswordNormalizer.SecureBytes(KT.Pw1);
        using var kek = Kdf.DeriveKek(pw, header.Salt, KT.Kdf, KdfLimits.Testing);
        using var dek = SecureBuffer.Random(32);
        var slots = VaultCrypto.MakeSlots(header, kek, dek);
        using var content = VaultContent.Empty(Clock.Now());
        content.Entries.Add(TestTresor.Entry("Bank", password: "Konto-123", notes: "Notiz"));
        content.PrepareForSave(Clock.Now());
        var (bytes, _) = VaultCrypto.BuildFile(header, slots, 3, dek, content, legacyV1Content: true);
        return (bytes, pw, r);
    }

    private static void JedesByte(byte[] bytes, Func<VaultFile, IDisposable> passwordPath, Func<VaultFile, IDisposable> recoveryPath)
    {
        var findings = new Findings();
        foreach (var mask in new byte[] { 0x01, 0x80, 0xFF })
        {
            Parallel.For(0, bytes.Length, i =>
            {
                var b = (byte[])bytes.Clone();
                b[i] ^= mask;
                for (var path = 0; path < 2; path++)
                {
                    try
                    {
                        var file = VaultFile.Parse(b);
                        using var opened = path == 0 ? passwordPath(file) : recoveryPath(file);
                        findings.Add("ok " + i);
                    }
                    catch (SiegelException e)
                    {
                        if (e.Code != SiegelErrorCode.CorruptFile || e.Detail != "file.checksum") { findings.Add(i + ": " + e.Message); }
                    }
#pragma warning disable CA1031 // Der Test meldet jeden fremden Fehler als Befund statt abzubrechen.
                    catch (Exception e)
#pragma warning restore CA1031
                    {
                        findings.Add(i + ": fremder Fehler " + e.GetType().Name);
                    }
                }
            });
        }
        Assert.Empty(findings.All);
    }

    private static void Angreifer(byte[] bytes, Func<VaultFile, OpenedVault> passwordPath, Func<VaultFile, OpenedVault> recoveryPath,
        SiegelErrorCode[] allowedPw, SiegelErrorCode[] allowedRec)
    {
        var findings = new Findings();
        var body = bytes.Length - FileFormat.ChecksumBytes;
        foreach (var mask in new byte[] { 0x01, 0x80 })
        {
            Parallel.For(0, body, i =>
            {
                var b = (byte[])bytes.Clone();
                b[i] ^= mask;
                var forged = KT.WithFixedChecksum(b);
                foreach (var (path, allowed, name) in new[] { (passwordPath, allowedPw, "pw"), (recoveryPath, allowedRec, "rec") })
                {
                    try
                    {
                        using var opened = path(VaultFile.Parse(forged));
                        findings.Add(name + " ok " + i);
                    }
                    catch (SiegelException e)
                    {
                        if (!allowed.Contains(e.Code)) { findings.Add(name + " " + i + ": " + e.Message); }
                    }
#pragma warning disable CA1031 // Der Test meldet jeden fremden Fehler als Befund statt abzubrechen.
                    catch (Exception e)
#pragma warning restore CA1031
                    {
                        findings.Add(name + " " + i + ": fremder Fehler " + e.GetType().Name);
                    }
                }
            });
        }
        Assert.Empty(findings.All);
    }

    private static readonly SiegelErrorCode[] PwErlaubt =
    [
        SiegelErrorCode.WrongPassword, SiegelErrorCode.CorruptFile, SiegelErrorCode.KdfParametersOutOfRange,
        SiegelErrorCode.UnsupportedVersion, SiegelErrorCode.FactorMissing, SiegelErrorCode.WrongCard,
    ];

    private static readonly SiegelErrorCode[] RecErlaubt =
        [SiegelErrorCode.WrongRecoveryCode, SiegelErrorCode.CorruptFile, SiegelErrorCode.UnsupportedVersion];

    [Fact]
    public void Jedes_Byte_gekippt_Stufe_1_ist_file_checksum()
    {
        using var t = TestTresor.Create();
        JedesByte(t.Bytes, f => VaultCrypto.OpenWithPassword(f, t.Password, null, KdfLimits.Testing),
            f => VaultCrypto.OpenWithRecovery(f, t.R));
    }

    [Fact]
    public void Jedes_Byte_gekippt_Stufe_5_ist_file_checksum()
    {
        using var t = TestTresor.Create(SecurityLevel.Festung);
        JedesByte(t.Bytes, f => VaultCrypto.OpenWithPassword(f, t.Password, t.Factors, KdfLimits.Testing),
            f => VaultCrypto.OpenWithRecovery(f, t.R));
    }

    [Fact]
    public void Jedes_Byte_gekippt_Format_v1_ist_file_checksum()
    {
        var (bytes, pw, r) = V1Tresor();
        using (pw)
        using (r)
        {
            JedesByte(bytes, f => VaultCrypto.OpenWithPassword(f, pw, null, KdfLimits.Testing), f => VaultCrypto.OpenWithRecovery(f, r));
        }
    }

    [Fact]
    public void Jedes_Byte_der_Mac_Beispieldateien_gekippt_ist_file_checksum()
    {
        // Die Prüfsumme greift vor jedem Argon2: auch mit echten 256 MiB bleibt das schnell.
        foreach (var name in new[] { "v1_beispiel.siegel", "v2_beispiel.siegel" })
        {
            var bytes = Fixtures.MacBytes(name);
            var findings = new Findings();
            Parallel.For(0, bytes.Length, i =>
            {
                var b = (byte[])bytes.Clone();
                b[i] ^= 0x01;
                try
                {
                    _ = VaultFile.Parse(b);
                    findings.Add("ok " + i);
                }
                catch (SiegelException e) when (e.Code == SiegelErrorCode.CorruptFile && e.Detail == "file.checksum")
                {
                }
            });
            Assert.Empty(findings.All);
        }
    }

    [Fact]
    public void Angreifer_Stufe_1_Byte_kippen_und_Pruefsumme_neu_nie_Erfolg()
    {
        using var t = TestTresor.Create();
        Angreifer(t.Bytes, f => VaultCrypto.OpenWithPassword(f, t.Password, null, KdfLimits.Testing),
            f => VaultCrypto.OpenWithRecovery(f, t.R), PwErlaubt, RecErlaubt);
    }

    [Fact]
    public void Angreifer_Stufe_5_Byte_kippen_und_Pruefsumme_neu_nie_Erfolg()
    {
        using var t = TestTresor.Create(SecurityLevel.Festung);
        Angreifer(t.Bytes, f => VaultCrypto.OpenWithPassword(f, t.Password, t.Factors, KdfLimits.Testing),
            f => VaultCrypto.OpenWithRecovery(f, t.R), PwErlaubt, RecErlaubt);
    }

    [Fact]
    public void Angreifer_Format_v1_Byte_kippen_und_Pruefsumme_neu_nie_Erfolg()
    {
        var (bytes, pw, r) = V1Tresor();
        using (pw)
        using (r)
        {
            Angreifer(bytes, f => VaultCrypto.OpenWithPassword(f, pw, null, KdfLimits.Testing), f => VaultCrypto.OpenWithRecovery(f, r),
                PwErlaubt, RecErlaubt);
        }
    }

    [Fact]
    public void Abgeschnitten_oder_verlaengert_ist_corruptFile_auch_mit_neuer_Pruefsumme()
    {
        using var t = TestTresor.Create();
        var bytes = t.Bytes;
        var hl = KT.HeaderLength(bytes);
        var variants = new List<byte[]>();
        foreach (var cut in new[] { 1, 31, 32, 33, 100, 16_384, bytes.Length - hl, bytes.Length - 1653, bytes.Length - 1, bytes.Length })
        {
            variants.Add(bytes[..(bytes.Length - cut)]);
        }
        foreach (var extra in new[] { 1, 16, 32, 16_384 }) { variants.Add([.. bytes, .. new byte[extra]]); }
        variants.Add(KT.WithFixedChecksum(bytes[..^1]));
        variants.Add(KT.WithFixedChecksum([.. bytes, 0]));
        variants.Add(KT.WithFixedChecksum(bytes[..(hl + VaultSlots.Size + 36 + 32)]));
        var inserted = bytes.ToList();
        inserted.Insert(hl + VaultSlots.Size + 36, 0);
        variants.Add(KT.WithFixedChecksum([.. inserted]));
        foreach (var v in variants)
        {
            var e1 = Assert.Throws<SiegelException>(() => VaultCrypto.OpenWithPassword(VaultFile.Parse(v), t.Password, null, KdfLimits.Testing));
            Assert.Equal(SiegelErrorCode.CorruptFile, e1.Code);
            var e2 = Assert.Throws<SiegelException>(() => VaultCrypto.OpenWithRecovery(VaultFile.Parse(v), t.R));
            Assert.Equal(SiegelErrorCode.CorruptFile, e2.Code);
        }
    }

    [Fact]
    public void Unveraendert_oeffnen_beide_Wege_und_v1_liefert_Migrations_KEK()
    {
        var (bytes, pw, r) = V1Tresor();
        using (pw)
        using (r)
        {
            var file = VaultFile.Parse(bytes);
            using var a = VaultCrypto.OpenWithPassword(file, pw, null, KdfLimits.Testing);
            using var b = VaultCrypto.OpenWithRecovery(file, r);
            Assert.Equal("Bank", Assert.Single(a.Content.Entries).Title);
            Assert.Equal("Notiz", Assert.Single(b.Content.Entries).Notes);
            // Migrations-KEK = HKDF(p, kdfSalt, "Siegel v2 kek" ‖ 0) öffnet einen v2-Kopf mit demselben Salz.
            Assert.NotNull(a.MigrationKek);
            var v2 = file.Header.Rebuilt(file.Header.Salt, factors: HeaderFactorFields.None);
            using var p = Kdf.DeriveKek(pw, v2.Salt, v2.Kdf, KdfLimits.Testing);
            using var kek = FactorKdf.Kek(p, v2, new FactorSecrets());
            Assert.True(kek.ConstantTimeEquals(a.MigrationKek!));
        }
    }
}
#endif
