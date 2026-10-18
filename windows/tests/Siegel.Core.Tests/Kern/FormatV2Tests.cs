#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Dateiformat v2 (§13.2): strenger Parser, Konsistenz Maske ↔ Nullfelder, Herabstufung (wie KernFormatV2Tests.swift).</summary>
public class FormatV2Tests
{
    /// <summary>Offsets im Kopf v2.</summary>
    private const int OffMask = 53, OffScheme = 54, OffSe = 55, OffTag = 71, OffCredLen = 75, OffCred = 77;

    private static RecoveryPublicKeys RandomPk() => new(Zufall.Bytes(RecoveryPublicKeys.PkMBytes), Zufall.Bytes(RecoveryPublicKeys.PkXBytes));

    private static byte[] NonZero(int n)
    {
        var b = Zufall.Bytes(n);
        b[0] |= 1;
        return b;
    }

    [Fact]
    public void Kopf_v2_Rundlauf_aller_Masken_Schemata_und_Credential_Laengen()
    {
        var vaultId = Zufall.Bytes(16);
        for (var raw = 0; raw <= 7; raw++)
        {
            foreach (var scheme in new[] { RecoveryScheme.SingleCode, RecoveryScheme.Shamir2Of3 })
            {
                foreach (var credLen in new[] { 16, 1024 })
                {
                    var mask = (FactorSet)raw;
                    var fields = new HeaderFactorFields(
                        mask.Contains(FactorKind.SecureEnclave) ? Zufall.NewGuid() : null,
                        mask.Contains(FactorKind.Card) ? Zufall.Bytes(4) : null,
                        mask.Contains(FactorKind.SecurityKey) ? Zufall.Bytes(credLen) : null,
                        mask.Contains(FactorKind.SecurityKey) ? NonZero(32) : null);
                    var h = VaultHeader.V2(vaultId, KT.Kdf, Zufall.Bytes(16), fields, scheme, RandomPk());
                    var extra = mask.Contains(FactorKind.SecurityKey) ? credLen : 0;
                    Assert.Equal(VaultHeader.V2FixedSize + extra, h.Bytes.Length);
                    var r = new ByteReader([.. h.Bytes, 9, 9, 9]);
                    var back = VaultHeader.Parse(r);
                    Assert.Equal(h, back);
                    Assert.Equal(3, r.Remaining);
                    Assert.Equal(mask, back.Factors);
                    Assert.Equal(fields, back.FactorFields);
                    var info = back.Info;
                    Assert.Equal(2, info.FormatVersion);
                    Assert.Equal(mask, info.Factors);
                    Assert.Equal(scheme, info.RecoveryScheme);
                    Assert.Equal(mask.Contains(FactorKind.SecureEnclave), info.SeKeyId is not null);
                    Assert.Equal(mask.Contains(FactorKind.Card), info.CardTag is not null);
                    Assert.Equal(mask.Contains(FactorKind.SecurityKey), info.FidoCredentialId is not null);
                    Assert.Equal(mask.Contains(FactorKind.SecurityKey), info.FidoSalt is not null);
                    // ungesetzte Felder sind Nullbytes
                    if (!mask.Contains(FactorKind.SecureEnclave)) { Assert.True(Bytes.AllZero(h.Bytes.AsSpan(OffSe, 16))); }
                    if (!mask.Contains(FactorKind.Card)) { Assert.True(Bytes.AllZero(h.Bytes.AsSpan(OffTag, 4))); }
                    if (!mask.Contains(FactorKind.SecurityKey)) { Assert.True(Bytes.AllZero(h.Bytes.AsSpan(OffCredLen, 2 + 32))); }
                }
            }
        }
    }

    [Fact]
    public void Kopf_v1_Rundlauf_und_Laenge()
    {
        var h = VaultHeader.V1(Zufall.Bytes(16), KT.Kdf, Zufall.Bytes(16), RandomPk());
        Assert.Equal(VaultHeader.V1Size, h.Bytes.Length);
        var back = VaultHeader.Parse(new ByteReader(h.Bytes));
        Assert.Equal(h, back);
        Assert.Equal(1, back.FormatVersion);
        Assert.Equal(FactorSet.None, back.Factors);
        Assert.Equal(RecoveryScheme.SingleCode, back.RecoveryScheme);
        Assert.Equal("Siegel v1 slot pw", System.Text.Encoding.ASCII.GetString(back.Labels.PwSlot));
    }

    [Fact]
    public void Kopf_v2_schreiben_lehnt_falsche_Faktor_Felder_ab()
    {
        var vid = Zufall.Bytes(16);
        HeaderFactorFields[] bad =
        [
            new(SeKeyId: Guid.Empty),
            new(CardTag: [1, 2, 3]),
            new(FidoCredentialId: Zufall.Bytes(15), FidoSalt: NonZero(32)),
            new(FidoCredentialId: Zufall.Bytes(1025), FidoSalt: NonZero(32)),
            new(FidoCredentialId: Zufall.Bytes(16)),
            new(FidoSalt: NonZero(32)),
            new(FidoCredentialId: Zufall.Bytes(16), FidoSalt: new byte[32]),
        ];
        foreach (var f in bad)
        {
            KT.Throws(SiegelErrorCode.Crypto, () => VaultHeader.V2(vid, KT.Kdf, Zufall.Bytes(16), f, RecoveryScheme.SingleCode, RandomPk()));
        }
    }

    [Fact]
    public void Strenger_Parser_Masken_Schema_Nullfelder_Credential_Laenge()
    {
        using var t = TestTresor.Create(SecurityLevel.Festung);
        var bytes = t.Bytes;
        var credLen = t.File.Header.FactorFields.FidoCredentialId!.Length;
        var saltAt = OffCred + credLen;
        byte[] Variant(Action<List<byte>> change)
        {
            var b = bytes.ToList();
            change(b);
            return KT.WithFixedChecksum([.. b]);
        }
        (string Code, byte[] Bytes)[] cases =
        [
            ("header.factorMask", Variant(b => b[OffMask] |= 0x08)),
            ("header.factorMask", Variant(b => b[OffMask] = 0x80)),
            ("header.recoveryScheme", Variant(b => b[OffScheme] = 0)),
            ("header.recoveryScheme", Variant(b => b[OffScheme] = 3)),
            ("header.seKeyID", Variant(b => b[OffMask] &= 0xFE)),
            ("header.seKeyID", Variant(b => { for (var i = OffSe; i < OffTag; i++) { b[i] = 0; } })),
            ("header.cardTag", Variant(b => b[OffMask] &= 0xFD)),
            ("header.fidoCredential", Variant(b => b[OffMask] &= 0xFB)),
            ("header.fidoCredential", Variant(b => { b[OffCredLen] = 15; b[OffCredLen + 1] = 0; })),
            ("header.fidoCredential", Variant(b => { b[OffCredLen] = 0x01; b[OffCredLen + 1] = 0x04; })),
            ("header.fidoCredential", Variant(b => { b[OffCredLen] = 0; b[OffCredLen + 1] = 0; })),
            ("header.fidoSalt", Variant(b => { for (var i = saltAt; i < saltAt + 32; i++) { b[i] = 0; } })),
            ("header.fidoSalt", Variant(b =>
            {
                // FIDO-Bit aus, Credential entfernt, Länge 0, aber Salz nicht null
                b[OffMask] &= 0xFB;
                b[OffCredLen] = 0;
                b[OffCredLen + 1] = 0;
                b.RemoveRange(OffCred, credLen);
            })),
            ("header.version", Variant(b => b[6] = 0)),
            ("header.kdfAlg", Variant(b => b[24] = 2)),
            ("header.magic", Variant(b => b[0] = (byte)'X')),
        ];
        foreach (var (code, v) in cases)
        {
            KT.Corrupt(code, () => VaultFile.Parse(v));
        }
    }

    [Fact]
    public void Neuere_Version_mit_eigenem_Pruefsummen_Label_ist_UnsupportedVersion()
    {
        using var t = TestTresor.Create();
        var b = (byte[])t.Bytes.Clone();
        b[6] = 3;
        // Ohne neue Prüfsumme: das Label der behaupteten Version passt nicht → Bitfäule.
        KT.Corrupt("file.checksum", () => VaultFile.Parse(b));
        var forged = KT.WithFixedChecksum(b);
        KT.Throws(SiegelErrorCode.UnsupportedVersion, "3", () => VaultFile.Parse(forged));
        KT.Throws(SiegelErrorCode.UnsupportedVersion, "3", () => VaultFile.Inspect(forged));
    }

    [Fact]
    public void Herabstufung_durch_Kopf_Aenderung_gelingt_nie()
    {
        using var t = TestTresor.Create(SecurityLevel.Festung);
        var file = t.File;
        var h = file.Header;
        var rest = t.Bytes[h.Bytes.Length..^FileFormat.ChecksumBytes];
        byte[] With(byte[] header) => KT.WithFixedChecksum([.. header, .. rest, .. new byte[32]]);
        var variants = new List<(string Name, byte[] Bytes, FactorSecrets Factors)>();
        foreach (var drop in new[] { FactorSet.SecureEnclave, FactorSet.Card, FactorSet.SecurityKey, FactorSet.All })
        {
            var fields = h.FactorFields;
            if (drop.Contains(FactorKind.SecureEnclave)) { fields = fields with { SeKeyId = null }; }
            if (drop.Contains(FactorKind.Card)) { fields = fields with { CardTag = null }; }
            if (drop.Contains(FactorKind.SecurityKey)) { fields = fields with { FidoCredentialId = null, FidoSalt = null }; }
            var nh = VaultHeader.V2(h.VaultId, h.Kdf, h.Salt, fields, h.RecoveryScheme, h.Pk);
            var f = new FactorSecrets
            {
                SecureEnclave = fields.Mask.Contains(FactorKind.SecureEnclave) ? t.Factors.SecureEnclave : null,
                Card = fields.Mask.Contains(FactorKind.Card) ? t.Factors.Card : null,
                SecurityKey = fields.Mask.Contains(FactorKind.SecurityKey) ? t.Factors.SecurityKey : null,
            };
            variants.Add(("ohne " + (int)drop, With(nh.Bytes), f));
        }
        variants.Add(("Schema 1", With(VaultHeader.V2(h.VaultId, h.Kdf, h.Salt, h.FactorFields, RecoveryScheme.SingleCode, h.Pk).Bytes),
            t.Factors));
        variants.Add(("v1-Kopf", With(VaultHeader.V1(h.VaultId, h.Kdf, h.Salt, h.Pk).Bytes), new FactorSecrets()));
        foreach (var (_, v, factors) in variants)
        {
            var parsed = VaultFile.Parse(v);
            KT.Throws(SiegelErrorCode.WrongPassword, () => VaultCrypto.OpenWithPassword(parsed, t.Password, factors, KdfLimits.Testing));
            KT.Corrupt("rec.slot", () => VaultCrypto.OpenWithRecovery(parsed, t.R));
        }
    }

    [Fact]
    public void Stufe_im_Inhalt_muss_zu_den_Faktoren_im_Kopf_passen()
    {
        using var t = TestTresor.Create();
        var header = t.File.Header;
        using var dek = SecureBuffer.Random(32);
        using var kek = SecureBuffer.Random(32);
        var slots = VaultCrypto.MakeSlots(header, kek, dek);
        using var content = VaultContent.Empty(Clock.Now());
        content.Level = SecurityLevel.Festung;
        var (bytes, _) = VaultCrypto.BuildFile(header, slots, 9, dek, content);
        KT.Corrupt("payload.level", () => VaultCrypto.DecryptPayload(VaultFile.Parse(bytes), dek));
    }

    [Fact]
    public void Beide_Wege_oeffnen_einen_frischen_Tresor_jeder_Stufe()
    {
        foreach (var level in Enum.GetValues<SecurityLevel>())
        {
            using var t = TestTresor.Create(level);
            var file = t.File;
            Assert.Equal(level.Factors(), file.Header.Factors);
            Assert.Equal(level.RecoveryScheme(), file.Header.RecoveryScheme);
            using var a = VaultCrypto.OpenWithPassword(file, t.Password, t.Factors, KdfLimits.Testing);
            using var b = VaultCrypto.OpenWithRecovery(file, t.R);
            Assert.True(a.Dek.ConstantTimeEquals(b.Dek));
            Assert.Equal(["Bank", "Mail"], a.Content.Entries.Select(e => e.Title));
            Assert.Equal(t.Content.Entries.Select(e => e.Password), b.Content.Entries.Select(e => e.Password));
            Assert.Equal(t.Content.Entries.Select(e => e.Created), a.Content.Entries.Select(e => e.Created));
            Assert.Equal(level, a.Content.Level);
            // Stufen 4/5: zwei Teile; sonst ein Code (beide gegen den Kopf geprüft)
            using var r = RecoveryMatching.CombineShares([t.Shares[2], t.Shares[0]]);
            Assert.True(r.ConstantTimeEquals(t.R));
            Assert.Equal(RecoveryCodeMatch.Exact,
                RecoveryMatching.MatchRecoveryCode(RecoveryCodeCodec.ParseSymbols(t.Code, true), file.Header));
        }
    }

    [Fact]
    public void Datei_Laengen_Grenzen()
    {
        KT.Corrupt("file.length", () => VaultFile.Parse(new byte[VaultHeader.V1Size + 31]));
        KT.Corrupt("file.length", () => VaultFile.VerifyChecksum(new byte[FileFormat.MaxFileBytes + 1]));
        KT.Corrupt("file.checksum", () => VaultFile.Parse(new byte[VaultHeader.V1Size + 32]));
    }
}
#endif
