#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Feste Testvektoren (SPEC §10, Fixtures/README.md). Werte NIE ändern.</summary>
public class TestvektorTests
{
    // (a) R = 00 01 … 1f, vaultID = a0 a1 … af
    internal static readonly byte[] R = KT.Seq(0, 32);
    internal static readonly byte[] VaultIdA = KT.Seq(0xa0, 16);
    internal const string Sha3PkM = "07d2a982d901e86a75c81c97704b1a66571c8ae4664039ec55e286cbbac206f2";
    internal const string PkX = "157638f533039b946e64edc0135d67ad5c805d89cc0530bec075e14266213107";
    internal const string Code = "000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FRAC8";
    internal const string KitId = "HKEH-KJPJ";

    [Fact]
    public void A_pkM_pkX_Code_und_Kit_aus_R()
    {
        using var r = KT.Secure(R);
        var pk = RecoveryKem.DerivePublicKeys(r, VaultIdA);
        Assert.Equal(1568, pk.PkM.Length);
        Assert.Equal(Sha3PkM, KT.Hex(Sha3Hasher.Of(pk.PkM)));
        Assert.Equal(PkX, KT.Hex(pk.PkX));
        Assert.Equal(Code, RecoveryCodeCodec.Format(r));
        using var back = RecoveryCodeCodec.Decode(Code);
        Assert.True(back.ConstantTimeEquals(r));
        Assert.True(RecoveryKem.Matches(r, VaultIdA, pk));
        Assert.Equal(KitId, pk.KitId);
        Assert.Equal(KitId, RecoveryCodeCodec.KitId(pk.PkM, pk.PkX));
    }

    [Fact]
    public void A_Kit_Kennung_hat_das_Format_XXXX_XXXX()
    {
        using var r = KT.Secure(R);
        var kit = RecoveryKem.DerivePublicKeys(r, VaultIdA).KitId;
        Assert.Equal(9, kit.Length);
        Assert.Equal('-', kit[4]);
        Assert.All(kit.Replace("-", "", StringComparison.Ordinal), c => Assert.Contains(c, RecoveryCodeCodec.AlphabetText));
    }

    [Fact]
    public void A_anderes_R_oder_andere_vaultID_passt_nicht()
    {
        using var r = KT.Secure(R);
        var pk = RecoveryKem.DerivePublicKeys(r, VaultIdA);
        var other = (byte[])R.Clone();
        other[31] ^= 1;
        using var r2 = KT.Secure(other);
        Assert.False(RecoveryKem.Matches(r2, VaultIdA, pk));
        var vid2 = (byte[])VaultIdA.Clone();
        vid2[0] ^= 1;
        Assert.False(RecoveryKem.Matches(r, vid2, pk));
    }

    [Fact]
    public void C_KEK_rec_der_v1_Beispieldatei_ohne_Argon2()
    {
        var file = VaultFile.Parse(Fixtures.MacBytes("v1_beispiel.siegel"));
        Assert.Equal(1, file.Header.FormatVersion);
        using var r = RecoveryCodeCodec.Decode(BeispielDateien.V1Code);
        using var kek = RecoveryKem.Decapsulate(r, file.Header.VaultId, file.Header.Pk, file.Slots.CtM, file.Slots.CtX,
            file.Header.Labels.HybridKem);
        Assert.Equal("c406914254c7efdd3c75b9510e779fa6553b3776c0ffa7c2c988c4259ce3f9d8", kek.HexForTesting());
        using var dek = Aead.Unwrap(kek, file.Slots.RecSlot, VaultSlots.RecAd(file.Header));
        Assert.NotNull(dek);
        Assert.Equal(new KdfParameters(3, 256UL << 20), file.Header.Kdf);
        Assert.Equal(6UL, file.Generation);
    }

    [Fact]
    public void E_Mehrfaktor_KAT_der_v2_Beispieldatei_ohne_Argon2()
    {
        var vid = Bytes.OfGuid(Guid.Parse(BeispielDateien.V2VaultId));
        var salt = KT.FromHex("e1a44dd212cc4e593c56f3c2aeef12c1");
        using var p = KT.Secure(KT.FromHex("0aba515de29ce382121b9355eb693daebc778d6378affdf4719f2c25f618b2d0"));
        using var se = KT.Factor(0x11);
        using var q = KT.Factor(0x22);
        using var fido = KT.Factor(0x33);
        using var e = FactorKdf.FactorKey(se, FactorKind.SecureEnclave, vid);
        using var c = FactorKdf.FactorKey(q, FactorKind.Card, vid);
        using var y = FactorKdf.FactorKey(fido, FactorKind.SecurityKey, vid);
        Assert.Equal("8fbcf78df09ce432ff8b693dd8c8dce0aba9c424280e7a17763677aa2fd776d5", e.HexForTesting());
        Assert.Equal("d57682004bbd6e767859be1a1306e9f8499a829a7184cf88d57560685b1c961d", c.HexForTesting());
        Assert.Equal("89f8f8f3c3d18b6756605cda1a1860df54afaa61b5d11413837e58a613a1c4c6", y.HexForTesting());
        const string kekHex = "c15d504d2f670fbf21d5ba74fc2395139ef5aafc826d87bae6bac24c5f096c89";
        using var kek = FactorKdf.Kek(p, [e, c, y], salt, 7);
        Assert.Equal(kekHex, kek.HexForTesting());
        // Über den Kopf der Datei (Reihenfolge und Maske aus dem Kopf), und dieser KEK öffnet pwSlot und Inhalt.
        var file = VaultFile.Parse(Fixtures.MacBytes("v2_beispiel.siegel"));
        Assert.Equal("e1a44dd212cc4e593c56f3c2aeef12c1", KT.Hex(file.Header.Salt));
        var factors = new FactorSecrets { SecureEnclave = se, Card = q, SecurityKey = fido };
        using var kek2 = FactorKdf.Kek(p, file.Header, factors);
        Assert.Equal(kekHex, kek2.HexForTesting());
        using var dek = Aead.Unwrap(kek2, file.Slots.PwSlot, VaultSlots.PwAd(file.Header));
        Assert.NotNull(dek);
        var (content, _) = VaultCrypto.DecryptPayload(file, dek);
        using (content)
        {
            Assert.Equal(SecurityLevel.Festung, content.Level);
            Assert.Equal(3, content.Entries.Count);
            Assert.Equal(FactorSet.All, content.EntryFactors.Enrolled);
            Assert.Equal(Guid.Parse("66666666-7777-4888-8999-AAAAAAAAAAAA"), content.EntryFactors.SecureEnclave?.KeyId);
            Assert.Equal(KT.Repeat(0x44, 64), content.EntryFactors.SecurityKey?.CredentialId);
            Assert.Equal(KT.Repeat(0x66, 32), content.EntryFactors.SecurityKey?.EntrySalt);
            Assert.Equal(KT.Repeat(0x55, 32), content.EntryFactors.SecurityKey?.Salt);
        }
    }

    [Fact]
    public void D_Kartenkennung_der_v2_Beispieldatei()
    {
        using var q = KT.Factor(0x22);
        Assert.Equal("b2fdc001", KT.Hex(CardCode.Tag(q, Guid.Parse(BeispielDateien.V2VaultId))));
    }

    [Fact]
    public void D_Kopf_Auskunft_ohne_Argon2()
    {
        var bytes = Fixtures.MacBytes("v2_beispiel.siegel");
        Assert.Equal(19_985, bytes.Length);
        Assert.Equal("53c78ad55d5126ae72b9f02595104238b4d3c46359006c654713f27e6c82dff5",
            KT.Hex(System.Security.Cryptography.SHA256.HashData(bytes)));
        var counter = new TestHooks.Counter();
        TestHooks.KdfCounter = counter;
        try
        {
            var info = VaultFile.Inspect(bytes);
            Assert.Equal(0, counter.Value);
            Assert.Equal(2, info.FormatVersion);
            Assert.Equal(BeispielDateien.V2VaultId, Bytes.GuidText(info.VaultId));
            Assert.Equal(FactorSet.All, info.Factors);
            Assert.Equal(RecoveryScheme.Shamir2Of3, info.RecoveryScheme);
            Assert.Equal(Guid.Parse("11111111-2222-4333-8444-555555555555"), info.SeKeyId);
            Assert.Equal("b2fdc001", KT.Hex(info.CardTag!.Value.Span));
            Assert.Equal(KT.Repeat(0x44, 64), info.FidoCredentialId!.Value.ToArray());
            Assert.Equal(KT.Repeat(0x55, 32), info.FidoSalt!.Value.ToArray());
            Assert.Equal(new KdfParameters(3, 256UL << 20), info.Kdf);
            Assert.Equal("2RMY-XAAA", info.KitId);
        }
        finally
        {
            TestHooks.KdfCounter = null;
        }
        var v1 = VaultFile.Inspect(Fixtures.MacBytes("v1_beispiel.siegel"));
        Assert.Equal(1, v1.FormatVersion);
        Assert.Equal(FactorSet.None, v1.Factors);
        Assert.Equal(RecoveryScheme.SingleCode, v1.RecoveryScheme);
        Assert.Null(v1.SeKeyId);
        Assert.Null(v1.CardTag);
        Assert.Equal("3Q0A-CCCJ", v1.KitId);
        Assert.Equal(BeispielDateien.V1VaultId, Bytes.GuidText(v1.VaultId));
    }

    [Fact]
    public void D_Teile_der_v2_Beispieldatei_ergeben_das_Kit_ohne_Argon2()
    {
        var file = VaultFile.Parse(Fixtures.MacBytes("v2_beispiel.siegel"));
        foreach (var (a, b) in new[] { (0, 1), (0, 2), (1, 2), (2, 0) })
        {
            using var r = RecoveryMatching.CombineShares([BeispielDateien.V2Shares[a], BeispielDateien.V2Shares[b]]);
            Assert.True(RecoveryKem.Matches(r, file.Header.VaultId, file.Header.Pk));
        }
        Assert.Equal(1, Shamir.IndexOf(BeispielDateien.V2Shares[0]));
        Assert.Equal(3, Shamir.IndexOf(BeispielDateien.V2Shares[2]));
    }

    [Fact]
    public void Fehlender_Faktor_und_falsche_Karte_vor_Argon2()
    {
        var file = VaultFile.Parse(Fixtures.MacBytes("v2_beispiel.siegel"));
        using var pw = PasswordNormalizer.SecureBytes(BeispielDateien.V2Password);
        var counter = new TestHooks.Counter();
        TestHooks.KdfCounter = counter;
        try
        {
            foreach (var kind in FactorKindExtensions.AllKinds)
            {
                var f = BeispielDateien.V2Factors();
                switch (kind)
                {
                    case FactorKind.SecureEnclave: f.SecureEnclave = null; break;
                    case FactorKind.Card: f.Card = null; break;
                    default: f.SecurityKey = null; break;
                }
                KT.Throws(SiegelErrorCode.FactorMissing, kind.Code(),
                    () => VaultCrypto.OpenWithPassword(file, pw, f, KdfLimits.Production));
            }
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave",
                () => VaultCrypto.OpenWithPassword(file, pw, null, KdfLimits.Production));
            var wrongCard = BeispielDateien.V2Factors();
            wrongCard.Card = KT.Factor(0x23);
            KT.Throws(SiegelErrorCode.WrongCard, () => VaultCrypto.OpenWithPassword(file, pw, wrongCard, KdfLimits.Production));
            Assert.Equal(0, counter.Value);
        }
        finally
        {
            TestHooks.KdfCounter = null;
        }
    }
}
#endif
