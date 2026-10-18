#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>QR-Schlüsselkarte (CardCode, §14.2) und Mehrfaktor-Bindung (§13.1), wie KernCardCodeTests.swift.</summary>
public class CardCodeTests
{
    [Fact]
    public void Testvektor_q_00_bis_1f_Inhalt_Gruppen_Kennung()
    {
        using var q = FactorSecret.Copy(KT.Seq(0, 32));
        Assert.Equal("SIEGELKARTE1:000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFQVT8", CardCode.Payload(q));
        Assert.Equal("000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FQVT8", CardCode.GroupedText(q));
        Assert.Equal(KT.FromHex("08b8de3f"), CardCode.Tag(q, Bytes.ToGuid(KT.Seq(0xa0, 16))));
    }

    [Fact]
    public void Rundlauf_gescannt_abgetippt_klein_mit_Leerraum()
    {
        for (var n = 0; n < 50; n++)
        {
            using var q = CardCode.Generate();
            var payload = CardCode.Payload(q);
            Assert.StartsWith("SIEGELKARTE1:", payload, StringComparison.Ordinal);
            Assert.Equal(13 + 55, payload.Length);
            Assert.All(payload, c => Assert.Contains(c, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"));
            var grouped = CardCode.GroupedText(q);
            Assert.Equal(11, grouped.Split('-').Length);
            foreach (var input in new[] { payload, grouped, grouped.ToLowerInvariant(), " " + payload.ToLowerInvariant() + "\n",
                         grouped.Replace('-', ' ').Replace('0', 'O') })
            {
                using var back = CardCode.Decode(input);
                Assert.True(back.ConstantTimeEquals(q));
            }
        }
        using var a = CardCode.Generate();
        using var b = CardCode.Generate();
        Assert.False(a.ConstantTimeEquals(b));
    }

    [Fact]
    public void Fehler_Pruefsumme_Fuellbits_Laenge_Zeichen_Kartenversion()
    {
        using var q = FactorSecret.Copy(KT.Seq(0, 32));
        var grouped = CardCode.GroupedText(q).Replace("-", "", StringComparison.Ordinal).ToCharArray();
        var typo = (char[])grouped.Clone();
        typo[10] = typo[10] == 'A' ? 'B' : 'A';
        var pad = (char[])grouped.Clone();
        pad[54] = '9';
        string[] bad =
        [
            new(typo), new(pad), new(grouped[..^1]), new string(grouped) + "0", new string(grouped[..^1]) + "U",
            "SIEGELKARTE2:" + new string(grouped), "SIEGELKARTE1:", "", "?" + new string(grouped[1..]),
        ];
        foreach (var b in bad) { KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => CardCode.Decode(b)); }
        // Ein Notfallcode ist keine Karte (anderes Prüfsummen-Label)
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => CardCode.Decode(TestvektorTests.Code));
    }

    [Fact]
    public void Kennung_haengt_am_Tresor()
    {
        using var q = CardCode.Generate();
        var a = CardCode.Tag(q, Zufall.NewGuid());
        var b = CardCode.Tag(q, Zufall.NewGuid());
        Assert.Equal(4, a.Length);
        Assert.NotEqual(a, b);
        var vid = KT.Seq(0xa0, 16);
        Assert.Equal(CardCode.TagBytesFor(q, vid), CardCode.Tag(q, Bytes.ToGuid(vid)));
        Assert.Equal("FactorSecret(redacted)", q.ToString());
    }

    [Fact]
    public void Reihenfolge_Maske_und_jeder_Faktor_gehen_in_den_KEK_ein()
    {
        using var p = SecureBuffer.Random(32);
        var salt = Zufall.Bytes(16);
        var keys = Enumerable.Range(0, 3).Select(_ => SecureBuffer.Random(32)).ToList();
        using var other = SecureBuffer.Random(32);
        using var otherP = SecureBuffer.Random(32);
        using var baseKek = FactorKdf.Kek(p, keys, salt, 7);
        SecureBuffer[] variants =
        [
            FactorKdf.Kek(p, [keys[1], keys[0], keys[2]], salt, 7),
            FactorKdf.Kek(p, keys, salt, 6),
            FactorKdf.Kek(p, keys[..2], salt, 7),
            FactorKdf.Kek(p, keys, Zufall.Bytes(16), 7),
            FactorKdf.Kek(otherP, keys, salt, 7),
            FactorKdf.Kek(p, [keys[0], keys[1], other], salt, 7),
        ];
        foreach (var v in variants)
        {
            Assert.False(v.ConstantTimeEquals(baseKek));
            v.Dispose();
        }
        // Ohne Faktoren: HKDF über p allein, nicht p selbst (v2 unterscheidet sich von v1)
        using var noFactors = FactorKdf.Kek(p, [], salt, 0);
        Assert.False(noFactors.ConstantTimeEquals(p));
        // Faktor-Schlüssel sind domänengetrennt
        using var raw = FactorSecret.Copy(Zufall.Bytes(32));
        var vid = Zufall.Bytes(16);
        using var se = FactorKdf.FactorKey(raw, FactorKind.SecureEnclave, vid);
        using var card = FactorKdf.FactorKey(raw, FactorKind.Card, vid);
        using var fido = FactorKdf.FactorKey(raw, FactorKind.SecurityKey, vid);
        Assert.False(se.ConstantTimeEquals(card) || card.ConstantTimeEquals(fido) || se.ConstantTimeEquals(fido));
        using var se2 = FactorKdf.FactorKey(raw, FactorKind.SecureEnclave, Zufall.Bytes(16));
        Assert.False(se.ConstantTimeEquals(se2));
        foreach (var k in keys) { k.Dispose(); }
        KT.Throws(SiegelErrorCode.Crypto, "kek.length", () => FactorKdf.Kek(p, [SecureBuffer.Random(31)], salt, 1));
    }

    [Fact]
    public void Faktor_Geheimnis_genau_32_Byte()
    {
        KT.Throws(SiegelErrorCode.Crypto, "factor.length", () => FactorSecret.Copy(new byte[31]));
        KT.Throws(SiegelErrorCode.Crypto, "factor.length", () => FactorSecret.Copy(new byte[33]));
        using var f = FactorSecret.Copy(KT.Repeat(7, 32));
        byte[]? seen = null;
        f.Read(b => seen = b.ToArray());
        Assert.Equal(KT.Repeat(7, 32), seen);
    }

    [Fact]
    public void Eintrags_Hybridschluessel_aus_q_und_y2_sind_domaenengetrennt()
    {
        using var q = FactorSecret.Copy(KT.Repeat(0x22, 32));
        var vid = Bytes.OfGuid(Guid.Parse(BeispielDateien.V2VaultId));
        var card = EntryKeyDerivation.CardPublicKeys(q, vid);
        var fido = EntryKeyDerivation.FidoPublicKeys(q, vid);
        Assert.True(card.HasValidLengths && fido.HasValidLengths);
        Assert.NotEqual(card, fido);
        using var r = KT.Secure(KT.Repeat(0x22, 32));
        Assert.NotEqual(card, RecoveryKem.DerivePublicKeys(r, vid));
        // Die Mac-Datei v2 trägt genau diese öffentlichen Kartenschlüssel im Inhalt (q = 22…22).
        var file = VaultFile.Parse(Fixtures.MacBytes("v2_beispiel.siegel"));
        using var rr = RecoveryMatching.CombineShares([BeispielDateien.V2Shares[0], BeispielDateien.V2Shares[1]]);
        using var opened = VaultCrypto.OpenWithRecovery(file, rr);
        Assert.Equal(card, opened.Content.EntryFactors.Card?.Pk);
        Assert.Equal(KT.FromHex("b2fdc001"), opened.Content.EntryFactors.Card?.Tag);
        using var y2 = FactorSecret.Copy(KT.Repeat(0x77, 32));
        Assert.Equal(EntryKeyDerivation.FidoPublicKeys(y2, vid), opened.Content.EntryFactors.SecurityKey?.Pk);
        using var out1 = FactorSecret.Copy(KT.Repeat(0x33, 32));
        Assert.Equal(FactorKdf.FidoCheck(out1, vid), opened.Content.EntryFactors.SecurityKey?.Check);
    }
}
#endif
