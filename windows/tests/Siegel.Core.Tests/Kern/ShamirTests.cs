#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Notfallcode in Teilen (Shamir 2 aus 3, §15), wie KernShamirTests.swift (Kern ohne VaultStore).</summary>
public class ShamirTests
{
    private const string Alphabet = RecoveryCodeCodec.AlphabetText;

    private static char[] Chars(string s) => s.Replace("-", "", StringComparison.Ordinal).ToCharArray();

    private static char Other(char c, int shift = 7) => Alphabet[(Alphabet.IndexOf(c, StringComparison.Ordinal) + shift) % 32];

    private static string Grouped(char[] c) =>
        string.Join('-', Enumerable.Range(0, (c.Length + 4) / 5).Select(i => new string(c, i * 5, Math.Min(5, c.Length - i * 5))));

    private static IReadOnlyList<RecoveryCodeMatch> Check(VaultHeader header, string a, string b) =>
        RecoveryMatching.MatchRecoveryShares(RecoveryMatching.ParseShareInputs([a, b]), header);

    [Fact]
    public void GF256_Multiplikation_FIPS197_und_Inverse()
    {
        Assert.Equal(0xC1, Gf256.Mul(0x57, 0x83));
        Assert.Equal(0xFE, Gf256.Mul(0x57, 0x13));
        Assert.Equal(0, Gf256.Mul(0, 0xAB));
        Assert.Equal(0xAB, Gf256.Mul(1, 0xAB));
        Assert.Equal(0, Gf256.Inv(0));
        for (var a = 1; a <= 255; a++) { Assert.Equal(1, Gf256.Mul((byte)a, Gf256.Inv((byte)a))); }
        foreach (var (a, b, c) in new (byte, byte, byte)[] { (0x12, 0x34, 0x56), (0xFF, 0x80, 0x01), (0x8D, 0xF6, 0x7B) })
        {
            Assert.Equal(Gf256.Mul(a, b), Gf256.Mul(b, a));
            Assert.Equal(Gf256.Mul(a, (byte)(b ^ c)), Gf256.Mul(a, b) ^ Gf256.Mul(a, c));
        }
    }

    [Fact]
    public void Testvektor_R_00_bis_1f_a_a0_bis_bf_feste_Teile()
    {
        using var r = KT.Secure(KT.Seq(0, 32));
        using var a = KT.Secure(KT.Seq(0xA0, 32));
        var ys = Shamir.Split(r, a);
        try
        {
            Assert.Equal(string.Concat(Enumerable.Repeat("a0", 32)), ys[0].HexForTesting());
            Assert.Equal("5b585d5e57545152434045464f4c494a6b686d6e67646162737075767f7c797a", ys[1].HexForTesting());
            Assert.Equal("fbf9fffdf3f1f7f5ebe9efede3e1e7e5dbd9dfddd3d1d7d5cbc9cfcdc3c1c7c5", ys[2].HexForTesting());
            var codes = ys.Select((y, i) => Shamir.Format((byte)(i + 1), y)).ToList();
            Assert.Equal(
            [
                "06GA1-850M2-GA185-0M2GA-1850M-2GA18-50M2G-A1850-M2GA1-850M2-GA1GP-B",
                "09DNG-QAYAX-A52MJ-3812M-CKTC9-556PT-3DDSK-P8RB2-EDR7A-XKZFH-WQNY6-N",
                "0FXZK-ZZXYF-RZFXF-BX7QY-VRZ1W-ZJXQP-EZVQ9-X3NYN-SF4WZ-KE3R7-3WATN-T",
            ], codes);
            foreach (var (i, j) in new[] { (0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (2, 1) })
            {
                using var back = RecoveryMatching.CombineShares([codes[i], codes[j]]);
                Assert.True(back.ConstantTimeEquals(r));
            }
            Assert.All(codes, c => Assert.Equal(56 + 11, c.Length));
            Assert.Equal([1, 2, 3], codes.Select(Shamir.IndexOf));
        }
        finally
        {
            foreach (var y in ys) { y.Dispose(); }
        }
    }

    [Fact]
    public void Zufaelliges_R_alle_Paare_beide_Reihenfolgen()
    {
        for (var n = 0; n < 20; n++)
        {
            using var r = SecureBuffer.Random(32);
            var shares = RecoveryMatching.SharesFor(r, RecoveryKem.DerivePublicKeys(r, Zufall.Bytes(16)));
            Assert.Equal([1, 2, 3], shares.Select(s => s.Index));
            foreach (var (i, j) in new[] { (0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (2, 1) })
            {
                using var back = RecoveryMatching.CombineShares([shares[i].Formatted, shares[j].Formatted]);
                Assert.True(back.ConstantTimeEquals(r));
            }
        }
    }

    [Fact]
    public void Format_Laenge_Zeichen_Pruefsumme_Teilnummer_gleiche_Teile()
    {
        using var r = SecureBuffer.Random(32);
        var codes = RecoveryMatching.SharesFor(r, RecoveryKem.DerivePublicKeys(r, Zufall.Bytes(16))).Select(s => s.Formatted).ToList();
        var c = Chars(codes[0]);
        Assert.Equal(56, c.Length);
        Assert.Equal(12, codes[0].Split('-').Length);
        foreach (var v in new[] { codes[0].ToLowerInvariant(), new string(c), codes[0].Replace('-', ' ') })
        {
            var (x, y) = Shamir.Decode(v);
            y.Dispose();
            Assert.Equal(1, x);
        }
        foreach (var bad in new[] { new string(c[..^1]), new string(c) + "0", new string(c[..^1]) + "U", "", new string(c[..^1]) + "?" })
        {
            KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => Shamir.Decode(bad));
        }
        // Deterministisch über Testvektor (f): ein Tippfehler → Prüfsumme
        var d = Chars("06GA1-850M2-GA185-0M2GA-1850M-2GA18-50M2G-A1850-M2GA1-850M2-GA1GP-B");
        d[30] = Other(d[30]);
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => Shamir.Decode(new string(d)));
        Assert.Null(Shamir.IndexOf(new string(d)));
        // x = 0 oder 4 (gültige Prüfsumme dazu) → wie ein Tippfehler
        foreach (var x in new byte[] { 0, 4 })
        {
            using var y = SecureBuffer.Random(32);
            var fake = Shamir.Format(x, y);
            KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => Shamir.Decode(fake));
        }
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryMatching.CombineShares([codes[1], codes[1]]));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryMatching.CombineShares([codes[1]]));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryMatching.CombineShares(codes));
        Assert.True(RecoveryMatching.ShareInputIsComplete(codes[2]));
        Assert.True(RecoveryMatching.ShareInputIsComplete("????" + new string(c[4..])));
        Assert.False(RecoveryMatching.ShareInputIsComplete(new string(c[..^1])));
        var share = new RecoveryShare(1, codes[0], "AAAA-BBBB");
        Assert.DoesNotContain(new string(c[..10]), share.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Korrektur_exakt_Fragezeichen_1_und_2_Fehler_vertauschte_Nachbarn_pro_Teil()
    {
        using var t = TestTresor.Create(SecurityLevel.Maximal);
        var header = t.File.Header;
        var s = t.Shares;
        var a = Chars(s[0]);
        var b = Chars(s[2]);
        Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], Check(header, s[0], s[2]));
        var a1 = (char[])a.Clone();
        a1[17] = Other(a1[17]);
        Assert.Equal([RecoveryCodeMatch.Corrected(s[0], [17]), RecoveryCodeMatch.Exact], Check(header, Grouped(a1), s[2]));
        var b2 = (char[])b.Clone();
        b2[3] = Other(b2[3]);
        b2[55] = Other(b2[55], 11);
        Assert.Equal([RecoveryCodeMatch.Corrected(s[0], [17]), RecoveryCodeMatch.Corrected(s[2], [3, 55])],
            Check(header, Grouped(a1), new string(b2)));
        var pos = Enumerable.Range(0, 55).First(i => a[i] != a[i + 1]);
        var sw = (char[])a.Clone();
        (sw[pos], sw[pos + 1]) = (sw[pos + 1], sw[pos]);
        Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Corrected(s[0], [pos, pos + 1])], Check(header, s[2], Grouped(sw)));
        var q = (char[])b.Clone();
        foreach (var p in new[] { 0, 9, 30, 55 }) { q[p] = '?'; }
        Assert.Equal([RecoveryCodeMatch.Corrected(s[2], [0, 9, 30, 55]), RecoveryCodeMatch.Corrected(s[0], [17])],
            Check(header, new string(q), Grouped(a1)));
    }

    [Fact]
    public void Fehlerfaelle_fremde_Teile_gleicher_Teil_Unsinn()
    {
        using var f = TestTresor.Create(SecurityLevel.Maximal);
        using var g = TestTresor.Create(SecurityLevel.Maximal);
        var header = f.File.Header;
        var s = f.Shares;
        var t = g.Shares;
        var e = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => Check(header, t[0], t[1]));
        Assert.Equal(header.Pk.KitId, e.VaultKit);
        Assert.NotEqual(e.CodeKit, e.VaultKit);
        KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => Check(header, s[0], t[1]));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => Check(header, s[1], s[1]));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryMatching.ParseShareInputs([s[1]]));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => Check(header, s[0], "ABC"));
        var junk = Chars(s[0]);
        foreach (var i in new[] { 1, 2, 3, 20, 40 }) { junk[i] = Other(junk[i], 5); }
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => Check(header, new string(junk), s[1]));
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => RecoveryMatching.CombineShares([new string(junk), s[1]]));
    }
}
#endif
