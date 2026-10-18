#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Notfallcode (§1.5): Format, Eingabe, Füllbits, Prüfsumme, fremder Tresor, Fehlerkorrektur (wie
/// KernNotfallcodeTests.swift, ohne den Dateiteil von VaultStore, der in Stufe B kommt).</summary>
public class NotfallcodeTests
{
    private const string Alphabet = RecoveryCodeCodec.AlphabetText;

    private static char[] Chars(string code) => code.Replace("-", "", StringComparison.Ordinal).ToCharArray();

    private static string Grouped(char[] c) =>
        string.Join('-', Enumerable.Range(0, (c.Length + 4) / 5).Select(i => new string(c, i * 5, Math.Min(5, c.Length - i * 5))));

    private static char Other(char c, int shift = 7) => Alphabet[(Alphabet.IndexOf(c, StringComparison.Ordinal) + shift) % 32];

    private static RecoveryCodeMatch Match(string input, VaultHeader header) =>
        RecoveryMatching.MatchRecoveryCode(RecoveryCodeCodec.ParseSymbols(input, allowUnknown: true), header);

    [Fact]
    public void Eingabe_Gross_Klein_Leerraum_Bindestriche_O_I_L()
    {
        using var t = TestTresor.Create();
        var header = t.File.Header;
        var plain = t.Code.Replace("-", "", StringComparison.Ordinal);
        string[] variants =
        [
            t.Code.ToLowerInvariant(),
            plain,
            string.Join(' ', plain.ToCharArray()),
            t.Code.Replace('-', '\n'),
            "  " + t.Code.Replace('-', ' ') + "\t",
            t.Code.Replace('0', 'O').Replace('1', 'I'),
            t.Code.Replace('0', 'o').Replace('1', 'l'),
            t.Code.Replace('1', 'L'),
            "--" + t.Code + "--",
            t.Code.Replace("-", " 　", StringComparison.Ordinal),
        ];
        foreach (var v in variants)
        {
            using var back = RecoveryCodeCodec.Decode(v);
            Assert.True(back.ConstantTimeEquals(t.R));
            Assert.Equal(RecoveryCodeMatch.Exact, Match(v, header));
        }
    }

    [Fact]
    public void Format_falsche_Laenge_ungueltige_Zeichen_U_zu_viele_Fragezeichen()
    {
        using var t = TestTresor.Create();
        var c = Chars(t.Code);
        string[] bad =
        [
            new string(c[..^1]),
            new string(c) + "0",
            "",
            new string(c[..^1]) + "U",
            new string(c[..^1]) + "*",
            new string(c[..^1]) + "Ä",
            "?????" + new string(c[5..]),
        ];
        foreach (var b in bad)
        {
            KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryCodeCodec.Decode(b));
            KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => Match(b, t.File.Header));
        }
        // ? ist beim exakten Dekodieren nicht erlaubt
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryCodeCodec.Decode("?" + new string(c[1..])));
        Assert.True(RecoveryMatching.CodeInputIsComplete("????" + new string(c[4..])));
        Assert.False(RecoveryMatching.CodeInputIsComplete(new string(c[..^1])));
        Assert.False(RecoveryMatching.CodeInputIsComplete(new string(c[..^1]) + "U"));
        Assert.False(RecoveryMatching.CodeInputIsComplete("?????" + new string(c[5..])));
    }

    [Fact]
    public void Fuellbits_ungleich_0_sind_InvalidRecoveryCodeFormat_und_werden_korrigiert()
    {
        using var t = TestTresor.Create();
        var c = Chars(t.Code);
        var last = Alphabet.IndexOf(c[54], StringComparison.Ordinal);
        Assert.Equal(0, last % 8);
        c[54] = Alphabet[last + 1];
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryCodeCodec.Decode(new string(c)));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryCodeCodec.Decode(TestvektorTests.Code[..^1] + "9"));
        // Ein Fehler im letzten Zeichen wird korrigiert; drei Fehler (eins davon im letzten Zeichen) nicht.
        Assert.Equal(RecoveryCodeMatch.Corrected(t.Code, [54]), Match(new string(c), t.File.Header));
        var three = (char[])c.Clone();
        three[5] = Other(three[5]);
        three[20] = Other(three[20]);
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => Match(new string(three), t.File.Header));
        Assert.True(RecoveryMatching.CodeInputIsComplete(new string(three)));
    }

    [Fact]
    public void Pruefsumme_falsch_ist_RecoveryCodeChecksum()
    {
        var c = Chars(TestvektorTests.Code);
        c[10] = Other(c[10]);
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => RecoveryCodeCodec.Decode(new string(c)));
        // Deterministisch über Testvektor (a): Kopf mit dessen pkM/pkX, drei Fehler sind nicht korrigierbar.
        using var r = KT.Secure(TestvektorTests.R);
        var header = VaultHeader.V2(TestvektorTests.VaultIdA, KT.Kdf, new byte[16], HeaderFactorFields.None, RecoveryScheme.SingleCode,
            RecoveryKem.DerivePublicKeys(r, TestvektorTests.VaultIdA));
        Assert.Equal(RecoveryCodeMatch.Exact, Match(TestvektorTests.Code, header));
        var d = Chars(TestvektorTests.Code);
        d[20] = Other(d[20]);
        d[21] = Other(d[21]);
        d[40] = Other(d[40]);
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => RecoveryCodeCodec.Decode(new string(d)));
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => Match(new string(d), header));
        d[40] = Chars(TestvektorTests.Code)[40];
        Assert.Equal(RecoveryCodeMatch.Corrected(TestvektorTests.Code, [20, 21]), Match(new string(d), header));
    }

    [Fact]
    public void Fremder_Tresor_ist_WrongRecoveryCode_mit_beiden_Kit_Kennungen()
    {
        using var a = TestTresor.Create();
        using var b = TestTresor.Create();
        var header = a.File.Header;
        // codeKit wird mit der vaultID DIESES Tresors abgeleitet (HKDF-Salz).
        var codeKit = RecoveryKem.DerivePublicKeys(b.R, header.VaultId).KitId;
        var e = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => Match(b.Code, header));
        Assert.Equal(codeKit, e.CodeKit);
        Assert.Equal(header.Pk.KitId, e.VaultKit);
        Assert.NotEqual(codeKit, e.VaultKit);
        var e2 = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => VaultCrypto.OpenWithRecovery(a.File, b.R));
        Assert.Equal(codeKit, e2.CodeKit);
        Assert.Equal(header.Pk.KitId, e2.VaultKit);
    }

    [Fact]
    public void Korrektur_1_ersetztes_Zeichen_jede_Gruppe_auch_das_letzte()
    {
        using var t = TestTresor.Create();
        var original = Chars(t.Code);
        foreach (var pos in new[] { 0, 4, 5, 27, 53, 54 })
        {
            var c = (char[])original.Clone();
            c[pos] = Other(c[pos], 3);
            Assert.Equal(RecoveryCodeMatch.Corrected(t.Code, [pos]), Match(Grouped(c), t.File.Header));
        }
    }

    [Fact]
    public void Korrektur_2_ersetzte_Zeichen()
    {
        using var t = TestTresor.Create();
        var c = Chars(t.Code);
        c[3] = Other(c[3]);
        c[41] = Other(c[41], 11);
        Assert.Equal(RecoveryCodeMatch.Corrected(t.Code, [3, 41]), Match(new string(c), t.File.Header));
    }

    [Fact]
    public void Korrektur_vertauschte_Nachbarn()
    {
        using var t = TestTresor.Create();
        var original = Chars(t.Code);
        var pos = Enumerable.Range(0, 54).First(i => original[i] != original[i + 1]);
        var c = (char[])original.Clone();
        (c[pos], c[pos + 1]) = (c[pos + 1], c[pos]);
        Assert.Equal(RecoveryCodeMatch.Corrected(t.Code, [pos, pos + 1]), Match(Grouped(c), t.File.Header));
    }

    [Fact]
    public void Korrektur_4_unleserliche_Zeichen()
    {
        using var t = TestTresor.Create();
        var c = Chars(t.Code);
        int[] positions = [2, 17, 33, 54];
        foreach (var p in positions) { c[p] = '?'; }
        Assert.Equal(RecoveryCodeMatch.Corrected(t.Code, positions), Match(Grouped(c), t.File.Header));
        var d = t.Code.ToLowerInvariant().Replace("-", "", StringComparison.Ordinal).ToCharArray();
        d[30] = '?';
        Assert.Equal(RecoveryCodeMatch.Corrected(t.Code, [30]), Match(new string(d), t.File.Header));
    }

    [Fact]
    public void Zufaelliger_Code_findet_keinen_Treffer()
    {
        using var t = TestTresor.Create();
        using var r = SecureBuffer.Random(32);
        var random = RecoveryCodeCodec.Format(r);
        var e = KT.Throws(SiegelErrorCode.WrongRecoveryCode, () => Match(random, t.File.Header));
        Assert.Equal(t.File.Header.Pk.KitId, e.VaultKit);
        // Mit einem unleserlichen Zeichen: kein Treffer → Prüfsummen-Fehler (nicht die erfundene Kit-Kennung).
        var c = Chars(random);
        c[7] = '?';
        KT.Throws(SiegelErrorCode.RecoveryCodeChecksum, () => Match(new string(c), t.File.Header));
    }

    [Fact]
    public void Bestaetigungsgruppe_wird_normalisiert()
    {
        Assert.Equal("01ABC", RecoveryCodeCodec.NormalizedGroup(" o-Ia bc "));
        Assert.Null(RecoveryCodeCodec.NormalizedGroup("AB?CD"));
        Assert.Null(RecoveryCodeCodec.NormalizedGroup("ABUCD"));
    }

    [Fact]
    public void Geschwaerzte_Beschreibungen()
    {
        using var t = TestTresor.Create();
        var code = new RecoveryCode(t.Code, "AAAA-BBBB");
        Assert.DoesNotContain(t.Code[..10], code.ToString(), StringComparison.Ordinal);
        Assert.Contains("AAAA-BBBB", code.ToString(), StringComparison.Ordinal);
        var pending = new PendingRecovery(code, [1, 5]);
        Assert.DoesNotContain(t.Code[..10], pending.ToString(), StringComparison.Ordinal);
        var corrected = RecoveryCodeMatch.Corrected(t.Code, [1]);
        Assert.DoesNotContain(t.Code[..10], corrected.ToString(), StringComparison.Ordinal);
        Assert.Equal(11, code.Groups.Count);
    }
}
#endif
