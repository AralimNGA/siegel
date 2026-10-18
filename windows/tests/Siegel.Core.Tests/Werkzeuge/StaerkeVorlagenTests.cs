using System.Diagnostics;
using Siegel.Werkzeuge.Staerke.Zxcvbn;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Tests;

/// <summary>30 typische Passwörter gegen die Intuition (TypischePasswoerterTests.swift).</summary>
public class StaerkeTypischTests
{
    public static TheoryData<string, double> Faelle => new()
    {
        { "YB1898", 20 }, { "FCBasel1893!", 25 }, { "scbern2026", 22 }, { "EHCBiel2025!", 30 }, { "HCDavos1921", 30 },
        { "BVB09Dortmund", 30 }, { "Michael1985", 22 }, { "Sabine1972!", 30 }, { "Levin2008", 22 },
        { "LaraMüller2010", 32 }, { "Thomas.Meier1979", 36 }, { "Jürg1965!", 30 }, { "qwertz123", 15 },
        { "1qay2wsx", 15 }, { "asdfghjklöä", 18 }, { "yxcvbnm,.-", 18 }, { "147258369", 15 }, { "+\"*ç%&/()=", 18 },
        { "IchLiebeMeinenHund", 40 }, { "Mein Hund heisst Bello", 58 }, { "DieSonneScheintHeute!", 55 },
        { "ichgehejetztnachhause", 55 }, { "Ich wohne seit 2015 in Biel", 58 }, { "EsWarEinmalEinKönig1990", 45 },
        { "Sommer2025!", 22 }, { "Grüezi123", 22 }, { "Zürich2026", 22 }, { "P@ssw0rt!", 20 },
        { "kerze-vulkan-flaute-pirat", 55 }, { "correcthorsebatterystaple", 55 },
    };

    [Fact]
    public void GenauDreissig()
    {
        Assert.Equal(30, Faelle.Count);
        Assert.Equal(30, Faelle.Select(f => (string)f[0]).Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [MemberData(nameof(Faelle))]
    public void GegenIntuition(string password, double intuitionMax)
    {
        // Bezugsjahr fest wie in der Swift-Tabelle (HERKUNFT.md, gemessen 2026)
        var bits = PasswordStrength.Analyze(password, [], 2026).Bits;
        Assert.True(bits < intuitionMax, $"{password}: {bits}");
        Assert.False(MasterPasswordPolicy.Check(password, ["siegel"]).Ok);
    }
}

/// <summary>Befund #18/#49: Vorlagen und die Kürzung auf 256 Zeichen (VorlagenTests.swift).</summary>
public class StaerkeVorlagenTests
{
    public static TheoryData<string> Befund18 => new()
    {
        "Hund1Hund2Hund3Hund4Hund5Hund6", "Hund1Hund2Hund3Hund4Hund5", "Hund1Hund2Hund3Hund4",
        "Basel1Basel2Basel3Basel4", "Bello1Bello2Bello3Bello4", "Katze1Katze2Katze3Katze4Katze5",
        "Basel4000Bern3000Zürich8000", "Thun3600Bern3000Biel2500",
        "Mo-Di-Mi-Do-Fr-Sa-So", "Mo.Di.Mi.Do.Fr.Sa.So", "Lu-Ma-Me-Je-Ve-Sa-Di",
        "Jan.Feb.Mar.Apr.Mai.Jun", "Jan-Feb-Mar-Apr-May-Jun",
        "Hund01Hund02Hund03Hund04Hund05", "Velo10-Velo20-Velo30-Velo40", "Ski2026Ski2025Ski2024Ski2023",
        "Hund1Hund2Hund3Hund4Hund5Hun", "1Hund2Hund3Hund4Hund5Hund6Hund",
        "Montag-Dienstag-Mittwoch-Donnerstag", "SonntagSamstagFreitagDonnerstag", "Januar.Februar.März.April",
        "janvier-fevrier-mars-avril-mai", "lunedi martedi mercoledi giovedi", "Sa-So-Mo-Di-Mi-Do",
        "3600 Thun 3000 Bern 2500 Biel", "Luzern6000Zug6300Basel4000",
    };

    [Theory]
    [MemberData(nameof(Befund18))]
    public void Befund18Unter60(string password)
    {
        var analysis = PasswordStrength.Analyze(password, ["siegel"], 2026);
        Assert.True(analysis.Bits < 60, $"{analysis.Bits} Bit, {analysis.PatternSummary}");
        Assert.False(MasterPasswordPolicy.Check(password, ["siegel"]).Ok);
    }

    [Fact]
    public void ZaehlerVorlageWirdAlsEinStueckErkannt()
    {
        var analysis = PasswordStrength.Analyze("Hund1Hund2Hund3Hund4Hund5Hund6", [], 2026);
        Assert.Single(analysis.Sequence);
        Assert.Equal(ZxcvbnPattern.Counter, analysis.Sequence[0].Pattern);
        Assert.True(analysis.Bits < 30, $"{analysis.Bits}");
        var hund = PasswordStrength.Analyze("Hund", [], 2026).Bits;
        Assert.True(Math.Abs(analysis.Bits - (hund + Math.Log2(10) + 3 + Math.Log2(5) + Math.Log2(6))) < 0.5);
    }

    private static List<ZxcvbnMatch> Matches(string text) => StaerkeHilfe.Omnimatch(text, out _);

    [Fact]
    public void ZaehlerNurMitArithmetischerFolge()
    {
        Assert.DoesNotContain(Matches("Hund7Hund3Hund9Hund1"), m => m.Pattern == ZxcvbnPattern.Counter);
        Assert.DoesNotContain(Matches("Hund1Hund4Hund7"), m => m.Pattern == ZxcvbnPattern.Counter);
        Assert.Contains(Matches("Hund1Hund3Hund5"), m => m.Pattern == ZxcvbnPattern.Counter);
        Assert.Contains(Matches("Hund9Hund10Hund11"), m => m.Pattern == ZxcvbnPattern.Counter && m.I == 0 && m.J == 16);
        Assert.DoesNotContain(Matches("Hund1Katz2Maus3"), m => m.Pattern == ZxcvbnPattern.Counter);
        Assert.NotEmpty(Matches("Hund1Hund2"));
        var broken = Matches("Ab1Ab2Ab3Ab9").Where(m => m.Pattern == ZxcvbnPattern.Counter).ToList();
        Assert.Contains(broken, m => m.I == 0 && m.J == 10);
        Assert.DoesNotContain(broken, m => m.J == 11);
    }

    private static bool Covers(string text, ZxcvbnPattern pattern) => StaerkeHilfe.Covers(text, pattern);

    [Fact]
    public void Kalenderfolgen()
    {
        Assert.True(Covers("Mo-Di-Mi-Do-Fr-Sa-So", ZxcvbnPattern.Calendar));
        Assert.True(Covers("MoDiMiDoFr", ZxcvbnPattern.Calendar));
        Assert.True(Covers("So.Sa.Fr.Do", ZxcvbnPattern.Calendar));
        Assert.True(Covers("Sa-So-Mo-Di", ZxcvbnPattern.Calendar));
        Assert.True(Covers("Jan.Feb.Mar.Apr.Mai.Jun", ZxcvbnPattern.Calendar));
        Assert.True(Covers("sept-okt-nov-dez", ZxcvbnPattern.Calendar));
        Assert.True(Covers("JANUARY FEBRUARY MARCH", ZxcvbnPattern.Calendar));
        Assert.True(Covers("août/septembre/octobre", ZxcvbnPattern.Calendar));
        Assert.False(Covers("Mo-Mi-Fr", ZxcvbnPattern.Calendar));
        Assert.False(Covers("Mo-Di.Mi", ZxcvbnPattern.Calendar));
        Assert.False(Covers("Mo-Di-Mi-Do-Fr-Sa-So-Mo", ZxcvbnPattern.Calendar));
    }

    [Fact]
    public void OrtUndPostleitzahl()
    {
        Assert.True(Covers("Thun3600", ZxcvbnPattern.PlaceCode));
        Assert.True(Covers("thun 3600", ZxcvbnPattern.PlaceCode));
        Assert.True(Covers("3600Thun", ZxcvbnPattern.PlaceCode));
        Assert.True(Covers("3600 Thun", ZxcvbnPattern.PlaceCode));
        Assert.True(Covers("Zürich8000", ZxcvbnPattern.PlaceCode));
        Assert.True(Covers("Zuerich-8000", ZxcvbnPattern.PlaceCode));
        Assert.False(Covers("Thun0999", ZxcvbnPattern.PlaceCode));
        Assert.False(Covers("Thun9700", ZxcvbnPattern.PlaceCode));
        Assert.False(Covers("Thun36001", ZxcvbnPattern.PlaceCode));
        Assert.False(Covers("Kerze3600", ZxcvbnPattern.PlaceCode));
        var rund = PasswordStrength.Analyze("Thun3600", [], 2026).Bits;
        var krumm = PasswordStrength.Analyze("Thun3613", [], 2026).Bits;
        Assert.True(rund < krumm);
        Assert.True(rund < 20, $"{rund}");
    }

    [Fact]
    public void GegenprobenBleibenStark()
    {
        foreach (var password in new[] { "kV7#pQ2$mZ9!xR4@tL8&", "Mo7#Di2$Zug9!xR4@tL8&q", "Thun3600-kerze-vulkan-flaute-pirat-seide",
                     "q9Xf3Lp8Vm2Zr7Wk4Tn6", "kerze-vulkan-flaute-pirat-seide-hafen" })
        {
            var bits = PasswordStrength.Analyze(password, ["siegel"], 2026).Bits;
            Assert.True(bits >= 60, $"{password}: {bits}");
        }
    }

    [Fact]
    public void WiederholungUeberDieKuerzungsgrenze()
    {
        var b = new string('a', 33) + new string('b', 33) + new string('c', 33) + new string('d', 33);
        Assert.Equal(132, b.Length);
        var einfach = PasswordStrength.Estimate(b).Bits;
        var doppelt = PasswordStrength.Estimate(b + b).Bits;
        Assert.True(doppelt < 60, $"{doppelt}");
        Assert.True(doppelt <= einfach + 1.01);
        Assert.False(MasterPasswordPolicy.Check(b + b, ["siegel"]).Ok);
    }

    [Fact]
    public void LangerSatzZweimalGetippt()
    {
        const string satz = "Der Fuchs springt am Montag über den Zaun, weil der Hund im Garten bellt und die Katze auf dem "
            + "Dach sitzt und in die Sonne blinzelt, bis es Abend wird.";
        Assert.InRange(SwiftText.Zeichenzahl(satz), 129, 255);
        var einmal = PasswordStrength.Estimate(satz).Bits;
        var zweimal = PasswordStrength.Estimate(satz + satz).Bits;
        Assert.True(zweimal <= einmal + 1.01, $"{einmal} → {zweimal}");
        var mitRest = PasswordStrength.Estimate(satz + satz + "!!").Bits;
        Assert.True(mitRest <= einmal + 1 + 20, $"{mitRest}");
    }

    [Fact]
    public void KuerzungErhoehtNieGegenueberDerGanzenPeriode()
    {
        uint state = 99;
        foreach (var length in new[] { 129, 150, 200, 300 })
        {
            var periode = new string([.. Enumerable.Range(0, length).Select(_ =>
            {
                state = unchecked(state * 1_103_515_245 + 12345);
                return (char)(97 + (state >> 16) % 26);
            })]);
            var einmal = PasswordStrength.Estimate(periode).Bits;
            var dreimal = PasswordStrength.Estimate(periode + periode + periode).Bits;
            Assert.True(dreimal <= einmal + Math.Log2(3) + 0.01, $"Länge {length}: {einmal} → {dreimal}");
        }
    }

    [Fact]
    public void PeriodeNachKmp()
    {
        PasswordStrength.PeriodicPrefix? P(string s) => PasswordStrength.LongestPeriodicPrefix(new Zeichenvorrat().Zerlegen(s));
        Assert.Equal(new PasswordStrength.PeriodicPrefix(11, 3), P("abcabcabcab"));
        Assert.Equal(new PasswordStrength.PeriodicPrefix(6, 2), P("abababx"));
        Assert.Null(P("abcdef"));
        Assert.Equal(new PasswordStrength.PeriodicPrefix(4, 1), P("aaaa"));
    }

    [Fact]
    public void LaufzeitMitNeuenMustern()
    {
        _ = ZxcvbnDictionary.Shared;
        string[] samples =
        [
            string.Concat(Enumerable.Repeat("Hund1", 12)) + "Hund",
            "Mo-Di-Mi-Do-Fr-Sa-So-Jan-Feb-Mar-Apr-Mai-Jun-Jul-Aug-Sep-Okt-Nov",
            "Thun3600Bern3000Biel2500Basel4000Zürich8000Luzern6000Chur7000ab",
            string.Concat(Enumerable.Repeat("1a", 32)),
            string.Concat(Enumerable.Repeat("a1b2", 16)),
        ];
#if DEBUG
        var limit = TimeSpan.FromMilliseconds(250);
#else
        var limit = TimeSpan.FromMilliseconds(20);
#endif
        foreach (var sample in samples)
        {
            _ = PasswordStrength.Estimate(sample);
            var worst = TimeSpan.Zero;
            for (var i = 0; i < 3; i++)
            {
                var uhr = Stopwatch.StartNew();
                _ = PasswordStrength.Estimate(sample);
                worst = TimeSpan.FromTicks(Math.Max(worst.Ticks, uhr.Elapsed.Ticks));
            }
            Assert.True(worst < limit, $"{sample[..20]}: {worst}");
        }
    }
}
