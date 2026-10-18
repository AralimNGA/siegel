using System.Diagnostics;
using Siegel.Werkzeuge.Staerke.Zxcvbn;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Tests;

/// <summary>Hilfen wie in den Swift-Tests (covers, Zerlegung).</summary>
internal static class StaerkeHilfe
{
    internal static ZxcvbnMatcher Matcher(Zeichenvorrat vorrat, params string[] inputs) =>
        new(ZxcvbnDictionary.Shared, [.. inputs.Select(MasterPasswordPolicy.Normalized)], 2026, KeyboardGraphs.All, vorrat);

    internal static List<ZxcvbnMatch> Omnimatch(string password, out Zeichen[] chars, params string[] inputs)
    {
        var vorrat = new Zeichenvorrat();
        chars = vorrat.Zerlegen(password);
        return Matcher(vorrat, inputs).Omnimatch(chars);
    }

    /// <summary>Gibt es einen Treffer des Musters über das ganze Passwort?</summary>
    internal static bool Covers(string password, ZxcvbnPattern pattern, params string[] inputs)
    {
        var matches = Omnimatch(password, out var chars, inputs);
        return matches.Any(m => m.Pattern == pattern && m.I == 0 && m.J == chars.Length - 1);
    }

    internal static double Bits(string password, params string[] inputs) => PasswordStrength.Estimate(password, inputs).Bits;
}

/// <summary>Schätzung nach SPEC §1.6 (Port von Tests/SiegelCoreTests/Staerke/PasswordStrengthTests.swift).</summary>
public class StaerkeSchaetzungTests
{
    public static TheoryData<string, string[]> Unter60 => new()
    {
        { "Passwort1234!", [] }, { "Passwort2026!", [] }, { "Sommer2026!!!", [] }, { "Qwertz123456!", [] },
        { "aaaaaaaaaaaaa", [] }, { "Aaaaaaaaaaaa1!", [] }, { "Quendolin2008!!!", ["quendolin"] }, { "YB-Meister-2026", [] },
    };

    [Theory]
    [MemberData(nameof(Unter60))]
    public void SpecBeispielUnter60(string password, string[] inputs)
    {
        var (bits, level) = PasswordStrength.Estimate(password, inputs);
        Assert.True(bits < 60, $"{bits}");
        Assert.True(level <= StrengthLevel.Fair);
        Assert.False(MasterPasswordPolicy.Check(password, inputs).Ok);
    }

    [Fact]
    public void NameNurMitBenutzereingabeSchwach()
    {
        var ohne = StaerkeHilfe.Bits("Quendolin2008!!!");
        var mit = StaerkeHilfe.Bits("Quendolin2008!!!", "quendolin");
        Assert.True(mit < ohne);
        Assert.True(mit < 30);
    }

    [Fact]
    public void GeneriertePassphraseMindestens60()
    {
        for (var i = 0; i < 300; i++)
        {
            var phrase = PassphraseGenerator.Generate();
            Assert.True(PasswordStrength.Estimate(phrase).Bits >= 60);
            Assert.True(MasterPasswordPolicy.Check(phrase, ["siegel"]).Ok);
        }
    }

    [Fact]
    public void ZwanzigZufallszeichenAus94()
    {
        var pool = Enumerable.Range(33, 94).Select(c => (char)c).ToArray();
        Assert.Equal(94, pool.Length);
        Assert.True(StaerkeHilfe.Bits("kV7#pQ2$mZ9!xR4@tL8&") >= 60);
        const int count = 2000;
        var atLeast60 = 0;
        var minimum = double.PositiveInfinity;
        for (var n = 0; n < count; n++)
        {
            var password = new string([.. Enumerable.Range(0, 20).Select(_ => pool[Sodium.Uniform(94)])]);
            var bits = PasswordStrength.Estimate(password).Bits;
            if (bits >= 60) { atLeast60++; }
            minimum = Math.Min(minimum, bits);
        }
        Assert.True((double)atLeast60 / count >= 0.995);
        Assert.True(minimum >= 50);
    }

    [Fact]
    public void TastaturQwertzUndQwerty()
    {
        Assert.True(StaerkeHilfe.Covers("qwertzuiop", ZxcvbnPattern.Spatial));
        Assert.True(StaerkeHilfe.Covers("yxcvbnm", ZxcvbnPattern.Spatial));
        Assert.True(StaerkeHilfe.Covers("asdfghjklöä", ZxcvbnPattern.Spatial));
        Assert.True(StaerkeHilfe.Covers("+\"*ç%&/()=", ZxcvbnPattern.Spatial));
        Assert.True(StaerkeHilfe.Covers("zxcvbnm", ZxcvbnPattern.Spatial));
        Assert.True(StaerkeHilfe.Covers("1qay2wsx", ZxcvbnPattern.Spatial) || StaerkeHilfe.Covers("1qay2wsx", ZxcvbnPattern.Dictionary));
        Assert.True(StaerkeHilfe.Covers("7412369", ZxcvbnPattern.Spatial));
        Assert.True(StaerkeHilfe.Bits("ztrewq") < 20);
    }

    private static HashSet<string> Nachbarn(KeyboardGraph graph, string taste) =>
        [.. graph.Neighbors[Zeichenvorrat.Fest(taste)].Where(a => a is not null).SelectMany(a => a!).Select(z => z.Text)];

    [Fact]
    public void TastaturGraphenSindKorrekt()
    {
        foreach (var graph in KeyboardGraphs.All)
        {
            Assert.Empty(graph.MisalignedTokens);
            Assert.True(graph.AverageDegree > 2);
        }
        var qwertz = KeyboardGraphs.All.Single(g => g.Name == "qwertz_ch");
        Assert.Superset(new HashSet<string> { "t", "u", "g", "h", "6", "7" }, Nachbarn(qwertz, "z"));
        Assert.Superset(new HashSet<string> { "<", "a", "s", "x" }, Nachbarn(qwertz, "y"));
        Assert.Contains(Zeichenvorrat.Fest("ç"), qwertz.Shifted);
        var qwerty = KeyboardGraphs.All.Single(g => g.Name == "qwerty");
        Assert.Equal(new HashSet<string> { "1", "!", "2", "@", "w", "W", "a", "A" }, Nachbarn(qwerty, "q"));
        var keypad = KeyboardGraphs.All.Single(g => g.Name == "keypad");
        Assert.Equal(8, keypad.Neighbors[Zeichenvorrat.Fest("5")].Count(a => a is not null));
    }

    [Fact]
    public void WiederholungenFolgenJahreDaten()
    {
        Assert.True(StaerkeHilfe.Covers("aaaaaaaa", ZxcvbnPattern.Repeated));
        Assert.True(StaerkeHilfe.Covers("abcabcabc", ZxcvbnPattern.Repeated));
        Assert.True(StaerkeHilfe.Covers("abcdefgh", ZxcvbnPattern.Sequence));
        Assert.True(StaerkeHilfe.Covers("98765", ZxcvbnPattern.Sequence));
        Assert.True(StaerkeHilfe.Covers("acegi", ZxcvbnPattern.Sequence));
        Assert.True(StaerkeHilfe.Covers("1999", ZxcvbnPattern.Year));
        Assert.True(StaerkeHilfe.Covers("2099", ZxcvbnPattern.Year));
        Assert.False(StaerkeHilfe.Covers("1899", ZxcvbnPattern.Year));
        Assert.True(StaerkeHilfe.Covers("24.12.1990", ZxcvbnPattern.Date));
        Assert.True(StaerkeHilfe.Covers("241290", ZxcvbnPattern.Date));
        Assert.True(StaerkeHilfe.Covers("1990-12-24", ZxcvbnPattern.Date));
        Assert.True(StaerkeHilfe.Covers("1.1.91", ZxcvbnPattern.Date));
        Assert.True(StaerkeHilfe.Bits("24.12.1990") < 20);
    }

    [Fact]
    public void WoerterbuchUmgekehrtUndL33t()
    {
        Assert.True(StaerkeHilfe.Covers("passwort", ZxcvbnPattern.Dictionary));
        Assert.True(StaerkeHilfe.Covers("trowssap", ZxcvbnPattern.Dictionary));
        Assert.True(StaerkeHilfe.Covers("P@ssw0rt", ZxcvbnPattern.Dictionary));
        Assert.True(StaerkeHilfe.Covers("s0mm3r", ZxcvbnPattern.Dictionary));
        Assert.True(StaerkeHilfe.Covers("|1eb3", ZxcvbnPattern.Dictionary));
        Assert.True(StaerkeHilfe.Bits("P@ssw0rt") < 15);
        Assert.True(StaerkeHilfe.Bits("TROWSSAP") < 15);
    }

    [Fact]
    public void GrossschreibungKostetWenig()
    {
        var klein = StaerkeHilfe.Bits("sommer");
        var gross = StaerkeHilfe.Bits("Sommer");
        var alle = StaerkeHilfe.Bits("SOMMER");
        var gemischt = StaerkeHilfe.Bits("sOmMeR");
        Assert.True(gross - klein <= 1.01);
        Assert.True(alle - klein <= 1.01);
        Assert.True(gemischt > gross);
    }

    [Fact]
    public void BenutzereingabenWerdenErkannt()
    {
        Assert.True(StaerkeHilfe.Covers("zwurbelmann", ZxcvbnPattern.Dictionary, "Zwurbelmann"));
        Assert.False(StaerkeHilfe.Covers("zwurbelmann", ZxcvbnPattern.Dictionary));
        Assert.True(StaerkeHilfe.Bits("Zwurbelmann1999", "zwurbelmann") < StaerkeHilfe.Bits("Zwurbelmann1999"));
    }

    [Fact]
    public void PassphrasenKetteAusEigenerListe()
    {
        Assert.True(StaerkeHilfe.Covers("kerze-vulkan-flaute-pirat", ZxcvbnPattern.Passphrase));
        var vier = StaerkeHilfe.Bits("kerze-vulkan-flaute-pirat");
        Assert.True(vier < 60);
        Assert.True(vier > 40);
        Assert.True(StaerkeHilfe.Covers("Kerze Vulkan Flaute", ZxcvbnPattern.Passphrase));
        Assert.True(StaerkeHilfe.Covers("kerzevulkanflaute", ZxcvbnPattern.Passphrase));
        Assert.True(StaerkeHilfe.Covers("kerze-vulkan_flaute", ZxcvbnPattern.Passphrase));
    }

    /// <summary>Befund #17: anderes Trennstück oder l33t macht aus 44 Bit Zufall nicht wieder 69–86 Bit.</summary>
    [Theory]
    [InlineData("kerze, vulkan, flaute, pirat")]
    [InlineData("kerze - vulkan - flaute - pirat")]
    [InlineData("kerze--vulkan--flaute--pirat")]
    [InlineData("kerze  vulkan  flaute  pirat")]
    [InlineData("kerze1vulkan2flaute3pirat")]
    [InlineData("k3rze-vulk4n-fl4ute-pir4t")]
    [InlineData("Kerze. Vulkan. Flaute. Pirat")]
    [InlineData("kerze_vulkan-flaute.pirat")]
    public void GekuerztePassphraseMitAnderemTrenner(string password)
    {
        Assert.True(StaerkeHilfe.Covers(password, ZxcvbnPattern.Passphrase));
        Assert.True(StaerkeHilfe.Bits(password) < 60);
        Assert.False(MasterPasswordPolicy.Check(password, []).Ok);
    }

    [Fact]
    public void VierWoerterMitBeliebigemTrennerAbgelehnt()
    {
        foreach (var separator in new[] { ", ", " - ", "--", "  ", ". ", "; ", "~", "1" })
        {
            for (var i = 0; i < 60; i++)
            {
                var password = string.Join(separator, PassphraseGenerator.Generate(4).Split('-'));
                Assert.True(StaerkeHilfe.Bits(password) < 60, $"Trenner {separator}");
            }
        }
        foreach (var separator in new[] { ", ", " - ", "--", "  " })
        {
            for (var i = 0; i < 40; i++)
            {
                var phrase = PassphraseGenerator.Generate().Replace("-", separator, StringComparison.Ordinal);
                Assert.True(StaerkeHilfe.Bits(phrase) >= 60, $"Trenner {separator}");
            }
        }
    }

    [Fact]
    public void WortfolgenMitTrennzeichen()
    {
        Assert.True(StaerkeHilfe.Covers("Mein Hund heisst Bello", ZxcvbnPattern.Phrase));
        Assert.True(StaerkeHilfe.Covers("Ich wohne seit 2015 in Olten", ZxcvbnPattern.Phrase));
        Assert.True(StaerkeHilfe.Bits("Mein Hund heisst Bello") < 60);
        Assert.True(StaerkeHilfe.Bits("Ich wohne seit 2015 in Olten") < 60);
        Assert.True(StaerkeHilfe.Covers("Mein Hund-heisst Bello", ZxcvbnPattern.Phrase));
        Assert.True(StaerkeHilfe.Bits("Mein  Hund  heisst  Bello") < 60);
        Assert.True(StaerkeHilfe.Bits("Mein, Hund, heisst, Bello") < 60);
        for (var i = 0; i < 100; i++)
        {
            Assert.True(StaerkeHilfe.Bits(PassphraseGenerator.Generate().Replace('-', ' ')) >= 60);
        }
        Assert.True(StaerkeHilfe.Bits("Der rote Fuchs springt über den faulen Hund") >= 60);
    }

    [Fact]
    public void KleinereRangprodukte()
    {
        Assert.Equal(0, ZxcvbnMatcher.Log2SmallerProducts(40, 1));
        Assert.Equal(0, ZxcvbnMatcher.Log2SmallerProducts(1, 5));
        var value = ZxcvbnMatcher.Log2SmallerProducts(36, 4);
        Assert.True(Math.Abs(value - Math.Log2(Math.Pow(36 * Math.Log(2.0), 3) / 6)) < 1e-9);
    }

    [Fact]
    public void ListenSindGeladen()
    {
        var ranks = ZxcvbnDictionary.Shared.Ranks;
        Assert.True(ranks.Count > 250_000);
        Assert.Equal(1, ranks["123456"]);
        Assert.True(ranks["passwort"] <= 10);
        foreach (var word in new[] { "grüezi", "gruezi", "zürich", "zuerich", "zurich", "müller", "mueller", "yb", "scb", "fcb",
                     "biel", "bern", "thun", "meister", "sommer", "schatz", "matterhorn", "eishockey",
                     "michael", "sabine", "smith", "the", "correct" })
        {
            Assert.True(ranks.ContainsKey(word), $"fehlt: {word}");
        }
        Assert.Equal(ZxcvbnDictionary.Web2Rank, ranks["zymotic"]);
        Assert.True(ranks["kerze"] <= ZxcvbnDictionary.PassphraseRank);
        Assert.True(ZxcvbnDictionary.Shared.MaxWordLength >= 20);
    }

    [Fact]
    public void VornKomprimierteListeWirdRichtigEntpackt()
    {
        var words = new List<string>();
        ZxcvbnListData.ForEachFrontCoded("0aardwolf\n5ic\n4\n3c"u8.ToArray(), (word, _) => words.Add(word));
        Assert.Equal(["aardwolf", "aardwic", "aard", "aarc"], words);
    }

    [Fact]
    public void NormalisierungWieSpec()
    {
        Assert.Equal(StaerkeHilfe.Bits("ab cd ef"), StaerkeHilfe.Bits("ab\u00A0cd ef"));
        Assert.Equal(StaerkeHilfe.Bits("café"), StaerkeHilfe.Bits("cafe\u0301"));
    }

    [Fact]
    public void StufenGrenzen()
    {
        Assert.Equal(StrengthLevel.VeryWeak, PasswordStrength.LevelForBits(0));
        Assert.Equal(StrengthLevel.VeryWeak, PasswordStrength.LevelForBits(27.99));
        Assert.Equal(StrengthLevel.Weak, PasswordStrength.LevelForBits(28));
        Assert.Equal(StrengthLevel.Weak, PasswordStrength.LevelForBits(35.99));
        Assert.Equal(StrengthLevel.Fair, PasswordStrength.LevelForBits(36));
        Assert.Equal(StrengthLevel.Fair, PasswordStrength.LevelForBits(59.99));
        Assert.Equal(StrengthLevel.Strong, PasswordStrength.LevelForBits(60));
        Assert.Equal(StrengthLevel.Strong, PasswordStrength.LevelForBits(79.99));
        Assert.Equal(StrengthLevel.VeryStrong, PasswordStrength.LevelForBits(80));
        Assert.Equal(0, PasswordStrength.Estimate("").Bits);
        Assert.Equal(StrengthLevel.VeryWeak, PasswordStrength.Estimate("").Level);
    }

    [Fact]
    public void BruteForceZehnJeZeichen()
    {
        var bits = StaerkeHilfe.Bits("龍虎鳳凰麒麟亀蛇");
        Assert.True(Math.Abs(bits - 8 * Math.Log2(10.0)) < 0.01);
    }

    [Fact]
    public void SehrLangeEingabeBleibtSchnellUndEndlich()
    {
        uint state = 12345;                                            // feste Pseudo-Zufallsfolge
        var lang = new string([.. Enumerable.Range(0, 4800).Select(_ =>
        {
            state = unchecked(state * 1_103_515_245 + 12345);
            return (char)(33 + (state >> 16) % 94);
        })]);
        _ = PasswordStrength.Estimate("warmup");
        var uhr = Stopwatch.StartNew();
        var bits = PasswordStrength.Estimate(lang).Bits;
        Assert.True(double.IsFinite(bits));
        Assert.True(bits > 60);
        Assert.True(uhr.Elapsed < TimeSpan.FromSeconds(2), $"{uhr.Elapsed}");
    }

    [Fact]
    public async Task NebenlaeufigGleichesErgebnis()
    {
        const string password = "Sommer2026!!!Kerze";
        var expected = PasswordStrength.Estimate(password).Bits;
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => PasswordStrength.Estimate(password).Bits)));
        Assert.All(results, r => Assert.Equal(expected, r));
    }

    /// <summary>Die Oberfläche schätzt bei jedem Tastendruck: 64 Zeichen unter 20 ms (Release; Debug grosszügiger).</summary>
    [Fact]
    public void Laufzeit64Zeichen()
    {
        _ = ZxcvbnDictionary.Shared;
        string[] samples =
        [
            "P@ssw0rd!|1Sommer2026-qwertz-147258-abcabc-Kerze-Vulkan-24.12.19",
            string.Concat(Enumerable.Repeat("1!|l", 16)),
            "kerze-vulkan-flaute-pirat-seide-hafen-kerze-vulkan-flaute-pirat-",
            "IchLiebeMeinenHundUndMeineKatzeSehrSehrFestUndImmerWiederGern!!!",
            "jK8#mW2$qP5!vB9@zR4&tY7*nL3%hG6^fD1(sA0)xC2+eU5=oI8?wQ4:rT7;yE1~",
        ];
#if DEBUG
        var limit = TimeSpan.FromMilliseconds(150);
#else
        var limit = TimeSpan.FromMilliseconds(20);
#endif
        foreach (var sample in samples)
        {
            Assert.Equal(64, sample.Length);
            _ = PasswordStrength.Estimate(sample);                     // JIT aufwärmen
            var worst = TimeSpan.Zero;
            for (var i = 0; i < 5; i++)
            {
                var uhr = Stopwatch.StartNew();
                _ = PasswordStrength.Estimate(sample);
                worst = TimeSpan.FromTicks(Math.Max(worst.Ticks, uhr.Elapsed.Ticks));
            }
            Assert.True(worst < limit, $"{sample[..10]}: {worst}");
        }
    }
}

/// <summary>Master-Passwort-Regel nach SPEC §1.6/§8 und Normalisierung nach §1.1 (MasterPasswordPolicyTests.swift).</summary>
public class StaerkeRegelTests
{
    [Fact]
    public void Grenzwerte()
    {
        Assert.Equal(60, MasterPasswordPolicy.MinimumBits);
        Assert.Equal(12, MasterPasswordPolicy.MinimumLength);
        Assert.Equal(1024, MasterPasswordPolicy.MaximumUtf8Bytes);
    }

    [Fact]
    public void PassphraseIstOk()
    {
        var result = MasterPasswordPolicy.Check(PassphraseGenerator.Generate());
        Assert.True(result.Ok);
        Assert.True(result.Bits >= 60);
    }

    [Fact]
    public void ZuKurzIstNieOk()
    {
        var result = MasterPasswordPolicy.Check("kV7#pQ2$mZ9");
        Assert.False(result.Ok);
        Assert.True(result.Bits < 60);
    }

    [Fact]
    public void Hoechstens1024Bytes()
    {
        const string prefix = "kV7#pQ2$mZ9!xR4@tL8&";
        var exact = prefix + new string('a', 1024 - prefix.Length);
        Assert.Equal(1024, System.Text.Encoding.UTF8.GetByteCount(exact));
        Assert.True(MasterPasswordPolicy.Check(exact).Ok);
        var result = MasterPasswordPolicy.Check(exact + "a");
        Assert.False(result.Ok);
        Assert.True(result.Bits >= 60);
        var umlaut = prefix + new string('ä', 503);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(umlaut) > 1024);
        Assert.False(MasterPasswordPolicy.Check(umlaut).Ok);
    }

    [Fact]
    public void NormalisierungZsUndNfc()
    {
        Assert.Equal("a b", MasterPasswordPolicy.Normalized("a\u00A0b"));
        Assert.Equal("é", MasterPasswordPolicy.Normalized("e\u0301"));
        Assert.Equal("a b c d", MasterPasswordPolicy.Normalized("a\u2003b\u202Fc\u3000d"));
        Assert.Equal("a\tb\u200Bc", MasterPasswordPolicy.Normalized("a\tb\u200Bc"));
        Assert.Equal("  wort  ", MasterPasswordPolicy.Normalized("  wort  "));
        Assert.Equal(" x ", MasterPasswordPolicy.Normalized("\u00A0x\u00A0"));
        // Einzelne Surrogate (gibt es in Swift nicht) werden zu U+FFFD statt einer Ausnahme
        Assert.Equal("a�b", MasterPasswordPolicy.Normalized("a\uD800b"));
    }

    [Fact]
    public void PruefungNachNormalisierung()
    {
        const string mitNbsp = "Kerze\u00A0Vulkan\u00A0Flaute\u00A0Pirat\u00A0Seide\u00A0Hafen";
        const string mitLeer = "Kerze Vulkan Flaute Pirat Seide Hafen";
        Assert.Equal(MasterPasswordPolicy.Check(mitLeer).Bits, MasterPasswordPolicy.Check(mitNbsp).Bits);
        Assert.Equal(MasterPasswordPolicy.Check(mitLeer).Ok, MasterPasswordPolicy.Check(mitNbsp).Ok);
        var zerlegt = string.Concat(Enumerable.Repeat("e\u0301", 11));
        Assert.Equal(11, SwiftText.Zeichenzahl(MasterPasswordPolicy.Normalized(zerlegt)));
        Assert.False(MasterPasswordPolicy.Check(zerlegt).Ok);
    }

    [Fact]
    public void BenutzereingabenAusKontonamen()
    {
        var inputs = MasterPasswordPolicy.UserInputs("jmueller", "Jürg Müller-Zbinden");
        Assert.Equal("siegel", inputs[0]);
        foreach (var expected in new[] { "jmueller", "jürg", "juerg", "jurg", "müller", "mueller", "muller", "zbinden",
                     "jürgmüllerzbinden", "jürg müller-zbinden" })
        {
            Assert.Contains(expected, inputs);
        }
        Assert.Equal(inputs.Count, inputs.Distinct(StringComparer.Ordinal).Count());
        var ohne = MasterPasswordPolicy.Check("JuergMueller1971!", ["siegel"]).Bits;
        var mit = MasterPasswordPolicy.Check("JuergMueller1971!", inputs).Bits;
        Assert.True(mit <= ohne);
        Assert.True(MasterPasswordPolicy.Check("Siegel2026Siegel!", ["siegel"]).Bits < 60);
    }

    [Fact]
    public void StandardEingabenEnthaltenSiegelUndKonto()
    {
        var inputs = MasterPasswordPolicy.DefaultUserInputs();
        Assert.Contains("siegel", inputs);
        Assert.Contains(SwiftText.Klein(MasterPasswordPolicy.Normalized(Environment.UserName)), inputs);
    }
}

/// <summary>Passphrasen-Generator nach SPEC §1.6 (PassphraseGeneratorTests.swift).</summary>
public class StaerkePassphraseTests
{
    [Fact]
    public void ListeGenau2048()
    {
        Assert.Equal(2048, PassphraseGenerator.WordListCount);
        Assert.Equal(2048, PassphraseGenerator.Words.Count);
        Assert.Equal(2048, PassphraseGenerator.Words.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void ListeNurKleinbuchstabenVierBisAcht()
    {
        foreach (var word in PassphraseGenerator.Words)
        {
            Assert.InRange(word.Length, 4, 8);
            Assert.All(word, c => Assert.InRange(c, 'a', 'z'));
        }
    }

    [Fact]
    public void ListeOhneGesperrteStaemme()
    {
        string[] blocked = ["arsch", "fick", "hure", "nazi", "sex", "porn", "nackt", "mord", "leiche", "bombe", "waffen",
            "krieg", "drog", "teufel", "idiot", "dumm", "doof", "jude", "sarg", "kotz", "kack"];
        foreach (var word in PassphraseGenerator.Words)
        {
            Assert.DoesNotContain(blocked, b => word.Contains(b, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void FormatSechsWoerterMitBindestrich()
    {
        var list = PassphraseGenerator.Words.ToHashSet(StringComparer.Ordinal);
        for (var i = 0; i < 200; i++)
        {
            var parts = PassphraseGenerator.Generate().Split('-');
            Assert.Equal(6, parts.Length);
            Assert.All(parts, p => Assert.Contains(p, list));
        }
        Assert.Equal("", PassphraseGenerator.Generate(0));
        Assert.Equal("", PassphraseGenerator.Generate(-3));
        Assert.DoesNotContain("-", PassphraseGenerator.Generate(1), StringComparison.Ordinal);
        Assert.Equal(10, PassphraseGenerator.Generate(10).Split('-').Length);
    }

    [Fact]
    public void Entropie()
    {
        Assert.Equal(66, PassphraseGenerator.EntropyBits(6));
        Assert.Equal(11, PassphraseGenerator.EntropyBits(1));
        Assert.Equal(0, PassphraseGenerator.EntropyBits(0));
        Assert.Equal(0, PassphraseGenerator.EntropyBits(-1));
    }

    [Fact]
    public void ZufallUnterschiedlich()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 500; i++) { seen.Add(PassphraseGenerator.Generate()); }
        Assert.Equal(500, seen.Count);
    }

    /// <summary>Rohe Ziehung: 2048 · 50 Ziehungen, Chi-Quadrat (df 2047) unter 2047 + 6σ, Einzelwerte 10…110,
    /// erste und zweite Listenhälfte gleich oft (randombytes_uniform nutzt den ganzen Bereich).</summary>
    [Fact]
    public void GrobGleichverteilt()
    {
        var words = PassphraseGenerator.Words;
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var i = 0; i < words.Count; i++) { index[words[i]] = i; }
        var counts = new int[words.Count];
        var draws = words.Count * 50;
        var done = 0;
        while (done < draws)
        {
            foreach (var part in PassphraseGenerator.Draw(8).Split('-'))
            {
                counts[index[part]]++;
                done++;
            }
        }
        var expected = (double)done / words.Count;
        var chi2 = counts.Sum(c => Math.Pow(c - expected, 2) / expected);
        Assert.True(chi2 < 2047 + 6 * 64, $"{chi2}");
        Assert.True(counts.Min() >= 10);
        Assert.True(counts.Max() <= 110);
        var firstHalf = counts[..1024].Sum();
        var secondHalf = counts[1024..].Sum();
        Assert.True(Math.Abs((double)(firstHalf - secondHalf)) < 6 * Math.Sqrt(done));
    }

    [Fact]
    public void VorschlagErfuelltRegelImmer()
    {
        var ranks = ZxcvbnDictionary.Shared.Ranks;
        var haeufigste = PassphraseGenerator.Words.OrderBy(w => ranks.GetValueOrDefault(w, int.MaxValue)).Take(6);
        Assert.True(PasswordStrength.Estimate(string.Join("-", haeufigste)).Bits < 60);
        for (var i = 0; i < 200; i++)
        {
            Assert.True(PasswordStrength.Estimate(PassphraseGenerator.Generate()).Bits >= 60);
        }
    }
}
