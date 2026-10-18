using System.Text;

namespace Siegel.Werkzeuge.Tests;

/// <summary>Passwort-Generator (SPEC §7.5, §8, §10; Port von PasswordGeneratorTests.swift): Länge, Klassen, erstes
/// Zeichen, ähnliche Zeichen, Gleichverteilung (Chi-Quadrat) und exakte Entropie (Vollaufzählung).</summary>
public class PasswordGeneratorTests
{
    private static PasswordGeneratorOptions Options(int length = 24, bool upper = true, bool lower = true, bool digits = true,
        bool symbols = true, bool avoid = false) => new(length, upper, lower, digits, symbols, avoid);

    /// <summary>Alle 16 Klassen-Kombinationen (inkl. „keine“) × ähnliche Zeichen an/aus, Länge 8.</summary>
    private static readonly List<PasswordGeneratorOptions> AllCombinations =
        [.. Enumerable.Range(0, 16).SelectMany(mask => new[] { false, true }.Select(avoid =>
            Options(8, (mask & 1) != 0, (mask & 2) != 0, (mask & 4) != 0, (mask & 8) != 0, avoid)))];

    /// <summary>Kritischer Chi-Quadrat-Wert (Wilson–Hilferty) für sehr kleines Fehlalarm-Risiko (z = 4.75).</summary>
    private static double ChiSquareCritical(int df)
    {
        var k = (double)df;
        const double z = 4.75;
        var a = 2.0 / (9.0 * k);
        return k * Math.Pow(1 - a + z * Math.Sqrt(a), 3);
    }

    private static double ChiSquare(int[] counts)
    {
        var total = (double)counts.Sum();
        var expected = total / counts.Length;
        return counts.Sum(c => Math.Pow(c - expected, 2) / expected);
    }

    private static byte[] Bytes(string s) => Encoding.ASCII.GetBytes(s);

    [Theory]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(12)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    public void LaengeWirdEingehalten(int length)
    {
        for (var i = 0; i < 50; i++) { Assert.Equal(length, PasswordGenerator.Generate(Options(length)).Length); }
    }

    [Fact]
    public void LaengeWirdGeklemmt()
    {
        foreach (var (input, expected) in new[] { (int.MinValue, 8), (-5, 8), (0, 8), (7, 8), (65, 64), (1000, 64), (int.MaxValue, 64) })
        {
            Assert.Equal(expected, PasswordGenerator.Generate(Options(input)).Length);
            Assert.Equal(PasswordGenerator.EntropyBits(Options(expected)), PasswordGenerator.EntropyBits(Options(input)));
        }
    }

    [Fact]
    public void Vorraete()
    {
        var symbols = PasswordGenerator.SymbolCharacters;
        Assert.Equal(32, symbols.Length);
        Assert.Equal(32, symbols.Distinct().Count());
        Assert.All(symbols, b => Assert.InRange(b, (byte)0x21, (byte)0x7E));
        var all = PasswordGenerator.UppercaseCharacters.Concat(PasswordGenerator.LowercaseCharacters)
            .Concat(PasswordGenerator.DigitCharacters).Concat(symbols).ToHashSet();
        Assert.Equal(Enumerable.Range(0x21, 94).Select(b => (byte)b).ToHashSet(), all);
        Assert.Equal(Bytes("0Oo1lI|!`'\",.;:").ToHashSet(), PasswordGenerator.AmbiguousCharacters.ToHashSet());
        Assert.Equal([24, 24, 8, 23], PasswordGenerator.CharacterClasses(Options(avoid: true)).Select(c => c.Length));
        Assert.Empty(PasswordGenerator.ForbiddenFirstCharacters.Intersect(PasswordGenerator.AmbiguousCharacters));
    }

    [Fact]
    public void KlassenGarantie()
    {
        foreach (var options in AllCombinations)
        {
            var classes = PasswordGenerator.CharacterClasses(options).Select(c => c.ToHashSet()).ToList();
            var pool = classes.SelectMany(c => c).ToHashSet();
            for (var i = 0; i < 300; i++)
            {
                var bytes = Bytes(PasswordGenerator.Generate(options));
                Assert.Equal(8, bytes.Length);
                Assert.All(bytes, b => Assert.Contains(b, pool));
                foreach (var cls in classes) { Assert.Contains(bytes, cls.Contains); }
            }
        }
    }

    [Fact]
    public void FallbackKlein()
    {
        var none = Options(upper: false, lower: false, digits: false, symbols: false);
        var classes = PasswordGenerator.CharacterClasses(none);
        Assert.Single(classes);
        Assert.Equal(PasswordGenerator.LowercaseCharacters, classes[0]);
        for (var i = 0; i < 100; i++) { Assert.All(PasswordGenerator.Generate(none), c => Assert.InRange(c, 'a', 'z')); }
        Assert.Equal(PasswordGenerator.EntropyBits(Options(upper: false, digits: false, symbols: false)), PasswordGenerator.EntropyBits(none));
    }

    [Fact]
    public void ErstesZeichen()
    {
        var forbidden = PasswordGenerator.ForbiddenFirstCharacters.ToHashSet();
        var onlySymbols = Options(8, upper: false, lower: false, digits: false, symbols: true);
        var seenLater = new HashSet<byte>();
        for (var i = 0; i < 4000; i++)
        {
            var bytes = Bytes(PasswordGenerator.Generate(onlySymbols));
            Assert.DoesNotContain(bytes[0], forbidden);
            seenLater.UnionWith(bytes.Skip(1).Where(forbidden.Contains));
        }
        Assert.Equal(forbidden, seenLater);
        foreach (var options in AllCombinations)
        {
            for (var i = 0; i < 100; i++) { Assert.DoesNotContain((byte)PasswordGenerator.Generate(options)[0], forbidden); }
        }
    }

    [Fact]
    public void AehnlicheZeichen()
    {
        var ambiguous = PasswordGenerator.AmbiguousCharacters.ToHashSet();
        var options = Options(64, avoid: true);
        for (var i = 0; i < 2000; i++)
        {
            Assert.All(Bytes(PasswordGenerator.Generate(options)), b => Assert.DoesNotContain(b, ambiguous));
        }
    }

    [Fact]
    public void GleichverteilungKleinsterFall()
    {
        // Klassen {a,b} und {=,1}, Länge 2: erlaubt sind genau a=, a1, b=, b1, 1a, 1b (gleich wahrscheinlich).
        List<byte[]> classes = [Bytes("ab"), Bytes("=1")];
        string[] valid = ["a=", "a1", "b=", "b1", "1a", "1b"];
        var counts = new int[valid.Length];
        for (var i = 0; i < 60_000; i++)
        {
            var index = Array.IndexOf(valid, PasswordGenerator.Generate(classes, 2));
            Assert.True(index >= 0, "unerwartete Zeichenkette");
            counts[index]++;
        }
        Assert.True(ChiSquare(counts) < ChiSquareCritical(valid.Length - 1));
        Assert.True(Math.Abs(PasswordGenerator.ExactEntropyBits(classes, 2) - Math.Log2(6)) < 1e-12);
    }

    [Fact]
    public void GleichverteilungChiQuadrat()
    {
        var classes = PasswordGenerator.CharacterClasses(Options());
        var classOf = new Dictionary<byte, int>();
        for (var i = 0; i < classes.Count; i++) { foreach (var b in classes[i]) { classOf[b] = i; } }

        // (a) Länge 24: Stellen 1…23 innerhalb jeder Klasse gleichverteilt, Stelle 0 über die erlaubten Zeichen.
        var later = new Dictionary<byte, int>();
        var first = new Dictionary<byte, int>();
        for (var n = 0; n < 20_000; n++)
        {
            var bytes = Bytes(PasswordGenerator.Generate(Options(24)));
            first[bytes[0]] = first.GetValueOrDefault(bytes[0]) + 1;
            foreach (var b in bytes.Skip(1)) { later[b] = later.GetValueOrDefault(b) + 1; }
        }
        foreach (var cls in classes)
        {
            Assert.True(ChiSquare([.. cls.Select(b => later.GetValueOrDefault(b))]) < ChiSquareCritical(cls.Length - 1));
            var allowed = cls.Where(b => !PasswordGenerator.ForbiddenFirstCharacters.Contains(b)).ToArray();
            Assert.True(ChiSquare([.. allowed.Select(b => first.GetValueOrDefault(b))]) < ChiSquareCritical(allowed.Length - 1));
        }

        // (b) Länge 8: Die Klassen-Garantie sitzt an keiner festen Stelle.
        var digitsAt = new int[7];
        var symbolsAt = new int[7];
        for (var n = 0; n < 30_000; n++)
        {
            var bytes = Bytes(PasswordGenerator.Generate(Options(8)));
            for (var position = 1; position < 8; position++)
            {
                if (classOf[bytes[position]] == 2) { digitsAt[position - 1]++; }
                if (classOf[bytes[position]] == 3) { symbolsAt[position - 1]++; }
            }
        }
        Assert.True(ChiSquare(digitsAt) < ChiSquareCritical(6));
        Assert.True(ChiSquare(symbolsAt) < ChiSquareCritical(6));

        // (c) Länge 64: über alle 94 Zeichen gleichverteilt.
        var all = new Dictionary<byte, int>();
        for (var n = 0; n < 4_000; n++)
        {
            foreach (var b in Bytes(PasswordGenerator.Generate(Options(64))).Skip(1)) { all[b] = all.GetValueOrDefault(b) + 1; }
        }
        Assert.True(ChiSquare([.. Enumerable.Range(0x21, 94).Select(b => all.GetValueOrDefault((byte)b))]) < ChiSquareCritical(93));

        // (d) Nur eine Klasse: exakt gleichverteilt.
        var lower = new Dictionary<byte, int>();
        for (var n = 0; n < 5_000; n++)
        {
            foreach (var b in Bytes(PasswordGenerator.Generate(Options(32, upper: false, digits: false, symbols: false))))
            {
                lower[b] = lower.GetValueOrDefault(b) + 1;
            }
        }
        Assert.True(ChiSquare([.. PasswordGenerator.LowercaseCharacters.Select(b => lower.GetValueOrDefault(b))]) < ChiSquareCritical(25));
    }

    [Fact]
    public void EntropieBruteForce()
    {
        var forbidden = PasswordGenerator.ForbiddenFirstCharacters.ToHashSet();
        double BruteForceBits(List<byte[]> classes, int length)
        {
            var pool = classes.SelectMany(c => c).ToArray();
            var sets = classes.Select(c => c.ToHashSet()).ToList();
            var count = 0;
            var indices = new int[length];
            while (true)
            {
                if (!forbidden.Contains(pool[indices[0]]))
                {
                    var chars = indices.Select(i => pool[i]).ToArray();
                    if (sets.All(set => chars.Any(set.Contains))) { count++; }
                }
                var position = length - 1;
                while (position >= 0)
                {
                    indices[position]++;
                    if (indices[position] < pool.Length) { break; }
                    indices[position] = 0;
                    position--;
                }
                if (position < 0) { break; }
            }
            return Math.Log2(count);
        }

        var reduced = PasswordGenerator.CharacterClasses(Options(avoid: true));
        var full = PasswordGenerator.CharacterClasses(Options());
        var cases = new List<(List<byte[]> Classes, int Length)>
        {
            ([PasswordGenerator.DigitCharacters, PasswordGenerator.SymbolCharacters], 3),
            ([reduced[0], reduced[2], reduced[3]], 3),
            ([full[2], full[3]], 4),
            ([Bytes("AB"), Bytes("a"), Bytes("012"), Bytes("=+!#")], 5),
            ([Bytes("AB"), Bytes("a"), Bytes("012"), Bytes("=+!#")], 4),
            ([Bytes("-@"), Bytes("x")], 3),
        };
        foreach (var (classes, length) in cases)
        {
            var exact = PasswordGenerator.ExactEntropyBits(classes, length);
            Assert.True(Math.Abs(exact - BruteForceBits(classes, length)) < 1e-9);
        }
    }

    [Fact]
    public void EntropiePlausibel()
    {
        Assert.True(Math.Abs(PasswordGenerator.EntropyBits(Options(8, upper: false, lower: false, digits: true, symbols: false)) - 8 * Math.Log2(10)) < 1e-9);
        Assert.True(Math.Abs(PasswordGenerator.EntropyBits(Options(24, upper: false, digits: false, symbols: false)) - 24 * Math.Log2(26)) < 1e-9);
        var standard = PasswordGenerator.EntropyBits(Options());
        var upperBound = Math.Log2(90.0) + 23 * Math.Log2(94.0);
        Assert.True(standard < upperBound);
        Assert.True(standard > upperBound - 0.2);
        Assert.InRange(standard, 150, 158);
        Assert.True(PasswordGenerator.EntropyBits(Options(avoid: true)) < standard);
        var previous = 0.0;
        for (var length = 8; length <= 64; length++)
        {
            var bits = PasswordGenerator.EntropyBits(Options(length));
            Assert.True(bits > previous);
            Assert.True(bits <= length * Math.Log2(94));
            previous = bits;
        }
        Assert.True(PasswordGenerator.EntropyBits(Options(20)) > 120);
        Assert.True(PasswordGenerator.EntropyBits(Options(8)) > 50);
    }

    [Fact]
    public void Annahmewahrscheinlichkeit()
    {
        foreach (var options in AllCombinations)
        {
            var classes = PasswordGenerator.CharacterClasses(options);
            var pool = (double)classes.Sum(c => c.Length);
            var firstPool = (double)classes.Sum(c => c.Count(b => !PasswordGenerator.ForbiddenFirstCharacters.Contains(b)));
            var bits = PasswordGenerator.EntropyBits(options);
            var acceptance = Math.Pow(2, bits - Math.Log2(firstPool) - 7 * Math.Log2(pool));
            Assert.True(acceptance > 0.3);
            Assert.True(acceptance <= 1 + 1e-12);
            Assert.True(Math.Abs(acceptance - PasswordGenerator.AcceptanceProbability(classes, 8)) < 1e-9);
        }
    }

    [Fact]
    public void UnmoeglicheVorgabenEndenSofort()
    {
        Assert.Equal("", PasswordGenerator.Generate([Bytes("=")], 1));
        Assert.Equal("", PasswordGenerator.Generate([Bytes("ab"), Bytes("01")], 1));
        Assert.Equal("", PasswordGenerator.Generate([], 8));
        Assert.Equal(0, PasswordGenerator.ExactEntropyBits([Bytes("=")], 1));
        Assert.Equal("a=", PasswordGenerator.Generate([Bytes("="), Bytes("a")], 2));
    }
}
