using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Staerke.Zxcvbn;

// Bewertung (zxcvbn scoring.coffee) wie Sources/SiegelCore/Staerke/Zxcvbn/ZxcvbnScoring.swift: Rateversuche je Muster
// und die kleinste Zerlegung per dynamischer Programmierung, g(l) = l! · Π guesses(m) + 10000^(l−1), in log2.

internal static class ZxcvbnScoring
{
    internal const double BruteforceCardinality = 10;
    internal const double MinGuessesBeforeGrowingSequence = 10_000;
    internal const double MinSubmatchGuessesSingleChar = 10;
    internal const double MinSubmatchGuessesMultiChar = 50;
    internal const int MinYearSpace = 20;

    internal readonly record struct Result(double Log2Guesses, IReadOnlyList<ZxcvbnMatch> Sequence);

    /// <summary>Untergrenze für Teilstücke kürzer als das ganze Passwort (estimate_guesses).</summary>
    internal static double AdjustedLog2(in ZxcvbnMatch match, int passwordLength)
    {
        if (match.Length >= passwordLength) { return Math.Max(match.Log2Guesses, 0); }
        var floor = match.Length == 1 ? MinSubmatchGuessesSingleChar : MinSubmatchGuessesMultiChar;
        return Math.Max(match.Log2Guesses, Math.Log2(floor));
    }

    internal static double BruteforceLog2(int length)
    {
        var raw = length * Math.Log2(BruteforceCardinality);
        var floor = length == 1 ? MinSubmatchGuessesSingleChar + 1 : MinSubmatchGuessesMultiChar + 1;
        return Math.Max(raw, Math.Log2(floor));
    }

    /// <summary>Varianten der Gross-/Kleinschreibung (zxcvbn uppercase_variations, auf Unicode erweitert).</summary>
    internal static double UppercaseVariations(ReadOnlySpan<Zeichen> token)
    {
        var upper = 0;
        var lower = 0;
        foreach (var c in token)
        {
            if (c.IstGross) { upper++; } else if (c.IstKlein) { lower++; }
        }
        if (upper == 0) { return 1; }
        if (token.Length > 1 && upper == 1)
        {
            if (token[0].IstGross) { return 2; }
            if (token[^1].IstGross) { return 2; }
        }
        if (lower == 0) { return 2; }
        var variations = 0.0;
        for (var k = 1; k <= Math.Min(upper, lower); k++) { variations += ZxcvbnMath.NCk(upper + lower, k); }
        return Math.Max(variations, 1);
    }

    /// <summary>Varianten der l33t-Ersetzungen (zxcvbn l33t_variations); <paramref name="lowerToken"/> klein.
    /// <paramref name="sub"/>: l33t-Zeichen → Buchstabe. Ganzzahlige Produkte, die Reihenfolge ist egal.</summary>
    internal static double L33tVariations(ReadOnlySpan<Zeichen> lowerToken, IReadOnlyList<KeyValuePair<Zeichen, Zeichen>> sub)
    {
        var variations = 1.0;
        foreach (var (subbed, unsubbed) in sub)
        {
            var s = 0;
            var u = 0;
            foreach (var c in lowerToken)
            {
                if (ReferenceEquals(c, subbed)) { s++; } else if (ReferenceEquals(c, unsubbed)) { u++; }
            }
            if (s == 0) { continue; }
            if (u == 0)
            {
                variations *= 2;
            }
            else
            {
                var possibilities = 0.0;
                for (var k = 1; k <= Math.Min(u, s); k++) { possibilities += ZxcvbnMath.NCk(u + s, k); }
                variations *= possibilities;
            }
        }
        return variations;
    }

    internal static double SpatialLog2Guesses(int length, int turns, int shifted, KeyboardGraph graph)
    {
        var s = graph.StartingPositions;
        var d = graph.AverageDegree;
        var guesses = 0.0;
        if (length >= 2)
        {
            for (var i = 2; i <= length; i++)
            {
                var possibleTurns = Math.Min(turns, i - 1);
                if (possibleTurns < 1) { continue; }
                for (var j = 1; j <= possibleTurns; j++)
                {
                    guesses += ZxcvbnMath.NCk(i - 1, j - 1) * s * Math.Pow(d, j);
                }
            }
        }
        var lg = Math.Log2(Math.Max(guesses, 1));
        if (shifted > 0)
        {
            var unshifted = length - shifted;
            if (unshifted == 0)
            {
                lg += 1;
            }
            else
            {
                var variations = 0.0;
                for (var k = 1; k <= Math.Min(shifted, unshifted); k++) { variations += ZxcvbnMath.NCk(shifted + unshifted, k); }
                lg += Math.Log2(Math.Max(variations, 1));
            }
        }
        return lg;
    }

    internal static double SequenceLog2Guesses(ReadOnlySpan<Zeichen> token, bool ascending)
    {
        if (token.IsEmpty) { return 0; }
        var first = token[0];
        double basis;
        if (first.Ascii is 'a' or 'A' or 'z' or 'Z' or '0' or '1' or '9')
        {
            basis = 4;
        }
        else if (first.Ziffer >= 0)
        {
            basis = 10;
        }
        else
        {
            basis = 26;                                                 // auch für andere Alphabete (konservativ)
        }
        if (!ascending) { basis *= 2; }
        return Math.Log2(basis * token.Length);
    }

    // Kleinste Zerlegung (most_guessable_match_sequence)

    private readonly record struct Entry(int L, double Lg, double Lpi, ZxcvbnMatch Match);

    internal static Result MostGuessable(int n, List<ZxcvbnMatch> matches, bool excludeAdditive = false)
    {
        if (n <= 0) { return new Result(0, []); }

        var byEnd = new List<ZxcvbnMatch>[n];
        for (var k = 0; k < n; k++) { byEnd[k] = []; }
        foreach (var m in matches)
        {
            if (m.I >= 0 && m.J < n && m.I <= m.J) { byEnd[m.J].Add(m); }
        }
        for (var k = 0; k < n; k++)
        {
            if (byEnd[k].Count > 1) { StableSortByI(byEnd[k]); }
        }

        var optimal = new List<Entry>[n];
        for (var k = 0; k < n; k++) { optimal[k] = []; }
        var log2Additive = Math.Log2(MinGuessesBeforeGrowingSequence);

        bool EntryFor(int k, int l, out Entry found)
        {
            foreach (var e in optimal[k])
            {
                if (e.L == l)
                {
                    found = e;
                    return true;
                }
            }
            found = default;
            return false;
        }

        void Update(in ZxcvbnMatch m, int l)
        {
            var k = m.J;
            var lpi = AdjustedLog2(m, n);
            if (l > 1)
            {
                if (!EntryFor(m.I - 1, l - 1, out var previous)) { return; }
                lpi += previous.Lpi;
            }
            var lg = ZxcvbnMath.Log2Factorial(l) + lpi;
            if (!excludeAdditive)
            {
                lg = ZxcvbnMath.LogAdd(lg, (l - 1) * log2Additive);
            }
            var list = optimal[k];
            foreach (var competing in list)
            {
                if (competing.L <= l && competing.Lg <= lg) { return; }
            }
            var neu = new Entry(l, lg, lpi, m);
            for (var index = 0; index < list.Count; index++)
            {
                if (list[index].L == l)
                {
                    list[index] = neu;
                    return;
                }
            }
            list.Add(neu);
        }

        ZxcvbnMatch Bruteforce(int i, int j) =>
            new(ZxcvbnPattern.Bruteforce, i, j, BruteforceLog2(j - i + 1));

        void BruteforceUpdate(int k)
        {
            Update(Bruteforce(0, k), 1);
            if (k < 1) { return; }
            for (var i = 1; i <= k; i++)
            {
                var m = Bruteforce(i, k);
                var previous = optimal[i - 1];
                // Kopie der Länge: Update ändert nur optimal[k] (k ≥ i), nie optimal[i − 1]
                for (var index = 0; index < previous.Count; index++)
                {
                    var e = previous[index];
                    if (e.Match.Pattern != ZxcvbnPattern.Bruteforce) { Update(m, e.L + 1); }
                }
            }
        }

        for (var k = 0; k < n; k++)
        {
            foreach (var m in byEnd[k])
            {
                if (m.I > 0)
                {
                    var previous = optimal[m.I - 1];
                    for (var index = 0; index < previous.Count; index++) { Update(m, previous[index].L + 1); }
                }
                else
                {
                    Update(m, 1);
                }
            }
            BruteforceUpdate(k);
        }

        // Zurückverfolgen
        Entry? best = null;
        foreach (var e in optimal[n - 1])
        {
            if (best is null || e.Lg < best.Value.Lg) { best = e; }
        }
        if (best is null) { return new Result(BruteforceLog2(n), []); }
        var sequence = new List<ZxcvbnMatch>();
        var kk = n - 1;
        var ll = best.Value.L;
        while (kk >= 0 && ll >= 1 && EntryFor(kk, ll, out var e))
        {
            sequence.Insert(0, e.Match);
            kk = e.Match.I - 1;
            ll -= 1;
        }
        return new Result(best.Value.Lg, sequence);
    }

    /// <summary>Stabil nach I sortieren (Swifts sort ist stabil; List.Sort nicht).</summary>
    private static void StableSortByI(List<ZxcvbnMatch> list)
    {
        for (var a = 1; a < list.Count; a++)
        {
            var current = list[a];
            var b = a - 1;
            while (b >= 0 && list[b].I > current.I)
            {
                list[b + 1] = list[b];
                b--;
            }
            list[b + 1] = current;
        }
    }
}
