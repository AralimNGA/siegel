using System.Text;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Staerke.Zxcvbn;

// Muster-Erkennung (zxcvbn matching.coffee) bit-gleich zu Sources/SiegelCore/Staerke/Zxcvbn/ZxcvbnMatching.swift:
// Wörterbuch (auch umgekehrt und l33t), Tastaturfolgen, Wiederholungen, Folgen, Jahre, Daten, Benutzereingaben, dazu
// die Siegel-Erweiterungen (Passphrasen-Ketten, Wortfolgen, Vorlagen in ZxcvbnMatcher.Vorlagen.cs). Reihenfolge der
// Treffer und aller Schleifen wie in Swift, damit Grenzen (maxPassphraseSteps …) gleich greifen.

internal sealed partial class ZxcvbnMatcher
{
    private readonly ZxcvbnDictionary dictionary;
    private readonly Dictionary<string, int> userRanks = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> userLookup;
    private readonly int userMaxLength;
    private readonly int referenceYear;
    private readonly KeyboardGraph[] graphs;
    private readonly Zeichenvorrat vorrat;

    /// <param name="userInputs">schon nach SPEC §1.1 normalisiert</param>
    internal ZxcvbnMatcher(ZxcvbnDictionary dictionary, IReadOnlyList<string> userInputs, int referenceYear,
        KeyboardGraph[] graphs, Zeichenvorrat vorrat)
    {
        this.dictionary = dictionary;
        this.vorrat = vorrat;
        var maxLength = 0;
        var rank = 0;
        foreach (var input in userInputs)
        {
            var sb = new StringBuilder();
            foreach (var z in vorrat.Zerlegen(input)) { sb.Append(z.Klein.Text); }
            var key = sb.ToString();
            if (key.Length == 0) { continue; }
            rank++;
            userRanks.TryAdd(key, rank);
            maxLength = Math.Max(maxLength, Encoding.UTF8.GetByteCount(key));
        }
        userLookup = userRanks.GetAlternateLookup<ReadOnlySpan<char>>();
        userMaxLength = maxLength;
        this.referenceYear = referenceYear;
        this.graphs = graphs;
    }

    private static Zeichen[] Klein(Zeichen[] password)
    {
        var lower = new Zeichen[password.Length];
        for (var k = 0; k < password.Length; k++) { lower[k] = password[k].Klein; }
        return lower;
    }

    // Alle Muster

    internal List<ZxcvbnMatch> Omnimatch(Zeichen[] password)
    {
        var matches = new List<ZxcvbnMatch>();
        if (password.Length == 0) { return matches; }
        var lower = Klein(password);
        DictionaryMatches(password, lower, matches);
        ReverseDictionaryMatches(password, lower, matches);
        L33tMatches(password, lower, matches);
        SpatialMatches(password, matches);
        RepeatMatches(password, matches);
        SequenceMatches(password, matches);
        YearMatches(password, matches);
        DateMatches(password, matches);
        PassphraseMatches(password, lower, matches);
        PhraseMatches(password, lower, matches);
        CounterMatches(password, matches);
        CalendarMatches(password, lower, matches);
        PlaceCodeMatches(password, lower, matches);
        return matches;
    }

    // Verkettete Schlüssel: Teilstücke als Span ohne neue Zeichenketten nachschlagen

    private readonly struct Verkettung
    {
        internal Verkettung(ReadOnlySpan<Zeichen> keys)
        {
            var sb = new StringBuilder();
            Start = new int[keys.Length + 1];
            for (var k = 0; k < keys.Length; k++)
            {
                Start[k] = sb.Length;
                sb.Append(keys[k].Text);
            }
            Start[keys.Length] = sb.Length;
            Text = sb.ToString();
        }

        internal string Text { get; }
        internal int[] Start { get; }

        /// <summary>keys[i..&lt;j] (j exklusiv).</summary>
        internal ReadOnlySpan<char> Wort(int i, int j) => Text.AsSpan(Start[i], Start[j] - Start[i]);
    }

    /// <summary>Kleinster Rang aus Wörterbuch und Benutzereingaben, −1 wenn keiner.</summary>
    private int Rang(ReadOnlySpan<char> wort)
    {
        var best = dictionary.Lookup.TryGetValue(wort, out var r) ? r : -1;
        if (userLookup.TryGetValue(wort, out var user) && (best < 0 || user < best)) { best = user; }
        return best;
    }

    // Wörterbuch

    private readonly record struct Hit(int I, int J, int Rank);

    /// <summary>Alle Teilstücke von <paramref name="keys"/>, die in einer Liste stehen. Mit <paramref name="marked"/> nur
    /// Teilstücke, die mindestens eine markierte Stelle enthalten (l33t).</summary>
    private List<Hit> RankHits(Zeichen[] keys, bool[]? marked)
    {
        var n = keys.Length;
        var limit = Math.Max(dictionary.MaxWordLength, userMaxLength);
        var hits = new List<Hit>();
        var nextMarked = new int[n + 1];
        Array.Fill(nextMarked, n);
        if (marked is not null)
        {
            for (var k = n - 1; k >= 0; k--) { nextMarked[k] = marked[k] ? k : nextMarked[k + 1]; }
        }
        var kette = new Verkettung(keys);
        for (var i = 0; i < n; i++)
        {
            var firstUseful = marked is null ? i : nextMarked[i];
            if (firstUseful >= n) { break; }
            var end = Math.Min(n, i + limit);
            if (firstUseful >= end) { continue; }
            for (var j = i; j < end; j++)
            {
                if (j < firstUseful) { continue; }
                var best = Rang(kette.Wort(i, j + 1));
                if (best >= 0) { hits.Add(new Hit(i, j, best)); }
            }
        }
        return hits;
    }

    private void DictionaryMatches(Zeichen[] password, Zeichen[] lower, List<ZxcvbnMatch> matches)
    {
        foreach (var hit in RankHits(lower, null))
        {
            var token = password.AsSpan(hit.I, hit.J - hit.I + 1);
            var lg = Math.Log2(hit.Rank) + Math.Log2(ZxcvbnScoring.UppercaseVariations(token));
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Dictionary, hit.I, hit.J, lg));
        }
    }

    private void ReverseDictionaryMatches(Zeichen[] password, Zeichen[] lower, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        if (n <= 1) { return; }
        var reversed = (Zeichen[])lower.Clone();
        Array.Reverse(reversed);
        foreach (var hit in RankHits(reversed, null))
        {
            var i = n - 1 - hit.J;
            var j = n - 1 - hit.I;
            var token = password.AsSpan(i, j - i + 1);
            var lg = Math.Log2(hit.Rank) + Math.Log2(ZxcvbnScoring.UppercaseVariations(token)) + 1;   // umgekehrt: doppelt
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Dictionary, i, j, lg));
        }
    }

    /// <summary>l33t-Tabelle nach SPEC §1.6: Zeichen → mögliche Buchstaben.</summary>
    internal static readonly Dictionary<Zeichen, Zeichen[]> L33tTable = new()
    {
        [Zeichenvorrat.Fest("@")] = [Zeichenvorrat.Fest("a")],
        [Zeichenvorrat.Fest("4")] = [Zeichenvorrat.Fest("a")],
        [Zeichenvorrat.Fest("3")] = [Zeichenvorrat.Fest("e")],
        [Zeichenvorrat.Fest("1")] = [Zeichenvorrat.Fest("i"), Zeichenvorrat.Fest("l")],
        [Zeichenvorrat.Fest("!")] = [Zeichenvorrat.Fest("i"), Zeichenvorrat.Fest("l")],
        [Zeichenvorrat.Fest("|")] = [Zeichenvorrat.Fest("i"), Zeichenvorrat.Fest("l")],
        [Zeichenvorrat.Fest("0")] = [Zeichenvorrat.Fest("o")],
        [Zeichenvorrat.Fest("$")] = [Zeichenvorrat.Fest("s")],
        [Zeichenvorrat.Fest("5")] = [Zeichenvorrat.Fest("s")],
        [Zeichenvorrat.Fest("7")] = [Zeichenvorrat.Fest("t")],
        [Zeichenvorrat.Fest("9")] = [Zeichenvorrat.Fest("g")],
    };

    private void L33tMatches(Zeichen[] password, Zeichen[] lower, List<ZxcvbnMatch> matches)
    {
        var present = new List<Zeichen>();
        foreach (var c in password)
        {
            if (L33tTable.ContainsKey(c) && !present.Contains(c)) { present.Add(c); }
        }
        if (present.Count == 0) { return; }
        // Alle vollständigen Zuordnungen (jedes vorkommende l33t-Zeichen → genau ein Buchstabe)
        var subs = new List<List<KeyValuePair<Zeichen, Zeichen>>> { new() };
        foreach (var c in present)
        {
            var letters = L33tTable[c];
            var next = new List<List<KeyValuePair<Zeichen, Zeichen>>>();
            foreach (var sub in subs)
            {
                foreach (var letter in letters)
                {
                    next.Add([.. sub, new KeyValuePair<Zeichen, Zeichen>(c, letter)]);
                }
            }
            subs = next;
        }
        var n = password.Length;
        foreach (var sub in subs)
        {
            var translated = (Zeichen[])lower.Clone();
            var marked = new bool[n];
            for (var k = 0; k < n; k++)
            {
                foreach (var (key, letter) in sub)
                {
                    if (ReferenceEquals(key, password[k]))
                    {
                        translated[k] = letter;
                        marked[k] = true;
                        break;
                    }
                }
            }
            foreach (var hit in RankHits(translated, marked))
            {
                if (hit.J <= hit.I) { continue; }
                var token = password.AsSpan(hit.I, hit.J - hit.I + 1);
                var lg = Math.Log2(hit.Rank)
                    + Math.Log2(ZxcvbnScoring.UppercaseVariations(token))
                    + Math.Log2(ZxcvbnScoring.L33tVariations(lower.AsSpan(hit.I, hit.J - hit.I + 1), sub));
                matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Dictionary, hit.I, hit.J, lg));
            }
        }
    }

    // Passphrasen aus der eigenen Liste (Siegel-Erweiterung)

    /// <summary>Wörter der Passphrasen-Liste.</summary>
    internal static readonly HashSet<string> PassphraseWords = new(PassphraseGenerator.Words, StringComparer.Ordinal);
    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> PassphraseLookup =
        PassphraseWords.GetAlternateLookup<ReadOnlySpan<char>>();
    /// <summary>Mögliche Trennzeichen (Leerzeichen, - _ . , ; : / + * | ~ # ! ? oder keins).</summary>
    internal const int PassphraseSeparatorChoices = 16;
    private const int MaxPassphraseMatches = 4096;
    /// <summary>Obergrenze der durchsuchten Ketten (Laufzeit bei konstruierten Eingaben).</summary>
    private const int MaxPassphraseSteps = 50_000;

    private sealed record PassphraseChain(int End, (int Start, int End)[] Tokens, (int Start, int End)[] Gaps, double L33tLog2);

    private struct WortStelle
    {
        internal int Length;
        internal double L33t;
    }

    private static void PassphraseMatches(Zeichen[] password, Zeichen[] lower, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        if (n < 8) { return; }
        // Kleinschreibung und – falls l33t-Zeichen vorkommen – zwei Übersetzungen (1 ! | → i bzw. l)
        var variants = new List<Zeichen[]> { lower };
        var hatL33t = false;
        foreach (var c in password)
        {
            if (L33tTable.ContainsKey(c)) { hatL33t = true; break; }
        }
        if (hatL33t)
        {
            for (var choice = 0; choice < 2; choice++)
            {
                var v = new Zeichen[n];
                for (var k = 0; k < n; k++)
                {
                    v[k] = L33tTable.TryGetValue(lower[k], out var letters) && letters.Length > 0
                        ? letters[Math.Min(choice, letters.Length - 1)]
                        : lower[k];
                }
                variants.Add(v);
            }
        }
        // Wörter (4–8 Buchstaben) je Startposition mit ihren l33t-Varianten (log2)
        var wordsAt = new List<WortStelle>[n];
        for (var p = 0; p < n; p++) { wordsAt[p] = []; }
        var ketten = new Verkettung[variants.Count];
        for (var v = 0; v < variants.Count; v++) { ketten[v] = new Verkettung(variants[v]); }
        for (var p = 0; p < n; p++)
        {
            for (var index = 0; index < variants.Count; index++)
            {
                var chars = variants[index];
                for (var length = 1; length <= 8; length++)
                {
                    if (p + length > n) { break; }
                    if (length < 4 || !PassphraseLookup.Contains(ketten[index].Wort(p, p + length))) { continue; }
                    var l33t = 0.0;
                    if (index > 0)
                    {
                        var sub = new List<KeyValuePair<Zeichen, Zeichen>>();
                        for (var q = p; q < p + length; q++)
                        {
                            if (ReferenceEquals(chars[q], lower[q])) { continue; }
                            var vorhanden = sub.FindIndex(e => ReferenceEquals(e.Key, lower[q]));
                            var eintrag = new KeyValuePair<Zeichen, Zeichen>(lower[q], chars[q]);
                            if (vorhanden >= 0) { sub[vorhanden] = eintrag; } else { sub.Add(eintrag); }
                        }
                        if (sub.Count == 0) { continue; }                 // ohne Ersetzung: schon in Variante 0
                        l33t = Math.Log2(ZxcvbnScoring.L33tVariations(lower.AsSpan(p, length), sub));
                    }
                    var list = wordsAt[p];
                    var k = list.FindIndex(w => w.Length == length);
                    if (k >= 0)
                    {
                        if (l33t < list[k].L33t) { list[k] = new WortStelle { Length = length, L33t = l33t }; }
                    }
                    else
                    {
                        list.Add(new WortStelle { Length = length, L33t = l33t });
                    }
                }
            }
        }
        var perWord = Math.Log2(PassphraseGenerator.WordListCount);
        var emitted = 0;
        var steps = 0;
        for (var start = 0; start < n; start++)
        {
            if (wordsAt[start].Count == 0) { continue; }
            var stack = new List<PassphraseChain>();
            foreach (var w in wordsAt[start])
            {
                stack.Add(new PassphraseChain(start + w.Length, [(start, start + w.Length)], [], w.L33t));
            }
            while (stack.Count > 0)
            {
                var chain = stack[^1];
                stack.RemoveAt(stack.Count - 1);
                steps++;
                if (steps > MaxPassphraseSteps) { return; }
                if (chain.Tokens.Length >= 2)
                {
                    var gaps = new Zeichen[chain.Gaps.Length][];
                    for (var g = 0; g < gaps.Length; g++) { gaps[g] = password[chain.Gaps[g].Start..chain.Gaps[g].End]; }
                    var lg = chain.Tokens.Length * perWord
                        + SeparatorsLog2(gaps)
                        + PassphraseCaseLog2(password, chain.Tokens) + chain.L33tLog2;
                    matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Passphrase, start, chain.End - 1, lg));
                    emitted++;
                    if (emitted >= MaxPassphraseMatches) { return; }
                }
                // nächstes Wort nach einem Trennstück aus 0–3 Zeichen, die keine Buchstaben sind
                for (var gapLength = 0; gapLength <= MaxSeparatorLength; gapLength++)
                {
                    var next = chain.End + gapLength;
                    if (next >= n) { break; }
                    if (gapLength > 0 && password[next - 1].IstBuchstabe) { break; }
                    foreach (var word in wordsAt[next])
                    {
                        stack.Add(new PassphraseChain(next + word.Length,
                            [.. chain.Tokens, (next, next + word.Length)],
                            [.. chain.Gaps, (chain.End, next)],
                            chain.L33tLog2 + word.L33t));
                    }
                }
            }
        }
    }

    /// <summary>Schreibweise einer Wortkette (siehe <see cref="CaseState"/>).</summary>
    private static double PassphraseCaseLog2(Zeichen[] password, (int Start, int End)[] tokens)
    {
        var state = new CaseState();
        foreach (var (s, e) in tokens) { state.Add(password.AsSpan(s, e - s)); }
        return state.Log2Variations;
    }

    /// <summary>Schreibweise einer wachsenden Wortkette: alles klein = 1; jedes Wort klein oder mit grossem Anfang
    /// oder alles GROSS = 2; sonst Varianten je Wort wie zxcvbn.</summary>
    internal sealed class CaseState
    {
        private bool allLower = true;
        private bool allNatural = true;
        private bool allUpper = true;
        private double log2Product;

        internal void Add(ReadOnlySpan<Zeichen> token)
        {
            var upper = 0;
            var lower = 0;
            foreach (var c in token)
            {
                if (c.IstGross) { upper++; } else if (c.IstKlein) { lower++; }
            }
            if (upper > 0) { allLower = false; }
            if (lower > 0) { allUpper = false; }
            var capitalized = upper == 1 && token.Length > 0 && token[0].IstGross;
            if (upper > 0 && !capitalized) { allNatural = false; }
            log2Product += Math.Log2(ZxcvbnScoring.UppercaseVariations(token));
        }

        internal double Log2Variations
        {
            get
            {
                if (allLower) { return 0; }
                if (allNatural || allUpper) { return 1; }
                return log2Product;
            }
        }
    }

    // Trennstücke (gemeinsam für Passphrasen-Ketten und Wortfolgen)

    /// <summary>Häufige Trennzeichen; zusammen mit „keins“ die 16 Varianten.</summary>
    internal static readonly HashSet<Zeichen> CommonSeparators =
        [.. " -_.,;:/+*|~#!?".Select(c => Zeichenvorrat.Fest(c.ToString()))];
    /// <summary>Längstes Trennstück zwischen zwei Wörtern.</summary>
    internal const int MaxSeparatorLength = 3;

    internal static double SeparatorCharLog2(Zeichen c)
    {
        if (CommonSeparators.Contains(c)) { return Math.Log2(CommonSeparators.Count); }
        if (c.Ziffer >= 0) { return ZxcvbnMath.Log2Of10; }
        if (c.IstAscii) { return Math.Log2(33); }                    // übrige druckbare Satz- und Sonderzeichen
        return 7;                                                   // seltene Zeichen (≈ 128 Varianten)
    }

    /// <summary>Zeichen für Zeichen, mit Wahl der Länge (1–3).</summary>
    internal static double FreeSeparatorLog2(ReadOnlySpan<Zeichen> gap)
    {
        var sum = 0.0;
        foreach (var c in gap) { sum += SeparatorCharLog2(c); }
        return sum + (gap.Length > 1 ? Math.Log2(MaxSeparatorLength) : 0);
    }

    /// <summary>„--“, „  “, „, “, „ -“, „ - “: übliche Muster aus zwei bis drei häufigen Trennzeichen.</summary>
    internal static bool IsCommonSeparatorPattern(ReadOnlySpan<Zeichen> a)
    {
        if (a.Length != 2 && a.Length != 3) { return false; }
        foreach (var c in a) { if (!CommonSeparators.Contains(c)) { return false; } }
        var alleGleich = true;
        foreach (var c in a) { if (!ReferenceEquals(c, a[0])) { alleGleich = false; } }
        if (alleGleich) { return true; }
        var leer = Zeichenvorrat.Fest(" ");
        if (a.Length == 2) { return ReferenceEquals(a[0], leer) || ReferenceEquals(a[1], leer); }
        return ReferenceEquals(a[0], leer) && ReferenceEquals(a[2], leer);
    }

    /// <summary>log2 der Varianten für ein überall gleiches Trennstück.</summary>
    internal static double ConstantSeparatorLog2(ReadOnlySpan<Zeichen> gap)
    {
        var basis = Math.Log2(PassphraseSeparatorChoices);
        if (gap.IsEmpty) { return basis; }
        if (gap.Length == 1 && CommonSeparators.Contains(gap[0])) { return basis; }
        if (IsCommonSeparatorPattern(gap)) { return basis + Math.Log2(5); }
        return FreeSeparatorLog2(gap) + 1;
    }

    /// <summary>log2 der Varianten aller Trennstücke einer Kette.</summary>
    internal static double SeparatorsLog2(Zeichen[][] gaps)
    {
        var tracker = new SeparatorTracker();
        foreach (var gap in gaps) { tracker.Add(gap); }
        return tracker.Log2Variants;
    }

    /// <summary>Schrittweise Berechnung von <see cref="SeparatorsLog2"/> für wachsende Ketten.</summary>
    internal sealed class SeparatorTracker
    {
        private readonly List<(Zeichen[] Gap, int Count, double Log2)> distinct = [];
        private int total;
        private double independent;
        /// <summary>Σ count · log2 über alle verschiedenen Trennstücke.</summary>
        private double weighted;

        internal void Add(ReadOnlySpan<Zeichen> gap)
        {
            total++;
            independent += 1 + (gap.IsEmpty ? 0 : FreeSeparatorLog2(gap));
            for (var k = 0; k < distinct.Count; k++)
            {
                if (Gleich(distinct[k].Gap, gap))
                {
                    var d = distinct[k];
                    distinct[k] = (d.Gap, d.Count + 1, d.Log2);
                    weighted += d.Log2;
                    return;
                }
            }
            var cost = ConstantSeparatorLog2(gap);
            distinct.Add((gap.ToArray(), 1, cost));
            weighted += cost;
        }

        internal double Log2Variants
        {
            get
            {
                if (distinct.Count == 0) { return 0; }
                if (distinct.Count == 1) { return distinct[0].Log2; }
                var best = independent;
                foreach (var b in distinct)
                {
                    // Grund-Trennstück einmal, Lage der Abweichungen, jede Abweichung wie ein eigenes Trennstück
                    var cost = b.Log2 + ZxcvbnMath.Log2Binomial(total, total - b.Count) + (weighted - b.Count * b.Log2);
                    best = Math.Min(best, cost);
                }
                return 1 + best;
            }
        }
    }

    internal static bool Gleich(ReadOnlySpan<Zeichen> a, ReadOnlySpan<Zeichen> b)
    {
        if (a.Length != b.Length) { return false; }
        for (var k = 0; k < a.Length; k++) { if (!ReferenceEquals(a[k], b[k])) { return false; } }
        return true;
    }

    // Wortfolgen mit Trennzeichen (Siegel-Erweiterung)

    private void PhraseMatches(Zeichen[] password, Zeichen[] lower, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        var runs = new List<(int Start, int End)>();
        var k = 0;
        while (k < n)
        {
            var c = password[k];
            if (c.IstBuchstabe)
            {
                var start = k;
                while (k < n && password[k].IstBuchstabe) { k++; }
                runs.Add((start, k));
            }
            else if (c.IstZahl)
            {
                var start = k;
                while (k < n && password[k].IstZahl && !password[k].IstBuchstabe) { k++; }
                runs.Add((start, k));
            }
            else
            {
                k++;
            }
        }
        if (runs.Count < 2) { return; }
        var logRanks = new double[runs.Count];
        for (var r = 0; r < runs.Count; r++) { logRanks[r] = TokenLog2Rank(lower, runs[r].Start, runs[r].End); }
        for (var a = 0; a < runs.Count; a++)
        {
            var log2P = logRanks[a];
            var separators = new SeparatorTracker();
            var casing = new CaseState();
            casing.Add(password.AsSpan(runs[a].Start, runs[a].End - runs[a].Start));
            var count = 1;
            for (var b = a + 1; b < runs.Count; b++)
            {
                var gapStart = runs[b - 1].End;
                var gapEnd = runs[b].Start;
                if (gapEnd - gapStart > MaxSeparatorLength) { break; }
                separators.Add(password.AsSpan(gapStart, gapEnd - gapStart));
                casing.Add(password.AsSpan(runs[b].Start, runs[b].End - runs[b].Start));
                log2P += logRanks[b];
                count++;
                var lg = log2P + Log2SmallerProducts(log2P, count) + casing.Log2Variations + separators.Log2Variants;
                matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Phrase, runs[a].Start, runs[b].End - 1, lg));
            }
        }
    }

    /// <summary>log2 von max(1, (ln P)^(k−1)/(k−1)!): Wortfolgen mit kleinerem Rangprodukt.</summary>
    internal static double Log2SmallerProducts(double log2P, int count)
    {
        if (count < 2) { return 0; }
        var lnP = log2P * Math.Log(2);
        if (!(lnP > 1)) { return 0; }
        var value = (count - 1) * Math.Log2(lnP) - ZxcvbnMath.Log2Factorial(count - 1);
        return Math.Max(0, value);
    }

    /// <summary>log2 des Rangs eines Laufs lower[start..&lt;end]: Ziffern als Jahr oder 10^Länge, Wörter mit Rang,
    /// höchstens 10^Länge.</summary>
    private double TokenLog2Rank(Zeichen[] lower, int start, int end)
    {
        var length = end - start;
        var bruteforce = length * ZxcvbnMath.Log2Of10;
        var allDigits = true;
        for (var k = start; k < end; k++) { if (lower[k].Ziffer < 0) { allDigits = false; break; } }
        if (allDigits)
        {
            if (length == 4)
            {
                var d0 = lower[start].Ziffer;
                var d1 = lower[start + 1].Ziffer;
                if ((d0 == 1 && d1 == 9) || (d0 == 2 && d1 == 0))
                {
                    var year = 0;
                    for (var k = start; k < end; k++) { year = year * 10 + lower[k].Ziffer; }
                    return Math.Log2(Math.Max(Math.Abs(year - referenceYear), ZxcvbnScoring.MinYearSpace));
                }
            }
            return bruteforce;
        }
        var kette = new Verkettung(lower.AsSpan(start, length));
        var best = Rang(kette.Wort(0, length));
        if (best < 0) { return bruteforce; }
        return Math.Min(Math.Log2(best), bruteforce);
    }

    // Tastaturfolgen

    private void SpatialMatches(Zeichen[] password, List<ZxcvbnMatch> matches)
    {
        foreach (var graph in graphs) { SpatialMatches(password, graph, matches); }
    }

    private static void SpatialMatches(Zeichen[] password, KeyboardGraph graph, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        var i = 0;
        while (i < n - 1)
        {
            var j = i + 1;
            var lastDirection = -1;
            var turns = 0;
            var shiftedCount = !graph.IsKeypad && graph.Shifted.Contains(password[i]) ? 1 : 0;
            while (true)
            {
                var previous = password[j - 1];
                var found = false;
                if (j < n && graph.Neighbors.TryGetValue(previous, out var adjacents))
                {
                    var current = password[j];
                    for (var direction = 0; direction < adjacents.Length; direction++)
                    {
                        var adjacent = adjacents[direction];
                        if (adjacent is null) { continue; }
                        var position = Array.IndexOf(adjacent, current);
                        if (position < 0) { continue; }
                        found = true;
                        if (position == 1) { shiftedCount++; }
                        if (lastDirection != direction)
                        {
                            turns++;
                            lastDirection = direction;
                        }
                        break;
                    }
                }
                if (found)
                {
                    j++;
                }
                else
                {
                    if (j - i > 2)
                    {
                        var lg = ZxcvbnScoring.SpatialLog2Guesses(j - i, turns, shiftedCount, graph);
                        matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Spatial, i, j - 1, lg));
                    }
                    i = j;
                    break;
                }
            }
        }
    }

    // Wiederholungen

    private void RepeatMatches(Zeichen[] password, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        bool Equal(int a, int b, int length)
        {
            for (var k = 0; k < length; k++)
            {
                if (!ReferenceEquals(password[a + k], password[b + k])) { return false; }
            }
            return true;
        }
        int Repetitions(int start, int length)
        {
            var reps = 2;
            while (start + (reps + 1) * length <= n && Equal(start, start + reps * length, length)) { reps++; }
            return reps;
        }
        var lastIndex = 0;
        while (lastIndex < n)
        {
            // gierig (.+)\1+ und genügsam (.+?)\1+ ab der ersten Stelle, an der es eine Wiederholung gibt
            var foundStart = -1;
            int greedyLength = 0, greedyReps = 0, lazyLength = 0, lazyReps = 0;
            var start = lastIndex;
            while (start < n && foundStart < 0)
            {
                var maxLength = (n - start) / 2;
                if (maxLength >= 1)
                {
                    var greedy = -1;
                    for (var length = maxLength; length >= 1; length--)
                    {
                        if (Equal(start, start + length, length))
                        {
                            greedy = length;
                            break;
                        }
                    }
                    if (greedy > 0)
                    {
                        greedyLength = greedy;
                        greedyReps = Repetitions(start, greedy);
                        lazyLength = greedyLength;
                        lazyReps = greedyReps;
                        for (var length = 1; length <= maxLength; length++)
                        {
                            if (Equal(start, start + length, length))
                            {
                                lazyLength = length;
                                lazyReps = Repetitions(start, length);
                                break;
                            }
                        }
                        foundStart = start;
                    }
                }
                if (foundStart < 0) { start++; }
            }
            if (foundStart < 0) { break; }
            int total;
            int baseLength;
            if (greedyLength * greedyReps > lazyLength * lazyReps)
            {
                total = greedyLength * greedyReps;
                // kürzeste Periode des gierigen Treffers (^(.+?)\1+$)
                var period = greedyLength;
                for (var length = 1; length <= total / 2; length++)
                {
                    if (total % length != 0) { continue; }
                    var periodic = true;
                    for (var k = length; k < total; k++)
                    {
                        if (!ReferenceEquals(password[foundStart + k], password[foundStart + k - length]))
                        {
                            periodic = false;
                            break;
                        }
                    }
                    if (periodic)
                    {
                        period = length;
                        break;
                    }
                }
                baseLength = period;
            }
            else
            {
                total = lazyLength * lazyReps;
                baseLength = lazyLength;
            }
            var i = foundStart;
            var j = i + total - 1;
            var basis = password[i..(i + baseLength)];
            var baseResult = ZxcvbnScoring.MostGuessable(basis.Length, Omnimatch(basis));
            var lg = baseResult.Log2Guesses + Math.Log2(total / baseLength);
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Repeated, i, j, lg));
            lastIndex = j + 1;
        }
    }

    // Folgen (abc, 9876, aceg)

    internal const int MaxSequenceDelta = 5;

    private static void SequenceMatches(Zeichen[] password, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        if (n <= 1) { return; }
        const long noDelta = 1L << 40;
        long Delta(int k)
        {
            var a = password[k].Skalar;
            var b = password[k - 1].Skalar;
            if (a < 0 || b < 0) { return noDelta; }
            return a - b;
        }
        void Update(int i, int j, long delta)
        {
            var magnitude = Math.Abs(delta);
            if (!(j - i > 1 || magnitude == 1)) { return; }
            if (!(magnitude > 0 && magnitude <= MaxSequenceDelta)) { return; }
            var token = password.AsSpan(i, j - i + 1);
            var lg = ZxcvbnScoring.SequenceLog2Guesses(token, delta > 0);
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Sequence, i, j, lg));
        }
        var start = 0;
        var lastDelta = Delta(1);
        for (var k = 1; k < n; k++)
        {
            var d = Delta(k);
            if (d == lastDelta) { continue; }
            var j = k - 1;
            Update(start, j, lastDelta);
            start = j;
            lastDelta = d;
        }
        Update(start, n - 1, lastDelta);
    }

    // Jahre 1900–2099

    private void YearMatches(Zeichen[] password, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        if (n < 4) { return; }
        for (var i = 0; i <= n - 4; i++)
        {
            var a = password[i].Ziffer;
            var b = password[i + 1].Ziffer;
            var c = password[i + 2].Ziffer;
            var d = password[i + 3].Ziffer;
            if (a < 0 || b < 0 || c < 0 || d < 0) { continue; }
            if (!((a == 1 && b == 9) || (a == 2 && b == 0))) { continue; }
            var year = a * 1000 + b * 100 + c * 10 + d;
            var space = Math.Max(Math.Abs(year - referenceYear), ZxcvbnScoring.MinYearSpace);
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Year, i, i + 3, Math.Log2(space)));
        }
    }

    // Daten (1.1.91, 01.01.1991, 010191, 19910101 …)

    internal const int DateMinYear = 1000;
    internal const int DateMaxYear = 2099;

    private static readonly Dictionary<int, (int K, int L)[]> DateSplits = new()
    {
        [4] = [(1, 2), (2, 3)],
        [5] = [(1, 3), (2, 3)],
        [6] = [(1, 2), (2, 4), (4, 5)],
        [7] = [(1, 3), (2, 3), (4, 5), (4, 6)],
        [8] = [(2, 4), (4, 6)],
    };

    private static readonly HashSet<Zeichen> DateSeparators = [.. " /\\_.-".Select(c => Zeichenvorrat.Fest(c.ToString()))];

    private readonly record struct Dmy(int Year, int Month, int Day);

    private void DateMatches(Zeichen[] password, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        var found = new List<(int I, int J, int Year, bool Separator)>();
        var digits = new int[n];
        for (var k = 0; k < n; k++) { digits[k] = password[k].Ziffer; }

        int Number(int from, int to)                     // [from, to)
        {
            var value = 0;
            for (var k = from; k < to; k++) { value = value * 10 + (digits[k] < 0 ? 0 : digits[k]); }
            return value;
        }

        // ohne Trennzeichen: 4 bis 8 Ziffern
        if (n >= 4)
        {
            for (var i = 0; i <= n - 4; i++)
            {
                for (var j = i + 3; j <= i + 7; j++)
                {
                    if (j >= n) { break; }
                    var allDigits = true;
                    for (var k = i; k <= j; k++) { if (digits[k] < 0) { allDigits = false; break; } }
                    if (!allDigits) { break; }
                    var length = j - i + 1;
                    Dmy? best = null;
                    var bestDistance = int.MaxValue;
                    if (DateSplits.TryGetValue(length, out var splits))
                    {
                        foreach (var (k, l) in splits)
                        {
                            var dmy = MapIntsToDmy(Number(i, i + k), Number(i + k, i + l), Number(i + l, j + 1));
                            if (dmy is null) { continue; }
                            var distance = Math.Abs(dmy.Value.Year - referenceYear);
                            if (best is null || distance < bestDistance)
                            {
                                best = dmy;
                                bestDistance = distance;
                            }
                        }
                    }
                    if (best is not null) { found.Add((i, j, best.Value.Year, false)); }
                }
            }
        }

        // mit Trennzeichen: 6 bis 10 Zeichen, d{1,4} s d{1,2} s d{1,4} mit gleichem Trennzeichen
        if (n >= 6)
        {
            for (var i = 0; i <= n - 6; i++)
            {
                for (var j = i + 5; j <= i + 9; j++)
                {
                    if (j >= n) { break; }
                    if (!ParseSeparatedDate(password, digits, i, j, out var a, out var b, out var c)) { continue; }
                    var dmy = MapIntsToDmy(a, b, c);
                    if (dmy is null) { continue; }
                    found.Add((i, j, dmy.Value.Year, true));
                }
            }
        }

        // Treffer entfernen, die echt in einem anderen Datum enthalten sind
        for (var index = 0; index < found.Count; index++)
        {
            var candidate = found[index];
            var isSubmatch = false;
            for (var other = 0; other < found.Count; other++)
            {
                if (other == index) { continue; }
                var outer = found[other];
                if (outer.I <= candidate.I && outer.J >= candidate.J)
                {
                    isSubmatch = true;
                    break;
                }
            }
            if (isSubmatch) { continue; }
            var guesses = (double)Math.Max(Math.Abs(candidate.Year - referenceYear), ZxcvbnScoring.MinYearSpace) * 365;
            if (candidate.Separator) { guesses *= 4; }
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Date, candidate.I, candidate.J, Math.Log2(guesses)));
        }
    }

    private static bool ParseSeparatedDate(Zeichen[] password, int[] digits, int i, int j, out int first, out int second,
        out int third)
    {
        first = second = third = 0;
        // erster Block 1–4 Ziffern
        var k = i;
        while (k <= j && digits[k] >= 0 && k - i < 4)
        {
            first = first * 10 + digits[k];
            k++;
        }
        var firstLength = k - i;
        if (firstLength < 1 || k > j) { return false; }
        var separator = password[k];
        if (!DateSeparators.Contains(separator)) { return false; }
        k++;
        var secondStart = k;
        while (k <= j && digits[k] >= 0 && k - secondStart < 2)
        {
            second = second * 10 + digits[k];
            k++;
        }
        if (k - secondStart < 1 || k > j || !ReferenceEquals(password[k], separator)) { return false; }
        k++;
        var thirdStart = k;
        while (k <= j && digits[k] >= 0 && k - thirdStart < 4)
        {
            third = third * 10 + digits[k];
            k++;
        }
        return k - thirdStart >= 1 && k == j + 1;
    }

    private static Dmy? MapIntsToDmy(int a, int b, int c)
    {
        if (b > 31 || b <= 0) { return null; }
        int over12 = 0, over31 = 0, under1 = 0;
        foreach (var value in (ReadOnlySpan<int>)[a, b, c])
        {
            if ((value > 99 && value < DateMinYear) || value > DateMaxYear) { return null; }
            if (value > 31) { over31++; }
            if (value > 12) { over12++; }
            if (value <= 0) { under1++; }
        }
        if (over31 >= 2 || over12 == 3 || under1 >= 2) { return null; }

        // Jahr hinten (c) oder vorne (a)
        var splits = new (int Year, int R0, int R1)[] { (c, a, b), (a, b, c) };
        foreach (var (year, r0, r1) in splits)
        {
            if (year < DateMinYear || year > DateMaxYear) { continue; }
            var dm = MapIntsToDm(r0, r1);
            if (dm is null) { return null; }
            return new Dmy(year, dm.Value.Month, dm.Value.Day);
        }
        foreach (var (year, r0, r1) in splits)
        {
            var dm = MapIntsToDm(r0, r1);
            if (dm is null) { continue; }
            return new Dmy(TwoToFourDigitYear(year), dm.Value.Month, dm.Value.Day);
        }
        return null;
    }

    private static (int Day, int Month)? MapIntsToDm(int r0, int r1)
    {
        foreach (var (d, m) in new[] { (r0, r1), (r1, r0) })
        {
            if (d is >= 1 and <= 31 && m is >= 1 and <= 12) { return (d, m); }
        }
        return null;
    }

    private static int TwoToFourDigitYear(int year)
    {
        if (year > 99) { return year; }
        if (year > 50) { return year + 1900; }
        return year + 2000;
    }
}
