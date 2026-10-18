using System.Text;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Staerke.Zxcvbn;

// Siegel-Erweiterungen (Befund #18) wie Sources/SiegelCore/Staerke/Zxcvbn/ZxcvbnVorlagen.swift: Zähler-Vorlagen
// („Hund1Hund2Hund3“), Kalenderfolgen („Mo-Di-Mi-Do“) und Ort + Postleitzahl („Thun3600“). Sie können Schätzungen nur
// senken, denn die Zerlegung nimmt immer das Minimum.

internal sealed partial class ZxcvbnMatcher
{
    // Zähler-Vorlage (Grundwort mit hochzählender Zahl)

    /// <summary>Erlaubte Schrittweiten (Betrag) einer Zähler-Vorlage; beide Richtungen.</summary>
    internal static readonly int[] CounterSteps = [1, 2, 5, 10];
    private const int MaxCounterMatches = 64;

    private readonly record struct CounterToken(Zeichen? Char, int? Value, int Width, int Lower, int Upper);

    internal void CounterMatches(Zeichen[] password, List<ZxcvbnMatch> matches)
    {
        var tokens = new List<CounterToken>();
        var placeholders = new List<int>();
        var k = 0;
        var n = password.Length;
        while (k < n)
        {
            if (password[k].Ziffer >= 0)
            {
                var start = k;
                var value = 0;
                while (k < n && password[k].Ziffer >= 0)
                {
                    if (k - start < 9) { value = value * 10 + password[k].Ziffer; }
                    k++;
                }
                placeholders.Add(tokens.Count);
                tokens.Add(new CounterToken(null, k - start <= 9 ? value : null, k - start, start, k));
            }
            else
            {
                tokens.Add(new CounterToken(password[k], null, 0, k, k + 1));
                k++;
            }
        }
        if (placeholders.Count < 2) { return; }

        bool Same(int a, int b) => ReferenceEquals(tokens[a].Char, tokens[b].Char);
        var baseCache = new Dictionary<string, double>(StringComparer.Ordinal);
        var emitted = 0;
        var next = 0;                                       // Index in placeholders: erster Platzhalter ≥ s
        for (var s = 0; s < tokens.Count; s++)
        {
            while (next < placeholders.Count && placeholders[next] < s) { next++; }
            if (next + 1 >= placeholders.Count) { break; }
            // Genau ein Platzhalter je Vorlage: Periode = Abstand zum nächsten Platzhalter.
            var p = placeholders[next];
            var period = placeholders[next + 1] - p;
            if (period < 2 || s < p - period + 1) { continue; }

            var reps = 1;
            var weiter = true;
            while (weiter && s + (reps + 1) * period <= tokens.Count)
            {
                for (var t = 0; t < period; t++)
                {
                    if (!Same(s + t, s + reps * period + t))
                    {
                        weiter = false;
                        break;
                    }
                }
                if (weiter) { reps++; }
            }
            if (reps < 2) { continue; }

            var offset = p - s;
            var values = new List<int>();
            for (var r = 0; r < reps; r++)
            {
                var v = tokens[s + r * period + offset].Value;
                if (v is null) { break; }
                values.Add(v.Value);
            }
            if (values.Count < 2) { continue; }
            var step = values[1] - values[0];
            if (!CounterSteps.Contains(Math.Abs(step))) { continue; }
            var count = 2;
            while (count < values.Count && values[count] - values[count - 1] == step) { count++; }
            reps = count;

            // Abgebrochene letzte Wiederholung (Anfang der Vorlage, Zahl nur, wenn sie die Folge fortsetzt)
            var tailStart = s + reps * period;
            var tail = 0;
            while (tail < period - 1 && tailStart + tail < tokens.Count && Same(s + tail, tailStart + tail))
            {
                if (tail == offset)
                {
                    var v = tokens[tailStart + tail].Value;
                    if (v is null || v.Value - values[reps - 1] != step) { break; }
                }
                tail++;
            }

            var basis = new List<Zeichen>();
            for (var t = 0; t < period; t++)
            {
                if (tokens[s + t].Char is { } c) { basis.Add(c); }
            }
            var key = string.Concat(basis.Select(z => z.Text));
            if (!baseCache.TryGetValue(key, out var baseLog2))
            {
                var b = basis.ToArray();
                baseLog2 = ZxcvbnScoring.MostGuessable(b.Length, Omnimatch(b)).Log2Guesses;
                baseCache[key] = baseLog2;
            }
            double repetitions = reps + (tail > 0 ? 1 : 0);
            var lg = baseLog2 + tokens[p].Width * ZxcvbnMath.Log2Of10 + Math.Log2(2 * CounterSteps.Length)
                + Math.Log2(period) + Math.Log2(repetitions);
            var last = tokens[tailStart + tail - 1];
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Counter, tokens[s].Lower, last.Upper - 1, lg));
            emitted++;
            if (emitted >= MaxCounterMatches) { return; }
        }
    }

    // Kalenderfolgen (Wochentage, Monate)

    /// <summary>Feste Reihen (klein): Wochentage und Monate in Kurz- und Langform, DE/EN/FR/IT. Je Stelle mehrere
    /// Schreibweisen; die erste ist die Hauptform (andere kosten 1 Bit).</summary>
    internal static readonly string[][][] CalendarSeries =
    [
        // Wochentage
        [["mo"], ["di"], ["mi"], ["do"], ["fr"], ["sa"], ["so"]],
        [["montag"], ["dienstag"], ["mittwoch"], ["donnerstag"], ["freitag"], ["samstag", "sonnabend"], ["sonntag"]],
        [["mo"], ["tu"], ["we"], ["th"], ["fr"], ["sa"], ["su"]],
        [["mon"], ["tue", "tues"], ["wed"], ["thu", "thur", "thurs"], ["fri"], ["sat"], ["sun"]],
        [["monday"], ["tuesday"], ["wednesday"], ["thursday"], ["friday"], ["saturday"], ["sunday"]],
        [["lu"], ["ma"], ["me"], ["je"], ["ve"], ["sa"], ["di"]],
        [["lun"], ["mar"], ["mer"], ["jeu"], ["ven"], ["sam"], ["dim"]],
        [["lundi"], ["mardi"], ["mercredi"], ["jeudi"], ["vendredi"], ["samedi"], ["dimanche"]],
        [["lu"], ["ma"], ["me"], ["gi"], ["ve"], ["sa"], ["do"]],
        [["lun"], ["mar"], ["mer"], ["gio"], ["ven"], ["sab"], ["dom"]],
        [["lunedì", "lunedi"], ["martedì", "martedi"], ["mercoledì", "mercoledi"], ["giovedì", "giovedi"],
         ["venerdì", "venerdi"], ["sabato"], ["domenica"]],
        // Monate
        [["jan"], ["feb"], ["mär", "mar", "maer", "mrz"], ["apr"], ["mai"], ["jun"], ["jul"], ["aug"],
         ["sep", "sept"], ["okt"], ["nov"], ["dez"]],
        [["januar", "jänner", "jaenner"], ["februar", "feber"], ["märz", "maerz", "marz"], ["april"], ["mai"],
         ["juni"], ["juli"], ["august"], ["september"], ["oktober"], ["november"], ["dezember"]],
        [["jan"], ["feb"], ["mar"], ["apr"], ["may"], ["jun"], ["jul"], ["aug"], ["sep", "sept"], ["oct"],
         ["nov"], ["dec"]],
        [["january"], ["february"], ["march"], ["april"], ["may"], ["june"], ["july"], ["august"],
         ["september"], ["october"], ["november"], ["december"]],
        [["janv", "jan"], ["févr", "fevr", "fév", "fev"], ["mars"], ["avr"], ["mai"], ["juin"], ["juil"],
         ["août", "aout"], ["sept", "sep"], ["oct"], ["nov"], ["déc", "dec"]],
        [["janvier"], ["février", "fevrier"], ["mars"], ["avril"], ["mai"], ["juin"], ["juillet"],
         ["août", "aout"], ["septembre"], ["octobre"], ["novembre"], ["décembre", "decembre"]],
        [["gen"], ["feb"], ["mar"], ["apr"], ["mag"], ["giu"], ["lug"], ["ago"], ["set"], ["ott"], ["nov"],
         ["dic"]],
        [["gennaio"], ["febbraio"], ["marzo"], ["aprile"], ["maggio"], ["giugno"], ["luglio"], ["agosto"],
         ["settembre"], ["ottobre"], ["novembre"], ["dicembre"]],
    ];

    private sealed record Spelling(Zeichen[] Chars, bool Primary);

    private sealed record CalendarStart(int Series, int Item, Zeichen[] Spelling, bool Primary);

    private static Zeichen[] FesteZeichen(string text)
    {
        var grenzen = Graphemzerlegung.Grenzen(text);
        var result = new Zeichen[grenzen.Length - 1];
        for (var i = 0; i < result.Length; i++) { result[i] = Zeichenvorrat.Fest(text[grenzen[i]..grenzen[i + 1]]); }
        return result;
    }

    /// <summary>Schreibweisen je Reihe und Stelle, längste zuerst (stabil, damit „sept“ vor „sep“ geprüft wird).</summary>
    private static readonly Spelling[][][] CalendarSpellings =
        [.. CalendarSeries.Select(series => series.Select(spellings => spellings
            .Select((s, offset) => new Spelling(FesteZeichen(s), offset == 0))
            .OrderByDescending(s => s.Chars.Length)
            .ToArray()).ToArray())];

    /// <summary>Erste Buchstaben → mögliche Anfänge (Reihe, Stelle, Schreibweise).</summary>
    private static readonly Dictionary<Zeichen, List<CalendarStart>> CalendarIndex = CalendarIndexAnlegen();

    private static Dictionary<Zeichen, List<CalendarStart>> CalendarIndexAnlegen()
    {
        var index = new Dictionary<Zeichen, List<CalendarStart>>();
        for (var s = 0; s < CalendarSpellings.Length; s++)
        {
            for (var item = 0; item < CalendarSpellings[s].Length; item++)
            {
                foreach (var spelling in CalendarSpellings[s][item])
                {
                    if (spelling.Chars.Length == 0) { continue; }
                    var first = spelling.Chars[0];
                    if (!index.TryGetValue(first, out var list))
                    {
                        list = [];
                        index[first] = list;
                    }
                    list.Add(new CalendarStart(s, item, spelling.Chars, spelling.Primary));
                }
            }
        }
        return index;
    }

    internal static void CalendarMatches(Zeichen[] password, Zeichen[] lower, List<ZxcvbnMatch> matches)
    {
        var n = lower.Length;
        if (n < 4) { return; }
        bool MatchesAt(int position, Zeichen[] spelling)
        {
            if (position + spelling.Length > n) { return false; }
            for (var offset = 0; offset < spelling.Length; offset++)
            {
                if (!ReferenceEquals(lower[position + offset], spelling[offset])) { return false; }
            }
            return true;
        }
        var seriesLog2 = Math.Log2(CalendarSeries.Length);
        for (var i = 0; i < n; i++)
        {
            if (!CalendarIndex.TryGetValue(lower[i], out var starts)) { continue; }
            foreach (var start in starts)
            {
                if (!MatchesAt(i, start.Spelling)) { continue; }
                var series = CalendarSpellings[start.Series];
                var length = series.Length;
                foreach (var direction in (ReadOnlySpan<int>)[1, -1])
                {
                    var item = start.Item;
                    var end = i + start.Spelling.Length;
                    var count = 1;
                    var variant = !start.Primary;
                    Zeichen[]? separator = null;
                    var casing = new CaseState();
                    casing.Add(password.AsSpan(i, end - i));
                    while (count < length)
                    {
                        var nextItem = (item + direction + length) % length;
                        var foundGap = -1;
                        var foundChars = 0;
                        var foundPrimary = false;
                        for (var gap = 0; gap <= MaxSeparatorLength && foundGap < 0; gap++)
                        {
                            var position = end + gap;
                            if (position >= n) { break; }
                            if (gap > 0 && password[position - 1].IstBuchstabe) { break; }
                            if (separator is not null && !Gleich(password.AsSpan(end, position - end), separator)) { continue; }
                            foreach (var spelling in series[nextItem])
                            {
                                if (MatchesAt(position, spelling.Chars))
                                {
                                    foundGap = gap;
                                    foundChars = spelling.Chars.Length;
                                    foundPrimary = spelling.Primary;
                                    break;
                                }
                            }
                        }
                        if (foundGap < 0) { break; }
                        separator ??= password[end..(end + foundGap)];
                        var itemStart = end + foundGap;
                        end = itemStart + foundChars;
                        casing.Add(password.AsSpan(itemStart, end - itemStart));
                        variant = variant || !foundPrimary;
                        item = nextItem;
                        count++;
                        var lg = seriesLog2 + Math.Log2(length) + 1
                            + ConstantSeparatorLog2(separator)
                            + casing.Log2Variations + Math.Log2(count) + (variant ? 1 : 0);
                        matches.Add(new ZxcvbnMatch(ZxcvbnPattern.Calendar, i, end - 1, lg));
                    }
                }
            }
        }
    }

    // Ort + Postleitzahl

    /// <summary>Ränge der eigenen Orts- und Vereinsliste (placesCH), Wort → Rang.</summary>
    internal static readonly Dictionary<string, int> PlaceRanks = PlaceRanksAnlegen();
    private static readonly Dictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> PlaceLookup =
        PlaceRanks.GetAlternateLookup<ReadOnlySpan<char>>();

    private static Dictionary<string, int> PlaceRanksAnlegen()
    {
        var ranks = new Dictionary<string, int>(StringComparer.Ordinal);
        ZxcvbnListData.ForEachLine(ZxcvbnListData.Lesen("placesCH"), (index, fields) =>
        {
            foreach (var f in fields) { ranks.TryAdd(f.Word, index + 1); }
        });
        return ranks;
    }

    /// <summary>Längster Ort in Zeichen (Graphem-Cluster).</summary>
    internal static readonly int PlaceMaxLength = PlaceRanks.Keys.Aggregate(0, (m, k) => Math.Max(m, SwiftText.Zeichenzahl(k)));
    /// <summary>Schweizer Postleitzahlen (mit Liechtenstein): 1000–9699.</summary>
    internal const int PostalMin = 1000;
    internal const int PostalMax = 9699;
    /// <summary>Trennzeichen zwischen Ort und Postleitzahl.</summary>
    internal static readonly HashSet<Zeichen> PlaceSeparators = [.. " -_./,".Select(c => Zeichenvorrat.Fest(c.ToString()))];

    /// <summary>Ein Ort + Postleitzahl als Einheit.</summary>
    private sealed record PlaceUnit(int I, int J, double Core, bool PlaceFirst, Zeichen? Inner)
    {
        /// <summary>Form: Reihenfolge (1 Bit) + mit/ohne Trennzeichen (1 Bit) + welches Trennzeichen.</summary>
        internal double FormatLog2 => 2 + (Inner is null ? 0 : Math.Log2(PlaceSeparators.Count));
    }

    private sealed record PlaceChain(PlaceUnit First, double Sum, int End, Zeichen[]? Separator, int Count);

    private const int MaxPlaceChainSteps = 2000;

    internal void PlaceCodeMatches(Zeichen[] password, Zeichen[] lower, List<ZxcvbnMatch> matches)
    {
        var n = password.Length;
        var units = new List<PlaceUnit>();
        var k = 0;
        while (k < n)
        {
            if (password[k].Ziffer < 0)
            {
                k++;
                continue;
            }
            var start = k;
            var value = 0;
            while (k < n && password[k].Ziffer >= 0)
            {
                if (k - start < 4) { value = value * 10 + password[k].Ziffer; }
                k++;
            }
            if (k - start != 4 || value < PostalMin || value > PostalMax) { continue; }
            var codeLog2 = value % 100 == 0 ? Math.Log2(87.0) : Math.Log2(8700.0);

            for (var gap = 0; gap <= 1; gap++)
            {
                // Ort davor: "Thun3600", "Thun 3600"
                Zeichen? inner = null;
                if (gap == 1)
                {
                    if (start < 1 || !PlaceSeparators.Contains(password[start - 1])) { continue; }
                    inner = password[start - 1];
                }
                var wordEnd = start - gap;
                if (wordEnd <= 0) { continue; }
                for (var wordStart = wordEnd - 1; wordStart >= Math.Max(0, wordEnd - PlaceMaxLength); wordStart--)
                {
                    var rank = PlaceRank(lower, wordStart, wordEnd);
                    if (rank < 0) { continue; }
                    var core = Math.Log2(rank)
                        + Math.Log2(ZxcvbnScoring.UppercaseVariations(password.AsSpan(wordStart, wordEnd - wordStart)))
                        + codeLog2;
                    units.Add(new PlaceUnit(wordStart, k - 1, core, true, inner));
                }
            }
            for (var gap = 0; gap <= 1; gap++)
            {
                // Ort danach: "3600Thun", "3600 Thun"
                Zeichen? inner = null;
                if (gap == 1)
                {
                    if (k >= n || !PlaceSeparators.Contains(password[k])) { continue; }
                    inner = password[k];
                }
                var wordStart = k + gap;
                if (wordStart >= n) { continue; }
                for (var wordEnd = wordStart + 1; wordEnd <= Math.Min(n, wordStart + PlaceMaxLength); wordEnd++)
                {
                    var rank = PlaceRank(lower, wordStart, wordEnd);
                    if (rank < 0) { continue; }
                    var core = Math.Log2(rank)
                        + Math.Log2(ZxcvbnScoring.UppercaseVariations(password.AsSpan(wordStart, wordEnd - wordStart)))
                        + codeLog2;
                    units.Add(new PlaceUnit(start, wordEnd - 1, core, false, inner));
                }
            }
        }
        if (units.Count == 0) { return; }
        foreach (var unit in units)
        {
            matches.Add(new ZxcvbnMatch(ZxcvbnPattern.PlaceCode, unit.I, unit.J, unit.Core + unit.FormatLog2));
        }

        // Ketten gleicher Form: Tiefensuche über alle passenden Einheiten (begrenzt)
        var stack = units.Select(u => new PlaceChain(u, u.Core, u.J + 1, null, 1)).ToList();
        var steps = 0;
        while (stack.Count > 0)
        {
            var chain = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            steps++;
            if (steps > MaxPlaceChainSteps) { return; }
            for (var gap = 0; gap <= MaxSeparatorLength; gap++)
            {
                var position = chain.End + gap;
                if (position >= n) { break; }
                if (gap > 0)
                {
                    var c = password[position - 1];
                    if (c.IstBuchstabe || c.Ziffer >= 0) { break; }
                }
                if (chain.Separator is not null && !Gleich(password.AsSpan(chain.End, position - chain.End), chain.Separator))
                {
                    continue;
                }
                foreach (var unit in units)
                {
                    if (unit.I != position || unit.PlaceFirst != chain.First.PlaceFirst
                        || !ReferenceEquals(unit.Inner, chain.First.Inner))
                    {
                        continue;
                    }
                    var separator = chain.Separator ?? password[chain.End..position];
                    var next = new PlaceChain(chain.First, chain.Sum + unit.Core, unit.J + 1, separator, chain.Count + 1);
                    var lg = next.Sum + chain.First.FormatLog2 + ConstantSeparatorLog2(separator) + Math.Log2(next.Count);
                    matches.Add(new ZxcvbnMatch(ZxcvbnPattern.PlaceCode, chain.First.I, unit.J, lg));
                    stack.Add(next);
                }
            }
        }
    }

    /// <summary>Rang eines Orts lower[start..&lt;end] (kleinster aus Ortsliste und Gesamtwörterbuch), −1 wenn kein Ort.</summary>
    private int PlaceRank(Zeichen[] lower, int start, int end)
    {
        var sb = new StringBuilder();
        for (var q = start; q < end; q++) { sb.Append(lower[q].Text); }
        var word = sb.ToString();
        if (!PlaceLookup.TryGetValue(word, out var place)) { return -1; }
        return dictionary.Ranks.TryGetValue(word, out var r) ? Math.Min(place, r) : place;
    }
}
