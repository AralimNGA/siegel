using Siegel.Werkzeuge.Staerke.Zxcvbn;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge;

/// <summary>Stärke-Stufen in Bit geschätzter Rateversuche (wie <c>PasswordStrength.Level</c> auf dem Mac).</summary>
public enum StrengthLevel { VeryWeak = 0, Weak = 1, Fair = 2, Strong = 3, VeryStrong = 4 }

/// <summary>
/// Schätzt die Stärke eines Passworts wie zxcvbn (SPEC §1.6), bit-gleich zur Swift-Fassung
/// (Sources/SiegelCore/Staerke/PasswordStrength.swift): kleinste Zahl Rateversuche über eine Zerlegung in erkannte
/// Muster, <c>bits = log2(guesses)</c>.
/// Stufen: VeryWeak &lt; 28, Weak &lt; 36, Fair &lt; 60 (Untergrenze des Master-Passworts), Strong &lt; 80, VeryStrong ≥ 80.
/// Analysiert werden höchstens die ersten 256 Zeichen (Graphem-Cluster); bei Kürzung deckelt die längste periodische
/// Anfangsfolge der ganzen Eingabe die Schätzung (Befund #49).
/// </summary>
public static class PasswordStrength
{
    internal const double WeakBits = 28;
    internal const double FairBits = 36;
    internal const double StrongBits = 60;
    internal const double VeryStrongBits = 80;

    /// <summary>Längere Eingaben werden nur bis hierhin analysiert (Laufzeit wächst etwa quadratisch).</summary>
    internal const int MaximumAnalyzedLength = 256;

    /// <summary>Bezugsjahr für Jahres- und Datumsmuster (zxcvbn REFERENCE_YEAR), wie Swift einmal bestimmt.</summary>
    internal static readonly int CurrentYear = DateTime.Now.Year;

    public static (double Bits, StrengthLevel Level) Estimate(string password, IReadOnlyList<string>? userInputs = null)
    {
        var bits = Analyze(password, userInputs).Bits;
        return (bits, LevelForBits(bits));
    }

    internal static StrengthLevel LevelForBits(double bits)
    {
        if (bits < WeakBits) { return StrengthLevel.VeryWeak; }
        if (bits < FairBits) { return StrengthLevel.Weak; }
        if (bits < StrongBits) { return StrengthLevel.Fair; }
        if (bits < VeryStrongBits) { return StrengthLevel.Strong; }
        return StrengthLevel.VeryStrong;
    }

    /// <summary>Ergebnis mit Zerlegung (für Tests; enthält das Passwort, nie protokollieren).</summary>
    internal sealed class Analysis(double bits, IReadOnlyList<ZxcvbnMatch> sequence, Zeichen[] characters)
    {
        internal double Bits { get; } = bits;
        internal IReadOnlyList<ZxcvbnMatch> Sequence { get; } = sequence;
        internal Zeichen[] Characters { get; } = characters;

        /// <summary>Lesbare Zerlegung, z. B. „dictionary(Sommer) year(2026)“ (nur Tests).</summary>
        internal string PatternSummary => string.Join(" ", Sequence.Select(m =>
            $"{m.Pattern.ToString().ToLowerInvariant()}({string.Concat(Characters[m.I..(m.J + 1)].Select(z => z.Text))})"));

        public override string ToString() => "Analysis(redacted)";
    }

    internal static Analysis Analyze(string password, IReadOnlyList<string>? userInputs = null, int? referenceYear = null)
    {
        var year = referenceYear ?? CurrentYear;
        var inputs = userInputs ?? [];
        var normalized = MasterPasswordPolicy.Normalized(password);
        var vorrat = new Zeichenvorrat();
        var full = vorrat.Zerlegen(normalized);
        var characters = full.Length > MaximumAnalyzedLength ? full[..MaximumAnalyzedLength] : full;
        if (characters.Length == 0) { return new Analysis(0, [], []); }
        var normalizedInputs = inputs.Select(MasterPasswordPolicy.Normalized).ToList();
        var matcher = new ZxcvbnMatcher(ZxcvbnDictionary.Shared, normalizedInputs, year, KeyboardGraphs.All, vorrat);
        var result = ZxcvbnScoring.MostGuessable(characters.Length, matcher.Omnimatch(characters));
        var bits = Math.Max(result.Log2Guesses, 0);
        if (full.Length > MaximumAnalyzedLength)
        {
            var cap = PeriodicCap(full, inputs, year);
            if (cap is { } c && c < bits) { bits = c; }
        }
        return new Analysis(bits, result.Sequence, characters);
    }

    internal readonly record struct PeriodicPrefix(int Length, int Period);

    /// <summary>Längste Anfangsfolge mit Periode p und mindestens zwei vollen Wiederholungen (2p ≤ Länge), KMP O(n).</summary>
    internal static PeriodicPrefix? LongestPeriodicPrefix(Zeichen[] chars)
    {
        var n = chars.Length;
        if (n < 2) { return null; }
        var prefix = new int[n];
        for (var i = 1; i < n; i++)
        {
            var k = prefix[i - 1];
            while (k > 0 && !ReferenceEquals(chars[i], chars[k])) { k = prefix[k - 1]; }
            if (ReferenceEquals(chars[i], chars[k])) { k++; }
            prefix[i] = k;
        }
        for (var length = n; length >= 2; length--)
        {
            var period = length - prefix[length - 1];
            if (2 * period <= length) { return new PeriodicPrefix(length, period); }
        }
        return null;
    }

    /// <summary>Deckel für gekürzte Eingaben (Befund #49): Periode + log2(Länge/Periode), ein Rest zählt wie ein
    /// zweites Teilstück (2! · g1 · g2 + 10000, wie zxcvbn).</summary>
    internal static double? PeriodicCap(Zeichen[] full, IReadOnlyList<string> userInputs, int referenceYear)
    {
        if (LongestPeriodicPrefix(full) is not { } periodic || periodic.Length <= MaximumAnalyzedLength) { return null; }
        var basis = Analyze(Text(full, 0, periodic.Period), userInputs, referenceYear).Bits;
        var bits = basis + Math.Log2((double)periodic.Length / periodic.Period);
        if (periodic.Length < full.Length)
        {
            var rest = Analyze(Text(full, periodic.Length, full.Length), userInputs, referenceYear).Bits;
            bits = ZxcvbnMath.LogAdd(1 + bits + rest, Math.Log2(ZxcvbnScoring.MinGuessesBeforeGrowingSequence));
        }
        return bits;
    }

    private static string Text(Zeichen[] chars, int start, int end) =>
        string.Concat(chars[start..end].Select(z => z.Text));
}
