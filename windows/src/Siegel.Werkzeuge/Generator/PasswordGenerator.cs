using System.Text;

namespace Siegel.Werkzeuge;

/// <summary>Optionen des Zufallspasswort-Generators (wie <c>PasswordGenerator.Options</c> auf dem Mac).</summary>
public sealed record PasswordGeneratorOptions(int Length = 24, bool Uppercase = true, bool Lowercase = true,
    bool Digits = true, bool Symbols = true, bool AvoidAmbiguous = false);

/// <summary>
/// Zufallspasswörter (SPEC §7.5, §8), gleich wie Sources/SiegelCore/Werkzeuge/PasswordGenerator.swift.
/// Gleichverteilt über alle Zeichenketten der Länge L aus den gewählten Klassen, die aus jeder Klasse mindestens ein
/// Zeichen enthalten und nicht mit <c>= + - @</c> beginnen: erstes Zeichen aus dem Vorrat ohne diese, die übrigen aus
/// dem ganzen Vorrat (<c>randombytes_uniform</c>); fehlt eine Klasse, wird die ganze Zeichenkette neu gezogen.
/// Klassen: Gross A–Z, Klein a–z, Ziffern 0–9, Symbole (32 druckbare ASCII-Sonderzeichen ohne Leerzeichen).
/// „Ähnliche Zeichen vermeiden“ entfernt <c>0 O o 1 l I | ! ` ' " , . ; :</c>. Keine Klasse → Kleinbuchstaben.
/// Länge auf 8…64 geklemmt.
/// </summary>
public static class PasswordGenerator
{
    internal const int MinimumLength = 8;
    internal const int MaximumLength = 64;

    internal static readonly byte[] UppercaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"u8.ToArray();
    internal static readonly byte[] LowercaseCharacters = "abcdefghijklmnopqrstuvwxyz"u8.ToArray();
    internal static readonly byte[] DigitCharacters = "0123456789"u8.ToArray();
    /// <summary>Druckbare ASCII-Sonderzeichen 0x21–0x7E ohne Buchstaben und Ziffern (32 Zeichen).</summary>
    internal static readonly byte[] SymbolCharacters = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"u8.ToArray();
    internal static readonly byte[] AmbiguousCharacters = "0Oo1lI|!`'\",.;:"u8.ToArray();
    /// <summary>Nie als erstes Zeichen (Formel-Präfixe in Tabellenprogrammen).</summary>
    internal static readonly byte[] ForbiddenFirstCharacters = "=+-@"u8.ToArray();

    /// <summary>Die verwendeten, nicht leeren Klassen in fester Reihenfolge (Gross, Klein, Ziffern, Symbole).</summary>
    internal static List<byte[]> CharacterClasses(PasswordGeneratorOptions options)
    {
        var chosen = new List<byte[]>();
        if (options.Uppercase) { chosen.Add(UppercaseCharacters); }
        if (options.Lowercase) { chosen.Add(LowercaseCharacters); }
        if (options.Digits) { chosen.Add(DigitCharacters); }
        if (options.Symbols) { chosen.Add(SymbolCharacters); }
        if (chosen.Count == 0) { chosen.Add(LowercaseCharacters); }
        if (options.AvoidAmbiguous)
        {
            chosen = [.. chosen.Select(cls => cls.Where(b => !AmbiguousCharacters.Contains(b)).ToArray())];
        }
        return [.. chosen.Where(c => c.Length > 0)];
    }

    internal static int ClampedLength(int length) => Math.Min(Math.Max(length, MinimumLength), MaximumLength);

    public static string Generate(PasswordGeneratorOptions options)
    {
        options ??= new PasswordGeneratorOptions();
        return Generate(CharacterClasses(options), ClampedLength(options.Length));
    }

    /// <summary>Kern ohne Klemmen (Tests ziehen auch kurze Längen). Klassen disjunkt, nicht leer, ASCII.
    /// Ist keine gültige Zeichenkette möglich, kommt "" zurück.</summary>
    internal static string Generate(IReadOnlyList<byte[]> classes, int length)
    {
        Sodium.EnsureReady();
        var pool = classes.SelectMany(c => c).ToArray();
        var firstPool = pool.Where(b => !ForbiddenFirstCharacters.Contains(b)).ToArray();
        if (length <= 0 || pool.Length == 0 || firstPool.Length == 0 || classes.Count > length || classes.Count >= 31
            || pool.Any(b => b >= 128) || !(AcceptanceProbability(classes, length) > 1e-6))
        {
            return "";
        }

        // Byte → Bitmaske der Klassen, zu denen es gehört
        var classMask = new int[128];
        for (var index = 0; index < classes.Count; index++)
        {
            foreach (var b in classes[index]) { classMask[b] |= 1 << index; }
        }
        var fullMask = (1 << classes.Count) - 1;

        var buffer = new byte[length];
        try
        {
            while (true)
            {
                var seen = 0;
                for (var position = 0; position < length; position++)
                {
                    var source = position == 0 ? firstPool : pool;
                    var b = source[(int)Sodium.randombytes_uniform((uint)source.Length)];
                    buffer[position] = b;
                    seen |= classMask[b];
                }
                if (seen == fullMask) { break; }            // sonst ganz verwerfen und neu ziehen
            }
            return Encoding.ASCII.GetString(buffer);
        }
        finally
        {
            Sodium.Wipe(buffer);
        }
    }

    /// <summary>Exakte Zufalls-Entropie log2(|S|) der tatsächlichen Verteilung (Inklusion–Exklusion).</summary>
    public static double EntropyBits(PasswordGeneratorOptions options)
    {
        options ??= new PasswordGeneratorOptions();
        return ExactEntropyBits(CharacterClasses(options), ClampedLength(options.Length));
    }

    internal static double ExactEntropyBits(IReadOnlyList<byte[]> classes, int length)
    {
        var acceptance = AcceptanceProbability(classes, length);
        if (!(acceptance > 0)) { return 0; }
        double a0 = classes.Sum(FirstAllowedCount);
        double b0 = classes.Sum(c => c.Length);
        return Math.Log2(a0) + (length - 1) * Math.Log2(b0) + Math.Log2(acceptance);
    }

    private static int FirstAllowedCount(byte[] cls) => cls.Count(b => !ForbiddenFirstCharacters.Contains(b));

    /// <summary>Wahrscheinlichkeit, dass ein Zug alle Klassen enthält (= |S| / (a∅ · b∅^(L−1))). 0 = unmöglich.</summary>
    internal static double AcceptanceProbability(IReadOnlyList<byte[]> classes, int length)
    {
        if (length <= 0 || classes.Count == 0 || classes.Count > length || classes.Count >= 31) { return 0; }
        var sizes = classes.Select(c => (double)c.Length).ToArray();
        var firstSizes = classes.Select(c => (double)FirstAllowedCount(c)).ToArray();
        var b0 = sizes.Sum();
        var a0 = firstSizes.Sum();
        if (!(a0 > 0) || !(b0 > 0)) { return 0; }

        var k = classes.Count;
        var correction = 0.0;
        for (var mask = 1; mask < (1 << k); mask++)
        {
            double aT = a0, bT = b0;
            var excluded = 0;
            for (var c = 0; c < k; c++)
            {
                if ((mask & (1 << c)) == 0) { continue; }
                aT -= firstSizes[c];
                bT -= sizes[c];
                excluded++;
            }
            if (!(aT > 0) || !(bT > 0)) { continue; }      // Term ist 0
            var term = aT / a0 * Math.Pow(bT / b0, length - 1);
            correction += excluded % 2 == 1 ? -term : term;
        }
        return Math.Max(0, Math.Min(1, 1 + correction));
    }
}
