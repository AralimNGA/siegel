using System.Text;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge;

/// <summary>
/// Regel für das Master-Passwort (SPEC §1.6, im Kern erzwungen): geschätzte Stärke ≥ 60 Bit, mindestens 12 Zeichen,
/// höchstens 1024 UTF-8-Bytes, nur Zeichen aus Unicode 15.0 (v4.7, Befund krypto-2), geprüft nach der Abbildung aus
/// §1.1 (Zs → U+0020, dann NFC). Benutzereingaben wie auf dem Mac: "siegel", der Benutzername (unter Windows
/// <see cref="Environment.UserName"/>) und dessen Teile.
/// </summary>
public static class MasterPasswordPolicy
{
    public const double MinimumBits = 60;
    public const int MinimumLength = 12;
    public const int MaximumUtf8Bytes = 1024;

    /// <summary>Benutzereingaben wie Mac: "siegel" + Benutzername (unter Windows: Environment.UserName) und Teile.
    /// <paramref name="userInputs"/> ersetzt sie (Tests).</summary>
    public static (double Bits, bool Ok) Check(string password, IReadOnlyList<string>? userInputs = null)
    {
        var normalized = Normalized(password);
        var bits = PasswordStrength.Estimate(normalized, userInputs ?? DefaultUserInputs()).Bits;
        return (bits, Satisfied(normalized, bits));
    }

    /// <summary>Die Regel auf ein schon abgebildetes Passwort mit seiner Schätzung (Swift <c>satisfied(normalized:bits:)</c>).
    /// Zeichen ab Unicode 15.1 lehnt sie ab: Für Zeichen aus Unicode 15.0 ist die NFC in jeder späteren Version gleich
    /// (Stabilitätsregel), Foundation kennt Unicode 16 nur zum Teil. Das Alter je Skalar stammt aus der Swift-Tabelle
    /// (<see cref="SwiftNormalisierung.NurUnicode15"/>), nicht aus .NET.</summary>
    internal static bool Satisfied(string normalized, double bits) =>
        bits >= MinimumBits
        && SwiftText.Zeichenzahl(normalized) >= MinimumLength
        && Encoding.UTF8.GetByteCount(normalized) <= MaximumUtf8Bytes
        && SwiftNormalisierung.NurUnicode15(normalized);

    /// <summary>RFC 8265 OpaqueString wie SPEC §1.1: jedes Zs-Zeichen ausser U+0020 → U+0020, dann NFC. Nichts trimmen.</summary>
    internal static string Normalized(string password) => SwiftText.OpaqueString(password);

    /// <summary>"siegel", Benutzername samt Teilen. Unter Windows gibt es kein Gegenstück zu <c>NSFullUserName()</c>
    /// ohne Plattform-API; der volle Name bleibt leer.</summary>
    internal static IReadOnlyList<string> DefaultUserInputs()
    {
        string name;
        try
        {
            name = Environment.UserName;
        }
        catch (InvalidOperationException)
        {
            name = "";
        }
        return UserInputs(name, "");
    }

    /// <summary>Teile: ganzer Wert, Wörter (an Leerraum und Satzzeichen getrennt), Wörter zusammengeschrieben, je mit
    /// Umschrift der Umlaute (ü → ue und u, ß → ss).</summary>
    internal static List<string> UserInputs(string userName, string fullName)
    {
        var result = new List<string>();
        void Add(string value)
        {
            var lowered = SwiftText.Klein(Normalized(value));
            if (lowered.Length == 0) { return; }
            foreach (var variant in AsciiVariants(lowered))
            {
                if (!result.Contains(variant, StringComparer.Ordinal)) { result.Add(variant); }
            }
        }
        Add("siegel");
        foreach (var value in new[] { userName, fullName })
        {
            Add(value);
            var parts = Teile(value);
            if (parts.Count > 1)
            {
                foreach (var part in parts)
                {
                    if (SwiftText.Zeichenzahl(part) >= 2) { Add(part); }
                }
                Add(string.Concat(parts));
            }
        }
        return result;
    }

    /// <summary>Swift <c>value.split { !$0.isLetter &amp;&amp; !$0.isNumber }</c> (ohne leere Teile).</summary>
    private static List<string> Teile(string value)
    {
        var text = SwiftText.Repariert(value);
        var vorrat = new Zeichenvorrat();
        var parts = new List<string>();
        var current = new StringBuilder();
        foreach (var z in vorrat.Zerlegen(text))
        {
            if (!z.IstBuchstabe && !z.IstZahl)
            {
                if (current.Length > 0) { parts.Add(current.ToString()); }
                current.Clear();
            }
            else
            {
                current.Append(z.Text);
            }
        }
        if (current.Length > 0) { parts.Add(current.ToString()); }
        return parts;
    }

    /// <summary>Schreibvarianten ohne Umlaute (zuerst das Original).</summary>
    internal static List<string> AsciiVariants(string word)
    {
        (string From, string To)[] lang = [("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss"),
            ("é", "e"), ("è", "e"), ("ê", "e"), ("à", "a"), ("ç", "c")];
        (string From, string To)[] kurz = [("ä", "a"), ("ö", "o"), ("ü", "u"), ("ß", "ss"),
            ("é", "e"), ("è", "e"), ("ê", "e"), ("à", "a"), ("ç", "c")];
        var variants = new List<string> { word };
        foreach (var table in new[] { lang, kurz })
        {
            var v = word;
            foreach (var (from, to) in table) { v = v.Replace(from, to, StringComparison.Ordinal); }
            if (!variants.Contains(v, StringComparer.Ordinal)) { variants.Add(v); }
        }
        return variants;
    }
}
