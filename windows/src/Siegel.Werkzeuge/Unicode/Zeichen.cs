using Siegel.Modell;

namespace Siegel.Werkzeuge.Unicode;

/// <summary>
/// Ein Swift-<c>Character</c> (Graphem-Cluster) mit den Eigenschaften, die die Stärke-Schätzung braucht. Gleichheit
/// ist Referenzgleichheit: Alle Zeichen einer Schätzung kommen aus demselben <see cref="Zeichenvorrat"/>, und gleicher
/// Text (NFC) ergibt dasselbe Objekt – wie Swifts kanonischer Vergleich bei NFC-Eingaben.
/// </summary>
internal sealed class Zeichen
{
    internal Zeichen(string text, Zeichen? klein = null)
    {
        Text = text;
        var skalare = SwiftText.Skalare(text);
        Skalar = skalare.Length == 1 ? skalare[0] : -1;
        Ascii = Skalar is >= 0 and < 0x80 ? Skalar : (text == "\r\n" ? 0x0A : -1);   // Swift: "\r\n".asciiValue == 10
        var erster = skalare.Length > 0 ? skalare[0] : 0;
        var merkmale = SwiftUnicode.Merkmale(erster);
        IstBuchstabe = (merkmale & SwiftUnicode.Buchstabe) != 0;
        IstZahl = (merkmale & SwiftUnicode.Zahl) != 0;
        if (Skalar >= 0)
        {
            IstGross = (merkmale & SwiftUnicode.Gross) != 0;
            IstKlein = (merkmale & SwiftUnicode.Klein) != 0;
        }
        else
        {
            // Swift CharacterProperties: mehrere Skalare → _isUppercased && isCased bzw. _isLowercased && isCased
            var istGrossgeschrieben = SwiftText.KanonischGleich(text, SwiftText.Gross(text));
            var istKleingeschrieben = SwiftText.KanonischGleich(text, SwiftText.Klein(text));
            var hatFall = !istGrossgeschrieben || !istKleingeschrieben;
            IstGross = istGrossgeschrieben && hatFall;
            IstKlein = istKleingeschrieben && hatFall;
        }
        Klein = klein ?? this;
    }

    /// <summary>Der Cluster als UTF-16 (NFC).</summary>
    internal string Text { get; }

    /// <summary>Wert, falls genau ein Skalar, sonst −1.</summary>
    internal int Skalar { get; }

    /// <summary>Swift <c>asciiValue</c> oder −1.</summary>
    internal int Ascii { get; }

    /// <summary>Kleinschreibung nach zxcvbn (<c>zxcvbnLower</c>): A–Z → a–z, sonst <c>lowercased()</c>, wenn es genau
    /// ein Character bleibt.</summary>
    internal Zeichen Klein { get; set; }

    internal bool IstBuchstabe { get; }
    internal bool IstZahl { get; }
    internal bool IstGross { get; }
    internal bool IstKlein { get; }

    /// <summary>Swift <c>isASCII</c>.</summary>
    internal bool IstAscii => Ascii >= 0;

    /// <summary>Ziffer 0–9 (nur ASCII), sonst −1.</summary>
    internal int Ziffer => Ascii is >= 48 and <= 57 ? Ascii - 48 : -1;

    public override string ToString() => "Zeichen(redacted)";
}

/// <summary>
/// Vorrat der Zeichen einer Schätzung: ASCII und alle Zeichen der festen Tabellen (Tastaturen, Kalender) sind
/// gemeinsam und unveränderlich, alles andere entsteht je Vorrat. Nicht threadsicher (eine Schätzung = ein Vorrat).
/// </summary>
internal sealed class Zeichenvorrat
{
    private static readonly Dictionary<string, Zeichen> gemeinsam = GemeinsamAnlegen();
    private readonly Dictionary<string, Zeichen> eigene = new(StringComparer.Ordinal);

    private static Dictionary<string, Zeichen> GemeinsamAnlegen()
    {
        var d = new Dictionary<string, Zeichen>(StringComparer.Ordinal);
        for (var c = 'a'; c <= 'z'; c++) { d[c.ToString()] = new Zeichen(c.ToString()); }
        for (var c = 'A'; c <= 'Z'; c++) { d[c.ToString()] = new Zeichen(c.ToString(), d[((char)(c + 32)).ToString()]); }
        for (var c = 0; c < 0x80; c++)
        {
            var t = ((char)c).ToString();
            if (!d.ContainsKey(t)) { d[t] = new Zeichen(t); }
        }
        d["\r\n"] = new Zeichen("\r\n");
        // Nicht-ASCII-Zeichen der festen Tabellen (QWERTZ-CH, Kalender) samt ihrer Kleinschreibung
        foreach (var text in new[] { "§", "°", "ç", "ü", "è", "¨", "ö", "é", "ä", "à", "£", "ì", "û", "Ü", "Ö", "Ä", "É", "È", "À", "Ç" })
        {
            Hinzufuegen(d, text);
        }
        return d;
    }

    private static Zeichen Hinzufuegen(Dictionary<string, Zeichen> d, string text)
    {
        if (d.TryGetValue(text, out var vorhanden)) { return vorhanden; }
        var z = new Zeichen(text);
        d[text] = z;
        var klein = KleinText(z);
        if (klein is not null && !string.Equals(klein, text, StringComparison.Ordinal))
        {
            z.Klein = Hinzufuegen(d, klein);
        }
        return z;
    }

    /// <summary>Text der zxcvbn-Kleinschreibung oder null, wenn das Zeichen bleibt.</summary>
    private static string? KleinText(Zeichen z)
    {
        if (z.Ascii >= 0) { return z.Ascii is >= 65 and <= 90 ? ((char)(z.Ascii + 32)).ToString() : null; }
        var klein = SwiftText.Klein(z.Text);
        if (string.Equals(klein, z.Text, StringComparison.Ordinal)) { return null; }
        if (SwiftText.Zeichenzahl(klein) != 1) { return null; }
        return SwiftText.Nfc(klein);
    }

    /// <summary>Gemeinsames Zeichen (ASCII oder aus den festen Tabellen).</summary>
    internal static Zeichen Fest(string text) =>
        gemeinsam.TryGetValue(text, out var z) ? z : throw new SiegelException(SiegelErrorCode.Io, "zeichen.fest");

    /// <summary>Das Zeichen zu einem Cluster-Text (NFC).</summary>
    internal Zeichen Hole(string text)
    {
        if (gemeinsam.TryGetValue(text, out var z)) { return z; }
        if (eigene.TryGetValue(text, out z)) { return z; }
        z = new Zeichen(text);
        eigene[text] = z;
        var klein = KleinText(z);
        if (klein is not null && !string.Equals(klein, text, StringComparison.Ordinal))
        {
            z.Klein = Hole(klein);
        }
        return z;
    }

    /// <summary>Zerlegt eine (schon normalisierte) Zeichenkette in Character.</summary>
    internal Zeichen[] Zerlegen(string text)
    {
        var grenzen = Graphemzerlegung.Grenzen(text);
        var result = new Zeichen[grenzen.Length - 1];
        for (var i = 0; i < result.Length; i++)
        {
            result[i] = Hole(text[grenzen[i]..grenzen[i + 1]]);
        }
        return result;
    }
}
