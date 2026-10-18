namespace Siegel.Werkzeuge.Unicode;

/// <summary>
/// Erweiterte Graphem-Cluster nach UAX #29 (Unicode 16, Regeln GB3–GB13 samt GB9c) mit den Klassen, die Swift
/// verwendet (<see cref="SwiftUnicode"/>). Ergebnis wie Swifts <c>Array(string)</c>. Eigene Umsetzung, weil
/// <c>System.Globalization.StringInfo</c> in .NET 10 GB9c (indische Konjunkte wie „क्ष“) nicht kennt.
/// </summary>
internal static class Graphemzerlegung
{
    /// <summary>UTF-16-Anfänge aller Character und zum Schluss die Länge (also Anzahl + 1 Einträge).</summary>
    internal static int[] Grenzen(string text)
    {
        var grenzen = new List<int>(text.Length + 1) { 0 };
        if (text.Length == 0) { return [.. grenzen]; }

        var position = 0;
        var vorher = SwiftText.SkalarBei(text, 0, out var breite);
        position += breite;
        var vorherKlasse = SwiftUnicode.Klasse(vorher);

        // Zustand für die kontextabhängigen Regeln
        var regionalIndicators = vorherKlasse == GraphemKlasse.RegionalIndicator ? 1 : 0;    // GB12/GB13
        var emoji = SwiftUnicode.Bildzeichen(vorher) ? 1 : 0;                                 // GB11: 1 = ExtPict Extend*, 2 = … ZWJ
        var indisch = SwiftUnicode.InCB(vorher) == 1;                                         // GB9c: Konsonant [Extend|Linker]*
        var linker = false;

        while (position < text.Length)
        {
            var aktuell = SwiftText.SkalarBei(text, position, out breite);
            var klasse = SwiftUnicode.Klasse(aktuell);
            var incb = SwiftUnicode.InCB(aktuell);
            var bild = SwiftUnicode.Bildzeichen(aktuell);

            if (Trennen(vorherKlasse, klasse, incb, bild, regionalIndicators, emoji, indisch, linker))
            {
                grenzen.Add(position);
            }

            // Zustand fortschreiben
            regionalIndicators = klasse == GraphemKlasse.RegionalIndicator ? regionalIndicators + 1 : 0;
            if (bild) { emoji = 1; }
            else if (emoji == 1 && klasse == GraphemKlasse.Extend) { emoji = 1; }
            else if (emoji == 1 && klasse == GraphemKlasse.Zwj) { emoji = 2; }
            else { emoji = 0; }
            if (incb == 1)
            {
                indisch = true;
                linker = false;
            }
            else if (indisch && incb == 2)
            {
                linker = true;
            }
            else if (!(indisch && incb == 3))
            {
                indisch = false;
                linker = false;
            }

            vorherKlasse = klasse;
            position += breite;
        }
        grenzen.Add(text.Length);
        return [.. grenzen];
    }

    private static bool Trennen(GraphemKlasse p, GraphemKlasse c, int incb, bool bild, int regionalIndicators, int emoji,
        bool indisch, bool linker)
    {
        if (p == GraphemKlasse.CR && c == GraphemKlasse.LF) { return false; }                       // GB3
        if (p is GraphemKlasse.Control or GraphemKlasse.CR or GraphemKlasse.LF) { return true; }     // GB4
        if (c is GraphemKlasse.Control or GraphemKlasse.CR or GraphemKlasse.LF) { return true; }     // GB5
        if (p == GraphemKlasse.L && c is GraphemKlasse.L or GraphemKlasse.V or GraphemKlasse.LV or GraphemKlasse.LVT)
        {
            return false;                                                                           // GB6
        }
        if (p is GraphemKlasse.LV or GraphemKlasse.V && c is GraphemKlasse.V or GraphemKlasse.T) { return false; } // GB7
        if (p is GraphemKlasse.LVT or GraphemKlasse.T && c == GraphemKlasse.T) { return false; }     // GB8
        if (c is GraphemKlasse.Extend or GraphemKlasse.Zwj) { return false; }                        // GB9
        if (c == GraphemKlasse.SpacingMark) { return false; }                                        // GB9a
        if (p == GraphemKlasse.Prepend) { return false; }                                            // GB9b
        if (incb == 1 && indisch && linker) { return false; }                                        // GB9c
        if (p == GraphemKlasse.Zwj && bild && emoji == 2) { return false; }                          // GB11
        if (p == GraphemKlasse.RegionalIndicator && c == GraphemKlasse.RegionalIndicator && regionalIndicators % 2 == 1)
        {
            return false;                                                                           // GB12/GB13
        }
        return true;                                                                                // GB999
    }
}
