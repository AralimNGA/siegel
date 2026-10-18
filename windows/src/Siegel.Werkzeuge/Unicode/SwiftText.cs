using System.Globalization;
using System.Text;

namespace Siegel.Werkzeuge.Unicode;

/// <summary>
/// Zeichenketten-Semantik wie Swift/Foundation auf dem Mac: Character = erweitertes Graphem-Cluster nach UAX #29 in
/// Swifts Fassung (mit GB9c, Indic_Conjunct_Break – .NET 10 kennt diese Regel nicht), volle Gross-/Kleinschreibung je
/// Skalar (wie <c>String.lowercased()</c>, ohne Final-Sigma), Foundation-Zeichenmengen <c>.whitespaces</c> und
/// <c>.whitespacesAndNewlines</c>, RFC-8265-Abbildung (SPEC §1.1).
/// </summary>
internal static class SwiftText
{
    /// <summary>Einzelne Surrogate → U+FFFD (Swift-Zeichenketten enthalten nie welche).</summary>
    internal static string Repariert(string text)
    {
        var bad = -1;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1])) { i++; continue; }
            if (char.IsSurrogate(c)) { bad = i; break; }
        }
        if (bad < 0) { return text; }
        var sb = new StringBuilder(text.Length);
        sb.Append(text, 0, bad);
        for (var i = bad; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                sb.Append(c).Append(text[i + 1]);
                i++;
            }
            else
            {
                sb.Append(char.IsSurrogate(c) ? '�' : c);
            }
        }
        return sb.ToString();
    }

    /// <summary>RFC 8265 OpaqueString wie SPEC §1.1: jedes Zs-Zeichen ausser U+0020 → U+0020, dann NFC. Nichts trimmen.</summary>
    internal static string OpaqueString(string password)
    {
        var text = Repariert(password);
        StringBuilder? sb = null;
        for (var i = 0; i < text.Length; i++)
        {
            var s = SkalarBei(text, i, out var width);
            var map = s != 0x20 && SwiftUnicode.Kategorie(s) == UnicodeCategory.SpaceSeparator;
            if (map && sb is null)
            {
                sb = new StringBuilder(text.Length);
                sb.Append(text, 0, i);
            }
            if (sb is not null)
            {
                if (map) { sb.Append(' '); } else { sb.Append(text, i, width); }
            }
            i += width - 1;
        }
        return NfcRoh(sb?.ToString() ?? text);
    }

    /// <summary>NFC wie Foundation <c>precomposedStringWithCanonicalMapping</c> aus der gemessenen Tabelle (nie .NET/ICU:
    /// das hinge an der Windows-Version und würfe bei U+FFFE; Befunde krypto-1/krypto-2).</summary>
    private static string NfcRoh(string text) => SwiftNormalisierung.NfcFoundation(text);

    internal static int SkalarBei(string text, int index, out int width)
    {
        var c = text[index];
        if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
        {
            width = 2;
            return char.ConvertToUtf32(c, text[index + 1]);
        }
        width = 1;
        return char.IsSurrogate(c) ? 0xFFFD : c;
    }

    /// <summary>Skalare der Zeichenkette (einzelne Surrogate als U+FFFD).</summary>
    internal static int[] Skalare(string text)
    {
        var result = new List<int>(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            result.Add(SkalarBei(text, i, out var width));
            i += width - 1;
        }
        return [.. result];
    }

    /// <summary>Swift <c>String.lowercased()</c>: volle Kleinschreibung je Skalar.</summary>
    internal static string Klein(string text) => Abbilden(text, klein: true);

    /// <summary>Swift <c>String.uppercased()</c>: volle Grossschreibung je Skalar.</summary>
    internal static string Gross(string text) => Abbilden(text, klein: false);

    private static string Abbilden(string text, bool klein)
    {
        var ascii = true;
        foreach (var c in text)
        {
            if (c >= 0x80) { ascii = false; break; }
        }
        if (ascii)
        {
            return klein ? AsciiKlein(text) : AsciiGross(text);
        }
        var sb = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var s = SkalarBei(text, i, out var width);
            var abbildung = klein ? SwiftUnicode.KleinVon(s) : SwiftUnicode.GrossVon(s);
            if (abbildung is not null) { sb.Append(abbildung); } else { sb.Append(char.ConvertFromUtf32(s)); }
            i += width - 1;
        }
        return sb.ToString();
    }

    private static string AsciiKlein(string text)
    {
        foreach (var c in text)
        {
            if (c is >= 'A' and <= 'Z') { return string.Create(text.Length, text, (ziel, q) => { for (var i = 0; i < q.Length; i++) { ziel[i] = q[i] is >= 'A' and <= 'Z' ? (char)(q[i] + 32) : q[i]; } }); }
        }
        return text;
    }

    private static string AsciiGross(string text)
    {
        foreach (var c in text)
        {
            if (c is >= 'a' and <= 'z') { return string.Create(text.Length, text, (ziel, q) => { for (var i = 0; i < q.Length; i++) { ziel[i] = q[i] is >= 'a' and <= 'z' ? (char)(q[i] - 32) : q[i]; } }); }
        }
        return text;
    }

    /// <summary>Foundation <c>CharacterSet.whitespaces</c> (gemessen auf macOS 26: Zs, U+0009 und U+200B).</summary>
    internal static bool IstLeerzeichen(int s) =>
        s is 0x09 or 0x20 or 0xA0 or 0x1680 or (>= 0x2000 and <= 0x200B) or 0x202F or 0x205F or 0x3000;

    /// <summary>Foundation <c>CharacterSet.whitespacesAndNewlines</c> (dazu U+000A–000D, U+0085, U+2028, U+2029).</summary>
    internal static bool IstLeerzeichenOderUmbruch(int s) =>
        IstLeerzeichen(s) || s is (>= 0x0A and <= 0x0D) or 0x85 or 0x2028 or 0x2029;

    /// <summary>Foundation <c>trimmingCharacters(in:)</c>: Skalare am Rand entfernen.</summary>
    internal static string Trimmen(string text, Func<int, bool> menge)
    {
        var start = 0;
        while (start < text.Length)
        {
            var s = SkalarBei(text, start, out var width);
            if (!menge(s)) { break; }
            start += width;
        }
        var end = text.Length;
        while (end > start)
        {
            var width = end - 2 >= start && char.IsLowSurrogate(text[end - 1]) && char.IsHighSurrogate(text[end - 2]) ? 2 : 1;
            var s = SkalarBei(text, end - width, out _);
            if (!menge(s)) { break; }
            end -= width;
        }
        return start == 0 && end == text.Length ? text : text[start..end];
    }

    /// <summary>Anzahl Character (Graphem-Cluster) wie Swift <c>String.count</c>.</summary>
    internal static int Zeichenzahl(string text) => Graphemzerlegung.Grenzen(text).Length - 1;

    /// <summary>Kanonisch gleich wie Swift <c>String ==</c> (Standardbibliothek, nicht Foundation; Befund krypto-4).</summary>
    internal static bool KanonischGleich(string a, string b) => SwiftStringComparer.Instance.Equals(a, b);

    /// <summary>NFC wie Foundation <c>precomposedStringWithCanonicalMapping</c>, einzelne Surrogate vorher U+FFFD.</summary>
    internal static string Nfc(string text) => NfcRoh(Repariert(text));

    /// <summary>Swift <c>String.contains(_:)</c> für eine Folge aus druckbaren ASCII-Zeichen (z. B. <c>"://"</c>): ein
    /// Treffer zählt nur an Character-Grenzen (gemessen auf macOS 26.7: in <c>https://</c> + U+200D + <c>.ch</c> findet Swift
    /// <c>"://"</c> nicht, weil U+200D zum zweiten „/“ gehört; ebenso nach einem Prepend-Zeichen vor „:“). Für solche
    /// Folgen genügt der Blick auf die Nachbarn: davor kein Prepend (GB9b), danach kein Extend, ZWJ oder SpacingMark
    /// (GB9, GB9a); innen trennt UAX #29 druckbares ASCII immer.</summary>
    internal static bool EnthaeltFolge(string text, string folge)
    {
        for (var i = text.IndexOf(folge, StringComparison.Ordinal); i >= 0; i = text.IndexOf(folge, i + 1, StringComparison.Ordinal))
        {
            var davor = i == 0 || SwiftUnicode.Klasse(SkalarVor(text, i)) != GraphemKlasse.Prepend;
            var ende = i + folge.Length;
            var danach = ende == text.Length
                || SwiftUnicode.Klasse(SkalarBei(text, ende, out _)) is not (GraphemKlasse.Extend or GraphemKlasse.Zwj or GraphemKlasse.SpacingMark);
            if (davor && danach) { return true; }
        }
        return false;
    }

    /// <summary>Skalar, der an <paramref name="index"/> endet (einzelne Surrogate als U+FFFD wie <see cref="SkalarBei"/>).</summary>
    private static int SkalarVor(string text, int index) =>
        index >= 2 && char.IsLowSurrogate(text[index - 1]) && char.IsHighSurrogate(text[index - 2])
            ? SkalarBei(text, index - 2, out _)
            : SkalarBei(text, index - 1, out _);

    /// <summary>Kommt ein Skalar aus der Menge vor?</summary>
    internal static bool EnthaeltSkalar(string text, Func<int, bool> menge)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (menge(SkalarBei(text, i, out var width))) { return true; }
            i += width - 1;
        }
        return false;
    }

    /// <summary>Alle Skalare aus der Menge entfernen.</summary>
    internal static string OhneSkalare(string text, Func<int, bool> menge)
    {
        if (!EnthaeltSkalar(text, menge)) { return text; }
        var sb = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var s = SkalarBei(text, i, out var width);
            if (!menge(s)) { sb.Append(text, i, width); }
            i += width - 1;
        }
        return sb.ToString();
    }
}
