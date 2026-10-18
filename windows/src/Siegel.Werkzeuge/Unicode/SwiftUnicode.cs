using System.Globalization;
using System.IO.Compression;
using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Unicode;

/// <summary>Graphem-Klassen nach UAX #29 (wie Swift sie anwendet).</summary>
internal enum GraphemKlasse : byte
{
    Other = 0, CR, LF, Control, Extend, Zwj, RegionalIndicator, Prepend, SpacingMark, L, V, T, LV, LVT,
}

/// <summary>
/// Unicode-Eigenschaften genau so, wie Swift (macOS) sie sieht: aus der Tabelle <c>swift_unicode.txt.gz</c>, die
/// <c>SiegelStaerkeExport unicode</c> erzeugt (windows/skripte/listen_exportieren.py). Damit hängen Stärke-Schätzung,
/// Gross-/Kleinschreibung und Zeichenzählung weder von der Windows-Version noch von ICU ab, und C# trifft Swift
/// bit-genau (Character.isLetter = Alphabetic, isNumber = Numeric_Type, volle Kleinschreibung ohne Final-Sigma, …).
/// </summary>
internal static class SwiftUnicode
{
    internal const int Buchstabe = 1;
    internal const int Zahl = 2;
    internal const int Gross = 4;
    internal const int Klein = 8;
    internal const int Leerraum = 16;

    private const int BlockBits = 8;
    private const int BlockSize = 1 << BlockBits;

    private static readonly Tabelle daten = Laden();

    private sealed record Tabelle(ushort[] Bloecke, uint[] Werte, Dictionary<int, string> Kleinschreibung,
        Dictionary<int, string> Grossschreibung);

    // Bits: 0–4 Merkmale, 5–9 Kategorie, 10–13 Graphem-Klasse, 14 Bildzeichen, 15–16 InCB
    private static uint Wert(int skalar)
    {
        if ((uint)skalar > 0x10FFFF) { return 29u << 5; }
        var block = daten.Bloecke[skalar >> BlockBits];
        return daten.Werte[(block << BlockBits) | (skalar & (BlockSize - 1))];
    }

    internal static int Merkmale(int skalar) => (int)(Wert(skalar) & 0x1F);

    internal static UnicodeCategory Kategorie(int skalar) => (UnicodeCategory)((Wert(skalar) >> 5) & 0x1F);

    internal static GraphemKlasse Klasse(int skalar) => (GraphemKlasse)((Wert(skalar) >> 10) & 0xF);

    internal static bool Bildzeichen(int skalar) => ((Wert(skalar) >> 14) & 1) != 0;

    /// <summary>Indic_Conjunct_Break: 0 keins, 1 Konsonant, 2 Linker, 3 Extend.</summary>
    internal static int InCB(int skalar) => (int)((Wert(skalar) >> 15) & 3);

    /// <summary>Swift <c>Unicode.Scalar.Properties.isWhitespace</c> (White_Space).</summary>
    internal static bool IstLeerraum(int skalar) => (Merkmale(skalar) & Leerraum) != 0;

    /// <summary>Volle Kleinschreibung eines Skalars (SpecialCasing ohne Bedingungen), null = unverändert.</summary>
    internal static string? KleinVon(int skalar) => daten.Kleinschreibung.GetValueOrDefault(skalar);

    /// <summary>Volle Grossschreibung eines Skalars, null = unverändert.</summary>
    internal static string? GrossVon(int skalar) => daten.Grossschreibung.GetValueOrDefault(skalar);

    private static Tabelle Laden()
    {
        var werte = new uint[0x110000];
        for (var s = 0xD800; s <= 0xDFFF; s++) { werte[s] = 16u << 5; }    // Surrogate (kommen nach der Reparatur nie vor)
        var klein = new Dictionary<int, string>();
        var gross = new Dictionary<int, string>();
        using (var stream = typeof(SwiftUnicode).Assembly.GetManifestResourceStream("Siegel.Werkzeuge.Unicode.swift_unicode.txt.gz")
            ?? throw new SiegelException(SiegelErrorCode.Io, "resource.unicode"))
        using (var gzip = new GZipStream(stream, CompressionMode.Decompress))
        using (var reader = new StreamReader(gzip, Encoding.UTF8))
        {
            string? zeile;
            while ((zeile = reader.ReadLine()) is not null)
            {
                if (zeile.Length == 0 || zeile[0] == '#') { continue; }
                var teile = zeile.Split(' ');
                switch (teile[0])
                {
                    case "R":
                        var von = Hex(teile[1]);
                        var bis = Hex(teile[2]);
                        var wert = (uint)Hex(teile[3]) | (uint.Parse(teile[4], CultureInfo.InvariantCulture) << 5)
                            | (uint.Parse(teile[5], CultureInfo.InvariantCulture) << 10)
                            | (uint.Parse(teile[6], CultureInfo.InvariantCulture) << 14)
                            | (uint.Parse(teile[7], CultureInfo.InvariantCulture) << 15);
                        for (var s = von; s <= bis; s++) { werte[s] = wert; }
                        break;
                    case "K":
                        klein[Hex(teile[1])] = Abbildung(teile);
                        break;
                    case "G":
                        gross[Hex(teile[1])] = Abbildung(teile);
                        break;
                    default:
                        throw new SiegelException(SiegelErrorCode.Io, "resource.unicode");
                }
            }
        }

        // Zweistufig ablegen: gleiche 256er-Blöcke nur einmal.
        var bloecke = new ushort[0x110000 >> BlockBits];
        var eindeutig = new List<uint>();
        var bekannt = new Dictionary<string, ushort>();
        for (var b = 0; b < bloecke.Length; b++)
        {
            var teil = werte.AsSpan(b << BlockBits, BlockSize);
            var schluessel = Convert.ToBase64String(System.Runtime.InteropServices.MemoryMarshal.AsBytes(teil));
            if (!bekannt.TryGetValue(schluessel, out var index))
            {
                index = (ushort)(eindeutig.Count >> BlockBits);
                eindeutig.AddRange(teil.ToArray());
                bekannt[schluessel] = index;
            }
            bloecke[b] = index;
        }
        return new Tabelle(bloecke, [.. eindeutig], klein, gross);
    }

    private static int Hex(string text) => int.Parse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static string Abbildung(string[] teile)
    {
        var sb = new StringBuilder();
        for (var i = 2; i < teile.Length; i++) { sb.Append(char.ConvertFromUtf32(Hex(teile[i]))); }
        return sb.ToString();
    }
}
