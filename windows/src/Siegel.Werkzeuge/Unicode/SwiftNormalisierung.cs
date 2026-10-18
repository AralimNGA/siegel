using System.Globalization;
using System.IO.Compression;
using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Unicode;

/// <summary>
/// Kanonische Normalisierung genau so, wie Swift auf dem Mac sie rechnet – aus der Tabelle <c>swift_nfc.txt.gz</c>, die
/// <c>SiegelStaerkeExport nfc</c> misst (windows/skripte/listen_exportieren.py), nie aus .NET/ICU (Befunde krypto-1,
/// krypto-2, krypto-4). <see cref="string.Normalize()"/> hängt an der ICU des Betriebssystems (andere Bytes für Argon2 nach
/// einem Windows-Update) und wirft bei U+FFFE; beides gibt es hier nicht. Zwei Lesarten:
/// <list type="bullet">
/// <item><see cref="NfcFoundation"/>: Foundation <c>precomposedStringWithCanonicalMapping</c> (SPEC §1.1: Master-Passwort,
/// reuseTag). Gemessen, nicht nach der Norm (Befunde im Detail: KERN-NOTIZEN-CS.md, „Normalisierung“): Foundation
/// (macOS 26) kennt Unicode 16 nur zum Teil, lässt „träge“ Zeichen (Hangul-Silben, U+0CCA, U+113C5, U+16121 …) aus der
/// Eingabe unzerlegt und setzt sie nicht weiter zusammen, setzt Hangul nur aus direkt folgenden Jamo zusammen (L ≤
/// U+1113, V ≤ U+1176, T U+11A7…U+11C3, Surrogat-Ergebnis → U+FFFD), ordnet nicht über den Anfang eines zerlegten
/// Starters mit Nicht-Starter-Zerlegung hinweg (U+0F73), macht aus einem Nicht-Starter am Anfang bzw. dem Ergebnis
/// einer Einzelzerlegung samt folgendem „Verdoppler“ (U+1611E, U+113C2) dessen Doppelform und sucht Paare mit einem
/// zweiten Glied aus der BMP mit den unteren 16 Bit des Starters (U+F00D4 U+0301 → U+1ED0).</item>
/// <item><see cref="SchluesselSwift"/>: Gleichheit von Swift-<c>String</c> (<c>==</c>, <c>Set</c>, <c>Dictionary</c>), die
/// kanonische Äquivalenz der Standardbibliothek (Hangul nach der Norm, eigene Unicode-Daten, gleiche Abschnitte beim
/// Ordnen wie Foundation).</item>
/// </list>
/// </summary>
internal static class SwiftNormalisierung
{
    private const int Skalare = 0x110000;

    private sealed class Daten
    {
        internal Dictionary<int, int[]> ZerlegungFoundation { get; } = [];
        internal Dictionary<int, int[]> ZerlegungSwift { get; } = [];
        internal Dictionary<int, byte> KlasseFoundation { get; } = [];
        internal Dictionary<int, byte> KlasseSwift { get; } = [];
        internal Dictionary<long, int> Paare { get; } = [];
        internal Dictionary<long, int> PaareSwift { get; } = [];
        internal Dictionary<int, byte> EigeneKlasse { get; } = [];
        internal Dictionary<int, int> Verdoppelt { get; } = [];
        internal HashSet<int> Traege { get; } = [];
        internal ulong[] WirktFoundation { get; } = new ulong[Skalare / 64];
        internal ulong[] WirktSwift { get; } = new ulong[Skalare / 64];
        internal ulong[] Unicode15 { get; } = new ulong[Skalare / 64];
    }

    private static readonly Lazy<Daten> daten = new(Laden, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>Foundation <c>precomposedStringWithCanonicalMapping</c>; einzelne Surrogate vorher U+FFFD.</summary>
    internal static string NfcFoundation(string text)
    {
        var d = daten.Value;
        if (!Wirkt(text, d.WirktFoundation)) { return SwiftText.Repariert(text); }
        var folge = new Folge(text.Length + 8);
        foreach (var s in SwiftText.Skalare(text))
        {
            var start = folge.Anzahl;
            if (s is >= 0xAC00 and <= 0xD7A3 || d.Traege.Contains(s))
            {
                folge.Add(s, Merkmal.Traege);
            }
            else if (d.ZerlegungFoundation.TryGetValue(s, out var z))
            {
                var einzel = z.Length == 1 && d.KlasseFoundation.GetValueOrDefault(z[0]) == 0;
                foreach (var t in z) { folge.Add(t, einzel ? Merkmal.Einzel : Merkmal.Keins); }
            }
            else
            {
                folge.Add(s, Merkmal.Keins);
            }
            if (EigeneKlasse(s, d, d.KlasseFoundation) == 0 && folge.Anzahl > start) { folge.Abschnitt[start] = true; }
        }
        Ordnen(folge, d.KlasseFoundation);
        return Text(Zusammensetzen(folge, d));
    }

    /// <summary>
    /// Schlüssel für die Gleichheit von Swift-<c>String</c>: die NFC der Standardbibliothek (sie vergleicht diese Form).
    /// Zwei Zeichenketten sind für Swift genau dann gleich, wenn ihre Schlüssel ordinal gleich sind.
    /// </summary>
    internal static string SchluesselSwift(string text)
    {
        var d = daten.Value;
        if (!Wirkt(text, d.WirktSwift)) { return SwiftText.Repariert(text); }
        var folge = new Folge(text.Length + 8);
        foreach (var s in SwiftText.Skalare(text))
        {
            var start = folge.Anzahl;
            ZerlegenSwift(s, folge, d);
            if (EigeneKlasse(s, d, d.KlasseSwift) == 0 && folge.Anzahl > start) { folge.Abschnitt[start] = true; }
        }
        Ordnen(folge, d.KlasseSwift);
        return Text(ZusammensetzenSwift(folge.Skalare, d));
    }

    /// <summary>Zusammensetzen nach UAX #15 (Hangul nach der Norm), Paare der Standardbibliothek.</summary>
    private static List<int> ZusammensetzenSwift(List<int> folge, Daten d)
    {
        var r = new List<int>(folge.Count);
        var starterPos = -1;
        var starter = 0;
        var letzteKlasse = 0;
        foreach (var ch in folge)
        {
            int klasse = d.KlasseSwift.GetValueOrDefault(ch);
            if (starterPos >= 0 && (letzteKlasse < klasse || letzteKlasse == 0))
            {
                var zusammen = -1;
                if (starter is >= 0x1100 and <= 0x1112 && ch is >= 0x1161 and <= 0x1175)
                {
                    zusammen = 0xAC00 + ((starter - 0x1100) * 21 + (ch - 0x1161)) * 28;
                }
                else if (starter is >= 0xAC00 and <= 0xD7A3 && (starter - 0xAC00) % 28 == 0 && ch is >= 0x11A8 and <= 0x11C2)
                {
                    zusammen = starter + (ch - 0x11A7);
                }
                else if (d.PaareSwift.TryGetValue(Schluessel(starter, ch), out var p))
                {
                    zusammen = p;
                }
                if (zusammen >= 0)
                {
                    r[starterPos] = zusammen;
                    starter = zusammen;
                    continue;
                }
            }
            if (klasse == 0)
            {
                starterPos = r.Count;
                starter = ch;
            }
            letzteKlasse = klasse;
            r.Add(ch);
        }
        return r;
    }

    [Flags]
    private enum Merkmal : byte
    {
        Keins = 0,
        /// <summary>Ergebnis einer Einzelzerlegung (ein Starter, z. B. U+F928 → U+5ECA).</summary>
        Einzel = 1,
        /// <summary>Aus der Eingabe, träge: weder zerlegt noch weiter zusammengesetzt.</summary>
        Traege = 2,
    }

    /// <summary>Zerlegte Folge: Skalare mit Merkmalen (wandern beim Ordnen mit) und Abschnittsanfängen (je Stelle).</summary>
    private sealed class Folge(int kapazitaet)
    {
        internal List<int> Skalare { get; } = new(kapazitaet);
        internal List<Merkmal> Merkmale { get; } = new(kapazitaet);
        internal List<bool> Abschnitt { get; } = new(kapazitaet);
        internal int Anzahl => Skalare.Count;

        internal void Add(int s, Merkmal m)
        {
            Skalare.Add(s);
            Merkmale.Add(m);
            Abschnitt.Add(false);
        }
    }

    /// <summary>Klasse des Eingabezeichens selbst: bei zerlegbaren die eigene (Tabelle K), sonst die der Lesart.</summary>
    private static int EigeneKlasse(int s, Daten d, Dictionary<int, byte> klassen) =>
        d.EigeneKlasse.TryGetValue(s, out var k) ? k
        : d.ZerlegungSwift.ContainsKey(s) || s is >= 0xAC00 and <= 0xD7A3 ? 0 : klassen.GetValueOrDefault(s);

    /// <summary>Jeder Skalar ist spätestens in Unicode 15.0 vergeben (Master-Passwort-Regel, SPEC §1.6 v4.7).</summary>
    internal static bool NurUnicode15(string text)
    {
        var d = daten.Value;
        foreach (var s in SwiftText.Skalare(text))
        {
            if (!Bit(d.Unicode15, s)) { return false; }
        }
        return true;
    }

    private static bool Bit(ulong[] menge, int s) => (menge[s >> 6] & (1UL << (s & 63))) != 0;

    private static void Setzen(ulong[] menge, int s) => menge[s >> 6] |= 1UL << (s & 63);

    /// <summary>Kommt ein Skalar vor, an dem die Normalisierung etwas ändern könnte?</summary>
    private static bool Wirkt(string text, ulong[] menge)
    {
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c < 0xC0) { continue; }                                           // darunter wirkt nie etwas
            if (char.IsSurrogate(c)) { return true; }                            // genau prüfen (Paar oder Reparatur)
            if (Bit(menge, c)) { return true; }
        }
        return false;
    }

    private static void ZerlegenSwift(int s, Folge folge, Daten d)
    {
        if (s is >= 0xAC00 and <= 0xD7A3)
        {
            var i = s - 0xAC00;
            folge.Add(0x1100 + i / 588, Merkmal.Keins);
            folge.Add(0x1161 + i % 588 / 28, Merkmal.Keins);
            if (i % 28 != 0) { folge.Add(0x11A7 + i % 28, Merkmal.Keins); }
            return;
        }
        if (!d.ZerlegungSwift.TryGetValue(s, out var z))
        {
            folge.Add(s, Merkmal.Keins);
            return;
        }
        foreach (var t in z) { ZerlegenSwift(t, folge, d); }
    }

    /// <summary>Kanonisch ordnen: Nicht-Starter stabil nach Klasse, nie vor den Anfang ihres Abschnitts (gemessen wie
    /// Foundation und Swift-String: ein zerlegter Starter wie U+0F73 beginnt einen neuen Abschnitt).</summary>
    private static void Ordnen(Folge folge, Dictionary<int, byte> klassen)
    {
        var s = folge.Skalare;
        var m = folge.Merkmale;
        var abschnitt = 0;
        for (var i = 0; i < s.Count; i++)
        {
            if (folge.Abschnitt[i]) { abschnitt = i; }
            var k = klassen.GetValueOrDefault(s[i]);
            if (k == 0) { continue; }
            var j = i;
            while (j > abschnitt && klassen.GetValueOrDefault(s[j - 1]) > k)
            {
                (s[j - 1], s[j]) = (s[j], s[j - 1]);
                (m[j - 1], m[j]) = (m[j], m[j - 1]);
                j--;
            }
        }
    }

    /// <summary>Zusammensetzen wie Foundation: Paare wie UAX #15 (blockiert, wenn dazwischen eine gleiche oder höhere
    /// Klasse steht), Hangul nur aus direkt folgenden Jamo L V (T) mit Foundations Bereichen.</summary>
    private static List<int> Zusammensetzen(Folge f, Daten d)
    {
        var folge = f.Skalare;
        var r = new List<int>(folge.Count);
        var starterPos = -1;
        var starter = 0;
        var starterTraege = false;
        var letzteKlasse = 0;
        for (var i = 0; i < folge.Count; i++)
        {
            var ch = folge[i];
            int klasse = d.KlasseFoundation.GetValueOrDefault(ch);
            // Gemessen: ein Abschnitt, der mit einem Nicht-Starter beginnt (zerlegtes U+0F73 …), setzt nichts mit dem
            // Starter davor zusammen (U+304B U+0F73 U+3099 bleibt U+304B U+3099 U+0F71 U+0F72).
            if (i > 0 && f.Abschnitt[i] && klasse != 0) { starterPos = -1; }
            // Gemessen: ein Nicht-Starter ganz am Anfang oder das Ergebnis einer Einzelzerlegung, direkt gefolgt von
            // einem Verdoppler V (Paar V+V), wird samt V zur Doppelform (U+0301 U+1611E → U+16121).
            if (((f.Merkmale[i] & Merkmal.Einzel) != 0 || (i == 0 && klasse != 0)) && i + 1 < folge.Count
                && d.Verdoppelt.TryGetValue(folge[i + 1], out var doppel))
            {
                starterPos = r.Count;
                starter = doppel;
                starterTraege = false;
                letzteKlasse = 0;
                r.Add(doppel);
                i++;
                continue;
            }
            // Gemessen: ein Nicht-Starter ganz am Anfang dient als Starter (U+11F41 U+0301 → U+1F45, siehe unten).
            if (i == 0 && klasse != 0)
            {
                starterPos = 0;
                starter = ch;
                starterTraege = false;
                letzteKlasse = 0;
                r.Add(ch);
                continue;
            }
            if (starterPos >= 0)
            {
                if (letzteKlasse == 0 && starterPos == r.Count - 1 && starter is >= 0x1100 and <= 0x1113
                    && ch is >= 0x1161 and <= 0x1176)
                {
                    var silbe = 0xAC00 + ((starter - 0x1100) * 21 + (ch - 0x1161)) * 28;
                    if (i + 1 < folge.Count && folge[i + 1] is >= 0x11A7 and <= 0x11C3)
                    {
                        silbe += folge[i + 1] - 0x11A7;
                        i++;
                    }
                    if (silbe is >= 0xD800 and <= 0xDFFF) { silbe = 0xFFFD; }   // gemessen: Foundation liefert U+FFFD
                    r[starterPos] = silbe;
                    starter = silbe;
                    starterTraege = true;                                  // Foundation hängt kein T mehr an
                    continue;
                }
                // Gemessen: Für ein zweites Glied aus der BMP sucht Foundation das Paar mit den unteren 16 Bit des Starters
                // (U+F00D4 U+0301 → U+1ED0 wie U+00D4 U+0301; U+E0061 U+0302 → U+00E2).
                var basis = ch <= 0xFFFF ? starter & 0xFFFF : starter;
                if (!starterTraege && (letzteKlasse < klasse || letzteKlasse == 0)
                    && d.Paare.TryGetValue(Schluessel(basis, ch), out var zusammen))
                {
                    r[starterPos] = zusammen;
                    starter = zusammen;
                    continue;
                }
            }
            if (klasse == 0)
            {
                starterPos = r.Count;
                starter = ch;
                starterTraege = (f.Merkmale[i] & Merkmal.Traege) != 0;
            }
            letzteKlasse = klasse;
            r.Add(ch);
        }
        return r;
    }

    private static long Schluessel(int a, int b) => ((long)a << 21) | (uint)b;

    private static string Text(List<int> skalare)
    {
        var sb = new StringBuilder(skalare.Count + 4);
        foreach (var s in skalare)
        {
            if (s < 0x10000) { sb.Append((char)s); } else { sb.Append(char.ConvertFromUtf32(s)); }
        }
        return sb.ToString();
    }

    private static Daten Laden()
    {
        var d = new Daten();
        var swiftZusatz = new Dictionary<int, int[]>();
        var swiftKlassen = new Dictionary<int, byte>();
        var swiftPaare = new Dictionary<long, int>();
        var swiftOhne = new HashSet<long>();
        using (var stream = typeof(SwiftNormalisierung).Assembly.GetManifestResourceStream("Siegel.Werkzeuge.Unicode.swift_nfc.txt.gz")
            ?? throw Fehler())
        using (var gzip = new GZipStream(stream, CompressionMode.Decompress))
        using (var reader = new StreamReader(gzip, Encoding.UTF8))
        {
            string? zeile;
            while ((zeile = reader.ReadLine()) is not null)
            {
                if (zeile.Length == 0 || zeile[0] == '#') { continue; }
                var t = zeile.Split(' ');
                switch (t[0])
                {
                    case "D":
                        d.ZerlegungFoundation[Hex(t[1])] = Zerlegung(t);
                        d.ZerlegungSwift[Hex(t[1])] = Zerlegung(t);
                        break;
                    case "O":                                                // träge: nur Swift-String zerlegt sie
                        d.ZerlegungSwift[Hex(t[1])] = Zerlegung(t);
                        d.Traege.Add(Hex(t[1]));
                        break;
                    case "K":
                        d.EigeneKlasse[Hex(t[1])] = Klasse(t[2]);
                        break;
                    case "C":
                        d.KlasseFoundation[Hex(t[1])] = Klasse(t[2]);
                        break;
                    case "P":
                        d.Paare[Schluessel(Hex(t[1]), Hex(t[2]))] = Hex(t[3]);
                        if (Hex(t[1]) == Hex(t[2])) { d.Verdoppelt[Hex(t[1])] = Hex(t[3]); }
                        break;
                    case "SD":
                        swiftZusatz[Hex(t[1])] = Zerlegung(t);
                        break;
                    case "SC":
                        swiftKlassen[Hex(t[1])] = Klasse(t[2]);
                        break;
                    case "SP":
                        swiftPaare[Schluessel(Hex(t[1]), Hex(t[2]))] = Hex(t[3]);
                        break;
                    case "SX":
                        swiftOhne.Add(Schluessel(Hex(t[1]), Hex(t[2])));
                        break;
                    case "A":
                        for (var s = Hex(t[1]); s <= Hex(t[2]); s++) { Setzen(d.Unicode15, s); }
                        break;
                    default:
                        throw Fehler();
                }
            }
        }
        if (d.ZerlegungFoundation.Count < 1000 || d.Paare.Count < 900 || d.KlasseFoundation.Count < 900) { throw Fehler(); }
        foreach (var (s, z) in swiftZusatz) { d.ZerlegungSwift[s] = z; }
        foreach (var (k, c) in d.Paare)
        {
            if (!swiftOhne.Contains(k)) { d.PaareSwift[k] = c; }
        }
        foreach (var (k, c) in swiftPaare) { d.PaareSwift[k] = c; }
        foreach (var (s, k) in d.KlasseFoundation) { d.KlasseSwift[s] = k; }
        foreach (var (s, k) in swiftKlassen)
        {
            if (k == 0) { d.KlasseSwift.Remove(s); } else { d.KlasseSwift[s] = k; }
        }

        // Wo kann sich etwas ändern? Foundation: zerlegbar, Klasse ≠ 0, zweites Glied eines Paars, Hangul-V (L+V).
        foreach (var s in d.ZerlegungFoundation.Keys) { Setzen(d.WirktFoundation, s); }
        foreach (var s in d.KlasseFoundation.Keys) { Setzen(d.WirktFoundation, s); }
        foreach (var k in d.Paare.Keys) { Setzen(d.WirktFoundation, (int)(k & 0x1FFFFF)); }
        for (var s = 0x1161; s <= 0x1176; s++) { Setzen(d.WirktFoundation, s); }
        // Swift-String: zerlegbar (auch Hangul-Silben), Klasse ≠ 0, zweites Glied eines Paars, Hangul-V und -T.
        foreach (var s in d.ZerlegungSwift.Keys) { Setzen(d.WirktSwift, s); }
        foreach (var s in d.KlasseSwift.Keys) { Setzen(d.WirktSwift, s); }
        foreach (var k in d.PaareSwift.Keys) { Setzen(d.WirktSwift, (int)(k & 0x1FFFFF)); }
        for (var s = 0xAC00; s <= 0xD7A3; s++) { Setzen(d.WirktSwift, s); }
        for (var s = 0x1161; s <= 0x1175; s++) { Setzen(d.WirktSwift, s); }
        for (var s = 0x11A8; s <= 0x11C2; s++) { Setzen(d.WirktSwift, s); }
        return d;
    }

    private static SiegelException Fehler() => new(SiegelErrorCode.Io, "resource.nfc");

    private static int Hex(string text) =>
        int.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) && v is >= 0 and < Skalare
            && v is not (>= 0xD800 and <= 0xDFFF) ? v : throw Fehler();

    private static byte Klasse(string text) =>
        byte.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var k) ? k : throw Fehler();

    private static int[] Zerlegung(string[] teile)
    {
        if (teile.Length < 3) { throw Fehler(); }
        var r = new int[teile.Length - 2];
        for (var i = 2; i < teile.Length; i++) { r[i - 2] = Hex(teile[i]); }
        return r;
    }
}
