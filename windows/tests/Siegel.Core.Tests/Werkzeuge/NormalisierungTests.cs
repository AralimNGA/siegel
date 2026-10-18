using System.Globalization;
using Siegel.Core;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Tests;

/// <summary>
/// Normalisierung wie Swift auf dem Mac (Befunde krypto-1, krypto-2, krypto-4; SPEC-WINDOWS W7): Foundation-NFC für das
/// Master-Passwort (SPEC §1.1) und die Gleichheit von Swift-<c>String</c> – aus der Tabelle, nie über ICU. Die
/// Erwartungswerte rechnete Swift (<c>SiegelStaerkeExport nfc-korpus</c> / <c>gleich</c>, korpus_erzeugen.py); die Tests
/// laufen ohne Xcode, also auch unter Windows, und beweisen dort, dass die ICU des Systems keine Rolle spielt.
/// </summary>
public class NormalisierungTests
{
    private static string Hex(string s) => string.Join(" ", SwiftText.Skalare(s).Select(v => v.ToString("X4", CultureInfo.InvariantCulture)));

    [Fact]
    public void NfcKorpusWieFoundation()
    {
        var faelle = Testdaten.Base64Datensaetze("nfc_korpus.txt.gz");
        var erwartet = Testdaten.Base64Datensaetze("nfc_erwartet.txt.gz");
        Assert.True(faelle.Count > 40_000, $"Korpus zu klein: {faelle.Count}");
        Assert.Equal(faelle.Count, erwartet.Count);
        var fehler = new List<string>();
        for (var i = 0; i < faelle.Count; i++)
        {
            var text = faelle[i][0];
            var nfc = SwiftText.Nfc(text);
            var pw = PasswordNormalizer.Normalize(text);
            if (!string.Equals(nfc, erwartet[i][0], StringComparison.Ordinal)
                || !string.Equals(PasswordNormalizer.NfcOnly(text), erwartet[i][0], StringComparison.Ordinal)
                || !string.Equals(pw, erwartet[i][1], StringComparison.Ordinal)
                || !string.Equals(MasterPasswordPolicy.Normalized(text), erwartet[i][1], StringComparison.Ordinal))
            {
                fehler.Add($"Fall {i + 1} [{Hex(text)}]: Swift {Hex(erwartet[i][0])} / {Hex(erwartet[i][1])}, C# {Hex(nfc)} / {Hex(pw)}");
            }
        }
        Assert.True(fehler.Count == 0, $"{fehler.Count} Abweichungen:\n" + string.Join("\n", fehler.Take(40)));
    }

    [Fact]
    public void GleichheitKorpusWieSwiftString()
    {
        var faelle = Testdaten.Base64Datensaetze("gleich_korpus.txt.gz");
        var erwartet = Testdaten.Zeilen("gleich_erwartet.txt.gz");
        Assert.True(faelle.Count > 40_000, $"Korpus zu klein: {faelle.Count}");
        Assert.Equal(faelle.Count, erwartet.Count);
        var vergleich = SwiftStringComparer.Instance;
        var fehler = new List<string>();
        var gleiche = 0;
        for (var i = 0; i < faelle.Count; i++)
        {
            var (a, b) = (faelle[i][0], faelle[i][1]);
            var soll = erwartet[i] == "1";
            gleiche += soll ? 1 : 0;
            var ist = vergleich.Equals(a, b);
            if (ist != soll || ist != vergleich.Equals(b, a) || ist != SwiftText.KanonischGleich(a, b)
                || (ist && vergleich.GetHashCode(a) != vergleich.GetHashCode(b)))
            {
                fehler.Add($"Fall {i + 1} [{Hex(a)}] / [{Hex(b)}]: Swift {soll}, C# {ist}");
            }
        }
        Assert.True(gleiche > 10_000 && gleiche < faelle.Count - 5_000);
        Assert.True(fehler.Count == 0, $"{fehler.Count} Abweichungen:\n" + string.Join("\n", fehler.Take(40)));
    }

    /// <summary>krypto-1: U+FFFE (ein Nichtzeichen, das Swift annimmt) wirft nie – .NET <c>string.Normalize</c> täte es.</summary>
    [Fact]
    public void NichtzeichenOhneAusnahme()
    {
        foreach (var text in new[] { "abc\uFFFEdef", "\uFFFE", "\uFFFF", "e\u0301\uFFFEe\u0301", "\uFDD0\u00A0x", "\U0001FFFE" })
        {
            var nfc = SwiftText.Nfc(text);
            var pw = PasswordNormalizer.Normalize(text);
            Assert.Equal(nfc.Replace("\u00A0", " ", StringComparison.Ordinal), pw);
            Assert.True(SwiftStringComparer.Instance.Equals(text, nfc));
            Assert.Equal(SwiftStringComparer.Instance.GetHashCode(text), SwiftStringComparer.Instance.GetHashCode(nfc));
        }
        Assert.Equal("abc\uFFFEdef", PasswordNormalizer.Normalize("abc\uFFFEdef"));
        Assert.Equal("\u00E9\uFFFE\u00E9", SwiftText.Nfc("e\u0301\uFFFEe\u0301"));
        using var bytes = PasswordNormalizer.SecureBytes("abc\uFFFEdef");
        using var l = bytes.Borrow();
        Assert.Equal("616263EFBFBE646566", Convert.ToHexString(l.Span));
    }

    /// <summary>krypto-2: gemessen auf macOS 26 – Foundation setzt Unicode-16-Paare nur zum Teil zusammen. Swift-String
    /// (Standardbibliothek) hält alle drei für gleich; .NET mit ICU 76 setzte alle drei zusammen.</summary>
    [Fact]
    public void Unicode16WieFoundation()
    {
        Assert.Equal("16D67 16D67", Hex(SwiftText.Nfc("\U00016D67\U00016D67")));        // Kirat Rai: bleibt
        Assert.Equal("16D68", Hex(SwiftText.Nfc("\U00016D68")));                       // opak: bleibt auch
        Assert.Equal("105D2 0307", Hex(SwiftText.Nfc("\U000105D2\u0307")));            // Todhri: bleibt
        Assert.Equal("16121", Hex(SwiftText.Nfc("\U0001611E\U0001611E")));             // Gurung Khema: zusammen
        Assert.Equal("113C5", Hex(SwiftText.Nfc("\U000113C2\U000113C2")));             // Tulu-Tigalari: zusammen
        Assert.True(SwiftText.KanonischGleich("\U00016D67\U00016D67", "\U00016D68"));
        Assert.True(SwiftText.KanonischGleich("\U000105D2\u0307", "\U000105C9"));
        Assert.True(SwiftText.KanonischGleich("\U0001611E\U0001611E", "\U00016121"));
        Assert.False(SwiftText.KanonischGleich("a\u00A0b", "a b"));
    }

    /// <summary>Foundation setzt Hangul eigen zusammen (gemessen): fertige Silben bleiben, nur Jamo L V (T) direkt
    /// hintereinander, mit Foundations Bereichsgrenzen; Swift-String vergleicht nach der Norm.</summary>
    [Fact]
    public void HangulWieFoundation()
    {
        Assert.Equal("AC01", Hex(SwiftText.Nfc("\u1100\u1161\u11A8")));
        Assert.Equal("AC00 11A8", Hex(SwiftText.Nfc("\uAC00\u11A8")));                  // Norm: AC01
        Assert.Equal("AC00", Hex(SwiftText.Nfc("\u1100\u1161\u11A7")));                 // U+11A7 verschwindet
        Assert.Equal("AE4C", Hex(SwiftText.Nfc("\u1100\u1176")));
        Assert.Equal("D7A4", Hex(SwiftText.Nfc("\u1112\u1176")));
        Assert.Equal("FFFD", Hex(SwiftText.Nfc("\u1113\u1176\u11C3")));                 // fiele in die Surrogate
        Assert.Equal("AC00 0301 11A8", Hex(SwiftText.Nfc("\u1100\u1161\u0301\u11A8")));
        Assert.True(SwiftText.KanonischGleich("\uAC00\u11A8", "\uAC01"));
        Assert.False(SwiftText.KanonischGleich("\u1100\u1161\u11A7", "\uAC00"));
    }

    [Fact]
    public void NurZeichenAusUnicode15()
    {
        Assert.True(SwiftNormalisierung.NurUnicode15("Abc-123 \u00E9\uFFFE\uFFFF\uFDD0\uE000\U0010FFFD\U00031350\U0001FAE8\uAC00"));
        foreach (var neu in new[] { "\U00016D67", "\U000105D2", "\U0001611E", "\U0002EBF0", "\U0001FAE9", "\U000E0080", "\u0378" })
        {
            Assert.False(SwiftNormalisierung.NurUnicode15("a" + neu), Hex(neu));
        }
        const string stark = "u,F?CfDuMlYWuJASPVQ*6GUG@O";
        Assert.True(MasterPasswordPolicy.Check(stark, ["siegel"]).Ok);
        var r = MasterPasswordPolicy.Check(stark + "\U00016D67\U00016D67", ["siegel"]);
        Assert.False(r.Ok);
        Assert.True(r.Bits >= 60);
        Assert.True(MasterPasswordPolicy.Check(stark + "\uFFFE", ["siegel"]).Ok);
    }
}
