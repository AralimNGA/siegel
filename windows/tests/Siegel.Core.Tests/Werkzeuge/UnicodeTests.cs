using System.Globalization;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Tests;

/// <summary>Swift-Semantik der Zeichen (gemessen mit swiftc 6.4 auf macOS 26, siehe SwiftUnicode/SwiftText).</summary>
public class UnicodeTests
{
    private static Zeichen Z(string text)
    {
        var zeichen = new Zeichenvorrat().Zerlegen(text);
        Assert.Single(zeichen);
        return zeichen[0];
    }

    private static string Hex(string s) => string.Join(" ", SwiftText.Skalare(s).Select(v => v.ToString("X4", CultureInfo.InvariantCulture)));

    [Fact]
    public void CharacterEigenschaftenWieSwift()
    {
        // (Text, isLetter, isNumber, isUppercase, isLowercase, Kleinschreibung)
        (string Text, bool L, bool N, bool U, bool Kl, string Klein)[] faelle =
        [
            ("A", true, false, true, false, "0061"), ("a", true, false, false, true, "0061"),
            ("İ", true, false, true, false, "0069 0307"), ("Σ", true, false, true, false, "03C3"),
            ("ß", true, false, false, true, "00DF"), ("ẞ", true, false, true, false, "00DF"),
            ("ǅ", true, false, false, false, "01C6"), ("Ⅳ", true, true, true, false, "2173"),
            ("一", true, true, false, false, "4E00"), ("½", false, true, false, false, "00BD"),
            ("Ⓐ", true, false, true, false, "24D0"), ("ⓐ", true, false, false, true, "24D0"),
            ("q\u0307", true, false, false, true, "0071 0307"), ("Q\u0307", true, false, true, false, "0071 0307"),
            ("1", false, true, false, false, "0031"), ("é", true, false, false, true, "00E9"),
            ("🇨🇭", false, false, false, false, "1F1E8 1F1ED"), ("क\u094Dष", true, false, false, false, "0915 094D 0937"),
        ];
        foreach (var f in faelle)
        {
            var z = Z(f.Text);
            Assert.True(f.L == z.IstBuchstabe, $"isLetter {Hex(f.Text)}");
            Assert.True(f.N == z.IstZahl, $"isNumber {Hex(f.Text)}");
            Assert.True(f.U == z.IstGross, $"isUppercase {Hex(f.Text)}");
            Assert.True(f.Kl == z.IstKlein, $"isLowercase {Hex(f.Text)}");
            Assert.Equal(f.Klein, Hex(SwiftText.Klein(f.Text)));
        }
        Assert.Equal(10, Z("\r\n").Ascii);                             // Swift: "\r\n".asciiValue == 10
        Assert.True(Z("\r\n").IstAscii);
        Assert.Equal("i\u0307", Z("İ").Klein.Text);                    // zxcvbnLower bleibt ein Character
        Assert.Equal("ss", SwiftText.Klein(SwiftText.Gross("ß")).ToLowerInvariant());
    }

    [Fact]
    public void KleinschreibungOhneFinalSigma()
    {
        Assert.Equal("aσ", SwiftText.Klein("AΣ"));
        Assert.Equal("ασ ", SwiftText.Klein("ΑΣ "));
        Assert.Equal("SS", SwiftText.Gross("ß"));
        Assert.Equal("ʼN", SwiftText.Gross("ŉ"));
    }

    [Fact]
    public void GraphemeMitGb9cUndEmoji()
    {
        Assert.Equal(2, SwiftText.Zeichenzahl("क\u094Dषa"));                  // .NET StringInfo zählt hier 3
        Assert.Equal(1, SwiftText.Zeichenzahl("क\u094D\u200Dष"));
        Assert.Equal(2, SwiftText.Zeichenzahl("🇨🇭🇩🇪"));
        Assert.Equal(1, SwiftText.Zeichenzahl("👨\u200D👩\u200D👧"));
        Assert.Equal(1, SwiftText.Zeichenzahl("👍🏽"));
        Assert.Equal(1, SwiftText.Zeichenzahl("\r\n"));
        Assert.Equal(1, SwiftText.Zeichenzahl("각"));
        Assert.Equal(2, SwiftText.Zeichenzahl("🇨🇭🇩"));                     // Paar + einzelnes RI
        Assert.Equal(0, SwiftText.Zeichenzahl(""));
    }

    [Fact]
    public void FoundationLeerraumMengen()
    {
        Assert.Equal("x", SwiftText.Trimmen("\u200B\t x \u00A0", SwiftText.IstLeerzeichen));
        Assert.Equal("\nx", SwiftText.Trimmen("\nx ", SwiftText.IstLeerzeichen));
        Assert.Equal("x", SwiftText.Trimmen("\r\n\u0085x\u2028\u2029", SwiftText.IstLeerzeichenOderUmbruch));
        Assert.Equal("", SwiftText.Trimmen("   ", SwiftText.IstLeerzeichen));
        Assert.Equal("😀", SwiftText.Trimmen(" 😀 ", SwiftText.IstLeerzeichen));
    }

    [Fact]
    public void EinzelneSurrogateWerdenRepariert()
    {
        Assert.Equal("a�b�", SwiftText.Repariert("a\uDC00b\uD800"));
        Assert.Equal("😀", SwiftText.Repariert("😀"));
        Assert.Equal(PasswordStrength.Estimate("a�b").Bits, PasswordStrength.Estimate("a\uDC00b").Bits);
    }

    [Fact]
    public void TabelleVollstaendig()
    {
        Assert.Equal(UnicodeCategory.SpaceSeparator, SwiftUnicode.Kategorie(0x3000));
        Assert.Equal(UnicodeCategory.Format, SwiftUnicode.Kategorie(0x200B));
        Assert.Equal(GraphemKlasse.Zwj, SwiftUnicode.Klasse(0x200D));
        Assert.Equal(GraphemKlasse.RegionalIndicator, SwiftUnicode.Klasse(0x1F1E6));
        Assert.Equal(GraphemKlasse.LVT, SwiftUnicode.Klasse(0xAC01));
        Assert.True(SwiftUnicode.Bildzeichen(0x1F600));
        Assert.Equal(2, SwiftUnicode.InCB(0x094D));
        Assert.Equal(1, SwiftUnicode.InCB(0x0915));
        Assert.Equal(3, SwiftUnicode.InCB(0x200D));
        Assert.Equal(UnicodeCategory.OtherNotAssigned, SwiftUnicode.Kategorie(0x110000));
    }
}
