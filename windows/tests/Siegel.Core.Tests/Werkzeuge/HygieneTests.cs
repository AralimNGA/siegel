using System.Text;
using System.Text.RegularExpressions;
using Siegel.Modell;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Tests;

/// <summary>SPEC §5 / SPEC-WINDOWS W3 für Siegel.Werkzeuge: keine Ausgaben, nur SiegelException mit festen Codes,
/// geschwärzte Beschreibungen, keine Inhalte in Fehlermeldungen.</summary>
public partial class HygieneTests
{
    /// <summary>Quelltext ohne Kommentare und ohne Inhalt von Zeichenketten (einfacher Lexer).</summary>
    internal static string NurCode(string quelle)
    {
        var sb = new StringBuilder(quelle.Length);
        var i = 0;
        while (i < quelle.Length)
        {
            var c = quelle[i];
            if (c == '/' && i + 1 < quelle.Length && quelle[i + 1] == '/')
            {
                while (i < quelle.Length && quelle[i] != '\n') { i++; }
                continue;
            }
            if (c == '/' && i + 1 < quelle.Length && quelle[i + 1] == '*')
            {
                var ende = quelle.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = ende < 0 ? quelle.Length : ende + 2;
                continue;
            }
            if (c == '"' && i + 2 < quelle.Length && quelle[i + 1] == '"' && quelle[i + 2] == '"')
            {
                var ende = quelle.IndexOf("\"\"\"", i + 3, StringComparison.Ordinal);
                sb.Append("\"\"");
                i = ende < 0 ? quelle.Length : ende + 3;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                var verbatim = i > 0 && quelle[i - 1] == '@';
                var j = i + 1;
                while (j < quelle.Length && quelle[j] != c)
                {
                    if (quelle[j] == '\\' && !verbatim) { j++; }
                    else if (verbatim && quelle[j] == '"' && j + 1 < quelle.Length && quelle[j + 1] == '"') { j++; }
                    j++;
                }
                sb.Append(c).Append(c);
                i = j + 1;
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    private static readonly (string Name, Regex Muster)[] Sperren =
    [
        ("Console", ConsoleMuster()),
        ("Debug.Write/Print", DebugMuster()),
        ("Trace", TraceMuster()),
        ("Debugger", DebuggerMuster()),
        ("fremde Ausnahme", FremdeAusnahmeMuster()),
        ("ThrowIf…", ThrowIfMuster()),
        ("Environment.FailFast", FailFastMuster()),
    ];

    [GeneratedRegex(@"\bConsole\s*\.")] private static partial Regex ConsoleMuster();
    [GeneratedRegex(@"\bDebug\s*\.\s*(Write|Print|Assert|Fail)")] private static partial Regex DebugMuster();
    [GeneratedRegex(@"\bTrace\s*\.")] private static partial Regex TraceMuster();
    [GeneratedRegex(@"\bDebugger\s*\.")] private static partial Regex DebuggerMuster();
    [GeneratedRegex(@"\bthrow\s+new\s+(?!SiegelException\b)\w+")] private static partial Regex FremdeAusnahmeMuster();
    [GeneratedRegex(@"\b\w+Exception\s*\.\s*ThrowIf")] private static partial Regex ThrowIfMuster();
    [GeneratedRegex(@"\bEnvironment\s*\.\s*FailFast")] private static partial Regex FailFastMuster();

    [Fact]
    public void QuelltextOhneAusgabenUndFremdeAusnahmen()
    {
        var paket = Testdaten.Paket();
        Assert.NotNull(paket);
        var ordner = Path.Combine(paket!, "windows", "src", "Siegel.Werkzeuge");
        var dateien = Directory.EnumerateFiles(ordner, "*.cs", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToList();
        Assert.NotEmpty(dateien);
        var funde = new List<string>();
        foreach (var datei in dateien)
        {
            var text = File.ReadAllText(datei);
            // Unsichtbare Steuer-, Format- und Richtungszeichen im Quelltext (Trojan Source) → als \uXXXX schreiben
            foreach (var r in text.EnumerateRunes())
            {
                if (r.Value >= 0x80 && Rune.GetUnicodeCategory(r) is System.Globalization.UnicodeCategory.Control
                    or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator
                    or System.Globalization.UnicodeCategory.ParagraphSeparator or System.Globalization.UnicodeCategory.PrivateUse
                    or System.Globalization.UnicodeCategory.OtherNotAssigned)
                {
                    funde.Add($"{Path.GetRelativePath(ordner, datei)}: unsichtbares Zeichen U+{r.Value:X4}");
                }
            }
            var zeilen = NurCode(text).Split('\n');
            for (var z = 0; z < zeilen.Length; z++)
            {
                foreach (var (name, muster) in Sperren)
                {
                    if (muster.IsMatch(zeilen[z])) { funde.Add($"{Path.GetRelativePath(ordner, datei)}:{z + 1}: {name}"); }
                }
            }
        }
        Assert.True(funde.Count == 0, string.Join("\n", funde));
    }

    [Fact]
    public void LexerBlendetKommentareUndZeichenkettenAus()
    {
        Assert.DoesNotMatch(ConsoleMuster(), NurCode("var x = \"Console.WriteLine\"; // Console.Write"));
        Assert.Matches(ConsoleMuster(), NurCode("/* x */ Console.WriteLine(1);"));
        Assert.Matches(FremdeAusnahmeMuster(), NurCode("throw new InvalidOperationException(\"x\");"));
        Assert.DoesNotMatch(FremdeAusnahmeMuster(), NurCode("throw new SiegelException(SiegelErrorCode.Io, \"x\");"));
    }

    [Fact]
    public void BeschreibungenSindGeschwaerzt()
    {
        using var p = Totp.Parse("otpauth://totp/Geheimdienst:anna?secret=JBSWY3DPEHPK3PXP");
        foreach (var text in new[] { p.ToString(), $"{p}" })
        {
            Assert.DoesNotContain("JBSWY3DP", text, StringComparison.Ordinal);
            Assert.DoesNotContain("anna", text, StringComparison.Ordinal);
            Assert.DoesNotContain("Geheimdienst", text, StringComparison.Ordinal);
        }
        using var puffer = Geheimpuffer.Kopie("geheim"u8);
        Assert.Equal("Geheimpuffer(redacted)", puffer.ToString());
        var analyse = PasswordStrength.Analyze("Geheim-Passwort-2026", [], 2026);
        Assert.DoesNotContain("Geheim", analyse.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("Geheim", new Zeichenvorrat().Zerlegen("G")[0].ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void FehlerEnthaltenNurFesteCodes()
    {
        const string geheim = "Supergeheim-4711";
        var csv = Assert.Throws<SiegelException>(() => CsvImport.Parse(Encoding.UTF8.GetBytes(
            "name,url,username,password,note\nA,https://a.example,u," + geheim + "\"x,\n")));
        Assert.Equal("csv.quote", csv.Detail);
        Assert.DoesNotContain(geheim, csv.Message, StringComparison.Ordinal);
        var totp = Assert.Throws<SiegelException>(() => Totp.Parse("otpauth://totp/" + geheim + "?secret=" + geheim));
        Assert.DoesNotContain(geheim, totp.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("4711", totp.ToString(), StringComparison.Ordinal);
        var kdbx = Assert.Throws<SiegelException>(() => KeePassExport.Kdbx([], geheim[..5], new KdbxKdf(1, 64 << 10), DateTimeOffset.UtcNow));
        Assert.Equal(SiegelErrorCode.PasswordTooWeak, kdbx.Code);
        Assert.DoesNotContain(geheim[..5], kdbx.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GeheimpufferIstSchreibgeschuetztUndWirdFreigegeben()
    {
        var puffer = Geheimpuffer.Kopie([1, 2, 3]);
        Assert.Equal(3, puffer.Length);
        Assert.True(puffer.KonstantGleich([1, 2, 3]));
        Assert.False(puffer.KonstantGleich([1, 2, 4]));
        var e = Assert.Throws<SiegelException>(() =>
        {
            using var w = puffer.Schreiben();
            w.Span[0] = 9;
        });
        Assert.Equal("secure.readonly", e.Detail);
        puffer.Dispose();
        Assert.Equal("secure.disposed", Assert.Throws<SiegelException>(() =>
        {
            using var l = puffer.Lesen();
        }).Detail);
        using var flaeche = Geheimpuffer.Rechenflaeche(4);
        using (var w = flaeche.Schreiben()) { w.Span[3] = 7; }
        using (var l = flaeche.Lesen()) { Assert.Equal(new byte[] { 0, 0, 0, 7 }, l.Span.ToArray()); }
    }
}
