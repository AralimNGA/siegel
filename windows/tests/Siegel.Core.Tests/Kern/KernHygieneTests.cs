using System.Text;
using System.Text.RegularExpressions;
using Siegel.Werkzeuge.Tests;

namespace Siegel.Core.Tests.Kern;

/// <summary>SPEC §5 / SPEC-WINDOWS W3 für Siegel.Core (Gegenstück zu <c>HygieneTests</c> der Werkzeuge und zu
/// <c>windows/skripte/sperren_windows.py</c>): keine Ausgaben, nach aussen nur SiegelException. Läuft in jedem Bau
/// (auch Release und unter Windows ohne Python), damit <c>dotnet test</c> die Regel durchsetzt.</summary>
public partial class KernHygieneTests
{
    /// <summary>Interne Ausnahmen, die nie nach aussen gelangen, je Datei freigegeben (gleiche Liste wie
    /// <c>INTERN</c> in sperren_windows.py; Begründung dort).</summary>
    private static readonly Dictionary<string, string[]> Intern = new(StringComparer.Ordinal)
    {
        ["Kern/FileIO.cs"] = ["ExistsException"],
        ["Kern/P256.cs"] = ["CryptographicException"],
        ["Tresor/UnlockedVault.cs"] = ["HelloMaterialNeededException"],
        ["Tresor/UnlockedVault.Vernichtung.cs"] = ["HelloMaterialNeededException"],
    };

    [GeneratedRegex(@"\bConsole\s*\.")] private static partial Regex ConsoleMuster();
    [GeneratedRegex(@"\bDebug\s*\.\s*(Write|Print|Assert|Fail)")] private static partial Regex DebugMuster();
    [GeneratedRegex(@"\bTrace\s*\.")] private static partial Regex TraceMuster();
    [GeneratedRegex(@"\bDebugger\s*\.")] private static partial Regex DebuggerMuster();
    [GeneratedRegex(@"\bEnvironment\s*\.\s*FailFast")] private static partial Regex FailFastMuster();
    [GeneratedRegex(@"\b\w+Exception\s*\.\s*ThrowIf")] private static partial Regex ThrowIfMuster();
    [GeneratedRegex(@"\bthrow\s+new\s+([\w.]+)")] private static partial Regex WurfMuster();

    [Fact]
    public void Kern_ohne_Ausgaben_und_nur_SiegelException_nach_aussen()
    {
        var paket = Testdaten.Paket();
        Assert.NotNull(paket);
        var ordner = Path.Combine(paket!, "windows", "src", "Siegel.Core");
        var trenner = Path.DirectorySeparatorChar;
        var dateien = Directory.EnumerateFiles(ordner, "*.cs", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{trenner}obj{trenner}", StringComparison.Ordinal) && !p.Contains($"{trenner}bin{trenner}", StringComparison.Ordinal))
            .ToList();
        Assert.True(dateien.Count > 20);
        (string Name, Regex Muster)[] sperren =
        [
            ("Console", ConsoleMuster()), ("Debug.Write/Print", DebugMuster()), ("Trace", TraceMuster()),
            ("Debugger", DebuggerMuster()), ("Environment.FailFast", FailFastMuster()), ("ThrowIf…", ThrowIfMuster()),
        ];
        var funde = new List<string>();
        foreach (var datei in dateien)
        {
            var name = Path.GetRelativePath(ordner, datei).Replace('\\', '/');
            var text = File.ReadAllText(datei);
            foreach (var r in text.EnumerateRunes())
            {
                if (r.Value >= 0x80 && Rune.GetUnicodeCategory(r) is System.Globalization.UnicodeCategory.Control
                    or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator
                    or System.Globalization.UnicodeCategory.ParagraphSeparator or System.Globalization.UnicodeCategory.PrivateUse
                    or System.Globalization.UnicodeCategory.OtherNotAssigned)
                {
                    funde.Add($"{name}: unsichtbares Zeichen U+{r.Value:X4}");
                }
            }
            var erlaubt = Intern.GetValueOrDefault(name, []);
            var zeilen = HygieneTests.NurCode(text).Split('\n');
            for (var z = 0; z < zeilen.Length; z++)
            {
                foreach (var (sperre, muster) in sperren)
                {
                    if (muster.IsMatch(zeilen[z])) { funde.Add($"{name}:{z + 1}: {sperre}"); }
                }
                foreach (Match m in WurfMuster().Matches(zeilen[z]))
                {
                    var typ = m.Groups[1].Value.Split('.')[^1];
                    if (typ != "SiegelException" && !erlaubt.Contains(typ)) { funde.Add($"{name}:{z + 1}: fremde Ausnahme {typ}"); }
                }
            }
        }
        Assert.True(funde.Count == 0, string.Join("\n", funde));
    }

    [GeneratedRegex(@"\bNormalizationForm\b|\bIsNormalized\s*\(|\.Normalize\s*\(\s*\)")] private static partial Regex IcuNormalisierung();

    /// <summary>Befunde krypto-1/krypto-2: Kern und Werkzeuge normalisieren nie über .NET/ICU (<c>string.Normalize</c>
    /// wirft bei U+FFFE eine ArgumentException und hängt an der ICU-Version des Systems), sondern über die von Swift
    /// gemessene Tabelle (<c>SwiftNormalisierung</c>).</summary>
    [Fact]
    public void Normalisierung_nie_ueber_ICU()
    {
        var paket = Testdaten.Paket();
        Assert.NotNull(paket);
        var trenner = Path.DirectorySeparatorChar;
        var funde = new List<string>();
        foreach (var projekt in new[] { "Siegel.Core", "Siegel.Werkzeuge" })
        {
            var ordner = Path.Combine(paket!, "windows", "src", projekt);
            foreach (var datei in Directory.EnumerateFiles(ordner, "*.cs", SearchOption.AllDirectories)
                .Where(p => !p.Contains($"{trenner}obj{trenner}", StringComparison.Ordinal) && !p.Contains($"{trenner}bin{trenner}", StringComparison.Ordinal)))
            {
                var zeilen = HygieneTests.NurCode(File.ReadAllText(datei)).Split('\n');
                for (var z = 0; z < zeilen.Length; z++)
                {
                    if (IcuNormalisierung().IsMatch(zeilen[z])) { funde.Add($"{projekt}/{Path.GetFileName(datei)}:{z + 1}"); }
                }
            }
        }
        Assert.True(funde.Count == 0, "ICU-Normalisierung: " + string.Join("\n", funde));
    }

    [Fact]
    public void Freigegebene_interne_Ausnahmen_sind_nicht_oeffentlich()
    {
        // Was die Liste freigibt, darf nicht Teil der öffentlichen Schnittstelle sein (sonst gelangte es nach aussen).
        var typen = typeof(VaultStore).Assembly.GetTypes().Where(t => typeof(Exception).IsAssignableFrom(t)).ToList();
        Assert.All(typen, t => Assert.False(t.IsVisible, t.FullName));
        Assert.Contains(typen, t => t.Name == "ExistsException");
        Assert.Contains(typen, t => t.Name == "HelloMaterialNeededException");
    }
}
