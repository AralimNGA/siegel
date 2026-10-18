using System.Text;

namespace Siegel.Werkzeuge.Tests;

/// <summary>
/// Gegenprobe mit Swift/Foundation (Werte aus SiegelStaerkeExport autofill/titel, erzeugt von korpus_erzeugen.py):
/// AutofillMatcher und der CSV-Titel aus der URL entscheiden für jede Adresse gleich wie auf dem Mac, auch bei
/// IDNA, Punycode-Doppelgängern, IPv6, Ports, Benutzerinfo und Zufallseingaben. Hinweis: IDNA läuft in .NET über die
/// Plattform (ICU bzw. Windows); weicht Windows bei exotischen Hosts ab, zeigt dieser Test es.
/// </summary>
public class AdressKorpusTests
{
    private static string Sichtbar(string s) =>
        string.Concat(s.Select(c => c is < ' ' or > '~' ? $"\\u{(int)c:X4}" : c.ToString()));

    [Fact]
    public void AutofillWieSwift()
    {
        var faelle = Testdaten.Base64Datensaetze("autofill_korpus.txt.gz");
        var erwartet = Testdaten.Zeilen("autofill_erwartet.txt.gz");
        Assert.Equal(faelle.Count, erwartet.Count);
        Assert.True(faelle.Count >= 10_000);
        var fehler = new List<string>();
        for (var i = 0; i < faelle.Count; i++)
        {
            var treffer = AutofillMatcher.Matches(faelle[i][0], faelle[i][1]) ? "1" : "0";
            if (treffer != erwartet[i])
            {
                fehler.Add($"Fall {i + 1}: Swift {erwartet[i]}, C# {treffer}: {Sichtbar(faelle[i][0])} | {Sichtbar(faelle[i][1])}");
            }
        }
        Assert.True(fehler.Count == 0, $"{fehler.Count} Abweichungen:\n" + string.Join("\n", fehler.Take(30)));
        Assert.Contains("1", erwartet);
    }

    [Fact]
    public void CsvTitelWieSwift()
    {
        var faelle = Testdaten.Base64Datensaetze("titel_korpus.txt.gz");
        var erwartet = Testdaten.Zeilen("titel_erwartet.txt.gz").Select(z => Encoding.UTF8.GetString(Convert.FromBase64String(z))).ToList();
        Assert.Equal(faelle.Count, erwartet.Count);
        var fehler = new List<string>();
        for (var i = 0; i < faelle.Count; i++)
        {
            var titel = CsvText.TitleFromUrl(faelle[i][0]);
            if (titel != erwartet[i])
            {
                fehler.Add($"Fall {i + 1}: {Sichtbar(faelle[i][0])}: Swift {Sichtbar(erwartet[i])}, C# {Sichtbar(titel)}");
            }
        }
        Assert.True(fehler.Count == 0, $"{fehler.Count} Abweichungen:\n" + string.Join("\n", fehler.Take(30)));
    }
}
