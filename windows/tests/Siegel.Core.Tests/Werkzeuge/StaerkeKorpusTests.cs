using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Siegel.Werkzeuge.Staerke.Zxcvbn;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Tests;

/// <summary>
/// SPEC-WINDOWS W7: Die Stärke-Schätzung ist bit-gleich zur Swift-Referenz. Korpus und Erwartungswerte erzeugt
/// windows/skripte/korpus_erzeugen.py (Swift: SiegelStaerkeExport bewerten, Bezugsjahr fest). Für JEDES Passwort:
/// |Δ bits| ≤ 1e-9, gleiche Stufe, gleiche Zeichenzahl, gleiches Ergebnis der Master-Passwort-Regel.
/// </summary>
public class StaerkeKorpusTests
{
    [Fact]
    public void JedesPasswortBitGleichZuSwift()
    {
        var faelle = Testdaten.Base64Datensaetze("staerke_korpus.txt.gz");
        var erwartet = Testdaten.Zeilen("staerke_erwartet.txt.gz");
        var jahr = int.Parse(Testdaten.Kopfwerte("staerke_erwartet.txt.gz")["jahr"], CultureInfo.InvariantCulture);
        Assert.True(faelle.Count >= 10_000, $"Korpus zu klein: {faelle.Count}");
        Assert.Equal(faelle.Count, erwartet.Count);

        var fehler = new List<string>();
        var maxDelta = 0.0;
        for (var i = 0; i < faelle.Count; i++)
        {
            var passwort = faelle[i][0];
            var eingaben = faelle[i][1..];
            var teile = erwartet[i].Split('\t');
            var bits = double.Parse(teile[0], CultureInfo.InvariantCulture);
            var stufe = int.Parse(teile[1], CultureInfo.InvariantCulture);
            var zeichen = int.Parse(teile[2], CultureInfo.InvariantCulture);
            var regel = teile[3] == "1";

            var analyse = PasswordStrength.Analyze(passwort, eingaben, jahr);
            var normalisiert = MasterPasswordPolicy.Normalized(passwort);
            var anzahl = SwiftText.Zeichenzahl(normalisiert);
            var ok = MasterPasswordPolicy.Satisfied(normalisiert, analyse.Bits);
            var delta = Math.Abs(analyse.Bits - bits);
            maxDelta = Math.Max(maxDelta, delta);
            if (!(delta <= 1e-9) || (int)PasswordStrength.LevelForBits(analyse.Bits) != stufe || anzahl != zeichen || ok != regel)
            {
                fehler.Add($"Fall {i + 1}: Swift {bits.ToString("R", CultureInfo.InvariantCulture)}/{stufe}/{zeichen}/{regel}, "
                    + $"C# {analyse.Bits.ToString("R", CultureInfo.InvariantCulture)}/{(int)PasswordStrength.LevelForBits(analyse.Bits)}/{anzahl}/{ok}");
            }
        }
        Assert.True(fehler.Count == 0, $"{fehler.Count} Abweichungen (max Δ {maxDelta}):\n" + string.Join("\n", fehler.Take(40)));
    }

    [Fact]
    public void GraphemGrenzenWieSwift()
    {
        var faelle = Testdaten.Base64Datensaetze("graphem_korpus.txt.gz");
        var erwartet = Testdaten.Zeilen("graphem_erwartet.txt.gz");
        Assert.Equal(faelle.Count, erwartet.Count);
        var fehler = new List<string>();
        for (var i = 0; i < faelle.Count; i++)
        {
            var grenzen = Graphemzerlegung.Grenzen(faelle[i][0]);
            var laengen = string.Join(",", Enumerable.Range(0, grenzen.Length - 1).Select(k => grenzen[k + 1] - grenzen[k]));
            if (laengen != erwartet[i])
            {
                var skalare = string.Join(" ", SwiftText.Skalare(faelle[i][0]).Select(s => s.ToString("X4", CultureInfo.InvariantCulture)));
                fehler.Add($"Fall {i + 1} [{skalare}]: Swift {erwartet[i]}, C# {laengen}");
            }
        }
        Assert.True(fehler.Count == 0, $"{fehler.Count} Abweichungen:\n" + string.Join("\n", fehler.Take(40)));
    }

    /// <summary>Die Listen sind dieselben, die Swift kompiliert hat (Prüfsummen aus SiegelStaerkeExport kennzahlen),
    /// und das Wörterbuch ergibt dieselben Kennzahlen.</summary>
    [Fact]
    public void ListenUndKennzahlenWieSwift()
    {
        var zeilen = Testdaten.Zeilen("swift_kennzahlen.txt");
        var listen = 0;
        foreach (var zeile in zeilen)
        {
            var teile = zeile.Split(' ');
            switch (teile[0])
            {
                case "liste":
                    var daten = ZxcvbnListData.Lesen(teile[1]);
                    Assert.Equal(int.Parse(teile[2], CultureInfo.InvariantCulture), daten.Length);
                    Assert.Equal(teile[3], Convert.ToHexStringLower(SHA256.HashData(daten)));
                    listen++;
                    break;
                case "woerter":
                    Assert.Equal(int.Parse(teile[1], CultureInfo.InvariantCulture), ZxcvbnDictionary.Shared.Ranks.Count);
                    break;
                case "maxWortLaenge":
                    Assert.Equal(int.Parse(teile[1], CultureInfo.InvariantCulture), ZxcvbnDictionary.Shared.MaxWordLength);
                    break;
                case "rangSumme":
                    ulong summe = 0;
                    foreach (var r in ZxcvbnDictionary.Shared.Ranks.Values) { summe += (ulong)r; }
                    Assert.Equal(ulong.Parse(teile[1], CultureInfo.InvariantCulture), summe);
                    break;
                case "passphrase":
                    Assert.Equal(int.Parse(teile[1], CultureInfo.InvariantCulture), PassphraseGenerator.Words.Count);
                    Assert.Equal(teile[2], Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", PassphraseGenerator.Words)))));
                    break;
                case "orte":
                    Assert.Equal(int.Parse(teile[1], CultureInfo.InvariantCulture), ZxcvbnMatcher.PlaceRanks.Count);
                    Assert.Equal(int.Parse(teile[2], CultureInfo.InvariantCulture), ZxcvbnMatcher.PlaceMaxLength);
                    break;
                case "graph":
                    var g = KeyboardGraphs.All.Single(x => x.Name == teile[1]);
                    Assert.Equal(double.Parse(teile[2], CultureInfo.InvariantCulture), g.StartingPositions);
                    Assert.Equal(double.Parse(teile[3], CultureInfo.InvariantCulture), g.AverageDegree);
                    Assert.Equal(int.Parse(teile[4], CultureInfo.InvariantCulture), g.Shifted.Count);
                    Assert.Equal(int.Parse(teile[5], CultureInfo.InvariantCulture), g.MisalignedTokens.Count);
                    break;
                default:
                    break;
            }
        }
        Assert.Equal(13, listen);
    }

    /// <summary>MasterPasswordPolicy.UserInputs gleich wie Swift (userInputs(userName:fullName:)).</summary>
    [Fact]
    public void BenutzereingabenWieSwift()
    {
        var erwartet = Testdaten.Zeilen("swift_kennzahlen.txt").Where(z => z.StartsWith("benutzer ", StringComparison.Ordinal))
            .Select(z => z.Split(' ').Skip(1).Select(b => Encoding.UTF8.GetString(Convert.FromBase64String(b))).ToList()).ToList();
        Assert.Equal(2, erwartet.Count);
        Assert.Equal(erwartet[0], MasterPasswordPolicy.UserInputs("jmueller", "Jürg Müller-Zbinden"));
        Assert.Equal(erwartet[1], MasterPasswordPolicy.UserInputs("Aralim", "Aralim Ößtürk İnan-Çelik"));
    }
}
