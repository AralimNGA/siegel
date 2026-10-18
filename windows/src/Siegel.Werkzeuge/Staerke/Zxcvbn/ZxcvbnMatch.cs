namespace Siegel.Werkzeuge.Staerke.Zxcvbn;

// Gemeinsame Typen und Rechenhilfen der zxcvbn-Schätzung (Port von zxcvbn 4.4.2, Dropbox, MIT), bit-gleich zur
// Swift-Fassung Sources/SiegelCore/Staerke/Zxcvbn/ZxcvbnMatch.swift. Alle Rateversuche als log2.

/// <summary>Muster einer Erkennung.</summary>
internal enum ZxcvbnPattern
{
    Dictionary, Spatial, Repeated, Sequence, Year, Date, Bruteforce,
    /// <summary>Siegel-Erweiterung: Kette aus Wörtern der eigenen Passphrasen-Liste.</summary>
    Passphrase,
    /// <summary>Siegel-Erweiterung: Wortfolge mit Trennzeichen („Mein Hund heisst Bello“).</summary>
    Phrase,
    /// <summary>Siegel-Erweiterung (Befund #18): Grundwort mit hochzählender Zahl.</summary>
    Counter,
    /// <summary>Siegel-Erweiterung (Befund #18): Wochentage oder Monate in Folge.</summary>
    Calendar,
    /// <summary>Siegel-Erweiterung (Befund #18): Ort mit Postleitzahl.</summary>
    PlaceCode,
}

/// <summary>Ein erkanntes Muster über password[I…J] (Zeichen = Graphem-Cluster) mit seiner Schätzung.</summary>
internal readonly record struct ZxcvbnMatch(ZxcvbnPattern Pattern, int I, int J, double Log2Guesses)
{
    internal int Length => J - I + 1;
}

/// <summary>Rechenhilfen (Logarithmen zur Basis 2).</summary>
internal static class ZxcvbnMath
{
    internal static readonly double Log2Of10 = Math.Log2(10);

    /// <summary>Binomialkoeffizient n über k als Double.</summary>
    internal static double NCk(int n, int k)
    {
        if (k < 0 || k > n) { return 0; }
        if (k == 0 || k == n) { return 1; }
        var kk = Math.Min(k, n - k);
        var r = 1.0;
        double top = n;
        for (var d = 1; d <= kk; d++)
        {
            r *= top;
            r /= d;
            top -= 1;
        }
        return r;
    }

    /// <summary>log2 des Binomialkoeffizienten n über k (über ln Γ).</summary>
    internal static double Log2Binomial(int n, int k)
    {
        if (k <= 0 || k >= n) { return 0; }
        return (LnGamma(n + 1.0) - LnGamma(k + 1.0) - LnGamma(n - k + 1.0)) / Math.Log(2);
    }

    /// <summary>log2(2^a + 2^b) ohne Überlauf.</summary>
    internal static double LogAdd(double a, double b)
    {
        var hi = Math.Max(a, b);
        var lo = Math.Min(a, b);
        if (double.IsNegativeInfinity(lo)) { return hi; }
        return hi + Math.Log2(1 + Math.Pow(2, lo - hi));
    }

    /// <summary>log2(l!) für kleine l per Tabelle (wie Swift aufsummiert), sonst über ln Γ.</summary>
    internal static double Log2Factorial(int l)
    {
        if (l < 2) { return 0; }
        if (l < FactorialTable.Length) { return FactorialTable[l]; }
        return LnGamma(l + 1.0) / Math.Log(2);
    }

    private static readonly double[] FactorialTable = FactorialTableAnlegen();

    private static double[] FactorialTableAnlegen()
    {
        var table = new double[300];
        var acc = 0.0;
        for (var l = 2; l < table.Length; l++)
        {
            acc += Math.Log2(l);
            table[l] = acc;
        }
        return table;
    }

    /// <summary>
    /// ln Γ(x) für x ≥ 1 (Swift ruft <c>lgamma</c> der C-Bibliothek). Ganze Argumente bis 1024 aus einer Tabelle
    /// ln((n−1)!) mit kompensierter Summation (Fehler unter 1e-13), sonst Stirling-Reihe. .NET hat kein lgamma.
    /// </summary>
    internal static double LnGamma(double x)
    {
        if (x >= 1 && x < LnFactorials.Length + 1 && Math.Floor(x) == x) { return LnFactorials[(int)x - 1]; }
        // Stirling mit Bernoulli-Gliedern (für x > 10 auf Maschinengenauigkeit), kleine x per Rekursion hochschieben
        var shift = 0.0;
        while (x < 10)
        {
            shift -= Math.Log(x);
            x += 1;
        }
        var inv = 1 / x;
        var inv2 = inv * inv;
        var series = inv * (1.0 / 12 - inv2 * (1.0 / 360 - inv2 * (1.0 / 1260 - inv2 * (1.0 / 1680 - inv2 / 1188))));
        return shift + (x - 0.5) * Math.Log(x) - x + 0.5 * Math.Log(2 * Math.PI) + series;
    }

    /// <summary>ln(n!) für n = 0…1023 (Index n), Kahan-summiert.</summary>
    private static readonly double[] LnFactorials = LnFactorialsAnlegen();

    private static double[] LnFactorialsAnlegen()
    {
        var table = new double[1024];
        var sum = 0.0;
        var c = 0.0;
        for (var n = 1; n < table.Length; n++)
        {
            var y = Math.Log(n) - c;
            var t = sum + y;
            c = t - sum - y;
            sum = t;
            table[n] = sum;
        }
        return table;
    }
}
