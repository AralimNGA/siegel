using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Text;

namespace Siegel.Werkzeuge.Tests;

/// <summary>Findet die Testdaten (Werkzeuge/Daten) neben dieser Quelldatei bzw. oberhalb des Ausgabeordners.</summary>
internal static class Testdaten
{
    internal static string Ordner => ordner.Value;

    private static readonly Lazy<string> ordner = new(Suchen);

    private static string Suchen() => Suchen(QuellOrdner());

    private static string Suchen(string? quelle)
    {
        if (quelle is not null)
        {
            var neben = Path.Combine(quelle, "Daten");
            if (Directory.Exists(neben)) { return neben; }
        }
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var kandidat = Path.Combine(dir.FullName, "tests", "Siegel.Core.Tests", "Werkzeuge", "Daten");
            if (Directory.Exists(kandidat)) { return kandidat; }
            kandidat = Path.Combine(dir.FullName, "windows", "tests", "Siegel.Core.Tests", "Werkzeuge", "Daten");
            if (Directory.Exists(kandidat)) { return kandidat; }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Werkzeuge/Daten");
    }

    private static string? QuellOrdner([CallerFilePath] string pfad = "") => Path.GetDirectoryName(pfad);

    /// <summary>Paketordner (enthält Package.swift und windows/).</summary>
    internal static string? Paket()
    {
        var dir = new DirectoryInfo(Ordner);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Package.swift"))) { return dir.FullName; }
            dir = dir.Parent;
        }
        return null;
    }

    internal static string Text(string name)
    {
        var pfad = Path.Combine(Ordner, name);
        if (!name.EndsWith(".gz", StringComparison.Ordinal)) { return File.ReadAllText(pfad, Encoding.UTF8); }
        using var datei = File.OpenRead(pfad);
        using var gzip = new GZipStream(datei, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    /// <summary>Datensätze (Zeilen ohne '#'), Felder Base64-dekodiert.</summary>
    internal static List<string[]> Base64Datensaetze(string name)
    {
        var result = new List<string[]>();
        foreach (var zeile in Zeilen(name))
        {
            var felder = zeile.Split('\t');
            result.Add([.. felder.Select(f => Encoding.UTF8.GetString(Convert.FromBase64String(f)))]);
        }
        return result;
    }

    /// <summary>Zeilen ohne Kommentare; die Datei endet mit einem Umbruch (leere Zeilen sind Datensätze).</summary>
    internal static List<string> Zeilen(string name)
    {
        var zeilen = Text(name).Split('\n').ToList();
        if (zeilen.Count > 0 && zeilen[^1].Length == 0) { zeilen.RemoveAt(zeilen.Count - 1); }
        return [.. zeilen.Where(z => !z.StartsWith('#'))];
    }

    internal static Dictionary<string, string> Kopfwerte(string name)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var zeile in Text(name).Split('\n'))
        {
            if (!zeile.StartsWith("# ", StringComparison.Ordinal)) { continue; }
            var gleich = zeile.IndexOf('=', StringComparison.Ordinal);
            if (gleich > 2 && !zeile[2..gleich].Contains(' ', StringComparison.Ordinal)) { result[zeile[2..gleich]] = zeile[(gleich + 1)..]; }
        }
        return result;
    }
}
