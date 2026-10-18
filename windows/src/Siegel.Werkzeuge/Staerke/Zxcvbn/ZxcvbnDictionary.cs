using System.IO.Compression;
using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Staerke.Zxcvbn;

/// <summary>
/// Die gebündelten Wortlisten als eingebettete Ressourcen (Staerke/Listen/NAME.txt.gz), erzeugt von
/// windows/skripte/listen_exportieren.py aus den Swift-Listen (eine Quelle). Eine Zeile je Eintrag, kleingeschrieben,
/// nach Häufigkeit sortiert; Tabulator trennt Schreibvarianten mit gleichem Rang.
/// </summary>
internal static class ZxcvbnListData
{
    internal static byte[] Lesen(string name)
    {
        using var stream = typeof(ZxcvbnListData).Assembly.GetManifestResourceStream($"Siegel.Werkzeuge.Staerke.Listen.{name}.txt.gz")
            ?? throw new SiegelException(SiegelErrorCode.Io, "resource.list");
        using var gzip = new GZipStream(stream, CompressionMode.Decompress);
        using var ziel = new MemoryStream();
        gzip.CopyTo(ziel);
        return ziel.ToArray();
    }

    internal readonly record struct Field(string Word, int Bytes);

    /// <summary>Ruft <paramref name="body"/>(Zeilennummer, Felder) für jede nicht leere Zeile auf (wie Swift
    /// <c>forEachLine</c>, auf UTF-8-Bytes).</summary>
    internal static void ForEachLine(byte[] text, Action<int, List<Field>> body)
    {
        var index = 0;
        var start = 0;
        var fields = new List<Field>();
        var fieldStart = 0;
        var count = text.Length;
        for (var position = 0; position <= count; position++)
        {
            var b = position < count ? text[position] : (byte)0x0A;
            if (b == 0x09 || b == 0x0A)
            {
                if (position > fieldStart)
                {
                    fields.Add(new Field(Encoding.UTF8.GetString(text, fieldStart, position - fieldStart), position - fieldStart));
                }
                fieldStart = position + 1;
                if (b == 0x0A)
                {
                    if (position > start && fields.Count > 0)
                    {
                        body(index, fields);
                        index++;
                    }
                    fields = [];
                    start = position + 1;
                }
            }
        }
    }

    /// <summary>Vorn-komprimierte Liste: erstes Zeichen jeder Zeile = Länge des gemeinsamen Anfangs mit dem
    /// Vorgängerwort (0–9, a–z = 10–35), danach der Rest.</summary>
    internal static void ForEachFrontCoded(byte[] text, Action<string, int> body)
    {
        var previous = new List<byte>();
        var current = new List<byte>();
        var lineStart = 0;
        var count = text.Length;
        for (var position = 0; position <= count; position++)
        {
            var b = position < count ? text[position] : (byte)0x0A;
            if (b != 0x0A) { continue; }
            if (position > lineStart)
            {
                var code = text[lineStart];
                var shared = 0;
                if (code is >= 48 and <= 57) { shared = code - 48; }
                else if (code is >= 97 and <= 122) { shared = code - 97 + 10; }
                shared = Math.Min(shared, previous.Count);
                current.Clear();
                for (var i = 0; i < shared; i++) { current.Add(previous[i]); }
                for (var i = lineStart + 1; i < position; i++) { current.Add(text[i]); }
                var bytes = current.ToArray();
                body(Encoding.UTF8.GetString(bytes), bytes.Length);
                (previous, current) = (current, previous);
            }
            lineStart = position + 1;
        }
    }

    /// <summary>Erstes Feld jeder Zeile (für die Passphrasen-Wörter).</summary>
    internal static List<string> Lines(byte[] text)
    {
        var result = new List<string>();
        ForEachLine(text, (_, fields) => result.Add(fields[0].Word));
        return result;
    }
}

/// <summary>Alle Listen als ein Wörterbuch Wort → Rang (kleinster Rang über alle Listen), einmal aufgebaut.</summary>
internal sealed class ZxcvbnDictionary
{
    /// <summary>Uniformer Rang der englischen Zusatzwörter aus web2.</summary>
    internal const int Web2Rank = 150_000;
    /// <summary>Uniformer Rang der Passphrasen-Wörter.</summary>
    internal const int PassphraseRank = 2048;

    private static readonly Lazy<ZxcvbnDictionary> shared = new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    internal static ZxcvbnDictionary Shared => shared.Value;

    private ZxcvbnDictionary(Dictionary<string, int> ranks, int maxWordLength)
    {
        Ranks = ranks;
        Lookup = ranks.GetAlternateLookup<ReadOnlySpan<char>>();
        MaxWordLength = maxWordLength;
    }

    /// <summary>Rang = geschätzte Zahl Versuche, bis ein Angreifer das Wort erreicht.</summary>
    internal Dictionary<string, int> Ranks { get; }

    internal Dictionary<string, int>.AlternateLookup<ReadOnlySpan<char>> Lookup { get; }

    /// <summary>Längstes Wort in UTF-8-Bytes (obere Schranke für die Zeichenzahl).</summary>
    internal int MaxWordLength { get; }

    private enum Mode { Ranked, Uniform, FrontCoded }

    private static readonly (string Name, Mode Mode, int Rank)[] Sources =
    [
        ("passwords", Mode.Ranked, 0),
        ("passwordsGerman", Mode.Ranked, 0),
        ("englishWikipedia", Mode.Ranked, 0),
        ("usTvAndFilm", Mode.Ranked, 0),
        ("germanWords", Mode.Ranked, 0),
        ("surnames", Mode.Ranked, 0),
        ("maleNames", Mode.Ranked, 0),
        ("femaleNames", Mode.Ranked, 0),
        ("firstNamesCHDE", Mode.Ranked, 0),
        ("surnamesCHDE", Mode.Ranked, 0),
        ("placesCH", Mode.Ranked, 0),
        ("passphraseWords", Mode.Uniform, PassphraseRank),
        ("englishWeb2", Mode.FrontCoded, Web2Rank),
    ];

    private static ZxcvbnDictionary Load()
    {
        var ranks = new Dictionary<string, int>(320_000, StringComparer.Ordinal);
        var maxLength = 0;
        void Insert(string word, int rank, int byteCount)
        {
            if (ranks.TryGetValue(word, out var old) && old <= rank) { return; }
            ranks[word] = rank;
            if (byteCount > maxLength) { maxLength = byteCount; }
        }
        foreach (var (name, mode, rank) in Sources)
        {
            var text = ZxcvbnListData.Lesen(name);
            switch (mode)
            {
                case Mode.Ranked:
                    ZxcvbnListData.ForEachLine(text, (index, fields) =>
                    {
                        foreach (var f in fields) { Insert(f.Word, index + 1, f.Bytes); }
                    });
                    break;
                case Mode.Uniform:
                    ZxcvbnListData.ForEachLine(text, (_, fields) =>
                    {
                        foreach (var f in fields) { Insert(f.Word, rank, f.Bytes); }
                    });
                    break;
                default:
                    ZxcvbnListData.ForEachFrontCoded(text, (word, bytes) => Insert(word, rank, bytes));
                    break;
            }
        }
        return new ZxcvbnDictionary(ranks, maxLength);
    }
}
