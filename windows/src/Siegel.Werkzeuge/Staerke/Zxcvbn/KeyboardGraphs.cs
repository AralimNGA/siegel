using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge.Staerke.Zxcvbn;

// Adjazenzgraphen der Tastaturen wie Sources/SiegelCore/Staerke/Zxcvbn/KeyboardGraphs.swift (zxcvbn
// build_keyboard_adjacency_graphs.py, selbst aufgebaut). Jede Taste ist ein Token „unverschoben verschoben“, die Zeilen
// sind wie auf der Tastatur je um ein Zeichen eingerückt; Ziffernblöcke stehen gerade.

internal sealed class KeyboardGraph
{
    internal KeyboardGraph(string name, bool isKeypad, Dictionary<Zeichen, Zeichen[]?[]> neighbors,
        HashSet<Zeichen> shifted, List<string> misaligned)
    {
        Name = name;
        IsKeypad = isKeypad;
        Neighbors = neighbors;
        Shifted = shifted;
        MisalignedTokens = misaligned;
        StartingPositions = neighbors.Count;
        var degreeSum = 0;
        foreach (var adj in neighbors.Values)
        {
            foreach (var a in adj) { if (a is not null) { degreeSum++; } }
        }
        AverageDegree = (double)degreeSum / Math.Max(1, neighbors.Count);
    }

    internal string Name { get; }
    internal bool IsKeypad { get; }
    /// <summary>Nachbartasten je Zeichen in fester Richtungsreihenfolge (null = keine Taste).</summary>
    internal Dictionary<Zeichen, Zeichen[]?[]> Neighbors { get; }
    /// <summary>Zeichen, die nur mit Umschalttaste entstehen.</summary>
    internal HashSet<Zeichen> Shifted { get; }
    internal double StartingPositions { get; }
    internal double AverageDegree { get; }
    /// <summary>Für Tests: Tokens, deren Spalte nicht auf das Raster fällt (muss leer sein).</summary>
    internal List<string> MisalignedTokens { get; }
}

internal static class KeyboardGraphs
{
    /// <summary>QWERTY (US), wie in zxcvbn.</summary>
    internal const string QwertyLayout =
        "`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) -_ =+\n" +
        "    qQ wW eE rR tT yY uU iI oO pP [{ ]} \\|\n" +
        "     aA sS dD fF gG hH jJ kK lL ;: '\"\n" +
        "      zZ xX cC vV bB nN mM ,< .> /?";

    /// <summary>QWERTZ Schweiz (ISO, mit Taste &lt;&gt; links von Y).</summary>
    internal const string QwertzCHLayout =
        "§° 1+ 2\" 3* 4ç 5% 6& 7/ 8( 9) 0= '? ^`\n" +
        "    qQ wW eE rR tT zZ uU iI oO pP üè ¨!\n" +
        "     aA sS dD fF gG hH jJ kK lL öé äà $£\n" +
        "   <> yY xX cC vV bB nN mM ,; .: -_";

    /// <summary>Ziffernblock (PC).</summary>
    internal const string KeypadLayout =
        "  / * -\n" +
        "7 8 9 +\n" +
        "4 5 6\n" +
        "1 2 3\n" +
        "  0 .";

    /// <summary>Ziffernblock (Mac).</summary>
    internal const string MacKeypadLayout =
        "  = / *\n" +
        "7 8 9 -\n" +
        "4 5 6 +\n" +
        "1 2 3\n" +
        "  0 .";

    internal static readonly KeyboardGraph[] All =
    [
        Build("qwerty", QwertyLayout, slanted: true),
        Build("qwertz_ch", QwertzCHLayout, slanted: true),
        Build("keypad", KeypadLayout, slanted: false),
        Build("mac_keypad", MacKeypadLayout, slanted: false),
    ];

    internal static KeyboardGraph Build(string name, string layout, bool slanted)
    {
        var table = new Dictionary<(int X, int Y), Zeichen[]>();
        var misaligned = new List<string>();
        var tokenSize = 0;
        var lines = layout.Split('\n');
        for (var row = 0; row < lines.Length; row++)
        {
            var y = row + 1;                                   // zxcvbn zählt ab 1
            var slant = slanted ? y - 1 : 0;
            var chars = Graphemzerlegung.Grenzen(lines[row]);
            var texts = new string[chars.Length - 1];
            for (var i = 0; i < texts.Length; i++) { texts[i] = lines[row][chars[i]..chars[i + 1]]; }
            var col = 0;
            while (col < texts.Length)
            {
                if (texts[col] == " ")
                {
                    col++;
                    continue;
                }
                var end = col;
                while (end < texts.Length && texts[end] != " ") { end++; }
                var token = new Zeichen[end - col];
                for (var t = 0; t < token.Length; t++) { token[t] = Zeichenvorrat.Fest(texts[col + t]); }
                if (tokenSize == 0) { tokenSize = token.Length; }
                var unit = tokenSize + 1;
                var offset = col - slant;
                if (offset < 0 || offset % unit != 0 || token.Length != tokenSize)
                {
                    misaligned.Add(string.Concat(texts[col..end]));
                }
                else
                {
                    table[(offset / unit, y)] = token;
                }
                col = end;
            }
        }

        (int X, int Y)[] Adjacent((int X, int Y) p)
        {
            var (x, yy) = p;
            if (slanted)
            {
                return [(x - 1, yy), (x, yy - 1), (x + 1, yy - 1), (x + 1, yy), (x, yy + 1), (x - 1, yy + 1)];
            }
            return [(x - 1, yy), (x - 1, yy - 1), (x, yy - 1), (x + 1, yy - 1), (x + 1, yy), (x + 1, yy + 1),
                (x, yy + 1), (x - 1, yy + 1)];
        }

        var neighbors = new Dictionary<Zeichen, Zeichen[]?[]>(ReferenceEqualityComparer.Instance);
        var shifted = new HashSet<Zeichen>(ReferenceEqualityComparer.Instance);
        foreach (var (pos, token) in table)
        {
            var adjacent = Adjacent(pos);
            var adj = new Zeichen[]?[adjacent.Length];
            for (var a = 0; a < adjacent.Length; a++) { adj[a] = table.GetValueOrDefault(adjacent[a]); }
            for (var index = 0; index < token.Length; index++)
            {
                neighbors[token[index]] = adj;
                if (slanted && index == 1) { shifted.Add(token[index]); }
            }
        }
        return new KeyboardGraph(name, !slanted, neighbors, shifted, misaligned);
    }
}
