namespace Siegel.Werkzeuge.Unicode;

/// <summary>
/// Gleichheit wie Swift-<c>String</c> (<c>==</c>, <c>Set&lt;String&gt;</c>, <c>Dictionary</c>-Schlüssel): kanonische
/// Äquivalenz, also <c>"e\u0301" == "\u00E9"</c> (Befund krypto-4). Ohne Abbildung der Leerzeichen (Swift hält „a b“ mit
/// U+00A0 und „a b“ für verschieden). Ausnahmefrei auch bei U+FFFE; Schlüssel aus <see cref="SwiftNormalisierung"/>.
/// </summary>
internal sealed class SwiftStringComparer : IEqualityComparer<string>
{
    internal static SwiftStringComparer Instance { get; } = new();

    private SwiftStringComparer()
    {
    }

    public bool Equals(string? x, string? y)
    {
        if (ReferenceEquals(x, y)) { return true; }
        if (x is null || y is null) { return false; }
        if (string.Equals(x, y, StringComparison.Ordinal)) { return true; }
        return string.Equals(SwiftNormalisierung.SchluesselSwift(x), SwiftNormalisierung.SchluesselSwift(y), StringComparison.Ordinal);
    }

    public int GetHashCode(string obj) =>
        obj is null ? 0 : StringComparer.Ordinal.GetHashCode(SwiftNormalisierung.SchluesselSwift(obj));
}
