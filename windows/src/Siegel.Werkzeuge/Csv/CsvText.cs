using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge;

/// <summary>Text-Hilfen für CSV und TOTP (wie <c>CSVText</c> auf dem Mac).</summary>
internal static class CsvText
{
    /// <summary>Steuer- und Bidi-Zeichen nach SPEC §8: U+0000–001F, U+007F, U+200E/200F, U+202A–202E, U+2066–2069.</summary>
    internal static bool IsControlOrBidi(int scalar) =>
        scalar is (>= 0x0000 and <= 0x001F) or 0x007F or 0x200E or 0x200F or (>= 0x202A and <= 0x202E)
            or (>= 0x2066 and <= 0x2069);

    internal static bool ContainsControlOrBidi(string text) => SwiftText.EnthaeltSkalar(text, IsControlOrBidi);

    internal static string StrippingControlAndBidi(string text) => SwiftText.OhneSkalare(text, IsControlOrBidi);

    /// <summary>Firefox: Millisekunden seit 1970 als ganze Zahl 0…253402300799999 (bis Ende Jahr 9999).</summary>
    internal static DateTimeOffset? DateFromMilliseconds(string text)
    {
        if (text.Length == 0 || text.Length > 15) { return null; }
        long ms = 0;
        foreach (var c in text)
        {
            if (c is < '0' or > '9') { return null; }
            ms = ms * 10 + (c - '0');
        }
        if (ms > 253_402_300_799_999) { return null; }
        return DateTimeOffset.FromUnixTimeMilliseconds(ms);
    }

    /// <summary>Titel aus der URL: Host ohne <c>www.</c>, klein. Ohne Schema wird <c>https://</c> versucht.
    /// Hosts mit Zeichen ausserhalb ASCII/Latein werden als Punycode gezeigt. Kein Host → die URL selbst.</summary>
    internal static string TitleFromUrl(string url)
    {
        var trimmed = SwiftText.Trimmen(url, SwiftText.IstLeerzeichen);
        var host = HostOf(trimmed);
        if (host is null && !SwiftText.EnthaeltFolge(trimmed, "://")) { host = HostOf("https://" + trimmed); }
        if (string.IsNullOrEmpty(host)) { return url; }
        var name = SwiftText.Klein(host);
        if (name.StartsWith("www.", StringComparison.Ordinal) && SwiftText.Zeichenzahl(name) > 4) { name = name[4..]; }
        return name;
    }

    private static string? HostOf(string text)
    {
        if (!UrlHost.Zerlegen(text, out var teile)) { return null; }
        var unicodeHost = UrlHost.UnicodeForm(teile);
        if (string.IsNullOrEmpty(unicodeHost)) { return null; }
        if (SwiftText.Skalare(unicodeHost).All(IsLatinOrAscii)) { return unicodeHost; }
        // Gemischte/fremde Schriftsysteme: Punycode-Form
        return UrlHost.AceForm(teile) ?? unicodeHost;
    }

    private static bool IsLatinOrAscii(int scalar) =>
        scalar is (>= 0x0000 and <= 0x007F) or (>= 0x00C0 and <= 0x00D6) or (>= 0x00D8 and <= 0x00F6) or (>= 0x00F8 and <= 0x024F);
}
