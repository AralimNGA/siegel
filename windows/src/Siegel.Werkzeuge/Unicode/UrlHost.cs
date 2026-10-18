using System.Globalization;
using System.Text;

namespace Siegel.Werkzeuge.Unicode;

/// <summary>
/// Schema, Host und Port einer Adresse, so wie Foundation sie auf dem Mac liefert (gemessen auf macOS 26):
/// <c>URLComponents(string:).host</c> (Unicode-Form: Prozent-Kodierung aufgelöst, Nicht-ASCII nach UTS #46 abgebildet,
/// ASCII mit xn--Teilen dekodiert, sonst unverändert) und <c>URL.host(percentEncoded: false)</c> (ACE/Punycode für
/// Nicht-ASCII, ohne Klammern bei IPv6). Strenge nur, wo Foundation streng ist: Host- und Port-Syntax; Pfad, Abfrage
/// und Benutzerinfo dürfen fast alles enthalten (Foundation kodiert sie still).
/// IDNA über <see cref="IdnMapping"/> (UTS #46, nicht-transitional, ohne STD3-Regeln wie Foundation).
/// </summary>
internal static class UrlHost
{
    /// <param name="Prozent">Der Host stand mit Prozent-Kodierung in der Adresse (<see cref="HostRoh"/> ist dekodiert).</param>
    internal readonly record struct Teile(string Scheme, string HostRoh, bool IstIPv6, long? Port, bool Prozent = false);

    /// <summary>Zerlegt nach RFC 3986 (mit Foundations Nachsicht). false = Foundation liefert keine URL; Host leer
    /// oder fehlend ergibt <see cref="Teile.HostRoh"/> = "" bzw. false bei fehlender Autorität.</summary>
    internal static bool Zerlegen(string text, out Teile teile)
    {
        teile = default;
        var scheme = "";
        var rest = text;
        var doppelpunkt = text.IndexOf(':', StringComparison.Ordinal);
        if (doppelpunkt > 0 && IstSchema(text.AsSpan(0, doppelpunkt)))
        {
            scheme = text[..doppelpunkt];
            rest = text[(doppelpunkt + 1)..];
        }
        if (!rest.StartsWith("//", StringComparison.Ordinal)) { return false; }    // keine Autorität, kein Host
        var ende = 2;
        while (ende < rest.Length && rest[ende] is not ('/' or '?' or '#')) { ende++; }
        var autoritaet = rest[2..ende];
        var at = autoritaet.LastIndexOf('@');
        var hostPort = at >= 0 ? autoritaet[(at + 1)..] : autoritaet;

        string host;
        string? portText = null;
        var ipv6 = false;
        if (hostPort.StartsWith('['))
        {
            var zu = hostPort.IndexOf(']', StringComparison.Ordinal);
            if (zu < 0) { return false; }
            host = hostPort[1..zu];
            ipv6 = true;
            var nach = hostPort[(zu + 1)..];
            if (nach.Length > 0)
            {
                if (nach[0] != ':') { return false; }
                portText = nach[1..];
            }
            foreach (var c in host)
            {
                if (!(char.IsAsciiHexDigit(c) || c is ':' or '.' or '%' or '-' or '_' or '~' || char.IsAsciiLetter(c))) { return false; }
            }
        }
        else
        {
            var p = hostPort.IndexOf(':', StringComparison.Ordinal);
            host = p >= 0 ? hostPort[..p] : hostPort;
            if (p >= 0) { portText = hostPort[(p + 1)..]; }
            if (!GueltigerRegName(host)) { return false; }
        }

        long? port = null;
        if (!string.IsNullOrEmpty(portText))
        {
            foreach (var c in portText) { if (!char.IsAsciiDigit(c)) { return false; } }
            // Überlauf: Foundation liefert die URL, aber keinen Port
            if (long.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var wert)) { port = wert; }
        }
        var dekodiert = ProzentDekodieren(host);
        if (dekodiert is null) { return false; }
        teile = new Teile(scheme, dekodiert, ipv6, port, host.Contains('%', StringComparison.Ordinal));
        return true;
    }

    private static bool IstSchema(ReadOnlySpan<char> s)
    {
        if (s.IsEmpty || !char.IsAsciiLetter(s[0])) { return false; }
        foreach (var c in s)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '+' or '-' or '.')) { return false; }
        }
        return true;
    }

    /// <summary>reg-name: unreserved, sub-delims, %XX, dazu Nicht-ASCII (IRI); kein Leerraum, keine Steuerzeichen.</summary>
    private static bool GueltigerRegName(string host)
    {
        for (var i = 0; i < host.Length; i++)
        {
            var c = host[i];
            if (c >= 0x80)
            {
                if (char.IsSurrogate(c) && !(char.IsHighSurrogate(c) && i + 1 < host.Length && char.IsLowSurrogate(host[i + 1])))
                {
                    return false;
                }
                continue;
            }
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~' or '!' or '$' or '&' or '\'' or '(' or ')'
                or '*' or '+' or ',' or ';' or '=')
            {
                continue;
            }
            if (c == '%' && i + 2 < host.Length && char.IsAsciiHexDigit(host[i + 1]) && char.IsAsciiHexDigit(host[i + 2]))
            {
                i += 2;
                continue;
            }
            return false;
        }
        return true;
    }

    private static string? ProzentDekodieren(string host)
    {
        if (!host.Contains('%', StringComparison.Ordinal)) { return host; }
        var bytes = new List<byte>();
        for (var i = 0; i < host.Length; i++)
        {
            if (host[i] == '%' && i + 2 < host.Length && char.IsAsciiHexDigit(host[i + 1]) && char.IsAsciiHexDigit(host[i + 2]))
            {
                bytes.Add(byte.Parse(host.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                i += 2;
            }
            else
            {
                var laenge = char.IsHighSurrogate(host[i]) && i + 1 < host.Length ? 2 : 1;
                bytes.AddRange(Encoding.UTF8.GetBytes(host.Substring(i, laenge)));
                i += laenge - 1;
            }
        }
        try
        {
            return new UTF8Encoding(false, true).GetString([.. bytes]);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = false };

    /// <summary>Foundation wendet IDNA nur auf Hosts bis 2048 Byte UTF-8 an (gemessen auf macOS 26.7: ein Host mit
    /// Nicht-ASCII über 2048 Byte ergibt weder <c>URLComponents.host</c> noch <c>URL.host</c>, ein ASCII-Host über 2048 Byte
    /// keine <c>URLComponents.host</c>). Darüber hier sofort null, ohne IDNA: <see cref="IdnMapping"/> (ICU) braucht für
    /// lange Folgen von Kombinationszeichen quadratische Zeit (Befund robust-7: eine URL an der 16-MiB-Grenze der CSV hätte
    /// den Import stundenlang blockiert).</summary>
    internal const int MaximumIdnaHostBytes = 2048;

    private static bool ZuLangFuerIdna(string host) =>
        host.Length > MaximumIdnaHostBytes || Encoding.UTF8.GetByteCount(host) > MaximumIdnaHostBytes;

    private static bool IstAscii(string s)
    {
        foreach (var c in s) { if (c >= 0x80) { return false; } }
        return true;
    }

    /// <summary>ACE-Form (Punycode) wie <c>URL.host(percentEncoded: false)</c>; null wenn IDNA scheitert.</summary>
    internal static string? AceForm(in Teile teile)
    {
        if (teile.IstIPv6 || IstAscii(teile.HostRoh)) { return teile.HostRoh; }
        if (ZuLangFuerIdna(teile.HostRoh)) { return null; }
        try
        {
            return Idn.GetAscii(teile.HostRoh);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Unicode-Form wie <c>URLComponents.host</c> (IPv6 mit Klammern); null wenn Foundation keine liefert.</summary>
    internal static string? UnicodeForm(in Teile teile)
    {
        if (teile.IstIPv6) { return "[" + teile.HostRoh + "]"; }
        var host = teile.HostRoh;
        if (host.Length == 0) { return host; }
        // Über 2048 Byte: ohne Prozent-Kodierung nie ein Host; mit (gemessen: Foundation dekodiert dann ohne Grenze) nur ASCII
        // ohne xn--, das ohne IDNA auskommt.
        var zuLang = ZuLangFuerIdna(host);
        if (zuLang && !teile.Prozent) { return null; }
        try
        {
            if (IstAscii(host))
            {
                var hatAce = host.Split('.').Any(l => l.StartsWith("xn--", StringComparison.OrdinalIgnoreCase));
                if (!hatAce) { return host; }
                return zuLang ? null : Idn.GetUnicode(host);
            }
            if (zuLang) { return null; }
            return Idn.GetUnicode(Idn.GetAscii(host));
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
