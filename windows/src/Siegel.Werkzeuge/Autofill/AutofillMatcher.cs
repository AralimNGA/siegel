using System.Globalization;
using System.Text;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge;

/// <summary>
/// Entscheidet, ob ein gespeicherter Eintrag für eine Website angeboten werden darf (SPEC §20), gleiche Regeln wie
/// Sources/SiegelCore/Werkzeuge/AutofillMatcher.swift. Lieber kein Treffer als ein falscher.
/// - Nur http und https; ohne Schema gilt https://. Nie http für einen https-Eintrag (umgekehrt erlaubt).
/// - Host gleich oder Unterdomain des gespeicherten Hosts, nie umgekehrt oder seitwärts; verglichen wird die
///   IDNA-Form (Punycode, klein, ohne Schlusspunkt).
/// - Öffentliche Suffixe (einteilig oder aus der eingebauten Liste), IP-Adressen und einteilige Hosts nur genau.
/// - Port: Eintrag mit Port verlangt genau diesen, sonst nur den Standardport.
/// - Abgelehnt: Leerraum, Steuer- und Formatzeichen, <c>\</c>, <c>%</c> vor dem Pfad, leere Host-Teile, Ports
///   ausserhalb 1–65535, Eingaben über 2048 Byte.
/// </summary>
public static class AutofillMatcher
{
    public static bool Matches(string entryUrl, string serviceIdentifier)
    {
        if (Origin.Parse(entryUrl) is not { } entry || Origin.Parse(serviceIdentifier) is not { } service) { return false; }

        // Nie http für einen https-Eintrag.
        if (entry.Scheme == "https" && service.Scheme != "https") { return false; }

        // Port
        if (entry.Port is { } entryPort)
        {
            if (service.EffectivePort != entryPort) { return false; }
        }
        else if (service.Port is { } servicePort && servicePort != Origin.DefaultPort(service.Scheme))
        {
            return false;
        }

        // Host
        if (entry.Host == service.Host) { return true; }
        if (!entry.AllowsSubdomains || service.IsIP) { return false; }
        return service.Host.EndsWith("." + entry.Host, StringComparison.Ordinal);
    }

    /// <summary>Mehrteilige öffentliche Suffixe (Auszug aus der Public Suffix List, wie auf dem Mac).</summary>
    internal static readonly HashSet<string> PublicSuffixes = new(StringComparer.Ordinal)
    {
        // Vereinigtes Königreich, Australien, Neuseeland
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk", "police.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz", "kiwi.nz",
        // Europa
        "co.at", "or.at", "ac.at", "gv.at", "gouv.fr", "asso.fr", "nom.fr", "com.fr", "gov.it", "edu.it",
        "com.es", "org.es", "gob.es", "com.pt", "gov.pt", "com.pl", "net.pl", "org.pl", "gov.pl",
        "co.hu", "com.gr", "gov.gr", "com.cy", "com.mt", "co.il", "org.il", "gov.il", "ac.il",
        "com.tr", "gov.tr", "org.tr", "net.tr", "com.ua", "gov.ua", "org.ua", "co.ua",
        // Asien
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "go.kr", "ac.kr",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.tw", "org.tw", "gov.tw", "com.hk", "org.hk", "gov.hk",
        "com.sg", "gov.sg", "edu.sg", "com.my", "gov.my", "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "co.id", "go.id", "or.id", "com.ph", "gov.ph", "co.th", "go.th", "in.th", "com.vn", "gov.vn",
        "com.pk", "gov.pk", "com.sa", "gov.sa", "com.qa", "ae.org",
        // Amerika, Afrika
        "com.br", "net.br", "org.br", "gov.br", "com.mx", "org.mx", "gob.mx", "com.ar", "gob.ar", "com.co",
        "gov.co", "com.pe", "gob.pe", "co.za", "org.za", "gov.za", "ac.za", "com.ng", "gov.ng", "co.ke", "or.ke",
        "com.eg", "gov.eg", "co.ma",
        // Häufige private Suffixe (jeder kann darunter eine Seite anlegen)
        "github.io", "gitlab.io", "githubusercontent.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
        "r2.dev", "web.app", "firebaseapp.com", "appspot.com", "herokuapp.com", "onrender.com", "fly.dev",
        "glitch.me", "blogspot.com", "wordpress.com", "wixsite.com", "myshopify.com", "azurewebsites.net",
        "azurestaticapps.net", "cloudfront.net", "amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com",
        "ngrok.io", "ngrok-free.app", "ngrok.app", "duckdns.org", "dyndns.org", "no-ip.org", "repl.co",
        "replit.app", "surge.sh", "neocities.org", "codeberg.page", "sharepoint.com", "readthedocs.io",
        "translate.goog", "notion.site", "carrd.co", "webflow.io", "framer.app", "deno.dev", "pythonanywhere.com",
    };

    /// <summary>Ursprung (Schema, Host, Port) einer Adresse.</summary>
    internal sealed record Origin(string Scheme, string Host, int? Port, bool IsIP, bool AllowsSubdomains)
    {
        internal const int MaximumBytes = 2048;

        internal static int DefaultPort(string scheme) => scheme == "http" ? 80 : 443;

        internal int EffectivePort => Port ?? DefaultPort(Scheme);

        internal static Origin? Parse(string? raw)
        {
            var text = SwiftText.Trimmen(SwiftText.Repariert(raw ?? ""), SwiftText.IstLeerzeichenOderUmbruch);
            if (text.Length == 0 || Encoding.UTF8.GetByteCount(text) > MaximumBytes) { return null; }
            // Kein Leerraum, keine Steuerzeichen, kein Backslash in der Adresse
            foreach (var s in SwiftText.Skalare(text))
            {
                var kategorie = SwiftUnicode.Kategorie(s);
                if (s == '\\' || SwiftUnicode.IstLeerraum(s) || CsvText.IsControlOrBidi(s)
                    || kategorie is UnicodeCategory.Control or UnicodeCategory.Format)
                {
                    return null;
                }
            }
            var withScheme = SwiftText.EnthaeltFolge(text, "://") ? text : "https://" + text;   // wie Swift (Character-Grenzen)
            // Prozent-Kodierung im Autoritätsteil nie zulassen (Browser und Foundation dekodieren dort nicht gleich)
            var schemeEnd = withScheme.IndexOf("://", StringComparison.Ordinal);
            if (schemeEnd >= 0)
            {
                var rest = withScheme[(schemeEnd + 3)..];
                var ende = rest.IndexOfAny(['/', '?', '#']);
                var authority = ende >= 0 ? rest[..ende] : rest;
                if (authority.Contains('%', StringComparison.Ordinal)) { return null; }
            }
            if (!UrlHost.Zerlegen(withScheme, out var teile)) { return null; }
            var rawScheme = SwiftText.Klein(teile.Scheme);
            if (rawScheme is not ("http" or "https")) { return null; }
            if (UrlHost.AceForm(teile) is not { } ace) { return null; }
            var host = SwiftText.Klein(ace);
            if (host.Length == 0) { return null; }
            int? port = null;
            if (teile.Port is { } p)
            {
                if (p is < 1 or > 65535) { return null; }
                port = (int)p;
            }
            if (host.EndsWith('.')) { host = host[..^1]; }
            if (host.Length == 0 || host.Contains('%', StringComparison.Ordinal) || host.StartsWith('.')
                || host.Contains("..", StringComparison.Ordinal))
            {
                return null;
            }

            var isIPv6 = host.Contains(':', StringComparison.Ordinal);
            var labels = host.Split('.');
            var isIPv4 = !isIPv6 && labels.Length == 4 && labels.All(l => l.Length > 0 && l.All(char.IsAsciiDigit));
            if (!isIPv6)
            {
                // Nach IDNA nur noch a–z, 0–9, '-', '_' und Punkte
                if (!host.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '.')) { return null; }
            }
            // Letzter Teil nur aus Ziffern, ohne gültige IPv4-Form (z. B. "1.2.3" oder "0x7f.1") → wie IP behandeln
            var numericTail = labels[^1].All(char.IsAsciiDigit);
            var isIP = isIPv6 || isIPv4 || numericTail;
            return new Origin(rawScheme, host, port, isIP, !isIP && labels.Length >= 2 && !PublicSuffixes.Contains(host));
        }
    }
}
