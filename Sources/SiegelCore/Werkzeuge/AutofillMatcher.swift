import Foundation

/// Entscheidet, ob ein gespeicherter Eintrag für eine Website angeboten werden darf (SPEC §20, Autofill
/// vorbereitet). Lieber kein Treffer als ein falscher: Ein Passwort, das auf einer Phishing-Seite angeboten
/// wird, ist verloren.
///
/// Regeln:
/// - Nur `http` und `https`. Ohne Schema gilt `https://` (gespeicherte Adressen wie `velo.example.ch`, und
///   die Domain-Kennungen des Systems sind https).
/// - **Nie `http` für einen `https`-Eintrag.** Ein `http`-Eintrag darf für `https` angeboten werden.
/// - Host: gleich oder Unterdomain des gespeicherten Hosts (`login.example.com` für `example.com`), nie
///   umgekehrt und nie seitwärts. Verglichen wird die IDNA-Form (Punycode, klein, ohne Schlusspunkt), so
///   dass `аррӏе.com` (kyrillisch) nie `apple.com` trifft.
/// - Keine Teil-Treffer über die registrierbare Domain hinaus: Ist der gespeicherte Host ein öffentliches
///   Suffix (einteilig wie `ch`, oder aus der kleinen eingebauten Liste wie `co.uk`, `com.au`, `github.io`),
///   gilt nur der genau gleiche Host. IP-Adressen und einteilige Hosts (`localhost`) ebenso nur genau.
/// - Port: Hat der Eintrag einen Port, muss die Website genau diesen haben; sonst nur den Standardport.
/// - Pfad, Abfrage, Benutzerinfo (`https://bank.ch@evil.com` hat den Host `evil.com`) zählen nicht.
/// - Abgelehnt (kein Treffer): Leerraum oder Steuerzeichen in der Adresse, `\` (Browser lesen es als `/`,
///   Foundation nicht – das wäre ein Einfallstor), `%` vor dem Pfad (Benutzerinfo, Host, Port), leere
///   Host-Teile, Ports ausserhalb 1–65535, Eingaben über 2048 Byte.
public enum AutofillMatcher {
    public static func matches(entryURL: String, serviceIdentifier: String) -> Bool {
        guard let entry = Origin(entryURL), let service = Origin(serviceIdentifier) else { return false }

        // Nie http für einen https-Eintrag.
        if entry.scheme == "https", service.scheme != "https" { return false }

        // Port
        if let entryPort = entry.port {
            guard service.effectivePort == entryPort else { return false }
        } else if let servicePort = service.port, servicePort != Origin.defaultPort(service.scheme) {
            return false
        }

        // Host
        if entry.host == service.host { return true }
        guard entry.allowsSubdomains, !service.isIP else { return false }
        return service.host.hasSuffix("." + entry.host)
    }

    // MARK: - Öffentliche Suffixe (klein, bewusst unvollständig)

    /// Mehrteilige öffentliche Suffixe (Auszug aus der Public Suffix List, ICANN- und häufige private
    /// Einträge). Einteilige Suffixe (Top-Level-Domains) gelten immer als öffentlich und stehen nicht hier.
    /// Fehlt ein Suffix, ist die Folge höchstens ein Treffer innerhalb dieses Suffixes für einen Eintrag, der
    /// genau auf das Suffix lautet – Einträge auf echte Domains sind davon nicht betroffen.
    static let publicSuffixes: Set<String> = [
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
    ]

    // MARK: - Ursprung (Schema, Host, Port)

    struct Origin: Equatable {
        let scheme: String
        let host: String
        let port: Int?
        let isIP: Bool
        let allowsSubdomains: Bool

        static let maximumBytes = 2048

        static func defaultPort(_ scheme: String) -> Int { scheme == "http" ? 80 : 443 }

        var effectivePort: Int { port ?? Origin.defaultPort(scheme) }

        init?(_ raw: String) {
            let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty, text.utf8.count <= Origin.maximumBytes else { return nil }
            // Kein Leerraum, keine Steuerzeichen, kein Backslash in der Adresse.
            for scalar in text.unicodeScalars {
                if scalar == "\\" || scalar.properties.isWhitespace || CSVText.isControlOrBidi(scalar)
                    || scalar.properties.generalCategory == .control || scalar.properties.generalCategory == .format {
                    return nil
                }
            }
            let withScheme = text.contains("://") ? text : "https://" + text
            // Prozent-Kodierung im Autoritätsteil (Benutzerinfo, Host, Port) nie zulassen: Systemkennungen sind
            // kanonisch, und Browser und Foundation dekodieren dort nicht gleich.
            if let schemeEnd = withScheme.range(of: "://") {
                let authority = withScheme[schemeEnd.upperBound...].prefix { $0 != "/" && $0 != "?" && $0 != "#" }
                guard !authority.contains("%") else { return nil }
            }
            guard let url = URL(string: withScheme), let rawScheme = url.scheme?.lowercased(),
                  rawScheme == "http" || rawScheme == "https",
                  var host = url.host(percentEncoded: false)?.lowercased(), !host.isEmpty else { return nil }
            if let port = url.port {
                guard (1...65535).contains(port) else { return nil }
                self.port = port
            } else {
                self.port = nil
            }
            if host.hasSuffix(".") { host.removeLast() }
            guard !host.isEmpty, !host.contains("%"), !host.hasPrefix("."), !host.contains("..") else { return nil }

            let isIPv6 = host.contains(":")
            let labels = host.split(separator: ".", omittingEmptySubsequences: false)
            let isIPv4 = !isIPv6 && labels.count == 4
                && labels.allSatisfy { !$0.isEmpty && $0.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
            if !isIPv6 {
                // Nach IDNA nur noch a–z, 0–9, '-', '_' und Punkte.
                let allowed = host.utf8.allSatisfy {
                    ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
                }
                guard allowed else { return nil }
            }
            // Letzter Teil nur aus Ziffern, ohne gültige IPv4-Form (z. B. "1.2.3" oder "0x7f.1") → wie IP behandeln.
            let numericTail = labels.last.map { $0.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } } ?? false
            self.scheme = rawScheme
            self.host = host
            self.isIP = isIPv6 || isIPv4 || numericTail
            self.allowsSubdomains = !isIP && labels.count >= 2 && !AutofillMatcher.publicSuffixes.contains(host)
        }
    }
}
