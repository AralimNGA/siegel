import Foundation

/// Website eines Eintrags (SPEC §6): „Website öffnen“ nur bei `http`/`https` (ohne Schema wird
/// `https://` vorangestellt), sonst deaktiviert. Hosts mit gemischten Schriftsystemen erscheinen als
/// Punycode, damit `аpple.com` (kyrillisches а) nicht wie `apple.com` aussieht.
public struct Website: Sendable, Equatable {
    /// Schema in Kleinbuchstaben ("https", "http", "ftp", "javascript" …).
    public let scheme: String
    /// Host wie eingegeben (klein, Unicode).
    public let host: String
    /// Host für die Anzeige: Unicode, oder Punycode bei gemischten Schriften.
    public let displayHost: String
    /// Host nur aus ASCII (IDNA/Punycode), für Vergleiche und zum Öffnen.
    public let asciiHost: String
    /// Rest nach dem Host (Port, Pfad, Abfrage), unverändert.
    public let rest: String
    /// Mindestens ein Teil des Hosts mischt Schriftsysteme.
    public let mixedScripts: Bool

    /// Darf geöffnet werden (nur http/https mit Host).
    public var isOpenable: Bool { (scheme == "http" || scheme == "https") && !host.isEmpty && openURL != nil }

    /// Anzeige ohne Schema: Host plus Pfad (ohne abschliessenden „/“).
    public var display: String {
        var pfad = rest
        if pfad == "/" { pfad = "" }
        return displayHost + pfad
    }

    /// URL zum Öffnen im Browser (Host als ASCII). nil, wenn nicht http/https.
    public var openURL: URL? {
        guard scheme == "http" || scheme == "https", !asciiHost.isEmpty else { return nil }
        guard let url = URL(string: scheme + "://" + asciiHost + rest), url.host() != nil else { return nil }
        return url
    }

    /// Zerlegt eine eingegebene Website. nil bei leerer Eingabe.
    public static func parse(_ input: String) -> Website? {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }

        var scheme = "https"
        var body = Substring(text)
        if let range = text.range(of: "://") {
            scheme = text[..<range.lowerBound].lowercased()
            body = text[range.upperBound...]
            guard isSchemeName(scheme) else { return Website.opaque(scheme: "", text) }
        } else if let doppelpunkt = text.firstIndex(of: ":") {
            // „mailto:…“, „javascript:…“ sind fremde Schemata; „host:8080/…“ ist ein Port.
            let vorne = text[..<doppelpunkt].lowercased()
            let hinten = text[text.index(after: doppelpunkt)...]
            let portZiffern = hinten.prefix { $0.isASCII && $0.isNumber }
            let istPort = !portZiffern.isEmpty
                && (hinten.count == portZiffern.count || hinten.dropFirst(portZiffern.count).first == "/")
            if !istPort && isSchemeName(vorne) {
                return Website.opaque(scheme: vorne, text)
            }
        }

        // Host = bis zum ersten / ? #, ohne Benutzerangabe und Port
        let ende = body.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? body.endIndex
        var autoritaet = body[..<ende]
        let rest = String(body[ende...])
        if let at = autoritaet.lastIndex(of: "@") {
            autoritaet = autoritaet[autoritaet.index(after: at)...]
        }
        var hostTeil = autoritaet
        var port = ""
        if hostTeil.hasPrefix("[") {
            // IPv6-Literal
            if let zu = hostTeil.firstIndex(of: "]") {
                port = String(hostTeil[hostTeil.index(after: zu)...])
                hostTeil = hostTeil[...zu]
            }
        } else if let doppelpunkt = hostTeil.lastIndex(of: ":") {
            port = String(hostTeil[doppelpunkt...])
            hostTeil = hostTeil[..<doppelpunkt]
        }
        let host = String(hostTeil).precomposedStringWithCanonicalMapping.lowercased()
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var gemischt = false
        var ascii: [String] = []
        for label in labels {
            if label.unicodeScalars.allSatisfy(\.isASCII) {
                ascii.append(label)
            } else {
                if ScriptCheck.isMixed(label) { gemischt = true }
                ascii.append(Punycode.encode(label).map { "xn--" + $0 } ?? label)
            }
        }
        // Auch über den ganzen Host (Befund #12): „аррӏе.com“ ist pro Teil einschriftig (kyrillisch bzw. lateinisch),
        // mischt aber Kyrillisch und Latein – sieht aus wie apple.com. Nur bei Nicht-ASCII-Hosts nötig.
        if !gemischt, !host.unicodeScalars.allSatisfy(\.isASCII), !ScriptCheck.isAllowedHost(host) {
            gemischt = true
        }
        let asciiHost = ascii.joined(separator: ".")
        return Website(scheme: scheme, host: host, displayHost: gemischt ? asciiHost : host, asciiHost: asciiHost,
                       rest: port + rest, mixedScripts: gemischt)
    }

    /// Fremdes Schema (mailto, javascript, file …): anzeigen wie eingegeben, nie öffnen.
    private static func opaque(scheme: String, _ text: String) -> Website {
        Website(scheme: scheme, host: "", displayHost: text, asciiHost: "", rest: "", mixedScripts: false)
    }

    private static func isSchemeName(_ s: String) -> Bool {
        guard let erstes = s.unicodeScalars.first, erstes.isASCII, CharacterSet.letters.contains(erstes) else {
            return false
        }
        return s.unicodeScalars.allSatisfy {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "+" || $0 == "-" || $0 == ".")
        }
    }
}

// MARK: - Punycode (RFC 3492)

/// Punycode-Kodierung eines einzelnen Host-Teils (ohne „xn--“).
public enum Punycode {
    private static let base = 36
    private static let tMin = 1
    private static let tMax = 26
    private static let skew = 38
    private static let damp = 700
    private static let initialBias = 72
    private static let initialN = 128

    public static func encode(_ input: String) -> String? {
        let werte = input.unicodeScalars.map { Int($0.value) }
        var output: [UInt8] = werte.filter { $0 < 0x80 }.map { UInt8($0) }
        let basis = output.count
        var h = basis
        if basis > 0 { output.append(UInt8(ascii: "-")) }
        var n = initialN
        var delta = 0
        var bias = initialBias
        while h < werte.count {
            guard let m = werte.filter({ $0 >= n }).min() else { return nil }
            let (schritt, ueberlauf) = (m - n).multipliedReportingOverflow(by: h + 1)
            guard !ueberlauf else { return nil }
            delta += schritt
            n = m
            for c in werte {
                if c < n {
                    delta += 1
                }
                if c == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                        if q < t { break }
                        output.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, h + 1, h == basis)
                    delta = 0
                    h += 1
                }
            }
            delta += 1
            n += 1
        }
        return String(decoding: output, as: UTF8.self)
    }

    private static func digit(_ d: Int) -> UInt8 {
        d < 26 ? UInt8(97 + d) : UInt8(22 + d)
    }

    private static func adapt(_ delta: Int, _ numPoints: Int, _ first: Bool) -> Int {
        var delta = first ? delta / damp : delta / 2
        delta += delta / numPoints
        var k = 0
        while delta > ((base - tMin) * tMax) / 2 {
            delta /= base - tMin
            k += base
        }
        return k + (base - tMin + 1) * delta / (delta + skew)
    }
}

// MARK: - Schriftsysteme

/// Erkennt Host-Teile, die Schriftsysteme mischen (z. B. lateinisch + kyrillisch). Erlaubt sind die
/// üblichen ostasiatischen Kombinationen (Han + Hiragana + Katakana, Han + Hangul, Han + Bopomofo).
enum ScriptCheck {
    enum Script: Hashable {
        case latin, greek, cyrillic, armenian, hebrew, arabic, georgian, thai, devanagari
        case han, hiragana, katakana, hangul, bopomofo
        case other(UInt32)
    }

    /// Schriften eines ganzen Hosts nach UTS #39 „Highly Restrictive“: genau eine Schrift, oder Latein zusammen
    /// mit den ostasiatischen Kombinationen (Han + Hiragana + Katakana, Han + Hangul, Han + Bopomofo).
    /// `日本語.jp` und `пример.рф` bleiben so Unicode, `аррӏе.com` (Kyrillisch + Latein) nicht.
    static func isAllowedHost(_ host: String) -> Bool {
        var schriften = Set<Script>()
        for scalar in host.unicodeScalars {
            if let s = script(scalar) { schriften.insert(s) }
        }
        guard schriften.count > 1 else { return true }
        let japanisch: Set<Script> = [.latin, .han, .hiragana, .katakana]
        let koreanisch: Set<Script> = [.latin, .han, .hangul]
        let chinesisch: Set<Script> = [.latin, .han, .bopomofo]
        return schriften.isSubset(of: japanisch) || schriften.isSubset(of: koreanisch) || schriften.isSubset(of: chinesisch)
    }

    static func isMixed(_ label: String) -> Bool {
        var schriften = Set<Script>()
        for scalar in label.unicodeScalars {
            if let s = script(scalar) { schriften.insert(s) }
        }
        guard schriften.count > 1 else { return false }
        let japanisch: Set<Script> = [.han, .hiragana, .katakana]
        let koreanisch: Set<Script> = [.han, .hangul]
        let chinesisch: Set<Script> = [.han, .bopomofo]
        return !(schriften.isSubset(of: japanisch) || schriften.isSubset(of: koreanisch)
            || schriften.isSubset(of: chinesisch))
    }

    /// Schriftsystem eines Zeichens; nil für gemeinsame Zeichen (Ziffern, Bindestrich, Satzzeichen, Marken).
    static func script(_ s: Unicode.Scalar) -> Script? {
        let v = s.value
        switch s.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter:
            break
        default:
            return nil
        }
        switch v {
        case 0x41...0x5A, 0x61...0x7A, 0xC0...0x24F, 0x1E00...0x1EFF, 0x2C60...0x2C7F, 0xA720...0xA7FF,
             0xAB30...0xAB6F, 0xFF21...0xFF3A, 0xFF41...0xFF5A, 0x250...0x2AF, 0x1D00...0x1DBF:
            return .latin
        case 0x370...0x3FF, 0x1F00...0x1FFF:
            return .greek
        case 0x400...0x52F, 0x1C80...0x1C8F, 0x2DE0...0x2DFF, 0xA640...0xA69F:
            return .cyrillic
        case 0x530...0x58F, 0xFB13...0xFB17:
            return .armenian
        case 0x590...0x5FF, 0xFB1D...0xFB4F:
            return .hebrew
        case 0x600...0x6FF, 0x750...0x77F, 0x8A0...0x8FF, 0xFB50...0xFDFF, 0xFE70...0xFEFF:
            return .arabic
        case 0x10A0...0x10FF, 0x2D00...0x2D2F:
            return .georgian
        case 0xE00...0xE7F:
            return .thai
        case 0x900...0x97F:
            return .devanagari
        case 0x3040...0x309F:
            return .hiragana
        case 0x30A0...0x30FF, 0x31F0...0x31FF, 0xFF66...0xFF9F:
            return .katakana
        case 0x1100...0x11FF, 0x3130...0x318F, 0xAC00...0xD7AF:
            return .hangul
        case 0x3100...0x312F, 0x31A0...0x31BF:
            return .bopomofo
        case 0x2E80...0x2FDF, 0x3005...0x3007, 0x3400...0x4DBF, 0x4E00...0x9FFF, 0xF900...0xFAFF,
             0x20000...0x3FFFF:
            return .han
        default:
            // Unbekannter Block: eigener Schlüssel je 128er-Block (vorsichtig: lieber Punycode als Täuschung)
            return .other(v >> 7)
        }
    }
}
