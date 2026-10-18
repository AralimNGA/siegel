#if DEBUG
import Foundation
@testable import SiegelCore

/// Ziel „autofill“: `AutofillMatcher.matches` (SPEC §20) – Kennungen kommen von fremden Websites und Apps.
///
/// Rahmung: Byte 0 = Erwartung (0 frei, 1 muss passen, 2 darf nie passen), danach Eintrag ‖ 0x00 ‖ Kennung (UTF-8).
/// Erzeugt werden zufällige Domains mit harmlosen Umschreibungen (Pfad, Gross/Klein, Schlusspunkt, Unterdomain,
/// Standardport, Benutzerinfo) und Phishing-Umschreibungen (fremde Domain mit dem Namen als Unterdomain, Pfad,
/// Benutzerinfo oder Anhängsel, http statt https, anderer Port, Doppelgänger-Zeichen, öffentliche Suffixe).
/// Invarianten: kein Absturz; harmlose Varianten passen immer; Phishing-Varianten nie; nie http für https.
final class ZielAutofill: FuzzZiel {
    let name = "autofill"
    let zeitlimit = 5.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 11)
    var zusatz: [String: Int] = [:]

    func vorbereiten(_ u: Umgebung) throws {
        korpus.saatAufnehmen([1] + Array("https://bank.example.ch".utf8) + [0] + Array("https://login.bank.example.ch/x".utf8))
        korpus.saatAufnehmen([2] + Array("https://bank.example.ch".utf8) + [0] + Array("https://bank.example.ch.evil.com".utf8))
        korpus.saatAufnehmen([0] + Array("velo.example.ch".utf8) + [0] + Array("http://[::1]:8080/".utf8))
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    private func label(_ z: inout Zufall) -> String {
        String((0..<z.int(4...10)).map { _ in Character(UnicodeScalar(UInt8(0x61 + z.int(26)))) })
    }

    /// Kyrillische/griechische Doppelgänger für lateinische Buchstaben.
    private static let doppelgaenger: [Character: String] = ["a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х",
                                                             "i": "і", "y": "у", "k": "κ", "n": "п"]

    func naechste(_ z: inout Zufall) -> [UInt8] {
        if z.chance(0.25) {
            // wild: Korpus-Eintrag mutieren, keine Erwartung
            let basis = korpus.waehle(&z)
            let teile = basis.dropFirst().split(separator: 0, omittingEmptySubsequences: false)
                .map { String(decoding: $0, as: UTF8.self) }
            let a = teile.first ?? "", b = teile.count > 1 ? teile[1] : ""
            return [0] + Array(Zeichen.mutieren(a, &z).utf8) + [0] + Array(Zeichen.mutieren(b, &z).utf8)
        }
        let tld = z.pick(["ch", "de", "com", "org", "net", "io", "app"])
        let h = (0..<z.int(1...2)).map { _ in label(&z) }.joined(separator: ".") + "." + tld
        var eintrag = z.pick(["https://", "", "https://"]) + h + z.pick(["", "/", "/login", "/a?b=c"])
        let httpEintrag = z.chance(0.1)
        if httpEintrag { eintrag = "http://" + h }
        let sub = label(&z)
        if z.chance(0.5) {
            // harmlos: muss passen
            let k: String
            switch z.int(9) {
            case 0: k = "https://" + h
            case 1: k = "https://" + h + "/pfad/seite?x=1#teil"
            case 2: k = "https://" + sub + "." + h
            case 3: k = "HTTPS://" + h.uppercased()
            case 4: k = "https://" + h + "."
            case 5: k = "https://" + h + ":443/"
            case 6: k = h
            case 7: k = "https://" + sub + "@" + h
            default: k = "https://" + sub + "." + sub + "." + h + "/"
            }
            return [1] + Array(eintrag.utf8) + [0] + Array(k.utf8)
        }
        // Phishing: darf nie passen
        let fremd = label(&z) + ".com"
        var k: String
        switch z.int(13) {
        case 0: k = "https://" + h + "." + fremd
        case 1: k = "https://" + fremd + "/" + h
        case 2: k = "https://" + h + z.pick(["x", "-", "0"])
        case 3: k = "https://" + sub + h
        case 4: k = "https://" + h + "@" + fremd
        case 5: k = httpEintrag ? "https://" + fremd : "http://" + h      // http nie für einen https-Eintrag
        case 6: k = "https://" + h + ":" + String(z.pick([8443, 444, 80, 1, 65535]))
        case 7:
            var s = Array(h)
            let stellen = s.indices.filter { Self.doppelgaenger[s[$0]] != nil }
            if let i = stellen.isEmpty ? nil : z.pick(stellen), let d = Self.doppelgaenger[s[i]], let c = d.first { s[i] = c }
            k = "https://" + String(s)
            if !stellen.isEmpty { break }
            k = "https://" + fremd
        case 8: k = "https://" + fremd + "?" + h
        case 9: k = "https://" + fremd + "#" + h
        case 10: k = "https://" + h.replacingOccurrences(of: ".", with: "%2E")
        case 11: k = "https://" + h + "\\@" + fremd
        default:
            // Eintrag auf ein öffentliches Suffix: nur genau gleich
            eintrag = "https://" + z.pick(["co.uk", "github.io", "com.au", "ch", "appspot.com"])
            k = "https://" + label(&z) + "." + String(eintrag.dropFirst(8))
        }
        return [2] + Array(eintrag.utf8) + [0] + Array(k.utf8)
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard let erwartung = e.first else { return "leer" }
        let teile = e.dropFirst().split(separator: 0, omittingEmptySubsequences: false).map { String(decoding: $0, as: UTF8.self) }
        let eintrag = teile.first ?? "", kennung = teile.count > 1 ? teile[1] : ""
        let treffer = AutofillMatcher.matches(entryURL: eintrag, serviceIdentifier: kennung)
        // nie http für https (unabhängig von der Erwartung)
        if treffer, eintrag.lowercased().hasPrefix("https://"), kennung.lowercased().hasPrefix("http://") {
            throw Fund("autofill", "http-Kennung für https-Eintrag angeboten")
        }
        if erwartung == 1, !treffer { throw Fund("autofill", "harmlose Variante passt nicht") }
        if erwartung == 2, treffer { throw Fund("autofill", "Phishing-Variante passt") }
        return treffer ? "treffer:\(erwartung)" : "kein:\(erwartung)"
    }
}
#endif
