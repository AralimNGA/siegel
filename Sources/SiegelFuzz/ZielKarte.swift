#if DEBUG
import Foundation
@testable import SiegelCore

/// Ziel „karte“: QR-Inhalt bzw. abgetippter Code der Schlüsselkarte (SPEC §14.2, `CardCode.decode`).
///
/// Rahmung: Byte 0 = Erwartung (1 = harmlos umgeschrieben, muss genau q ergeben), Byte 1…32 = q, danach UTF-8.
/// Invarianten: kein Absturz; Fehler nur `invalidRecoveryCodeFormat`; was gelingt, entspricht nach der Normalisierung
/// genau dem Code von q (unabhängig nachgerechnet) und ist im Rundlauf stabil; fremde Kartenversionen nie.
final class ZielKarte: FuzzZiel {
    let name = "karte"
    let zeitlimit = 5.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 4)
    var zusatz: [String: Int] = [:]

    func vorbereiten(_ u: Umgebung) throws {
        for b in [UInt8(0x00), 0x22, 0xFF, 0x5A] {
            let q = SaatWerte.wert(b)
            let qb = q.withUnsafeBytes { Array($0) }
            korpus.saatAufnehmen([1] + qb + Array(CardCode.payload(for: q).utf8))
            korpus.saatAufnehmen([1] + qb + Array(CardCode.groupedText(for: q).utf8))
        }
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    private static let praefixe = ["SIEGELKARTE1:", "siegelkarte1:", "SiegelKarte1:", "SIEGELKARTE2:", "SIEGELKARTE:",
                                   "SIEGELKARTE1", "SIEGEL KARTE1:", "ſIEGELKARTE1:", "SIEGELKARTE１:", "SIEGELKARTE1：",
                                   "SIEGELKARTE1::", " SIEGELKARTE1:", "XSIEGELKARTE1:", "SIEGELKARTE10:", ""]

    func naechste(_ z: inout Zufall) -> [UInt8] {
        if z.chance(0.5) {
            // frische Karte, harmlos umgeschrieben
            let q = (try? FactorSecret(copying: z.bytes(32))) ?? CardCode.generate()
            let qb = q.withUnsafeBytes { Array($0) }
            // Präfix und Code getrennt umschreiben (O/I/L nur im Code: „SIEGELKARTEl:“ ist zu Recht ungültig)
            var praefix = z.chance(0.5) ? "SIEGELKARTE1:" : ""
            var text = CardCode.groupedText(for: q)
            if praefix.isEmpty || z.chance(0.5) { text = text.replacingOccurrences(of: "-", with: "") }
            if z.chance(0.3) { text = text.lowercased(); praefix = praefix.lowercased() }
            if z.chance(0.2) { text = text.replacingOccurrences(of: "-", with: z.pick(["", " ", "\u{00A0}", "--"])) }
            if z.chance(0.2) { text = text.replacingOccurrences(of: "0", with: "O").replacingOccurrences(of: "1", with: "l") }
            var gueltig = true
            if z.chance(0.3) {
                // Präfix tauschen: dann gilt die Erwartung nur, wenn es ein gültiges Präfix ist
                praefix = z.pick(Self.praefixe)
                gueltig = ["SIEGELKARTE1:", "siegelkarte1:", "SiegelKarte1:", "ſIEGELKARTE1:", " SIEGELKARTE1:", ""]
                    .contains(praefix)
            }
            text = praefix + text
            if z.chance(0.3) { text = " \t" + text + "\n" }
            return [gueltig ? 1 : 0] + qb + Array(text.utf8)
        }
        var basis = korpus.waehle(&z)
        guard basis.count > 33 else { return basis }
        basis[0] = 0
        let text = String(decoding: basis[33...], as: UTF8.self)
        let neu = z.chance(0.8) ? Zeichen.mutieren(text, &z) : String(decoding: Mutator.bytes(Array(text.utf8), &z), as: UTF8.self)
        return Array(basis[0..<33]) + Array(neu.utf8)
    }

    /// Unabhängige Normalisierung: Rand-Leerraum weg, gültiges Präfix weg, dann wie beim Notfallcode.
    private static func normalisiert(_ s: String) -> String? {
        var rest = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if rest.uppercased().hasPrefix("SIEGELKARTE") {
            guard rest.uppercased().hasPrefix("SIEGELKARTE1:") else { return nil }
            rest = String(rest.dropFirst(13))
        }
        var out = ""
        for u in rest.unicodeScalars {
            if u.properties.isWhitespace || u == "-" { continue }
            guard u.isASCII else { return nil }
            var c = Character(u).uppercased()
            if c == "O" { c = "0" }
            if c == "I" || c == "L" { c = "1" }
            guard "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c) else { return nil }
            out += c
        }
        return out
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard e.count >= 33 else { return "kurz" }
        let erwartung = e[0] == 1
        let qErwartet = Array(e[1..<33])
        let text = String(decoding: e[33...], as: UTF8.self)
        do {
            let q = try CardCode.decode(text)
            let qb = q.withUnsafeBytes { Array($0) }
            let kanonisch = CardCode.groupedText(for: q).replacingOccurrences(of: "-", with: "")
            guard Self.normalisiert(text) == kanonisch else {
                throw Fund("karte", "decode akzeptiert eine Eingabe, die nicht dem Code entspricht")
            }
            guard let q2 = try? CardCode.decode(CardCode.payload(for: q)), q2.withUnsafeBytes({ Array($0) }) == qb else {
                throw Fund("karte", "Rundlauf payload → decode")
            }
            if erwartung, qb != qErwartet { throw Fund("karte", "harmlos umgeschriebene Karte ergibt anderes q") }
            _ = CardCode.tag(for: q, vaultID: UUID())
            return "ok"
        } catch let x as SiegelError {
            guard x == .invalidRecoveryCodeFormat else { throw Fund("fehlertyp", "CardCode.decode: " + fehlerCode(x)) }
            if erwartung { throw Fund("karte", "gültige Karte (harmlos umgeschrieben) abgelehnt") }
            return "fehler:" + (Self.normalisiert(text) == nil ? "zeichen" : "inhalt")
        }
    }
}
#endif
