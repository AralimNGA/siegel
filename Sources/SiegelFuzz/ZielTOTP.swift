#if DEBUG
import Foundation
@testable import SiegelCore

/// Ziel „totp“: otpauth-URI und Base32-Geheimnis (SPEC §18, `TOTP.parse`, `TOTP.code`).
///
/// Rahmung: Byte 0 = Art (0 Text parsen, 1 Rundlauf aus Parametern), Byte 1…8 = Zeitpunkt (Double-Bits), danach
/// UTF-8 bzw. Zufallsbytes für die Parameter.
/// Invarianten: kein Absturz; Fehler nur `totpInvalid` mit festem Code; Ergebnis hält alle Grenzen ein; der Code hat
/// genau `digits` Ziffern und 1 ≤ Restsekunden ≤ Periode für jeden Zeitpunkt (auch ±∞, NaN, vor 1970);
/// eine selbst gebaute URI ergibt genau die Parameter, aus denen sie gebaut wurde.
final class ZielTOTP: FuzzZiel {
    let name = "totp"
    let zeitlimit = 5.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 6)
    var zusatz: [String: Int] = [:]

    private static let saat = [
        "otpauth://totp/Bibliothek:leserin%40example.ch?secret=JBSWY3DPEHPK3PXP&issuer=Bibliothek",
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        "OTPAUTH://TOTP/?SECRET=jbswy3dpehpk3pxp&ALGORITHM=sha512&image=https%3A%2F%2Fx",
        "JBSW Y3DP EHPK 3PXP",
        "jbswy3dpehpk3pxp====",
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
        "otpauth-migration://offline?data=abc",
        "otpauth://totp/a:b:c?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=15&digits=6",
    ]

    func vorbereiten(_ u: Umgebung) throws {
        for s in Self.saat { korpus.saatAufnehmen([0] + Array(repeating: 0, count: 8) + Array(s.utf8)) }
        korpus.saatAufnehmen([1] + Array(repeating: 0, count: 8) + Array(repeating: 3, count: 40))
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    private static let bausteine = ["%", "%2", "%zz", "%00", "%3A", "&", "=", "?", "#", "/", ":", "secret=", "issuer=",
                                    "algorithm=SHA1", "algorithm=md5", "digits=7", "digits=0008", "period=14",
                                    "period=121", "period=", "&secret=AAAA", "====", "=", "\u{202E}", "\u{0}", "é",
                                    String(repeating: "A", count: 205), String(repeating: "%41", count: 700)]

    func naechste(_ z: inout Zufall) -> [UInt8] {
        let zeit: [UInt8] = {
            let d = z.pick([0, -1, 1e10, -1e300, 1e300, Double.infinity, -Double.infinity, Double.nan, 59, 1_111_111_109,
                            Double(z.int(0...4_000_000_000)), 9.1e15, -9.1e15, Date.distantFuture.timeIntervalSince1970])
            return withUnsafeBytes(of: d.bitPattern) { Array($0) }
        }()
        if z.chance(0.25) { return [1] + zeit + z.bytes(z.int(16...200)) }
        let basis = korpus.waehle(&z)
        guard basis.count >= 9 else { return basis }
        var text = Array(basis.dropFirst(9))
        for _ in 0..<z.int(1...3) {
            if z.chance(0.5) {
                text = Mutator.bytes(text, &z, maxLaenge: 4096)
            } else {
                text.insert(contentsOf: Array(z.pick(Self.bausteine).utf8), at: z.int(text.count + 1))
            }
        }
        return [0] + zeit + text
    }

    // MARK: Hilfen

    static func base32(_ b: [UInt8], padding: Bool) -> String {
        let a = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = ""
        var buf: UInt64 = 0
        var bits = 0
        for x in b {
            buf = (buf << 8) | UInt64(x)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(a[Int((buf >> UInt64(bits)) & 31)])
            }
        }
        if bits > 0 { out.append(a[Int((buf << UInt64(5 - bits)) & 31)]) }
        if padding { while out.count % 8 != 0 { out += "=" } }
        return out
    }

    static func prozent(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            if (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || b == 0x2D || b == 0x2E
                || b == 0x5F || b == 0x7E {
                out.append(Character(UnicodeScalar(b)))
            } else {
                out += String(format: "%%%02X", b)
            }
        }
        return out
    }

    private func pruefeCode(_ p: TOTP.Parameters, _ zeitBits: UInt64) throws {
        let zeiten = [Double(bitPattern: zeitBits), 0, -1, 59, 1_111_111_109, Double.infinity, -Double.infinity, .nan,
                      9.0e15, 1e300]
        for t in zeiten {
            let (code, rest) = TOTP.code(p, at: Date(timeIntervalSince1970: t))
            guard code.count == p.digits, code.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else {
                throw Fund("totp", "Code hat nicht genau \(p.digits) Ziffern")
            }
            guard rest >= 1, rest <= p.period else { throw Fund("totp", "Restsekunden ausserhalb 1…Periode") }
        }
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard e.count >= 9 else { return "kurz" }
        let zeitBits = e[1..<9].enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << UInt64(8 * $1.offset) }
        let rest = Array(e.dropFirst(9))
        if e[0] == 1 {
            // Rundlauf: Parameter aus den Bytes, URI bauen, parsen, vergleichen
            var z = Zufall(saat: rest.reduce(UInt64(0x7077)) { ($0 &* 131) &+ UInt64($1) })
            let geheim = z.bytes(z.int(10...128))
            let alg = z.pick(TOTP.Parameters.Algorithm.allCases)
            let ziffern = z.pick([6, 8])
            let periode = z.int(15...120)
            let teile = ["a", "Z", " ", "é", "@", ".", "%", "&", "?", "#", "/", "=", "+", "😀", "ß", "-"]
            var aussteller = (0..<z.int(0...10)).map { _ in z.pick(teile) }.joined()
            var konto = (0..<z.int(0...12)).map { _ in z.pick(teile + [":"]) }.joined()
            aussteller = aussteller.replacingOccurrences(of: ":", with: "").trimmingCharacters(in: .whitespaces)
            // Ohne Aussteller trennt ein „:“ (auch als %3A) im Label Aussteller und Konto (Key-URI-Format).
            if aussteller.isEmpty { konto = konto.replacingOccurrences(of: ":", with: "") }
            konto = konto.trimmingCharacters(in: .whitespaces)
            var uri = "otpauth://" + (z.chance(0.5) ? "totp" : "TOTP") + "/"
            uri += aussteller.isEmpty ? Self.prozent(konto) : Self.prozent(aussteller) + ":" + Self.prozent(konto)
            var params = ["secret=" + Self.base32(geheim, padding: z.chance(0.5))]
            if !aussteller.isEmpty { params.append("issuer=" + Self.prozent(aussteller)) }
            if alg != .sha1 || z.chance(0.5) { params.append("algorithm=" + (z.chance(0.5) ? alg.uriName : alg.uriName.lowercased())) }
            if ziffern != 6 || z.chance(0.5) { params.append("digits=\(ziffern)") }
            if periode != 30 || z.chance(0.5) { params.append("period=\(periode)") }
            if z.chance(0.3) { params.append("image=https%3A%2F%2Fexample.ch%2Fa.png") }
            params.shuffle(using: &z)
            uri += "?" + params.joined(separator: "&")
            let erwartet = try TOTP.Parameters(secret: geheim, algorithm: alg, digits: ziffern, period: periode,
                                               issuer: aussteller, account: konto)
            let p: TOTP.Parameters
            do { p = try TOTP.parse(uri) } catch {
                if uri.utf8.count > 2048 { return "rundlauf:zuLang" }
                throw Fund("rundlauf", "selbst gebaute URI abgelehnt: " + fehlerCode(error))
            }
            guard p == erwartet else { throw Fund("rundlauf", "URI ergibt andere Parameter") }
            try pruefeCode(p, zeitBits)
            return "rundlauf:ok"
        }
        let text = String(decoding: rest, as: UTF8.self)
        do {
            let p = try TOTP.parse(text)
            guard [6, 8].contains(p.digits), (15...120).contains(p.period), (10...128).contains(p.secretByteCount),
                  p.issuer.utf8.count <= 256, p.account.utf8.count <= 256,
                  !CSVText.containsControlOrBidi(p.issuer), !CSVText.containsControlOrBidi(p.account) else {
                throw Fund("totp", "Parameter ausserhalb der Grenzen")
            }
            try pruefeCode(p, zeitBits)
            return "ok:" + p.algorithm.rawValue
        } catch let x as SiegelError {
            guard case let .totpInvalid(c) = x, TOTP.reasonCodes.contains(c) else {
                throw Fund("fehlertyp", "TOTP.parse: " + fehlerCode(x))
            }
            return "totpInvalid(" + c + ")"
        }
    }
}
#endif
