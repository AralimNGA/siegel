#if DEBUG
import Foundation
@testable import SiegelCore

/// Ziel „notfall“: Notfallcode und Teile (SPEC §1.5, §15) – Eingabe-Toleranz, Prüfsummen, Fehlerkorrektur.
///
/// Rahmung: Byte 0 = Art (0 Code lesen, 1 Teile lesen/kombinieren, 2 Code prüfen mit Korrektur, 3 Teile prüfen mit
/// Korrektur), Byte 1 = Saat, Byte 2 = Erwartung (1 = korrigierbar: muss genau das Original liefern), danach UTF-8
/// (bei Teilen zwei Texte, getrennt durch 0x00).
/// Invarianten: kein Absturz/Hänger; Fehler nur aus {invalidRecoveryCodeFormat, recoveryCodeChecksum,
/// wrongRecoveryCode}; jeder Treffer ergibt die öffentlichen Schlüssel des Kopfes; ein Code mit ≤ 2 ersetzten
/// Zeichen, einem Nachbartausch oder ≤ 4 „?“ wird immer gefunden, mit genau den geänderten Stellen.
final class ZielNotfall: FuzzZiel {
    let name = "notfall"
    let zeitlimit = 60.0
    private var saaten: [TresorSaat] = []
    private let korpus = Korpus()
    private var z = Zufall(saat: 3)
    var zusatz: [String: Int] = [:]
    var neueSaat = false

    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    func vorbereiten(_ u: Umgebung) throws {
        saaten = try SaatErzeugung.laden(u, neu: neueSaat)
        for (i, s) in saaten.enumerated() {
            if let c = s.code {
                korpus.saatAufnehmen([0, UInt8(i), 0] + Array(c.utf8))
                korpus.saatAufnehmen([2, UInt8(i), 1] + Array(c.utf8))
            } else if s.teile.count == 3 {
                korpus.saatAufnehmen([1, UInt8(i), 0] + Array(s.teile[0].utf8) + [0] + Array(s.teile[1].utf8))
                korpus.saatAufnehmen([3, UInt8(i), 1] + Array(s.teile[2].utf8) + [0] + Array(s.teile[0].utf8))
            }
        }
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    // MARK: Erzeugen

    private enum Fehlerart: CaseIterable { case keiner, ersetzt1, ersetzt2, tausch, fragezeichen }

    /// Symbole (0…31) des kanonischen Codes bzw. Teils.
    private static func symbole(_ s: String) -> [Int] {
        s.compactMap { c in alphabet.firstIndex(of: c) }
    }

    /// Fehler einbauen (auf Symbolebene) und harmlos umschreiben (Gross/Klein, Leerraum, Bindestriche, O/I/L).
    private func verfaelsche(_ kanonisch: String, art: Fehlerart, _ z: inout Zufall) -> String {
        var sym = Self.symbole(kanonisch)
        var unbekannt = Set<Int>()
        switch art {
        case .keiner: break
        case .ersetzt1, .ersetzt2:
            var stellen = Set<Int>()
            while stellen.count < (art == .ersetzt1 ? 1 : 2) { stellen.insert(z.int(sym.count)) }
            for i in stellen { sym[i] = (sym[i] + z.int(1...31)) % 32 }
        case .tausch:
            var i = z.int(sym.count - 1)
            var versuche = 0
            while sym[i] == sym[i + 1], versuche < 50 { i = z.int(sym.count - 1); versuche += 1 }
            sym.swapAt(i, i + 1)
        case .fragezeichen:
            while unbekannt.count < z.int(1...4) { unbekannt.insert(z.int(sym.count)) }
        }
        var out = ""
        for (i, v) in sym.enumerated() {
            if i > 0, i % 5 == 0 {
                switch z.int(6) {
                case 0: out += ""
                case 1: out += z.pick(Zeichen.leerraum.filter { $0.unicodeScalars.allSatisfy(\.properties.isWhitespace) })
                default: out += "-"
                }
            }
            if unbekannt.contains(i) { out += "?"; continue }
            var c = String(Self.alphabet[v])
            if c == "0", z.chance(0.2) { c = "O" }
            if c == "1", z.chance(0.2) { c = z.pick(["I", "L", "i", "l"]) }
            if z.chance(0.3) { c = c.lowercased() }
            out += c
        }
        if z.chance(0.2) { out = " " + out + "\n" }
        return out
    }

    func naechste(_ z: inout Zufall) -> [UInt8] {
        if z.chance(0.35) {
            // Korpus-Eintrag wild mutieren (Erwartung aus)
            var basis = korpus.waehle(&z)
            guard basis.count > 3 else { return basis }
            basis[2] = 0
            let teile = basis[3...].split(separator: 0, omittingEmptySubsequences: false)
                .map { String(decoding: $0, as: UTF8.self) }
            let neu = teile.map { z.chance(0.7) ? Zeichen.mutieren($0, &z) : $0 }
            var out = Array(basis[0..<3])
            for (i, t) in neu.enumerated() {
                if i > 0 { out.append(0) }
                out += Array(t.utf8)
            }
            return out
        }
        let art = UInt8(z.pick([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 3]))
        let mitCode = saaten.indices.filter { saaten[$0].code != nil }
        let mitTeilen = saaten.indices.filter { saaten[$0].teile.count == 3 }
        switch art {
        case 0, 2:
            let k = z.pick(mitCode)
            var kanonisch = saaten[k].code ?? ""
            if art == 0, z.chance(0.3), let r = try? SecureBytes.copy(z.bytes(32)), let c = try? RecoveryCodeCodec.format(r: r) {
                kanonisch = c
            }
            let f = art == 2 ? z.pick(Fehlerart.allCases) : z.pick([.keiner, .keiner, .ersetzt1, .tausch])
            return [art, UInt8(k), 1] + Array(verfaelsche(kanonisch, art: f, &z).utf8)
        default:
            let k = z.pick(mitTeilen)
            let s = saaten[k]
            var i = z.int(3)
            var j = (i + z.int(1...2)) % 3
            var erwartung: UInt8 = 1
            if z.chance(0.05) { j = i; erwartung = 0 }      // derselbe Teil zweimal
            if z.chance(0.05) { swap(&i, &j) }
            var b = s.teile[j]
            if z.chance(0.05), let fremd = mitTeilen.filter({ $0 != k }).randomElement(using: &z) {
                b = saaten[fremd].teile[j]                    // Teil eines anderen Tresors
                erwartung = 0
            }
            let fa: Fehlerart = art == 3 ? z.pick(Fehlerart.allCases) : z.pick([.keiner, .keiner, .ersetzt1])
            let fb: Fehlerart = art == 3 ? z.pick([.keiner, .keiner, .ersetzt1, .ersetzt2, .tausch, .fragezeichen]) : .keiner
            let ta = verfaelsche(s.teile[i], art: fa, &z)
            let tb = verfaelsche(b, art: fb, &z)
            return [art, UInt8(k), erwartung] + Array(ta.utf8) + [0] + Array(tb.utf8)
        }
    }

    // MARK: Prüfen

    private static func erlaubt(_ e: SiegelError) -> Bool {
        switch e {
        case .invalidRecoveryCodeFormat, .recoveryCodeChecksum, .wrongRecoveryCode: return true
        default: return false
        }
    }

    /// Unabhängige Normalisierung nach §1.5 (White_Space und „-“ weg, Gross, O→0, I/L→1). nil = ungültiges Zeichen.
    private static func normalisiert(_ s: String) -> String? {
        var out = ""
        for u in s.unicodeScalars {
            if u.properties.isWhitespace || u == "-" { continue }
            guard u.isASCII else { return nil }
            var c = Character(u).uppercased()
            if c == "O" { c = "0" }
            if c == "I" || c == "L" { c = "1" }
            guard c.count == 1, let ch = c.first, alphabet.contains(ch) || ch == "?" else { return nil }
            out += c
        }
        return out
    }

    private func pruefeTreffer(_ m: RecoveryCodeMatch, eingabe: String, kanonisch: String?, header: VaultHeader,
                               teil: Bool) throws -> String {
        let formatiert: String
        switch m {
        case .exact:
            guard let n = Self.normalisiert(eingabe) else { throw Fund("korrektur", "exact für ungültige Zeichen") }
            formatiert = RecoveryCodeCodec.formatSymbols(Self.symbole(n).map(UInt8.init), groupSize: 5)
        case let .corrected(f, stellen):
            formatiert = f
            guard !stellen.isEmpty, stellen.count <= 4, stellen == stellen.sorted(),
                  stellen.allSatisfy({ $0 >= 0 && $0 < (teil ? 56 : 55) }) else {
                throw Fund("korrektur", "unplausible Stellen \(stellen)")
            }
        }
        if let kanonisch, formatiert != kanonisch {
            throw Fund("korrektur", "Treffer ist nicht der Originalcode")
        }
        if !teil {
            let r = try RecoveryCodeCodec.decode(formatiert)
            guard RecoveryKEM.matches(r: r, vaultID: header.vaultID, expected: header.pk) else {
                throw Fund("korrektur", "Treffer passt nicht zum Kopf")
            }
        }
        if case .exact = m { return "exact" }
        return "corrected"
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard e.count >= 3 else { return "leer" }
        let art = e[0] & 3
        let s = saaten[Int(e[1]) % saaten.count]
        let erwartung = e[2] == 1
        let texte = e[3...].split(separator: 0, omittingEmptySubsequences: false).map { String(decoding: $0, as: UTF8.self) }
        let a = texte.first ?? ""
        let b = texte.count > 1 ? texte[1] : ""
        switch art {
        case 0:
            // Lesen ohne Korrektur
            let vollstaendig = VaultStore.recoveryCodeInputIsComplete(a)
            let sym = try? RecoveryCodeCodec.parseSymbols(a, allowUnknown: true)
            guard vollstaendig == (sym != nil) else { throw Fund("eingabe", "recoveryCodeInputIsComplete widerspricht parseSymbols") }
            _ = RecoveryCodeCodec.normalizedGroup(a)
            do {
                let r = try RecoveryCodeCodec.decode(a)
                let f = try RecoveryCodeCodec.format(r: r)
                guard let n = Self.normalisiert(a), n == f.replacingOccurrences(of: "-", with: "") else {
                    throw Fund("eingabe", "decode akzeptiert eine Eingabe, die nicht der Code ist")
                }
                guard try RecoveryCodeCodec.decode(f).constantTimeEquals(r) else { throw Fund("eingabe", "Rundlauf") }
                return "code:ok"
            } catch let x as SiegelError {
                guard x == .invalidRecoveryCodeFormat || x == .recoveryCodeChecksum else {
                    throw Fund("fehlertyp", "decode: " + fehlerCode(x))
                }
                // 55 gültige Zeichen und Füllbits 0 (letztes Zeichen 0, 8, G, R): dann nur noch Prüfsummenfehler.
                if x == .invalidRecoveryCodeFormat, let n = Self.normalisiert(a), n.count == 55, !n.contains("?"),
                   let letztes = n.last, "08GR".contains(letztes) {
                    throw Fund("eingabe", "gültige Form, trotzdem invalidRecoveryCodeFormat")
                }
                // Umgekehrt: falsche Länge, „?“ oder fremde Zeichen dürfen nie als Prüfsummenfehler erscheinen.
                if x == .recoveryCodeChecksum, Self.normalisiert(a).map({ $0.count != 55 || $0.contains("?") }) ?? true {
                    throw Fund("eingabe", "ungültige Form als Prüfsummenfehler gemeldet")
                }
                return "code:" + fehlerCode(x)
            }
        case 1:
            _ = VaultStore.recoveryShareInputIsComplete(a)
            let ia = VaultStore.recoveryShareIndex(a)
            do {
                let d = try Shamir.decode(a)
                guard ia == Int(d.x) else { throw Fund("eingabe", "recoveryShareIndex widerspricht decode") }
                let f = try Shamir.format(x: d.x, y: d.y)
                guard let n = Self.normalisiert(a), n == f.replacingOccurrences(of: "-", with: "") else {
                    throw Fund("eingabe", "Teil akzeptiert, der nicht dem Teil entspricht")
                }
            } catch let x as SiegelError {
                guard x == .invalidRecoveryCodeFormat || x == .recoveryCodeChecksum else {
                    throw Fund("fehlertyp", "Shamir.decode: " + fehlerCode(x))
                }
                guard ia == nil else { throw Fund("eingabe", "Index für ungültigen Teil") }
            }
            do {
                let r = try VaultStore.combineShares([a, b])
                if erwartung, s.teile.contains(where: { Self.normalisiert($0) == Self.normalisiert(a) }),
                   s.teile.contains(where: { Self.normalisiert($0) == Self.normalisiert(b) }),
                   !r.constantTimeEquals(s.r) {
                    throw Fund("teile", "zwei gültige Teile ergeben nicht R")
                }
                return "teile:ok"
            } catch let x as SiegelError {
                guard x == .invalidRecoveryCodeFormat || x == .recoveryCodeChecksum else {
                    throw Fund("fehlertyp", "combineShares: " + fehlerCode(x))
                }
                return "teile:" + fehlerCode(x)
            }
        case 2:
            let kanonisch = erwartung ? s.code : nil
            do {
                let sym = try RecoveryCodeCodec.parseSymbols(a, allowUnknown: true)
                let m = try VaultStore.matchRecoveryCode(symbols: sym, header: s.header)
                return "pruefen:" + (try pruefeTreffer(m, eingabe: a, kanonisch: kanonisch, header: s.header, teil: false))
            } catch let x as SiegelError {
                guard Self.erlaubt(x) else { throw Fund("fehlertyp", "matchRecoveryCode: " + fehlerCode(x)) }
                if erwartung { throw Fund("korrektur", "korrigierbarer Code nicht gefunden (" + fehlerCode(x) + ")") }
                if case let .wrongRecoveryCode(_, vaultKit) = x, vaultKit != s.header.pk.kitID {
                    throw Fund("korrektur", "falsche Kit-Kennung des Tresors gemeldet")
                }
                return "pruefen:" + fehlerCode(x)
            }
        default:
            do {
                let sym = try VaultStore.parseShareInputs([a, b])
                let m = try VaultStore.matchRecoveryShares(sym, header: s.header)
                guard m.count == 2 else { throw Fund("korrektur", "nicht genau zwei Ergebnisse") }
                // Erwartete Originalteile in Eingabereihenfolge
                var codes: [String] = []
                for (t, eingabe) in zip(m, [a, b]) {
                    let kanon = erwartung ? s.teile.first { kandidat in
                        let ns = Self.symbole(kandidat)
                        let ne = Self.symbole(Self.normalisiert(eingabe)?.replacingOccurrences(of: "?", with: "0") ?? "")
                        return ns.count == ne.count && zip(ns, ne).filter { $0 != $1 }.count <= 6
                    } : nil
                    codes.append(try pruefeTreffer(t, eingabe: eingabe, kanonisch: kanon, header: s.header, teil: true))
                }
                // Beide korrigierten Teile müssen R ergeben, das zum Kopf passt
                let fa: String, fb: String
                switch m[0] { case .exact: fa = a; case let .corrected(f, _): fa = f }
                switch m[1] { case .exact: fb = b; case let .corrected(f, _): fb = f }
                let r = try VaultStore.combineShares([fa, fb])
                guard RecoveryKEM.matches(r: r, vaultID: s.header.vaultID, expected: s.header.pk) else {
                    throw Fund("korrektur", "korrigierte Teile passen nicht zum Kopf")
                }
                return "teilepruefen:" + codes.joined(separator: "+")
            } catch let x as SiegelError {
                guard Self.erlaubt(x) else { throw Fund("fehlertyp", "matchRecoveryShares: " + fehlerCode(x)) }
                if erwartung { throw Fund("korrektur", "korrigierbare Teile nicht gefunden (" + fehlerCode(x) + ")") }
                return "teilepruefen:" + fehlerCode(x)
            }
        }
    }
}
#endif
