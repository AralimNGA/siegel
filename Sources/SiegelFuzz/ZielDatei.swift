#if DEBUG
import CryptoKit
import Foundation
@testable import SiegelCore

/// Ziel „datei“: Tresordateien v1/v2 (SPEC §2, §13.2), strukturbewusst mutiert.
///
/// Rahmung: Byte 0 = Index der Saat, danach die (mutierte) Datei.
/// Invarianten:
/// - kein Absturz, kein Hänger; jeder Fehler ist ein `SiegelError` aus der erlaubten Menge;
/// - die Prüfsumme wird vor allem anderen geprüft (eigene, unabhängige Nachrechnung);
/// - eine Datei, die nicht bytegleich mit einer Saat ist, öffnet nie – weder über Passwort (+ Faktoren) noch über
///   den Notfallweg, auch nicht mit neu berechneter Prüfsumme;
/// - Präzision: nur Inhalt geändert (Kopf und Slots gleich) → `corruptFile`; Kopf unverändert → der Notfallweg
///   meldet nach der pk-Prüfung nur `corruptFile`, nie `wrongRecoveryCode` (§1.3).
final class ZielDatei: FuzzZiel {
    let name = "datei"
    let zeitlimit = 20.0
    private(set) var saaten: [TresorSaat] = []
    private var saatHashes = Set<String>()
    private let korpus = Korpus()
    private var z = Zufall(saat: 1)
    var zusatz: [String: Int] = [:]
    var neueSaat = false

    func vorbereiten(_ u: Umgebung) throws {
        saaten = try SaatErzeugung.laden(u, neu: neueSaat)
        try SaatErzeugung.selbsttest(saaten)
        precondition(saaten.count < 256, "saat.anzahl")
        for (i, s) in saaten.enumerated() {
            saatHashes.insert(sha256Hex(s.bytes))
            korpus.saatAufnehmen([UInt8(i)] + s.bytes)
        }
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    // MARK: Erzeugen

    /// Nur Mutanten der Fixtures (für den Python-Differenztest, referenz/differenz.sh): echte KDF-Profile.
    var nurFixtures = false

    func naechste(_ z: inout Zufall) -> [UInt8] {
        var basis = korpus.waehle(&z)
        if nurFixtures {
            let fx = saaten.indices.filter { saaten[$0].echtesProfil }
            if !fx.contains(Int(basis[0]) % saaten.count), let k = fx.isEmpty ? nil : z.pick(fx) {
                basis = [UInt8(k)] + saaten[k].bytes
            }
        }
        let k = Int(basis[0]) % saaten.count
        var b = Array(basis.dropFirst())
        let s = saaten[k]
        for _ in 0..<z.int(1...3) { b = mutiere(b, s, &z) }
        pruefsumme(&b, &z)
        return [UInt8(k)] + b
    }

    private func feld(_ s: TresorSaat, _ name: String) -> Feld? { s.layout.first { $0.name == name } }

    private func setze(_ b: inout [UInt8], _ f: Feld, _ werte: [UInt8]) {
        for (i, v) in werte.enumerated() where f.bereich.lowerBound + i < min(f.bereich.upperBound, b.count) {
            b[f.bereich.lowerBound + i] = v
        }
    }

    private func setzeZahl(_ b: inout [UInt8], _ f: Feld, _ v: UInt64) {
        let n = f.ganzzahl > 0 ? f.ganzzahl : f.bereich.count
        setze(&b, f, (0..<n).map { UInt8(truncatingIfNeeded: v >> UInt64(8 * $0)) })
    }

    private func leseZahl(_ b: [UInt8], _ f: Feld) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<min(8, f.ganzzahl) where f.bereich.lowerBound + i < b.count {
            v |= UInt64(b[f.bereich.lowerBound + i]) << UInt64(8 * i)
        }
        return v
    }

    /// Grenzwerte je Ganzzahlfeld.
    private func grenzwerte(_ f: Feld, _ b: [UInt8]) -> [UInt64] {
        let aktuell = leseZahl(b, f)
        let nah = [aktuell &+ 1, aktuell &- 1]
        switch f.name {
        case "version": return [0, 1, 2, 3, 0x100, 0xFFFF]
        case "kdfAlg": return [0, 1, 2, 0xFF]
        case "ops": return [0, 1, 2, 3, 4, 10, 11, 0x7FFF_FFFF, 0xFFFF_FFFF] + nah
        case "mem": return [0, 1024, (8 << 10) - 1024, 8 << 10, (8 << 10) + 1, 16 << 10, 1 << 20, (1 << 20) + 1024,
                            256 << 20, (256 << 20) - 1024, 4 << 30, (4 << 30) + 1024, UInt64.max] + nah
        case "mask": return [0, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x80, 0xFF]
        case "scheme": return [0, 1, 2, 3, 0xFF]
        case "credLen": return [0, 1, 15, 16, 17, 1023, 1024, 1025, 0xFFFF] + nah
        case "generation": return [0, 1, UInt64.max, UInt64.max - 1] + nah
        case "ctLen":
            return [0, 16, 16_399, 16_400, 16_401, 16_400 + 16_384, 64 << 20, (64 << 20) + 1, 0xFFFF_FFFF,
                    aktuell &+ 16_384, aktuell &- 16_384] + nah
        default: return [0, 1, UInt64.max] + nah
        }
    }

    private static let abschnitte: [(String, [String])] = [
        ("kopf", ["magic", "version", "vaultID", "kdfAlg", "ops", "mem", "salt", "mask", "scheme", "seKeyID", "cardTag",
                  "credLen", "credID", "fidoSalt", "pkM", "pkX"]),
        ("slots", ["pwSlot.nonce", "pwSlot.ct", "pwSlot.tag", "ctM", "ctX", "recSlot.nonce", "recSlot.ct", "recSlot.tag"]),
        ("pwSlot", ["pwSlot.nonce", "pwSlot.ct", "pwSlot.tag"]),
        ("recSlot", ["recSlot.nonce", "recSlot.ct", "recSlot.tag"]),
        ("kapsel", ["ctM", "ctX"]),
        ("pk", ["pkM", "pkX"]),
        ("faktorfelder", ["mask", "scheme", "seKeyID", "cardTag", "credLen", "credID", "fidoSalt"]),
        ("inhalt", ["generation", "payload.nonce", "ctLen", "payload.ct", "payload.tag"]),
    ]

    private func bereich(_ s: TresorSaat, _ namen: [String]) -> Range<Int>? {
        let fs = s.layout.filter { namen.contains($0.name) }
        guard let a = fs.map(\.bereich.lowerBound).min(), let e = fs.map(\.bereich.upperBound).max() else { return nil }
        return a..<e
    }

    private func mutiere(_ input: [UInt8], _ s: TresorSaat, _ z: inout Zufall) -> [UInt8] {
        var b = input
        let felder = s.layout.filter { $0.bereich.upperBound <= b.count }
        guard !felder.isEmpty else { return Mutator.bytes(b, &z) }
        switch z.int(14) {
        case 0, 1:
            // Bit in einem Feld kippen (Kopf und Slots bevorzugt: kleine Felder zählen gleich viel wie grosse)
            let f = z.pick(felder)
            b[f.bereich.lowerBound + z.int(f.bereich.count)] ^= UInt8(1) << UInt8(z.int(8))
        case 2:
            // Feld auf Null / FF / Zufall / Wert derselben Stelle einer anderen Saat
            let f = z.pick(felder)
            let anders = z.pick(saaten)
            switch z.int(4) {
            case 0: setze(&b, f, [UInt8](repeating: 0, count: f.bereich.count))
            case 1: setze(&b, f, [UInt8](repeating: 0xFF, count: f.bereich.count))
            case 2: setze(&b, f, z.bytes(f.bereich.count))
            default:
                if let g = anders.layout.first(where: { $0.name == f.name }), g.bereich.upperBound <= anders.bytes.count {
                    setze(&b, f, Array(anders.bytes[g.bereich]))
                }
            }
        case 3, 4:
            // Ganzzahlfeld auf Grenzwert
            let ints = felder.filter { $0.ganzzahl > 0 }
            if let f = ints.isEmpty ? nil : z.pick(ints) { setzeZahl(&b, f, z.pick(grenzwerte(f, b))) }
        case 5:
            b = maskeKonsistent(b, s, &z)
        case 6:
            b = credLaenge(b, s, &z)
        case 7:
            // Kürzen an einer Feldgrenze (± wenige Byte)
            let f = z.pick(felder)
            let n = max(0, min(b.count, f.bereich.lowerBound + z.int(-3...3)))
            b = Array(b.prefix(n))
        case 8:
            // Einfügen/Löschen an einer Feldgrenze
            let f = z.pick(felder)
            let at = min(b.count, f.bereich.lowerBound)
            if z.chance(0.5) {
                b.insert(contentsOf: z.bytes(z.pick([1, 2, 4, 8, 16, 32])), at: at)
            } else {
                let n = min(b.count - at, z.pick([1, 2, 4, 16, f.bereich.count]))
                b.removeSubrange(at..<(at + n))
            }
        case 9:
            // Abschnitt aus einer anderen Saat einsetzen (Teile zwischen Tresoren vertauschen)
            let (_, namen) = z.pick(Self.abschnitte)
            let anders = z.pick(saaten)
            if let hier = bereich(s, namen), let dort = bereich(anders, namen), hier.upperBound <= b.count {
                b.replaceSubrange(hier, with: anders.bytes[dort])
            }
        case 10:
            // Polster-Bereich: letzte Blöcke des Chiffrats vor dem Tag (Klartext dort = Padding)
            if let f = feld(s, "payload.ct"), f.bereich.upperBound <= b.count, f.bereich.count > 64 {
                let i = f.bereich.upperBound - 1 - z.int(64)
                b[i] ^= UInt8(1) << UInt8(z.int(8))
            }
        case 11:
            // Datei verlängern
            b += z.bytes(z.pick([1, 16, 32, 16_384]))
        case 12:
            // ctLen konsistent mit der Dateilänge ändern (Chiffrat kürzen/verlängern)
            if let f = feld(s, "ctLen"), let ct = feld(s, "payload.ct"), ct.bereich.upperBound + 48 <= b.count {
                let delta = z.pick([-16_384, -16, -1, 1, 16, 16_384])
                var neu = Int(leseZahl(b, f)) + delta
                neu = max(0, neu)
                setzeZahl(&b, f, UInt64(neu))
                if delta > 0 {
                    b.insert(contentsOf: z.bytes(delta), at: ct.bereich.upperBound)
                } else {
                    let a = max(ct.bereich.lowerBound, ct.bereich.upperBound + delta)
                    b.removeSubrange(a..<ct.bereich.upperBound)
                }
            }
        default:
            b = Mutator.bytes(b, &z, schritte: z.int(1...2), maxLaenge: FileFormat.maxFileBytes)
        }
        return b
    }

    /// v2: Maske mit passenden Feldern (Nullfelder bzw. Werte), damit der Kopf den Parser besteht und Krypto erreicht.
    private func maskeKonsistent(_ input: [UInt8], _ s: TresorSaat, _ z: inout Zufall) -> [UInt8] {
        guard s.header.formatVersion == 2, let m = feld(s, "mask"), let se = feld(s, "seKeyID"),
              let tag = feld(s, "cardTag"), let fs = feld(s, "fidoSalt"), fs.bereich.upperBound <= input.count else {
            return input
        }
        var b = input
        let maske = UInt8(z.int(8))
        setze(&b, m, [maske])
        setze(&b, se, maske & 1 != 0 ? (z.chance(0.1) ? [UInt8](repeating: 0, count: 16) : z.bytes(16))
                                       : [UInt8](repeating: 0, count: 16))
        setze(&b, tag, maske & 2 != 0 ? z.bytes(4) : [0, 0, 0, 0])
        setze(&b, fs, maske & 4 != 0 ? (z.chance(0.1) ? [UInt8](repeating: 0, count: 32) : z.bytes(32))
                                      : [UInt8](repeating: 0, count: 32))
        let hatFido = (s.header.factorFields.fidoCredentialID != nil)
        if (maske & 4 != 0) != hatFido {
            return credLaenge(b, s, &z, neu: maske & 4 != 0 ? z.pick([16, 48, 1024]) : 0)
        }
        return b
    }

    /// Credential-Länge ändern und die Bytes passend einfügen/entfernen (Kopf bleibt sonst gültig).
    private func credLaenge(_ input: [UInt8], _ s: TresorSaat, _ z: inout Zufall, neu: Int? = nil) -> [UInt8] {
        guard s.header.formatVersion == 2, let lf = feld(s, "credLen"), lf.bereich.upperBound <= input.count else {
            return input
        }
        var b = input
        let alt = Int(leseZahl(b, lf))
        let n = neu ?? z.pick([0, 1, 15, 16, 17, 64, 1023, 1024, 1025, alt + 1, max(0, alt - 1)])
        setzeZahl(&b, lf, UInt64(n))
        let start = lf.bereich.upperBound
        let altEnde = min(b.count, start + alt)
        b.replaceSubrange(start..<altEnde, with: z.bytes(n))
        return b
    }

    /// Prüfsumme: meist neu berechnet (Angreifer), sonst alt, mit falschem Label oder Zufall.
    private func pruefsumme(_ b: inout [UInt8], _ z: inout Zufall) {
        guard b.count > 32 else { return }
        let koerper = Array(b.dropLast(32))
        switch z.int(20) {
        case 0..<12: b = koerper + FileFormat.fileChecksum(koerper[...])
        case 12, 13: b = koerper + FileFormat.fileChecksum(koerper[...], version: z.pick([1, 2, 3]))
        case 14: b = koerper + z.bytes(32)
        default: break
        }
    }

    // MARK: Prüfen

    /// Unabhängig nachgerechnet (SPEC §2): SHA3-256("Siegel v<n> file check" ‖ alles davor), n aus Byte 6–7.
    static func pruefsummeStimmt(_ b: [UInt8]) -> Bool {
        guard b.count >= 32 + 8 else { return false }
        let v = UInt16(b[6]) | UInt16(b[7]) << 8
        var h = SHA3_256()
        h.update(data: Array("Siegel v\(v) file check".utf8))
        h.update(data: Array(b.dropLast(32)))
        return Array(h.finalize()) == Array(b.suffix(32))
    }

    private static func istKorrupt(_ e: SiegelError, _ codes: [String]? = nil) -> Bool {
        if case let .corruptFile(c) = e { return codes.map { $0.contains(c) } ?? true }
        return false
    }

    private static func erlaubtLesen(_ e: SiegelError) -> Bool {
        switch e {
        case .corruptFile, .unsupportedVersion: return true
        default: return false
        }
    }

    private static func erlaubtOeffnen(_ e: SiegelError, notfall: Bool) -> Bool {
        switch e {
        case .corruptFile, .unsupportedVersion, .kdfParametersOutOfRange, .kdfFailed: return true
        case .wrongPassword, .factorMissing, .wrongCard: return !notfall
        case .wrongRecoveryCode: return notfall
        default: return false
        }
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard let k0 = e.first else { return "leer" }
        let s = saaten[Int(k0) % saaten.count]
        let b = Array(e.dropFirst())
        let identisch = saatHashes.contains(sha256Hex(b))
        let summeOK = Self.pruefsummeStimmt(b)

        // Kopf-Auskunft (VaultStore.inspect ohne Datei): Prüfsumme + Kopf, kein Argon2.
        do {
            try VaultFile.verifyChecksum(b)
            _ = try VaultFile.parseHeaderOnly(Array(b.dropLast(FileFormat.checksumBytes))).info
        } catch let x as SiegelError {
            guard Self.erlaubtLesen(x) else { throw Fund("fehlertyp", "Kopf-Auskunft: " + fehlerCode(x)) }
        } catch {
            throw Fund("fehlertyp", "Kopf-Auskunft: kein SiegelError (" + fehlerCode(error) + ")")
        }

        let file: VaultFile
        do {
            file = try VaultFile.parse(b)
        } catch let x as SiegelError {
            guard Self.erlaubtLesen(x) else { throw Fund("fehlertyp", "parse: " + fehlerCode(x)) }
            if !summeOK, !Self.istKorrupt(x, ["file.checksum", "file.length"]) {
                throw Fund("reihenfolge", "falsche Prüfsumme, aber zuerst " + fehlerCode(x) + " gemeldet")
            }
            return "parse:" + fehlerCode(x)
        } catch {
            throw Fund("fehlertyp", "parse: kein SiegelError (" + fehlerCode(error) + ")")
        }
        guard summeOK else { throw Fund("pruefsumme", "Datei mit falscher Prüfsumme wurde gelesen") }

        let nurInhalt = file.header == s.header && file.slots == s.datei.slots
        var code = "pw:"
        // Passwortweg (teure Argon2-Läufe nur bei den Fixtures mit fremden Parametern überspringen)
        if s.echtesProfil, file.header.kdf != s.header.kdf, (try? KDFLimits.production.validate(file.header.kdf)) != nil {
            zusatz["argon2_teuer_uebersprungen", default: 0] += 1
            code += "uebersprungen"
        } else {
            if s.echtesProfil, file.header.salt != s.header.salt { zusatz["argon2_256MiB_neues_salz", default: 0] += 1 }
            do {
                _ = try VaultCrypto.openWithPassword(file, password: s.pw, factors: s.faktoren, limits: s.limits,
                                                     cache: s.cache)
                if !identisch { throw Fund("oeffnet", "manipulierte Datei öffnet über den Passwortweg") }
                code += "ok"
            } catch let x as SiegelError {
                guard Self.erlaubtOeffnen(x, notfall: false) else { throw Fund("fehlertyp", "Passwortweg: " + fehlerCode(x)) }
                if nurInhalt, !Self.istKorrupt(x) {
                    throw Fund("praezision", "nur Inhalt geändert, Passwortweg meldet " + fehlerCode(x))
                }
                code += fehlerCode(x)
            }
        }
        // Notfallweg (inkl. Entsiegeln wie bei recover)
        code += "|rec:"
        do {
            let o = try VaultCrypto.openWithRecovery(file, r: s.r)
            _ = try VaultStore.unsealed(o, r: s.r)
            if !identisch { throw Fund("oeffnet", "manipulierte Datei öffnet über den Notfallweg") }
            code += "ok"
        } catch let x as SiegelError {
            guard Self.erlaubtOeffnen(x, notfall: true) else { throw Fund("fehlertyp", "Notfallweg: " + fehlerCode(x)) }
            if case .wrongRecoveryCode = x, file.header.pk == s.header.pk, file.header.vaultID == s.header.vaultID {
                throw Fund("praezision", "Kit stimmt, trotzdem wrongRecoveryCode statt corruptFile (§1.3)")
            }
            if nurInhalt, !Self.istKorrupt(x) {
                throw Fund("praezision", "nur Inhalt geändert, Notfallweg meldet " + fehlerCode(x))
            }
            code += fehlerCode(x)
        }
        if identisch { zusatz["unveraendert", default: 0] += 1 }
        return code
    }
}
#endif
