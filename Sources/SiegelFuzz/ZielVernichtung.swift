#if DEBUG
import CryptoKit
import Darwin
import Foundation
@testable import SiegelCore

// Ziel „vernichtung“ (SPEC §23): gefuzzter Zustand `Hardware/zustand.json`, gefuzzte Ablage des
// Vernichtungs-Passworts (`<fileID>.siegelhw`), Vertauschen zwischen zwei Saat-Tresoren und eine gefuzzte Welt
// (V fehlt oder fremd, Tresordatei kaputt oder fehlt, Rollback-Wächter, schreibgeschützter Hardware-Ordner,
// Vernichtungs-Schicht mit Fehlverhalten, Wettlauf um zustand.json zwischen Probe und Vermerk); danach bis zu
// 12 Vorgänge: Status, Totmann mit gefuzzter Uhr (Anker + Abstand), Entsperren mit Faktor-Varianten, Sicherung
// einspielen und – in einer offen gehaltenen Sitzung – Eintrag speichern, Passwortwechsel, Selbstvernichtung
// einstellen (Vernichtungs-Passwort ersetzen bzw. entfernen, Einstellungen, Markieren), Notfallweg, Verbotenes in der
// Vernichtungs-Sitzung, alte Ablage zurücklegen.
//
// Orakel: ein eigenes Modell der dokumentierten Abläufe (ZielVernichtungModell.swift, nach KERN-NOTIZEN.md,
// Abschnitt Selbstvernichtung), eigene Leser (ZielVernichtungLeser.swift) und modellfreie Invarianten
// (ZielVernichtungAblauf.swift). Jeder Widerspruch ist ein Fund.

final class ZielVernichtung: FuzzZiel {
    let name = "vernichtung"
    let zeitlimit = 60.0
    var zusatz: [String: Int] = [:]
    var neueSaat = false
    let korpus = Korpus()
    private var z = Zufall(saat: 23)
    var saaten: [VSaat] = []
    var wurzel: URL?
    var zaehler = 0

    static let tag: TimeInterval = 86_400
    static let fehlerSE = fehlerCode(SiegelError.factorUnavailable(.secureEnclave))
    static let fehlerFalsch = fehlerCode(SiegelError.wrongPassword)
    static let fehlerNichtDa = fehlerCode(SiegelError.io("entry.notFound"))
    static let falschesPasswort = "Falsch-q8,Vd:Lk3#xRw+Tz!mP9@bN6^cJ2"
    static let maxVorgaenge = 12

    static func kanonisch(_ d: Date) -> Date { Date(timeIntervalSince1970: d.timeIntervalSince1970) }
    static func uuid(_ b: [UInt8]) -> UUID { VaultHeader.uuid(b) }
    static func hw(_ id: UUID) -> String { SaatWerte.hwName(id).lowercased() }
    static var t0: Double { SaatWerte.zeitpunkt.timeIntervalSince1970 }

    /// Bits der gefuzzten Welt.
    enum W {
        /// V von A fehlt.
        static let vFehlt: UInt16 = 1 << 0
        /// V-Datei von B (eigene Kennung) dazulegen.
        static let vVonB: UInt16 = 1 << 1
        /// V-Rohbytes von B unter dem V-Namen von A (fremdes Material unter dem richtigen Namen).
        static let vVonBUnterA: UInt16 = 1 << 2
        /// Tresordatei mit Bitfehler im Inhalt (Kopf lesbar).
        static let tresorKaputt: UInt16 = 1 << 3
        /// Tresordatei fehlt.
        static let tresorFehlt: UInt16 = 1 << 4
        /// Rollback-Wächter kennt eine höhere Generation.
        static let rollback: UInt16 = 1 << 5
        /// Hardware-Ordner schreibgeschützt (`chflags uchg`: kein Anlegen, Umbenennen, Löschen; Inhalte bestehender
        /// Dateien lassen sich weiter überschreiben).
        static let schreibschutz: UInt16 = 1 << 6
        /// Zwei Bits Modus der Vernichtungs-Schicht (s. `ProtokollEraser.Modus`).
        static let eraserVerschiebung: UInt16 = 7
        /// Wettlauf: zwischen Probe (beide Argon2) und Vermerk tauscht ein Testhaken zustand.json gegen eine Fassung,
        /// die den Entsperr-SE-Schlüssel als V nennt.
        static let wettlauf: UInt16 = 1 << 9
        static let alle: UInt16 = (1 << 10) - 1
    }

    /// Eine Vernichtungs-Saat mit allem, was Modell und Prüfungen brauchen.
    final class VSaat {
        let saat: TresorSaat
        let v: VernichtungsSaat
        let header: VaultHeader
        let inhalt: InhaltM
        let alle: Set<UUID>
        let vernichtbar: Set<UUID>
        let versiegelt: Set<UUID>
        /// Gelöschte Einträge („Zuletzt gelöscht“) mit Löschzeitpunkt.
        let geloescht: [UUID: Date]
        let eintragKeyID: UUID?
        let duressPasswort: String?
        let zustand0: [UInt8]
        let ablage0: [UInt8]?
        /// Schutz 1 (offen) und sichtbar: für „Eintrag speichern“.
        let offenID: UUID?
        /// Versiegelt mit Schutz ≥ 4, nicht vernichtbar: für „Eintrag speichern“ und „Markieren“.
        let markierbarID: UUID?
        /// Geheimteile je Eintrag beim ersten echten Entsperren (nil = vernichtet).
        var erwartet: [UUID: EntrySecrets?] = [:]

        init(_ s: TresorSaat, _ v: VernichtungsSaat) throws {
            saat = s
            self.v = v
            header = s.header
            guard let c = s.inhalt, let cfg = c.destruction else { throw Fund("saat", "Vernichtungs-Saat ohne Inhalt") }
            inhalt = InhaltM(deadmanDays: cfg.settings.deadmanDays, maxFailed: cfg.settings.maxFailedAttempts,
                             duressEnabled: cfg.settings.duressEnabled, vKeyID: cfg.vKey?.keyID,
                             duressFileID: cfg.duress?.fileID)
            alle = Set(c.entries.filter { $0.deletedAt == nil }.map(\.id))
            vernichtbar = Set(c.destructible.keys)
            versiegelt = Set(c.sealed.keys)
            var g: [UUID: Date] = [:]
            for e in c.entries { if let d = e.deletedAt { g[e.id] = d } }
            geloescht = g
            eintragKeyID = c.entryFactors.secureEnclave?.keyID
            duressPasswort = v.plan.passwort
            zustand0 = v.zustand ?? []
            ablage0 = cfg.duress.flatMap { v.dateien[v.pfad($0.fileID)] }
            offenID = c.entries.first { $0.deletedAt == nil && !$0.secretsSealed }?.id
            markierbarID = c.entries.first {
                $0.deletedAt == nil && $0.protection >= .maximal && c.sealed[$0.id] != nil && c.destructible[$0.id] == nil
            }?.id
        }

        var vaultID: UUID { header.uuid }
        var seKeyID: UUID? { header.factorFields.seKeyID }
        var vKeyID: UUID { v.plan.vKeyID }
        var passwort: String { saat.passwort }
        var stufe: SecurityLevel { v.stufe }
        var faktoren: FactorSecrets { SaatWerte.faktoren(v.stufe.factors) }
    }

    // MARK: Vorbereiten

    func vorbereiten(_ u: Umgebung) throws {
        let alle = try SaatErzeugung.laden(u, neu: neueSaat)
        try SaatErzeugung.selbsttest(alle)
        saaten = try alle.compactMap { s in try s.vernichtung.map { try VSaat(s, $0) } }
        guard saaten.count >= 2 else { throw Fund("saat", "zu wenige Vernichtungs-Saaten") }
        // §23.1: Sicherungen der Saaten liefern mit dem Notfallcode keine vernichtbaren Einträge.
        for s in saaten { try SaatErzeugung.sicherungenPruefen(s.saat) }
        wurzel = FileManager.default.temporaryDirectory
            .appendingPathComponent("siegelfuzz-vernichtung-\(getpid())", isDirectory: true)
        let wurzelPfad = wurzel?.path ?? ""
        _ = atexit_b { _ = try? FileManager.default.removeItem(atPath: wurzelPfad) }
        // Erwartete Geheimteile: einmal echt entsperren (Kopie im Temp-Ordner) und alles aufdecken.
        for (i, s) in saaten.enumerated() {
            var roh = Eingabe(a: UInt8(i), b: UInt8(i))
            roh.zustand = s.zustand0
            roh.ablage = s.ablage0 ?? []
            let ordner = try aufbauen(roh, s, s)
            defer { aufraeumen(ordner) }
            let store = VaultStore(directory: ordner, rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
            let v = try TestHooks.$now.withValue(SaatWerte.zeitpunkt.addingTimeInterval(60)) {
                Self.sitzung(try store.unlock(masterPassword: s.passwort, factors: s.faktoren))
            }
            defer { v.lock() }
            guard !v.isDuressSession, Set(v.entries.map(\.id)) == s.alle else {
                throw Fund("saat", "Saat \(s.saat.name): echtes Entsperren zeigt nicht alle Einträge")
            }
            let anbieter = DateiAnbieter(hardware: store.hardwareDirectory, vKeyID: s.vKeyID)
            for id in s.alle {
                do {
                    s.erwartet[id] = .some(try synchron { try await v.revealSecrets(id: id, factors: anbieter) })
                    if s.vernichtbar.contains(id), s.saat.vVernichtet {
                        throw Fund("saat", "Saat \(s.saat.name): vernichteter Eintrag lesbar")
                    }
                } catch let x as SiegelError {
                    guard s.vernichtbar.contains(id), s.saat.vVernichtet, x == .factorUnavailable(.secureEnclave) else {
                        throw Fund("saat", "Saat \(s.saat.name): Eintrag nicht lesbar (" + fehlerCode(x) + ")")
                    }
                    s.erwartet[id] = .some(nil)
                }
            }
            // Eigener Leser: Zustand und Ablage der Saat werden gelesen, das Vernichtungs-Passwort erkannt.
            guard case .gueltig = ZustandM.lesen(JWert.lesen(s.zustand0) ?? .null) else {
                throw Fund("saat", "Saat \(s.saat.name): eigener Leser versteht zustand.json nicht")
            }
            if let d = s.inhalt.duressFileID, let pw = s.duressPasswort {
                guard let a = s.ablage0, let f = AblageBefund.lesen(a, erwartet: d),
                      AblageBefund.erkannt(pw, f, vaultID: s.header.vaultID, kdf: s.header.kdf),
                      !AblageBefund.erkannt(s.passwort, f, vaultID: s.header.vaultID, kdf: s.header.kdf) else {
                    throw Fund("saat", "Saat \(s.saat.name): eigener Prüfwert erkennt das Vernichtungs-Passwort nicht")
                }
            }
            guard s.offenID != nil, s.markierbarID != nil else {
                throw Fund("saat", "Saat \(s.saat.name): kein offener bzw. markierbarer Eintrag")
            }
            korpus.saatAufnehmen(Eingabe.frisch(UInt8(i), UInt8((i + 1) % saaten.count), s, &z).kodiert)
        }
        // Gezielte Abläufe als Saat-Eingaben, jede ungestörte Saat einmal als Selbsttest.
        for i in saaten.indices {
            for (k, ops) in Self.saatAblaeufe.enumerated() {
                var e = Eingabe(a: UInt8(i), b: UInt8((i + 1 + k) % saaten.count))
                e.zustand = saaten[i].zustand0
                e.ablage = saaten[i].ablage0 ?? []
                e.ops = ops
                korpus.saatAufnehmen(e.kodiert)
                _ = try pruefe(e.kodiert)
            }
        }
    }

    /// Ablauf-Vorlagen (Selbsttest und Saat-Korpus): Status, Totmann, Entsperren mit allen Passwörtern; Passwortwechsel
    /// mit anschliessendem Vernichtungs-Passwort; Ersetzen, Markieren, Entfernen; Vernichtungs-Sitzung mit Speichern und
    /// Verbotenem; Notfallweg; Faktor-Varianten; alte Ablage nach der Rotation.
    static let saatAblaeufe: [[Op]] = [
        [Op(0), Op(2, anker: 4, zeit: 3600), Op(3, anker: 4, zeit: 7200), Op(4, anker: 4, zeit: 9000),
         Op(1, anker: 4, zeit: 10_000)],
        [Op(4, anker: 4, zeit: 60), Op(10), Op(3), Op(4)],
        [Op(4, anker: 4, zeit: 60), Op(11, v: 0), Op(3), Op(3, v: 0x08), Op(4)],
        [Op(4, anker: 4, zeit: 60), Op(11, v: 2), Op(1, anker: 1, zeit: 1), Op(4)],
        [Op(4, anker: 4, zeit: 60), Op(11, v: 3), Op(3), Op(4)],
        [Op(4, anker: 4, zeit: 60), Op(11, v: 1), Op(13), Op(3), Op(9), Op(13, v: 1), Op(13, v: 2), Op(9, v: 2), Op(4)],
        [Op(3), Op(9), Op(9, v: 2), Op(13), Op(13, v: 1), Op(13, v: 2), Op(4), Op(14), Op(3)],
        [Op(12), Op(4), Op(9), Op(3)],
        [Op(2, v: 1), Op(2, v: 2), Op(2, v: 3), Op(3, v: 3), Op(4, v: 1), Op(4, v: 3), Op(6, v: 1), Op(8, v: 3), Op(4)],
        [Op(1, anker: 1, zeit: 0), Op(1, anker: 1, zeit: -1e-3), Op(4, anker: 1, zeit: 1), Op(14), Op(3), Op(4)],
    ]

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    // MARK: Eingabe

    /// Ein Vorgang: Art, Variante (Faktoren, Unterart), Zeit als Anker + Abstand (0 = absolut).
    struct Op: Equatable {
        var op: UInt8
        var v: UInt8 = 0
        /// 0 absolut, 1 Frist, 2 letzte echte Entsperrung, 3 letzte − 1 Tag, 4 t0 – aufgelöst zur Laufzeit aus dem
        /// Modell (deterministisch).
        var anker: UInt8 = 4
        var zeit: Double = 3600

        init(_ op: UInt8, v: UInt8 = 0, anker: UInt8 = 4, zeit: Double = 3600) {
            self.op = op
            self.v = v
            self.anker = anker
            self.zeit = zeit
        }
    }

    /// Rahmung (Version 2): 0xD2 ‖ a ‖ b ‖ Zustand-Art ‖ Ablage-Art ‖ Welt (u16 LE) ‖ n ‖
    /// n × (Op, Variante, Anker, Zeit f64 LE) ‖ u32 + Zustand ‖ u32 + Ablage.
    struct Eingabe {
        static let version: UInt8 = 0xD2
        var a: UInt8
        var b: UInt8
        /// 0 Datei, 1 fehlt, 2 Ordner, 3 Symlink → Tresordatei, 4 Symlink → V, 5 Symlink ins Leere
        var zArt: UInt8 = 0
        /// 0 unter A-Namen, 1 unter B-Namen, 2 fehlt, 3 unter beiden Namen
        var dArt: UInt8 = 0
        var welt: UInt16 = 0
        var ops: [Op] = []
        var zustand: [UInt8] = []
        var ablage: [UInt8] = []

        init(a: UInt8, b: UInt8) {
            self.a = a
            self.b = b
        }

        var kodiert: [UInt8] {
            var out: [UInt8] = [Self.version, a, b, zArt, dArt, UInt8(welt & 0xFF), UInt8(welt >> 8),
                                UInt8(min(ops.count, 255))]
            for o in ops.prefix(255) {
                out += [o.op, o.v, o.anker]
                out += withUnsafeBytes(of: o.zeit.bitPattern.littleEndian) { Array($0) }
            }
            out += withUnsafeBytes(of: UInt32(zustand.count).littleEndian) { Array($0) } + zustand
            out += withUnsafeBytes(of: UInt32(ablage.count).littleEndian) { Array($0) } + ablage
            return out
        }

        static func dekodieren(_ b: [UInt8]) -> Eingabe? {
            guard b.count >= 8, b[0] == version else { return nil }
            var e = Eingabe(a: b[1], b: b[2])
            e.zArt = b[3]
            e.dArt = b[4]
            e.welt = (UInt16(b[5]) | UInt16(b[6]) << 8) & W.alle
            var i = 8
            for _ in 0..<Int(b[7]) {
                guard i + 11 <= b.count else { return nil }
                var bits: UInt64 = 0
                for k in 0..<8 { bits |= UInt64(b[i + 3 + k]) << UInt64(8 * k) }
                e.ops.append(Op(b[i], v: b[i + 1], anker: b[i + 2], zeit: Double(bitPattern: bits)))
                i += 11
            }
            func block() -> [UInt8]? {
                guard i + 4 <= b.count else { return nil }
                let n = Int(b[i]) | Int(b[i + 1]) << 8 | Int(b[i + 2]) << 16 | Int(b[i + 3]) << 24
                i += 4
                guard n <= b.count - i else { return nil }
                defer { i += n }
                return Array(b[i..<(i + n)])
            }
            guard let zz = block(), let aa = block() else { return nil }
            e.zustand = zz
            e.ablage = aa
            return e
        }

        /// Frische Eingabe: Status, ein paar Vorgänge, oft ein Block in einer offenen Sitzung, am Schluss meist echt.
        static func frisch(_ a: UInt8, _ b: UInt8, _ s: VSaat, _ z: inout Zufall) -> Eingabe {
            var e = Eingabe(a: a, b: b)
            e.zustand = s.zustand0
            e.ablage = s.ablage0 ?? []
            e.ops = [Op(0)]
            for _ in 0..<z.int(1...3) { e.ops.append(ZielVernichtung.zufallsOp(&z)) }
            if z.chance(0.5) {
                e.ops.append(Op(z.chance(0.7) ? 4 : 3, v: 0, anker: 4, zeit: 60))
                for _ in 0..<z.int(1...2) { e.ops.append(ZielVernichtung.sitzungsOp(&z)) }
                e.ops.append(Op(UInt8(z.pick([1, 3, 3, 4, 2])), v: 0, anker: UInt8(z.pick([1, 4])), zeit: 1))
            }
            if z.chance(0.8) { e.ops.append(Op(4, v: 0, anker: UInt8(z.pick([1, 2, 4])), zeit: z.pick([1, -1, 3600]))) }
            if e.ops.count > ZielVernichtung.maxVorgaenge { e.ops = Array(e.ops.prefix(ZielVernichtung.maxVorgaenge)) }
            return e
        }
    }

    // MARK: Erzeugen

    /// Zeit eines Vorgangs: meist Anker (Frist, letzte, letzte − 1 Tag, t0) + kleiner Abstand an der Grenze.
    static func zufallsZeit(_ z: inout Zufall, uhr: Bool) -> (UInt8, Double) {
        if z.chance(0.75) {
            let anker = UInt8(z.pick([1, 1, 1, 2, 2, 3, 4, 4]))
            return (anker, z.pick([0, 1e-3, -1e-3, 1, -1, 0.5, -0.5, 3600, -3600, 86_400, -86_400, 10 * tag]))
        }
        var t = z.pick([t0, t0 + 10 * tag, t0 + 400 * tag, t0 - tag, t0 + 30 * tag])
        if z.chance(0.2) { t = Double(z.int(-2_000_000_000...4_000_000_000)) }
        if uhr, z.chance(0.2) {
            t = z.pick([.infinity, -.infinity, .nan, .greatestFiniteMagnitude, -.greatestFiniteMagnitude, 0, -1e12,
                        1e12, 1e300, -0.0, .leastNonzeroMagnitude])
        }
        return (0, t)
    }

    /// Faktor-Variante: meist korrekt (0), sonst Karte fehlt (1), Karte falsch (2), SE-Wert falsch (3), Schlüssel
    /// fehlt (4).
    static func zufallsVariante(_ z: inout Zufall) -> UInt8 {
        z.chance(0.7) ? 0 : UInt8(z.int(1...4))
    }

    static func zufallsOp(_ z: inout Zufall) -> Op {
        let op = UInt8(z.pick([0, 1, 1, 1, 2, 2, 3, 3, 3, 4, 4, 5, 6, 7, 8, 9, 10, 11, 11, 12, 13, 14]))
        if op >= 9 { return sitzungsOp(&z, op: op) }
        let (anker, zeit) = zufallsZeit(&z, uhr: op == 1)
        var v = zufallsVariante(&z)
        if op == 3, z.chance(0.25) { v |= 0x08 }
        return Op(op, v: v, anker: anker, zeit: zeit)
    }

    static func sitzungsOp(_ z: inout Zufall, op: UInt8? = nil) -> Op {
        let o = op ?? UInt8(z.pick([9, 9, 10, 10, 11, 11, 11, 11, 12, 13, 13, 14]))
        let (anker, zeit) = zufallsZeit(&z, uhr: false)
        return Op(o, v: z.byte(), anker: anker, zeit: zeit)
    }

    func saat(_ i: UInt8) -> VSaat { saaten[Int(i) % saaten.count] }

    func naechste(_ z: inout Zufall) -> [UInt8] {
        var e: Eingabe
        if let x = Eingabe.dekodieren(korpus.waehle(&z)) {
            e = x
        } else {
            e = Eingabe.frisch(UInt8(z.int(saaten.count)), UInt8(z.int(saaten.count)), saaten[0], &z)
        }
        for _ in 0..<z.int(1...3) { mutiere(&e, &z) }
        if e.ops.count > Self.maxVorgaenge { e.ops = Array(e.ops.prefix(Self.maxVorgaenge)) }
        return e.kodiert
    }

    private func kennungen(_ a: VSaat, _ b: VSaat) -> [UUID?] {
        [a.vKeyID, a.inhalt.duressFileID, a.eintragKeyID, a.seKeyID, b.vKeyID, b.inhalt.duressFileID, b.seKeyID,
         b.eintragKeyID, nil, UUID(uuidString: "0D0D0D0D-1111-4222-8333-444444444444")]
    }

    private func kennungWert(_ id: UUID?, _ z: inout Zufall) -> JWert {
        guard let id else { return .null }
        switch z.int(10) {
        case 0: return .str(id.uuidString.lowercased())
        case 1: return .str(String(id.uuidString.dropLast()))
        default: return .str(id.uuidString)
        }
    }

    private func zeitWert(_ z: inout Zufall) -> JWert {
        switch z.int(12) {
        case 0: return .null
        case 1: return .roh(z.pick(["1e999", "-1e999", "NaN", "Infinity", "-0", "1792000000.0", "1.792e9", "0e0"]))
        case 2: return .str("1792000000")
        case 3: return .dbl(z.pick([1e300, -1e300, 0.5, 1_792_000_000.25, -62_135_596_800.0, 253_402_300_800.0]))
        default:
            let (anker, zeit) = Self.zufallsZeit(&z, uhr: true)
            let t = anker == 0 ? zeit : Self.t0 + zeit
            return t == t.rounded() && abs(t) < 9e15 ? .int(Int64(t)) : .dbl(t)
        }
    }

    private func ganzWert(_ z: inout Zufall, _ werte: [Int64]) -> JWert {
        switch z.int(10) {
        case 0: return .null
        case 1: return .roh(z.pick(["1e1", "10.0", "-0", "9223372036854775808", "1e999"]))
        case 2: return .str("10")
        case 3: return .bool(true)
        default: return .int(z.pick(werte))
        }
    }

    /// Strukturbewusste Mutation des Zustands (Felder, Typen, Zeiten, Zähler, Kennungen, vaultID, Einstellungen).
    private func mutiereZustand(_ w: inout JWert, _ a: VSaat, _ b: VSaat, _ z: inout Zufall) {
        guard case .obj = w else {
            w = JWert.lesen(a.zustand0) ?? .obj([:])
            return
        }
        let ids = kennungen(a, b)
        switch z.int(16) {
        case 0:
            if z.chance(0.7) {
                let id = z.pick([a.vaultID, b.vaultID, z.uuid()])
                w["vaultID"] = kennungWert(id, &z)
            } else {
                w["vaultID"] = z.pick([.null, .int(1), .str("kaputt")])
            }
        case 1: w["vKeyID"] = kennungWert(z.pick(ids), &z)
        case 2: w["duressFileID"] = kennungWert(z.pick(ids), &z)
        case 3: w["lastGenuineUnlock"] = zeitWert(&z)
        case 4:
            let n = Int64(a.inhalt.maxFailed ?? 10)
            w["failedAttempts"] = ganzWert(&z, [0, 1, n - 1, n, n + 1, 1_000_000, 1_000_001, -1, Int64.max])
        case 5:
            var s = w["settings"] ?? .obj([:])
            switch z.int(4) {
            case 0: s["deadmanDays"] = ganzWert(&z, [6, 7, 8, 30, 365, 366, 0, -1])
            case 1: s["maxFailedAttempts"] = ganzWert(&z, [9, 10, 11, 20, 50, 100, 101])
            case 2: s["duressEnabled"] = z.pick([.bool(true), .bool(false), .int(1), .null])
            default: s = z.pick([.null, .arr([]), .obj([:])])
            }
            w["settings"] = s
        case 6:
            if z.chance(0.3) {
                w["destroyed"] = .null
            } else {
                let at = zeitWert(&z)
                w["destroyed"] = .obj(["keyID": kennungWert(z.pick(ids), &z),
                                       "trigger": .str(z.pick(["deadman", "failedAttempts", "duressPassword", "x"])),
                                       "at": at])
            }
        case 7: w["rekeyPending"] = z.pick([.bool(true), .bool(false), .null, .str("ja"), .int(1)])
        case 8: w["v"] = z.pick([.int(1), .int(2), .int(0), .str("1"), .dbl(1.0)])
        case 9:
            if case let .obj(o) = w, !o.isEmpty { w[z.pick(Array(o.keys).sorted())] = nil }
        case 10: w["extra"] = .int(1)
        case 11:
            // Zustand von B, wahlweise auf A umgeschrieben (vertauscht)
            w = JWert.lesen(b.zustand0) ?? w
            if z.chance(0.5) { w["vaultID"] = .str(a.vaultID.uuidString) }
        case 12:
            // gültig machen: Vernichtungs-Passwort ⇔ Ablage, Bereiche
            var s = w["settings"] ?? .obj([:])
            if case .obj = s {} else { s = .obj([:]) }
            let hatAblage: Bool = { if case .str? = w["duressFileID"] { return true } else { return false } }()
            s["duressEnabled"] = .bool(hatAblage)
            if case let .int(d)? = s["deadmanDays"], !(7...365).contains(d) { s["deadmanDays"] = .int(7) }
            if case let .int(n)? = s["maxFailedAttempts"], !(10...100).contains(n) { s["maxFailedAttempts"] = .int(10) }
            w["settings"] = s
            if case let .int(f)? = w["failedAttempts"], !(0...1_000_000).contains(f) { w["failedAttempts"] = .int(0) }
            w["vaultID"] = .str(a.vaultID.uuidString)
            w["v"] = .int(1)
        case 13:
            // Totmann scharf: Frist kurz und lange vorbei
            var s = w["settings"] ?? .obj([:])
            s["deadmanDays"] = .int(Int64(z.pick([7, 8, 30])))
            w["settings"] = s
            w["lastGenuineUnlock"] = .int(Int64(Self.t0) - Int64(z.pick([0, 6, 7, 8, 100])) * 86_400)
            if z.chance(0.5) { w["vKeyID"] = kennungWert(z.pick(ids), &z) }
        case 14:
            // Zähler scharf: kurz vor der Schwelle
            var s = w["settings"] ?? .obj([:])
            let n = z.pick([10, 11, 20])
            s["maxFailedAttempts"] = .int(Int64(n))
            w["settings"] = s
            w["failedAttempts"] = .int(Int64(n - z.int(1...2)))
            if z.chance(0.5) { w["vKeyID"] = kennungWert(z.pick(ids), &z) }
        default:
            w = z.pick([.arr([]), .null, .str("x"), .int(1), .obj([:])])
        }
    }

    /// Regionen der Ablage (Format siehe AblageBefund).
    private static let regionen: [Range<Int>] = [0..<8, 8..<10, 10..<11, 11..<27, 27..<29, 29..<45, 45..<61,
                                                  61..<1629, 1629..<1661, 1661..<1733, 1733..<1951, 1951..<2016,
                                                  2016..<2048]

    private func mutiereAblage(_ e: inout Eingabe, _ a: VSaat, _ b: VSaat, _ z: inout Zufall) {
        var x = e.ablage
        if x.count != AblageBefund.laenge || z.chance(0.1) { x = z.chance(0.7) ? (a.ablage0 ?? b.ablage0 ?? x) : (b.ablage0 ?? x) }
        var neuSumme = z.chance(0.8)
        switch z.int(9) {
        case 0, 1:
            if x.count == AblageBefund.laenge {
                let r = z.pick(Self.regionen)
                x[r.lowerBound + z.int(r.count)] ^= UInt8(1) << UInt8(z.int(8))
            }
        case 2: if x.count > 10 { x[10] = z.pick([0, 1, 3, 2]) }
        case 3:
            if x.count >= 27 {
                let id = z.pick([b.inhalt.duressFileID, a.vKeyID, z.uuid(), a.inhalt.duressFileID].compactMap { $0 })
                x.replaceSubrange(11..<27, with: VaultHeader.bytes(of: id))
            }
        case 4: if x.count > 9 { x[8] = 2 }
        case 5: if x.count > 28 { x[27] = 0x81 }
        case 6:
            if x.count == AblageBefund.laenge {
                let gueltig = (try? P256.KeyAgreement.PrivateKey(rawRepresentation: z.bytes(32)))
                    .map { Array($0.publicKey.x963Representation) }
                let p: [UInt8] = z.chance(0.5) ? [0x04] + [UInt8](repeating: 0, count: 64) : (gueltig ?? [0x04])
                x.replaceSubrange(1951..<2016, with: p)
            }
        case 7:
            x = z.chance(0.5) ? Array(x.prefix(z.int(0...max(0, x.count - 1)))) : x + z.bytes(z.int(1...64))
            neuSumme = false
        default:
            // Salz/Prüfwert/Kapsel von B einsetzen
            if x.count == AblageBefund.laenge, let bb = b.ablage0 {
                let r = z.pick([29..<45, 45..<61, 61..<1733, 29..<1733])
                x.replaceSubrange(r, with: bb[r])
            }
        }
        if neuSumme, x.count == AblageBefund.laenge {
            x.replaceSubrange(AblageBefund.summeAnfang..<AblageBefund.laenge,
                              with: AblageBefund.pruefsumme(x[0..<AblageBefund.summeAnfang]))
        }
        e.ablage = x
    }

    private func mutiere(_ e: inout Eingabe, _ z: inout Zufall) {
        let a = saat(e.a)
        let b = saat(e.b)
        switch z.int(14) {
        case 0, 1, 2:
            var w = JWert.lesen(e.zustand) ?? (JWert.lesen(a.zustand0) ?? .obj([:]))
            for _ in 0..<z.int(1...3) { mutiereZustand(&w, a, b, &z) }
            e.zustand = w.bytes
        case 3:
            e.zustand = Mutator.bytes(e.zustand, &z, maxLaenge: 20 << 10)
            if z.chance(0.05) { e.zustand += [UInt8](repeating: 0x20, count: 17 << 10) }
        case 4:
            e.zArt = z.chance(0.6) ? 0 : UInt8(z.int(1...5))
        case 5, 6:
            mutiereAblage(&e, a, b, &z)
            if z.chance(0.3) { e.dArt = UInt8(z.int(4)) }
        case 7:
            if !e.ops.isEmpty, z.chance(0.35) {
                e.ops.remove(at: z.int(e.ops.count))
            } else {
                e.ops.insert(Self.zufallsOp(&z), at: z.int(e.ops.count + 1))
            }
        case 8:
            // Sitzungs-Block einfügen: Entsperren, 1–2 Sitzungs-Vorgänge, danach ein Entsperren bzw. der Totmann
            var block = [Op(z.chance(0.75) ? 4 : 3, v: 0, anker: 4, zeit: 60)]
            for _ in 0..<z.int(1...2) { block.append(Self.sitzungsOp(&z)) }
            block.append(Op(UInt8(z.pick([3, 3, 4, 1, 2, 5])), v: z.chance(0.2) ? 0x08 : 0, anker: 1, zeit: z.pick([0, 1, -1])))
            e.ops.insert(contentsOf: block, at: z.int(e.ops.count + 1))
        case 9:
            if !e.ops.isEmpty {
                let i = z.int(e.ops.count)
                let (anker, zeit) = Self.zufallsZeit(&z, uhr: e.ops[i].op % 15 == 1)
                e.ops[i].anker = anker
                e.ops[i].zeit = zeit
            }
        case 10:
            if !e.ops.isEmpty {
                let i = z.int(e.ops.count)
                e.ops[i].v = e.ops[i].op >= 9 ? z.byte() : (Self.zufallsVariante(&z) | (z.chance(0.2) ? 0x08 : 0))
            }
        case 11:
            // Welt: meist ein Bit, selten der Eraser-Modus
            if z.chance(0.8) {
                e.welt ^= UInt16(1) << UInt16(z.pick([0, 1, 2, 3, 4, 5, 6, 9]))
            } else {
                e.welt ^= UInt16(z.int(1...3)) << W.eraserVerschiebung
            }
            e.welt &= W.alle
        case 12:
            if !e.ops.isEmpty { e.ops.swapAt(z.int(e.ops.count), z.int(e.ops.count)) }
        default:
            if z.chance(0.5) { e.a = UInt8(z.int(saaten.count)) } else { e.b = UInt8(z.int(saaten.count)) }
        }
    }

    // MARK: Umgebung aufbauen

    /// Tresorordner von A im Temp-Ordner, mit gefuzztem Zustand, gefuzzter Ablage und Welt-Bits. Der Schreibschutz
    /// wird erst nach dem Start des Modells gesetzt (`Lauf.schreibschutzSetzen`).
    func aufbauen(_ e: Eingabe, _ a: VSaat, _ b: VSaat) throws -> URL {
        zaehler += 1
        guard let wurzel else { throw SiegelError.io("fuzz.wurzel") }
        let ordner = wurzel.appendingPathComponent("e\(zaehler)", isDirectory: true)
            .appendingPathComponent("Siegel", isDirectory: true)
        aufraeumen(ordner)
        let fm = FileManager.default
        for (rel, bytes) in a.v.dateien {
            let u = ordner.appendingPathComponent(rel)
            try fm.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(bytes).write(to: u)
        }
        let hw = ordner.appendingPathComponent(VaultStore.hardwareFolderName, isDirectory: true)
        try fm.createDirectory(at: hw, withIntermediateDirectories: true)
        let zustandURL = hw.appendingPathComponent(DestructionState.fileName)
        try? fm.removeItem(at: zustandURL)
        switch e.zArt % 6 {
        case 0: try Data(e.zustand).write(to: zustandURL)
        case 1: break
        case 2: try fm.createDirectory(at: zustandURL, withIntermediateDirectories: false)
        case 3: try fm.createSymbolicLink(atPath: zustandURL.path, withDestinationPath: "../" + VaultStore.vaultFileName)
        case 4: try fm.createSymbolicLink(atPath: zustandURL.path, withDestinationPath: SaatWerte.hwName(a.vKeyID))
        default: try fm.createSymbolicLink(atPath: zustandURL.path, withDestinationPath: "gibt-es-nicht.json")
        }
        if let d = a.inhalt.duressFileID { try? fm.removeItem(at: hw.appendingPathComponent(SaatWerte.hwName(d))) }
        var namen: [UUID] = []
        switch e.dArt % 4 {
        case 0: namen = [a.inhalt.duressFileID].compactMap { $0 }
        case 1: namen = [b.inhalt.duressFileID].compactMap { $0 }
        case 2: namen = []
        default: namen = [a.inhalt.duressFileID, b.inhalt.duressFileID].compactMap { $0 }
        }
        for id in Set(namen) where !e.ablage.isEmpty {
            try Data(e.ablage).write(to: hw.appendingPathComponent(SaatWerte.hwName(id)))
        }
        let vA = hw.appendingPathComponent(SaatWerte.hwName(a.vKeyID))
        if e.welt & W.vFehlt != 0 { try? fm.removeItem(at: vA) }
        if e.welt & W.vVonB != 0, b.vKeyID != a.vKeyID {
            try Data(SaatWerte.vRoh(b.v.plan.nummer)).write(to: hw.appendingPathComponent(SaatWerte.hwName(b.vKeyID)))
        }
        if e.welt & W.vVonBUnterA != 0, b.vKeyID != a.vKeyID {
            try Data(SaatWerte.vRoh(b.v.plan.nummer)).write(to: vA)
        }
        let tresor = ordner.appendingPathComponent(VaultStore.vaultFileName)
        if e.welt & W.tresorFehlt != 0 {
            try? fm.removeItem(at: tresor)
        } else if e.welt & W.tresorKaputt != 0 {
            var t = a.saat.bytes
            // Bitfehler im verschlüsselten Inhalt (Kopf und Slots bleiben lesbar).
            t[t.count - 32 - 16 - 5] ^= 0x10
            try Data(t).write(to: tresor)
        }
        return ordner
    }

    /// Temp-Ordner einer Eingabe entfernen (Schreibschutz vorher aufheben).
    func aufraeumen(_ ordner: URL) {
        let hw = ordner.appendingPathComponent(VaultStore.hardwareFolderName, isDirectory: true)
        _ = chflags(hw.path, 0)
        try? FileManager.default.removeItem(at: ordner.deletingLastPathComponent())
    }

    static func sitzung(_ o: UnlockOutcome) -> UnlockedVault {
        switch o {
        case let .unlocked(v): return v
        case let .rollbackSuspected(v, _, _): return v
        }
    }
}

/// Zeichnet jeden Aufruf der austauschbaren Vernichtungs-Schicht auf. Modus (Welt-Bits): 0 vernichtet wie der Kern
/// (Datei-Variante), 1 wirft ohne zu löschen, 2 tut still nichts, 3 löscht und wirft. In allen Fällen muss der Kern
/// die Datei selbst überschreiben und löschen (Rückfall in `eraseDestructionKey`).
final class ProtokollEraser: DestructionKeyEraser, @unchecked Sendable {
    private let lock = NSLock()
    private var liste: [UUID] = []
    let modus: UInt8

    init(modus: UInt8 = 0) { self.modus = modus & 3 }

    var ids: [UUID] { lock.withLock { liste } }

    func destroy(keyID: UUID, directory: URL) throws {
        lock.withLock { liste.append(keyID) }
        switch modus {
        case 1: throw SiegelError.io("fuzz.eraser")
        case 2: return
        case 3:
            try? FileDestructionKeyEraser().destroy(keyID: keyID, directory: directory)
            throw SiegelError.io("fuzz.eraser")
        default: try FileDestructionKeyEraser().destroy(keyID: keyID, directory: directory)
        }
    }
}
#endif
