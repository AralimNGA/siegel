#if DEBUG
import Foundation
@testable import SiegelCore

/// Ziel „sicherung“: Namen der Sicherungen (lokal, zweiter Ort, beschädigt), die Ausdünnung (SPEC §4) und das
/// Einspielen der Saat-Tresore (auch mit eingerichteter Selbstvernichtung, §23).
/// Der zweite Sicherungsort ist ein frei gewählter Ordner (USB-Stick, iCloud Drive): Dateinamen dort sind fremde Daten.
///
/// Rahmung: Byte 0 = Art (0 Name lesen, 1 Ausdünnung, 2 Rundlauf, 3 Einspielen), danach UTF-8 bzw. Datensätze
/// (8 Byte Zeitversatz, 1 Byte angeheftet) bzw. bei 3: Saat ‖ Passwort-Art ‖ Weg (+0x80: Prüfsumme neu) ‖
/// n × (Offset u16, XOR-Byte).
/// Invarianten: kein Absturz; erzeugte Namen werden genau zurückgelesen (Zeit, Generation, Anlass); die Ausdünnung
/// löscht nie angeheftete Sicherungen und nie die älteste, nur vorhandene, und sie ist deterministisch.
/// Einspielen: Fehler nur feste Codes; nur die unveränderte Datei mit dem echten Passwort wird eingesetzt (nie eine
/// Vernichtungs-Sitzung, auch nicht mit dem Vernichtungs-Passwort); danach gilt es als echtes Entsperren (Zähler 0,
/// Einstellungen aus dem Inhalt), die Tresordatei öffnet mit dem Master-Passwort, nicht vernichtbare Einträge sind
/// lesbar, vernichtbare nur ohne Vernichtung. Ohne Erfolg bleiben Tresordatei und Sicherungen bytegleich; nur
/// `wrongPassword` zählt als Fehlversuch (auch das Vernichtungs-Passwort, das auf diesen Wegen nicht erkannt wird),
/// an der Schwelle wird V vernichtet.
final class ZielSicherung: FuzzZiel {
    let name = "sicherung"
    let zeitlimit = 5.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 10)
    var zusatz: [String: Int] = [:]
    var neueSaat = false
    private static let jetzt = Date(timeIntervalSince1970: 1_792_200_000)
    private var saaten: [TresorSaat] = []
    private var wurzel: URL?
    private var zaehler = 0

    func vorbereiten(_ u: Umgebung) throws {
        let id = UUID(uuidString: "06CAF7C7-5BFA-4C75-ABEC-76E7488CC7A2") ?? UUID()
        for name in [BackupNaming.localName(date: Self.jetzt, generation: 7, reason: "migration-v1"),
                     BackupNaming.localName(date: Self.jetzt, generation: UInt64.max, reason: nil),
                     BackupNaming.externalName(vaultID: id, date: Self.jetzt),
                     BackupNaming.quarantineName(date: Self.jetzt, suffix: "ab12")] {
            korpus.saatAufnehmen([0] + Array(name.utf8))
        }
        korpus.saatAufnehmen([1] + Array(repeating: 0, count: 90))
        // Einspielen: Saat-Tresore ohne Fixtures (echtes Profil wäre pro Eingabe zu teuer)
        saaten = try SaatErzeugung.laden(u, neu: neueSaat).filter { !$0.echtesProfil }
        try SaatErzeugung.selbsttest(saaten)
        // §23.1: Sicherungen der Vernichtungs-Saaten liefern mit dem Notfallcode keine vernichtbaren Einträge.
        for s in saaten { try SaatErzeugung.sicherungenPruefen(s) }
        wurzel = FileManager.default.temporaryDirectory
            .appendingPathComponent("siegelfuzz-sicherung-\(getpid())", isDirectory: true)
        // Die leere Wurzel bleibt sonst pro Prozess liegen (die Unterordner e<n> werden pro Eingabe entfernt).
        let wurzelPfad = wurzel?.path ?? ""
        _ = atexit_b { _ = try? FileManager.default.removeItem(atPath: wurzelPfad) }
        for i in saaten.indices {
            korpus.saatAufnehmen([3, UInt8(i), 0, 0])
            korpus.saatAufnehmen([3, UInt8(i), 1, 1])
            korpus.saatAufnehmen([3, UInt8(i), 2, 0])
            korpus.saatAufnehmen([3, UInt8(i), 0, 0x80, 0x40, 0x00, 0x01])
        }
        for i in saaten.indices {
            let c = try pruefe([3, UInt8(i), 0, 0])
            guard c.hasPrefix("einspielen:ok") else { throw Fund("saat", "Einspielen der Saat \(saaten[i].name): \(c)") }
        }
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    func naechste(_ z: inout Zufall) -> [UInt8] {
        if z.chance(0.3) {
            // frisch erzeugter Name mit Zufallswerten (Rundlauf)
            let d = Date(timeIntervalSince1970: Double(z.int(0...253_402_300_799)))
            let anlass = z.chance(0.5) ? nil : z.pick(["import", "notfall", "neues-kit", "migration-v1", "a-b-c", "vor", ""])
            return [2] + Array(BackupNaming.localName(date: d, generation: z.chance(0.5) ? UInt64(z.int(0...1000)) : UInt64.max,
                                                      reason: anlass).utf8) + [0] + withUnsafeBytes(of: d.timeIntervalSince1970.bitPattern) { Array($0) }
        }
        let basis = korpus.waehle(&z)
        guard let art = basis.first else { return [0] }
        var b = Array(basis.dropFirst())
        if art == 0, z.chance(0.6) {
            b = Array(Zeichen.mutieren(String(decoding: b, as: UTF8.self), &z).utf8)
        } else {
            b = Mutator.bytes(b, &z, maxLaenge: 9 * 400)
        }
        if art == 3, z.chance(0.5) {
            // Einspielen: Passwort-Art, Weg und gezielte Bitfehler (Kopf, Slots, Inhalt, Prüfsumme)
            var e = [UInt8(z.int(max(1, saaten.count))), UInt8(z.int(3)), UInt8(z.int(2)) | (z.chance(0.5) ? 0x80 : 0)]
            for _ in 0..<z.pick([0, 0, 1, 1, 2]) {
                let off = z.pick([z.int(0...60), z.int(60...140), z.int(140...3400), z.int(3400...20_000)])
                e += [UInt8(off & 0xFF), UInt8(off >> 8), UInt8(1) << UInt8(z.int(8))]
            }
            return [3] + e
        }
        return [art == 2 ? 0 : art] + b
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard let art = e.first else { return "leer" }
        let b = Array(e.dropFirst())
        switch art % 4 {
        case 3:
            return try einspielen(b)
        case 0:
            let name = String(decoding: b, as: UTF8.self)
            let lokal = BackupNaming.parseLocal(name)
            let extern = BackupNaming.parseAnyExternal(name)
            if let lokal {
                // Ein gelesener Name wird mit denselben Werten wieder erzeugt und erneut gelesen
                let neu = BackupNaming.localName(date: lokal.date, generation: lokal.generation, reason: lokal.reason)
                guard let zurueck = BackupNaming.parseLocal(neu), zurueck.generation == lokal.generation,
                      zurueck.reason == lokal.reason else { throw Fund("sicherung", "lokaler Name nicht stabil") }
            }
            return "name:" + (lokal != nil ? "lokal" : "") + (extern != nil ? "extern" : "") + (lokal == nil && extern == nil ? "nein" : "")
        case 2:
            // Rundlauf: localName → parseLocal
            guard let null = b.firstIndex(of: 0), b.count >= null + 9 else { return "kurz" }
            let name = String(decoding: b[..<null], as: UTF8.self)
            let zeit = Double(bitPattern: b[(null + 1)..<(null + 9)].enumerated()
                .reduce(UInt64(0)) { $0 | UInt64($1.element) << UInt64(8 * $1.offset) })
            guard let l = BackupNaming.parseLocal(name), l.date.timeIntervalSince1970 == zeit.rounded(.down) else {
                throw Fund("sicherung", "erzeugter Name wird nicht genau zurückgelesen")
            }
            return "rundlauf:ok"
        default:
            var items: [BackupThinning.Item] = []
            var i = 0
            while i + 9 <= b.count, items.count < 400 {
                let roh = b[i..<(i + 8)].enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << UInt64(8 * $1.offset) }
                // Versatz bis ± ~ 3 Jahre, gelegentlich extrem
                let versatz = (b[i + 8] & 0x80) != 0 ? Double(Int64(bitPattern: roh)) / 1e6
                    : Double(Int64(bitPattern: roh) % 100_000_000)
                items.append(BackupThinning.Item(url: URL(fileURLWithPath: "/x/\(items.count).siegel"),
                                                 date: Self.jetzt.addingTimeInterval(-versatz),
                                                 pinned: (b[i + 8] & 1) != 0))
                i += 9
            }
            let weg = BackupThinning.selectForDeletion(items, now: Self.jetzt)
            guard weg == BackupThinning.selectForDeletion(items, now: Self.jetzt) else {
                throw Fund("sicherung", "Ausdünnung nicht deterministisch")
            }
            let wegSet = Set(weg)
            guard wegSet.count == weg.count, wegSet.isSubset(of: Set(items.map(\.url))) else {
                throw Fund("sicherung", "Ausdünnung nennt doppelte oder fremde Dateien")
            }
            if items.contains(where: { $0.pinned && wegSet.contains($0.url) }) {
                throw Fund("sicherung", "angeheftete Sicherung würde gelöscht")
            }
            if let aelteste = items.min(by: { $0.date < $1.date }), wegSet.contains(aelteste.url) {
                throw Fund("sicherung", "älteste Sicherung würde gelöscht")
            }
            return "duennen:" + (weg.isEmpty ? "nichts" : "etwas")
        }
    }

    // MARK: Einspielen

    private static let falsch = "Falsch-q8,Vd:Lk3#xRw+Tz!mP9@bN6^cJ2"

    private static func erlaubt(_ e: SiegelError) -> Bool {
        switch e {
        case .wrongPassword, .corruptFile, .unsupportedVersion, .kdfParametersOutOfRange, .kdfFailed, .factorMissing,
             .wrongCard: return true
        case let .io(c): return c == "backup.missing"
        default: return false
        }
    }

    private func einspielen(_ b: [UInt8]) throws -> String {
        guard b.count >= 3, !saaten.isEmpty, let wurzel else { return "einspielen:kurz" }
        let s = saaten[Int(b[0]) % saaten.count]
        let pwArt = b[1] % 3
        var weg = b[2] & 1
        let neuePruefsumme = b[2] & 0x80 != 0
        if s.vernichtung == nil { weg = 0 }
        var flips: [(Int, UInt8)] = []
        var i = 3
        while i + 3 <= b.count, flips.count < 8 {
            if b[i + 2] != 0 { flips.append((Int(b[i]) | Int(b[i + 1]) << 8, b[i + 2])) }
            i += 3
        }
        zaehler += 1
        let basis = wurzel.appendingPathComponent("e\(zaehler)", isDirectory: true)
        let ordner = basis.appendingPathComponent("Siegel", isDirectory: true)
        try? FileManager.default.removeItem(at: basis)
        defer { try? FileManager.default.removeItem(at: basis) }
        let dateien = s.vernichtung?.dateien ?? [VaultStore.vaultFileName: s.bytes]
        for (rel, bytes) in dateien {
            let u = ordner.appendingPathComponent(rel)
            try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(bytes).write(to: u)
        }
        let store = VaultStore(directory: ordner, rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        // Datei zum Einspielen: die Tresordatei (Import) bzw. die neueste Sicherung, mit Bitfehlern
        let datei: URL
        if weg == 0 {
            datei = basis.appendingPathComponent("import.siegel")
        } else {
            guard let neueste = store.backups().first?.url else { throw Fund("saat", "Saat \(s.name) ohne Sicherung") }
            datei = neueste
        }
        let original = weg == 0 ? s.bytes : [UInt8](try Data(contentsOf: datei))
        var bytes = original
        for (off, x) in flips where off < bytes.count { bytes[off] ^= x }
        if neuePruefsumme, !flips.isEmpty, bytes.count > 32 {
            let koerper = Array(bytes.dropLast(32))
            bytes = koerper + FileFormat.fileChecksum(koerper[...])
        }
        try Data(bytes).write(to: datei)
        let veraendert = bytes != original
        let pw = pwArt == 0 ? s.passwort : (pwArt == 1 ? Self.falsch : (s.vernichtung?.plan.passwort ?? Self.falsch))
        let hw = store.hardwareDirectory
        let zustandURL = hw.appendingPathComponent(DestructionState.fileName)
        let vorherZustand = try? FileIO.read(zustandURL, maxSize: 1 << 20)
        let vorherTresor = try UmgebungsDateien.einsammeln(ordner).filter { !$0.key.hasPrefix(VaultStore.hardwareFolderName + "/") }
        let jetzt = SaatWerte.zeitpunkt.addingTimeInterval(3600)
        let ergebnis: String
        do {
            let v = try TestHooks.$now.withValue(jetzt) { () -> UnlockedVault in
                weg == 0 ? try store.importBackup(from: datei, masterPassword: pw, factors: s.faktoren)
                    : try store.restoreNewestReadableBackup(masterPassword: pw, factors: s.faktoren).0
            }
            defer { v.lock() }
            guard pwArt == 0, !veraendert else {
                throw Fund("einspielen", "eingesetzt, obwohl " + (veraendert ? "Datei verändert" : "Passwort falsch")
                           + " (Art \(pwArt), Weg \(weg))")
            }
            guard !v.isDuressSession else { throw Fund("einspielen", "Einspielen öffnet eine Vernichtungs-Sitzung") }
            try nachEchtemEinspielen(s, store, v)
            ergebnis = "einspielen:ok"
        } catch let x as SiegelError {
            guard Self.erlaubt(x) else { throw Fund("fehlertyp", "Einspielen: " + fehlerCode(x)) }
            if pwArt == 0, !veraendert { throw Fund("einspielen", "unveränderte Datei, echtes Passwort: " + fehlerCode(x)) }
            let nachher = try UmgebungsDateien.einsammeln(ordner).filter { !$0.key.hasPrefix(VaultStore.hardwareFolderName + "/") }
            guard nachher == vorherTresor else {
                throw Fund("datei", "Einspielen ohne Erfolg verändert Tresordatei oder Sicherungen")
            }
            try zaehlerPruefen(s, x, vorher: vorherZustand, nachher: try? FileIO.read(zustandURL, maxSize: 1 << 20),
                               hw: hw, jetzt: jetzt)
            ergebnis = "einspielen:" + fehlerCode(x)
        } catch let f as Fund {
            throw f
        } catch {
            throw Fund("fehlertyp", "Einspielen: kein SiegelError (" + fehlerCode(error) + ")")
        }
        return ergebnis + (s.vernichtung != nil ? ":v" : "") + (weg == 1 ? ":neueste" : "")
    }

    /// Fehlversuch-Zähler nach einem gescheiterten Einspielen (eigene Nachrechnung, KERN-NOTIZEN „Zähler“).
    private func zaehlerPruefen(_ s: TresorSaat, _ x: SiegelError, vorher: [UInt8]?, nachher: [UInt8]?, hw: URL,
                                jetzt: Date) throws {
        guard let vs = s.vernichtung else { return }
        guard let vorher, let w = JWert.lesen(vorher), case var .gueltig(st) = ZustandM.lesen(w),
              st.vaultID == s.header.uuid, !st.nennt(s.header.factorFields.seKeyID) else {
            guard nachher == vorher else { throw Fund("zaehler", "Zustand ohne gültige Vorlage verändert") }
            return
        }
        let vDatei = hw.appendingPathComponent(SaatWerte.hwName(vs.plan.vKeyID))
        guard x == .wrongPassword, let n = st.maxFailed, st.destroyed == nil else {
            guard nachher == vorher else { throw Fund("zaehler", "Zustand verändert ohne Fehlversuch (" + fehlerCode(x) + ")") }
            return
        }
        st.failed = min(st.failed + 1, 1_000_000)
        var vernichtet = false
        if st.failed >= n, let v = st.vKeyID {
            st.destroyed = ZustandM.Vermerk(keyID: v, trigger: "failedAttempts", at: ZielVernichtung.kanonisch(jetzt))
            vernichtet = true
        }
        guard let nachher, let w2 = JWert.lesen(nachher), case let .gueltig(ist) = ZustandM.lesen(w2), ist == st else {
            throw Fund("zaehler", "Fehlversuch beim Einspielen falsch vermerkt")
        }
        if vernichtet {
            zusatz["einspielen_zaehler_vernichtet", default: 0] += 1
            guard !FileManager.default.fileExists(atPath: vDatei.path) else {
                throw Fund("zaehler", "Schwelle erreicht, V nicht vernichtet")
            }
        }
    }

    /// Nach erfolgreichem Einspielen: gilt als echtes Entsperren; Tresordatei öffnet; Einträge lesbar wie erwartet.
    private func nachEchtemEinspielen(_ s: TresorSaat, _ store: VaultStore, _ v: UnlockedVault) throws {
        let datei = try VaultFile.parse(try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes))
        _ = try VaultCrypto.openWithPassword(datei, password: s.pw, factors: s.faktoren, limits: s.limits)
        guard let vs = s.vernichtung, let inhalt = s.inhalt, let cfg = inhalt.destruction else { return }
        let status = store.destructionStatus()
        guard status.failedAttempts == 0, status.settings == cfg.settings else {
            throw Fund("einspielen", "Einspielen gilt nicht als echtes Entsperren (Zähler/Einstellungen)")
        }
        let anbieter = DateiAnbieter(hardware: store.hardwareDirectory, vKeyID: vs.plan.vKeyID)
        for e in v.entries {
            let r: String
            do {
                _ = try synchron { try await v.revealSecrets(id: e.id, factors: anbieter) }
                r = "ok"
            } catch let x as SiegelError {
                r = fehlerCode(x)
            } catch {
                throw Fund("fehlertyp", "Aufdecken nach dem Einspielen: kein SiegelError")
            }
            let soll = inhalt.destructible[e.id] != nil && s.vVernichtet ? fehlerCode(SiegelError.factorUnavailable(.secureEnclave)) : "ok"
            guard r == soll else { throw Fund("einspielen", "Aufdecken nach dem Einspielen: \(r) statt \(soll)") }
        }
    }
}
#endif
