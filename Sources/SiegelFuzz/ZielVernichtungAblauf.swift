#if DEBUG
import CryptoKit
import Darwin
import Foundation
@testable import SiegelCore

// Ziel „vernichtung“, Teil 3: Ablauf einer Eingabe. Jeder Vorgang wird zuerst am Kern ausgeführt und beobachtet
// (Ergebnis, Aufrufe der Vernichtungs-Schicht, Hardware-Ordner samt Dateiinhalten, zustand.json, Tresordatei, in einer
// Sitzung deren Sicht), dann sagt das Modell denselben Vorgang voraus; jeder Unterschied ist ein Fund. Dazu
// modellfreie Invarianten (Fehlermengen, Entsperr-SE-Schlüssel, Vernichtungs-Sitzung schreibt nie, Vermerk ⇒ V weg,
// Rotation entwertet alte Umschläge, Sicherungen nach dem Markieren, Unsichtbarkeit in der Vernichtungs-Sitzung).

extension ZielVernichtung {
    /// Ein Umschlag des Vernichtungs-Passworts, wie der Kern ihn geschrieben hat: DEK-Epoche, Passwort, Kennung.
    struct Umschlag {
        let epoche: Int
        let pw: String
        let id: UUID
        let bytes: [UInt8]
    }

    /// Testhaken für den Wettlauf zwischen Probe und Vermerk (Welt-Bit `W.wettlauf`).
    final class WettlaufKasten: @unchecked Sendable {
        let url: URL
        let seKeyID: UUID?
        private let lock = NSLock()
        private var _getauscht: [UInt8]?

        init(url: URL, seKeyID: UUID?) {
            self.url = url
            self.seKeyID = seKeyID
        }

        var getauscht: [UInt8]? { lock.withLock { _getauscht } }

        /// zustand.json gegen eine Fassung tauschen, die den Entsperr-SE-Schlüssel als V nennt (nur ein gültiger,
        /// kanonisch lesbarer Zustand wird getauscht).
        func tauschen() {
            guard let se = seKeyID, let b = try? FileIO.read(url, maxSize: 1 << 20), var w = JWert.lesen(b),
                  case .gueltig = ZustandM.lesen(w) else { return }
            w["vKeyID"] = .str(se.uuidString)
            w["destroyed"] = .null
            let neu = w.bytes
            guard (try? Data(neu).write(to: url)) != nil else { return }
            lock.withLock { _getauscht = neu }
        }
    }

    final class Lauf {
        let e: Eingabe
        let a: VSaat
        let b: VSaat
        /// Saat mit fremdem Vernichtungs-Passwort (nie A selbst).
        let fremd: VSaat
        let ordner: URL
        let hw: URL
        let store: VaultStore
        let eraser: ProtokollEraser
        let anbieter: DateiAnbieter
        let waechter = InMemoryRollbackGuard()
        var w: Welt
        var ergebnisse: [String] = []

        // Inhalts-Ebene (für das Modell und die Vorgänge)
        var passwort: String
        var duressPW: String?
        var duressPWAlt: String?
        var sitzung: UnlockedVault?
        var sitzungDuress = false
        var sitzungPW = ""
        var umschlaege: [[UInt8]: Umschlag] = [:]
        /// Kennungen, die je ein Zustand nannte (feldbewusst), und alle Ablage-Kennungen des Inhalts.
        var genannt: Set<UUID> = []
        var ablageIDs: Set<UUID> = []

        init(_ e: Eingabe, _ a: VSaat, _ b: VSaat, fremd: VSaat, ordner: URL) {
            self.e = e
            self.a = a
            self.b = b
            self.fremd = fremd
            self.ordner = ordner
            hw = ordner.appendingPathComponent(VaultStore.hardwareFolderName, isDirectory: true)
            store = VaultStore(directory: ordner, rollbackGuard: waechter, testKDF: true)
            eraser = ProtokollEraser(modus: UInt8((e.welt >> W.eraserVerschiebung) & 3))
            store.destructionKeyEraser = eraser
            anbieter = DateiAnbieter(hardware: hw, vKeyID: a.vKeyID)
            passwort = a.passwort
            duressPW = a.duressPasswort
            w = Welt(vaultID: a.vaultID, vKeyIDSaat: a.vKeyID, seKeyIDSaat: a.seKeyID, alle: a.alle,
                     vernichtbar: a.vernichtbar, versiegelt: a.versiegelt, geloescht: a.geloescht, inhalt: a.inhalt,
                     stufe: a.stufe, kdf: a.header.kdf, seKeyIDKopf: a.seKeyID, eintragKeyID: a.eintragKeyID, kopfLesbar: true,
                     tresorLesbar: true, tresorDa: true, z: nil, zArt: 1, dateien: [])
            if let id = a.inhalt.duressFileID { ablageIDs.insert(id) }
            if let id = b.inhalt.duressFileID { ablageIDs.insert(id) }
        }

        var zustandURL: URL { hw.appendingPathComponent(DestructionState.fileName) }
        var tresorURL: URL { ordner.appendingPathComponent(VaultStore.vaultFileName) }
        var korrekt: FactorSecrets { SaatWerte.faktoren(a.stufe.factors) }

        func hardwareNamen() -> Set<String> {
            Set(((try? FileManager.default.contentsOfDirectory(atPath: hw.path)) ?? []).map { $0.lowercased() })
        }

        func hardwareDateien() -> [String: [UInt8]] {
            var out: [String: [UInt8]] = [:]
            for n in (try? FileManager.default.contentsOfDirectory(atPath: hw.path)) ?? [] {
                if let d = try? FileIO.read(hw.appendingPathComponent(n), maxSize: 1 << 20) { out[n.lowercased()] = d }
            }
            return out
        }

        func zustandsArt() -> (UInt8, [UInt8]?) {
            var st = stat()
            guard lstat(zustandURL.path, &st) == 0 else { return (1, nil) }
            switch st.st_mode & S_IFMT {
            case S_IFDIR: return (2, nil)
            case S_IFLNK: return (3, nil)
            default: return (0, try? FileIO.read(zustandURL, maxSize: 1 << 20))
            }
        }

        /// Sicherungen und Tresordatei (für „bytegleich“).
        func tresorUndSicherungen() -> [String: [UInt8]] {
            ((try? UmgebungsDateien.einsammeln(ordner)) ?? [:]).filter { !$0.key.hasPrefix(VaultStore.hardwareFolderName + "/") }
        }

        func tresorBytes() -> [UInt8]? { try? FileIO.read(tresorURL, maxSize: FileFormat.maxFileBytes) }

        func schreibschutz(_ an: Bool) {
            _ = chflags(hw.path, an ? UInt32(UF_IMMUTABLE) : 0)
        }

        func sitzungSperren() {
            sitzung?.lock()
            sitzung = nil
            sitzungDuress = false
        }
    }

    /// Zustand vor einem Vorgang.
    struct Vorher {
        let dateien: [String: [UInt8]]
        let namen: Set<String>
        let zArt: UInt8
        let zBytes: [UInt8]?
        let tresorUndSicherungen: [String: [UInt8]]
        let tresor: [UInt8]?
        let eraseAnzahl: Int
        /// Sicherungen in der Reihenfolge, in der `restoreNewestReadableBackup` sie probiert, mit ihren Faktoren.
        let sicherungen: [FactorSet]
        /// Entsperr-SE-Schlüssel aus den Köpfen der eigenen Sicherungen (und beiseitegelegter Tresordateien).
        let sicherungsSE: Set<UUID>
    }

    func vorher(_ l: Lauf) -> Vorher {
        let (zArt, zBytes) = l.zustandsArt()
        var faktoren: [FactorSet] = []
        let aktuellID = (try? FileIO.readPrefix(l.tresorURL, count: VaultHeader.maxSize))
            .flatMap { try? VaultFile.parseHeaderOnly($0) }?.uuid
        var liste = l.store.backups()
        if let aktuellID, liste.contains(where: { $0.vaultID == aktuellID }) { liste = liste.filter { $0.vaultID == aktuellID } }
        for s in liste {
            guard let bytes = try? FileIO.read(s.url, maxSize: FileFormat.maxFileBytes),
                  let f = try? VaultFile.parse(bytes) else { continue }
            faktoren.append(f.header.factors)
        }
        var se = Set<UUID>()
        let wurzel = l.ordner.appendingPathComponent(VaultStore.backupFolderName, isDirectory: true)
        let eigene = wurzel.appendingPathComponent(l.a.vaultID.uuidString, isDirectory: true)
        let fm = FileManager.default
        let namen = ((try? fm.contentsOfDirectory(atPath: eigene.path)) ?? []).map { eigene.appendingPathComponent($0) }
            + ((try? fm.contentsOfDirectory(atPath: wurzel.path)) ?? []).map { wurzel.appendingPathComponent($0) }
        for u in namen where u.pathExtension == "siegel" {
            if let p = try? FileIO.readPrefix(u, count: VaultHeader.maxSize), let h = try? VaultFile.parseHeaderOnly(p),
               h.uuid == l.a.vaultID, let id = h.factorFields.seKeyID { se.insert(id) }
        }
        return Vorher(dateien: l.hardwareDateien(), namen: l.hardwareNamen(), zArt: zArt, zBytes: zBytes,
                      tresorUndSicherungen: l.tresorUndSicherungen(), tresor: l.tresorBytes(), eraseAnzahl: l.eraser.ids.count,
                      sicherungen: faktoren, sicherungsSE: se)
    }

    // MARK: Eingabe prüfen

    func pruefe(_ roh: [UInt8]) throws -> String {
        guard let e = Eingabe.dekodieren(roh), !saaten.isEmpty else { return "rahmung" }
        let a = saat(e.a)
        let b = saat(e.b)
        let ordner = try aufbauen(e, a, b)
        let fremd = a === b ? saaten[(Int(e.b) % saaten.count + 1) % saaten.count] : b
        let l = Lauf(e, a, b, fremd: fremd, ordner: ordner)
        defer {
            l.sitzungSperren()
            aufraeumen(ordner)
        }
        try startModell(l)
        if e.welt & W.rollback != 0 { l.waechter.record(vaultID: a.vaultID, generation: a.saat.datei.generation + 1) }
        if e.welt & W.schreibschutz != 0 { l.schreibschutz(true) }
        try beobachteStatus(l)
        for o in e.ops.prefix(Self.maxVorgaenge) { try vorgang(l, o) }
        try schluss(l)
        for (name, bit) in [("v_fehlt", W.vFehlt), ("v_von_b", W.vVonB), ("v_von_b_unter_a", W.vVonBUnterA),
                            ("tresor_kaputt", W.tresorKaputt), ("tresor_fehlt", W.tresorFehlt), ("rollback", W.rollback),
                            ("schreibschutz", W.schreibschutz), ("wettlauf", W.wettlauf)] where e.welt & bit != 0 {
            zusatz["welt_" + name, default: 0] += 1
        }
        let modus = (e.welt >> W.eraserVerschiebung) & 3
        if modus != 0 { zusatz["welt_eraser\(modus)", default: 0] += 1 }
        return String(format: "%03x|", e.welt) + Set(l.ergebnisse).sorted().joined(separator: ",")
    }

    /// zustand.json lesen: Ob er gilt, entscheidet der Parser des Kerns; der eigene Leser muss Feld für Feld dasselbe
    /// ergeben (Differenztest), und was der Kern annimmt, hält die dokumentierten Bereiche.
    func zustandLesen(_ bytes: [UInt8]) throws -> ZustandM? {
        let kern = bytes.count <= DestructionState.maxFileBytes ? (try? DestructionState.decode(bytes)).map(ZustandM.aus) : nil
        let baum = bytes.count <= DestructionState.maxFileBytes ? JWert.lesen(bytes) : nil
        let eigen = baum.map { ZustandM.lesen($0) } ?? .ungueltig
        switch (kern, eigen) {
        case let (k?, .gueltig(m)):
            guard k == m else { throw Fund("leser", "Kern und eigener Leser lesen zustand.json verschieden") }
        case let (k?, .unbestimmt):
            guard let baum, case let .gueltig(m) = ZustandM.lesen(baum, nachsichtig: true), k == m else {
                throw Fund("leser", "Kern nimmt zustand.json in anderer Schreibweise an als der eigene Leser")
            }
            zusatz["zustand_nicht_kanonisch_angenommen", default: 0] += 1
        case let (k?, .ungueltig):
            // Nur die bekannte Nachsicht von JSONDecoder (Zeichenkodierung, s. `JWert.lesenWieJSONDecoder`) erklärt das;
            // die Felder müssen dann dieselben sein.
            guard baum == nil, let b2 = JWert.lesenWieJSONDecoder(bytes), case let .gueltig(m) = ZustandM.lesen(b2), k == m else {
                throw Fund("leser", "Kern nimmt einen zustand.json an, den das dokumentierte Format verwirft")
            }
            zusatz["zustand_json_nachsichtig", default: 0] += 1
        case (nil, .gueltig):
            throw Fund("leser", "Kern verwirft einen gültigen zustand.json")
        case (nil, .unbestimmt):
            zusatz["zustand_nicht_kanonisch_verworfen", default: 0] += 1
        case (nil, .ungueltig):
            break
        }
        if let k = kern, !k.inBereichen { throw Fund("leser", "Kern nimmt Werte ausserhalb der Bereiche an") }
        return kern
    }

    /// Modell aus der aufgebauten Welt.
    private func startModell(_ l: Lauf) throws {
        let (zArt, zBytes) = l.zustandsArt()
        l.w.zArt = zArt
        if zArt == 0, let zBytes {
            l.w.z = try zustandLesen(zBytes)
            zusatz[l.w.z == nil ? "zustand_verworfen" : "zustand_gueltig", default: 0] += 1
            if let baum = JWert.lesen(zBytes) { l.genannt.formUnion(baum.genannteKennungen) }
        }
        l.w.dateien = l.hardwareNamen()
        let vA = Self.hw(l.a.vKeyID)
        if l.e.welt & W.vVonBUnterA != 0, l.b.vKeyID != l.a.vKeyID, l.w.dateien.contains(vA) { l.w.fremd.insert(vA) }
        l.w.tresorDa = l.e.welt & W.tresorFehlt == 0
        l.w.tresorLesbar = l.w.tresorDa && l.e.welt & W.tresorKaputt == 0
        l.w.kopfLesbar = l.w.tresorDa
        l.w.rollback = l.e.welt & W.rollback != 0
        l.w.schreibschutz = l.e.welt & W.schreibschutz != 0
        l.w.sicherungsSE = vorher(l).sicherungsSE
        l.w.ablageVorlage = saaten.lazy.compactMap(\.ablage0).first ?? []
        if let bytes = l.a.ablage0, let id = l.a.inhalt.duressFileID, let pw = l.a.duressPasswort,
           let f = AblageBefund.lesen(bytes, erwartet: id) {
            l.umschlaege[f.nutzlast] = Umschlag(epoche: 0, pw: pw, id: id, bytes: bytes)
        }
    }

    private func beobachteStatus(_ l: Lauf) throws {
        let s = l.store.destructionStatus()
        let soll = Self.status(l.w)
        guard s == soll else {
            throw Fund("status", "destructionStatus " + Self.statusText(s) + " statt " + Self.statusText(soll))
        }
        // Was der Kern zeigt, hält die Bereiche.
        if let d = s.settings.deadmanDays, !(7...365).contains(d) { throw Fund("status", "Frist ausserhalb 7…365") }
        if let n = s.settings.maxFailedAttempts, !(10...100).contains(n) { throw Fund("status", "Grenze ausserhalb 10…100") }
        l.ergebnisse.append("status:" + (s == .off ? "aus" : "an"))
    }

    /// Zeit eines Vorgangs: absolut oder Anker (aus dem Modell, deterministisch) + Abstand.
    func zeitAufloesen(_ o: Op, _ w: Welt) -> Double {
        guard o.anker % 5 != 0 else { return o.zeit }
        let st = w.aktuell
        let last = st?.last?.timeIntervalSince1970 ?? Self.t0
        let basis: Double
        switch o.anker % 5 {
        case 1: basis = st?.deadline?.timeIntervalSince1970 ?? (last + 30 * Self.tag)
        case 2: basis = last
        case 3: basis = last - Self.tag
        default: basis = Self.t0
        }
        return basis + (o.zeit.isFinite ? o.zeit : 0)
    }

    /// Fehlercode für den Vergleich; `corruptFile` ohne Zusatz (die Stelle des Bitfehlers ist hier nicht Gegenstand).
    static func ergebnisCode(_ x: SiegelError) -> String {
        if case .corruptFile = x { return "fehler:corruptFile" }
        return "fehler:" + fehlerCode(x)
    }

    // MARK: Ein Vorgang

    // swiftlint:disable:next function_body_length cyclomatic_complexity
    private func vorgang(_ l: Lauf, _ o: Op) throws {
        let op = o.op % 15
        let zeitRoh = zeitAufloesen(o, l.w)
        // Für alles ausser checkDeadman(now:) ist die Uhr endlich (TestHooks.now; so liefert sie auch macOS).
        let zeit = op == 1 || zeitRoh.isFinite ? zeitRoh : Self.t0
        let jetzt = Date(timeIntervalSince1970: zeit)
        if op == 0 {
            try beobachteStatus(l)
            return
        }
        if [2, 3, 4, 5, 6, 7, 8, 12].contains(op) { l.sitzungSperren() }
        if case let (0, zb?) = l.zustandsArt(), let baum = JWert.lesen(zb) {
            l.genannt.formUnion(baum.genannteKennungen)
        }
        let v0 = vorher(l)
        let fv = FV(o.v)
        let kasten = WettlaufKasten(url: l.zustandURL, seKeyID: l.w.seKeyIDKopf)
        let kopfLesbar = l.w.kopfLesbar

        // 1. Kern ausführen und beobachten
        var beob = Beobachtung()
        var pw = ""
        var neueAblage: UUID?
        var markiert = false
        switch op {
        case 1:
            do {
                beob.ergebnis = try l.store.checkDeadman(now: jetzt) ? "true" : "false"
            } catch let x as SiegelError {
                beob.ergebnis = Self.ergebnisCode(x)
            } catch {
                throw Fund("fehlertyp", "checkDeadman: kein SiegelError (" + fehlerCode(error) + ")")
            }
        case 2, 3, 4, 5, 7:
            switch op {
            case 2: pw = Self.falschesPasswort
            case 3:
                pw = (o.v & 0x08 != 0 ? l.duressPWAlt : nil) ?? l.duressPW ?? l.duressPWAlt ?? l.a.duressPasswort
                    ?? "Nicht-eingerichtet-7#Qw!Lk2@Zp9"
            case 5: pw = l.fremd.duressPasswort ?? "Fremd-nicht-eingerichtet-8#Qw!Lk2"
            default: pw = l.passwort
            }
            let haken = l.e.welt & W.wettlauf != 0 ? TestHooks.Hook { kasten.tauschen() } : nil
            let faktoren = fv.werte(l.a.stufe)
            let passwort = pw
            do {
                let ausgang = try TestHooks.$now.withValue(jetzt) {
                    try TestHooks.$afterDuressArgon.withValue(haken) {
                        try l.store.unlock(masterPassword: passwort, factors: faktoren)
                    }
                }
                let (v, rb): (UnlockedVault, Bool) = {
                    switch ausgang {
                    case let .unlocked(v): return (v, false)
                    case let .rollbackSuspected(v, _, _): return (v, true)
                    }
                }()
                l.sitzung = v
                l.sitzungDuress = v.isDuressSession
                l.sitzungPW = pw
                beob.ergebnis = (v.isDuressSession ? "vernichtungssitzung" : "echt") + (rb ? "-rollback" : "")
                if op == 7, !v.isDuressSession, !v.destroyedEntries.isEmpty {
                    do {
                        try TestHooks.$now.withValue(jetzt) { try v.removeDestroyedEntries() }
                        beob.ergebnis += "+entfernt"
                    } catch let x as SiegelError {
                        beob.ergebnis += "+entfernen:" + fehlerCode(x)
                    }
                }
            } catch let x as SiegelError {
                beob.ergebnis = Self.ergebnisCode(x)
            } catch let f as Fund {
                throw f
            } catch {
                throw Fund("fehlertyp", "unlock: kein SiegelError (" + fehlerCode(error) + ")")
            }
        case 6, 8:
            pw = op == 6 ? Self.falschesPasswort : (l.duressPW ?? l.a.duressPasswort ?? Self.falschesPasswort)
            let faktoren = fv.werte(l.a.stufe)
            let passwort = pw
            do {
                let (v, _) = try TestHooks.$now.withValue(jetzt) {
                    try l.store.restoreNewestReadableBackup(masterPassword: passwort, factors: faktoren)
                }
                v.lock()
                beob.ergebnis = "echt"
            } catch let x as SiegelError {
                beob.ergebnis = Self.ergebnisCode(x)
            } catch {
                throw Fund("fehlertyp", "Sicherung einspielen: kein SiegelError (" + fehlerCode(error) + ")")
            }
        case 9:
            beob.ergebnis = try speichernAusfuehren(l, o, jetzt)
        case 10:
            beob.ergebnis = try passwortwechselAusfuehren(l, o, jetzt)
        case 11:
            (beob.ergebnis, neueAblage, markiert) = try einstellenAusfuehren(l, o, jetzt)
        case 12:
            beob.ergebnis = try notfallAusfuehren(l, jetzt)
        case 13:
            beob.ergebnis = try verbotenAusfuehren(l, o, jetzt)
        default:
            beob.ergebnis = ablageZuruecklegen(l)
        }
        if l.sitzung != nil, [2, 3, 4, 5, 7, 9, 10, 11, 12, 13].contains(op), let v = l.sitzung {
            beob.sitzung = try sitzungBeobachten(l, v)
        }
        if let g = kasten.getauscht, let baum = JWert.lesen(g) {
            l.genannt.formUnion(baum.genannteKennungen)
            zusatz["wettlauf_getauscht", default: 0] += 1
        }
        if beob.ergebnis.contains("-rollback") { zusatz["rollback_gemeldet", default: 0] += 1 }
        beob.loeschungen = Array(l.eraser.ids.dropFirst(v0.eraseAnzahl))
        beob.dateien = l.hardwareNamen()
        let nachDateien = l.hardwareDateien()
        beob.veraendert = Set(nachDateien.compactMap { n, d in
            n != DestructionState.fileName && v0.dateien[n] != d ? n : nil
        })
        let (nachArt, nachBytes) = l.zustandsArt()
        if nachArt == v0.zArt, nachBytes == v0.zBytes {
            beob.zustand = .unveraendert
        } else {
            switch nachArt {
            case 1: beob.zustand = .fehlt
            case 2: beob.zustand = .ordner
            case 3: beob.zustand = .symlink
            default:
                if let b = nachBytes, let m = try zustandLesen(b) {
                    beob.zustand = .datei(m)
                    if let baum = JWert.lesen(b) { l.genannt.formUnion(baum.genannteKennungen) }
                } else {
                    beob.zustand = .unlesbar
                }
            }
        }
        let tresorNach = l.tresorBytes()
        beob.tresor = Self.tresorVergleich(v0.tresor, tresorNach)
        l.ergebnisse.append("\(op):" + beob.ergebnis)
        if !beob.loeschungen.isEmpty { zusatz["vernichtet_vorgang\(op)", default: 0] += 1 }
        if let k = l.a.eintragKeyID.map(Self.hw), v0.namen.contains(k), !beob.dateien.contains(k) {
            // Nur über einen manipulierten Zustand im gesperrten Zustand (dokumentierte Grenze).
            zusatz["eintragsschluessel_geloescht", default: 0] += 1
        }

        // 2. Allgemeine Invarianten (modellfrei)
        try allgemeineVorgang(l, op, fv, beob, v0, kopfLesbar: kopfLesbar)

        // 3. Modell sagt voraus
        var w = l.w
        w.neuerVorgang()
        w.inhalte = v0.dateien
        w.sicherungsSE = v0.sicherungsSE
        var p = Beobachtung()
        switch op {
        case 1:
            p.ergebnis = w.totmann(jetzt)
        case 2, 3, 4, 5, 7:
            _ = w.totmann(jetzt)
            entsperrenVorhersagen(l, &w, &p, op: op, pw: pw, fv: fv, jetzt: jetzt, vorher: v0, getauscht: kasten.getauscht)
        case 6, 8:
            _ = w.totmann(jetzt)
            var ergebnis: String?
            var falsch = false
            for kinds in v0.sicherungen {
                if let f = fv.vorpruefung(kinds) {
                    ergebnis = "fehler:" + f
                    break
                }
                falsch = true
            }
            if ergebnis == nil {
                if falsch {
                    w.fehlversuch(jetzt)
                    ergebnis = "fehler:" + Self.fehlerFalsch
                } else {
                    ergebnis = "fehler:corruptFile"
                }
            }
            p.ergebnis = ergebnis ?? ""
        case 9:
            p.ergebnis = speichernVorhersagen(l, &w, o, jetzt)
        case 10:
            p.ergebnis = passwortwechselVorhersagen(l, &w, o, jetzt)
        case 11:
            p.ergebnis = einstellenVorhersagen(l, &w, o, jetzt, neueAblage: neueAblage)
        case 12:
            p.ergebnis = notfallVorhersagen(l, &w, jetzt)
            if p.ergebnis == "ok" { p.sitzung = w.sitzung(vernichtungsSitzung: false) }
        case 13:
            p.ergebnis = l.sitzung == nil ? "keine-sitzung"
                : (l.sitzungDuress && o.v % 3 == 2 ? "ok" : "fehler:" + Self.fehlerFalsch)
        default:
            if let id = l.a.inhalt.duressFileID, let bytes = l.a.ablage0 {
                let n = Self.hw(id)
                w.dateien.insert(n)
                w.fremd.remove(n)
                if v0.dateien[n] != bytes { w.veraendert.insert(n) }
                p.ergebnis = "ok"
            } else {
                p.ergebnis = "keine-ablage"
            }
        }
        if [9, 10, 11, 13].contains(op), l.sitzung != nil {
            p.sitzung = w.sitzung(vernichtungsSitzung: l.sitzungDuress)
        }
        p.loeschungen = w.loeschungen
        p.dateien = w.dateien
        p.veraendert = w.veraendert
        p.tresor = w.tresor
        switch w.geschrieben {
        case nil: p.zustand = .unveraendert
        case .some(nil): p.zustand = .fehlt
        case let .some(.some(m)): p.zustand = .datei(m)
        }
        // Ein unveränderter Zustand, den der Kern bytegleich neu schreibt, zählt als geschrieben.
        if case .unveraendert = beob.zustand, case let .datei(m) = p.zustand,
           let vb = v0.zBytes, v0.zArt == 0, (try? zustandLesen(vb)) == m {
            p.zustand = .unveraendert
        }
        guard p == beob else {
            throw Fund("modell", "Vorgang \(op) (Zeit \(zeit)): " + Self.unterschied(p, beob))
        }
        if w.schreibFehler { zusatz["schreibfehler_vorhergesagt", default: 0] += 1 }
        l.w = w

        // 4. Nach dem Vorgang: Umschläge merken, Rotation und Sicherungen prüfen
        if let id = l.w.inhalt?.duressFileID, beob.veraendert.contains(Self.hw(id)), let bytes = nachDateien[Self.hw(id)],
           let f = AblageBefund.lesen(bytes, erwartet: id), let dpw = l.duressPW, l.umschlaege[f.nutzlast] == nil {
            l.umschlaege[f.nutzlast] = Umschlag(epoche: l.w.dekEpoche, pw: dpw, id: id, bytes: bytes)
        }
        if beob.tresor == .neuerZugang {
            try rotationPruefen(l, alt: v0.tresor, neu: tresorNach, nach: nachDateien, geschrieben: beob.veraendert)
        }
        if op == 11, markiert, beob.ergebnis.hasPrefix("ok") { try sicherungenNachMarkieren(l) }
    }

    static func tresorVergleich(_ alt: [UInt8]?, _ neu: [UInt8]?) -> Beobachtung.T {
        guard alt != neu else { return .gleich }
        guard let alt, let neu, let ha = try? VaultFile.parseHeaderOnly(alt), let hn = try? VaultFile.parseHeaderOnly(neu) else {
            return .geschrieben
        }
        return ha.salt == hn.salt ? .geschrieben : .neuerZugang
    }

    /// Die Ablage, die der Kern beim Entsperren prüfen würde (`duressProbe` nach `checkDeadman`).
    static func probe(_ w: Welt, _ dateien: [String: [UInt8]]) -> AblageBefund? {
        guard let st = w.aktuell, st.duressEnabled, let id = st.duressFileID, w.dateien.contains(hw(id)),
              !w.fremd.contains(hw(id)), let b = dateien[hw(id)] else { return nil }
        return AblageBefund.lesen(b, erwartet: id)
    }

    // MARK: Entsperren (Vorhersage)

    // swiftlint:disable:next function_parameter_count
    private func entsperrenVorhersagen(_ l: Lauf, _ w: inout Welt, _ p: inout Beobachtung, op: UInt8, pw: String, fv: FV,
                                       jetzt: Date, vorher: Vorher, getauscht: [UInt8]?) {
        let kinds = w.stufe.factors
        guard w.tresorDa else {
            p.ergebnis = Self.ergebnisCode(SiegelError.vaultMissing)
            return
        }
        guard w.tresorLesbar else {
            p.ergebnis = "fehler:corruptFile"
            return
        }
        let probe = Self.probe(w, vorher.dateien)
        if let f = fv.vorpruefung(kinds) {
            p.ergebnis = "fehler:" + f
            return
        }
        if pw == l.passwort, fv.richtig(kinds) {
            let rb = w.echtEntsperren(jetzt)
            p.ergebnis = "echt" + (rb ? "-rollback" : "")
            if op == 7, w.vermerkt, !w.vernichtbar.isEmpty {
                w.alle.subtract(w.vernichtbar)
                w.vernichtbar = []
                w.inhalt = nil
                w.speichern(neuerDEK: false, jetzt)
                p.ergebnis += "+entfernt"
            }
            p.sitzung = w.sitzung(vernichtungsSitzung: false)
            return
        }
        if let f = probe, AblageBefund.erkannt(pw, f, vaultID: l.a.header.vaultID, kdf: w.kdf) {
            if let g = getauscht {
                // Wettlauf: der Haken hat zustand.json zwischen Probe und Vermerk getauscht.
                w.z = try? zustandLesen(g)
                w.zArt = 0
                if let m = w.z { w.geschrieben = .some(m) }
            }
            w.vernichtungsEntsperren(jetzt)
            let epoche = l.umschlaege[f.nutzlast]?.epoche
            if fv.richtig(kinds), epoche == w.dekEpoche {
                p.ergebnis = "vernichtungssitzung" + (w.rollback ? "-rollback" : "")
                p.sitzung = w.sitzung(vernichtungsSitzung: true)
            } else {
                p.ergebnis = "fehler:" + Self.fehlerFalsch
            }
            return
        }
        w.fehlversuch(jetzt)
        p.ergebnis = "fehler:" + Self.fehlerFalsch
    }

    // MARK: Vorgänge in der offenen Sitzung

    /// Eintrag speichern (Titel ändern): offener Eintrag, versiegelter, vernichtbarer (in der Vernichtungs-Sitzung
    /// unsichtbar → `io("entry.stale")`).
    private func speichernAusfuehren(_ l: Lauf, _ o: Op, _ jetzt: Date) throws -> String {
        guard let v = l.sitzung else { return "keine-sitzung" }
        guard let id = speicherZiel(l, o), var e = v.allEntriesForTesting.first(where: { $0.id == id }) else {
            return "kein-eintrag"
        }
        e.title = e.title.hasSuffix(" (b)") ? String(e.title.dropLast(4)) : e.title + " (b)"
        do {
            try TestHooks.$now.withValue(jetzt) { try v.upsert(e) }
            return "ok"
        } catch let x as SiegelError {
            return Self.ergebnisCode(x)
        }
    }

    private func speicherZiel(_ l: Lauf, _ o: Op) -> UUID? {
        switch o.v % 3 {
        case 0: return l.a.offenID
        case 1: return l.a.markierbarID
        default: return l.w.vernichtbar.min(by: { $0.uuidString < $1.uuidString }) ?? l.a.vernichtbar.min(by: { $0.uuidString < $1.uuidString })
        }
    }

    private func speichernVorhersagen(_ l: Lauf, _ w: inout Welt, _ o: Op, _ jetzt: Date) -> String {
        guard l.sitzung != nil else { return "keine-sitzung" }
        guard let id = speicherZiel(l, o), w.alle.contains(id) else { return "kein-eintrag" }
        if l.sitzungDuress, w.vernichtbar.contains(id) { return Self.ergebnisCode(SiegelError.io("entry.stale")) }
        w.speichern(neuerDEK: false, jetzt)
        return "ok"
    }

    private func neuesMasterPasswort(_ l: Lauf) -> String {
        l.passwort == SaatWerte.passwort2 ? SaatWerte.passwort : SaatWerte.passwort2
    }

    private func passwortwechselAusfuehren(_ l: Lauf, _ o: Op, _ jetzt: Date) throws -> String {
        guard let v = l.sitzung else { return "keine-sitzung" }
        let aktuell = l.sitzungDuress ? l.sitzungPW : (o.v % 2 == 1 ? Self.falschesPasswort : l.passwort)
        let neu = neuesMasterPasswort(l)
        let f = l.korrekt
        do {
            try TestHooks.$now.withValue(jetzt) { try v.changeMasterPassword(current: aktuell, new: neu, factors: f) }
            return "ok"
        } catch let x as SiegelError {
            return Self.ergebnisCode(x)
        }
    }

    private func passwortwechselVorhersagen(_ l: Lauf, _ w: inout Welt, _ o: Op, _ jetzt: Date) -> String {
        guard l.sitzung != nil else { return "keine-sitzung" }
        if l.sitzungDuress || o.v % 2 == 1 { return "fehler:" + Self.fehlerFalsch }
        w.speichern(neuerDEK: true, jetzt)
        l.passwort = neuesMasterPasswort(l)
        return "ok"
    }

    /// Anfrage für „Selbstvernichtung einstellen“ aus dem Modell (Inhalt): 0 Vernichtungs-Passwort ersetzen bzw.
    /// einschalten, 1 nur Einstellungen (Totmann umschalten), 2 einen weiteren Eintrag markieren (async, mit
    /// Eintrags-Faktoren, danach `purgeBackups`), 3 Vernichtungs-Passwort entfernen.
    private func einstellenAnfrage(_ l: Lauf, _ o: Op) -> (DestructionSettings, String?, Set<UUID>, Bool) {
        let inh = l.w.inhalt
        var s = DestructionSettings(deadmanDays: inh?.deadmanDays, maxFailedAttempts: inh?.maxFailed,
                                    duressEnabled: inh?.duressEnabled ?? false)
        var auswahl = l.w.vernichtbar
        var dpw: String?
        var markieren = false
        switch o.v % 4 {
        case 0:
            s.duressEnabled = true
            let erstes = l.a.duressPasswort ?? "Zw5!Mn8#Rb3@Yc6^Ka1&Erstes"
            dpw = l.duressPW == SaatWerte.zwang2 ? erstes : SaatWerte.zwang2
        case 2:
            if let m = l.a.markierbarID, !auswahl.contains(m), l.w.alle.contains(m) {
                auswahl.insert(m)
                markieren = true
            } else {
                s.deadmanDays = s.deadmanDays == nil ? 30 : nil
            }
        case 3:
            s.duressEnabled = false
        default:
            s.deadmanDays = s.deadmanDays == nil ? 30 : nil
        }
        return (s, dpw, auswahl, markieren)
    }

    private func einstellenAusfuehren(_ l: Lauf, _ o: Op, _ jetzt: Date) throws -> (String, UUID?, Bool) {
        guard let v = l.sitzung else { return ("keine-sitzung", nil, false) }
        let (s, dpw, auswahl, markieren) = einstellenAnfrage(l, o)
        let pw = l.sitzungDuress ? l.sitzungPW : l.passwort
        let f = l.korrekt
        let alt = v.contentForTesting?.destruction?.duress?.fileID
        do {
            if markieren {
                let anbieter = DateiAnbieter(hardware: l.hw)
                _ = try synchron {
                    try await TestHooks.$now.withValue(jetzt) {
                        try await v.configureDestruction(s, duressPassword: dpw, destructible: auswahl, masterPassword: pw,
                                                         factors: f, vKey: nil, entryFactors: anbieter)
                    }
                }
            } else {
                _ = try TestHooks.$now.withValue(jetzt) {
                    try v.configureDestruction(s, duressPassword: dpw, destructible: auswahl, masterPassword: pw,
                                               factors: f, vKey: nil)
                }
            }
        } catch let x as SiegelError {
            return (Self.ergebnisCode(x), nil, markieren)
        }
        let neu = v.contentForTesting?.destruction?.duress?.fileID
        if let neu, neu != alt {
            // Neue Ablage-Kennung (vom Kern zufällig gewählt): nie eine bekannte Datei.
            let bekannt = [l.a.vKeyID, l.a.seKeyID, l.a.eintragKeyID, l.b.vKeyID, alt].compactMap { $0 }
            guard !bekannt.contains(neu) else { throw Fund("vernichtung", "neue Ablage-Kennung nennt eine bekannte Datei") }
            l.ablageIDs.insert(neu)
        }
        return ("ok", neu != alt ? neu : nil, markieren)
    }

    // swiftlint:disable:next cyclomatic_complexity
    private func einstellenVorhersagen(_ l: Lauf, _ w: inout Welt, _ o: Op, _ jetzt: Date, neueAblage: UUID?) -> String {
        guard l.sitzung != nil else { return "keine-sitzung" }
        if l.sitzungDuress { return "fehler:" + Self.fehlerFalsch }
        let (s, dpw, auswahl, markieren) = einstellenAnfrage(l, o)
        if w.vermerkt { return Self.ergebnisCode(SiegelError.io("destruction.destroyed")) }
        let aktiv = s.anyTriggerEnabled || !auswahl.isEmpty
        if aktiv, w.stufe < .maximal { return Self.ergebnisCode(SiegelError.notAllowedAtLevel) }
        for id in auswahl where !w.alle.contains(id) { return Self.ergebnisCode(SiegelError.io("entry.notFound")) }
        let altV = w.inhalt?.vKeyID
        let v = aktiv ? altV : nil
        if aktiv, v == nil { return Self.ergebnisCode(SiegelError.factorMissing(.secureEnclave)) }
        let altAblage = w.inhalt?.duressFileID
        if s.duressEnabled, altAblage == nil, dpw == nil {
            return Self.ergebnisCode(SiegelError.io("destruction.duressPassword"))
        }
        if markieren {
            // Neu versiegeln über die Notfall-Gruppe: Eintrags-SE-Schlüssel (Datei), Karte, Sicherheitsschlüssel.
            guard let e = w.eintragKeyID, w.dateien.contains(Self.hw(e)) else { return "fehler:" + Self.fehlerSE }
            if w.fremd.contains(Self.hw(e)) { return "fehler:" + Self.fehlerFalsch }
        }
        let ablage: UUID? = s.duressEnabled ? (dpw != nil ? neueAblage : altAblage) : nil
        if aktiv {
            w.inhalt = InhaltM(deadmanDays: s.deadmanDays, maxFailed: s.maxFailedAttempts, duressEnabled: s.duressEnabled,
                               vKeyID: v, duressFileID: ablage)
        } else {
            w.inhalt = nil
        }
        let neueMarkierung = auswahl.subtracting(w.vernichtbar)
        w.vernichtbar = auswahl
        w.versiegelt.subtract(neueMarkierung)
        let rotation = altAblage != nil && altAblage != ablage
        w.speichern(neuerDEK: rotation, jetzt)
        if let altV, altV != v { w.loesche(altV) }
        if let dpw {
            l.duressPWAlt = l.duressPW
            l.duressPW = dpw
        } else if !s.duressEnabled, l.duressPW != nil {
            l.duressPWAlt = l.duressPW
            l.duressPW = nil
        }
        return "ok"
    }

    private func notfallAusfuehren(_ l: Lauf, _ jetzt: Date) throws -> String {
        let neu = neuesMasterPasswort(l)
        let s = l.a.saat
        do {
            let v = try TestHooks.$now.withValue(jetzt) { () -> UnlockedVault in
                if let code = s.code {
                    return try l.store.recover(code: code, newMasterPassword: neu, kdf: SaatWerte.testKDF)
                }
                return try l.store.recover(shares: Array(s.teile.prefix(2)), newMasterPassword: neu, kdf: SaatWerte.testKDF)
            }
            l.sitzung = v
            l.sitzungDuress = false
            l.sitzungPW = neu
            return "ok"
        } catch let x as SiegelError {
            return Self.ergebnisCode(x)
        }
    }

    private func notfallVorhersagen(_ l: Lauf, _ w: inout Welt, _ jetzt: Date) -> String {
        guard w.tresorDa else { return Self.ergebnisCode(SiegelError.vaultMissing) }
        guard w.tresorLesbar else { return "fehler:corruptFile" }
        // Notfallweg: vernichtbare Einträge fallen weg, Stufe 1, alles offen, Selbstvernichtung aus (§23).
        w.alle.subtract(w.vernichtbar)
        w.vernichtbar = []
        w.versiegelt = []
        w.inhalt = nil
        w.stufe = .standard
        w.kdf = SaatWerte.testKDF
        w.seKeyIDKopf = nil
        w.eintragKeyID = nil
        w.speichern(neuerDEK: true, jetzt)
        l.passwort = neuesMasterPasswort(l)
        if l.duressPW != nil {
            l.duressPWAlt = l.duressPW
            l.duressPW = nil
        }
        return "ok"
    }

    /// In der Vernichtungs-Sitzung: Selbstvernichtung einstellen, Passwortwechsel (beides `wrongPassword`),
    /// vernichtete Einträge entfernen (ohne Wirkung). In einer echten Sitzung: Passwortwechsel mit falschem Passwort.
    private func verbotenAusfuehren(_ l: Lauf, _ o: Op, _ jetzt: Date) throws -> String {
        guard let v = l.sitzung else { return "keine-sitzung" }
        let f = l.korrekt
        let neu = neuesMasterPasswort(l)
        do {
            try TestHooks.$now.withValue(jetzt) {
                if l.sitzungDuress {
                    switch o.v % 3 {
                    case 0:
                        let inh = l.w.inhalt
                        let s = DestructionSettings(deadmanDays: inh?.deadmanDays, maxFailedAttempts: inh?.maxFailed,
                                                    duressEnabled: inh?.duressEnabled ?? false)
                        try v.configureDestruction(s, duressPassword: nil, destructible: l.w.vernichtbar,
                                                   masterPassword: l.sitzungPW, factors: f, vKey: nil)
                    case 1:
                        try v.changeMasterPassword(current: l.sitzungPW, new: neu, factors: f)
                    default:
                        try v.removeDestroyedEntries()
                    }
                } else {
                    try v.changeMasterPassword(current: Self.falschesPasswort, new: neu, factors: f)
                }
            }
            return "ok"
        } catch let x as SiegelError {
            return Self.ergebnisCode(x)
        }
    }

    /// Angreifer legt die Ablage vom Anfang zurück (unter ihren ursprünglichen Namen).
    private func ablageZuruecklegen(_ l: Lauf) -> String {
        guard let id = l.a.inhalt.duressFileID, let bytes = l.a.ablage0 else { return "keine-ablage" }
        let schutz = l.e.welt & W.schreibschutz != 0
        if schutz { l.schreibschutz(false) }
        defer { if schutz { l.schreibschutz(true) } }
        do {
            try Data(bytes).write(to: l.hw.appendingPathComponent(SaatWerte.hwName(id)))
        } catch {
            return "schreiben:fehler"
        }
        return "ok"
    }

    // MARK: Sitzung beobachten

    private func sitzungBeobachten(_ l: Lauf, _ v: UnlockedVault) throws -> Beobachtung.Sitzung {
        var auf: [UUID: String] = [:]
        let anbieter = l.anbieter
        let vVorher = anbieter.vAnzahl
        let duress = v.isDuressSession
        let verborgen = duress ? l.w.vernichtbar : []
        for id in Set(v.entries.map(\.id)).union(verborgen) {
            do {
                let s = try synchron { try await v.revealSecrets(id: id, factors: anbieter) }
                if case let .some(.some(soll)) = l.a.erwartet[id] {
                    auf[id] = s == soll ? "ok" : "falsch"
                } else {
                    auf[id] = "vernichtet-lesbar"
                }
            } catch let x as SiegelError {
                auf[id] = fehlerCode(x)
            } catch {
                throw Fund("fehlertyp", "Aufdecken: kein SiegelError (" + fehlerCode(error) + ")")
            }
        }
        let vAufrufe = l.anbieter.vAnzahl - vVorher
        // Modellfrei: In der Vernichtungs-Sitzung verrät keine Abfrage die unsichtbaren Einträge (Differenz gegen den
        // ungefilterten Inhalt).
        try unsichtbarkeitPruefen(v, verborgen: verborgen)
        return Beobachtung.Sitzung(vernichtungsSitzung: duress, sichtbar: Set(v.entries.map(\.id)),
                                   vernichtet: Set(v.destroyedEntries), aufdecken: auf, vAufrufe: vAufrufe,
                                   markiert: v.destructibleEntries, keyID: v.destructionKeyID,
                                   status: v.destructionStatus, geloescht: Set(v.deletedEntries.map(\.id)))
    }

    private func unsichtbarkeitPruefen(_ v: UnlockedVault, verborgen: Set<UUID>) throws {
        let intern = v.allEntriesForTesting
        let soll = intern.filter { !verborgen.contains($0.id) }.map { max($0.modified, $0.deletedAt ?? .distantPast) }.max()
        guard v.lastModified == soll else { throw Fund("sitzung", "lastModified passt nicht zu den sichtbaren Einträgen") }
        guard !verborgen.isEmpty else { return }
        let r = v.securityReport()
        let bericht = Set(r.weak + r.old + r.sameAsMaster + r.reused.flatMap { $0 })
        guard bericht.isDisjoint(with: verborgen) else {
            throw Fund("sitzung", "Bericht nennt vernichtete Einträge in der Vernichtungs-Sitzung")
        }
        guard v.masterPasswordReuse.isDisjoint(with: verborgen),
              Set(v.deletedEntries.map(\.id)).isDisjoint(with: verborgen),
              Set(v.entries.map(\.id)).isDisjoint(with: verborgen) else {
            throw Fund("sitzung", "Abfrage zeigt vernichtete Einträge in der Vernichtungs-Sitzung")
        }
        guard v.destructibleEntries.isEmpty, v.destroyedEntries.isEmpty else {
            throw Fund("sitzung", "Vernichtungs-Sitzung meldet markierte bzw. vernichtete Einträge")
        }
        let st = v.destructionStatus
        guard st.destroyedTrigger == nil, st.destroyedAt == nil else {
            throw Fund("sitzung", "Vernichtungs-Sitzung zeigt den Vermerk der Vernichtung")
        }
    }

    // MARK: Allgemeine Invarianten (auch ohne Modell)

    // swiftlint:disable:next function_body_length cyclomatic_complexity
    private func allgemeineVorgang(_ l: Lauf, _ op: UInt8, _ fv: FV, _ b: Beobachtung, _ v0: Vorher,
                                   kopfLesbar: Bool) throws {
        let a = l.a
        let falsch = "fehler:" + Self.fehlerFalsch
        let faktorFehler: Set<String> = ["fehler:" + fehlerCode(SiegelError.factorMissing(.card)),
                                         "fehler:" + fehlerCode(SiegelError.factorMissing(.securityKey)),
                                         "fehler:" + fehlerCode(SiegelError.wrongCard)]
        let dateiFehler: Set<String> = [Self.ergebnisCode(SiegelError.vaultMissing), "fehler:corruptFile"]
        var erlaubt: Set<String>
        switch op {
        case 1: erlaubt = ["true", "false", "fehler:" + fehlerCode(SiegelError.io("destruction.write"))]
        case 2, 5: erlaubt = Set([falsch]).union(faktorFehler).union(dateiFehler)
        case 3:
            erlaubt = Set([falsch, "vernichtungssitzung", "vernichtungssitzung-rollback"]).union(faktorFehler).union(dateiFehler)
        case 4, 7:
            erlaubt = ["echt", "echt-rollback", "echt+entfernt", "echt-rollback+entfernt"]
            if !fv.richtig(l.w.stufe.factors) { erlaubt.formUnion(faktorFehler); erlaubt.insert(falsch) }
            if !l.w.tresorLesbar { erlaubt.formUnion(dateiFehler) }
        case 6, 8: erlaubt = Set([falsch, "fehler:corruptFile"]).union(faktorFehler)
        case 9: erlaubt = ["ok", "keine-sitzung", "kein-eintrag", Self.ergebnisCode(SiegelError.io("entry.stale"))]
        case 10: erlaubt = ["ok", "keine-sitzung", falsch]
        case 11:
            erlaubt = ["ok", "keine-sitzung", falsch, Self.ergebnisCode(SiegelError.io("destruction.destroyed")),
                       Self.ergebnisCode(SiegelError.notAllowedAtLevel),
                       Self.ergebnisCode(SiegelError.factorMissing(.secureEnclave)),
                       Self.ergebnisCode(SiegelError.io("destruction.duressPassword")), "fehler:" + Self.fehlerSE,
                       Self.ergebnisCode(SiegelError.io("entry.notFound"))]
        case 12: erlaubt = Set(["ok"]).union(dateiFehler)
        case 13: erlaubt = ["ok", "keine-sitzung", falsch]
        default: erlaubt = ["ok", "keine-ablage"]
        }
        guard erlaubt.contains(b.ergebnis) else {
            throw Fund(op == 4 || op == 7 ? "aussperrung" : "fehlertyp", "Vorgang \(op): \(b.ergebnis)")
        }
        // Der Entsperr-SE-Schlüssel bleibt immer (sonst öffnen die Tresordatei und die Sicherungen nur noch mit dem
        // Notfallcode) – auch ohne lesbare Tresordatei (Befund vernichtung-6) und nach dem Notfallweg (vernichtung-7).
        if let se = a.seKeyID {
            let n = Self.hw(se)
            if v0.namen.contains(n), !b.dateien.contains(n) || l.hardwareDateien()[n] != SaatWerte.oeffnungRoh {
                throw Fund("aussperrung", "Vorgang \(op) hat den Entsperr-SE-Schlüssel gelöscht oder verändert"
                           + (kopfLesbar ? "" : " (ohne lesbare Tresordatei)"))
            }
        }
        // Keine Temp-Reste
        if b.dateien.contains(where: { $0.hasPrefix(".") }) { throw Fund("datei", "Temp-Rest im Hardware-Ordner") }
        // Eine Vernichtungs-Sitzung öffnet nur mit dem eigenen Vernichtungs-Passwort und einer Ablage, die es erkennt;
        // Tresordatei und Sicherungen bleiben dabei bytegleich.
        if b.ergebnis.hasPrefix("vernichtungssitzung") {
            guard op == 3 else { throw Fund("vernichtung", "Vernichtungs-Sitzung mit falschem Passwort (Vorgang \(op))") }
            let pws = [l.duressPW, l.duressPWAlt, a.duressPasswort].compactMap { $0 }
            let erkannt = v0.dateien.contains { name, bytes in
                guard name.hasSuffix(".siegelhw"), let id = UUID(uuidString: String(name.dropLast(9))),
                      let f = AblageBefund.lesen(bytes, erwartet: id) else { return false }
                return pws.contains { AblageBefund.erkannt($0, f, vaultID: a.header.vaultID, kdf: l.w.kdf) }
            }
            guard erkannt else { throw Fund("vernichtung", "Vernichtungs-Sitzung ohne passende Ablage") }
            guard l.tresorUndSicherungen() == v0.tresorUndSicherungen else {
                throw Fund("vernichtung", "Vernichtungs-Sitzung verändert Tresordatei oder Sicherungen")
            }
        }
        let ohneErfolg = [1, 2, 5, 6, 8].contains(op) || b.ergebnis.hasPrefix("fehler") || b.ergebnis.hasPrefix("kein")
            || (op == 13) || (l.sitzungDuress && [9, 10, 11].contains(op) && !b.ergebnis.hasPrefix("ok"))
        if ohneErfolg {
            guard l.tresorUndSicherungen() == v0.tresorUndSicherungen else {
                throw Fund("datei", "Vorgang \(op) ohne Erfolg verändert Tresordatei oder Sicherungen (\(b.ergebnis))")
            }
        }
        if op == 13, b.ergebnis != "keine-sitzung" {
            guard b.dateien == v0.namen, l.hardwareDateien() == v0.dateien else {
                throw Fund("vernichtung", "Verbotener Vorgang ändert den Hardware-Ordner")
            }
        }
        // Sitzung: echtes Passwort → echte Sitzung; nicht vernichtbare bleiben lesbar, vernichtbare ohne V nie.
        if let s = b.sitzung {
            if op == 4 || op == 7 || op == 12 {
                guard !s.vernichtungsSitzung else { throw Fund("vernichtung", "echtes Passwort öffnet Vernichtungs-Sitzung") }
            }
            let vName = Self.hw(a.vKeyID)
            let vDa = b.dateien.contains(vName) && l.hardwareDateien()[vName] == SaatWerte.vRoh(a.v.plan.nummer)
            for (id, r) in s.aufdecken where l.w.vernichtbar.contains(id) || a.vernichtbar.contains(id) {
                if s.vernichtungsSitzung {
                    guard r == Self.fehlerNichtDa else {
                        throw Fund("vernichtung", "vernichtbarer Eintrag in der Vernichtungs-Sitzung erreichbar: \(r)")
                    }
                } else if r == "ok" || r == "vernichtet-lesbar" || r == "falsch" {
                    guard vDa, r == "ok" else { throw Fund("vernichtung", "vernichtbarer Eintrag nach der Vernichtung lesbar") }
                } else if r != Self.fehlerSE, r != Self.fehlerFalsch {
                    throw Fund("fehlertyp", "Aufdecken (vernichtbar): \(r)")
                }
            }
            if s.vernichtungsSitzung {
                guard s.sichtbar.isDisjoint(with: l.w.vernichtbar), s.markiert.isEmpty, s.vernichtet.isEmpty,
                      s.status.destroyedTrigger == nil, s.keyID == l.w.inhalt?.vKeyID else {
                    throw Fund("sitzung", "Vernichtungs-Sitzung verrät die Vernichtung")
                }
            }
        }
        // Gelöscht wird nur, was ein Zustand nennt (V, Ablage, vernichtet), V der Saaten oder eine Ablage des Inhalts.
        let entfernt = v0.namen.subtracting(b.dateien).subtracting([DestructionState.fileName])
        if !entfernt.isEmpty {
            let bekannt = Set(l.genannt.union(l.ablageIDs).union([a.vKeyID, l.b.vKeyID]).map(Self.hw))
            for n in entfernt where !bekannt.contains(n) {
                throw Fund("vernichtung", "Kern löscht eine Datei, die niemand nennt: \(n)")
            }
        }
        // Vermerk ⇒ V weg: nach jedem Vorgang, der checkDeadman fährt und nicht echt entsperrt, ist eine als vernichtet
        // vermerkte Datei weg (bzw. im schreibgeschützten Ordner überschrieben), und der Schlüssel gibt nichts mehr frei.
        // Nicht nach dem echten Entsperren: Es übernimmt einen Vermerk auf V aus dem bisherigen Zustand, auch wenn
        // checkDeadman ihn vorher nicht gelten liess; das Löschen holt die nächste Prüfung nach (KERN-NOTIZEN).
        let seKopf = l.w.seKeyIDKopf
        if [1, 2, 3, 5, 6, 8].contains(op), case let (0, zb?) = l.zustandsArt(), let st = try? DestructionState.decode(zb),
           let x = st.destroyed?.keyID, !kopfLesbar || (st.vaultID == a.vaultID && !(seKopf.map { st.names($0) } ?? false)) {
            let n = Self.hw(x)
            if l.w.schreibschutz {
                if v0.dateien[n] != nil, let nach = l.hardwareDateien()[n], nach == v0.dateien[n] {
                    throw Fund("vernichtung", "vermerkter Schlüssel im schreibgeschützten Ordner nicht überschrieben")
                }
            } else {
                guard !b.dateien.contains(n) else { throw Fund("vernichtung", "vermerkter Schlüssel liegt noch da: \(n)") }
                let roh = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
                let direkt = DateiAnbieter(hardware: l.hw)
                do {
                    _ = try synchron { try await direkt.secureEnclaveSharedSecret(keyID: x, ephemeralPublicKey: roh) }
                    throw Fund("vernichtung", "vermerkter Schlüssel gibt noch etwas frei")
                } catch let f as Fund {
                    throw f
                } catch {
                    guard (error as? SiegelError) == .factorUnavailable(.secureEnclave) else {
                        throw Fund("fehlertyp", "vermerkter Schlüssel: " + fehlerCode(error))
                    }
                }
            }
        }
    }

    // MARK: Rotation und Sicherungen

    /// Nach jedem neuen Zugang (neues Salz, neuer DEK): Kein früherer Umschlag (Kopie der Ablage + sein
    /// Vernichtungs-Passwort + Faktoren) öffnet die neue Tresordatei; die eben geschriebene Ablage öffnet sie.
    private func rotationPruefen(_ l: Lauf, alt: [UInt8]?, neu: [UInt8]?, nach: [String: [UInt8]],
                                 geschrieben: Set<String>) throws {
        guard let alt, let neu, let fa = try? VaultFile.parse(alt), let fn = try? VaultFile.parse(neu) else { return }
        guard fa.header.salt != fn.header.salt else { throw Fund("rotation", "neuer Zugang ohne neues Salz") }
        guard let binding = try DuressCrypto.binding(header: fn.header, factors: l.korrekt) else { return }
        func dek(_ bytes: [UInt8], _ id: UUID, _ pw: String) throws -> SecureBytes? {
            guard let f = try? DuressFile.decode(bytes, expectedID: id) else { return nil }
            let d = try DuressCrypto.derive(password: try PasswordNormalizer.secureBytes(pw), salt: f.salt,
                                            kdf: fn.header.kdf, limits: .testing)
            return DuressCrypto.open(f, d: d, binding: binding, vaultID: fn.header.vaultID).dek
        }
        for u in l.umschlaege.values where u.epoche < l.w.dekEpoche {
            if let k = try dek(u.bytes, u.id, u.pw), (try? VaultCrypto.decryptPayload(fn, dek: k)) != nil {
                throw Fund("rotation", "ein alter Umschlag des Vernichtungs-Passworts öffnet die neue Tresordatei")
            }
        }
        zusatz["rotation_geprueft", default: 0] += 1
        if let id = l.w.inhalt?.duressFileID, let pw = l.duressPW, geschrieben.contains(Self.hw(id)),
           let bytes = nach[Self.hw(id)] {
            guard let k = try dek(bytes, id, pw), (try? VaultCrypto.decryptPayload(fn, dek: k)) != nil else {
                throw Fund("rotation", "die neue Ablage öffnet die neue Tresordatei nicht")
            }
        }
    }

    /// Nach dem Markieren (§23.1): Keine Sicherung im Tresorordner liefert mit dem Notfallcode einen vernichtbaren
    /// Eintrag (`purgeBackups`).
    private func sicherungenNachMarkieren(_ l: Lauf) throws {
        let praefix = VaultStore.backupFolderName + "/"
        for (rel, bytes) in l.tresorUndSicherungen() where rel.hasPrefix(praefix) {
            guard let (lesbar, _) = try? SaatErzeugung.notfallLesbar(bytes, r: l.a.saat.r) else { continue }
            if !lesbar.isDisjoint(with: l.w.vernichtbar) {
                throw Fund("sicherung-notfall", "nach dem Markieren liefert eine Sicherung mit dem Notfallcode einen "
                           + "vernichtbaren Eintrag (§23.1)")
            }
        }
        zusatz["sicherungen_nach_markieren_geprueft", default: 0] += 1
    }

    // MARK: Schluss

    /// Zum Schluss: Schreibschutz weg, Tresordatei wieder da; das echte Passwort öffnet immer eine echte Sitzung
    /// (Zustand und Ablage sperren nie aus).
    private func schluss(_ l: Lauf) throws {
        l.sitzungSperren()
        l.schreibschutz(false)
        if l.e.welt & (W.tresorFehlt | W.tresorKaputt) != 0, !l.w.tresorLesbar {
            try Data(l.a.saat.bytes).write(to: l.tresorURL)
        }
        if let se = l.a.seKeyID, !l.hardwareNamen().contains(Self.hw(se)) {
            throw Fund("aussperrung", "Entsperr-SE-Schlüssel gelöscht")
        }
        let pw = l.passwort
        let f = l.korrekt
        let v = try TestHooks.$now.withValue(SaatWerte.zeitpunkt.addingTimeInterval(400 * Self.tag)) { () -> UnlockedVault in
            do {
                return Self.sitzung(try l.store.unlock(masterPassword: pw, factors: f))
            } catch let x as SiegelError {
                throw Fund("aussperrung", "echtes Passwort öffnet nicht: " + fehlerCode(x))
            }
        }
        defer { v.lock() }
        guard !v.isDuressSession else { throw Fund("vernichtung", "echtes Passwort öffnet Vernichtungs-Sitzung") }
        guard Set(v.entries.map(\.id)) == l.w.alle else {
            throw Fund("vernichtung", "echtes Entsperren zeigt nicht alle Einträge (unsichtbare nicht mitgeschrieben?)")
        }
    }
}
#endif
