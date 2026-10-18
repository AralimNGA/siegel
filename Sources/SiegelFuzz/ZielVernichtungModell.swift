#if DEBUG
import Foundation
@testable import SiegelCore

// Ziel „vernichtung“, Teil 2: das Modell (Orakel). Es rechnet die dokumentierten Abläufe aus KERN-NOTIZEN.md
// (Abschnitt Selbstvernichtung) unabhängig vom Kern nach: `currentState` (vaultID-Bindung, ein Zustand, der den
// Entsperr-SE-Schlüssel nennt, gilt nicht; ohne lesbaren Kopf gilt er trotzdem), Totmann, Zähler (nur
// `wrongPassword`), Vernichtungs-Passwort (Probe, erkannt, Umschlag an DEK und Faktoren), echtes Entsperren (Rotation
// bei `rekeyPending`, Vermerk, veraltete Ablage), jedes Speichern (`syncDestructionAfterWrite`), Passwortwechsel,
// Selbstvernichtung einstellen, Notfallweg, vernichtete Einträge entfernen, Schreibschutz und Rollback.

extension ZielVernichtung {
    /// Was das Modell über einen Vorgang vorhersagt bzw. was beobachtet wurde.
    struct Beobachtung: Equatable {
        enum Z: Equatable {
            case unveraendert
            case fehlt
            case ordner
            case symlink
            case datei(ZustandM)
            case unlesbar
        }

        /// Tresordatei: unverändert, neu geschrieben (gleicher Zugang), neuer Zugang (neues Salz und neuer DEK).
        enum T: String, Equatable {
            case gleich, geschrieben, neuerZugang
        }

        struct Sitzung: Equatable {
            var vernichtungsSitzung: Bool
            var sichtbar: Set<UUID>
            var vernichtet: Set<UUID>
            var aufdecken: [UUID: String]
            var vAufrufe: Int
            /// `destructibleEntries`
            var markiert: Set<UUID>
            /// `destructionKeyID`
            var keyID: UUID?
            /// `UnlockedVault.destructionStatus`
            var status: DestructionStatus
            /// `deletedEntries`
            var geloescht: Set<UUID>
        }

        var ergebnis = ""
        var loeschungen: [UUID] = []
        var dateien: Set<String> = []
        /// Dateien im Hardware-Ordner (ausser zustand.json), die neu sind oder deren Inhalt sich geändert hat.
        var veraendert: Set<String> = []
        var zustand: Z = .unveraendert
        var tresor: T = .gleich
        var sitzung: Sitzung?
    }

    /// Faktor-Varianten der Entsperr-Vorgänge.
    enum FV: UInt8 {
        case korrekt = 0, karteFehlt, karteFalsch, seFalsch, schluesselFehlt

        init(_ v: UInt8) { self = FV(rawValue: (v & 0x07) % 5) ?? .korrekt }

        /// Faktor-Werte zur Saat-Stufe (Zusätzliche ignoriert der Kern).
        func werte(_ stufe: SecurityLevel) -> FactorSecrets {
            var f = SaatWerte.faktoren(stufe.factors)
            switch self {
            case .korrekt: break
            case .karteFehlt: f = FactorSecrets(secureEnclave: f.secureEnclave, card: nil, securityKey: f.securityKey)
            case .karteFalsch:
                f = FactorSecrets(secureEnclave: f.secureEnclave, card: f.card == nil ? nil : SaatWerte.wert(0x52),
                                  securityKey: f.securityKey)
            case .seFalsch:
                f = FactorSecrets(secureEnclave: f.secureEnclave == nil ? nil : SaatWerte.wert(0x51), card: f.card,
                                  securityKey: f.securityKey)
            case .schluesselFehlt: f = FactorSecrets(secureEnclave: f.secureEnclave, card: f.card, securityKey: nil)
            }
            return f
        }

        /// Vorprüfung vor Argon2 (`FactorKDF.precheck`) für eine Datei mit diesen Faktoren: Fehlercode oder nil.
        func vorpruefung(_ kinds: FactorSet) -> String? {
            switch self {
            case .karteFehlt where kinds.contains(.card): return fehlerCode(SiegelError.factorMissing(.card))
            case .schluesselFehlt where kinds.contains(.securityKey):
                return fehlerCode(SiegelError.factorMissing(.securityKey))
            case .karteFalsch where kinds.contains(.card): return fehlerCode(SiegelError.wrongCard)
            default: return nil
            }
        }

        /// Faktoren passen zur Datei (Vorprüfung bestanden und kein falscher Wert).
        func richtig(_ kinds: FactorSet) -> Bool {
            vorpruefung(kinds) == nil && !(self == .seFalsch && kinds.contains(.secureEnclave))
        }
    }

    /// Das Modell eines Tresorordners (Welt, wie der Kern sie sieht, und der massgebliche Inhalt).
    struct Welt {
        // fest
        let vaultID: UUID
        let vKeyIDSaat: UUID
        let seKeyIDSaat: UUID?

        // massgeblicher Inhalt
        var alle: Set<UUID>
        var vernichtbar: Set<UUID>
        var versiegelt: Set<UUID>
        var geloescht: [UUID: Date]
        var inhalt: InhaltM?
        var stufe: SecurityLevel
        /// KDF-Parameter des Kopfes (auch für d des Vernichtungs-Passworts; der Notfallweg setzt neue).
        var kdf: KDFParameters
        /// Entsperr-SE-Schlüssel des Kopfes der aktuellen Tresordatei (nach dem Notfallweg keiner).
        var seKeyIDKopf: UUID?
        var eintragKeyID: UUID?
        /// Zählt die DEK-Wechsel (Umschläge öffnen nur den DEK ihrer Epoche).
        var dekEpoche = 0
        /// Der Wächter kennt eine höhere Generation als die Tresordatei.
        var rollback = false

        // Welt
        var kopfLesbar: Bool
        var tresorLesbar: Bool
        var tresorDa: Bool
        var schreibschutz = false
        var z: ZustandM?
        /// 0 Datei, 1 fehlt, 2 Ordner, 3 Symlink
        var zArt: UInt8
        var dateien: Set<String>
        /// Dateien, deren Inhalt nicht mehr der ursprüngliche Schlüssel ist (überschrieben oder fremd).
        var fremd: Set<String> = []
        /// Inhalt des Hardware-Ordners zu Beginn des Vorgangs (für „ist das wirklich eine Ablage?“).
        var inhalte: [String: [UInt8]] = [:]
        /// Entsperr-SE-Schlüssel aus den Köpfen der eigenen Sicherungen (gelten ohne lesbare Tresordatei).
        var sicherungsSE: Set<UUID> = []
        /// Irgendeine gültige Ablage (Vorlage für die Platzhalter frisch gekapselter Ablagen in `inhalte`).
        var ablageVorlage: [UInt8] = []

        // Vorhersage des laufenden Vorgangs
        var loeschungen: [UUID] = []
        var geschrieben: ZustandM?? = nil
        var veraendert: Set<String> = []
        var tresor: Beobachtung.T = .gleich
        /// Schreiben von zustand.json gescheitert (Schreibschutz).
        var schreibFehler = false

        mutating func neuerVorgang() {
            loeschungen = []
            geschrieben = nil
            veraendert = []
            tresor = .gleich
            schreibFehler = false
        }

        /// `currentState`: gehört zu dieser Datei und nennt den Entsperr-SE-Schlüssel nicht; ohne lesbaren Kopf gilt er,
        /// solange er keinen Entsperr-SE-Schlüssel einer eigenen Sicherung nennt.
        var aktuell: ZustandM? {
            guard let z else { return nil }
            guard kopfLesbar else {
                return z.vaultID == vaultID && sicherungsSE.contains(where: { z.nennt($0) }) ? nil : z
            }
            guard z.vaultID == vaultID, !z.nennt(seKeyIDKopf) else { return nil }
            return z
        }

        // MARK: Dateien

        /// V (bzw. eine genannte Datei) vernichten über die Schicht mit Rückfall: danach weg; im schreibgeschützten
        /// Ordner bleibt sie, aber überschrieben.
        mutating func loesche(_ id: UUID) {
            loeschungen.append(id)
            entferneDatei(ZielVernichtung.hw(id))
        }

        /// Überschreiben und löschen (`overwriteAndRemove`).
        mutating func entferneDatei(_ n: String) {
            guard dateien.contains(n) else { return }
            if schreibschutz {
                fremd.insert(n)
                veraendert.insert(n)
            } else {
                dateien.remove(n)
                fremd.remove(n)
                veraendert.remove(n)
            }
        }

        mutating func schreibe(_ st: ZustandM) {
            guard zArt != 2, !schreibschutz else {
                schreibFehler = true
                return
            }
            zArt = 0
            z = st
            geschrieben = .some(st)
            dateien.insert(DestructionState.fileName)
        }

        mutating func entferneZustand() {
            guard zArt == 0 || zArt == 3, !schreibschutz else { return }
            zArt = 1
            z = nil
            geschrieben = .some(nil)
            dateien.remove(DestructionState.fileName)
        }

        /// `destroyLocked`: V vernichten und vermerken.
        mutating func vernichte(_ st: inout ZustandM, _ trigger: String, _ at: Date) {
            guard st.destroyed == nil, let v = st.vKeyID else { return }
            loesche(v)
            st.destroyed = ZustandM.Vermerk(keyID: v, trigger: trigger, at: ZielVernichtung.kanonisch(at))
            schreibe(st)
        }

        // MARK: Abläufe im gesperrten Zustand

        /// `checkDeadman(now:)`: "true", "false" oder der Fehler beim Vermerken.
        mutating func totmann(_ jetzt: Date) -> String {
            guard var st = aktuell else { return "false" }
            if let d = st.destroyed {
                if dateien.contains(ZielVernichtung.hw(d.keyID)) { loesche(d.keyID) }
                return "false"
            }
            guard let days = st.deadmanDays, let last = st.last, st.vKeyID != nil else { return "false" }
            guard jetzt.timeIntervalSince1970.isFinite else { return "false" }
            let now = ZielVernichtung.kanonisch(jetzt)
            // Uhr rückwärts (mehr als ein Tag vor der letzten echten Entsperrung): nichts. Bei Fristen ≥ 7 Tagen folgt
            // das schon aus der Frist; die Regel steht hier wie im Kern als eigene Zeile (§23.2).
            if now < last.addingTimeInterval(-ZielVernichtung.tag) { return "false" }
            guard now >= last.addingTimeInterval(TimeInterval(days) * ZielVernichtung.tag) else { return "false" }
            vernichte(&st, "deadman", now)
            return schreibFehler ? "fehler:" + fehlerCode(SiegelError.io("destruction.write")) : "true"
        }

        /// `recordFailedAttempt`: nur bei `wrongPassword`.
        mutating func fehlversuch(_ jetzt: Date) {
            guard var st = aktuell, let n = st.maxFailed, st.destroyed == nil else { return }
            st.failed = min(st.failed + 1, 1_000_000)
            if st.failed >= n, st.vKeyID != nil {
                vernichte(&st, "failedAttempts", jetzt)
                return
            }
            schreibe(st)
        }

        /// `recordDuressUnlock`: liest wie alle Prüfungen im gesperrten Zustand über `currentState` (ein Zustand, der
        /// zwischen Probe und Vermerk getauscht wurde und den Entsperr-SE-Schlüssel nennt, gilt nicht).
        mutating func vernichtungsEntsperren(_ jetzt: Date) {
            guard var st = aktuell else { return }
            st.failed = 0
            st.rekeyPending = true
            if let d = st.destroyed {
                if dateien.contains(ZielVernichtung.hw(d.keyID)) { loesche(d.keyID) }
                schreibe(st)
            } else if st.vKeyID != nil {
                vernichte(&st, "duressPassword", jetzt)
            } else {
                schreibe(st)
            }
        }

        // MARK: Echtes Entsperren und Speichern

        private func uebernehmen(_ st: inout ZustandM) {
            st.deadmanDays = inhalt?.deadmanDays
            st.maxFailed = inhalt?.maxFailed
            st.duressEnabled = inhalt?.duressEnabled ?? false
            st.vKeyID = inhalt?.vKeyID
            st.duressFileID = inhalt?.duressFileID
            if let d = st.destroyed, d.keyID != st.vKeyID { st.destroyed = nil }
            if st.maxFailed == nil { st.failed = 0 }
            if inhalt == nil { st.last = nil }
        }

        /// Veraltete Ablage entfernen – nie eine Datei, die der Tresor noch braucht (Entsperr-SE-Schlüssel,
        /// Eintrags-SE-Schlüssel, V, aktuelle Ablage), und nur, wenn die Datei wirklich eine Ablage mit dieser Kennung ist.
        private mutating func veralteteAblage(alt: UUID?, behalten: UUID?) {
            guard let alt, alt != behalten else { return }
            let inGebrauch = [seKeyIDKopf, eintragKeyID, inhalt?.vKeyID].compactMap { $0 }
            guard !inGebrauch.contains(alt) else { return }
            let n = ZielVernichtung.hw(alt)
            guard !fremd.contains(n), let b = inhalte[n], AblageBefund.lesen(b, erwartet: alt) != nil else { return }
            // overwriteAndRemove nimmt den Namen genau so (Grossbuchstaben wie die Dateien des Fuzzers).
            entferneDatei(ZielVernichtung.hw(alt))
        }

        /// Umschlag des Vernichtungs-Passworts frisch kapseln (braucht F: Stufe mit Faktoren). Eine vorhandene Datei
        /// wird nur ersetzt, wenn sie die Form einer Ablage hat (nie ein Schlüssel unter diesem Namen).
        private mutating func ablageSchreiben() {
            guard let d = inhalt?.duressFileID, !stufe.factors.isEmpty, !schreibschutz else { return }
            let n = ZielVernichtung.hw(d)
            if dateien.contains(n) {
                guard !fremd.contains(n), let b = inhalte[n], AblageBefund.hatForm(b) else { return }
            }
            dateien.insert(n)
            fremd.remove(n)
            veraendert.insert(n)
            inhalte[n] = AblageBefund.mitKennung(ablageVorlage, d)
        }

        private mutating func ablegen(_ st: ZustandM, vorher: ZustandM?) {
            if st.isEmpty {
                if vorher != nil || zArt != 1 { entferneZustand() }
                return
            }
            guard st != vorher else { return }
            schreibe(st)
        }

        /// `recordGenuineUnlock` (liest zustand.json ungefiltert, nimmt ihn nur bei gleicher vaultID).
        mutating func echtVermerken(_ jetzt: Date) {
            let vorher = z
            guard inhalt != nil || vorher != nil else { return }
            var st = vorher.flatMap { $0.vaultID == vaultID ? $0 : nil } ?? ZustandM(vaultID: vaultID)
            uebernehmen(&st)
            st.failed = 0
            if inhalt != nil {
                let now = ZielVernichtung.kanonisch(jetzt)
                st.last = max(st.last ?? now, now)
            }
            ablageSchreiben()
            veralteteAblage(alt: vorher?.duressFileID, behalten: st.duressFileID)
            ablegen(st, vorher: vorher)
        }

        /// `syncDestructionAfterWrite`
        mutating func nachSchreiben(neuerDEK: Bool, _ jetzt: Date) {
            let vorher = z
            guard inhalt != nil || vorher != nil else { return }
            var st = vorher.flatMap { $0.vaultID == vaultID ? $0 : nil } ?? ZustandM(vaultID: vaultID)
            uebernehmen(&st)
            if neuerDEK { st.rekeyPending = false }
            if st.anyTrigger, st.last == nil { st.last = ZielVernichtung.kanonisch(jetzt) }
            ablageSchreiben()
            veralteteAblage(alt: vorher?.duressFileID, behalten: st.duressFileID)
            ablegen(st, vorher: vorher)
        }

        /// `persist`: Tresordatei schreiben (gelöschte Einträge nach 30 Tagen weg), danach `syncDestructionAfterWrite`.
        mutating func speichern(neuerDEK: Bool, _ jetzt: Date) {
            let now = ZielVernichtung.kanonisch(jetzt)
            geloescht = geloescht.filter { now.timeIntervalSince($0.value) < 30 * ZielVernichtung.tag }
            tresor = neuerDEK ? .neuerZugang : (tresor == .neuerZugang ? .neuerZugang : .geschrieben)
            if neuerDEK { dekEpoche += 1 }
            rollback = false
            nachSchreiben(neuerDEK: neuerDEK, jetzt)
        }

        /// Echtes Entsperren: zuerst die Rotation nach einer Vernichtungs-Sitzung (nicht bei Rollback-Verdacht), dann
        /// der Vermerk. Liefert, ob das Ergebnis Rollback-Verdacht meldet.
        mutating func echtEntsperren(_ jetzt: Date) -> Bool {
            if aktuell?.rekeyPending == true, !rollback {
                speichern(neuerDEK: true, jetzt)
                echtVermerken(jetzt)
                return false
            }
            echtVermerken(jetzt)
            return rollback
        }

        /// Vernichtet laut Zustand (V des Inhalts als vernichtet vermerkt)?
        var vermerkt: Bool {
            guard let v = inhalt?.vKeyID else { return false }
            return aktuell?.destroyed?.keyID == v
        }

        // MARK: Sitzung

        func aufdecken(_ id: UUID, vernichtungsSitzung: Bool) -> String {
            if vernichtbar.contains(id) {
                if vernichtungsSitzung { return ZielVernichtung.fehlerNichtDa }
                if vermerkt { return ZielVernichtung.fehlerSE }
                let n = ZielVernichtung.hw(inhalt?.vKeyID ?? vKeyIDSaat)
                guard dateien.contains(n) else { return ZielVernichtung.fehlerSE }
                return fremd.contains(n) ? ZielVernichtung.fehlerFalsch : "ok"
            }
            if versiegelt.contains(id) {
                guard let e = eintragKeyID, dateien.contains(ZielVernichtung.hw(e)) else { return ZielVernichtung.fehlerSE }
                return fremd.contains(ZielVernichtung.hw(e)) ? ZielVernichtung.fehlerFalsch : "ok"
            }
            return "ok"
        }

        func sitzung(vernichtungsSitzung d: Bool) -> Beobachtung.Sitzung {
            let sichtbar = d ? alle.subtracting(vernichtbar) : alle
            var auf: [UUID: String] = [:]
            for id in sichtbar.union(d ? vernichtbar : []) { auf[id] = aufdecken(id, vernichtungsSitzung: d) }
            let keyID: UUID? = inhalt?.vKeyID.flatMap { d || !vermerkt ? $0 : nil }
            return Beobachtung.Sitzung(vernichtungsSitzung: d, sichtbar: sichtbar,
                                       vernichtet: !d && vermerkt ? vernichtbar : [], aufdecken: auf,
                                       vAufrufe: d || vermerkt ? 0 : vernichtbar.count, markiert: d ? [] : vernichtbar,
                                       keyID: keyID, status: sitzungsStatus(d, keyID: keyID),
                                       geloescht: Set(geloescht.keys).subtracting(d ? vernichtbar : []))
        }

        /// `UnlockedVault.destructionStatus`: Einstellungen aus dem Inhalt, in einer Vernichtungs-Sitzung ohne Vermerk.
        func sitzungsStatus(_ d: Bool, keyID: UUID?) -> DestructionStatus {
            let st = ZielVernichtung.status(self)
            let settings = inhalt.map {
                DestructionSettings(deadmanDays: $0.deadmanDays, maxFailedAttempts: $0.maxFailed,
                                    duressEnabled: $0.duressEnabled)
            } ?? .off
            let deadline = settings.deadmanDays.flatMap { days in
                st.lastGenuineUnlock.map { ZielVernichtung.kanonisch($0.addingTimeInterval(TimeInterval(days) * ZielVernichtung.tag)) }
            }
            return DestructionStatus(settings: settings, lastGenuineUnlock: st.lastGenuineUnlock,
                                     failedAttempts: st.failedAttempts, deadline: deadline,
                                     destroyedTrigger: d ? nil : st.destroyedTrigger, destroyedAt: d ? nil : st.destroyedAt,
                                     keyConfigured: st.keyConfigured || keyID != nil)
        }
    }

    /// Erwarteter Status (`destructionStatus()`) eines Modells.
    static func status(_ w: Welt) -> DestructionStatus {
        guard let st = w.aktuell else { return .off }
        let settings = DestructionSettings(deadmanDays: st.deadmanDays, maxFailedAttempts: st.maxFailed,
                                           duressEnabled: st.duressEnabled)
        return DestructionStatus(settings: settings, lastGenuineUnlock: st.last, failedAttempts: st.failed,
                                 deadline: st.deadline,
                                 destroyedTrigger: st.destroyed.flatMap { DestructionTrigger(rawValue: $0.trigger) },
                                 destroyedAt: st.destroyed?.at, keyConfigured: st.vKeyID != nil || st.destroyed != nil)
    }

    static func statusText(_ s: DestructionStatus) -> String {
        let t = s.settings
        return "{tage \(t.deadmanDays.map(String.init) ?? "-"), n \(t.maxFailedAttempts.map(String.init) ?? "-"), "
            + "zwang \(t.duressEnabled), letzte \(s.lastGenuineUnlock.map { "\($0.timeIntervalSince1970)" } ?? "-"), "
            + "fehl \(s.failedAttempts), vernichtet \(s.destroyedTrigger?.rawValue ?? "-"), V \(s.keyConfigured)}"
    }

    static func text(_ z: Beobachtung.Z) -> String {
        switch z {
        case .unveraendert: return "unverändert"
        case .fehlt: return "fehlt"
        case .ordner: return "Ordner"
        case .symlink: return "Symlink"
        case .unlesbar: return "unlesbar"
        case let .datei(m):
            return "{fehl \(m.failed), letzte \(m.last.map { "\($0.timeIntervalSince1970)" } ?? "-"), vernichtet "
                + "\(m.destroyed.map { $0.trigger + "@" + $0.keyID.uuidString.prefix(8) } ?? "-"), V \(m.vKeyID.map { String($0.uuidString.prefix(8)) } ?? "-"), "
                + "Ablage \(m.duressFileID.map { String($0.uuidString.prefix(8)) } ?? "-"), rekey \(m.rekeyPending), "
                + "tage \(m.deadmanDays.map(String.init) ?? "-"), n \(m.maxFailed.map(String.init) ?? "-")}"
        }
    }

    static func unterschied(_ p: Beobachtung, _ b: Beobachtung) -> String {
        var t: [String] = []
        if p.ergebnis != b.ergebnis { t.append("Ergebnis \(b.ergebnis) statt \(p.ergebnis)") }
        if p.loeschungen != b.loeschungen {
            t.append("vernichtet \(b.loeschungen.map(\.uuidString)) statt \(p.loeschungen.map(\.uuidString))")
        }
        if p.dateien != b.dateien {
            t.append("Hardware-Ordner: weg \(p.dateien.subtracting(b.dateien).sorted()), neu \(b.dateien.subtracting(p.dateien).sorted())")
        }
        if p.veraendert != b.veraendert {
            t.append("Inhalt geändert \(b.veraendert.sorted()) statt \(p.veraendert.sorted())")
        }
        if p.zustand != b.zustand { t.append("zustand.json \(text(b.zustand)) statt \(text(p.zustand))") }
        if p.tresor != b.tresor { t.append("Tresordatei \(b.tresor.rawValue) statt \(p.tresor.rawValue)") }
        if p.sitzung != b.sitzung {
            if let x = p.sitzung, let y = b.sitzung {
                if x.vernichtungsSitzung != y.vernichtungsSitzung { t.append("Sitzungsart") }
                if x.sichtbar != y.sichtbar { t.append("sichtbare Einträge") }
                if x.vernichtet != y.vernichtet { t.append("destroyedEntries \(y.vernichtet.count) statt \(x.vernichtet.count)") }
                for (id, s) in x.aufdecken where y.aufdecken[id] != s {
                    t.append("Aufdecken \(id.uuidString.prefix(8)): \(y.aufdecken[id] ?? "-") statt \(s)")
                }
                if x.vAufrufe != y.vAufrufe { t.append("V-Aufrufe \(y.vAufrufe) statt \(x.vAufrufe)") }
                if x.markiert != y.markiert { t.append("destructibleEntries \(y.markiert.count) statt \(x.markiert.count)") }
                if x.keyID != y.keyID {
                    t.append("destructionKeyID \(y.keyID.map { String($0.uuidString.prefix(8)) } ?? "-") statt "
                             + "\(x.keyID.map { String($0.uuidString.prefix(8)) } ?? "-")")
                }
                if x.status != y.status { t.append("Sitzungs-Status \(statusText(y.status)) statt \(statusText(x.status))") }
                if x.geloescht != y.geloescht { t.append("deletedEntries \(y.geloescht.count) statt \(x.geloescht.count)") }
            } else {
                t.append("Sitzung \(b.sitzung == nil ? "fehlt" : "unerwartet")")
            }
        }
        return t.joined(separator: "; ")
    }
}
#endif
