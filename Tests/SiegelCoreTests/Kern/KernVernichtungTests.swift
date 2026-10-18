import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Fehler eines Aufrufs (nil = kein Fehler); für Fälle mit Nutzlast wie `passwordTooWeak(bits:)`.
func vFehler(_ body: () async throws -> Void) async -> SiegelError? {
    do {
        try await body()
        return nil
    } catch let e as SiegelError {
        return e
    } catch {
        return .io("test.fremd")
    }
}

private let tag: TimeInterval = 86_400

@Suite("Selbstvernichtung: Einrichten (§23.3)")
struct KernVernichtungEinrichtenTests {
    @Test("Markieren nur Schutz 4/5 in Stufe 4/5; vernichtbar = an V versiegelt, ohne Notfall-Umschlag")
    func markieren() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .fingerabdruck)
        let c = try v.add("Krypto", .festung)
        #expect(await vFehler { try await v.einrichten(.off, markieren: [b.id]) } == .notAllowedAtLevel)

        let report = try await v.einrichten(.off, markieren: [a.id, c.id])
        #expect(report?.isComplete == true)
        #expect(v.vault.destructibleEntries == [a.id, c.id])
        #expect(v.vault.destructionKeyID == v.vKeyID)
        let content = try #require(v.vault.contentForTesting)
        #expect(Set(content.destructible.keys) == [a.id, c.id])
        #expect(content.sealed[a.id] == nil && content.sealed[c.id] == nil && content.sealed[b.id] != nil)
        // Kein Notfall-Umschlag, keine Gruppe für die vernichtbaren Masken.
        #expect(Set(content.recoveryGroups.map(\.mask)) == [[.secureEnclave]])
        let json = try v.t.jsonOnDisk(v.vault)
        #expect(json.contains("\"recovery\":null"))
        #expect(json.contains("\"destruction\":{\"duress\":null,\"settings\":{\"deadmanDays\":null"))
        #expect(json.contains("\"vKey\":{\"keyID\":\"" + v.vKeyID.uuidString))

        // Aufdecken über V (+ Karte, + Sicherheitsschlüssel); der Eintrags-SE-Schlüssel wird nicht gefragt.
        let before = v.t.p.count(.secureEnclave)
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
        #expect(try await v.reveal(c.id) == EntrySecrets(c))
        #expect(v.provider.vCount == 2)
        #expect(v.t.p.count(.secureEnclave) == before)
        #expect(try await v.reveal(b.id) == EntrySecrets(b))
        // Liste und offene Felder bleiben normal.
        #expect(v.vault.entries.count == 3)
        #expect(v.vault.entries.first { $0.id == a.id }?.secretsSealed == true)
        // Nach dem Neu-Öffnen genauso.
        try v.reopen()
        #expect(v.vault.destructibleEntries == [a.id, c.id])
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
    }

    @Test("Stufe 1–3: einschalten und markieren abgelehnt, alles aus geht")
    func stufeZuTief() async throws {
        let v = try VTresor(.hoch)
        let a = try v.add("Bank", .maximal)
        #expect(await vFehler { try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: []) }
                == .notAllowedAtLevel)
        #expect(await vFehler { try await v.einrichten(.off, markieren: [a.id]) } == .notAllowedAtLevel)
        #expect(await vFehler {
            try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [])
        } == .notAllowedAtLevel)
        #expect(try await v.einrichten(.off, markieren: [], vKey: false) == nil)
        #expect(v.vault.contentForTesting?.destruction == nil)
        #expect(!FileManager.default.fileExists(atPath: v.stateURL.path))
    }

    @Test("Falsche Konfigurationen werden abgelehnt, ohne etwas zu schreiben")
    func falscheKonfigurationen() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let generation = v.vault.generation
        let pw = VTresor.duressPW
        #expect(await vFehler { try await v.einrichten(DestructionSettings(deadmanDays: 6), markieren: []) }
                == .io("destruction.deadmanDays"))
        #expect(await vFehler { try await v.einrichten(DestructionSettings(deadmanDays: 366), markieren: []) }
                == .io("destruction.deadmanDays"))
        #expect(await vFehler { try await v.einrichten(DestructionSettings(maxFailedAttempts: 9), markieren: []) }
                == .io("destruction.maxFailedAttempts"))
        #expect(await vFehler { try await v.einrichten(DestructionSettings(maxFailedAttempts: 101), markieren: []) }
                == .io("destruction.maxFailedAttempts"))
        // Vernichtungs-Passwort: fehlt beim Einschalten, ist mitgegeben ohne Einschalten, zu schwach, = Master.
        #expect(await vFehler { try await v.einrichten(DestructionSettings(duressEnabled: true), markieren: []) }
                == .io("destruction.duressPassword"))
        #expect(await vFehler { try await v.einrichten(DestructionSettings(deadmanDays: 30), duress: pw, markieren: []) }
                == .io("destruction.duressPassword"))
        let schwach = await vFehler {
            try await v.einrichten(DestructionSettings(duressEnabled: true), duress: KT.weak, markieren: [])
        }
        if case .passwordTooWeak = schwach {} else { Issue.record("passwordTooWeak erwartet") }
        #expect(await vFehler {
            try await v.einrichten(DestructionSettings(duressEnabled: true), duress: KT.pw1, markieren: [])
        } == .masterPasswordReused)
        // Ohne V, falsches Passwort, unbekannter Eintrag, V = Eintrags-SE-Schlüssel, ungültiger Punkt.
        #expect(await vFehler { try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [], vKey: false) }
                == .factorMissing(.secureEnclave))
        #expect(await vFehler { try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [], password: KT.pw2) }
                == .wrongPassword)
        #expect(await vFehler { try await v.einrichten(.off, markieren: [UUID()]) } == .io("entry.notFound"))
        let gleich = EntryKeyEnrollment(keyID: v.t.p.entryKeyID, publicKey: v.vKey.publicKey.x963Representation)
        #expect(await vFehler {
            try await v.vault.configureDestruction(DestructionSettings(deadmanDays: 30), duressPassword: nil,
                                                   destructible: [], masterPassword: KT.pw1, factors: try v.factors(),
                                                   vKey: gleich, entryFactors: v.provider)
        } == .crypto("factor.keyID"))
        let kaputt = EntryKeyEnrollment(keyID: UUID(), publicKey: Data(repeating: 4, count: 65))
        #expect(await vFehler {
            try await v.vault.configureDestruction(DestructionSettings(deadmanDays: 30), duressPassword: nil,
                                                   destructible: [], masterPassword: KT.pw1, factors: try v.factors(),
                                                   vKey: kaputt, entryFactors: v.provider)
        } == .crypto("factor.publicKey"))
        // Markieren braucht die Geheimteile: synchron → factorMissing; async ohne Provider ebenso.
        #expect(await vFehler {
            try v.vault.configureDestruction(.off, duressPassword: nil, destructible: [a.id], masterPassword: KT.pw1,
                                             factors: try v.factors(), vKey: v.vEnrollment)
        } == .factorMissing(.secureEnclave))
        #expect(await vFehler {
            try await v.vault.configureDestruction(.off, duressPassword: nil, destructible: [a.id],
                                                   masterPassword: KT.pw1, factors: try v.factors(),
                                                   vKey: v.vEnrollment, entryFactors: nil)
        } == .factorMissing(.secureEnclave))
        #expect(v.vault.generation == generation)
        #expect(!FileManager.default.fileExists(atPath: v.stateURL.path))
        #expect(v.t.p.count(.secureEnclave) == 0)

        // Gültig einrichten; danach ein anderes V, solange Einträge daran hängen → abgelehnt.
        try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [a.id])
        let anderes = EntryKeyEnrollment(keyID: UUID(), publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        #expect(await vFehler {
            try await v.vault.configureDestruction(DestructionSettings(deadmanDays: 30), duressPassword: nil,
                                                   destructible: [a.id], masterPassword: KT.pw1,
                                                   factors: try v.factors(), vKey: anderes, entryFactors: v.provider)
        } == .notAllowedAtLevel)
        // Nur Einstellungen ändern geht auch synchron (nichts neu zu versiegeln).
        try v.vault.configureDestruction(DestructionSettings(deadmanDays: 60, maxFailedAttempts: 20), duressPassword: nil,
                                         destructible: [a.id], masterPassword: KT.pw1, factors: try v.factors(),
                                         vKey: nil)
        #expect(v.vault.destructionSettings == DestructionSettings(deadmanDays: 60, maxFailedAttempts: 20))
        #expect(v.store.destructionStatus().settings == DestructionSettings(deadmanDays: 60, maxFailedAttempts: 20))
    }

    @Test("Markieren entfernt ältere Sicherungen (sie enthielten den Eintrag mit Notfallweg)")
    func sicherungenBereinigt() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try v.add("Mail", .fingerabdruck)
        try v.add("Shop", .maximal)
        #expect(v.t.f.localBackups().count >= 3)
        let report = try #require(try await v.einrichten(.off, markieren: [a.id]))
        #expect(report.isComplete)
        let backups = v.t.f.localBackups()
        #expect(!backups.isEmpty)
        for b in backups {
            let c = try v.t.f.openFile(b.url, factors: try v.factors())
            #expect(c.sealed[a.id] == nil)
            #expect(c.destructible[a.id] != nil)
        }
        // Nur Einstellungen ändern bereinigt nichts.
        try v.add("Neu", .maximal)
        let count = v.t.f.localBackups().count
        #expect(try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [a.id]) == nil)
        #expect(v.t.f.localBackups().count >= count)
    }

    @Test("Wird ein Eintrag während der Freigabe geändert, gilt das Geöffnete nicht mehr")
    func waehrendDerFreigabeGeaendert() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let vault = v.vault
        v.t.p.onAnswer {
            try? vault.setProtection(.maximal, id: a.id, secrets: EntrySecrets(password: "Inzwischen-geaendert-1"))
        }
        #expect(await vFehler { try await v.einrichten(.off, markieren: [a.id]) } == .io("entry.stale"))
        v.t.p.onAnswer(nil)
        #expect(v.vault.destructibleEntries.isEmpty)
        #expect(try await v.reveal(a.id).password == "Inzwischen-geaendert-1")
    }

    @Test("Befund ablaeufe-5: Markiert ohne Auslöser – Stand nennt den Schlüssel V, offen und gesperrt")
    func markiertOhneAusloeser() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Krypto", .maximal)
        #expect(!v.vault.destructionStatus.keyConfigured && !v.store.destructionStatus().keyConfigured)
        try await v.einrichten(.off, markieren: [a.id])
        let offen = v.vault.destructionStatus
        #expect(!offen.settings.anyTriggerEnabled && offen.keyConfigured)
        v.vault.lock()
        // Gesperrt unterscheidet die Oberfläche diesen Zustand jetzt von „nichts eingerichtet“ (Warnung im Notfallweg).
        let gesperrt = v.store.destructionStatus()
        #expect(!gesperrt.settings.anyTriggerEnabled && gesperrt.keyConfigured && gesperrt != .off)
        try v.reopen()
        // Alles aus: V weg, Stand wieder wie nie eingerichtet.
        try await v.einrichten(.off, markieren: [], vKey: false)
        #expect(!v.vault.destructionStatus.keyConfigured && v.store.destructionStatus() == .off)
    }

    @Test("Entmarkieren versiegelt wieder normal (mit Notfallweg); alles aus entfernt V")
    func entmarkieren() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let c = try v.add("Krypto", .festung)
        try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [a.id, c.id])
        let vCalls = v.provider.vCount
        try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [c.id])
        #expect(v.provider.vCount == vCalls + 1)
        #expect(v.vault.destructibleEntries == [c.id])
        let content = try #require(v.vault.contentForTesting)
        #expect(content.sealed[a.id] != nil && content.destructible[a.id] == nil)
        #expect(try await v.reveal(a.id) == EntrySecrets(a))

        // Alles aus: c wieder normal, V vernichtet (nicht mehr gebraucht), Zustand weg.
        try await v.einrichten(.off, markieren: [], vKey: false)
        #expect(v.vault.contentForTesting?.destruction == nil)
        #expect(v.vault.destructibleEntries.isEmpty)
        #expect(v.eraser.destroyed == [v.vKeyID])
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(!FileManager.default.fileExists(atPath: v.stateURL.path))
        #expect(try await v.reveal(c.id) == EntrySecrets(c))
        // Beide wieder über den Notfallcode lesbar.
        let kit = try #require(v.t.kit)
        v.vault.lock()
        let r = try v.store.recover(shares: [kit.shares[0].formatted, kit.shares[2].formatted], newMasterPassword: KT.pw2,
                                   kdf: KT.kdf)
        #expect(r.entries.first { $0.id == a.id }?.password == a.password)
        #expect(r.entries.first { $0.id == c.id }?.notes == c.notes)
    }

    @Test("Stufe, KDF, Master-Passwort und Schutz respektieren die Selbstvernichtung")
    func regelnAndererWege() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        let f = try v.factors()
        #expect(await vFehler {
            try v.vault.changeSecurityLevel(to: .hoch, masterPassword: KT.pw1, currentFactors: f,
                                            newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        } == .notAllowedAtLevel)
        #expect(await vFehler {
            try v.vault.changeMasterPassword(current: KT.pw1, new: KT.pw1, factors: f,
                                             kdf: KDFParameters(opsLimit: 3, memLimitBytes: 64 << 10))
        } == .notAllowedAtLevel)
        #expect(await vFehler {
            try v.vault.changeMasterPassword(current: KT.pw1, new: VTresor.duressPW, factors: f)
        } == .masterPasswordReused)
        // Schutz: unter 4 nicht (erst entmarkieren), 4 → 5 bleibt vernichtbar.
        let s = try await v.reveal(a.id)
        #expect(await vFehler { try v.vault.setProtection(.hoch, id: a.id, secrets: s) } == .notAllowedAtLevel)
        try v.vault.setProtection(.festung, id: a.id, secrets: s.replacingPassword(with: "Neu-123!"))
        #expect(v.vault.destructibleEntries == [a.id])
        #expect(try await v.reveal(a.id).password == "Neu-123!")
        // Eine andere Karte geht nicht (Stufe 4 öffnet mit ihr); den Eintrags-SE-Schlüssel ersetzen geht, denn der
        // vernichtbare Eintrag hängt an V, nicht an ihm.
        #expect(await vFehler {
            try v.vault.enrollFactors(NewFactorMaterial(card: CardEnrollment(q: CardCode.generate())),
                                      masterPassword: KT.pw1, currentFactors: f)
        } == .wrongCard)
        let ersatz = EntryKeyEnrollment(keyID: UUID(), publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        try v.vault.enrollFactors(NewFactorMaterial(entryKey: ersatz), masterPassword: KT.pw1, currentFactors: f)
        #expect(try await v.reveal(a.id).password == "Neu-123!")
        // Stufe 4 → 5 geht (gleiches KDF-Profil), der Eintrag bleibt vernichtbar.
        try v.vault.changeSecurityLevel(to: .festung, masterPassword: KT.pw1, currentFactors: try v.t.k.secrets(.all),
                                        newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        #expect(v.vault.level == .festung)
        #expect(v.vault.destructibleEntries == [a.id])
        #expect(try v.duressEnvelopeOpens())
    }
}

@Suite("Selbstvernichtung: Auslöser (§23.2)")
struct KernVernichtungAusloeserTests {
    @Test("Totmann-Schalter: vernichtet nach Ablauf der Frist, auch gesperrt; danach nur noch entfernen")
    func totmann() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .maximal)
        let o = try v.add("Notiz", .fingerabdruck)
        try await TestHooks.$now.withValue(t0) {
            try await v.einrichten(DestructionSettings(deadmanDays: 7), markieren: [a.id])
        }
        let status = v.store.destructionStatus()
        #expect(status.lastGenuineUnlock == t0)
        #expect(status.deadline == t0.addingTimeInterval(7 * tag))
        #expect(!status.deadlineIsNear(now: t0.addingTimeInterval(5 * tag)))
        #expect(status.deadlineIsNear(now: t0.addingTimeInterval(5.5 * tag)))
        v.vault.lock()

        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(7 * tag - 1)) == false)
        #expect(FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(7 * tag)) == true)
        #expect(v.eraser.destroyed == [v.vKeyID])
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        let after = v.store.destructionStatus()
        #expect(after.destroyedTrigger == .deadman)
        #expect(after.destroyedAt == t0.addingTimeInterval(7 * tag))
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(30 * tag)) == false)
        #expect(v.eraser.destroyed == [v.vKeyID])

        // Echtes Entsperren: Meldung, Eintrag unlesbar (ohne Touch-ID-Anfrage), die anderen unberührt.
        try v.reopen()
        #expect(!v.vault.isDuressSession)
        #expect(v.vault.destroyedEntries == [a.id])
        #expect(v.vault.destructionStatus.destroyedTrigger == .deadman)
        #expect(v.vault.destructionKeyID == nil)
        let calls = v.provider.vCount
        #expect(await vFehler { _ = try await v.reveal(a.id) } == .factorUnavailable(.secureEnclave))
        #expect(v.provider.vCount == calls)
        #expect(try await v.reveal(b.id) == EntrySecrets(b))
        #expect(try await v.reveal(o.id) == EntrySecrets(o))
        #expect(await vFehler { try v.vault.setProtection(.festung, id: a.id, secrets: EntrySecrets()) }
                == .io("entry.destroyed"))
        #expect(await vFehler { try await v.einrichten(DestructionSettings(deadmanDays: 7), markieren: []) }
                == .io("destruction.destroyed"))

        // Entfernen: Eintrag weg, Selbstvernichtung aus, Zustand weg.
        try v.vault.removeDestroyedEntries()
        #expect(!v.vault.entries.contains { $0.id == a.id })
        #expect(v.vault.destroyedEntries.isEmpty)
        #expect(v.vault.destructionSettings == .off)
        #expect(!FileManager.default.fileExists(atPath: v.stateURL.path))
        #expect(v.store.destructionStatus() == .off)
        #expect(try await v.reveal(b.id) == EntrySecrets(b))
        // Neu einrichten mit neuem V geht wieder.
        let neu = P256.KeyAgreement.PrivateKey()
        let nID = UUID()
        try await v.vault.configureDestruction(DestructionSettings(deadmanDays: 7), duressPassword: nil,
                                               destructible: [b.id], masterPassword: KT.pw1, factors: try v.factors(),
                                               vKey: EntryKeyEnrollment(keyID: nID, publicKey: neu.publicKey.x963Representation),
                                               entryFactors: v.provider)
        #expect(v.vault.destructibleEntries == [b.id])
    }

    @Test("Totmann-Schalter greift auch beim Entsperren, bevor etwas geöffnet wird")
    func totmannBeimEntsperren() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await TestHooks.$now.withValue(t0) {
            try await v.einrichten(DestructionSettings(deadmanDays: 10), markieren: [a.id])
        }
        try TestHooks.$now.withValue(t0.addingTimeInterval(11 * tag)) { try v.reopen() }
        #expect(v.vault.destroyedEntries == [a.id])
        #expect(v.store.destructionStatus().destroyedTrigger == .deadman)
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
    }

    @Test("Uhr läuft rückwärts: nicht vernichten, Frist nicht verlängern")
    func uhrRueckwaerts() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await TestHooks.$now.withValue(t0) {
            try await v.einrichten(DestructionSettings(deadmanDays: 7), markieren: [a.id])
        }
        v.vault.lock()
        let bytes = try Data(contentsOf: v.stateURL)
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(-2 * tag)) == false)
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(-0.5 * tag)) == false)
        #expect(try Data(contentsOf: v.stateURL) == bytes)
        // Echtes Entsperren mit zurückgestellter Uhr: letzte echte Entsperrung bleibt t0.
        try TestHooks.$now.withValue(t0.addingTimeInterval(-10 * tag)) { try v.reopen() }
        #expect(v.store.destructionStatus().lastGenuineUnlock == t0)
        #expect(v.store.destructionStatus().deadline == t0.addingTimeInterval(7 * tag))
        // Uhr wieder richtig, Entsperren am Tag 3: Frist ab da.
        try TestHooks.$now.withValue(t0.addingTimeInterval(3 * tag)) { try v.reopen() }
        #expect(v.store.destructionStatus().lastGenuineUnlock == t0.addingTimeInterval(3 * tag))
        v.vault.lock()
        // Uhr wieder rückwärts nach Ablauf → nichts; vorwärts über die Frist → vernichtet.
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(-20 * tag)) == false)
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(10 * tag - 1)) == false)
        #expect(v.eraser.destroyed.isEmpty)
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(10 * tag)) == true)
        #expect(v.eraser.destroyed == [v.vKeyID])
    }

    @Test("Fehlversuch-Zähler: nur wrongPassword zählt, echtes Entsperren setzt zurück, bei N vernichtet")
    func zaehler() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .maximal)
        try await v.einrichten(DestructionSettings(maxFailedAttempts: 10), markieren: [a.id])
        v.vault.lock()
        let f = try v.factors()
        for i in 1...4 {
            #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw2, factors: f) } == .wrongPassword)
            #expect(v.store.destructionStatus().failedAttempts == i)
        }
        #expect(!v.store.destructionStatus().shouldWarnAboutAttempts)
        #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw2, factors: f) } == .wrongPassword)
        #expect(v.store.destructionStatus().shouldWarnAboutAttempts)
        #expect(v.store.destructionStatus().remainingAttempts == 5)
        // Zählen nicht: fehlender Faktor, falsche Karte, Argon2-Fehler.
        #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw2, factors: try v.t.k.secrets([.secureEnclave])) }
                == .factorMissing(.card))
        var falscheKarte = f
        falscheKarte.card = CardCode.generate()
        #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw2, factors: falscheKarte) } == .wrongCard)
        #expect(await vFehler {
            try TestHooks.$forceKDFFailure.withValue(true) { _ = try v.store.unlock(masterPassword: KT.pw2, factors: f) }
        } == .kdfFailed)
        #expect(v.store.destructionStatus().failedAttempts == 5)
        // Echtes Entsperren setzt zurück.
        try v.reopen()
        #expect(v.store.destructionStatus().failedAttempts == 0)
        v.vault.lock()
        // Auch die Sicherungswege zählen.
        let backup = try #require(v.t.f.localBackups().first)
        #expect(await vFehler { _ = try v.store.restoreBackup(backup, masterPassword: KT.pw2, factors: f) } == .wrongPassword)
        #expect(v.store.destructionStatus().failedAttempts == 1)
        for _ in 2...9 {
            #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw3, factors: f) } == .wrongPassword)
        }
        #expect(v.eraser.destroyed.isEmpty)
        #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw3, factors: f) } == .wrongPassword)
        #expect(v.eraser.destroyed == [v.vKeyID])
        #expect(v.store.destructionStatus().destroyedTrigger == .failedAttempts)
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        // Weitere Fehlversuche ändern nichts mehr.
        #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw3, factors: f) } == .wrongPassword)
        #expect(v.eraser.destroyed == [v.vKeyID])
        // Echt entsperrt: a vernichtet, b unberührt.
        try v.reopen()
        #expect(v.vault.destroyedEntries == [a.id])
        #expect(await vFehler { _ = try await v.reveal(a.id) } == .factorUnavailable(.secureEnclave))
        #expect(try await v.reveal(b.id) == EntrySecrets(b))
    }

    @Test("Alle Sicherungswege zählen; Argon2-Fehler bei beiden Läufen zählt nicht")
    func sicherungswege() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(maxFailedAttempts: 10, duressEnabled: true), duress: VTresor.duressPW,
                               markieren: [a.id])
        v.vault.lock()
        let f = try v.factors()
        #expect(try v.store.checkDeadman(now: Date()) == false)
        #expect(await vFehler { _ = try v.store.restoreNewestReadableBackup(masterPassword: KT.pw2, factors: f) }
                == .wrongPassword)
        #expect(v.store.destructionStatus().failedAttempts == 1)
        #expect(await vFehler { _ = try v.store.importBackup(from: v.store.vaultURL, masterPassword: KT.pw2, factors: f) }
                == .wrongPassword)
        #expect(v.store.destructionStatus().failedAttempts == 2)
        // Mit Vernichtungs-Passwort: beide Argon2 scheitern (2 gleichzeitig), dann nacheinander – der erste scheitert
        // wieder (3) → kdfFailed, kein Fehlversuch.
        let counter = TestHooks.Counter()
        #expect(await vFehler {
            try TestHooks.$forceKDFFailure.withValue(true) {
                try TestHooks.$kdfCounter.withValue(counter) { _ = try v.tryUnlock(KT.pw2) }
            }
        } == .kdfFailed)
        #expect(counter.value == 3)
        #expect(v.store.destructionStatus().failedAttempts == 2)
        #expect(v.eraser.destroyed.isEmpty)
        // Eine Sicherung mit dem Master-Passwort einsetzen gilt als echtes Entsperren (Zähler 0).
        let backup = try #require(v.t.f.localBackups().first)
        v.vault = try v.store.restoreBackup(backup, masterPassword: KT.pw1, factors: f)
        #expect(v.store.destructionStatus().failedAttempts == 0)
        #expect(try v.duressEnvelopeOpens())
    }

    @Test("Zähler aus: falsche Passwörter hinterlassen keine Spur")
    func zaehlerAus() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [a.id])
        v.vault.lock()
        let bytes = try Data(contentsOf: v.stateURL)
        for _ in 1...12 {
            #expect(await vFehler { _ = try v.store.unlock(masterPassword: KT.pw2, factors: try v.factors()) } == .wrongPassword)
        }
        #expect(try Data(contentsOf: v.stateURL) == bytes)
        #expect(v.store.destructionStatus().failedAttempts == 0)
        #expect(v.eraser.destroyed.isEmpty)
    }

    @Test("Schicht kaputt: der Kern überschreibt und löscht V selbst")
    func rueckfall() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(maxFailedAttempts: 10), markieren: [a.id])
        let kaputt = ZaehlEraser(untaetig: true)
        v.store.destructionKeyEraser = kaputt
        v.vault.lock()
        for _ in 1...10 { _ = try? v.store.unlock(masterPassword: KT.pw2, factors: try v.factors()) }
        #expect(kaputt.destroyed == [v.vKeyID])
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(v.store.destructionStatus().destroyedTrigger == .failedAttempts)
    }
}

@Suite("Selbstvernichtung: Vernichtungs-Passwort (§23.2 Nr. 3)")
struct KernVernichtungsPasswortTests {
    @Test("Vernichtungs-Passwort öffnet scheinbar normal, vernichtet vorher still, verlängert die Frist nicht")
    func vernichtungsSitzung() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .maximal)
        let o = try v.add("Notiz", .fingerabdruck)
        try await TestHooks.$now.withValue(t0) {
            try await v.einrichten(DestructionSettings(deadmanDays: 30, maxFailedAttempts: 10, duressEnabled: true),
                                   duress: VTresor.duressPW, markieren: [a.id])
        }
        v.vault.lock()
        _ = try? v.store.unlock(masterPassword: KT.pw2, factors: try v.factors())
        #expect(v.store.destructionStatus().failedAttempts == 1)
        let vaultBytes = try v.t.f.fileBytes()
        let backups = v.t.f.backupFileNames()
        let hw = v.hardwareNames()

        let dv = try TestHooks.$now.withValue(t0.addingTimeInterval(2 * tag)) { try v.tryUnlock(VTresor.duressPW) }
        #expect(dv.isDuressSession)
        #expect(v.eraser.destroyed == [v.vKeyID])
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        // Was die Sitzung geschrieben hat: nur V weg und der Zustand; Tresordatei und Sicherungen unverändert.
        #expect(try v.t.f.fileBytes() == vaultBytes)
        #expect(v.t.f.backupFileNames() == backups)
        #expect(v.hardwareNames() == hw.subtracting([v.vKeyID.uuidString + ".siegelhw"]))
        let st = try #require(v.state())
        #expect(st.lastGenuineUnlock == t0)
        #expect(st.failedAttempts == 0)
        #expect(st.destroyed?.trigger == .duressPassword)
        #expect(st.destroyed?.at == t0.addingTimeInterval(2 * tag))

        // Nach aussen normal: ohne den vernichteten Eintrag, nichts deutet auf die Vernichtung hin.
        #expect(Set(dv.entries.map(\.id)) == [b.id, o.id])
        #expect(dv.destroyedEntries.isEmpty)
        #expect(dv.destructibleEntries.isEmpty)
        #expect(dv.destructionKeyID == v.vKeyID)
        #expect(dv.destructionSettings.duressEnabled)
        #expect(dv.destructionStatus.destroyedTrigger == nil && dv.destructionStatus.destroyedAt == nil)
        #expect(dv.securityReport().total == 2)
        #expect(!dv.masterPasswordReuse.contains(a.id))
        #expect(await vFehler { _ = try await v.reveal(a.id, in: dv) } == .io("entry.notFound"))
        #expect(await vFehler { try dv.delete(id: a.id) } == .io("entry.notFound"))
        #expect(await vFehler { try dv.upsert(a) } == .io("entry.stale"))
        #expect(try await v.reveal(b.id, in: dv) == EntrySecrets(b))
        #expect(try await v.reveal(o.id, in: dv) == EntrySecrets(o))
        // Passwort-Bestätigungen gelten als falsch (das Vernichtungs-Passwort ist kein Master-Passwort).
        #expect(!dv.verify(masterPassword: VTresor.duressPW, factors: try v.factors()))
        #expect(await vFehler {
            try await dv.configureDestruction(.off, duressPassword: nil, destructible: [],
                                              masterPassword: VTresor.duressPW, factors: try v.factors(), vKey: nil,
                                              entryFactors: v.provider)
        } == .wrongPassword)
        try dv.removeDestroyedEntries()
        // Bearbeiten geht und schreibt normal; der vernichtete Eintrag bleibt im Inhalt.
        let n = schutzEntry("Neu", protection: .maximal)
        try dv.upsert(n)
        #expect(dv.entries.contains { $0.id == n.id })
        #expect(v.state()?.destroyed?.trigger == .duressPassword)
        dv.lock()

        // Der Besitzer sieht beim nächsten echten Entsperren die Meldung.
        try TestHooks.$now.withValue(t0.addingTimeInterval(5 * tag)) { try v.reopen() }
        #expect(!v.vault.isDuressSession)
        #expect(v.vault.destroyedEntries == [a.id])
        #expect(v.vault.destructionStatus.destroyedTrigger == .duressPassword)
        #expect(Set(v.vault.entries.map(\.id)) == [a.id, b.id, o.id, n.id])
        #expect(try await v.reveal(n.id) == EntrySecrets(n))
        #expect(v.store.destructionStatus().lastGenuineUnlock == t0.addingTimeInterval(5 * tag))
    }

    @Test("Zeitgleichheit: mit Vernichtungs-Passwort laufen immer beide Argon2 gleichzeitig")
    func zeitgleichheit() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        v.vault.lock()
        func messen(_ pw: String) throws -> (runs: Int, arrivals: Int, missed: Int, error: SiegelError?) {
            let counter = TestHooks.Counter()
            let rv = TestHooks.Rendezvous()
            var error: SiegelError?
            try TestHooks.$kdfCounter.withValue(counter) {
                try TestHooks.$kdfRendezvous.withValue(rv) {
                    do {
                        KT.anyVault(try v.store.unlock(masterPassword: pw, factors: try v.factors())).lock()
                    } catch let e as SiegelError {
                        error = e
                    }
                }
            }
            return (counter.value, rv.arrivals, rv.missed, error)
        }
        let echt = try messen(KT.pw1)
        #expect(echt.runs == 2 && echt.arrivals == 2 && echt.missed == 0 && echt.error == nil)
        let falsch = try messen(KT.pw3)
        #expect(falsch.runs == 2 && falsch.arrivals == 2 && falsch.missed == 0 && falsch.error == .wrongPassword)
        #expect(v.eraser.destroyed.isEmpty)
        let zwang = try messen(VTresor.duressPW)
        #expect(zwang.runs == 2 && zwang.arrivals == 2 && zwang.missed == 0 && zwang.error == nil)
        #expect(v.eraser.destroyed == [v.vKeyID])

        // Ohne Vernichtungs-Passwort bleibt es bei einem Argon2.
        let w = try VTresor(.maximal)
        let wa = try w.add("Bank", .maximal)
        try await w.einrichten(DestructionSettings(deadmanDays: 30), markieren: [wa.id])
        w.vault.lock()
        let counter = TestHooks.Counter()
        try TestHooks.$kdfCounter.withValue(counter) { try w.reopen() }
        #expect(counter.value == 1)
    }

    @Test("Fehlt die Ablage: gleiche Dauer, nichts erkannt; echtes Entsperren repariert sie")
    func ablageFehlt() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        let d = try #require(v.vault.contentForTesting?.destruction?.duress)
        let url = v.store.hardwareKeyURL(d.fileID)
        v.vault.lock()
        try FileManager.default.removeItem(at: url)
        let counter = TestHooks.Counter()
        let e = await vFehler {
            try TestHooks.$kdfCounter.withValue(counter) { _ = try v.tryUnlock(VTresor.duressPW) }
        }
        #expect(e == .wrongPassword)
        #expect(counter.value == 2)
        #expect(v.eraser.destroyed.isEmpty)
        try v.reopen()
        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(try v.duressEnvelopeOpens())
        v.vault.lock()
        #expect(try v.tryUnlock(VTresor.duressPW).isDuressSession)
    }

    @Test("Der Umschlag folgt jeder DEK-Rotation (ohne Passwort) und wird bei jedem Speichern neu gekapselt")
    func umschlagFolgtRotationen() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        #expect(try v.duressEnvelopeOpens())
        #expect(!(try v.duressEnvelopeOpens(VTresor.duressPW2)))
        let d = try #require(v.vault.contentForTesting?.destruction?.duress)
        let url = v.store.hardwareKeyURL(d.fileID)

        // Speichern (gleicher DEK): frische Kapselung.
        let f0 = try Data(contentsOf: url)
        try v.add("Mail", .maximal)
        #expect(try Data(contentsOf: url) != f0)
        #expect(try v.duressEnvelopeOpens())

        // Passwortwechsel (neuer DEK).
        var dek = try v.vault.dekForTesting()
        try v.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2, factors: try v.factors())
        #expect(!(try v.vault.dekForTesting().constantTimeEquals(dek)))
        #expect(try v.duressEnvelopeOpens())

        // Neues Kit (neuer DEK, versiegelte Einträge über ihre Gruppen).
        dek = try v.vault.dekForTesting()
        let kit = try v.vault.prepareRecovery(masterPassword: KT.pw2, factors: try v.factors(), scheme: .shamir2of3)
        try await v.vault.commitRecovery(kit, confirmation: KernStufen.confirmation(kit), entryFactors: v.provider)
        #expect(!(try v.vault.dekForTesting().constantTimeEquals(dek)))
        #expect(try v.duressEnvelopeOpens())

        // Stufenwechsel 4 → 5 (neuer DEK).
        dek = try v.vault.dekForTesting()
        try v.vault.changeSecurityLevel(to: .festung, masterPassword: KT.pw2, currentFactors: try v.t.k.secrets(.all),
                                        newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        #expect(!(try v.vault.dekForTesting().constantTimeEquals(dek)))
        #expect(try v.duressEnvelopeOpens())

        // Sicherung einsetzen (neuer DEK, Stand der Sicherung: Stufe 4).
        let backup = try #require(v.t.f.localBackups().first)
        let level4 = try v.t.k.secrets([.secureEnclave, .card])
        v.vault.lock()
        v.vault = try v.store.restoreBackup(backup, masterPassword: KT.pw2, factors: level4)
        #expect(try v.duressEnvelopeOpens())

        // Am Ende das echte Vernichtungs-Passwort.
        v.vault.lock()
        let dv = try v.tryUnlock(VTresor.duressPW)
        #expect(dv.isDuressSession)
        #expect(!dv.entries.contains { $0.id == a.id })
    }

    @Test("Vernichtungs-Passwort ändern und entfernen")
    func aendernUndEntfernen() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        let alt = try #require(v.vault.contentForTesting?.destruction?.duress?.fileID)
        let kopieAlt = Array(try Data(contentsOf: v.store.hardwareKeyURL(alt)))
        var dek = try v.vault.dekForTesting()
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW2, markieren: [a.id])
        let neu = try #require(v.vault.contentForTesting?.destruction?.duress?.fileID)
        #expect(alt != neu)
        #expect(!FileManager.default.fileExists(atPath: v.store.hardwareKeyURL(alt).path))
        #expect(try v.duressEnvelopeOpens(VTresor.duressPW2))
        #expect(!(try v.duressEnvelopeOpens(VTresor.duressPW)))
        // Ersetzen ist ein Zugangswechsel (v4.4): neuer DEK. Gegenprobe: alte Ablage + altes Vernichtungs-Passwort
        // (sogar mit allen Faktoren) öffnen die neue Datei nicht.
        #expect(!(try v.vault.dekForTesting().constantTimeEquals(dek)))
        let nachErsetzen = try v.offlineDuress(kopieAlt, fileID: alt, vaultFile: try v.t.f.fileBytes(),
                                               factors: try v.factors())
        #expect(nachErsetzen.recognized && nachErsetzen.content == nil)
        // Nur Einstellungen ändern behält das Passwort (und den DEK).
        dek = try v.vault.dekForTesting()
        try await v.einrichten(DestructionSettings(deadmanDays: 30, duressEnabled: true), markieren: [a.id])
        #expect(v.vault.contentForTesting?.destruction?.duress?.fileID == neu)
        #expect(try v.vault.dekForTesting().constantTimeEquals(dek))
        // Entfernen: Ablage weg, neuer DEK, das alte Vernichtungs-Passwort ist nur noch ein falsches Passwort.
        let kopieNeu = Array(try Data(contentsOf: v.store.hardwareKeyURL(neu)))
        try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [a.id])
        #expect(!FileManager.default.fileExists(atPath: v.store.hardwareKeyURL(neu).path))
        #expect(!(try v.vault.dekForTesting().constantTimeEquals(dek)))
        let nachEntfernen = try v.offlineDuress(kopieNeu, fileID: neu, password: VTresor.duressPW2,
                                                vaultFile: try v.t.f.fileBytes(), factors: try v.factors())
        #expect(nachEntfernen.recognized && nachEntfernen.content == nil)
        v.vault.lock()
        #expect(await vFehler { _ = try v.tryUnlock(VTresor.duressPW2) } == .wrongPassword)
        #expect(v.eraser.destroyed.isEmpty)
    }
}

@Suite("Selbstvernichtung: unlesbar nach der Vernichtung (§23.1)")
struct KernVernichtungUnlesbarTests {
    /// Tresor mit einem vernichtbaren (a) und einem nicht vernichtbaren Eintrag (b), mehreren Sicherungen; danach
    /// über den Fehlversuch-Zähler vernichtet.
    static func vernichtet() async throws -> (VTresor, VaultEntry, VaultEntry) {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .maximal)
        try await v.einrichten(DestructionSettings(maxFailedAttempts: 10), markieren: [a.id])
        try v.add("Shop", .fingerabdruck)
        try v.add("Velo", .maximal)
        v.vault.lock()
        for _ in 1...10 { _ = try? v.store.unlock(masterPassword: KT.pw2, factors: try v.factors()) }
        #expect(v.eraser.destroyed == [v.vKeyID])
        return (v, a, b)
    }

    @Test("Aus jeder Sicherung unlesbar, auch kryptografisch (mit allen übrigen Faktoren und dem DEK)")
    func ausSicherungen() async throws {
        let (v, a, b) = try await Self.vernichtet()
        let backups = v.t.f.localBackups()
        #expect(backups.count >= 2)
        for backup in backups {
            let c = try v.t.f.openFile(backup.url, factors: try v.factors())
            #expect(c.sealed[a.id] == nil)
            let blob = try #require(c.destructible[a.id])
            // Ohne V: mit einem anderen P-256-Schlüssel (alles andere echt) entsteht ein falsches K.
            let fremd = VernichtungsProvider(v.t.p, hardware: v.hardware, vKeyID: v.vKeyID)
            try P256.KeyAgreement.PrivateKey().rawRepresentation.write(to: v.vURL)
            defer { try? FileManager.default.removeItem(at: v.vURL) }
            let keys = try c.sealingKeys(vaultID: VaultHeader.bytes(of: v.vault.vaultID))
            let v0 = try #require(c.destruction?.vKey)
            let released = try await EntrySealing.release(blob.factors, id: a.id, mask: EntryProtection.maximal.factors,
                                                          keys: keys.factors, vaultID: keys.vaultID, provider: fremd,
                                                          se: .destruction(keyID: v0.keyID, publicKey: v0.publicKey))
            let opened = try EntrySealing.open(blob, id: a.id, s: UInt8(EntryProtection.maximal.rawValue),
                                               mask: EntryProtection.maximal.factors,
                                               adLabel: EntrySealing.destructibleAD, base: keys.base,
                                               vaultID: keys.vaultID, released: released,
                                               keyInfo: EntrySealing.destructibleKeyInfo)
            #expect(opened == nil)
        }
        // Eine ältere Sicherung einsetzen: a bleibt vernichtet, b lesbar.
        let oldest = try #require(backups.last)
        v.vault = try v.store.restoreBackup(oldest, masterPassword: KT.pw1, factors: try v.factors())
        #expect(v.vault.destroyedEntries == [a.id])
        #expect(await vFehler { _ = try await v.reveal(a.id) } == .factorUnavailable(.secureEnclave))
        #expect(try await v.reveal(b.id) == EntrySecrets(b))
    }

    @Test("Über den Notfallcode: vernichtbare Einträge fallen weg, die übrigen kommen zurück")
    func notfallcode() async throws {
        let (v, a, b) = try await Self.vernichtet()
        let kit = try #require(v.t.kit)
        let shares = [kit.shares[1].formatted, kit.shares[2].formatted]
        let r = try v.store.recover(shares: shares, newMasterPassword: KT.pw3, kdf: KT.kdf)
        #expect(!r.entries.contains { $0.id == a.id })
        #expect(r.entries.first { $0.id == b.id }?.password == b.password)
        #expect(r.level == .standard)
        #expect(r.destructionSettings == .off)
        #expect(r.destroyedEntries.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: v.stateURL.path))
        // Auch der Notfallweg über die Sicherungen (beschädigte Tresordatei) bringt a nicht zurück.
        r.lock()
        var bytes = try v.t.f.fileBytes()
        bytes[bytes.count / 2] ^= 0x01
        try v.t.f.writeFile(bytes)
        let (r2, _) = try v.store.recoverFromNewestReadableBackup(shares: shares, newMasterPassword: KT.pw4, kdf: KT.kdf)
        #expect(!r2.entries.contains { $0.id == a.id })
        #expect(r2.entries.contains { $0.id == b.id })
    }

    @Test("Kein Notfallweg schon vor der Vernichtung (so beim Markieren angekündigt)")
    func keinNotfallweg() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .maximal)
        try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [a.id])
        v.vault.lock()
        let kit = try #require(v.t.kit)
        let r = try v.store.recover(shares: [kit.shares[0].formatted, kit.shares[1].formatted], newMasterPassword: KT.pw2,
                                    kdf: KT.kdf)
        #expect(!r.entries.contains { $0.id == a.id })
        #expect(r.entries.first { $0.id == b.id }?.notes == b.notes)
        #expect(v.eraser.destroyed.isEmpty)
    }
}

@Suite("Selbstvernichtung: Zustand, Ablage und Konsistenz")
struct KernVernichtungFormatTests {
    @Test("Ohne Selbstvernichtung entsteht keine Datei; der Inhalt bleibt ohne Schlüssel \"destruction\"")
    func ohne() async throws {
        let v = try VTresor(.maximal)
        try v.add("Bank", .maximal)
        try v.reopen()
        #expect(!FileManager.default.fileExists(atPath: v.stateURL.path))
        #expect(v.hardwareNames() == [v.vKeyID.uuidString + ".siegelhw"])
        #expect(!(try v.t.jsonOnDisk(v.vault)).contains("destruction"))
        #expect(v.store.destructionStatus() == .off)
        #expect(v.vault.destructionStatus == .off)
    }

    @Test("Ablage des Vernichtungs-Passworts: Form wie die SE-Schlüsseldateien, feste Grösse, vom Backup ausgenommen")
    func ablage() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(deadmanDays: 30, duressEnabled: true), duress: VTresor.duressPW,
                               markieren: [a.id])
        let d = try #require(v.vault.contentForTesting?.destruction?.duress)
        let url = v.store.hardwareKeyURL(d.fileID)
        let bytes = Array(try Data(contentsOf: url))
        #expect(bytes.count == 2048)
        #expect(Array(bytes[0..<8]) == Array("SIEGELHW".utf8))
        #expect(bytes[8] == 1 && bytes[9] == 0 && bytes[10] == 2)
        #expect(Array(bytes[11..<27]) == VaultHeader.bytes(of: d.fileID))
        #expect(Int(bytes[27]) | Int(bytes[28]) << 8 == DuressFile.blobLength)
        #expect(DuressFile.checksum(Array(bytes[0..<2016])) == Array(bytes[2016...]))
        #expect((try? P256.KeyAgreement.PublicKey(x963Representation: bytes[(2016 - 65)..<2016])) != nil)
        // Strenger Leser: falsche Kennung, Bitfehler, Länge.
        #expect(throws: SiegelError.corruptFile("duress.id")) { try DuressFile.decode(bytes, expectedID: UUID()) }
        var kaputt = bytes
        kaputt[100] ^= 1
        #expect(throws: SiegelError.corruptFile("duress.checksum")) { try DuressFile.decode(kaputt, expectedID: d.fileID) }
        #expect(throws: SiegelError.corruptFile("duress.length")) {
            try DuressFile.decode(Array(bytes.dropLast()), expectedID: d.fileID)
        }
        for u in [url, v.stateURL, v.vURL] {
            #expect(try u.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
        }
        let st = try #require(v.state())
        #expect(st.duressFileID == d.fileID && st.vKeyID == v.vKeyID && st.vaultID == v.vault.vaultID)
        let json = try String(contentsOf: v.stateURL, encoding: .utf8)
        #expect(json.contains("\"settings\":{\"deadmanDays\":30,\"duressEnabled\":true,\"maxFailedAttempts\":null}"))
        #expect(json.contains("\"destroyed\":null"))
        #expect(json.contains("\"v\":1"))
    }

    @Test("zustand.json wird streng gelesen; fremder Tresor gilt nicht")
    func zustandStreng() throws {
        var s = DestructionState(vaultID: UUID())
        s.settings = DestructionSettings(deadmanDays: 30, maxFailedAttempts: 10, duressEnabled: true)
        s.vKeyID = UUID()
        s.duressFileID = UUID()
        s.failedAttempts = 3
        s.lastGenuineUnlock = Date(timeIntervalSince1970: 1_800_000_000)
        s.destroyed = .init(keyID: UUID(), trigger: .duressPassword, at: Date(timeIntervalSince1970: 1_800_000_100))
        #expect(try DestructionState.decode(try s.encoded()) == s)
        func variante(_ change: (inout [String: Any]) -> Void) throws -> [UInt8] {
            var obj = try #require(try JSONSerialization.jsonObject(with: Data(try s.encoded())) as? [String: Any])
            change(&obj)
            return Array(try JSONSerialization.data(withJSONObject: obj))
        }
        for bad in [try variante { $0["v"] = 2 }, try variante { $0["failedAttempts"] = -1 },
                    try variante { $0["duressFileID"] = NSNull() },
                    try variante { $0["settings"] = ["deadmanDays": 3, "duressEnabled": false] }, [0x7b]] {
            #expect(throws: SiegelError.corruptFile("destruction.state")) { try DestructionState.decode(bad) }
        }
    }

    @Test("Fremder Zustand (andere vaultID) gilt nicht")
    func fremderZustand() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(maxFailedAttempts: 10), markieren: [a.id])
        var st = try #require(v.state())
        st.vaultID = UUID()
        try DestructionState.write(st, in: v.hardware)
        #expect(v.store.destructionStatus() == .off)
        v.vault.lock()
        for _ in 1...12 { _ = try? v.store.unlock(masterPassword: KT.pw2, factors: try v.factors()) }
        #expect(v.eraser.destroyed.isEmpty)
        // Das echte Entsperren stellt den Zustand aus dem Inhalt wieder her.
        try v.reopen()
        #expect(v.state()?.vaultID == v.vault.vaultID)
        #expect(v.store.destructionStatus().settings.maxFailedAttempts == 10)
    }

    @Test("Konsistenzregeln im Inhalt (lesen → corruptFile, schreiben → crypto) und JSON-Rundlauf")
    func konsistenz() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try v.add("Mail", .maximal)
        try await v.einrichten(DestructionSettings(deadmanDays: 30, duressEnabled: true), duress: VTresor.duressPW,
                               markieren: [a.id])
        let c = try #require(v.vault.contentForTesting)
        let wrap = try #require(c.sealed.values.first?.recovery)
        try c.checkSealing { SiegelError.corruptFile($0) }
        let (padded, _) = try PayloadCodec.encode(c)
        let back = try PayloadCodec.decode(padded).content
        #expect(back.destructible == c.destructible && back.destruction == c.destruction && back.sealed == c.sealed)

        func abgelehnt(_ change: (inout VaultContent) -> Void) -> Bool {
            var x = c
            change(&x)
            return (try? x.checkSealing { SiegelError.corruptFile($0) }) == nil
        }
        #expect(abgelehnt { $0.level = .hoch })
        #expect(abgelehnt { $0.destruction?.vKey = nil })
        #expect(abgelehnt { $0.destruction = nil })
        #expect(abgelehnt { $0.destruction?.duress = nil })
        #expect(abgelehnt { $0.destruction?.settings.deadmanDays = 400 })
        #expect(abgelehnt { x in
            if let i = x.entries.firstIndex(where: { $0.id == a.id }) { x.entries[i].protection = .fingerabdruck }
        })
        #expect(abgelehnt { x in
            if let blob = x.destructible[a.id] { x.sealed[a.id] = SealedSecrets(blob: blob, recovery: wrap) }
        })
        #expect(abgelehnt { $0.destruction?.vKey?.keyID = v.t.p.entryKeyID })
        #expect(abgelehnt { $0.destructible[a.id]?.factors.seEphemeral = nil })
        // Schreiben eines kaputten Inhalts ist ein Programmfehler.
        var x = c
        x.level = .hoch
        #expect(throws: SiegelError.crypto("payload.destruction")) { _ = try PayloadCodec.encode(x) }
    }
}
