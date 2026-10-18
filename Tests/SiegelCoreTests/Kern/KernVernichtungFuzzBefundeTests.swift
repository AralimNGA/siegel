import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

// Regressionstests zu den Funden des Fuzz-Ziels „vernichtung“ (SiegelFuzz, Sources/SiegelFuzz/ZielVernichtung.swift).
// `Hardware/zustand.json` ist nicht authentisiert; der Kern nimmt ihn im gesperrten Zustand so, wie er ist
// (dokumentiert in KERN-NOTIZEN.md und SICHERHEIT.md). Er darf dabei aber nie selbst aussperren und nie eine Datei
// löschen, die der Tresor nachweislich noch braucht.

private let tag: TimeInterval = 86_400

/// Platzhalter-Dateien für SE-Schlüssel, deren Blob im Test nicht als Datei liegt (Entsperr- und Eintrags-Schlüssel).
private func platzhalter(_ v: VTresor, _ id: UUID) throws -> URL {
    let url = v.hardware.appendingPathComponent(id.uuidString + ".siegelhw")
    try Data(repeating: 0x41, count: 32).write(to: url)
    return url
}

private func zustandAendern(_ v: VTresor, _ change: (inout DestructionState) -> Void) throws {
    var st = try #require(v.state())
    change(&st)
    try DestructionState.write(st, in: v.hardware)
}

@Suite("Fuzz-Befunde: Selbstvernichtung")
struct KernVernichtungFuzzBefundeTests {
    @Test("Befund vernichtung-1: Ein Zustand, der den Entsperr-SE-Schlüssel nennt, gilt nicht (sonst Aussperrung)")
    func entsperrSchluesselNieVernichten() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(deadmanDays: 7, maxFailedAttempts: 10), markieren: [a.id])
        let se = try #require(v.vault.headerForTesting?.factorFields.seKeyID)
        let seDatei = try platzhalter(v, se)
        v.vault.lock()

        // Zähler kurz vor der Schwelle, V = Entsperr-Schlüssel: ein falsches Passwort darf ihn nicht löschen.
        try zustandAendern(v) {
            $0.vKeyID = se
            $0.failedAttempts = 9
        }
        #expect(v.store.destructionStatus() == .off)
        #expect(await vFehler { _ = try v.tryUnlock(KT.pw2) } == .wrongPassword)
        #expect(FileManager.default.fileExists(atPath: seDatei.path))
        #expect(!v.eraser.destroyed.contains(se))

        // Abgelaufene Frist bzw. ein Vermerk, der ihn als vernichtet nennt: ebenso nichts.
        try zustandAendern(v) {
            $0.vKeyID = se
            $0.lastGenuineUnlock = Date(timeIntervalSince1970: 1_700_000_000)
        }
        #expect(try v.store.checkDeadman(now: Date(timeIntervalSince1970: 1_800_000_000)) == false)
        try zustandAendern(v) {
            $0.vKeyID = v.vKeyID
            $0.destroyed = .init(keyID: se, trigger: .deadman, at: Date(timeIntervalSince1970: 1_700_000_000))
        }
        #expect(try v.store.checkDeadman(now: Date(timeIntervalSince1970: 1_800_000_000)) == false)
        #expect(FileManager.default.fileExists(atPath: seDatei.path))
        #expect(FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(v.eraser.destroyed.isEmpty)

        // Das echte Entsperren stellt den Zustand aus dem Inhalt wieder her; der Eintrag ist lesbar.
        try v.reopen()
        #expect(v.state()?.vKeyID == v.vKeyID)
        #expect(v.state()?.destroyed == nil)
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
    }

    @Test("Befund vernichtung-2: Echtes Entsperren löscht als „alte Ablage“ nie einen Schlüssel, den der Tresor braucht")
    func alteAblageNieInGebrauch() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .maximal)
        let o = try v.add("Notiz", .fingerabdruck)
        try await v.einrichten(DestructionSettings(deadmanDays: 30, duressEnabled: true), duress: VTresor.duressPW,
                             markieren: [a.id])
        let header = try #require(v.vault.headerForTesting)
        let se = try #require(header.factorFields.seKeyID)
        let eintrag = v.t.p.entryKeyID
        let seDatei = try platzhalter(v, se)
        let eintragDatei = try platzhalter(v, eintrag)
        let ablage = try #require(v.vault.contentForTesting?.destruction?.duress?.fileID)

        for genannt in [eintrag, v.vKeyID, se] {
            try zustandAendern(v) {
                $0.settings = DestructionSettings(duressEnabled: true)
                $0.duressFileID = genannt
            }
            try v.reopen()
            #expect(FileManager.default.fileExists(atPath: eintragDatei.path))
            #expect(FileManager.default.fileExists(atPath: seDatei.path))
            #expect(FileManager.default.fileExists(atPath: v.vURL.path))
            #expect(v.state()?.duressFileID == ablage)
            #expect(v.vault.destroyedEntries.isEmpty)
            #expect(try await v.reveal(a.id) == EntrySecrets(a))
            #expect(try await v.reveal(b.id) == EntrySecrets(b))
            #expect(try await v.reveal(o.id) == EntrySecrets(o))
        }
        // Auch nach einem Speichern (syncDestructionAfterWrite) und aus einem fremden Zustand (andere vaultID).
        try zustandAendern(v) {
            $0.vaultID = UUID()
            $0.duressFileID = v.vKeyID
        }
        try v.vault.upsert(schutzEntry("Neu", protection: .maximal))
        #expect(FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(v.state()?.vaultID == v.vault.vaultID)
        #expect(try await v.reveal(a.id) == EntrySecrets(a))

        // Eine wirklich veraltete Ablage (nicht in Gebrauch) wird weiter entfernt – nur, wenn die Datei eine Ablage mit
        // dieser Kennung ist (Befund vernichtung-7); eine andere Datei unter diesem Namen bleibt.
        let alt = UUID()
        let altDatei = try platzhalter(v, alt)
        try zustandAendern(v) { $0.duressFileID = alt }
        try v.reopen()
        #expect(FileManager.default.fileExists(atPath: altDatei.path))
        let f = try #require(v.store.readDuressFile(ablage))
        try Data(try DuressFile(fileID: alt, salt: f.salt, check: f.check, capsule: f.capsule, wrapped: f.wrapped).encoded())
            .write(to: altDatei)
        try zustandAendern(v) { $0.duressFileID = alt }
        try v.reopen()
        #expect(!FileManager.default.fileExists(atPath: altDatei.path))
    }

    @Test("Befund vernichtung-3: checkDeadman mit unbrauchbarer Uhr (±∞, NaN) vernichtet nicht und schreibt nichts")
    func uhrUnbrauchbar() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await TestHooks.$now.withValue(t0) {
            try await v.einrichten(DestructionSettings(deadmanDays: 7), markieren: [a.id])
        }
        v.vault.lock()
        let vorher = try Data(contentsOf: v.stateURL)
        for x in [Double.infinity, -.infinity, .nan] {
            #expect(try v.store.checkDeadman(now: Date(timeIntervalSince1970: x)) == false)
        }
        #expect(FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(v.eraser.destroyed.isEmpty)
        #expect(try Data(contentsOf: v.stateURL) == vorher)
        // Endliche Zeit nach Ablauf der Frist vernichtet wie immer (auch weit in der Zukunft).
        #expect(try v.store.checkDeadman(now: Date(timeIntervalSince1970: 1e300)) == true)
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(v.store.destructionStatus().destroyedAt == Date(timeIntervalSince1970: 1e300))
    }

    @Test("Befund vernichtung-4: zustand.json zwischen Probe und Vermerk getauscht – nennt er den Entsperr-SE-Schlüssel, wird nichts gelöscht")
    func wettlaufProbeUndVermerk() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        let se = try #require(v.vault.headerForTesting?.factorFields.seKeyID)
        let seDatei = try platzhalter(v, se)
        v.vault.lock()
        // Der Haken läuft nach beiden Argon2 (Vernichtungs-Passwort erkannt) und vor dem Vermerk.
        let hw = v.hardware
        let haken = TestHooks.Hook {
            guard var st = DestructionState.read(in: hw) else { return }
            st.vKeyID = se
            try? DestructionState.write(st, in: hw)
        }
        let dv = try TestHooks.$afterDuressArgon.withValue(haken) { try v.tryUnlock(VTresor.duressPW) }
        dv.lock()
        #expect(FileManager.default.fileExists(atPath: seDatei.path))
        #expect(!v.eraser.destroyed.contains(se))
        #expect(v.eraser.destroyed.isEmpty)
        // Der getauschte Zustand gilt nicht; das echte Entsperren stellt ihn aus dem Inhalt wieder her.
        #expect(v.store.destructionStatus() == .off)
        try v.reopen()
        #expect(v.state()?.vKeyID == v.vKeyID)
        #expect(FileManager.default.fileExists(atPath: seDatei.path))
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
    }

    @Test("Befund vernichtung-5: Hardware-Ordner nicht beschreibbar – checkDeadman meldet io(destruction.write), die nächste Prüfung holt es nach")
    func hardwareOrdnerNichtBeschreibbar() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await TestHooks.$now.withValue(t0) {
            try await v.einrichten(DestructionSettings(deadmanDays: 7), markieren: [a.id])
        }
        v.vault.lock()
        let vorher = try Data(contentsOf: v.vURL)
        let zustand = try Data(contentsOf: v.stateURL)
        // uchg: nichts anlegen, umbenennen oder löschen (Inhalte bestehender Dateien lassen sich überschreiben).
        #expect(chflags(v.hardware.path, UInt32(UF_IMMUTABLE)) == 0)
        defer { _ = chflags(v.hardware.path, 0) }
        #expect(await vFehler { _ = try v.store.checkDeadman(now: t0.addingTimeInterval(8 * tag)) } == .io("destruction.write"))
        // V ist überschrieben (unbrauchbar), aber noch da; ohne Vermerk wiederholt die nächste Prüfung das Vernichten.
        #expect(try Data(contentsOf: v.vURL) != vorher)
        #expect(try Data(contentsOf: v.stateURL) == zustand)
        _ = chflags(v.hardware.path, 0)
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(9 * tag)) == true)
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(v.store.destructionStatus().destroyedTrigger == .deadman)
    }

    @Test("Tiefenverteidigung: Ablage-Kennung und V heissen nie wie ein anderer SE-Schlüssel des Tresors")
    func schluesselKennungenVerschieden() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        let c = try #require(v.vault.contentForTesting)
        let s = try v.vault.snapshot()
        let se = try #require(s.header.factorFields.seKeyID)
        let eintrag = try #require(c.entryFactors.secureEnclave?.keyID)
        let ablage = try #require(c.destruction?.duress?.fileID)
        // Lesen: Ablage-Kennung = V bzw. Eintrags-SE-Schlüssel → verworfen (sonst überschriebe das Kapseln sie).
        let text = try #require(PayloadCodec.jsonStringForTesting(try PayloadCodec.encode(c).padded))
        for id in [v.vKeyID, eintrag] {
            let boese = text.replacingOccurrences(of: ablage.uuidString, with: id.uuidString)
            #expect(throws: SiegelError.corruptFile("payload.destruction")) {
                _ = try PayloadCodec.decode(try KernBerichtTests.padded(boese))
            }
        }
        // Schreiben: dasselbe ist ein Programmfehler.
        var x = c
        x.destruction?.duress?.fileID = v.vKeyID
        #expect(throws: SiegelError.crypto("payload.destruction")) { _ = try PayloadCodec.encode(x) }
        // V bzw. Ablage = Entsperr-SE-Schlüssel des Kopfes: Lesen (decryptPayload) und Schreiben (persist) lehnen ab.
        for setze in [{ (y: inout VaultContent) in y.destruction?.vKey?.keyID = se },
                      { (y: inout VaultContent) in y.destruction?.duress?.fileID = se }] {
            var y = c
            setze(&y)
            let gebaut = try VaultCrypto.buildFile(header: s.header, slots: s.slots, generation: s.generation + 1,
                                                   dek: s.dek, content: y)
            #expect(throws: SiegelError.corruptFile("payload.destruction")) {
                _ = try VaultCrypto.decryptPayload(try VaultFile.parse(gebaut.bytes), dek: s.dek)
            }
            #expect(throws: SiegelError.crypto("payload.destruction")) {
                _ = try v.store.persist(header: s.header, slots: s.slots, dek: s.dek, content: y,
                                        baseGeneration: s.generation, expectation: .generation(s.header.uuid, s.generation),
                                        reason: nil, duressBinding: s.duressBinding)
            }
        }
        // Nichts davon wurde geschrieben: der Tresor öffnet wie zuvor, der Eintrag ist lesbar.
        try v.reopen()
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
    }

    @Test("Befund vernichtung-6: Ohne lesbare Tresordatei gilt kein Zustand, der den Entsperr-SE-Schlüssel einer Sicherung nennt")
    func ohneTresordateiNieAussperren() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await TestHooks.$now.withValue(t0) {
            try await v.einrichten(DestructionSettings(deadmanDays: 7, maxFailedAttempts: 10), markieren: [a.id])
        }
        let se = try #require(v.vault.headerForTesting?.factorFields.seKeyID)
        let seDatei = try platzhalter(v, se)
        v.vault.lock()
        #expect(!v.store.backups().isEmpty)
        // Die Tresordatei fehlt (z. B. beschädigt beiseitegelegt); der Zustand nennt den Entsperr-SE-Schlüssel als V.
        let tresor = try Data(contentsOf: v.store.vaultURL)
        try FileManager.default.removeItem(at: v.store.vaultURL)
        try zustandAendern(v) {
            $0.vKeyID = se
            $0.failedAttempts = 9
        }
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(8 * tag)) == false)
        #expect(await vFehler {
            _ = try v.store.restoreNewestReadableBackup(masterPassword: KT.pw2, factors: try v.factors())
        } == .wrongPassword)
        #expect(FileManager.default.fileExists(atPath: seDatei.path))
        #expect(v.eraser.destroyed.isEmpty)
        #expect(v.store.destructionStatus() == .off)
        // Nennt er V, gilt er ohne Tresordatei weiter (Totmann-Schalter wie bisher).
        try zustandAendern(v) { $0.vKeyID = v.vKeyID }
        #expect(try v.store.checkDeadman(now: t0.addingTimeInterval(8 * tag)) == true)
        #expect(!FileManager.default.fileExists(atPath: v.vURL.path))
        #expect(FileManager.default.fileExists(atPath: seDatei.path))
        try tresor.write(to: v.store.vaultURL)
        try v.reopen()
        #expect(v.vault.destroyedEntries == [a.id])
    }

    @Test("Befund vernichtung-7: Der Notfallweg löscht als „alte Ablage“ nur eine Ablage, nie einen SE-Schlüssel")
    func notfallwegLoeschtNurAblagen() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let b = try v.add("Mail", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        let se = try #require(v.vault.headerForTesting?.factorFields.seKeyID)
        let seDatei = try platzhalter(v, se)
        let eintragDatei = try platzhalter(v, v.t.p.entryKeyID)
        v.vault.lock()
        let kit = try #require(v.t.kit)
        for genannt in [se, v.t.p.entryKeyID, v.vKeyID] {
            // Der Zustand nennt den Schlüssel als Ablage; danach der Notfallweg (neuer Kopf ohne Faktoren).
            try zustandAendern(v) {
                $0.settings = DestructionSettings(duressEnabled: true)
                $0.duressFileID = genannt
            }
            let r = try v.store.recover(shares: [kit.shares[0].formatted, kit.shares[2].formatted],
                                        newMasterPassword: KT.pw2, kdf: KT.kdf)
            #expect(r.entries.contains { $0.id == b.id })
            r.lock()
            #expect(FileManager.default.fileExists(atPath: seDatei.path))
            #expect(FileManager.default.fileExists(atPath: eintragDatei.path))
            #expect(FileManager.default.fileExists(atPath: v.vURL.path))
            // Ältere Sicherungen (Stufe 4) öffnen weiter mit Passwort und Faktoren, auch die Einträge.
            let alt = try #require(v.store.backups().first { VaultStore.readHeader($0.url)?.factorFields.seKeyID == se })
            let c = try v.t.f.openFile(alt.url, factors: try v.t.k.secrets([.secureEnclave, .card]))
            #expect(c.entries.contains { $0.id == b.id })
            // Für die nächste Runde: Zustand wie vor dem Notfallweg (gültig, mit Ablage).
            let st = DestructionState(vaultID: v.vault.vaultID)
            try DestructionState.write(st, in: v.hardware)
        }
    }

    @Test("Befund vernichtung-8: Das Kapseln der Ablage ersetzt nur eine Ablage, nie einen Schlüssel unter diesem Namen")
    func ablageUeberschreibtKeinenSchluessel() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [a.id])
        let c = try #require(v.vault.contentForTesting)
        let s = try v.vault.snapshot()
        let binding = try #require(s.duressBinding)
        let ablage = try #require(c.destruction?.duress)
        // Kennung, unter der ein Schlüssel liegt (hier V, 32 B roh; ebenso ein SE-Schlüssel mit anderer Bloblänge).
        var d = ablage
        d.fileID = v.vKeyID
        let vorher = try Data(contentsOf: v.vURL)
        #expect(throws: SiegelError.io("destruction.write")) {
            try v.store.writeDuressFile(d, dek: s.dek, binding: binding, vaultID: s.header.vaultID)
        }
        #expect(try Data(contentsOf: v.vURL) == vorher)
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
        // Eine beschädigte Ablage (Form intakt) heilt beim nächsten echten Entsperren.
        let url = v.store.hardwareKeyURL(ablage.fileID)
        var b = Array(try Data(contentsOf: url))
        b[100] ^= 0x01
        try Data(b).write(to: url)
        #expect(v.store.readDuressFile(ablage.fileID) == nil)
        try v.reopen()
        #expect(v.store.readDuressFile(ablage.fileID) != nil)
        #expect(try v.duressEnvelopeOpens())
    }
}
