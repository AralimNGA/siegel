import Foundation
import Testing
@testable import SiegelCore

// Regressionstests zu den Krypto-Befunden der zweiten Prüfung (SPEC v4.4):
// krypto-1  Umschlag des Vernichtungs-Passworts an die Faktoren gebunden
// krypto-2  DEK-Rotation nach einer Vernichtungs-Sitzung und beim Ersetzen/Entfernen des Vernichtungs-Passworts
// krypto-3  reuseTag nach derselben Abbildung wie das Master-Passwort (§1.1)

/// Umschlag nach der Formel bis v4.3 (ohne F) – so lag die Ablage vor v4.4 im Container.
private func ungebundeneAblage(_ d: DestructionConfig.Duress, dek: SecureBytes, vaultID: [UInt8]) throws -> [UInt8] {
    let enc = try RecoveryKEM.encapsulate(to: d.pk, label: DuressCrypto.label, context: VaultHeader.bytes(of: d.fileID))
    let wrapped = try AEAD.wrap(kek: enc.kek, secret: dek,
                                ad: DuressCrypto.wrapAD(vaultID: vaultID, fileID: d.fileID, salt: d.salt))
    return try DuressFile(fileID: d.fileID, salt: d.salt, check: d.check, capsule: HybridCapsule(enc),
                          wrapped: wrapped).encoded()
}

private func zufallsFaktor() throws -> FactorSecret { try FactorSecret(copying: randomBytes(32)) }

/// Eintrag mit Schutz 1 in Stufe 4/5 (dort bekommen neue Einträge mindestens Schutz 2).
@discardableResult
private func offenerEintrag(_ v: VTresor, _ title: String, password: String) throws -> VaultEntry {
    let e = schutzEntry(title, protection: .normal, password: password)
    try v.vault.upsert(e)
    try v.vault.setProtection(.normal, id: e.id, secrets: EntrySecrets(e))
    return e
}

@Suite("Krypto-Befunde: Vernichtungs-Passwort an Faktoren gebunden (krypto-1)")
struct KernDuressBindungTests {
    @Test("Stufe 5: Ablage + Vernichtungs-Passwort ohne Faktoren ergeben nur «erkannt», keinen DEK")
    func ohneFaktorenKeinDEK() async throws {
        let v = try VTresor(.festung)
        let geheim = "Schutz1-" + hexString(randomBytes(6))
        let offen = try offenerEintrag(v, "Offen", password: geheim)
        let zwei = try v.add("Zwei", .fingerabdruck)
        let bank = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [bank.id])
        let fileID = try #require(v.state()?.duressFileID)
        v.vault.lock()
        let ablage = Array(try Data(contentsOf: v.store.hardwareKeyURL(fileID)))
        let datei = try v.t.f.fileBytes()
        #expect(try VaultFile.parse(datei).header.factors == .all)

        // Angreifer mit Container-Kopie und Vernichtungs-Passwort, ohne Finger, Karte und Schlüssel.
        let ohne = try v.offlineDuress(ablage, fileID: fileID, vaultFile: datei, factors: nil)
        #expect(ohne.recognized && ohne.content == nil)
        // Karte gesehen (q bekannt), Secure Enclave und Sicherheitsschlüssel geraten.
        let geraten = FactorSecrets(secureEnclave: try zufallsFaktor(), card: v.t.k.q, securityKey: try zufallsFaktor())
        let mitKarte = try v.offlineDuress(ablage, fileID: fileID, vaultFile: datei, factors: geraten)
        #expect(mitKarte.recognized && mitKarte.content == nil)
        // Nur der Sicherheitsschlüssel falsch: auch nichts.
        let echt = try v.factors()
        let fastAlle = FactorSecrets(secureEnclave: echt.secureEnclave, card: echt.card, securityKey: try zufallsFaktor())
        #expect(try v.offlineDuress(ablage, fileID: fileID, vaultFile: datei, factors: fastAlle).content == nil)
        // Gegenprobe: mit allen Faktoren öffnet der Umschlag – genau das, was die Vernichtungs-Sitzung sieht.
        let alle = try #require(try v.offlineDuress(ablage, fileID: fileID, vaultFile: datei,
                                                    factors: try v.factors()).content)
        #expect(alle.entries.first { $0.id == offen.id }?.password == geheim)
        #expect(alle.entries.first { $0.id == zwei.id }?.secretsSealed == true)
        // Ein anderes Passwort wird gar nicht erkannt.
        #expect(!(try v.offlineDuress(ablage, fileID: fileID, password: KT.pw3, vaultFile: datei,
                                      factors: try v.factors()).recognized))
        // Das Offline-Raten vernichtet nichts.
        #expect(FileManager.default.fileExists(atPath: v.vURL.path))
    }

    @Test("Entsperren: Vernichtungs-Passwort mit falschem Faktor vernichtet (Prüfwert nur aus d), öffnet aber nicht")
    func falscherFaktorVernichtetOhneSitzung() async throws {
        let v = try VTresor(.festung)
        let bank = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [bank.id])
        v.vault.lock()
        let richtig = try v.factors()
        let falsch = FactorSecrets(secureEnclave: richtig.secureEnclave, card: richtig.card,
                                   securityKey: try zufallsFaktor())
        #expect(await vFehler { _ = try v.store.unlock(masterPassword: VTresor.duressPW, factors: falsch) }
            == .wrongPassword)
        #expect(v.eraser.destroyed == [v.vKeyID])
        #expect(v.store.destructionStatus().failedAttempts == 0)
        // Mit den richtigen Faktoren: Vernichtungs-Sitzung wie gewohnt.
        let dv = try v.tryUnlock(VTresor.duressPW)
        #expect(dv.isDuressSession)
        #expect(!dv.entries.contains { $0.id == bank.id })
    }

    @Test("Ablage aus v4.3 (ungebunden): nur «erkannt»; das nächste echte Entsperren schreibt sie gebunden neu")
    func ungebundeneAblageWirdErsetzt() async throws {
        let v = try VTresor(.maximal)
        let bank = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [bank.id])
        let d = try #require(v.vault.contentForTesting?.destruction?.duress)
        let header = try #require(v.vault.headerForTesting)
        let url = v.store.hardwareKeyURL(d.fileID)
        let alt = try ungebundeneAblage(d, dek: try v.vault.dekForTesting(), vaultID: header.vaultID)
        try Data(alt).write(to: url)
        #expect(!(try v.duressEnvelopeOpens()))
        v.vault.lock()

        // Unter Zwang vor dem ersten echten Entsperren: vernichtet, aber keine Sitzung (wie ein veralteter Umschlag).
        #expect(await vFehler { _ = try v.tryUnlock(VTresor.duressPW) } == .wrongPassword)
        #expect(v.eraser.destroyed == [v.vKeyID])

        try v.reopen()
        #expect(Array(try Data(contentsOf: url)) != alt)
        #expect(try v.duressEnvelopeOpens())
        v.vault.lock()
        #expect(try v.tryUnlock(VTresor.duressPW).isDuressSession)
    }

    @Test("Ohne F (Sitzung ohne Faktoren) wird ein Inhalt mit Vernichtungs-Passwort nie geschrieben")
    func ohneBindungKeinSchreiben() async throws {
        let v = try VTresor(.maximal)
        let bank = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [bank.id])
        v.vault.lock()
        let vorher = try v.t.f.fileBytes()
        let file = try VaultFile.parse(vorher)
        let opened = try VaultCrypto.openWithPassword(file, password: try PasswordNormalizer.secureBytes(KT.pw1),
                                                      factors: try v.factors(), limits: v.store.limits)
        let ohneF = try UnlockedVault(store: v.store, header: file.header, slots: file.slots, dek: opened.dek,
                                      content: opened.content, generation: file.generation,
                                      password: try PasswordNormalizer.secureBytes(KT.pw1))
        #expect(await vFehler { try ohneF.upsert(schutzEntry("Neu", protection: .maximal)) } == .crypto("duress.binding"))
        #expect(try v.t.f.fileBytes() == vorher)
    }
}

@Suite("Krypto-Befunde: DEK-Rotation rund um das Vernichtungs-Passwort (krypto-2)")
struct KernDuressRotationTests {
    @Test("Nach einer Vernichtungs-Sitzung erneuert das erste echte Entsperren den DEK; alte Kopien helfen nicht")
    func rotationNachVernichtungsSitzung() async throws {
        let v = try VTresor(.maximal)
        let bank = try v.add("Bank", .maximal)
        let mail = try offenerEintrag(v, "Mail", password: "Mail-" + hexString(randomBytes(6)))
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [bank.id])
        let fileID = try #require(v.state()?.duressFileID)
        let dek0 = try v.vault.dekForTesting()
        v.vault.lock()
        let ablage = Array(try Data(contentsOf: v.store.hardwareKeyURL(fileID)))

        // Zwang: die Sitzung arbeitet mit dem echten DEK.
        let dv = try v.tryUnlock(VTresor.duressPW)
        #expect(dv.isDuressSession)
        #expect(try dv.dekForTesting().constantTimeEquals(dek0))
        #expect(v.state()?.rekeyPending == true)
        #expect(try String(contentsOf: v.stateURL, encoding: .utf8).contains("\"rekeyPending\":true"))
        dv.lock()
        let generation0 = try VaultFile.parse(try v.t.f.fileBytes()).generation

        // Besitzer: echtes Entsperren → neuer DEK und neues Salz, sofort geschrieben, Vermerk erledigt.
        try v.reopen()
        let dek1 = try v.vault.dekForTesting()
        #expect(!dek1.constantTimeEquals(dek0))
        #expect(v.vault.generation > generation0)
        #expect(v.state()?.rekeyPending == false)
        #expect(!(try String(contentsOf: v.stateURL, encoding: .utf8)).contains("rekeyPending"))
        #expect(v.vault.destroyedEntries == [bank.id])
        #expect(v.vault.destructionStatus.destroyedTrigger == .duressPassword)
        #expect(v.vault.entries.first { $0.id == mail.id }?.password == mail.password)
        #expect(try v.duressEnvelopeOpens())

        // Später kommt der Angreifer an eine neuere Tresordatei.
        try offenerEintrag(v, "Neu", password: "Neu-" + hexString(randomBytes(6)))
        v.vault.lock()
        let spaeter = try v.t.f.fileBytes()
        #expect((try? VaultCrypto.decryptPayload(try VaultFile.parse(spaeter), dek: dek0)) == nil)
        // Alte Ablage + Vernichtungs-Passwort, sogar mit allen Faktoren: nur der alte DEK.
        let alt = try v.offlineDuress(ablage, fileID: fileID, vaultFile: spaeter, factors: try v.factors())
        #expect(alt.recognized && alt.content == nil)

        // Ein weiteres echtes Entsperren rotiert nicht erneut.
        try v.reopen()
        #expect(try v.vault.dekForTesting().constantTimeEquals(dek1))
        // Das Vernichtungs-Passwort wirkt weiter wie zuvor (nennt man es wieder, öffnet es wieder scheinbar normal).
        v.vault.lock()
        #expect(try v.tryUnlock(VTresor.duressPW).isDuressSession)
    }

    @Test("Bei Rollback-Verdacht wird nicht rotiert (der Nutzer entscheidet), der Vermerk bleibt")
    func keineRotationBeiRollback() async throws {
        let v = try VTresor(.maximal)
        let bank = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW, markieren: [bank.id])
        v.vault.lock()
        let dv = try v.tryUnlock(VTresor.duressPW)
        let dek0 = try dv.dekForTesting()
        dv.lock()
        let file = try VaultFile.parse(try v.t.f.fileBytes())
        v.store.rollbackGuard.record(vaultID: file.header.uuid, generation: file.generation + 5)
        let outcome = try v.store.unlock(masterPassword: KT.pw1, factors: try v.factors())
        guard case let .rollbackSuspected(r, _, _) = outcome else {
            Issue.record("Rollback-Verdacht erwartet")
            return
        }
        #expect(try r.dekForTesting().constantTimeEquals(dek0))
        #expect(v.state()?.rekeyPending == true)
        r.lock()
    }
}

@Suite("Krypto-Befunde: reuseTag wie das Master-Passwort normalisiert (krypto-3)")
struct KernReuseTagNormalisierungTests {
    static let nbsp = "Zebra\u{00A0}Kanu Fichte Lampe 7319 Q!"
    static let space = "Zebra Kanu Fichte Lampe 7319 Q!"

    @Test("KAT: Zs → U+0020 vor NFC; alter Tag (nur NFC) nur, wenn er abweicht")
    func vektoren() throws {
        // Grundschlüssel wie im Testvektor von KernSchutzVektorTests.
        let rk = try EntrySealing.reuseKey(try SecureBytes.copy(Array(1...32) as [UInt8]))
        #expect(EntrySealing.reuseTag(key: rk, password: Self.nbsp) == EntrySealing.reuseTag(key: rk, password: Self.space))
        #expect(EntrySealing.reuseTag(key: rk, password: "a\u{2003}b\u{3000}c") == EntrySealing.reuseTag(key: rk, password: "a b c"))
        // Bisherige Werte ohne Zs-Zeichen bleiben gleich (Testvektor aus KernSchutzVektorTests).
        #expect(KT.hex(EntrySealing.reuseTag(key: rk, password: "Passwort-a\u{0308}") ?? [])
            == "174f4b195dcaa51999f0192d5dfbd26a")
        #expect(EntrySealing.legacyReuseTag(key: rk, password: Self.space) == nil)
        #expect(EntrySealing.legacyReuseTag(key: rk, password: "Passwort-a\u{0308}") == nil)
        #expect(EntrySealing.legacyReuseTag(key: rk, password: "") == nil)
        var nfc = Self.nbsp.precomposedStringWithCanonicalMapping
        let alt = nfc.withUTF8 { EntrySealing.reuseTag(key: rk, bytes: UnsafeRawBufferPointer($0)) }
        #expect(EntrySealing.legacyReuseTag(key: rk, password: Self.nbsp) == alt)
        #expect(alt != EntrySealing.reuseTag(key: rk, password: Self.nbsp))
    }

    @Test("Versiegelter Eintrag mit U+00A0: Passwortwechsel auf dasselbe → masterPasswordReused (auch mit U+0020)")
    func versiegeltErkannt() throws {
        for neu in [Self.nbsp, Self.space] {
            let t = try SchutzTresor.make(.erhoeht)
            let se = try t.k.secrets([.secureEnclave])
            let e = schutzEntry("Bank", protection: .hoch, password: Self.nbsp)
            try t.vault.upsert(e)
            #expect(t.vault.entries.first { $0.id == e.id }?.secretsSealed == true)
            #expect(throws: SiegelError.masterPasswordReused) {
                try t.vault.changeMasterPassword(current: KT.pw1, new: neu, factors: se)
            }
        }
    }

    @Test("«Gleich wie Master-Passwort» auch bei versiegelten Einträgen mit U+00A0")
    func gleichWieMaster() throws {
        let t = try SchutzTresor.make(.erhoeht)
        let se = try t.k.secrets([.secureEnclave])
        try t.vault.changeMasterPassword(current: KT.pw1, new: Self.nbsp, factors: se)
        let e = schutzEntry("Bank", protection: .fingerabdruck, password: Self.nbsp)
        try t.vault.upsert(e)
        #expect(t.vault.masterPasswordReuse.contains(e.id))
        for typed in [Self.nbsp, Self.space] {
            let v = try t.reopen(password: typed)
            #expect(v.securityReport().sameAsMaster.contains(e.id))
            #expect(v.masterPasswordReuse.contains(e.id))
            v.lock()
        }
    }

    @Test("Alte Tags (bis v4.3, nur NFC): erkannt, wenn das Master-Passwort genau so getippt ist; kein Änderungsdatum")
    func alteTags() throws {
        let t = try SchutzTresor.make(.erhoeht)
        let se = try t.k.secrets([.secureEnclave])
        let versiegelt = schutzEntry("Bank", protection: .hoch, password: Self.nbsp)
        let offen = schutzEntry("Mail", protection: .normal, password: Self.nbsp)
        try t.vault.upsert(versiegelt)
        try t.vault.upsert(offen)
        let damals = Date(timeIntervalSince1970: 1_780_000_000)
        var altTag: [UInt8]?
        // Tags auf die alte Formel zurücksetzen (so lagen sie vor v4.4 im Inhalt).
        try t.vault.mutate { c, _, _ in
            let rk = try c.reuseKey()
            altTag = EntrySealing.legacyReuseTag(key: rk, password: Self.nbsp)
            for id in [versiegelt.id, offen.id] {
                c.meta[id]?.tag = altTag
                c.meta[id]?.changed = damals
            }
            return true
        }
        #expect(altTag != nil)
        // Versiegelt: der Passwortwechsel auf genau diese Eingabe wird abgelehnt.
        #expect(throws: SiegelError.masterPasswordReused) {
            try t.vault.changeMasterPassword(current: KT.pw1, new: Self.nbsp, factors: se)
        }
        // Offen: beim nächsten Speichern neuer Tag, aber kein neues Änderungsdatum.
        try t.vault.upsert(schutzEntry("Anderes", protection: .normal))
        let meta = try #require(t.vault.contentForTesting?.meta[offen.id])
        #expect(meta.tag != altTag)
        #expect(meta.changed == damals)
        #expect(meta.tag == EntrySealing.reuseTag(key: try #require(t.vault.contentForTesting).reuseKey(),
                                                  password: Self.nbsp))
    }

    @Test("Alter Tag eines versiegelten Eintrags: «Gleich wie Master-Passwort» nach dem Entsperren mit genau dieser Eingabe")
    func alteTagsNachEntsperren() throws {
        let t = try SchutzTresor.make(.erhoeht)
        let se = try t.k.secrets([.secureEnclave])
        try t.vault.changeMasterPassword(current: KT.pw1, new: Self.nbsp, factors: se)
        let e = schutzEntry("Bank", protection: .hoch, password: Self.nbsp)
        try t.vault.upsert(e)
        try t.vault.mutate { c, _, _ in
            let alt = EntrySealing.legacyReuseTag(key: try c.reuseKey(), password: Self.nbsp)
            c.meta[e.id]?.tag = alt
            return true
        }
        let v = try t.reopen(password: Self.nbsp)
        #expect(v.securityReport().sameAsMaster.contains(e.id))
        v.lock()
        // Ehrliche Grenze: mit U+0020 getippt passt der alte Tag nicht (bis der Eintrag neu versiegelt wird).
        let w = try t.reopen(password: Self.space)
        #expect(!w.securityReport().sameAsMaster.contains(e.id))
        w.lock()
    }
}
