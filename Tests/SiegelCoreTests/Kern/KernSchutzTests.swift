import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Eintrags-Schutz (SPEC §16): versiegeln, aufdecken, Regeln, Notfall, Kit- und Faktorwechsel.
/// Gegenseite der Faktoren: `SchutzProvider` (Software-P256, feste q/y2). Testschalter-KDF.
@Suite("Eintrags-Schutz (§16)")
struct KernSchutzTests {
    /// TOTP-Merkmal ohne „/“ (JSONEncoder schreibt „\/“).
    private func totpMark(_ e: VaultEntry) -> String { e.title + "?secret=JBSWY3DPEHPK3PXP" }

    @Test("Schutz 1–5: versiegelt, nur offene Felder sichtbar, Aufdecken ruft genau die Faktoren der Maske")
    func alleStufen() async throws {
        let t = try SchutzTresor.make()
        #expect(t.vault.enrolledFactors == .all)
        var originals: [EntryProtection: VaultEntry] = [:]
        for p in EntryProtection.allCases {
            let e = schutzEntry("E\(p.rawValue)", protection: p)
            try t.vault.upsert(e)
            originals[p] = e
        }
        let json = try t.jsonOnDisk()
        for p in EntryProtection.allCases {
            let o = try #require(originals[p])
            let stored = try #require(t.vault.entries.first { $0.id == o.id })
            #expect(stored.title == o.title && stored.username == o.username && stored.url == o.url)
            #expect(stored.protection == p)
            #expect(stored.secretsSealed == (p > .normal))
            let hidden = p > .normal
            if hidden {
                #expect(stored.password.isEmpty && stored.notes.isEmpty && stored.totp.isEmpty && stored.history.isEmpty)
            }
            // Passwort, Notizen, TOTP und Verlauf stehen nur bei Schutz 1 im Klartext-JSON.
            #expect(json.contains(o.password) == !hidden)
            #expect(json.contains(o.notes) == !hidden)
            #expect(json.contains(totpMark(o)) == !hidden)
            #expect(json.contains("Alt-" + o.title) == !hidden)
        }

        // Aufdecken nach dem Neu-Öffnen (alles persistiert)
        let v = try t.reopen()
        for p in EntryProtection.allCases {
            let o = try #require(originals[p])
            t.p.reset()
            let s = try await v.revealSecrets(id: o.id, factors: p == .normal ? nil : t.p)
            #expect(s == EntrySecrets(o))
            let m = p.factors
            #expect(t.p.counts == [m.contains(.secureEnclave) ? 1 : 0, m.contains(.card) ? 1 : 0,
                                   m.contains(.securityKey) ? 1 : 0])
        }
        // Liste und Suche ohne Faktor
        #expect(Set(v.entries.map(\.title)) == Set(originals.values.map(\.title)))
    }

    @Test("Fehlender Provider, nicht eingerichteter Faktor, Abbruch und fremde Fehler: nie Geheimteile")
    func fehlerfaelle() async throws {
        let t = try SchutzTresor.make(enroll: [.secureEnclave])
        let gen = t.vault.generation
        #expect(throws: SiegelError.factorMissing(.card)) { try t.vault.upsert(schutzEntry("K", protection: .maximal)) }
        #expect(throws: SiegelError.factorMissing(.card)) { try t.vault.upsert(schutzEntry("F", protection: .festung)) }
        #expect(t.vault.generation == gen)
        #expect(t.vault.entries.isEmpty)

        let e = schutzEntry("A", protection: .hoch)
        try t.vault.upsert(e)
        await #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
            try await t.vault.revealSecrets(id: e.id, factors: nil)
        }
        #expect(t.p.counts == [0, 0, 0])
        #expect(throws: SiegelError.factorMissing(.card)) {
            try t.vault.setProtection(.maximal, id: e.id, secrets: EntrySecrets(e))
        }
        await #expect(throws: SiegelError.io("entry.notFound")) {
            try await t.vault.revealSecrets(id: UUID(), factors: t.p)
        }
        let cases: [(SchutzProvider.Verhalten, SiegelError)] = [
            (.falsch, .wrongPassword), (.abbruch, .factorCancelled),
            (.fremderFehler, .factorUnavailable(.secureEnclave)), (.nichtVerfuegbar, .factorUnavailable(.secureEnclave)),
        ]
        for (verhalten, fehler) in cases {
            t.p.set(.secureEnclave, verhalten)
            await #expect(throws: fehler) { try await t.vault.revealSecrets(id: e.id, factors: t.p) }
        }
        t.p.set(.secureEnclave, .richtig)
        #expect(try await t.vault.revealSecrets(id: e.id, factors: t.p) == EntrySecrets(e))
    }

    @Test("Falsche Karte → wrongCard (Schlüssel wird nicht mehr gefragt), falscher Sicherheitsschlüssel → wrongPassword")
    func falscheKarteUndSchluessel() async throws {
        let t = try SchutzTresor.make()
        let e = schutzEntry("F", protection: .festung)
        try t.vault.upsert(e)
        t.p.set(.card, .falsch)
        await #expect(throws: SiegelError.wrongCard) { try await t.vault.revealSecrets(id: e.id, factors: t.p) }
        #expect(t.p.counts == [1, 1, 0])
        t.p.set(.card, .richtig)
        t.p.set(.securityKey, .falsch)
        t.p.reset()
        await #expect(throws: SiegelError.wrongPassword) { try await t.vault.revealSecrets(id: e.id, factors: t.p) }
        #expect(t.p.counts == [1, 1, 1])
        t.p.set(.securityKey, .richtig)
        #expect(try await t.vault.revealSecrets(id: e.id, factors: t.p) == EntrySecrets(e))
    }

    @Test("Sperren während der Freigabe: keine Geheimteile")
    func sperrenWaehrendFreigabe() async throws {
        let t = try SchutzTresor.make()
        let e = schutzEntry("S", protection: .fingerabdruck)
        try t.vault.upsert(e)
        let vault = t.vault
        t.p.onAnswer { vault.lock() }
        await #expect(throws: SiegelError.io("vault.locked")) { try await vault.revealSecrets(id: e.id, factors: t.p) }
    }

    @Test("Befund ablaeufe-4: Gesperrt zwischen zwei Faktoren → keine weitere Abfrage (Karte, Schlüssel)")
    func sperrenZwischenFaktoren() async throws {
        let t = try SchutzTresor.make()
        let e = schutzEntry("Krypto", protection: .festung)
        try t.vault.upsert(e)
        let vault = t.vault
        // Touch ID läuft noch, als die Auto-Sperre greift: Danach darf weder das Kamera- noch das Schlüssel-Sheet kommen.
        t.p.onAnswer { vault.lock() }
        await #expect(throws: SiegelError.io("vault.locked")) { try await vault.revealSecrets(id: e.id, factors: t.p) }
        #expect(t.p.counts == [1, 0, 0])
    }

    @Test("Befund ablaeufe-4: Neues Kit – gesperrt während der ersten Gruppe → keine weitere Freigabe, nichts geschrieben")
    func sperrenWaehrendGruppenFreigabe() async throws {
        let t = try SchutzTresor.make()
        for e in [schutzEntry("B", protection: .fingerabdruck), schutzEntry("D", protection: .maximal),
                  schutzEntry("E", protection: .festung)] {
            try t.vault.upsert(e)
        }
        let pending = try t.vault.prepareRecovery(masterPassword: KT.pw1)
        let conf = KernStufen.confirmation(pending)
        let gen = t.vault.generation
        let vault = t.vault
        t.p.onAnswer { vault.lock() }
        await #expect(throws: SiegelError.io("vault.locked")) {
            try await vault.commitRecovery(pending, confirmation: conf, entryFactors: t.p)
        }
        #expect(t.p.counts == [1, 0, 0])
        t.p.onAnswer(nil)
        #expect(try t.reopen().generation == gen)
    }

    @Test("Befund ablaeufe-4: Export – gesperrt während Argon2 → keine Freigabe danach (kein Touch-ID-Dialog)")
    func sperrenWaehrendExportArgon2() async throws {
        let t = try SchutzTresor.make()
        try t.vault.upsert(schutzEntry("B", protection: .fingerabdruck))
        let vault = t.vault
        let dir = t.f.dir.sub("Export")
        let observer = TestHooks.KDFObserver { _ in vault.lock() }
        let fehler: SiegelError? = await TestHooks.$kdfObserver.withValue(observer) {
            do {
                _ = try await vault.exportCSV(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets(),
                                              entryFactors: t.p)
                return nil
            } catch {
                return error as? SiegelError
            }
        }
        #expect(observer.runs == 1)
        #expect(fehler == .io("vault.locked"))
        #expect(t.p.counts == [0, 0, 0])
    }

    @Test("upsert: Standard-Schutz der Stufe, offene Felder ändern, Geheimteile und Schutz nur über setProtection")
    func upsertRegeln() async throws {
        let t = try SchutzTresor.make(.maximal)
        #expect(t.vault.policy.defaultEntryProtection == .fingerabdruck)
        let neu = schutzEntry("Neu", protection: .normal)
        try t.vault.upsert(neu)
        let stored = try #require(t.vault.entries.first { $0.id == neu.id })
        #expect(stored.protection == .fingerabdruck && stored.secretsSealed)
        let explizit = schutzEntry("Explizit", protection: .hoch)
        try t.vault.upsert(explizit)
        #expect(t.vault.entries.first { $0.id == explizit.id }?.protection == .hoch)

        // Offene Felder eines versiegelten Eintrags ändern: Geheimteile bleiben
        var edit = stored
        edit.title = "Neu umbenannt"
        edit.username = "jemand"
        let genBefore = t.vault.generation
        try t.vault.upsert(edit)
        #expect(t.vault.generation > genBefore)
        let renamed = try #require(t.vault.entries.first { $0.id == neu.id })
        #expect(renamed.title == "Neu umbenannt" && renamed.secretsSealed && renamed.modified >= stored.modified)
        #expect(try await t.vault.revealSecrets(id: neu.id, factors: t.p) == EntrySecrets(neu))

        // Geheimteile oder Schutz über upsert → abgelehnt, nichts geschrieben
        let gen = t.vault.generation
        var mitPasswort = renamed
        mitPasswort.password = "anders"
        #expect(throws: SiegelError.io("entry.sealedSecrets")) { try t.vault.upsert(mitPasswort) }
        var mitNotiz = renamed
        mitNotiz.notes = "x"
        #expect(throws: SiegelError.io("entry.sealedSecrets")) { try t.vault.upsert(mitNotiz) }
        for p: EntryProtection in [.normal, .hoch, .festung] {
            var anders = renamed
            anders.protection = p
            #expect(throws: SiegelError.io("entry.protection")) { try t.vault.upsert(anders) }
        }
        #expect(throws: SiegelError.io("entry.sealedSecrets")) { try t.vault.clearHistory(id: neu.id) }
        var kopie = renamed
        kopie.id = UUID()
        #expect(throws: SiegelError.io("entry.stale")) { try t.vault.upsert(kopie) }
        #expect(throws: SiegelError.io("entry.stale")) { try t.vault.importEntries([kopie]) }
        #expect(t.vault.generation == gen)

        // setProtection(.normal): offen mit den übergebenen Geheimteilen; die alte versiegelte Kopie ist jetzt veraltet
        try t.vault.setProtection(.normal, id: neu.id, secrets: EntrySecrets(neu))
        let offen = try #require(t.vault.entries.first { $0.id == neu.id })
        #expect(offen.protection == .normal && !offen.secretsSealed && EntrySecrets(offen) == EntrySecrets(neu))
        #expect(throws: SiegelError.io("entry.stale")) { try t.vault.upsert(renamed) }

        // Offener Eintrag: über upsert höher schützen (mit Passwortwechsel → Verlauf), nie tiefer
        var hoeher = offen
        hoeher.password = "Neues-Passwort-1"
        hoeher.protection = .maximal
        try t.vault.upsert(hoeher)
        let sealedAgain = try #require(t.vault.entries.first { $0.id == neu.id })
        #expect(sealedAgain.protection == .maximal && sealedAgain.secretsSealed)
        let revealed = try await t.vault.revealSecrets(id: neu.id, factors: t.p)
        #expect(revealed.password == "Neues-Passwort-1")
        #expect(revealed.history.contains { $0.password == neu.password })

        // Geheimteile bearbeiten: aufdecken → replacingPassword → setProtection
        let next = revealed.replacingPassword(with: "Drittes-Passwort-9")
        #expect(next.history.contains { $0.password == "Neues-Passwort-1" })
        #expect(!next.history.contains { $0.password == "Drittes-Passwort-9" })
        try t.vault.setProtection(.maximal, id: neu.id, secrets: next)
        t.p.reset()
        let third = try await t.vault.revealSecrets(id: neu.id, factors: t.p)
        #expect(third.password == "Drittes-Passwort-9" && Set(third.history) == Set(next.history))
        #expect(t.p.counts == [1, 1, 0])
        // Verlauf leeren geht über setProtection
        try t.vault.setProtection(.maximal, id: neu.id,
                                  secrets: EntrySecrets(password: third.password, notes: third.notes, totp: third.totp))
        #expect(try await t.vault.revealSecrets(id: neu.id, factors: t.p).history.isEmpty)
        // Feldgrenzen gelten auch für setProtection
        #expect(throws: SiegelError.io("entry.passwordTooLong")) {
            try t.vault.setProtection(.hoch, id: neu.id, secrets: EntrySecrets(password: String(repeating: "x", count: 5000)))
        }
    }

    @Test("Notfallcode in Teilen (Stufe 5) entsiegelt alles: Stufe 1, Schutz 1, auch gelöschte Einträge")
    func notfallTeile() async throws {
        let t = try SchutzTresor.make(.festung)
        let kit = try #require(t.kit)
        #expect(kit.scheme == .shamir2of3)
        let list = [schutzEntry("B", protection: .fingerabdruck), schutzEntry("C", protection: .hoch),
                    schutzEntry("D", protection: .maximal), schutzEntry("E", protection: .festung),
                    schutzEntry("Weg", protection: .festung)]
        for e in list { try t.vault.upsert(e) }
        try t.vault.delete(id: list[4].id)
        #expect(t.vault.contentForTesting?.recoveryGroups.count == 3)
        t.vault.lock()
        let shares = kit.shares.map(\.formatted)
        let v = try t.store.recover(shares: [shares[2], shares[0]], newMasterPassword: KT.pw2, kdf: KT.kdf)
        #expect(v.level == .standard)
        #expect(v.enrolledFactors.isEmpty)
        let all = v.entries + v.deletedEntries
        for o in list {
            let e = try #require(all.first { $0.id == o.id })
            #expect(e.protection == .normal && !e.secretsSealed)
            #expect(EntrySecrets(e) == EntrySecrets(o))
            #expect(try await v.revealSecrets(id: o.id, factors: nil) == EntrySecrets(o))
        }
        #expect(v.deletedEntries.map(\.id) == [list[4].id])
        let content = try #require(v.contentForTesting)
        #expect(content.sealed.isEmpty && content.recoveryGroups.isEmpty)
        // Neu öffnen: nur Passwort
        v.lock()
        let again = try #require(KT.unlocked(try t.store.unlock(masterPassword: KT.pw2)))
        #expect(again.entries.allSatisfy { !$0.secretsSealed && $0.protection == .normal })
    }

    @Test("Notfallcode (Stufe 2): entsiegelt; das neue Master-Passwort darf kein (versiegeltes) Eintragspasswort sein")
    func notfallCode() async throws {
        let t = try SchutzTresor.make(.erhoeht)
        let list = [schutzEntry("B", protection: .fingerabdruck), schutzEntry("D", protection: .maximal),
                    schutzEntry("E", protection: .festung, password: KT.pw3)]
        for e in list { try t.vault.upsert(e) }
        t.vault.lock()
        let code = try #require(t.kit?.code.formatted)
        #expect(throws: SiegelError.masterPasswordReused) {
            try t.store.recover(code: code, newMasterPassword: KT.pw3, kdf: KT.kdf)
        }
        let v = try t.store.recover(code: code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        for o in list {
            let e = try #require(v.entries.first { $0.id == o.id })
            #expect(EntrySecrets(e) == EntrySecrets(o) && e.protection == .normal)
        }
    }

    @Test("Notfallweg über Sicherungen (Datei beschädigt) entsiegelt ebenfalls")
    func notfallSicherung() throws {
        let t = try SchutzTresor.make(.erhoeht)
        let list = [schutzEntry("B", protection: .hoch), schutzEntry("E", protection: .festung)]
        for e in list { try t.vault.upsert(e) }
        try t.vault.upsert(kernEntry("Danach"))      // sichert den Stand mit B und E
        var bytes = try t.f.fileBytes()
        bytes[bytes.count / 2] ^= 0x40
        try t.f.writeFile(bytes)
        t.vault.lock()
        let code = try #require(t.kit?.code.formatted)
        #expect(throws: SiegelError.corruptFile("file.checksum")) {
            try t.store.recover(code: code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        let (v, _) = try t.store.recoverFromNewestReadableBackup(code: code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        #expect(v.level == .standard)
        for o in list {
            let e = try #require(v.entries.first { $0.id == o.id })
            #expect(EntrySecrets(e) == EntrySecrets(o) && !e.secretsSealed)
        }
    }

    @Test("Neues Kit mit versiegelten Einträgen: sync → factorMissing (nichts geschrieben), async mit einer Freigabe je Gruppe")
    func neuesKit() async throws {
        let t = try SchutzTresor.make()
        let list = [schutzEntry("B", protection: .fingerabdruck), schutzEntry("C", protection: .hoch),
                    schutzEntry("D", protection: .maximal), schutzEntry("E", protection: .festung)]
        for e in list { try t.vault.upsert(e) }
        let altCode = t.f.code
        let pending = try t.vault.prepareRecovery(masterPassword: KT.pw1)
        let conf = KernStufen.confirmation(pending)
        let gen = t.vault.generation
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try t.vault.commitRecovery(pending, confirmation: conf) }
        await #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
            try await t.vault.commitRecovery(pending, confirmation: conf, entryFactors: nil)
        }
        await #expect(throws: SiegelError.recoveryConfirmationMismatch) {
            try await t.vault.commitRecovery(pending, confirmation: ["AAAAA", "BBBBB"], entryFactors: t.p)
        }
        #expect(t.p.counts == [0, 0, 0])
        #expect(t.vault.generation == gen)
        #expect(try t.store.checkRecoveryCode(altCode) == .exact)

        try await t.vault.commitRecovery(pending, confirmation: conf, entryFactors: t.p)
        #expect(t.p.counts == [3, 2, 1])      // Gruppen {SE}, {SE, Karte}, {alle}
        #expect(t.vault.kitID == pending.code.kitID)
        #expect(t.vault.recoveryConfirmed)
        for o in list { #expect(try await t.vault.revealSecrets(id: o.id, factors: t.p) == EntrySecrets(o)) }
        t.vault.lock()
        #expect(throws: (any Error).self) { try t.store.checkRecoveryCode(altCode) }
        let v = try t.store.recover(code: pending.code.formatted, newMasterPassword: KT.pw2, kdf: KT.kdf)
        for o in list {
            let e = try #require(v.entries.first { $0.id == o.id })
            #expect(EntrySecrets(e) == EntrySecrets(o))
        }
    }

    @Test("Stufenwechsel mit neuem Kit (3 → 4, 5 → 3) nimmt versiegelte Einträge mit; Passwort vor der Freigabe")
    func stufenwechselMitKit() async throws {
        let t = try SchutzTresor.make(.hoch, enroll: [.secureEnclave])
        let e = schutzEntry("H", protection: .hoch)
        try t.vault.upsert(e)
        let se = try t.k.secrets([.secureEnclave])
        let shamir = try t.vault.prepareRecovery(masterPassword: KT.pw1, factors: se, scheme: .shamir2of3)
        let conf = KernStufen.confirmation(shamir)
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
            try t.vault.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1, currentFactors: se,
                                            newFactors: NewFactorMaterial(card: t.k.card), recovery: shamir,
                                            recoveryConfirmation: conf)
        }
        await #expect(throws: SiegelError.wrongPassword) {
            try await t.vault.changeSecurityLevel(to: .maximal, masterPassword: KT.pw2, currentFactors: se,
                                                  newFactors: NewFactorMaterial(card: t.k.card), recovery: shamir,
                                                  recoveryConfirmation: conf, entryFactors: t.p)
        }
        #expect(t.p.counts == [0, 0, 0])
        try await t.vault.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1, currentFactors: se,
                                              newFactors: NewFactorMaterial(card: t.k.card), recovery: shamir,
                                              recoveryConfirmation: conf, entryFactors: t.p)
        #expect(t.p.counts == [1, 0, 0])
        #expect(t.vault.level == .maximal && t.vault.kitID == shamir.code.kitID)
        #expect(t.vault.enrolledFactors == [.secureEnclave, .card])
        #expect(try await t.vault.revealSecrets(id: e.id, factors: t.p) == EntrySecrets(e))

        // Weitere Einträge mit Karte, dann 4 → 5 (gleiches Schema, kein Kit) und 5 → 3 (neues Kit, zwei Gruppen)
        let d = schutzEntry("D", protection: .maximal)
        try t.vault.upsert(d)
        let four = try t.k.secrets([.secureEnclave, .card])
        try t.vault.changeSecurityLevel(to: .festung, masterPassword: KT.pw1, currentFactors: four,
                                        newFactors: NewFactorMaterial(securityKey: try t.k.securityKey),
                                        recovery: nil, recoveryConfirmation: [])
        let single = try t.vault.prepareRecovery(masterPassword: KT.pw1, factors: try t.k.secrets(), scheme: .single)
        t.p.reset()
        try await t.vault.changeSecurityLevel(to: .hoch, masterPassword: KT.pw1, currentFactors: try t.k.secrets(),
                                              newFactors: NewFactorMaterial(), recovery: single,
                                              recoveryConfirmation: KernStufen.confirmation(single), entryFactors: t.p)
        #expect(t.p.counts == [2, 1, 0])
        #expect(t.vault.level == .hoch)
        t.vault.lock()
        let v = try t.store.recover(code: single.code.formatted, newMasterPassword: KT.pw2, kdf: KT.kdf)
        for o in [e, d] {
            let x = try #require(v.entries.first { $0.id == o.id })
            #expect(EntrySecrets(x) == EntrySecrets(o))
        }
    }

    @Test("Eintrags-Faktor ersetzen nur, solange kein versiegelter Eintrag daran hängt")
    func faktorErsetzen() async throws {
        let t = try SchutzTresor.make()
        let fremd = EntryKeyEnrollment(keyID: UUID(), publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let neueKarte = CardEnrollment(q: CardCode.generate())
        // ohne versiegelte Einträge erlaubt (und zurück)
        try t.vault.enrollFactors(NewFactorMaterial(entryKey: fremd, card: neueKarte), masterPassword: KT.pw1,
                                  currentFactors: FactorSecrets())
        try t.vault.enrollFactors(NewFactorMaterial(entryKey: t.p.entryKey, card: t.k.card), masterPassword: KT.pw1,
                                  currentFactors: FactorSecrets())
        let b = schutzEntry("B", protection: .fingerabdruck)
        try t.vault.upsert(b)
        let gen = t.vault.generation
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try t.vault.enrollFactors(NewFactorMaterial(entryKey: fremd), masterPassword: KT.pw1, currentFactors: FactorSecrets())
        }
        // Karte ist (noch) frei
        try t.vault.enrollFactors(NewFactorMaterial(card: neueKarte), masterPassword: KT.pw1, currentFactors: FactorSecrets())
        try t.vault.enrollFactors(NewFactorMaterial(card: t.k.card), masterPassword: KT.pw1, currentFactors: FactorSecrets())
        let d = schutzEntry("D", protection: .maximal)
        try t.vault.upsert(d)
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try t.vault.enrollFactors(NewFactorMaterial(card: neueKarte), masterPassword: KT.pw1, currentFactors: FactorSecrets())
        }
        // Stufenwechsel mit neuem Eintrags-Schlüssel ebenso
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try t.vault.changeSecurityLevel(to: .erhoeht, masterPassword: KT.pw1, currentFactors: FactorSecrets(),
                                            newFactors: NewFactorMaterial(secureEnclave: try t.k.seEnrollment, entryKey: fremd),
                                            recovery: nil, recoveryConfirmation: [])
        }
        // derselbe Faktor erneut ist kein Ersatz
        try t.vault.enrollFactors(NewFactorMaterial(entryKey: t.p.entryKey, card: t.k.card), masterPassword: KT.pw1,
                                  currentFactors: FactorSecrets())
        #expect(t.vault.generation > gen)
        #expect(try await t.vault.revealSecrets(id: d.id, factors: t.p) == EntrySecrets(d))
    }

    @Test("Zugangswechsel rotieren den DEK; versiegelte Einträge bleiben lesbar, auch aus Sicherungen")
    func dekRotation() async throws {
        let t = try SchutzTresor.make(.erhoeht)
        let e = schutzEntry("R", protection: .festung)
        try t.vault.upsert(e)
        let se = try t.k.secrets([.secureEnclave])
        let dek1 = try t.vault.dekForTesting()
        let baseKey = try #require(t.vault.contentForTesting?.entryKey)
        try t.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2, factors: se)
        #expect(try !t.vault.dekForTesting().constantTimeEquals(dek1))
        #expect(t.vault.contentForTesting?.entryKey == baseKey)
        #expect(try await t.vault.revealSecrets(id: e.id, factors: t.p) == EntrySecrets(e))
        // Master-Passwort gleich einem versiegelten Eintragspasswort → abgelehnt
        let m = schutzEntry("M", protection: .hoch, password: KT.pw3)
        try t.vault.upsert(m)
        #expect(throws: SiegelError.masterPasswordReused) {
            try t.vault.changeMasterPassword(current: KT.pw2, new: KT.pw3, factors: se)
        }
        // Stufe 2 → 3 (gleiches Schema)
        try t.vault.changeSecurityLevel(to: .hoch, masterPassword: KT.pw2, currentFactors: se,
                                        newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        #expect(try await t.vault.revealSecrets(id: e.id, factors: t.p) == EntrySecrets(e))
        // Sicherung vor dem Stufenwechsel einsetzen (DEK und Salz neu)
        let backup = try #require(t.f.localBackups().first { $0.reason == "stufenwechsel" })
        t.vault.lock()
        let v = try t.store.restoreBackup(backup, masterPassword: KT.pw2, factors: se)
        #expect(v.level == .erhoeht)
        #expect(try await v.revealSecrets(id: e.id, factors: t.p) == EntrySecrets(e))
        #expect(try await v.revealSecrets(id: m.id, factors: t.p) == EntrySecrets(m))
    }

    @Test("Papierkorb: versiegelte Einträge löschen, aufdecken, wiederherstellen; Entfernen räumt Gruppen auf")
    func papierkorb() async throws {
        let t = try SchutzTresor.make()
        let d = schutzEntry("D", protection: .maximal)
        try t.vault.upsert(d)
        try t.vault.delete(id: d.id)
        #expect(t.vault.deletedEntries.first?.secretsSealed == true)
        #expect(try await t.vault.revealSecrets(id: d.id, factors: t.p) == EntrySecrets(d))
        try t.vault.restore(id: d.id)
        #expect(t.vault.entries.first?.id == d.id)
        try t.vault.delete(id: d.id)
        try t.vault.purgeDeleted(id: d.id)
        let c = try #require(t.vault.contentForTesting)
        #expect(c.sealed.isEmpty && c.recoveryGroups.isEmpty && c.meta[d.id] == nil)
        // Ablauf nach 30 Tagen räumt ebenso auf
        let e = schutzEntry("E", protection: .fingerabdruck)
        try t.vault.upsert(e)
        try t.vault.delete(id: e.id)
        try TestHooks.$now.withValue(Date().addingTimeInterval(31 * 86_400)) {
            try t.vault.upsert(kernEntry("Später"))
        }
        let c2 = try #require(t.vault.contentForTesting)
        #expect(c2.sealed.isEmpty && c2.recoveryGroups.isEmpty)
        #expect(t.vault.deletedEntries.isEmpty)
    }

    @Test("importEntries: Stufe 4 versiegelt mit Schutz 2; Dubletten auch gegen versiegelte Einträge; fehlender Faktor")
    func importieren() async throws {
        let t = try SchutzTresor.make(.maximal)
        try t.vault.upsert(kernEntry("Bank", user: "anna", password: "Konto-123", url: "https://bank.ch"))
        let report = try t.vault.importEntries([
            kernEntry("Bank", user: "anna", password: "Konto-123", url: "bank.ch"),
            kernEntry("Bank", user: "anna", password: "Anders-456", url: "https://bank.ch"),
            kernEntry("Mail", user: "anna", password: "Post-789", url: "https://mail.ch"),
        ])
        #expect(report.added == 2 && report.skippedDuplicates == 1 && report.conflicts == 1)
        #expect(t.vault.entries.count == 3)
        #expect(t.vault.entries.allSatisfy { $0.secretsSealed && $0.protection == .fingerabdruck })
        let mail = try #require(t.vault.entries.first { $0.title == "Mail" })
        #expect(try await t.vault.revealSecrets(id: mail.id, factors: t.p).password == "Post-789")
        #expect(t.vault.entries.contains { $0.title == "Bank (Import)" })

        // Stufe 4 ohne Eintrags-SE-Schlüssel: neue Einträge (Schutz 2) brauchen ihn
        let ohne = try SchutzTresor.make(.maximal, enroll: [])
        #expect(ohne.vault.enrolledFactors == [.card])
        let gen = ohne.vault.generation
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try ohne.vault.upsert(kernEntry("A")) }
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try ohne.vault.importEntries([kernEntry("A")]) }
        #expect(ohne.vault.generation == gen)
    }

    @Test("Herabstufen der Schutz-Angabe in der Datei (Angreifer mit DEK) macht den Eintrag unlesbar")
    func herabstufenInDerDatei() async throws {
        let t = try SchutzTresor.make()
        let a = schutzEntry("A", protection: .fingerabdruck)
        let b = schutzEntry("B", protection: .maximal)
        try t.vault.upsert(a)
        try t.vault.upsert(b)
        let s = try t.vault.snapshot()
        let code = t.f.code

        func forge(_ change: (inout VaultContent) -> Void) throws {
            var c = s.content
            change(&c)
            let built = try VaultCrypto.buildFile(header: s.header, slots: s.slots, generation: s.generation + 1,
                                                  dek: s.dek, content: c)
            try t.f.writeFile(built.bytes)
        }
        let ib = try #require(s.content.entries.firstIndex { $0.id == b.id })
        // Schutz 4 → 2 und Karten-Kapsel entfernt: Datei gültig, aber der Eintrag lässt sich nicht öffnen
        try forge { c in
            c.entries[ib].protection = .fingerabdruck
            c.sealed[b.id]?.blob.factors.card = nil
        }
        t.vault.lock()
        let v = KT.anyVault(try t.store.unlock(masterPassword: KT.pw1))
        #expect(v.entries.first { $0.id == b.id }?.protection == .fingerabdruck)
        t.p.reset()
        await #expect(throws: SiegelError.wrongPassword) { try await v.revealSecrets(id: b.id, factors: t.p) }
        #expect(t.p.counts == [1, 0, 0])
        #expect(try await v.revealSecrets(id: a.id, factors: t.p) == EntrySecrets(a))
        v.lock()
        // Notfallweg: der Umschlag passt nicht zur Angabe → corruptFile (nie ein Teilerfolg)
        #expect(throws: SiegelError.corruptFile("entry.recovery")) {
            try t.store.recover(code: code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        // Schutz 1 bei versiegeltem Inhalt: der Kern schreibt so etwas nie (Prüfung beim Kodieren) …
        var inkonsistent = s.content
        inkonsistent.entries[ib].protection = .normal
        #expect(throws: SiegelError.crypto("entry.sealedState")) { try PayloadCodec.encode(inkonsistent) }
        // … und ein Angreifer mit DEK, der es per Hand baut, wird beim Lesen abgelehnt
        let (padded, _) = try PayloadCodec.encode(s.content)
        let json = try #require(PayloadCodec.jsonStringForTesting(padded))
        let forgedJSON = json.replacingOccurrences(of: "\"protection\":4", with: "\"protection\":1")
        #expect(forgedJSON != json)
        let gen = s.generation + 2
        let sealedPayload = try AEAD.seal(key: s.dek, plaintext: try KernBerichtTests.padded(forgedJSON),
                                          ad: VaultFile.payloadAD(header: s.header, slots: s.slots, generation: gen))
        try t.f.writeFile(VaultFile(header: s.header, slots: s.slots, generation: gen, nonce: sealedPayload.nonce,
                                    ciphertext: sealedPayload.ciphertext).serialize())
        #expect(throws: SiegelError.corruptFile("entry.sealedState")) { try t.store.unlock(masterPassword: KT.pw1) }
    }
}

/// Byte-Kipp-Proben mit versiegelten Einträgen (SPEC §10 + §16).
@Suite("Manipulation mit versiegelten Einträgen")
struct KernSchutzByteKippTests {
    private final class Findings: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [String] = []
        func add(_ s: String) { lock.withLock { items.append(s) } }
        var all: [String] { lock.withLock { items } }
    }

    private func forEachPosition(_ count: Int, _ body: @escaping @Sendable (Int) -> Void) {
        let chunk = 256
        DispatchQueue.concurrentPerform(iterations: (count + chunk - 1) / chunk) { c in
            for i in (c * chunk)..<min(count, (c + 1) * chunk) { body(i) }
        }
    }

    @Test("Datei mit versiegelten Einträgen: jedes Byte gekippt → corruptFile; Angreifer mit neuer Prüfsumme → nie Erfolg")
    func datei() throws {
        let t = try SchutzTresor.make()
        for p: EntryProtection in [.normal, .fingerabdruck, .maximal, .festung] {
            try t.vault.upsert(schutzEntry("E\(p.rawValue)", protection: p))
        }
        let bytes = try t.f.fileBytes()
        let pw = try PasswordNormalizer.secureBytes(KT.pw1)
        let r = try RecoveryCodeCodec.decode(t.f.code)
        // Kontrolle: unverändert öffnen beide Wege, der Notfallweg entsiegelt
        let file = try VaultFile.parse(bytes)
        _ = try VaultCrypto.openWithPassword(file, password: pw, limits: .testing)
        var control = try VaultCrypto.openWithRecovery(file, r: r).content
        try control.unsealAll(r: r, header: file.header)
        #expect(control.entries.allSatisfy { !$0.secretsSealed })

        let findings = Findings()
        forEachPosition(bytes.count) { i in
            var b = bytes
            b[i] ^= 0x01
            for path in 0..<2 {
                do {
                    let f = try VaultFile.parse(b)
                    _ = path == 0 ? try VaultCrypto.openWithPassword(f, password: pw, limits: .testing)
                        : try VaultCrypto.openWithRecovery(f, r: r)
                    findings.add("ok \(i)")
                } catch let e as SiegelError {
                    if e != .corruptFile("file.checksum") { findings.add("\(i): \(e)") }
                } catch {
                    findings.add("\(i): fremder Fehler")
                }
            }
        }
        let body = bytes.count - FileFormat.checksumBytes
        forEachPosition(body) { i in
            var b = bytes
            b[i] ^= 0x80
            let forged = KT.withFixedChecksum(b)
            do {
                let f = try VaultFile.parse(forged)
                _ = try VaultCrypto.openWithPassword(f, password: pw, limits: .testing)
                findings.add("pw ok \(i)")
            } catch {}
            do {
                let f = try VaultFile.parse(forged)
                var c = try VaultCrypto.openWithRecovery(f, r: r).content
                try c.unsealAll(r: r, header: f.header)
                findings.add("rec ok \(i)")
            } catch {}
        }
        #expect(findings.all.isEmpty, "\(findings.all.prefix(10))")
    }

    @Test("Versiegelte Teile manipuliert (Blob, Kapseln, Umschlag): Aufdecken und Notfallweg nie mit falschem Inhalt")
    func versiegelteTeile() async throws {
        let t = try SchutzTresor.make()
        let e = schutzEntry("F", protection: .festung)
        try t.vault.upsert(e)
        let content = try #require(t.vault.contentForTesting)
        let entry = try #require(content.entries.first { $0.id == e.id })
        let x = try #require(content.sealed[e.id])
        let vid = VaultHeader.bytes(of: t.vault.vaultID)
        let keys = try content.sealingKeys(vaultID: vid)
        let header = try #require(t.vault.headerForTesting)
        let group = try #require(content.recoveryGroups.first { $0.mask == .all })
        let kitKeys = try #require(EntrySealing.kitPrivateKeys(r: try RecoveryCodeCodec.decode(t.f.code), header: header))
        let gk = try EntrySealing.openGroup(group, kit: kitKeys, vaultID: vid)
        let provider = t.p
        let expected = EntrySecrets(e)

        @Sendable func reveal(_ y: SealedSecrets) async -> EntrySecrets? {
            do {
                let released = try await EntrySealing.release(y.blob.factors, id: e.id, mask: .all, keys: keys.factors,
                                                              vaultID: vid, provider: provider)
                guard let pt = try EntrySealing.open(y.blob, id: e.id, s: 5, mask: .all, adLabel: EntrySealing.entryAD,
                                                     base: keys.base, vaultID: vid, released: released) else { return nil }
                return try EntrySealing.decodeSecrets(pt)
            } catch {
                return nil
            }
        }
        @Sendable func viaRecovery(_ y: SealedSecrets) -> EntrySecrets? {
            try? VaultContent.openViaGroup(y, entry: entry, group: gk, vaultID: vid)
        }
        #expect(await reveal(x) == expected)
        #expect(viaRecovery(x) == expected)

        // Varianten: jedes Byte jedes Feldes gekippt; `usedByReveal`/`usedByRecovery`: Feld fliesst in den Weg ein.
        struct Variant: Sendable { let y: SealedSecrets; let field: String; let reveal: Bool; let recovery: Bool }
        var variants: [Variant] = []
        func add(_ field: String, _ count: Int, reveal: Bool, recovery: Bool, _ flip: (inout SealedSecrets, Int) -> Void) {
            for i in 0..<count {
                var y = x
                flip(&y, i)
                variants.append(Variant(y: y, field: field, reveal: reveal, recovery: recovery))
            }
        }
        add("nonce", x.blob.nonce.count, reveal: true, recovery: true) { $0.blob.nonce[$1] ^= 0x01 }
        add("ct", x.blob.ciphertext.count, reveal: true, recovery: true) { $0.blob.ciphertext[$1] ^= 0x01 }
        add("se", 65, reveal: true, recovery: false) { y, i in
            if var se = y.blob.factors.seEphemeral { se[i] ^= 0x01; y.blob.factors.seEphemeral = se }
        }
        add("card.ctM", RecoveryKEM.ctMBytes, reveal: true, recovery: false) { y, i in y.blob.factors.card?.ctM[i] ^= 0x01 }
        add("card.ctX", RecoveryKEM.ctXBytes, reveal: true, recovery: false) { y, i in y.blob.factors.card?.ctX[i] ^= 0x01 }
        add("fido.ctM", RecoveryKEM.ctMBytes, reveal: true, recovery: false) { y, i in y.blob.factors.fido?.ctM[i] ^= 0x01 }
        add("fido.ctX", RecoveryKEM.ctXBytes, reveal: true, recovery: false) { y, i in y.blob.factors.fido?.ctX[i] ^= 0x01 }
        add("rec.ctM", RecoveryKEM.ctMBytes, reveal: false, recovery: true) { $0.recovery.capsule.ctM[$1] ^= 0x01 }
        add("rec.ctX", RecoveryKEM.ctXBytes, reveal: false, recovery: true) { $0.recovery.capsule.ctX[$1] ^= 0x01 }
        add("rec.key", AEAD.wrappedBytes, reveal: false, recovery: true) { $0.recovery.wrapped[$1] ^= 0x01 }

        let findings = Findings()
        let all = variants
        await withTaskGroup(of: Void.self) { group in
            let chunk = 64
            for start in stride(from: 0, to: all.count, by: chunk) {
                group.addTask {
                    for v in all[start..<min(all.count, start + chunk)] {
                        let r = await reveal(v.y)
                        if v.reveal ? r != nil : r != expected { findings.add("reveal \(v.field)") }
                    }
                }
            }
        }
        forEachPosition(all.count) { i in
            let v = all[i]
            let r = viaRecovery(v.y)
            if v.recovery ? r != nil : r != expected { findings.add("recovery \(v.field)") }
        }
        #expect(findings.all.isEmpty, "\(findings.all.prefix(10))")
    }
}

/// Feste Testvektoren der Eintrags-Kryptografie (unabhängig mit Python `hmac`/`hashlib` nachgerechnet) und die
/// Bindung von Schutz und Maske an K und AD.
@Suite("Eintrags-Schutz: Testvektoren und Bindung")
struct KernSchutzVektorTests {
    private let entryID = UUID(uuidString: "11111111-2222-4333-8444-555555555555") ?? UUID()

    @Test("KAT: base, ss_se, K (Schutz 5 und 2), reuseTag (NFC), Kombinierer mit entryID")
    func vektoren() throws {
        let ebk = try SecureBytes.copy(Array(1...32) as [UInt8])
        let id = VaultHeader.bytes(of: entryID)
        let base = try EntrySealing.base(ebk, id: id)
        #expect(base.hexForTesting() == "f2ed345a214a17f411de468e98f4c24b7902992a531684b8c71ce2bccbeb8c69")
        let ssSE = try ([UInt8](repeating: 0x33, count: 32)).withUnsafeBytes { try EntrySealing.seSecret($0, id: id) }
        #expect(ssSE.hexForTesting() == "8dd0e9b6ecf256c901194453887d4a38716a47a923b9335bb757298f6156039d")
        let card = try SecureBytes.copy([UInt8](repeating: 0x44, count: 32))
        let fido = try SecureBytes.copy([UInt8](repeating: 0x55, count: 32))
        let k5 = try EntrySealing.entryKey(parts: [base, ssSE, card, fido], id: id, s: 5, mask: .all)
        #expect(k5.hexForTesting() == "7458486fbc1ed731ff768c3edcf2c4624f4836ea1e7ce26cfd8bf4d3a0a9ec40")
        let k2 = try EntrySealing.entryKey(parts: [base, ssSE], id: id, s: 2, mask: [.secureEnclave])
        #expect(k2.hexForTesting() == "4ecabd6048b4f76db1f1bf01086f10af1b19f06dd474a322d2b7f02f87f723a5")
        // falsche Anzahl Teile für die Maske → Fehler statt stiller Ableitung
        #expect(throws: SiegelError.crypto("entry.key")) {
            try EntrySealing.entryKey(parts: [base], id: id, s: 2, mask: [.secureEnclave])
        }
        let rk = try EntrySealing.reuseKey(ebk)
        #expect(rk.hexForTesting() == "23716ae24e05679cdac85914d15aba3857bef530b729432516d0d3d2c9c51dac")
        #expect(KT.hex(EntrySealing.reuseTag(key: rk, password: "Passwort-a\u{0308}") ?? []) == "174f4b195dcaa51999f0192d5dfbd26a")
        #expect(EntrySealing.reuseTag(key: rk, password: "Passwort-ä") == EntrySealing.reuseTag(key: rk, password: "Passwort-a\u{0308}"))
        #expect(EntrySealing.reuseTag(key: rk, password: "") == nil)
        let ss = [UInt8](repeating: 0x61, count: 32)
        let sx = [UInt8](repeating: 0x62, count: 32)
        let combined = try ss.withUnsafeBytes { m in
            try sx.withUnsafeBytes { x in
                try RecoveryKEM.combine(label: EntrySealing.cardLabel, context: id, ssM: m, ssX: x,
                                        ctX: [UInt8](repeating: 0x63, count: 32), pkX: [UInt8](repeating: 0x64, count: 32),
                                        ctM: [UInt8](repeating: 0x65, count: 1568), pkM: [UInt8](repeating: 0x66, count: 1568))
            }
        }
        #expect(combined.hexForTesting() == "56bed5e23780b1f2de4b58ecac2674b2ca957b26be0fa72a88d044f29ef2839f")
    }

    @Test("AD bindet vaultID, entryID, Schutz und Maske; K hängt an Schutz und Maske")
    func bindung() throws {
        let t = try SchutzTresor.make()
        let content = try #require(t.vault.contentForTesting)
        let vid = VaultHeader.bytes(of: t.vault.vaultID)
        let keys = try content.sealingKeys(vaultID: vid)
        let plain = try EntrySealing.encodeSecrets(EntrySecrets(password: "geheim"))
        let (blob, k) = try EntrySealing.seal(plain, id: entryID, s: 3, mask: [.secureEnclave],
                                              adLabel: EntrySealing.entryAD, keys: keys)
        let id = VaultHeader.bytes(of: entryID)
        func opens(_ ad: [UInt8]) -> Bool { AEAD.open(key: k, nonce: blob.nonce, ciphertext: blob.ciphertext, ad: ad) != nil }
        #expect(opens(EntrySealing.ad(EntrySealing.entryAD, vaultID: vid, id: id, s: 3, mask: [.secureEnclave])))
        #expect(!opens(EntrySealing.ad(EntrySealing.entryAD, vaultID: vid, id: id, s: 2, mask: [.secureEnclave])))
        #expect(!opens(EntrySealing.ad(EntrySealing.entryAD, vaultID: vid, id: id, s: 3, mask: [.secureEnclave, .card])))
        #expect(!opens(EntrySealing.ad(EntrySealing.entryAD, vaultID: vid, id: VaultHeader.bytes(of: UUID()), s: 3,
                                       mask: [.secureEnclave])))
        #expect(!opens(EntrySealing.ad(EntrySealing.entryAD, vaultID: randomBytes(16), id: id, s: 3, mask: [.secureEnclave])))
        #expect(!opens(EntrySealing.ad(EntrySealing.anchorAD, vaultID: vid, id: id, s: 3, mask: [.secureEnclave])))
        // Gleiche Faktor-Teile, andere Schutz-Angabe → anderes K
        let parts = [try EntrySealing.base(keys.base, id: id), try SecureBytes.random(count: 32)]
        let a = try EntrySealing.entryKey(parts: parts, id: id, s: 3, mask: [.secureEnclave])
        let b = try EntrySealing.entryKey(parts: parts, id: id, s: 2, mask: [.secureEnclave])
        #expect(!a.constantTimeEquals(b))
    }
}
