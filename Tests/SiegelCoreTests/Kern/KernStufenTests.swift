import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

@Suite("Faktoren und Stufen (§13, §14, §22)")
struct KernStufenTests {
    // MARK: Ableitung

    @Test("Jeder fehlende Faktor → factorMissing (vor Argon2), falsche Karte → wrongCard, falscher Wert → wrongPassword")
    func fehlendeUndFalscheFaktoren() throws {
        let (f, k, _) = try KernStufen.make(.festung)
        f.vault.lock()
        let counter = TestHooks.Counter()
        try TestHooks.$kdfCounter.withValue(counter) {
            for kind in FactorKind.allCases {
                var set = FactorSet.all
                set.remove(FactorSet(rawValue: kind.rawValue))
                #expect(throws: SiegelError.factorMissing(kind)) {
                    try f.store.unlock(masterPassword: KT.pw1, factors: try k.secrets(set))
                }
            }
            // Reihenfolge der Ableitung: zuerst Secure Enclave
            #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try f.store.unlock(masterPassword: KT.pw1) }
            var wrongCard = try k.secrets()
            wrongCard.card = CardCode.generate()
            #expect(throws: SiegelError.wrongCard) { try f.store.unlock(masterPassword: KT.pw1, factors: wrongCard) }
        }
        #expect(counter.value == 0)
        var wrongSE = try k.secrets()
        wrongSE.secureEnclave = try k.secret(randomBytes(32))
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: KT.pw1, factors: wrongSE) }
        var wrongKey = try k.secrets()
        wrongKey.securityKey = try k.secret(randomBytes(32))
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: KT.pw1, factors: wrongKey) }
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: KT.pw2, factors: try k.secrets()) }
        // Alle richtig; zusätzliche Faktoren stören nicht
        let v = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1, factors: try k.secrets())))
        #expect(v.level == .festung)
        #expect(v.verify(masterPassword: KT.pw1, factors: try k.secrets()))
        #expect(!v.verify(masterPassword: KT.pw1, factors: try k.secrets([.secureEnclave, .card])))
        #expect(!v.verify(masterPassword: KT.pw1))
    }

    @Test("Factor-Wert mit falscher Länge → crypto(factor.length)")
    func faktorLaenge() {
        #expect(throws: SiegelError.crypto("factor.length")) { try FactorSecret(copying: [UInt8](repeating: 1, count: 31)) }
        #expect(throws: SiegelError.crypto("factor.length")) { try FactorSecret(copying: [UInt8](repeating: 1, count: 33)) }
    }

    // MARK: Stufenwechsel

    @Test("Aufwärts 1 → 2 → 3 → 4 → 5: jede Stufe rotiert DEK und Salz und verlangt ihre Faktoren")
    func aufwaerts() throws {
        let f = try KernVault.make()
        let k = try KernFaktoren()
        try f.vault.upsert(kernEntry("Bank"))
        var current: FactorSet = []
        for level in [SecurityLevel.erhoeht, .hoch, .maximal, .festung] {
            let oldFile = try f.parsedFile()
            let oldDEK = try f.vault.dekForTesting()
            let kit = try KernStufen.change(f.vault, to: level, faktoren: k, current: current,
                                            newMaterial: try k.material(for: level).withoutExisting(current))
            let newFile = try f.parsedFile()
            #expect(newFile.header.salt != oldFile.header.salt)
            #expect(try !f.vault.dekForTesting().constantTimeEquals(oldDEK))
            #expect(throws: SiegelError.corruptFile("payload.auth")) { try VaultCrypto.decryptPayload(newFile, dek: oldDEK) }
            #expect(newFile.header.factors == level.factors)
            #expect(newFile.header.recoveryScheme == level.recoveryScheme)
            #expect(newFile.header.kdf == f.store.limits.profile(for: level))
            #expect(f.vault.level == level)
            #expect(f.vault.policy == level.policy)
            #expect(f.vault.headerInfo == (try f.store.inspect()))
            // Ein neues Kit (Wechsel auf 2 aus 3) ist mit der Bestätigung bestätigt; sonst bleibt der Stand.
            #expect(f.vault.recoveryConfirmed == (level >= .maximal))
            if level == .maximal { #expect(kit?.scheme == .shamir2of3) }
            #expect(f.localBackups().contains { $0.reason == "stufenwechsel" && $0.generation == oldFile.generation })
            current = level.factors
            // neu entsperren: nur mit genau den Faktoren der Stufe
            let again = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1, factors: try k.secrets(current))))
            #expect(again.entries.map(\.title) == ["Bank"])
            #expect(again.level == level)
        }
        #expect(f.vault.enrolledFactors == .all)
        #expect(f.vault.headerInfo.seKeyID == k.seKeyID)
        #expect(f.vault.headerInfo.cardTag == CardCode.tag(for: k.q, vaultID: f.vault.vaultID))
        #expect(f.vault.headerInfo.fidoCredentialID == Data(k.credentialID))
        #expect(f.vault.headerInfo.fidoSalt == Data(k.salt))
    }

    @Test("Abwärts 5 → 1: Faktoren fallen weg, Entsperr-SE-Schlüssel wird erst nach dem Schreiben entfernt")
    func abwaerts() throws {
        let (f, k, kit) = try KernStufen.make(.festung)
        #expect(kit?.scheme == .shamir2of3)
        try f.vault.upsert(kernEntry("A"))
        // Stufe 5 versiegelt neue Einträge (Schutz 2). Hier offen, damit der Kit-Wechsel ohne Freigabe geht
        // (Kit-Wechsel mit versiegelten Einträgen: KernSchutzTests).
        let a = try #require(f.vault.entries.first)
        #expect(a.protection == .fingerabdruck && a.secretsSealed)
        try f.vault.setProtection(.normal, id: a.id, secrets: EntrySecrets(password: "Geheim-123"))
        // SE-Ablage wie vom Hardware-Modul angelegt
        try FileIO.ensureDirectory(f.store.hardwareDirectory)
        let blob = f.store.hardwareDirectory.appendingPathComponent(k.seKeyID.uuidString + ".siegelhw")
        let other = f.store.hardwareDirectory.appendingPathComponent(k.entryKeyID.uuidString + ".siegelhw")
        try FileIO.writeExclusive(blob, bytes: [1, 2, 3])
        try FileIO.writeExclusive(other, bytes: [4, 5, 6])
        // 5 → 3 verlangt ein neues Kit (2 aus 3 → ein Code)
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try f.vault.changeSecurityLevel(to: .hoch, masterPassword: KT.pw1, currentFactors: try k.secrets(),
                                            newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        }
        // Gescheitertes Schreiben (falsches Passwort) entfernt nichts
        let single = try f.vault.prepareRecovery(masterPassword: KT.pw1, factors: try k.secrets(), scheme: .single)
        #expect(throws: SiegelError.wrongPassword) {
            try f.vault.changeSecurityLevel(to: .hoch, masterPassword: KT.pw2, currentFactors: try k.secrets(),
                                            newFactors: NewFactorMaterial(), recovery: single,
                                            recoveryConfirmation: KernStufen.confirmation(single))
        }
        #expect(FileIO.exists(blob))
        try f.vault.changeSecurityLevel(to: .hoch, masterPassword: KT.pw1, currentFactors: try k.secrets(),
                                        newFactors: NewFactorMaterial(), recovery: single,
                                        recoveryConfirmation: KernStufen.confirmation(single))
        #expect(f.vault.level == .hoch)
        #expect(f.vault.headerInfo.factors == [.secureEnclave])
        #expect(f.vault.headerInfo.recoveryScheme == .single)
        #expect(f.vault.kitID == single.code.kitID)
        #expect(FileIO.exists(blob))          // SE bleibt in Stufe 3
        #expect(try f.store.checkRecoveryCode(single.code.formatted) == .exact)
        try KernStufen.change(f.vault, to: .standard, faktoren: k, current: [.secureEnclave],
                              newMaterial: NewFactorMaterial())
        #expect(f.vault.headerInfo.factors.isEmpty)
        #expect(f.vault.headerInfo.seKeyID == nil)
        #expect(!FileIO.exists(blob))         // Entsperr-Schlüssel entfernt
        #expect(FileIO.exists(other))         // Eintrags-Schlüssel bleibt
        #expect(f.vault.enrolledFactors == .all)   // Eintrags-Faktoren bleiben eingerichtet
        f.vault.lock()
        let v = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)))
        #expect(v.entries.map(\.title) == ["A"])
        #expect(v.level == .standard)
    }

    @Test("Stufenwechsel braucht Passwort und alle aktuellen Faktoren; Fehler schreiben nichts")
    func wechselBrauchtAlles() throws {
        let (f, k, _) = try KernStufen.make(.hoch)
        let gen = f.vault.generation
        let mat = try k.material(for: .hoch)
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
            try f.vault.changeSecurityLevel(to: .erhoeht, masterPassword: KT.pw1, currentFactors: FactorSecrets(),
                                            newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        }
        #expect(throws: SiegelError.wrongPassword) {
            try f.vault.changeSecurityLevel(to: .erhoeht, masterPassword: KT.pw2, currentFactors: try k.secrets([.secureEnclave]),
                                            newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        }
        // Ziel verlangt eine Karte, die es nicht gibt
        let shamir = try f.vault.prepareRecovery(masterPassword: KT.pw1, factors: try k.secrets([.secureEnclave]),
                                                 scheme: .shamir2of3)
        #expect(throws: SiegelError.factorMissing(.card)) {
            try f.vault.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1,
                                            currentFactors: try k.secrets([.secureEnclave]),
                                            newFactors: NewFactorMaterial(), recovery: shamir,
                                            recoveryConfirmation: KernStufen.confirmation(shamir))
        }
        // Falsche Bestätigung → nichts geschrieben
        var wrong = KernStufen.confirmation(shamir)
        wrong[2] = wrong[2] == "00000" ? "11111" : "00000"
        #expect(throws: SiegelError.recoveryConfirmationMismatch) {
            try f.vault.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1,
                                            currentFactors: try k.secrets([.secureEnclave]),
                                            newFactors: mat, recovery: shamir, recoveryConfirmation: wrong)
        }
        // Kit mit falschem Schema für die Zielstufe
        let single = try f.vault.prepareRecovery(masterPassword: KT.pw1, factors: try k.secrets([.secureEnclave]),
                                                 scheme: .single)
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try f.vault.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1,
                                            currentFactors: try k.secrets([.secureEnclave]), newFactors: mat,
                                            recovery: single, recoveryConfirmation: KernStufen.confirmation(single))
        }
        #expect(f.vault.generation == gen)
        #expect(try f.parsedFile().generation == gen)
        #expect(f.vault.level == .hoch)
    }

    @Test("enrollFactors: Eintrags-Faktoren ohne Stufe; dieselbe Karte/derselbe Schlüssel öffnet später den Tresor")
    func einrichten() throws {
        let f = try KernVault.make()
        let k = try KernFaktoren()
        let dekBefore = try f.vault.dekForTesting()
        let saltBefore = try f.parsedFile().header.salt
        #expect(f.vault.enrolledFactors.isEmpty)
        #expect(throws: SiegelError.wrongPassword) {
            try f.vault.enrollFactors(NewFactorMaterial(card: k.card), masterPassword: KT.pw2, currentFactors: FactorSecrets())
        }
        try f.vault.enrollFactors(NewFactorMaterial(entryKey: k.entryKey, card: k.card, securityKey: try k.securityKey),
                                  masterPassword: KT.pw1, currentFactors: FactorSecrets())
        #expect(f.vault.enrolledFactors == .all)
        #expect(f.vault.level == .standard)
        // kein Zugangswechsel: DEK und Salz bleiben
        #expect(try f.vault.dekForTesting().constantTimeEquals(dekBefore))
        #expect(try f.parsedFile().header.salt == saltBefore)
        #expect(f.vault.securityKeyCredential?.credentialID == Data(k.credentialID))
        // öffentliche Teile im Inhalt
        let content = try #require(f.vault.contentForTesting)
        let vid = VaultHeader.bytes(of: f.vault.vaultID)
        #expect(content.entryFactors.card?.pk == (try EntryKeyDerivation.cardPublicKeys(q: k.q, vaultID: vid)))
        #expect(content.entryFactors.securityKey?.pk
                == (try EntryKeyDerivation.fidoPublicKeys(entryOutput: try k.secret(k.entryOutput), vaultID: vid)))
        #expect(content.entryFactors.secureEnclave?.publicKey == Array(k.entryPublicKey))
        // bleibt nach dem Entsperren
        f.vault.lock()
        let v = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)))
        #expect(v.enrolledFactors == .all)
        // Stufe 4 mit der eingerichteten Karte (gescannt, ohne neues Material) …
        let other = CardCode.generate()
        let shamir = try v.prepareRecovery(masterPassword: KT.pw1, factors: FactorSecrets(), scheme: .shamir2of3)
        let se = NewFactorMaterial(secureEnclave: try k.seEnrollment)
        #expect(throws: SiegelError.wrongCard) {
            try v.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1, currentFactors: FactorSecrets(card: other),
                                      newFactors: se, recovery: shamir, recoveryConfirmation: KernStufen.confirmation(shamir))
        }
        try v.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1, currentFactors: FactorSecrets(card: k.q),
                                  newFactors: se, recovery: shamir, recoveryConfirmation: KernStufen.confirmation(shamir))
        #expect(v.headerInfo.cardTag == CardCode.tag(for: k.q, vaultID: v.vaultID))
        // … und Stufe 5 mit dem eingerichteten Sicherheitsschlüssel (Ausgabe über den Prüfwert bestätigt)
        var current = try k.secrets([.secureEnclave, .card])
        current.securityKey = try k.secret(randomBytes(32))
        #expect(throws: SiegelError.wrongPassword) {
            try v.changeSecurityLevel(to: .festung, masterPassword: KT.pw1, currentFactors: current,
                                      newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        }
        current.securityKey = try k.secret(k.output)
        try v.changeSecurityLevel(to: .festung, masterPassword: KT.pw1, currentFactors: current,
                                  newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
        #expect(v.headerInfo.fidoCredentialID == Data(k.credentialID))
        #expect(v.headerInfo.fidoSalt == Data(k.salt))
        v.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1, factors: try k.secrets())) != nil)
    }

    @Test("enrollFactors: andere Karte/anderer Schlüssel als zum Öffnen wird abgelehnt; Material wird geprüft")
    func einrichtenGeprueft() throws {
        let (f, k, _) = try KernStufen.make(.festung)
        let gen = f.vault.generation
        #expect(throws: SiegelError.wrongCard) {
            try f.vault.enrollFactors(NewFactorMaterial(card: CardEnrollment(q: CardCode.generate())),
                                      masterPassword: KT.pw1, currentFactors: try k.secrets())
        }
        let otherKey = SecurityKeyEnrollment(credentialID: Data(randomBytes(32)), salt: Data(randomBytes(32)),
                                             output: try k.secret(randomBytes(32)), entrySalt: Data(randomBytes(32)),
                                             entryOutput: try k.secret(randomBytes(32)))
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try f.vault.enrollFactors(NewFactorMaterial(securityKey: otherKey), masterPassword: KT.pw1,
                                      currentFactors: try k.secrets())
        }
        // Dasselbe Material nochmals: nichts zu schreiben
        try f.vault.enrollFactors(NewFactorMaterial(card: k.card, securityKey: try k.securityKey),
                                  masterPassword: KT.pw1, currentFactors: try k.secrets())
        #expect(f.vault.generation == gen)
        // Ungültiges Material
        let bad: [NewFactorMaterial] = [
            NewFactorMaterial(entryKey: EntryKeyEnrollment(keyID: UUID(), publicKey: Data(repeating: 4, count: 65))),
            NewFactorMaterial(entryKey: EntryKeyEnrollment(keyID: UUID(), publicKey: Data(repeating: 4, count: 33))),
            NewFactorMaterial(securityKey: SecurityKeyEnrollment(credentialID: Data(count: 8), salt: Data(randomBytes(32)),
                                                                 output: try k.secret(k.output), entrySalt: Data(randomBytes(32)),
                                                                 entryOutput: try k.secret(k.entryOutput))),
            NewFactorMaterial(securityKey: SecurityKeyEnrollment(credentialID: Data(randomBytes(20)), salt: Data(k.salt),
                                                                 output: try k.secret(k.output), entrySalt: Data(k.salt),
                                                                 entryOutput: try k.secret(k.entryOutput))),
        ]
        for m in bad {
            let e = #expect(throws: SiegelError.self) {
                try f.vault.enrollFactors(m, masterPassword: KT.pw1, currentFactors: try k.secrets())
            }
            if case .crypto = e {} else { Issue.record("erwartet crypto(...)") }
        }
        #expect(f.vault.generation == gen)
    }

    @Test("Neue Faktoren ersetzen alte: neuer SE-Schlüssel und neue Karte; alter Entsperr-Schlüssel wird entfernt")
    func ersetzen() throws {
        let (f, k, _) = try KernStufen.make(.maximal)
        try FileIO.ensureDirectory(f.store.hardwareDirectory)
        let oldBlob = f.store.hardwareDirectory.appendingPathComponent(k.seKeyID.uuidString.lowercased() + ".siegelhw")
        try FileIO.writeExclusive(oldBlob, bytes: [1])
        let n = try KernFaktoren()
        try f.vault.changeSecurityLevel(to: .maximal, masterPassword: KT.pw1, currentFactors: try k.secrets([.secureEnclave, .card]),
                                        newFactors: NewFactorMaterial(secureEnclave: try n.seEnrollment, card: n.card),
                                        recovery: nil, recoveryConfirmation: [])
        #expect(!FileIO.exists(oldBlob))
        #expect(f.vault.headerInfo.seKeyID == n.seKeyID)
        f.vault.lock()
        #expect(throws: SiegelError.wrongCard) {
            try f.store.unlock(masterPassword: KT.pw1, factors: try k.secrets([.secureEnclave, .card]))
        }
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1, factors: try n.secrets([.secureEnclave, .card]))) != nil)
    }

    // MARK: Regeln der Stufe im Kern

    @Test("KDF-Profil: in Stufe 3–5 nicht schwächer als Stark; CSV-Export ab Stufe 4 gesperrt")
    func regeln() throws {
        let (f, k, _) = try KernStufen.make(.hoch)
        #expect(f.vault.kdf == f.store.limits.profile(for: .hoch))
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw1, factors: try k.secrets([.secureEnclave]),
                                             kdf: f.store.limits.profile(for: .standard))
        }
        // Passwortwechsel behält die Faktoren
        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2, factors: try k.secrets([.secureEnclave]))
        #expect(f.vault.headerInfo.factors == [.secureEnclave])
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try f.store.unlock(masterPassword: KT.pw2) }
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw2, factors: try k.secrets([.secureEnclave]))) != nil)
        // CSV in Stufe 3 erlaubt (mit Faktor), ohne Faktor nicht
        let target = f.dir.sub("Export")
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
            try f.vault.exportCSV(toParent: target, masterPassword: KT.pw2)
        }
        _ = try f.vault.exportCSV(toParent: target, masterPassword: KT.pw2, factors: try k.secrets([.secureEnclave]))
        let (g, gk, _) = try KernStufen.make(.maximal)
        let counter = TestHooks.Counter()
        let gFactors = try gk.secrets([.secureEnclave, .card])
        TestHooks.$kdfCounter.withValue(counter) {
            #expect(throws: SiegelError.notAllowedAtLevel) {
                try g.vault.exportCSV(toParent: g.dir.sub("Export"), masterPassword: KT.pw1, factors: gFactors)
            }
        }
        #expect(counter.value == 0)
        #expect(g.vault.policy.allowCSVExport == false)
        #expect(g.vault.policy.defaultEntryProtection == .fingerabdruck)
    }

    @Test("Sicherungen einsetzen braucht die Faktoren der Sicherung")
    func sicherungenMitFaktoren() throws {
        let (f, k, _) = try KernStufen.make(.erhoeht)
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        let newest = try #require(f.localBackups().first)
        f.vault.lock()
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try f.store.restoreBackup(newest, masterPassword: KT.pw1) }
        let v = try f.store.restoreBackup(newest, masterPassword: KT.pw1, factors: try k.secrets([.secureEnclave]))
        #expect(v.entries.map(\.title) == ["A"])
        #expect(v.level == .erhoeht)
        #expect(v.headerInfo.seKeyID == k.seKeyID)
        v.lock()
        // Datei beschädigen: neueste lesbare Sicherung nur mit Faktor
        var b = try f.fileBytes()
        b[b.count / 2] ^= 1
        try f.writeFile(b)
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
            try f.store.restoreNewestReadableBackup(masterPassword: KT.pw1)
        }
        let (w, used) = try f.store.restoreNewestReadableBackup(masterPassword: KT.pw1,
                                                                factors: try k.secrets([.secureEnclave]))
        #expect(used.vaultID == w.vaultID)
        #expect(w.level == .erhoeht)
        // Einspielen einer Kopie
        let kopie = f.dir.url.appendingPathComponent("kopie.siegel")
        try f.store.exportBackup(to: kopie)
        let dir = KernTempDir()
        let other = VaultStore(directory: dir.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try other.importBackup(from: kopie, masterPassword: KT.pw1) }
        let imported = try other.importBackup(from: kopie, masterPassword: KT.pw1, factors: try k.secrets([.secureEnclave]))
        #expect(imported.level == .erhoeht)
        #expect(try other.inspect().factors == [.secureEnclave])
    }

    @Test("Notfall-Wiederherstellung setzt Stufe 1: keine Faktoren, Einträge Schutz 1, Eintrags-Faktoren entfernt")
    func notfallSetztStufeEins() throws {
        let (f, k, kit) = try KernStufen.make(.maximal)
        var e = kernEntry("Geschützt")
        e.protection = .maximal
        try f.vault.upsert(e)
        #expect(f.vault.entries.first?.protection == .maximal)
        f.vault.lock()
        let shares = try #require(kit?.shares.map(\.formatted))
        #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try f.store.unlock(masterPassword: KT.pw1) }
        let v = try f.store.recover(shares: [shares[2], shares[0]], newMasterPassword: KT.pw2, kdf: KT.kdf)
        #expect(v.level == .standard)
        #expect(v.enrolledFactors.isEmpty)
        #expect(v.entries.first?.protection == .normal)
        #expect(v.headerInfo.factors.isEmpty)
        #expect(v.headerInfo.recoveryScheme == .shamir2of3)   // die Teile gelten weiter
        #expect(v.recoveryConfirmed)
        v.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw2)) != nil)
        _ = k
    }
}

extension NewFactorMaterial {
    /// Ohne das Material für Faktoren, die schon im Kopf stehen (sie bleiben über `currentFactors`).
    func withoutExisting(_ existing: FactorSet) -> NewFactorMaterial {
        NewFactorMaterial(secureEnclave: existing.contains(.secureEnclave) ? nil : secureEnclave,
                          entryKey: existing.isEmpty ? entryKey : nil,
                          card: existing.contains(.card) ? nil : card,
                          securityKey: existing.contains(.securityKey) ? nil : securityKey)
    }
}
