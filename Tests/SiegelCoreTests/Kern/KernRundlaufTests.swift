import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

@Suite("Rundlauf und Grundlagen")
struct KernRundlaufTests {
    @Test("Anlegen → Einträge → Sperren → Entsperren")
    func rundlauf() throws {
        let f = try KernVault.make()
        #expect(f.vault.generation == 1)
        #expect(f.vault.entries.isEmpty)
        #expect(f.vault.recoveryConfirmed == false)
        #expect(f.vault.kdf == KT.kdf)
        #expect(f.vault.kitID == f.pending.code.kitID)
        #expect(f.pending.code.groups.count == 11)
        #expect(f.pending.code.groups.allSatisfy { $0.count == 5 })
        #expect(f.pending.confirmationGroups.count == 2)
        #expect(Set(f.pending.confirmationGroups).count == 2)
        #expect(f.pending.confirmationGroups.allSatisfy { (0...10).contains($0) })

        var e = kernEntry("Bank", user: "anna.muster", password: "Kontostand-99", url: "https://bank.example.ch",
                      notes: "Zeile 1\nZeile 2 äöü «»")
        try f.vault.upsert(e)
        e.title = "Bank (privat)"
        try f.vault.upsert(e)
        try f.vault.upsert(kernEntry("Mail", user: "anna@example.ch", password: "Post-Fach-7"))
        #expect(f.vault.generation == 4)
        let expected = f.vault.allEntriesForTesting
        f.vault.lock()
        #expect(f.vault.isLocked)

        let again = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)))
        #expect(again.allEntriesForTesting == expected)
        #expect(again.generation == 4)
        #expect(again.vaultID == f.vault.vaultID)
        #expect(again.entries.map(\.title) == ["Bank (privat)", "Mail"])
    }

    @Test("Falsches Passwort → wrongPassword")
    func falschesPasswort() throws {
        let f = try KernVault.make()
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: KT.pw2) }
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: "") }
        #expect(f.vault.verify(masterPassword: KT.pw1))
        #expect(f.vault.verify(masterPassword: KT.pw2) == false)
    }

    @Test("crypto_pwhash-Fehler → kdfFailed, nie wrongPassword")
    func kdfFailedIstNichtWrongPassword() throws {
        let f = try KernVault.make()
        TestHooks.$forceKDFFailure.withValue(true) {
            #expect(throws: SiegelError.kdfFailed) { try f.store.unlock(masterPassword: KT.pw1) }
            #expect(throws: SiegelError.kdfFailed) { try f.store.unlock(masterPassword: KT.pw2) }
            #expect(throws: SiegelError.kdfFailed) { try f.vault.prepareRecovery(masterPassword: KT.pw1) }
        }
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)) != nil)
    }

    @Test("Vault fehlt / existiert schon")
    func fehltUndExistiert() throws {
        let f = try KernVault.make()
        #expect(throws: SiegelError.vaultAlreadyExists) { try f.store.create(masterPassword: KT.pw2, kdf: KT.kdf) }
        let leer = VaultStore(directory: f.dir.sub("Leer"), rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        #expect(leer.vaultExists == false)
        #expect(throws: SiegelError.vaultMissing) { try leer.unlock(masterPassword: KT.pw1) }
        #expect(throws: SiegelError.vaultMissing) { try leer.checkRecoveryCode(f.code) }
        #expect(throws: SiegelError.vaultMissing) { try leer.recover(code: f.code, newMasterPassword: KT.pw2, kdf: KT.kdf) }
    }

    @Test("Normalisierung: geschütztes Leerzeichen ≡ Leerzeichen, NFD ≡ NFC")
    func normalisierung() throws {
        #expect(PasswordNormalizer.normalize("a\u{00A0}b") == "a b")
        #expect(PasswordNormalizer.normalize("e\u{0301}") == "é")
        #expect(PasswordNormalizer.normalize("x\u{3000}y\u{2009}z") == "x y z")
        #expect(PasswordNormalizer.normalize("  rand  ") == "  rand  ")   // nichts trimmen
        #expect(Array(PasswordNormalizer.normalize("e\u{0301}").utf8) == [0xC3, 0xA9])
        #expect(VaultStore.passwordsMatch("a\u{00A0}b", "a b"))
        #expect(VaultStore.passwordsMatch("e\u{0301}", "é"))
        #expect(VaultStore.passwordsMatch("a b", "a  b") == false)
        #expect(VaultStore.passwordsMatch(" a", "a") == false)

        let nbsp = "u,F?CfDuMl\u{00A0}YWuJASPVQ*6GUG@O"
        let f = try KernVault.make(password: nbsp)
        #expect(KT.unlocked(try f.store.unlock(masterPassword: "u,F?CfDuMl YWuJASPVQ*6GUG@O")) != nil)

        let nfd = "v,:f,uX&%!kQ>Ne\u{0301}Iti@!3c>w:~"
        let g = try KernVault.make(password: nfd)
        #expect(KT.unlocked(try g.store.unlock(masterPassword: "v,:f,uX&%!kQ>NéIti@!3c>w:~")) != nil)
        #expect(throws: SiegelError.wrongPassword) { try g.store.unlock(masterPassword: "v,:f,uX&%!kQ>NeIti@!3c>w:~") }
    }

    @Test("Sperren verwirft alles, danach unbrauchbar")
    func sperren() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        let gen = f.vault.generation
        f.vault.lock()
        #expect(f.vault.isLocked)
        #expect(f.vault.entries.isEmpty)
        #expect(f.vault.deletedEntries.isEmpty)
        #expect(f.vault.masterPasswordReuse.isEmpty)
        #expect(f.vault.lastModified == nil)
        #expect(f.vault.generation == gen)
        #expect(f.vault.verify(masterPassword: KT.pw1) == false)
        #expect(throws: SiegelError.io("vault.locked")) { try f.vault.upsert(kernEntry("B")) }
        #expect(throws: SiegelError.io("vault.locked")) { try f.vault.prepareRecovery(masterPassword: KT.pw1) }
        #expect(throws: SiegelError.io("vault.locked")) { try f.vault.exportCSV(toParent: f.dir.url, masterPassword: KT.pw1) }
        #expect(throws: SiegelError.io("vault.locked")) { try f.vault.purgeBackups() }
        // Datei unverändert
        #expect(try f.parsedFile().generation == gen)
    }

    @Test("Geschwärzte Beschreibungen enthalten keine Geheimnisse")
    func geschwaerzt() throws {
        let f = try KernVault.make()
        let e = kernEntry("Titel-Geheim", user: "benutzer-geheim", password: "Passwort-Geheim", url: "https://geheim.example",
                      notes: "Notiz-Geheim")
        try f.vault.upsert(e)
        let secrets = ["Titel-Geheim", "benutzer-geheim", "Passwort-Geheim", "geheim.example", "Notiz-Geheim"]
        func check(_ s: String) {
            for secret in secrets { #expect(!s.contains(secret)) }
        }
        var dumped = ""
        dump(e, to: &dumped)
        check(String(describing: e))
        check(e.debugDescription)
        check(String(reflecting: e))
        check(dumped)

        let code = f.pending.code
        var dumpedCode = ""
        dump(code, to: &dumpedCode)
        var dumpedPending = ""
        dump(f.pending, to: &dumpedPending)
        for group in code.groups {
            #expect(!String(describing: code).contains(group))
            #expect(!code.debugDescription.contains(group))
            #expect(!dumpedCode.contains(group))
            #expect(!dumpedPending.contains(group))
            #expect(!String(describing: f.pending).contains(group))
        }

        var dumpedVault = ""
        dump(f.vault, to: &dumpedVault)
        check(String(describing: f.vault))
        check(f.vault.debugDescription)
        check(dumpedVault)

        let sb = try SecureBytes.copy(Array("Geheimnis-XYZ".utf8))
        var dumpedSB = ""
        dump(sb, to: &dumpedSB)
        #expect(String(describing: sb) == "SecureBytes(redacted)")
        #expect(!dumpedSB.contains("Geheimnis"))
        #expect(!sb.debugDescription.contains("Geheimnis"))

        let h = PasswordHistoryItem(password: "Verlauf-Geheim", changed: Date())
        #expect(!String(describing: h).contains("Verlauf-Geheim"))
    }

    @Test("Padding verschleiert kleine Grössenunterschiede")
    func padding() throws {
        let a = try KernVault.make()
        let b = try KernVault.make()
        try a.vault.upsert(kernEntry("A", notes: String(repeating: "x", count: 10)))
        try b.vault.upsert(kernEntry("Ein viel längerer Titel", notes: String(repeating: "y", count: 3000)))
        #expect(try a.fileBytes().count == b.fileBytes().count)
        let file = try a.parsedFile()
        #expect(file.ciphertext.count == PayloadCodec.blockSize + AEAD.tagBytes)
        // Grosser Inhalt → mehrere Blöcke, immer Vielfache von 16 KiB
        try a.vault.upsert(kernEntry("Gross", notes: String(repeating: "z", count: 40_000)))
        #expect((try a.parsedFile().ciphertext.count - AEAD.tagBytes) % PayloadCodec.blockSize == 0)
    }

    @Test("Feldgrenzen §3")
    func feldgrenzen() throws {
        let f = try KernVault.make()
        let ok = kernEntry(String(repeating: "t", count: 2048), user: String(repeating: "u", count: 2048),
                       password: String(repeating: "p", count: 4096), url: String(repeating: "w", count: 2048),
                       notes: String(repeating: "n", count: 256 << 10))
        try f.vault.upsert(ok)
        let gen = f.vault.generation
        #expect(throws: SiegelError.io("entry.titleTooLong")) { try f.vault.upsert(kernEntry(String(repeating: "t", count: 2049))) }
        #expect(throws: SiegelError.io("entry.passwordTooLong")) {
            try f.vault.upsert(kernEntry("x", password: String(repeating: "p", count: 4097)))
        }
        #expect(throws: SiegelError.io("entry.notesTooLong")) {
            try f.vault.upsert(kernEntry("x", notes: String(repeating: "n", count: (256 << 10) + 1)))
        }
        #expect(throws: SiegelError.io("entry.titleTooLong")) {
            try f.vault.importEntries([kernEntry(String(repeating: "ä", count: 1025))])
        }
        #expect(f.vault.generation == gen)
    }

    @Test("Verlauf: höchstens 10, jünger als 30 Tage nie verdrängt, harte Grenze 30")
    func verlauf() throws {
        let f = try KernVault.make()
        let start = Date(timeIntervalSince1970: 1_790_000_000)
        var e = kernEntry("Wechsel", password: "pw-0")
        try TestHooks.$now.withValue(start) { try f.vault.upsert(e) }
        // 15 alte Wechsel (je 40 Tage auseinander)
        for i in 1...15 {
            e.password = "pw-\(i)"
            try TestHooks.$now.withValue(start.addingTimeInterval(Double(i) * 40 * 86_400)) { try f.vault.upsert(e) }
        }
        var current = try #require(f.vault.entries.first)
        #expect(current.history.count == 10)
        #expect(current.history.first?.password == "pw-14")
        // 20 junge Wechsel innerhalb eines Tages (nach den alten)
        let late = start.addingTimeInterval(16 * 40 * 86_400)
        for i in 16...35 {
            e.password = "pw-\(i)"
            try TestHooks.$now.withValue(late.addingTimeInterval(Double(i) * 60)) { try f.vault.upsert(e) }
        }
        current = try #require(f.vault.entries.first)
        #expect(current.history.count == 20)
        // 15 weitere junge → harte Grenze 30
        for i in 36...50 {
            e.password = "pw-\(i)"
            try TestHooks.$now.withValue(late.addingTimeInterval(Double(i) * 60)) { try f.vault.upsert(e) }
        }
        current = try #require(f.vault.entries.first)
        #expect(current.history.count == 30)
        #expect(current.history.first?.password == "pw-49")
        #expect(!current.history.contains { $0.password == "pw-50" })
        // „Abbrechen“ (altes Passwort zurück): generiertes bleibt im Verlauf, aktuelles nicht
        e.password = "pw-49"
        try TestHooks.$now.withValue(late.addingTimeInterval(51 * 60)) { try f.vault.upsert(e) }
        current = try #require(f.vault.entries.first)
        #expect(current.history.first?.password == "pw-50")
        #expect(!current.history.contains { $0.password == "pw-49" })
        // created bleibt, modified wandert
        #expect(current.created == Clock.canonical(e.created))
        #expect(current.modified == Clock.canonical(late.addingTimeInterval(51 * 60)))
        try f.vault.clearHistory(id: current.id)
        #expect(f.vault.entries.first?.history.isEmpty == true)
    }

    @Test("Zuletzt gelöscht: 30 Tage, danach beim nächsten Speichern endgültig weg")
    func zuletztGeloescht() throws {
        let f = try KernVault.make()
        let t0 = Date(timeIntervalSince1970: 1_790_000_000)
        let a = kernEntry("A")
        let b = kernEntry("B")
        try TestHooks.$now.withValue(t0) {
            try f.vault.upsert(a)
            try f.vault.upsert(b)
            try f.vault.delete(id: a.id)
        }
        #expect(f.vault.entries.map(\.title) == ["B"])
        #expect(f.vault.deletedEntries.map(\.title) == ["A"])
        #expect(f.vault.lastModified == Clock.canonical(t0))
        try f.vault.restore(id: a.id)
        #expect(f.vault.deletedEntries.isEmpty)
        try TestHooks.$now.withValue(t0) { try f.vault.delete(id: a.id) }
        // nach 29 Tagen noch da
        try TestHooks.$now.withValue(t0.addingTimeInterval(29 * 86_400)) { try f.vault.upsert(b) }
        #expect(f.vault.deletedEntries.count == 1)
        // nach 31 Tagen beim nächsten Speichern weg
        try TestHooks.$now.withValue(t0.addingTimeInterval(31 * 86_400)) { try f.vault.upsert(b) }
        #expect(f.vault.deletedEntries.isEmpty)
        #expect(f.vault.allEntriesForTesting.count == 1)
        // endgültig löschen nur aus „Zuletzt gelöscht“
        #expect(throws: SiegelError.io("entry.notDeleted")) { try f.vault.purgeDeleted(id: b.id) }
        try f.vault.delete(id: b.id)
        try f.vault.purgeDeleted(id: b.id)
        #expect(f.vault.allEntriesForTesting.isEmpty)
        #expect(throws: SiegelError.io("entry.notFound")) { try f.vault.delete(id: UUID()) }
    }

    @Test("Inhalts-JSON: sortierte Schlüssel, null explizit, v = 1")
    func inhaltJSON() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        let file = try f.parsedFile()
        let dek = try f.vault.dekForTesting()
        let padded = try #require(AEAD.open(key: dek, nonce: file.nonce, ciphertext: file.ciphertext, ad: file.payloadAD))
        let json = try #require(PayloadCodec.jsonStringForTesting(padded))
        #expect(json.hasPrefix("{\"entries\":[{\"created\":"))
        #expect(json.contains("\"deletedAt\":null"))
        #expect(json.contains("\"recoveryConfirmedAt\":null"))
        #expect(json.contains("\"v\":2"))
        #expect(json.contains("\"level\":1"))
        #expect(json.contains("\"factors\":{\"card\":null,\"secureEnclave\":null,\"securityKey\":null}"))
        #expect(json.contains("\"protection\":1"))
        #expect(json.contains("\"totp\":\"\""))
    }

    @Test("defaultDirectory nur im Sandbox-Container")
    func sandbox() throws {
        #expect(throws: SiegelError.io("sandbox.missing")) { try VaultStore.defaultDirectory() }
    }

    @Test("volumeIsEncrypted liefert einen Wert für einen echten Ordner")
    func fileVault() throws {
        let dir = KernTempDir()
        #expect(VaultStore.volumeIsEncrypted(dir.url) != nil)
    }

    @Test("X25519 mit Nullpunkt wirft (CryptoKit)")
    func x25519Nullpunkt() throws {
        let zero = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(count: 32))
        #expect(throws: (any Error).self) {
            _ = try Curve25519.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: zero)
        }
        // ML-KEM: ungültiger öffentlicher Schlüssel wird erst beim Kapseln abgelehnt
        let pk = RecoveryPublicKeys(pkM: [UInt8](repeating: 0xFF, count: 1568), pkX: [UInt8](repeating: 9, count: 32))
        #expect(throws: SiegelError.crypto("kem.encapsulate")) {
            try RecoveryKEM.encapsulate(to: pk, label: FileFormat.Labels(version: 2).hybridKEM)
        }
    }

    /// Befund #20: CryptoKit beendet den Prozess bei falscher Seed-Länge selbst (MLKEM_cc.swift, gleicher Exit).
    /// Nur der Fehlerkanal unterscheidet, ob die eigene Vorbedingung vorher gegriffen hat.
    /// Unter ASan/TSan (skripte/sanitizer.sh) abgeschaltet: Der Kindprozess eines Exit-Tests lädt die Sanitizer-Laufzeit
    /// zu spät und startet gar nicht. Im normalen `swift test` läuft er.
    @Test("Seed-Länge ≠ 64 beendet den Prozess über die Vorbedingung (vor CryptoKit)",
          .disabled(if: Sanitizer.aktiv, "Exit-Test unter Sanitizer nicht startbar"))
    func seedLaengeVorbedingung() async throws {
        let result = try await #require(processExitsWith: .failure, observing: [\.standardErrorContent]) {
            RecoveryKEM.seedLengthTrapForTesting()
        }
        let err = String(decoding: result.standardErrorContent, as: UTF8.self)
        #expect(err.contains("Precondition failed: mlkem.seedLength"))
        #expect(!err.contains("MLKEM_cc"))
    }
}
