import Foundation
import Testing
@testable import SiegelCore

@Suite("Zugangswechsel, KDF-Grenzen, Passwort-Regel")
struct KernZugangTests {
    @Test("Passwortwechsel rotiert DEK und KDF-Salz, Notfallcode bleibt gültig")
    func passwortwechsel() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("Bank"))
        let oldFile = try f.parsedFile()
        let oldDEK = try f.vault.dekForTesting()
        #expect(throws: SiegelError.wrongPassword) { try f.vault.changeMasterPassword(current: KT.pw2, new: KT.pw3) }
        #expect(try f.parsedFile().generation == oldFile.generation)

        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2)
        let newFile = try f.parsedFile()
        #expect(newFile.generation == oldFile.generation + 1)
        #expect(newFile.header.salt != oldFile.header.salt)
        #expect(newFile.header.pk == oldFile.header.pk)
        #expect(newFile.header.vaultID == oldFile.header.vaultID)
        let newDEK = try f.vault.dekForTesting()
        #expect(!newDEK.constantTimeEquals(oldDEK))
        // alter DEK entschlüsselt den neuen Inhalt nicht
        #expect(throws: SiegelError.corruptFile("payload.auth")) { try VaultCrypto.decryptPayload(newFile, dek: oldDEK) }
        // altes Passwort öffnet die neue Datei nicht, neues schon
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: KT.pw1) }
        #expect(f.vault.verify(masterPassword: KT.pw2))
        #expect(f.vault.verify(masterPassword: KT.pw1) == false)
        let again = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw2)))
        #expect(again.entries.map(\.title) == ["Bank"])
        // Notfallcode bleibt gültig und liefert den neuen DEK
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
        let r = try RecoveryCodeCodec.decode(f.code)
        let viaCode = try VaultCrypto.openWithRecovery(newFile, r: r)
        #expect(viaCode.dek.constantTimeEquals(newDEK))
        // angeheftete Sicherung „vor-passwortwechsel“ mit der alten Generation
        let pinned = f.localBackups().filter { $0.reason == "passwortwechsel" }
        #expect(pinned.count == 1)
        #expect(pinned.first?.generation == oldFile.generation)
    }

    @Test("KDF-Profil wechseln (gleiches Passwort) rotiert ebenfalls")
    func profilwechsel() throws {
        let f = try KernVault.make()
        let old = try f.parsedFile()
        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw1, kdf: KT.kdf2)
        #expect(f.vault.kdf == KT.kdf2)
        let new = try f.parsedFile()
        #expect(new.header.kdf == KT.kdf2)
        #expect(new.header.salt != old.header.salt)
        f.vault.lock()
        let again = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)))
        #expect(again.kdf == KT.kdf2)
    }

    @Test("KDF-Grenzen beim Schreiben (echte und Testschalter-Grenzen)")
    func grenzenSchreiben() throws {
        let dir = KernTempDir()
        let prod = VaultStore(directory: dir.sub("Prod"), rollbackGuard: InMemoryRollbackGuard())
        let outOfRange = [
            KDFParameters(opsLimit: 3, memLimitBytes: 128 << 20),         // < 256 MiB
            KDFParameters(opsLimit: 3, memLimitBytes: (4 << 30) + 1024),  // > 4 GiB
            KDFParameters(opsLimit: 2, memLimitBytes: 1 << 30),           // t < 3
            KDFParameters(opsLimit: 11, memLimitBytes: 1 << 30),          // t > 10
            KDFParameters(opsLimit: 3, memLimitBytes: (1 << 30) + 1),     // kein Vielfaches von 1 KiB
        ]
        for p in outOfRange {
            #expect(throws: SiegelError.kdfParametersOutOfRange) { try prod.create(masterPassword: KT.pw1, kdf: p) }
        }
        #expect(prod.vaultExists == false)
        #expect(throws: Never.self) { try KDFLimits.production.validate(.standard) }
        #expect(throws: Never.self) { try KDFLimits.production.validate(.strong) }
        #expect(throws: Never.self) { try KDFLimits.production.validate(KDFParameters(opsLimit: 10, memLimitBytes: 4 << 30)) }

        // Testschalter verschiebt nur den Bereich, hebt ihn nicht auf
        let f = try KernVault.make()
        for p in [KDFParameters(opsLimit: 1, memLimitBytes: 4 << 10), KDFParameters(opsLimit: 4, memLimitBytes: 8 << 10),
                  KDFParameters(opsLimit: 1, memLimitBytes: (1 << 20) + 1024), KDFParameters.standard] {
            #expect(throws: SiegelError.kdfParametersOutOfRange) {
                try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2, kdf: p)
            }
            #expect(throws: SiegelError.kdfParametersOutOfRange) {
                try f.store.recover(code: f.code, newMasterPassword: KT.pw2, kdf: p)
            }
        }
        #expect(try f.parsedFile().generation == 1)
    }

    @Test("KDF-Grenzen beim Lesen: Datei ausserhalb → kdfParametersOutOfRange vor Argon2")
    func grenzenLesen() throws {
        let f = try KernVault.make()
        let bytes = try f.fileBytes()
        // Datei mit Testschalter-Parametern (8 KiB) ist für echte Grenzen zu schwach
        let prod = VaultStore(directory: f.store.directory, rollbackGuard: InMemoryRollbackGuard(), testKDF: false)
        #expect(throws: SiegelError.kdfParametersOutOfRange) { try prod.unlock(masterPassword: KT.pw1) }
        // Manipulierte Parameter mit neu berechneter Prüfsumme (DoS-Schutz: 8 GiB, t = 1000)
        func patched(ops: UInt32? = nil, mem: UInt64? = nil) -> [UInt8] {
            var b = bytes
            if let ops { withUnsafeBytes(of: ops.littleEndian) { b.replaceSubrange(25..<29, with: $0) } }
            if let mem { withUnsafeBytes(of: mem.littleEndian) { b.replaceSubrange(29..<37, with: $0) } }
            return KT.withFixedChecksum(b)
        }
        for v in [patched(mem: 8 << 30), patched(ops: 1000), patched(ops: 0), patched(mem: 4 << 10),
                  patched(mem: (16 << 10) + 1)] {
            try f.writeFile(v)
            let start = Date()
            #expect(throws: SiegelError.kdfParametersOutOfRange) { try f.store.unlock(masterPassword: KT.pw1) }
            // Argon2 mit 8 GiB bzw. t = 1000 würde Minuten dauern; abgelehnt wird vorher.
            #expect(Date().timeIntervalSince(start) < 30)
        }
        // Im Bereich, aber anders als beim Schreiben → AD-Bindung → wrongPassword (keine Herabstufung)
        try f.writeFile(patched(ops: 2))
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: KT.pw1) }
    }

    @Test("Policy: create/changeMasterPassword/recover werfen passwordTooWeak")
    func policy() throws {
        let dir = KernTempDir()
        let store = VaultStore(directory: dir.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        for weak in [KT.weak, "", "aaaaaaaa", String(repeating: "Ab1!", count: 300)] {
            let e = #expect(throws: SiegelError.self) { try store.create(masterPassword: weak, kdf: KT.kdf) }
            if case .passwordTooWeak = e {} else { Issue.record("erwartet passwordTooWeak") }
        }
        #expect(store.vaultExists == false)
        let f = try KernVault.make()
        let e1 = #expect(throws: SiegelError.self) { try f.vault.changeMasterPassword(current: KT.pw1, new: KT.weak) }
        if case .passwordTooWeak = e1 {} else { Issue.record("erwartet passwordTooWeak") }
        let e2 = #expect(throws: SiegelError.self) { try f.store.recover(code: f.code, newMasterPassword: KT.weak, kdf: KT.kdf) }
        if case .passwordTooWeak = e2 {} else { Issue.record("erwartet passwordTooWeak") }
        #expect(try f.parsedFile().generation == 1)
        // Die Bit-Schätzung kommt aus MasterPasswordPolicy
        if case let .passwordTooWeak(bits) = e1 { #expect(bits == MasterPasswordPolicy.check(KT.weak).bits) }
    }

    @Test("Wiederverwendung: masterPasswordReuse und masterPasswordReused")
    func wiederverwendung() throws {
        let f = try KernVault.make()
        let same = kernEntry("Gleich", password: KT.pw1)
        var viaHistory = kernEntry("Verlauf", password: KT.pw1)
        let other = kernEntry("Anders", password: KT.pw3)
        let normalized = kernEntry("Normalisiert", password: "u,F?CfDuMlYWuJASPVQ*6GUG@O")
        try f.vault.upsert(same)
        try f.vault.upsert(viaHistory)
        viaHistory.password = "Neu-Und-Anders-1"
        try f.vault.upsert(viaHistory)
        try f.vault.upsert(other)
        try f.vault.upsert(normalized)
        #expect(f.vault.masterPasswordReuse == [same.id, viaHistory.id, normalized.id])
        // neues Master-Passwort darf kein Eintragspasswort sein
        #expect(throws: SiegelError.masterPasswordReused) { try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw3) }
        #expect(throws: SiegelError.masterPasswordReused) {
            try f.store.recover(code: f.code, newMasterPassword: KT.pw3, kdf: KT.kdf)
        }
        // Nach dem Wechsel auf pw2 ist nichts mehr gleich
        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2)
        #expect(f.vault.masterPasswordReuse.isEmpty)
        var o = other
        o.password = KT.pw2
        try f.vault.upsert(o)
        #expect(f.vault.masterPasswordReuse == [other.id])
        // auch nach dem Entsperren
        f.vault.lock()
        let again = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw2)))
        #expect(again.masterPasswordReuse == [other.id])
        // Normalisierung: Eintrag mit geschütztem Leerzeichen = Master-Passwort mit Leerzeichen
        let g = try KernVault.make(password: "t=5:U.+F3mYW O6#O8@s~@~4_q:")
        try g.vault.upsert(kernEntry("NBSP", password: "t=5:U.+F3mYW\u{00A0}O6#O8@s~@~4_q:"))
        #expect(g.vault.masterPasswordReuse.count == 1)
    }
}
