import Foundation
import Testing
@testable import SiegelCore

/// Tests mit echten Argon2-Profilen (≥ 256 MiB, bis 1 GiB pro Lauf) – nacheinander (SPEC §10).
@Suite("Echte Profile", .serialized)
struct KernEchteProfileTests {
    /// Kopie der Beispieldatei in einem Temp-Ordner, Store mit echten Grenzen.
    private func copyFixture() throws -> (KernTempDir, VaultStore) {
        let dir = KernTempDir()
        let siegelDir = dir.sub("Siegel")
        try FileManager.default.copyItem(at: try KernBeispielDatei.url(),
                                         to: siegelDir.appendingPathComponent(VaultStore.vaultFileName))
        return (dir, VaultStore(directory: siegelDir, rollbackGuard: InMemoryRollbackGuard()))
    }

    @Test("(b) Beispieldatei öffnet über das Master-Passwort")
    func beispielPasswort() throws {
        let (dir, store) = try copyFixture()
        let before = try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes)
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: KernBeispielDatei.password)))
        KernBeispielDatei.check(vault)
        #expect(vault.vaultID.uuidString == KernBeispielDatei.vaultID)
        #expect(vault.generation == KernBeispielDatei.generation)
        #expect(vault.kitID == KernBeispielDatei.kitID)
        // Entsperren schreibt nichts.
        #expect(try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes) == before)
        _ = dir
    }

    @Test("(b) Beispieldatei öffnet über den Notfallcode")
    func beispielNotfallcode() throws {
        let (dir, store) = try copyFixture()
        #expect(try store.checkRecoveryCode(KernBeispielDatei.code) == .exact)
        let vault = try store.recover(code: KernBeispielDatei.code, newMasterPassword: KT.pw2, kdf: KernBeispielDatei.kdf)
        KernBeispielDatei.check(vault)
        #expect(vault.generation == KernBeispielDatei.generation + 1)
        vault.lock()
        // Neues Passwort öffnet, altes nicht mehr; Code bleibt gültig.
        #expect(KT.unlocked(try store.unlock(masterPassword: KT.pw2)) != nil)
        #expect(throws: SiegelError.wrongPassword) { try store.unlock(masterPassword: KernBeispielDatei.password) }
        #expect(try store.checkRecoveryCode(KernBeispielDatei.code) == .exact)
        // Die Wiederherstellung schreibt Format v2; vorher entsteht die angeheftete Sicherung „vor-migration-v1“
        // der Originaldatei (bytegleich).
        #expect(try store.inspect().formatVersion == 2)
        let pinned = store.backups().filter { $0.reason == "migration-v1" }
        #expect(pinned.count == 1)
        #expect(pinned.first?.generation == KernBeispielDatei.generation)
        if let p = pinned.first {
            #expect(try FileIO.read(p.url, maxSize: FileFormat.maxFileBytes)
                    == FileIO.read(try KernBeispielDatei.url(), maxSize: FileFormat.maxFileBytes))
        }
        _ = dir
    }

    @Test("(c) KEK_rec der Beispieldatei")
    func kekRec() throws {
        let file = try VaultFile.parse(try FileIO.read(try KernBeispielDatei.url(), maxSize: FileFormat.maxFileBytes))
        let r = try RecoveryCodeCodec.decode(KernBeispielDatei.code)
        #expect(file.header.formatVersion == 1)
        let kek = try RecoveryKEM.decapsulate(r: r, vaultID: file.header.vaultID, pk: file.header.pk,
                                              ctM: file.slots.ctM, ctX: file.slots.ctX,
                                              label: file.header.labels.hybridKEM)
        #expect(kek.hexForTesting() == KernBeispielDatei.kekRec)
        let dek = AEAD.unwrap(kek: kek, blob: file.slots.recSlot, ad: VaultSlots.recAD(file.header))
        #expect(dek != nil)
        #expect(file.header.kdf == KernBeispielDatei.kdf)
        #expect(file.generation == KernBeispielDatei.generation)
    }

    @Test("Standardprofil (1 GiB, t = 3): anlegen, entsperren, falsches Passwort")
    func standardRundlauf() throws {
        let dir = KernTempDir()
        let store = VaultStore(directory: dir.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard())
        let (vault, _) = try store.create(masterPassword: KT.pw1)
        #expect(vault.kdf == .standard)
        try vault.upsert(kernEntry("Bank"))
        vault.lock()
        let again = try #require(KT.unlocked(try store.unlock(masterPassword: KT.pw1)))
        #expect(again.entries.map(\.title) == ["Bank"])
        #expect(throws: SiegelError.wrongPassword) { try store.unlock(masterPassword: KT.pw2) }
    }
}
