import Foundation
import Testing
@testable import SiegelCore

/// Format v1 → v2 (§2 „Formatversionen“, §13.2) mit selbst gebauten v1-Dateien (Testschalter-KDF).
@Suite("Migration v1 → v2")
struct KernMigrationTests {
    /// Schreibt eine v1-Datei wie der Kern v3.1: Kopf v1, KEK = Argon2, Labels "Siegel v1 …", Inhalt `"v": 1`.
    /// Liefert den Notfallcode.
    @discardableResult
    static func writeV1(to store: VaultStore, password: String = KT.pw1, entries: [VaultEntry],
                        generation: UInt64 = 5, confirmed: Bool = true) throws -> String {
        let vaultID = VaultHeader.bytes(of: UUID())
        let r = try SecureBytes.random(count: 32)
        let pk = try RecoveryKEM.derivePublicKeys(r: r, vaultID: vaultID)
        let header = VaultHeader(v1: vaultID, kdf: KT.kdf, salt: randomBytes(16), pk: pk)
        let kek = try KDF.deriveKEK(password: try PasswordNormalizer.secureBytes(password), salt: header.salt,
                                    params: header.kdf, limits: .testing)
        let dek = try SecureBytes.random(count: 32)
        let slots = try VaultCrypto.makeSlots(header: header, kekPw: kek, dek: dek)
        var content = VaultContent(savedAt: Clock.now(), recoveryConfirmedAt: confirmed ? Clock.now() : nil,
                                   entries: entries)
        content.prepareForSave(now: Clock.now())
        let (padded, _) = try PayloadCodec.encode(content, legacyV1: true)
        let sealed = try AEAD.seal(key: dek, plaintext: padded,
                                   ad: VaultFile.payloadAD(header: header, slots: slots, generation: generation))
        let file = VaultFile(header: header, slots: slots, generation: generation, nonce: sealed.nonce,
                             ciphertext: sealed.ciphertext)
        try FileIO.ensureDirectory(store.directory)
        try FileIO.writeExclusive(store.vaultURL, bytes: file.serialize())
        return try RecoveryCodeCodec.format(r: r)
    }

    private func store() -> (KernTempDir, VaultStore) {
        let dir = KernTempDir()
        return (dir, VaultStore(directory: dir.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard(), testKDF: true))
    }

    @Test("Selbst gebaute v1-Datei ist wirklich v1 (Labels, JSON ohne Stufe)")
    func echteV1() throws {
        let (dir, s) = store()
        try Self.writeV1(to: s, entries: [kernEntry("A")])
        let bytes = try FileIO.read(s.vaultURL, maxSize: FileFormat.maxFileBytes)
        #expect(bytes.count == VaultHeader.v1Size + VaultSlots.size + 36 + 16_400 + 32)
        let file = try VaultFile.parse(bytes)
        #expect(file.header.formatVersion == 1)
        #expect(file.header.labels.payload == Array("Siegel v1 payload".utf8))
        let opened = try VaultCrypto.openWithPassword(file, password: try PasswordNormalizer.secureBytes(KT.pw1),
                                                      limits: .testing)
        #expect(opened.migrationKEK != nil)
        let padded = try #require(AEAD.open(key: opened.dek, nonce: file.nonce, ciphertext: file.ciphertext,
                                            ad: file.payloadAD))
        let json = try #require(PayloadCodec.jsonStringForTesting(padded))
        #expect(json.contains("\"v\":1"))
        #expect(!json.contains("level"))
        #expect(!json.contains("totp"))
        _ = dir
    }

    @Test("Jeder Schreibweg migriert: Speichern, Passwortwechsel, Notfall, neues Kit, Stufenwechsel, Wiederherstellen")
    func jederSchreibweg() throws {
        enum Weg: CaseIterable { case upsert, passwort, notfall, kit, stufe, sicherung }
        for weg in Weg.allCases {
            let (dir, s) = store()
            let code = try Self.writeV1(to: s, entries: [kernEntry("A")])
            let v1Bytes = try FileIO.read(s.vaultURL, maxSize: FileFormat.maxFileBytes)
            var password = KT.pw1
            var validCode: String? = code
            switch weg {
            case .upsert:
                let v = try #require(KT.unlocked(try s.unlock(masterPassword: KT.pw1)))
                try v.upsert(kernEntry("B"))
            case .passwort:
                let v = try #require(KT.unlocked(try s.unlock(masterPassword: KT.pw1)))
                try v.changeMasterPassword(current: KT.pw1, new: KT.pw2)
                password = KT.pw2
            case .notfall:
                _ = try s.recover(code: code, newMasterPassword: KT.pw2, kdf: KT.kdf)
                password = KT.pw2
            case .kit:
                let v = try #require(KT.unlocked(try s.unlock(masterPassword: KT.pw1)))
                let p = try v.prepareRecovery(masterPassword: KT.pw1)
                try v.commitRecovery(p, confirmation: KernStufen.confirmation(p))
                validCode = p.code.formatted
            case .stufe:
                let v = try #require(KT.unlocked(try s.unlock(masterPassword: KT.pw1)))
                try v.changeSecurityLevel(to: .standard, masterPassword: KT.pw1, currentFactors: FactorSecrets(),
                                          newFactors: NewFactorMaterial(), recovery: nil, recoveryConfirmation: [])
            case .sicherung:
                let kopie = dir.url.appendingPathComponent("v1.siegel")
                try FileIO.writeExclusive(kopie, bytes: v1Bytes)
                _ = try s.importBackup(from: kopie, masterPassword: KT.pw1)
            }
            let info = try s.inspect()
            #expect(info.formatVersion == 2, "\(weg)")
            let pinned = s.backups().filter { $0.reason == "migration-v1" }
            #expect(pinned.count == 1, "\(weg)")
            if let p = pinned.first {
                #expect(try FileIO.read(p.url, maxSize: FileFormat.maxFileBytes) == v1Bytes, "\(weg)")
            }
            // Zugang danach
            let v = try #require(KT.unlocked(try s.unlock(masterPassword: password)))
            #expect(v.entries.contains { $0.title == "A" }, "\(weg)")
            #expect(v.headerInfo.formatVersion == 2)
            if let validCode { #expect(try s.checkRecoveryCode(validCode) == .exact, "\(weg)") }
            // Die angeheftete v1-Sicherung öffnet weiter (Format v1 bleibt lesbar)
            v.lock()
            if let p = pinned.first {
                let restored = try s.restoreBackup(p, masterPassword: KT.pw1)
                #expect(restored.entries.map(\.title) == ["A"], "\(weg)")
            }
            _ = dir
        }
    }

    @Test("v1-Datei: Prüfsumme mit v1-Label, Byte kippen → corruptFile; v1-Code bleibt nach Migration gültig")
    func v1Pruefsumme() throws {
        let (dir, s) = store()
        let code = try Self.writeV1(to: s, entries: [])
        var b = try FileIO.read(s.vaultURL, maxSize: FileFormat.maxFileBytes)
        #expect(Array(b.suffix(32)) == FileFormat.fileChecksum(b.dropLast(32), version: 1))
        #expect(Array(b.suffix(32)) != FileFormat.fileChecksum(b.dropLast(32), version: 2))
        b[100] ^= 1
        FileIO.remove(s.vaultURL)
        try FileIO.writeExclusive(s.vaultURL, bytes: b)
        #expect(throws: SiegelError.corruptFile("file.checksum")) { try s.unlock(masterPassword: KT.pw1) }
        #expect(throws: SiegelError.corruptFile("file.checksum")) { try s.checkRecoveryCode(code) }
        _ = dir
    }
}
