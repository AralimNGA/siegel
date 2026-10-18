import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// (d) Beispieldatei v2 mit echtem Argon2 (256 MiB): in der seriellen Suite „Echte Profile“, damit nie zwei
/// grosse Argon2-Läufe gleichzeitig laufen.
extension KernEchteProfileTests {
    private typealias B = KernBeispielDateiV2

    private func copyFixtureV2() throws -> (KernTempDir, VaultStore) {
        let dir = KernTempDir()
        let siegelDir = dir.sub("Siegel")
        try FileManager.default.copyItem(at: try B.url(), to: siegelDir.appendingPathComponent(VaultStore.vaultFileName))
        return (dir, VaultStore(directory: siegelDir, rollbackGuard: InMemoryRollbackGuard()))
    }

    @Test("(d) v2-Beispieldatei: Kopf-Auskunft ohne Geheimnis und ohne Argon2")
    func v2Kopf() throws {
        let bytes = try FileIO.read(try B.url(), maxSize: FileFormat.maxFileBytes)
        #expect(bytes.count == B.size)
        #expect(KT.hex(SHA256.hash(data: bytes)) == B.sha256)
        let counter = TestHooks.Counter()
        let info = try TestHooks.$kdfCounter.withValue(counter) { try VaultStore.inspect(fileAt: try B.url()) }
        #expect(counter.value == 0)
        #expect(info.formatVersion == 2)
        #expect(info.vaultID.uuidString == B.vaultID)
        #expect(info.factors == .all)
        #expect(info.recoveryScheme == .shamir2of3)
        #expect(info.seKeyID == B.seKeyID)
        #expect(info.cardTag.map { KT.hex($0) } == B.cardTag)
        #expect(info.fidoCredentialID == Data(B.credentialID))
        #expect(info.fidoSalt == Data(B.fidoSalt))
        #expect(info.kdf == B.kdf)
        #expect(info.kitID == B.kitID)
    }

    @Test("(d) v2-Beispieldatei öffnet über Passwort + alle drei Faktoren")
    func v2Passwort() throws {
        let (dir, store) = try copyFixtureV2()
        let before = try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes)
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: B.password, factors: try B.factors())))
        B.check(vault)
        #expect(vault.vaultID.uuidString == B.vaultID)
        #expect(vault.generation == B.generation)
        #expect(vault.kitID == B.kitID)
        #expect(vault.enrolledFactors == .all)
        #expect(vault.headerInfo == (try store.inspect()))
        #expect(vault.policy == SecurityLevel.festung.policy)
        // Entsperren schreibt nichts.
        #expect(try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes) == before)
        // KAT: echtes Argon2 ergibt das festgehaltene p
        let file = try VaultFile.parse(before)
        #expect(KT.hex(file.header.salt) == B.salt)
        let p = try KDF.deriveKEK(password: try PasswordNormalizer.secureBytes(B.password), salt: file.header.salt,
                                  params: file.header.kdf, limits: .production)
        #expect(p.hexForTesting() == B.p)
        _ = dir
    }

    @Test("(d) Fehlender Faktor → factorMissing, falsche Karte → wrongCard, beides vor Argon2")
    func v2FehlendeFaktoren() throws {
        let (dir, store) = try copyFixtureV2()
        let all = try B.factors()
        let counter = TestHooks.Counter()
        try TestHooks.$kdfCounter.withValue(counter) {
            for kind in FactorKind.allCases {
                var f = all
                switch kind {
                case .secureEnclave: f.secureEnclave = nil
                case .card: f.card = nil
                case .securityKey: f.securityKey = nil
                }
                #expect(throws: SiegelError.factorMissing(kind)) { try store.unlock(masterPassword: B.password, factors: f) }
            }
            #expect(throws: SiegelError.factorMissing(.secureEnclave)) { try store.unlock(masterPassword: B.password) }
            var wrongCard = all
            wrongCard.card = try B.secret([UInt8](repeating: 0x23, count: 32))
            #expect(throws: SiegelError.wrongCard) { try store.unlock(masterPassword: B.password, factors: wrongCard) }
        }
        #expect(counter.value == 0)
        _ = dir
    }

    @Test("(d) Falscher Faktor-Wert oder falsches Passwort → wrongPassword")
    func v2FalscheFaktoren() throws {
        let (dir, store) = try copyFixtureV2()
        let all = try B.factors()
        var wrongSE = all
        wrongSE.secureEnclave = try B.secret([UInt8](repeating: 0x12, count: 32))
        #expect(throws: SiegelError.wrongPassword) { try store.unlock(masterPassword: B.password, factors: wrongSE) }
        var wrongKey = all
        wrongKey.securityKey = try B.secret([UInt8](repeating: 0x34, count: 32))
        #expect(throws: SiegelError.wrongPassword) { try store.unlock(masterPassword: B.password, factors: wrongKey) }
        #expect(throws: SiegelError.wrongPassword) { try store.unlock(masterPassword: KT.pw1, factors: all) }
        _ = dir
    }

    @Test("(d) v2-Beispieldatei über je zwei Teile (alle drei Paare, beide Reihenfolgen)")
    func v2Teile() throws {
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let (dir, store) = try copyFixtureV2()
            #expect(try store.checkRecoveryShares([B.shares[a], B.shares[b]]) == [.exact, .exact])
            #expect(try store.checkRecoveryShares([B.shares[b], B.shares[a]]) == [.exact, .exact])
            #expect(VaultStore.recoveryShareIndex(B.shares[a]) == a + 1)
            let vault = try store.recover(shares: [B.shares[a], B.shares[b]], newMasterPassword: KT.pw2, kdf: B.kdf)
            // Wiederherstellung: Stufe 1, keine Faktoren, Kit (Teile) bleibt gültig
            B.check(vault, level: .standard)
            #expect(vault.enrolledFactors.isEmpty)
            #expect(vault.generation == B.generation + 1)
            let info = try store.inspect()
            #expect(info.factors.isEmpty)
            #expect(info.recoveryScheme == .shamir2of3)
            #expect(info.kitID == B.kitID)
            #expect(try store.checkRecoveryShares([B.shares[a], B.shares[b]]) == [.exact, .exact])
            vault.lock()
            #expect(KT.unlocked(try store.unlock(masterPassword: KT.pw2)) != nil)
            #expect(store.backups().contains { $0.reason == "notfall" })
            _ = dir
        }
    }

    @Test("(b) v1-Beispieldatei: erstes Speichern migriert zu v2, Passwort und Code gelten weiter")
    func v1Migration() throws {
        let dir = KernTempDir()
        let siegelDir = dir.sub("Siegel")
        try FileManager.default.copyItem(at: try KernBeispielDatei.url(),
                                         to: siegelDir.appendingPathComponent(VaultStore.vaultFileName))
        let store = VaultStore(directory: siegelDir, rollbackGuard: InMemoryRollbackGuard())
        #expect(try store.inspect().formatVersion == 1)
        let counter = TestHooks.Counter()
        let vault = try TestHooks.$kdfCounter.withValue(counter) {
            let v = try #require(KT.unlocked(try store.unlock(masterPassword: KernBeispielDatei.password)))
            #expect(v.headerInfo.formatVersion == 1)
            try v.upsert(kernEntry("Neu nach Migration"))
            return v
        }
        // Migration ohne zweites Argon2 (gleiches Salz)
        #expect(counter.value == 1)
        let info = try store.inspect()
        #expect(info.formatVersion == 2)
        #expect(info.factors.isEmpty)
        #expect(info.recoveryScheme == .single)
        #expect(info.kitID == KernBeispielDatei.kitID)
        #expect(vault.headerInfo == info)
        #expect(vault.generation == KernBeispielDatei.generation + 1)
        let pinned = store.backups().filter { $0.reason == "migration-v1" }
        #expect(pinned.count == 1)
        #expect(try FileIO.read(try #require(pinned.first).url, maxSize: FileFormat.maxFileBytes)
                == FileIO.read(try KernBeispielDatei.url(), maxSize: FileFormat.maxFileBytes))
        // Weitere Speicherungen sind normal (keine weitere Migrationssicherung)
        try vault.upsert(kernEntry("Zweiter"))
        #expect(store.backups().filter { $0.reason == "migration-v1" }.count == 1)
        vault.lock()
        // Passwort und gedruckter v1-Code öffnen die v2-Datei
        let again = try #require(KT.unlocked(try store.unlock(masterPassword: KernBeispielDatei.password)))
        #expect(again.entries.count == KernBeispielDatei.erwartet.count + 2)
        #expect(again.headerInfo.formatVersion == 2)
        again.lock()
        #expect(try store.checkRecoveryCode(KernBeispielDatei.code) == .exact)
        let rec = try store.recover(code: KernBeispielDatei.code, newMasterPassword: KT.pw2, kdf: KernBeispielDatei.kdf)
        #expect(rec.entries.count == KernBeispielDatei.erwartet.count + 2)
        _ = dir
    }
}
