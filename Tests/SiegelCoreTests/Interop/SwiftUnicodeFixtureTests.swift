import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Eingefrorene Swift-Tresore mit U+FFFE und Unicode-16-Zeichen (`windows/tests/Fixtures/swift_fffe_*.siegel`,
/// `swift_kirat_master.siegel`, Werte in deren `README.md`; Befunde krypto-1 und krypto-2). Der C#-Kern öffnet sie in
/// `windows/tests/Siegel.Core.Tests/Kern/SwiftUnicodeTests.cs`. Hier: der Mac öffnet sie weiterhin, und die Regel ab
/// v4.7 lehnt das Unicode-16-Passwort für neue Tresore ab, ohne bestehende auszusperren.
@Suite("Interop: Swift-Tresore mit besonderen Zeichen", .serialized)
struct SwiftUnicodeFixtureTests {
    static let kdf = KDFParameters(opsLimit: 3, memLimitBytes: 256 << 20)

    @Test("swift_fffe_eintrag.siegel: Eintragspasswort mit U+FFFE, Notfallcode")
    func fffeEintrag() throws {
        let (dir, store) = try CSharpFixtureTests.store("swift_fffe_eintrag.siegel")
        #expect(try CSharpFixtureTests.sha256(CSharpFixtureTests.fixtures.appendingPathComponent("swift_fffe_eintrag.siegel"))
            == "7e518e61edafb7f8ab6d708d609b5b2c1de4d19af722c515a38cd9ea98c762ac")
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: "Fffe-Eintrag#7qLm!2xV9@Rk4")))
        let e = try #require(vault.entries.first { $0.title == "Import FFFE" })
        #expect(Array(e.password.utf8) == Array("neu\u{FFFE}wert".utf8))
        #expect(e.history.map(\.password) == ["abc\u{FFFE}def"])
        vault.lock()
        let neu = try store.recover(code: "E1PFH-SGMRG-YD3S3-NT32K-YXW95-E7KDG-SVTYF-9T3BQ-JMYPC-ZV94Q-59Q38",
                                    newMasterPassword: KT.pw2, kdf: Self.kdf)
        #expect(neu.entries.count == 2)
        neu.lock()
        _ = dir
    }

    @Test("swift_fffe_master.siegel: Master-Passwort mit U+FFFE")
    func fffeMaster() throws {
        let (dir, store) = try CSharpFixtureTests.store("swift_fffe_master.siegel")
        let master = "Wq7!vTz#2pLm\u{FFFE}9@Xc4$Rb8&Hn"
        #expect(VaultStore.passwordsMatch(master, master))
        #expect(MasterPasswordPolicy.check(master).ok)
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: master)))
        #expect(vault.entries.map(\.password) == ["Kette+Sattel-77"])
        vault.lock()
        _ = dir
    }

    @Test("swift_kirat_master.siegel: Unicode-16-Passwort öffnet weiter, neu angelegt wird es abgelehnt")
    func kiratMaster() throws {
        let (dir, store) = try CSharpFixtureTests.store("swift_kirat_master.siegel")
        let master = "u,F?CfDuMlYWuJASPVQ*6GUG@O\u{16D67}\u{16D67}"
        // Foundation (macOS 26) setzt U+16D67 U+16D67 nicht zusammen; der C#-Kern muss dieselben Bytes nehmen.
        #expect(Array(PasswordNormalizer.normalize(master).utf8) == Array(master.utf8))
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: master)))
        #expect(vault.entries.map(\.title) == ["Kirat", "Todhri", "Gurung", "Tulu", "Zerlegt"])
        vault.lock()
        // Neuer Tresor mit demselben Passwort: abgelehnt (v4.7), nichts angelegt.
        let leer = KernTempDir()
        let neuStore = VaultStore(directory: leer.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard())
        #expect(throws: SiegelError.passwordTooWeak(bits: MasterPasswordPolicy.check(master).bits)) {
            _ = try neuStore.create(masterPassword: master, kdf: Self.kdf)
        }
        #expect(!neuStore.vaultExists)
        _ = dir
    }
}
