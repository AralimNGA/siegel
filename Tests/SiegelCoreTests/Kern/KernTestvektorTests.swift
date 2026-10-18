import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Feste Testvektoren (SPEC §10). Werte NIE ändern – sie stehen auch in `Fixtures/README.md`.
enum KernTestvektor {
    // (a) R = 00 01 … 1f, vaultID = a0 a1 … af
    static let r = (0..<32).map { UInt8($0) }
    static let vaultID = (0xa0...0xaf).map { UInt8($0) }
    static let sha3PKM = "07d2a982d901e86a75c81c97704b1a66571c8ae4664039ec55e286cbbac206f2"
    static let pkX = "157638f533039b946e64edc0135d67ad5c805d89cc0530bec075e14266213107"
    static let code = "000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FRAC8"
    /// Zusätzlich festgehalten (unabhängig nachgerechnet).
    static let kitID = "HKEH-KJPJ"
}

/// (b)/(c) Beispieldatei `Fixtures/v1_beispiel.siegel` (m = 256 MiB, t = 3).
enum KernBeispielDatei {
    static let password = "7:etFa_0+Isq#jQ0oeTb8nWKFM*9"
    static let kdf = KDFParameters(opsLimit: 3, memLimitBytes: 256 << 20)
    static let code = "NHZZD-BYYYZ-ZYMNR-W0S31-BZK7X-0S860-H7KZ4-YEBE7-7JNMC-G8367-YZ2N0"
    static let kitID = "3Q0A-CCCJ"
    static let kekRec = "c406914254c7efdd3c75b9510e779fa6553b3776c0ffa7c2c988c4259ce3f9d8"
    static let vaultID = "06CAF7C7-5BFA-4C75-ABEC-76E7488CC7A2"
    static let generation: UInt64 = 6

    struct Erwartet {
        let title: String
        let username: String
        let firstPassword: String
        let password: String
        let url: String
        let notes: String
    }

    static let erwartet: [Erwartet] = [
        Erwartet(title: "Bibliothek Bern", username: "leserin.muster", firstPassword: "Buecher-Regal-42!",
                 password: "Buecher-Regal-42!", url: "https://bibliothek.example.ch",
                 notes: "Ausweisnummer steht auf der Karte."),
        Erwartet(title: "Velo-Club", username: "velofahrer", firstPassword: "Rad&Weg-2026",
                 password: "Kette+Sattel-77", url: "velo.example.ch", notes: ""),
        Erwartet(title: "Notiz ohne Website", username: "", firstPassword: "", password: "",
                 url: "", notes: "Zeilen\nmit Umlauten: äöü, Zeichen: «» – Ende"),
    ]

    static func url() throws -> URL {
        guard let dir = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
            throw SiegelError.io("test.fixtures")
        }
        return dir.appendingPathComponent("v1_beispiel.siegel", isDirectory: false)
    }

    /// Prüft den Inhalt gegen die erwarteten Einträge.
    static func check(_ vault: UnlockedVault) {
        let entries = vault.entries
        #expect(entries.count == erwartet.count)
        for e in erwartet {
            let found = entries.first { $0.title == e.title }
            #expect(found != nil)
            #expect(found?.username == e.username)
            #expect(found?.password == e.password)
            #expect(found?.url == e.url)
            #expect(found?.notes == e.notes)
            if e.firstPassword != e.password {
                #expect(found?.history.map(\.password) == [e.firstPassword])
            }
        }
        #expect(vault.recoveryConfirmed)
        #expect(vault.kdf == kdf)
    }
}

@Suite("Testvektoren")
struct KernTestvektorTests {
    @Test("(a) pkM/pkX/Code aus R = 00…1f, vaultID = a0…af")
    func vektorA() throws {
        let r = try SecureBytes(count: 32) { out in for i in 0..<32 { out[i] = KernTestvektor.r[i] } }
        let pk = try RecoveryKEM.derivePublicKeys(r: r, vaultID: KernTestvektor.vaultID)
        #expect(pk.pkM.count == 1568)
        #expect(KT.hex(SHA3_256.hash(data: pk.pkM)) == KernTestvektor.sha3PKM)
        #expect(KT.hex(pk.pkX) == KernTestvektor.pkX)
        #expect(try RecoveryCodeCodec.format(r: r) == KernTestvektor.code)
        let back = try RecoveryCodeCodec.decode(KernTestvektor.code)
        #expect(back.constantTimeEquals(r))
        #expect(RecoveryKEM.matches(r: r, vaultID: KernTestvektor.vaultID, expected: pk))
    }

    @Test("(a) Kit-Kennung hat das Format XXXX-XXXX")
    func kitKennung() throws {
        let r = try SecureBytes(count: 32) { out in for i in 0..<32 { out[i] = KernTestvektor.r[i] } }
        let pk = try RecoveryKEM.derivePublicKeys(r: r, vaultID: KernTestvektor.vaultID)
        let kit = pk.kitID
        #expect(kit.count == 9)
        #expect(Array(kit)[4] == "-")
        #expect(kit.replacingOccurrences(of: "-", with: "").allSatisfy { "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains($0) })
        #expect(kit == RecoveryCodeCodec.kitID(pkM: pk.pkM, pkX: pk.pkX))
        #expect(kit == KernTestvektor.kitID)
    }
}
