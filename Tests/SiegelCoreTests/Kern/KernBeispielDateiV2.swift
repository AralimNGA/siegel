import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// (d) Beispieldatei `Fixtures/v2_beispiel.siegel`: Stufe 5 (alle Faktoren, Notfall 2 aus 3), m = 256 MiB, t = 3.
/// Werte NIE ändern – sie stehen auch in `Fixtures/README.md`.
enum KernBeispielDateiV2 {
    static let password = "6Bn__S?ZC37umQe_9A!^6K!9_nNk"
    static let kdf = KDFParameters(opsLimit: 3, memLimitBytes: 256 << 20)

    // Feste Faktor-Geheimnisse (roh, wie sie das Hardware-Modul liefert)
    static let ecdhSE = [UInt8](repeating: 0x11, count: 32)
    static let q = [UInt8](repeating: 0x22, count: 32)
    static let hmacOutput = [UInt8](repeating: 0x33, count: 32)
    // Feste, nicht geheime Faktor-Angaben
    static let seKeyID = UUID(uuidString: "11111111-2222-4333-8444-555555555555") ?? UUID()
    static let entryKeyID = UUID(uuidString: "66666666-7777-4888-8999-AAAAAAAAAAAA") ?? UUID()
    /// Eintrags-SE-Schlüssel: öffentlicher Teil des P-256-Schlüssels mit Skalar 0x88…88.
    static let entryPrivateScalar = [UInt8](repeating: 0x88, count: 32)
    static let credentialID = [UInt8](repeating: 0x44, count: 64)
    static let fidoSalt = [UInt8](repeating: 0x55, count: 32)
    static let entrySalt = [UInt8](repeating: 0x66, count: 32)
    static let entryOutput = [UInt8](repeating: 0x77, count: 32)

    // Bei der Erzeugung festgehalten (README), unabhängig mit Python (hashlib/hmac + libsodium) nachgerechnet
    static let sha256 = "53c78ad55d5126ae72b9f02595104238b4d3c46359006c654713f27e6c82dff5"
    static let size = 19_985
    static let shares = [
        "04A6Z-0CJEQ-E7T55-1KVCB-7K5WQ-E3V63-2BGH5-P3KM3-RQF38-40TW4-Y1XQ2-N",
        "08F19-MM81R-FAMDM-D44N1-N36HJ-M1QKG-CG8GG-G7JF2-Q81KE-637EJ-35EMW-0",
        "0CC3V-RVQ4Y-MYEA3-0QP6Q-TH83H-XZKYW-YS0G3-X8F9M-CS43D-TAC0W-CSJTH-6",
    ]
    static let kitID = "2RMY-XAAA"
    static let vaultID = "D4F9B640-FECB-4BAB-A72D-28DBA1D1636D"
    static let generation: UInt64 = 7
    static let salt = "e1a44dd212cc4e593c56f3c2aeef12c1"
    static let p = "0aba515de29ce382121b9355eb693daebc778d6378affdf4719f2c25f618b2d0"
    static let e = "8fbcf78df09ce432ff8b693dd8c8dce0aba9c424280e7a17763677aa2fd776d5"
    static let c = "d57682004bbd6e767859be1a1306e9f8499a829a7184cf88d57560685b1c961d"
    static let y = "89f8f8f3c3d18b6756605cda1a1860df54afaa61b5d11413837e58a613a1c4c6"
    static let kek = "c15d504d2f670fbf21d5ba74fc2395139ef5aafc826d87bae6bac24c5f096c89"
    static let cardTag = "b2fdc001"

    struct Erwartet {
        let title: String
        let username: String
        let firstPassword: String
        let password: String
        let url: String
        let notes: String
        let totp: String
    }

    static let erwartet: [Erwartet] = [
        Erwartet(title: "Bibliothek Bern", username: "leserin.muster", firstPassword: "Buecher-Regal-42!",
                 password: "Buecher-Regal-42!", url: "https://bibliothek.example.ch",
                 notes: "Ausweisnummer steht auf der Karte.", totp: ""),
        Erwartet(title: "Velo-Club", username: "velofahrer", firstPassword: "Rad&Weg-2026",
                 password: "Kette+Sattel-77", url: "velo.example.ch", notes: "",
                 totp: "otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club"),
        Erwartet(title: "Notiz ohne Website", username: "", firstPassword: "", password: "",
                 url: "", notes: "Zeilen\nmit Umlauten: äöü, Zeichen: «» – Ende", totp: ""),
    ]

    static func url() throws -> URL {
        guard let dir = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
            throw SiegelError.io("test.fixtures")
        }
        return dir.appendingPathComponent("v2_beispiel.siegel", isDirectory: false)
    }

    static func secret(_ b: [UInt8]) throws -> FactorSecret { try FactorSecret(copying: b) }

    static func factors() throws -> FactorSecrets {
        FactorSecrets(secureEnclave: try secret(ecdhSE), card: try secret(q), securityKey: try secret(hmacOutput))
    }

    static func entryPublicKey() throws -> Data {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: entryPrivateScalar).publicKey.x963Representation
    }

    static func material() throws -> NewFactorMaterial {
        NewFactorMaterial(
            secureEnclave: SEEnrollment(keyID: seKeyID, secret: try secret(ecdhSE)),
            entryKey: EntryKeyEnrollment(keyID: entryKeyID, publicKey: try entryPublicKey()),
            card: CardEnrollment(q: try secret(q)),
            securityKey: SecurityKeyEnrollment(credentialID: Data(credentialID), salt: Data(fidoSalt),
                                               output: try secret(hmacOutput), entrySalt: Data(entrySalt),
                                               entryOutput: try secret(entryOutput)))
    }

    /// Prüft den Inhalt gegen die erwarteten Einträge.
    static func check(_ vault: UnlockedVault, level: SecurityLevel = .festung) {
        let entries = vault.entries
        #expect(entries.count == erwartet.count)
        for e in erwartet {
            let found = entries.first { $0.title == e.title }
            #expect(found != nil)
            #expect(found?.username == e.username)
            #expect(found?.password == e.password)
            #expect(found?.url == e.url)
            #expect(found?.notes == e.notes)
            #expect(found?.totp == e.totp)
            if e.firstPassword != e.password {
                #expect(found?.history.map(\.password) == [e.firstPassword])
            }
        }
        #expect(vault.recoveryConfirmed)
        #expect(vault.level == level)
        #expect(vault.kdf == kdf)
    }
}
