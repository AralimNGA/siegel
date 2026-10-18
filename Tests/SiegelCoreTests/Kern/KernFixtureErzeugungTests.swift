import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Erzeugt `Fixtures/v2_beispiel.siegel` – nur von Hand und nur einmal:
/// `SIEGEL_FIXTURE_V2_ZIEL=/pfad/v2_beispiel.siegel swift test --filter FixtureErzeugung`.
/// Die eingecheckten Dateien werden NIE neu erzeugt (sie müssen in jeder künftigen Version aufgehen).
/// `v1_beispiel.siegel` stammt vom Kern v3.1 (16.10.2026); der heutige Kern schreibt nur noch v2 und kann sie
/// nicht neu erzeugen.
@Suite("Fixture-Erzeugung (nur von Hand)", .serialized)
struct KernFixtureErzeugung {
    static let zielV2 = ProcessInfo.processInfo.environment["SIEGEL_FIXTURE_V2_ZIEL"]

    @Test(.enabled(if: zielV2 != nil))
    func erzeugeBeispielDateiV2() throws {
        guard let ziel = Self.zielV2 else { return }
        let B = KernBeispielDateiV2.self
        try TestHooks.$levelKDFOverride.withValue(B.kdf) {
            let dir = KernTempDir()
            let store = VaultStore(directory: dir.url.appendingPathComponent("Siegel", isDirectory: true),
                                   rollbackGuard: InMemoryRollbackGuard())
            let (vault, setup) = try store.create(masterPassword: B.password, kdf: B.kdf)
            try vault.commitRecovery(setup, confirmation: setup.confirmationGroups.map { setup.code.groups[$0] })
            for e in B.erwartet {
                try vault.upsert(VaultEntry(title: e.title, username: e.username, password: e.firstPassword,
                                            url: e.url, notes: e.notes, totp: e.totp))
            }
            let shamir = try vault.prepareRecovery(masterPassword: B.password, factors: FactorSecrets(),
                                                   scheme: .shamir2of3)
            let groups = shamir.shareConfirmationGroups.enumerated().map { k, g in shamir.shares[k].groups[g] }
            try vault.changeSecurityLevel(to: .festung, masterPassword: B.password, currentFactors: FactorSecrets(),
                                          newFactors: try B.material(), recovery: shamir,
                                          recoveryConfirmation: groups)
            // Verlauf: Velo-Club wechselt das Passwort (schon in Stufe 5 gespeichert)
            for e in B.erwartet where e.firstPassword != e.password {
                guard var current = vault.entries.first(where: { $0.title == e.title }) else { continue }
                current.password = e.password
                try vault.upsert(current)
            }

            let target = URL(fileURLWithPath: ziel)
            try? FileManager.default.removeItem(at: target)
            try FileManager.default.copyItem(at: store.vaultURL, to: target)

            let bytes = try FileIO.read(target, maxSize: FileFormat.maxFileBytes)
            let file = try VaultFile.parse(bytes)
            let pw = try PasswordNormalizer.secureBytes(B.password)
            let p = try KDF.deriveKEK(password: pw, salt: file.header.salt, params: file.header.kdf, limits: .production)
            let factors = try B.factors()
            let kek = try FactorKDF.kek(p: p, header: file.header, factors: factors)
            func hex(_ k: FactorKind, _ s: FactorSecret) throws -> String {
                try FactorKDF.factorKey(s, kind: k, vaultID: file.header.vaultID).hexForTesting()
            }
            var lines: [String] = []
            for s in shamir.shares { lines.append("share\(s.index)=\(s.formatted)") }
            lines.append("kit=\(shamir.code.kitID)")
            lines.append("vaultID=\(file.header.uuid.uuidString) generation=\(file.generation) size=\(bytes.count)")
            lines.append("sha256=\(KT.hex(SHA256.hash(data: bytes)))")
            lines.append("salt=\(KT.hex(file.header.salt))")
            lines.append("p=\(p.hexForTesting())")
            if let se = factors.secureEnclave { lines.append("e=\(try hex(.secureEnclave, se))") }
            if let q = factors.card { lines.append("c=\(try hex(.card, q))") }
            if let y = factors.securityKey { lines.append("y=\(try hex(.securityKey, y))") }
            lines.append("kek=\(kek.hexForTesting())")
            lines.append("cardTag=\(KT.hex(file.header.factorFields.cardTag ?? []))")
            try lines.joined(separator: "\n").write(to: target.appendingPathExtension("txt"), atomically: true,
                                                    encoding: .utf8)
        }
    }
}
