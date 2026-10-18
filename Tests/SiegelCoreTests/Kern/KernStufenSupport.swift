import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Faktor-Material für Tests (zufällig, wie es das Hardware-Modul liefern würde) und die passenden rohen Werte.
struct KernFaktoren {
    let seKeyID = UUID()
    let ecdhSE: [UInt8]
    let entryKeyID = UUID()
    let entryPublicKey: Data
    let q: FactorSecret
    let credentialID: [UInt8]
    let salt: [UInt8]
    let output: [UInt8]
    let entrySalt: [UInt8]
    let entryOutput: [UInt8]

    init() throws {
        ecdhSE = randomBytes(32)
        entryPublicKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        q = CardCode.generate()
        credentialID = randomBytes(48)
        salt = randomBytes(32)
        output = randomBytes(32)
        entrySalt = randomBytes(32)
        entryOutput = randomBytes(32)
    }

    func secret(_ b: [UInt8]) throws -> FactorSecret { try FactorSecret(copying: b) }

    /// Rohe Werte für das Öffnen (nur die verlangten).
    func secrets(_ set: FactorSet = .all) throws -> FactorSecrets {
        FactorSecrets(secureEnclave: set.contains(.secureEnclave) ? try secret(ecdhSE) : nil,
                      card: set.contains(.card) ? q : nil,
                      securityKey: set.contains(.securityKey) ? try secret(output) : nil)
    }

    var seEnrollment: SEEnrollment { get throws { SEEnrollment(keyID: seKeyID, secret: try secret(ecdhSE)) } }
    var entryKey: EntryKeyEnrollment { EntryKeyEnrollment(keyID: entryKeyID, publicKey: entryPublicKey) }
    var card: CardEnrollment { CardEnrollment(q: q) }
    var securityKey: SecurityKeyEnrollment {
        get throws {
            SecurityKeyEnrollment(credentialID: Data(credentialID), salt: Data(salt), output: try secret(output),
                                  entrySalt: Data(entrySalt), entryOutput: try secret(entryOutput))
        }
    }

    /// Material für genau die Faktoren einer Stufe (plus Eintrags-SE-Schlüssel).
    func material(for level: SecurityLevel, entryKey withEntryKey: Bool = true) throws -> NewFactorMaterial {
        NewFactorMaterial(secureEnclave: level.factors.contains(.secureEnclave) ? try seEnrollment : nil,
                          entryKey: withEntryKey ? entryKey : nil,
                          card: level.factors.contains(.card) ? card : nil,
                          securityKey: level.factors.contains(.securityKey) ? try securityKey : nil)
    }
}

enum KernStufen {
    /// Bestätigungsgruppen eines vorbereiteten Kits (beide Schemata).
    static func confirmation(_ p: PendingRecovery) -> [String] {
        switch p.scheme {
        case .single: return p.confirmationGroups.map { p.code.groups[$0] }
        case .shamir2of3: return p.shareConfirmationGroups.enumerated().map { k, g in p.shares[k].groups[g] }
        }
    }

    /// Stufe wechseln; bringt bei Schema-Wechsel ein neues Kit mit. Liefert das neue Kit (falls eins nötig war).
    @discardableResult
    static func change(_ vault: UnlockedVault, to level: SecurityLevel, faktoren: KernFaktoren,
                       current: FactorSet, newMaterial: NewFactorMaterial? = nil,
                       password: String = KT.pw1) throws -> PendingRecovery? {
        var pending: PendingRecovery?
        if vault.headerInfo.recoveryScheme != level.recoveryScheme {
            pending = try vault.prepareRecovery(masterPassword: password, factors: try faktoren.secrets(current),
                                                scheme: level.recoveryScheme)
        }
        try vault.changeSecurityLevel(to: level, masterPassword: password, currentFactors: try faktoren.secrets(current),
                                      newFactors: try newMaterial ?? faktoren.material(for: level),
                                      recovery: pending, recoveryConfirmation: pending.map(confirmation) ?? [])
        return pending
    }

    /// Test-Tresor direkt auf Stufe `level` (Testschalter-KDF). Liefert auch das gültige Kit.
    static func make(_ level: SecurityLevel) throws -> (KernVault, KernFaktoren, PendingRecovery?) {
        let f = try KernVault.make()
        let faktoren = try KernFaktoren()
        let kit = try change(f.vault, to: level, faktoren: faktoren, current: [])
        return (f, faktoren, kit)
    }
}
