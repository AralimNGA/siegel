import CryptoKit
import Foundation

/// Mehrfaktor-Ableitung (SPEC §13.1, Format v2). Faktor-Werte kommen roh (ECDH_SE, q, hmac-secret-Ausgabe je
/// 32 Byte); die HKDFs rechnet nur der Kern:
///   e = HKDF-SHA512(ECDH_SE, salt = vaultID, info = "Siegel v2 factor secure-enclave", 32)
///   c = HKDF-SHA512(q,       salt = vaultID, info = "Siegel v2 factor card", 32)
///   y = HKDF-SHA512(hmacOut, salt = vaultID, info = "Siegel v2 factor fido2", 32)
///   KEK_pw = HKDF-SHA512(ikm = p ‖ [e] ‖ [c] ‖ [y], salt = kdfSalt, info = "Siegel v2 kek" ‖ factorMask, 32)
/// mit p = Argon2id(pw). In Format v1 ist KEK_pw = p.
enum FactorKDF {
    static let seInfo = Array("Siegel v2 factor secure-enclave".utf8)
    static let cardInfo = Array("Siegel v2 factor card".utf8)
    static let fidoInfo = Array("Siegel v2 factor fido2".utf8)
    static let kekInfo = Array("Siegel v2 kek".utf8)
    /// Prüfwert der FIDO-Entsperr-Ausgabe im verschlüsselten Inhalt (nur wenn der Schlüssel für Einträge, aber
    /// nicht zum Öffnen eingerichtet ist; erlaubt die spätere Aufnahme in die Tresor-Stufe ohne Neuregistrierung).
    static let fidoCheckInfo = Array("Siegel v2 fido check".utf8)
    static let fidoCheckBytes = 16

    static func info(for kind: FactorKind) -> [UInt8] {
        switch kind {
        case .secureEnclave: seInfo
        case .card: cardInfo
        case .securityKey: fidoInfo
        }
    }

    /// `HKDF<SHA512>(ikm, salt, info, count)` in `SecureBytes`.
    static func hkdf(_ ikm: UnsafeRawBufferPointer, salt: [UInt8], info: [UInt8], count: Int) throws -> SecureBytes {
        let key = HKDF<SHA512>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info,
                                         outputByteCount: count)
        return try key.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    /// e, c bzw. y aus dem rohen Faktor-Wert.
    static func factorKey(_ raw: FactorSecret, kind: FactorKind, vaultID: [UInt8]) throws -> SecureBytes {
        try raw.withUnsafeBytes { try hkdf($0, salt: vaultID, info: info(for: kind), count: 32) }
    }

    /// Fehlende Faktoren (`factorMissing`, in der Reihenfolge der Ableitung) und eine falsche Karte (`wrongCard`,
    /// über die Karten-Kennung im Kopf) erkennen, bevor gerechnet wird. v1 kennt keine Faktoren.
    static func precheck(_ header: VaultHeader, _ factors: FactorSecrets) throws {
        guard header.formatVersion >= 2 else { return }
        for kind in header.factors.kinds where factors.secret(kind) == nil {
            throw SiegelError.factorMissing(kind)
        }
        if let tag = header.factorFields.cardTag, let q = factors.card {
            guard CardCode.tagBytes(q: q, vaultID: header.vaultID) == tag else { throw SiegelError.wrongCard }
        }
    }

    /// KEK_pw aus p (Argon2-Ausgabe) und den Faktoren, die der Kopf verlangt. Zusätzliche Faktoren werden ignoriert.
    static func kek(p: SecureBytes, header: VaultHeader, factors: FactorSecrets) throws -> SecureBytes {
        guard header.formatVersion >= 2 else { return p }
        try precheck(header, factors)
        var keys: [SecureBytes] = []
        for kind in header.factors.kinds {
            guard let raw = factors.secret(kind) else { throw SiegelError.factorMissing(kind) }
            keys.append(try factorKey(raw, kind: kind, vaultID: header.vaultID))
        }
        return try kek(p: p, factorKeys: keys, salt: header.salt, mask: header.factors.rawValue)
    }

    /// KEK_pw = HKDF-SHA512(p ‖ Faktor-Schlüssel, salt = kdfSalt, info = "Siegel v2 kek" ‖ mask, 32).
    static func kek(p: SecureBytes, factorKeys: [SecureBytes], salt: [UInt8], mask: UInt8) throws -> SecureBytes {
        guard p.count == KDF.keyBytes, factorKeys.allSatisfy({ $0.count == 32 }) else {
            throw SiegelError.crypto("kek.length")
        }
        let ikm = try concatenate([p] + factorKeys)
        return try ikm.withUnsafeBytes { try hkdf($0, salt: salt, info: kekInfo + [mask], count: 32) }
    }

    /// Teile (je 32 Byte) aneinanderhängen, in `SecureBytes`.
    static func concatenate(_ parts: [SecureBytes]) throws -> SecureBytes {
        guard !parts.isEmpty, parts.allSatisfy({ $0.count == 32 }) else { throw SiegelError.crypto("kek.length") }
        return try SecureBytes(count: 32 * parts.count) { out in
            for (i, part) in parts.enumerated() {
                part.withUnsafeBytes { src in
                    if let s = src.baseAddress, let d = out.baseAddress { (d + 32 * i).copyMemory(from: s, byteCount: 32) }
                }
            }
        }
    }

    /// Ganzer Passwortweg: Faktoren prüfen → KDF-Bereich → Argon2 (oder Cache) → Faktoren einrechnen.
    static func deriveKEK(header: VaultHeader, password: SecureBytes, factors: FactorSecrets, limits: KDFLimits,
                          cache: KEKCache?) throws -> (kek: SecureBytes, p: SecureBytes) {
        try precheck(header, factors)
        let p: SecureBytes
        if let cache {
            p = try cache.argon(header: header, password: password, limits: limits)
        } else {
            p = try KDF.deriveKEK(password: password, salt: header.salt, params: header.kdf, limits: limits)
        }
        return (try kek(p: p, header: header, factors: factors), p)
    }

    /// Prüfwert einer FIDO-Entsperr-Ausgabe (nicht umkehrbar, domänengetrennt von y).
    static func fidoCheck(_ output: FactorSecret, vaultID: [UInt8]) throws -> [UInt8] {
        let c = try output.withUnsafeBytes { try hkdf($0, salt: vaultID, info: fidoCheckInfo, count: fidoCheckBytes) }
        return c.withUnsafeBytes { Array($0) }
    }
}

/// Öffentliche Hybrid-Schlüssel für den Eintrags-Schutz (SPEC §16.1): aus q bzw. der FIDO-Eintragsausgabe y2.
enum EntryKeyDerivation {
    static let cardSeedInfo = Array("Siegel v2 card entry ML-KEM-1024 seed".utf8)
    static let cardX25519Info = Array("Siegel v2 card entry X25519".utf8)
    static let fidoSeedInfo = Array("Siegel v2 fido entry ML-KEM-1024 seed".utf8)
    static let fidoX25519Info = Array("Siegel v2 fido entry X25519".utf8)

    static func cardPublicKeys(q: FactorSecret, vaultID: [UInt8]) throws -> RecoveryPublicKeys {
        try RecoveryKEM.derivePublicKeys(ikm: q.storage, vaultID: vaultID, seedInfo: cardSeedInfo,
                                         x25519Info: cardX25519Info)
    }

    static func fidoPublicKeys(entryOutput: FactorSecret, vaultID: [UInt8]) throws -> RecoveryPublicKeys {
        try RecoveryKEM.derivePublicKeys(ikm: entryOutput.storage, vaultID: vaultID, seedInfo: fidoSeedInfo,
                                         x25519Info: fidoX25519Info)
    }
}

extension FactorSecrets {
    func secret(_ kind: FactorKind) -> FactorSecret? {
        switch kind {
        case .secureEnclave: secureEnclave
        case .card: card
        case .securityKey: securityKey
        }
    }
}

extension FactorSecret {
    /// Vergleich in konstanter Zeit.
    func constantTimeEquals(_ other: FactorSecret) -> Bool { storage.constantTimeEquals(other.storage) }
}

/// Wiederverwendung der Argon2-Ausgabe bei gleichem Salz + gleichen Parametern (kein zweites Argon2). Gespeichert
/// wird p (vor den Faktoren), damit Sicherungen mit gleichem Salz, aber anderen Faktoren denselben Lauf nutzen.
final class KEKCache: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [[UInt8]: SecureBytes] = [:]

    func argon(header: VaultHeader, password: SecureBytes, limits: KDFLimits) throws -> SecureBytes {
        try limits.validate(header.kdf)
        var key = header.salt
        key.appendLE(header.kdf.opsLimit)
        key.appendLE(header.kdf.memLimitBytes)
        if let hit = lock.withLock({ items[key] }) { return hit }
        let p = try KDF.deriveKEK(password: password, salt: header.salt, params: header.kdf, limits: limits)
        lock.withLock { items[key] = p }
        return p
    }
}
