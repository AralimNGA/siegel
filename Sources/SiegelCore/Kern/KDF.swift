import Clibsodium
import Foundation

/// Erlaubter Bereich der Argon2id-Parameter (SPEC §1.1). Geprüft vor jedem Ableiten und vor jedem Schreiben.
struct KDFLimits: Sendable, Equatable {
    let minMem: UInt64
    let maxMem: UInt64
    let minOps: UInt32
    let maxOps: UInt32

    /// 256 MiB ≤ m ≤ 4 GiB, 3 ≤ t ≤ 10.
    static let production = KDFLimits(minMem: 256 << 20, maxMem: 4 << 30, minOps: 3, maxOps: 10)

    #if DEBUG
    /// Testschalter: verschiebt den Bereich auf 8 KiB ≤ m ≤ 1 MiB, 1 ≤ t ≤ 3 (weiterhin mit Grenzen).
    static let testing = KDFLimits(minMem: 8 << 10, maxMem: 1 << 20, minOps: 1, maxOps: 3)
    #endif

    func validate(_ p: KDFParameters) throws {
        guard p.memLimitBytes >= minMem, p.memLimitBytes <= maxMem, p.memLimitBytes % 1024 == 0,
              p.opsLimit >= minOps, p.opsLimit <= maxOps else {
            throw SiegelError.kdfParametersOutOfRange
        }
    }

    /// KDF-Profil einer Stufe (SPEC §13: Standard für 1–2, Stark für 3–5). Unter dem Testschalter auf den
    /// Testbereich verschoben (Standard → 8 KiB/t 1, Stark → 16 KiB/t 2), damit Stufenwechsel testbar bleiben.
    func profile(for level: SecurityLevel) -> KDFParameters {
        #if DEBUG
        if let fixed = TestHooks.levelKDFOverride { return fixed }
        if self == .testing {
            return level.kdf == .strong ? KDFParameters(opsLimit: 2, memLimitBytes: 16 << 10)
                : KDFParameters(opsLimit: 1, memLimitBytes: 8 << 10)
        }
        #endif
        return level.kdf
    }

    /// Schwächer als das Profil der Stufe (weniger Speicher oder weniger Durchläufe)?
    func isWeaker(_ p: KDFParameters, thanLevel level: SecurityLevel) -> Bool {
        let min = profile(for: level)
        return p.memLimitBytes < min.memLimitBytes || p.opsLimit < min.opsLimit
    }
}

/// Master-Passwort → KEK_pw (Argon2id v1.3, 32 Byte).
enum KDF {
    static let saltBytes = 16
    static let keyBytes = 32

    /// `crypto_pwhash` ≠ 0 → `kdfFailed` (nie `wrongPassword`). Nie auf dem Main-Thread.
    static func deriveKEK(password: SecureBytes, salt: [UInt8], params: KDFParameters,
                          limits: KDFLimits) throws -> SecureBytes {
        dispatchPrecondition(condition: .notOnQueue(.main))
        _ = Sodium.ready
        try limits.validate(params)
        guard salt.count == saltBytes else { throw SiegelError.corruptFile("header.salt") }
        var ops = UInt64(params.opsLimit)
        #if DEBUG
        if TestHooks.forceKDFFailure { ops = 0 }
        TestHooks.kdfCounter?.increment()
        TestHooks.kdfRendezvous?.arrive()
        TestHooks.kdfObserver?.observe()
        #endif
        let mem = Int(params.memLimitBytes)
        return try SecureBytes(count: keyBytes) { out in
            let rc: Int32 = password.withUnsafeBytes { pw in
                salt.withUnsafeBytes { s in
                    guard let o = out.u8, let sp = s.u8, let pp = pw.baseAddress else { return -1 }
                    return crypto_pwhash(o, UInt64(keyBytes),
                                         pp.assumingMemoryBound(to: CChar.self), UInt64(pw.count),
                                         sp, ops, mem, crypto_pwhash_alg_argon2id13())
                }
            }
            guard rc == 0 else { throw SiegelError.kdfFailed }
        }
    }
}

/// RFC 8265 OpaqueString (SPEC §1.1): Zs ausser U+0020 → U+0020, dann NFC. Nichts trimmen.
enum PasswordNormalizer {
    static func normalize(_ s: String) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in s.unicodeScalars {
            if scalar.properties.generalCategory == .spaceSeparator {
                scalars.append(" ")
            } else {
                scalars.append(scalar)
            }
        }
        return String(scalars).precomposedStringWithCanonicalMapping
    }

    /// Normalisierte UTF-8-Bytes in `SecureBytes`.
    static func secureBytes(_ s: String) throws -> SecureBytes {
        var n = normalize(s)
        return try n.withUTF8 { try SecureBytes(copying: UnsafeRawBufferPointer($0)) }
    }
}
