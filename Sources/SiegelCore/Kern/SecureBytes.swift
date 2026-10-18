import Clibsodium
import Foundation

/// Geheimnis-Puffer in `sodium_malloc`-Speicher (Guard-Pages, mlock), beim Freigeben genullt (`sodium_free`).
/// Standardmässig nach dem Befüllen schreibgeschützt (`sodium_mprotect_readonly`); veränderliche Puffer nur
/// für interne Rechenflächen (Code-Korrektur). SPEC §5.
final class SecureBytes: @unchecked Sendable {
    private let base: UnsafeMutableRawPointer
    let count: Int
    private let readOnly: Bool

    /// Legt `count` Byte an (genullt) und lässt sie von `fill` beschreiben. Scheitert `fill`, wird sofort freigegeben.
    init(count: Int, readOnly: Bool = true, _ fill: (UnsafeMutableRawBufferPointer) throws -> Void) throws {
        _ = Sodium.ready
        let size = max(count, 1)
        guard count >= 0, let p = sodium_malloc(size) else { throw SiegelError.crypto("memory.alloc") }
        sodium_memzero(p, size)
        do {
            try fill(UnsafeMutableRawBufferPointer(start: p, count: count))
        } catch {
            sodium_free(p)
            throw error
        }
        if readOnly { _ = sodium_mprotect_readonly(p) }
        self.base = p
        self.count = count
        self.readOnly = readOnly
    }

    /// Kopie von Bytes (z. B. CryptoKit-Ausgaben, Passwort-UTF-8).
    convenience init(copying bytes: UnsafeRawBufferPointer) throws {
        try self.init(count: bytes.count) { out in
            if let src = bytes.baseAddress, let dst = out.baseAddress, bytes.count > 0 {
                dst.copyMemory(from: src, byteCount: bytes.count)
            }
        }
    }

    static func copy<C: ContiguousBytes>(_ bytes: C) throws -> SecureBytes {
        try bytes.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    /// `count` Zufallsbytes aus `randombytes_buf`.
    static func random(count: Int) throws -> SecureBytes {
        try SecureBytes(count: count) { out in
            if let p = out.baseAddress, count > 0 { randombytes_buf(p, count) }
        }
    }

    /// Veränderliche, genullte Rechenfläche.
    static func scratch(count: Int) throws -> SecureBytes {
        try SecureBytes(count: count, readOnly: false) { _ in }
    }

    deinit {
        sodium_free(base)
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// Nur für Rechenflächen (`scratch`).
    func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        precondition(!readOnly, "secure.readonly")
        return try body(UnsafeMutableRawBufferPointer(start: base, count: count))
    }

    /// Teilbereich als neuer Puffer.
    func slice(_ range: Range<Int>) throws -> SecureBytes {
        precondition(range.lowerBound >= 0 && range.upperBound <= count, "secure.range")
        return try withUnsafeBytes { try SecureBytes(copying: UnsafeRawBufferPointer(rebasing: $0[range])) }
    }

    /// Vergleich in konstanter Zeit (`sodium_memcmp`).
    func constantTimeEquals(_ other: SecureBytes) -> Bool {
        guard other.count == count else { return false }
        return other.withUnsafeBytes { constantTimeEquals($0) }
    }

    func constantTimeEquals(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard bytes.count == count else { return false }
        if count == 0 { return true }
        guard let b = bytes.baseAddress else { return false }
        return sodium_memcmp(base, b, count) == 0
    }

    #if DEBUG
    /// Nur Tests: Inhalt als Hex (Testvektoren).
    func hexForTesting() -> String {
        withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
    }
    #endif
}

extension SecureBytes: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String { "SecureBytes(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: KeyValuePairs<String, Any>(), displayStyle: .class) }
}

// MARK: - Zeiger-Hilfen

extension UnsafeRawBufferPointer {
    /// Zeiger als `UInt8` (nil bei leerem Puffer ohne Adresse).
    var u8: UnsafePointer<UInt8>? { baseAddress?.assumingMemoryBound(to: UInt8.self) }
}

extension UnsafeMutableRawBufferPointer {
    var u8: UnsafeMutablePointer<UInt8>? { baseAddress?.assumingMemoryBound(to: UInt8.self) }
}

/// Zufallszahl in 0..<upper (gleichverteilt, `randombytes_uniform`).
func secureUniform(_ upper: UInt32) -> UInt32 {
    _ = Sodium.ready
    return randombytes_uniform(upper)
}

/// Zufallsbytes für nicht geheime Werte (Nonces, Salze, Kennungen).
func randomBytes(_ count: Int) -> [UInt8] {
    _ = Sodium.ready
    var out = [UInt8](repeating: 0, count: count)
    out.withUnsafeMutableBytes { buf in
        if let p = buf.baseAddress, count > 0 { randombytes_buf(p, count) }
    }
    return out
}

/// Kleinbuchstaben-Hex (nur für nicht geheime Werte wie Dateinamen und Kennungen).
func hexString<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
    let digits = Array("0123456789abcdef".utf8)
    var out = [UInt8]()
    for b in bytes {
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 0x0f)])
    }
    return String(decoding: out, as: UTF8.self)
}
