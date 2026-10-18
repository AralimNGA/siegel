import Darwin
import Foundation
import Security
import SiegelCore

// Gemeinsame Hilfen des Hardware-Moduls. SiegelHardware hängt nur an SiegelCore (nicht direkt an libsodium);
// darum eigene, kleine Geheimnis-Puffer für Zwischenwerte. Endergebnisse gehen immer in `FactorSecret`.

/// Veränderlicher Puffer für geheime Zwischenwerte: eigene Seiten, `mlock` (best effort), beim Freigeben mit
/// `memset_s` genullt. Nur intern; nie länger halten als nötig.
final class SecretScratch: @unchecked Sendable {
    private let base: UnsafeMutableRawPointer
    private let capacity: Int
    let count: Int

    init(count: Int) {
        let page = Int(getpagesize())
        let wanted = max(count, 1)
        let size = (wanted + page - 1) / page * page
        base = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: page)
        base.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        _ = mlock(base, size)
        capacity = size
        self.count = max(count, 0)
    }

    convenience init(copying bytes: UnsafeRawBufferPointer) {
        self.init(count: bytes.count)
        if let src = bytes.baseAddress, bytes.count > 0 {
            base.copyMemory(from: src, byteCount: bytes.count)
        }
    }

    deinit {
        _ = memset_s(base, capacity, 0, capacity)
        _ = munlock(base, capacity)
        base.deallocate()
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: base, count: count))
    }

    /// Teilbereich als `FactorSecret` (genau 32 Byte, sonst `crypto("factor.length")`).
    func factorSecret(_ range: Range<Int>) throws -> FactorSecret {
        guard range.lowerBound >= 0, range.upperBound <= count else { throw SiegelError.crypto("factor.length") }
        return try withUnsafeBytes { try FactorSecret(copying: UnsafeRawBufferPointer(rebasing: $0[range])) }
    }
}

/// Zufall aus dem System-CSPRNG (`SecRandomCopyBytes`). Für Salze, Nonces, Kennungen.
enum SecureRandom {
    static func bytes(_ count: Int) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        guard count > 0 else { return out }
        let status = out.withUnsafeMutableBytes { buf -> OSStatus in
            guard let p = buf.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, buf.count, p)
        }
        guard status == errSecSuccess else { throw SiegelError.crypto("random") }
        return out
    }
}

/// Vergleich ohne frühen Ausstieg (Laufzeit hängt nur von der Länge ab).
func constantTimeEqual(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}

func constantTimeEqual(_ a: FactorSecret, _ b: FactorSecret) -> Bool {
    a.withUnsafeBytes { pa in b.withUnsafeBytes { pb in constantTimeEqual(pa, pb) } }
}

func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    a.withUnsafeBytes { pa in b.withUnsafeBytes { pb in constantTimeEqual(pa, pb) } }
}

/// Nullt ein Array (best effort; Swift kann vorher Kopien angelegt haben).
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buf in
        if let p = buf.baseAddress, buf.count > 0 { _ = memset_s(p, buf.count, 0, buf.count) }
    }
}

func wipe(_ data: inout Data) {
    data.withUnsafeMutableBytes { buf in
        if let p = buf.baseAddress, buf.count > 0 { _ = memset_s(p, buf.count, 0, buf.count) }
    }
}

// MARK: - Byte-Hilfen (Big-Endian für CTAPHID, Little-Endian für die Schlüsseldatei)

extension Array where Element == UInt8 {
    mutating func appendBE16(_ v: UInt16) { append(UInt8(v >> 8)); append(UInt8(v & 0xff)) }
    mutating func appendBE32(_ v: UInt32) {
        append(UInt8(v >> 24)); append(UInt8((v >> 16) & 0xff)); append(UInt8((v >> 8) & 0xff)); append(UInt8(v & 0xff))
    }
    mutating func appendLE16(_ v: UInt16) { append(UInt8(v & 0xff)); append(UInt8(v >> 8)) }

    func readBE16(at i: Int) -> UInt16 { UInt16(self[i]) << 8 | UInt16(self[i + 1]) }
    func readBE32(at i: Int) -> UInt32 {
        UInt32(self[i]) << 24 | UInt32(self[i + 1]) << 16 | UInt32(self[i + 2]) << 8 | UInt32(self[i + 3])
    }
    func readLE16(at i: Int) -> UInt16 { UInt16(self[i]) | UInt16(self[i + 1]) << 8 }
}
