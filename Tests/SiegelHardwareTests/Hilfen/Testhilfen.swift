import CommonCrypto
import CryptoKit
import Foundation
import SiegelCore
@testable import SiegelHardware

/// Reproduzierbarer Zufall für Fuzz-Tests (SplitMix64).
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func bytes(_ n: Int) -> [UInt8] { (0..<n).map { _ in UInt8.random(in: 0...255, using: &self) } }
}

extension FactorSecret {
    var testBytes: [UInt8] { withUnsafeBytes { Array($0) } }
}

extension SecretScratch {
    var testBytes: [UInt8] { withUnsafeBytes { Array($0) } }
}

func hex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []
    var it = s.filter { !$0.isWhitespace }.makeIterator()
    while let a = it.next(), let b = it.next() {
        out.append(UInt8(String([a, b]), radix: 16) ?? 0)
    }
    return out
}

func hexString(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

/// Gemeinsamer Wurzelordner dieses Testlaufs; Reste des vorigen Laufs werden beim ersten Zugriff entfernt.
private let testRoot: URL = {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("siegel-hardware-tests", isDirectory: true)
    try? FileManager.default.removeItem(at: root)
    try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
}()

/// Neuer, leerer Temp-Ordner pro Test.
func tempDirectory(_ name: String = "siegel-hw") -> URL {
    let url = testRoot.appendingPathComponent("\(name)-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

/// Karteninhalt im Format von SPEC §14.2 (`SIEGELKARTE1:` + Crockford-Base32 von q ‖ 2 B), ohne SiegelCore.CardCode.
func cardPayloadForTests(seed: UInt64 = 1) -> String {
    var rng = SplitMix64(seed: seed)
    let q = rng.bytes(32)
    var h = SHA3_256()
    h.update(data: Array("Siegel v2 card checksum".utf8))
    h.update(data: q)
    let data = q + Array(h.finalize())[0..<2]
    let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    var bits = 0, value = 0
    var out = ""
    for byte in data {
        value = (value << 8) | Int(byte)
        bits += 8
        while bits >= 5 {
            out.append(alphabet[(value >> (bits - 5)) & 0x1F])
            bits -= 5
        }
        value &= (1 << bits) - 1
    }
    if bits > 0 { out.append(alphabet[(value << (5 - bits)) & 0x1F]) }
    return "SIEGELKARTE1:" + out
}

// MARK: - Unabhängige Krypto für die Gegenseite (nicht der Code unter Test)

enum Gegenseite {
    /// HKDF-SHA-256 (RFC 5869) von Hand: Extract + ein Expand-Block.
    static func hkdf32(ikm: [UInt8], salt: [UInt8], info: [UInt8]) -> [UInt8] {
        let prk = Array(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt)))
        return Array(HMAC<SHA256>.authenticationCode(for: info + [0x01], using: SymmetricKey(data: prk)))
    }

    static func hmac(_ key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    static func aes(_ encrypt: Bool, key: [UInt8], iv: [UInt8], _ input: [UInt8]) -> [UInt8]? {
        guard input.count % 16 == 0, !input.isEmpty else { return nil }
        var out = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let status = CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0,
                             key, key.count, iv, input, input.count, &out, out.count, &moved)
        return status == kCCSuccess && moved == input.count ? out : nil
    }

    /// Gemeinsames Geheimnis nach PIN/UV-Protokoll: (HMAC-Schlüssel, AES-Schlüssel).
    static func pinSecret(_ version: Int, z: [UInt8]) -> (hmac: [UInt8], aes: [UInt8]) {
        if version == 1 {
            let k = Array(SHA256.hash(data: z))
            return (k, k)
        }
        let zero = [UInt8](repeating: 0, count: 32)
        return (hkdf32(ikm: z, salt: zero, info: Array("CTAP2 HMAC key".utf8)),
                hkdf32(ikm: z, salt: zero, info: Array("CTAP2 AES key".utf8)))
    }
}

extension CTAPHIDTimeouts {
    /// Kurze Fristen, damit Zeitüberschreitungen im Test schnell kommen.
    static var test: CTAPHIDTimeouts {
        var t = CTAPHIDTimeouts()
        t.initialize = .milliseconds(250)
        t.command = .milliseconds(250)
        t.userPresence = .milliseconds(300)
        t.cancelDrain = .milliseconds(60)
        t.busyRetry = .milliseconds(5)
        return t
    }

    static var fuzz: CTAPHIDTimeouts {
        var t = CTAPHIDTimeouts()
        t.initialize = .milliseconds(40)
        t.command = .milliseconds(40)
        t.userPresence = .milliseconds(40)
        t.cancelDrain = .milliseconds(10)
        t.busyRetry = .milliseconds(2)
        return t
    }
}
