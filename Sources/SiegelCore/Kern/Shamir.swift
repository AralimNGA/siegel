import CryptoKit
import Foundation

/// GF(2^8) mit Reduktionspolynom x^8 + x^4 + x^3 + x + 1 (0x11B), ohne Tabellen und ohne datenabhängige
/// Verzweigungen (SPEC §15).
enum GF256 {
    @inline(__always)
    static func mul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var a = a
        var b = b
        var r: UInt8 = 0
        for _ in 0..<8 {
            r ^= a & (0 &- (b & 1))
            let hi = a >> 7
            a = (a << 1) ^ (0x1B & (0 &- hi))
            b >>= 1
        }
        return r
    }

    /// a^254 = a^-1 (für a = 0 ergibt sich 0). Feste Multiplikationsfolge.
    static func inv(_ a: UInt8) -> UInt8 {
        var result: UInt8 = 1
        var base = a
        var e: UInt8 = 254
        for _ in 0..<8 {
            let m = mul(result, base)
            let take = 0 &- (e & 1)
            result = (m & take) | (result & ~take)
            base = mul(base, base)
            e >>= 1
        }
        return result
    }
}

/// Notfallcode geteilt, 2 aus 3 (SPEC §15): `share_x[i] = R[i] ⊕ a[i]·x` über GF(2^8), x ∈ {1, 2, 3}, `a` zufällig.
/// Ein Teil: x (1 B) ‖ share (32 B) ‖ Prüfsumme (2 B) = 35 Byte = 280 Bit → 56 Crockford-Base32-Zeichen (ohne
/// Füllbits), Gruppen à 5 (die letzte Gruppe hat 1 Zeichen). Prüfsumme = SHA3-256("Siegel v2 share checksum" ‖ x ‖
/// share)[0..<2].
enum Shamir {
    static let shareCount = 3
    static let shareBytes = 35
    static let symbolCount = 56
    static let groupSize = 5
    /// Ganze Gruppen à 5 (0…10); zur Bestätigung wird nur eine davon verlangt.
    static let fullGroups = 11
    static let checksumLabel = Array("Siegel v2 share checksum".utf8)

    /// R → drei Teile (y-Werte; x = Index + 1). `a` liegt nur kurz in einer sicheren Rechenfläche.
    static func split(_ r: SecureBytes) throws -> [SecureBytes] {
        try split(r, coefficients: try SecureBytes.random(count: RecoveryKEM.rBytes))
    }

    /// Mit festem `a` (Testvektoren).
    static func split(_ r: SecureBytes, coefficients a: SecureBytes) throws -> [SecureBytes] {
        precondition(r.count == RecoveryKEM.rBytes && a.count == RecoveryKEM.rBytes, "shamir.rLength")
        return try (1...UInt8(shareCount)).map { x in
            try SecureBytes(count: RecoveryKEM.rBytes) { out in
                r.withUnsafeBytes { rb in
                    a.withUnsafeBytes { ab in
                        for i in 0..<RecoveryKEM.rBytes { out[i] = rb[i] ^ GF256.mul(ab[i], x) }
                    }
                }
            }
        }
    }

    /// Lagrange in 0 aus zwei Teilen mit verschiedenen x: R = y1·x2/(x1⊕x2) ⊕ y2·x1/(x1⊕x2).
    static func combine(x1: UInt8, y1: SecureBytes, x2: UInt8, y2: SecureBytes) throws -> SecureBytes {
        guard x1 >= 1, x1 <= 3, x2 >= 1, x2 <= 3, x1 != x2,
              y1.count == RecoveryKEM.rBytes, y2.count == RecoveryKEM.rBytes else {
            throw SiegelError.invalidRecoveryCodeFormat
        }
        let dInv = GF256.inv(x1 ^ x2)
        let l1 = GF256.mul(x2, dInv)
        let l2 = GF256.mul(x1, dInv)
        return try SecureBytes(count: RecoveryKEM.rBytes) { out in
            y1.withUnsafeBytes { a in
                y2.withUnsafeBytes { b in
                    for i in 0..<RecoveryKEM.rBytes { out[i] = GF256.mul(a[i], l1) ^ GF256.mul(b[i], l2) }
                }
            }
        }
    }

    // MARK: Format

    static func checksum(x: UInt8, y: UnsafeRawBufferPointer) -> (UInt8, UInt8) {
        var h = SHA3_256()
        h.update(data: checksumLabel)
        h.update(data: [x])
        h.update(bufferPointer: y)
        let d = Array(h.finalize().prefix(2))
        return (d[0], d[1])
    }

    /// Teil x mit y-Wert → "XXXXX-…-X" (56 Zeichen in 12 Gruppen).
    static func format(x: UInt8, y: SecureBytes) throws -> String {
        let packed = try SecureBytes(count: shareBytes) { out in
            out[0] = x
            y.withUnsafeBytes { src in
                for i in 0..<32 { out[1 + i] = src[i] }
                let (a, b) = checksum(x: x, y: src)
                out[33] = a
                out[34] = b
            }
        }
        var syms = packed.withUnsafeBytes { RecoveryCodeCodec.symbols(fromBytes: $0) }
        defer { for i in syms.indices { syms[i] = 0 } }
        return RecoveryCodeCodec.formatSymbols(syms, groupSize: groupSize)
    }

    /// Gepackter Teil (35 Byte) gültig? x ∈ {1, 2, 3} und Prüfsumme stimmt.
    static func isValid(_ p: UnsafeRawBufferPointer) -> Bool {
        guard p.count >= shareBytes, p[0] >= 1, p[0] <= 3 else { return false }
        let (a, b) = checksum(x: p[0], y: UnsafeRawBufferPointer(rebasing: p[1..<33]))
        return a == p[33] && b == p[34]
    }

    /// Exakte Eingabe (ohne "?") → (x, y). Formatfehler → `invalidRecoveryCodeFormat`, Prüfsumme oder x ∉ 1…3 →
    /// `recoveryCodeChecksum`.
    static func decode(_ input: String) throws -> (x: UInt8, y: SecureBytes) {
        var syms = try RecoveryCodeCodec.parseSymbols(input, allowUnknown: false, count: symbolCount)
        defer { for i in syms.indices { syms[i] = 0 } }
        let packed = try SecureBytes.scratch(count: shareBytes)
        try packed.withUnsafeMutableBytes { out in
            syms.withUnsafeBytes { RecoveryCodeCodec.pack($0, into: out, count: symbolCount) }
            // Ein ungültiges x ist (wie eine falsche Prüfsumme) meist ein Tippfehler in den ersten beiden Zeichen.
            guard isValid(UnsafeRawBufferPointer(out)) else { throw SiegelError.recoveryCodeChecksum }
        }
        let x = packed.withUnsafeBytes { $0[0] }
        return (x, try packed.slice(1..<33))
    }

    /// Index des Teils (1…3), wenn die Eingabe exakt gültig ist; sonst nil.
    static func index(of input: String) -> Int? {
        guard let d = try? decode(input) else { return nil }
        return Int(d.x)
    }

    // MARK: Fehlerkorrektur pro Teil

    /// Ein Kandidat für einen Teil: gepackte 35 Byte (sichere Fläche) und geänderte Positionen (0…55).
    struct Candidate: @unchecked Sendable {
        let packed: SecureBytes
        let changed: [Int]
        var x: UInt8 { packed.withUnsafeBytes { $0[0] } }
        func y() throws -> SecureBytes { try packed.slice(1..<33) }
        var symbols: [UInt8] {
            Array(packed.withUnsafeBytes { RecoveryCodeCodec.symbols(fromBytes: $0) }.prefix(symbolCount))
        }
    }

    private final class Collector: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [Candidate] = []
        private var overflow = false
        let limit: Int
        init(limit: Int) { self.limit = limit }
        func add(_ p: UnsafeMutablePointer<UInt8>, changed: [Int]) {
            guard let copy = try? SecureBytes(copying: UnsafeRawBufferPointer(start: p, count: shareBytes)) else { return }
            lock.withLock {
                if items.count < limit { items.append(Candidate(packed: copy, changed: changed)) } else { overflow = true }
            }
        }
        var all: [Candidate] { lock.withLock { items } }
    }

    /// Gepackte Eingabe (unbekannte Stellen = 0) in einer sicheren Rechenfläche (36 Byte: 1 Reserve für setSymbol).
    private static func withPacked(_ input: [UInt8], _ body: (UnsafeMutablePointer<UInt8>) -> Void) {
        guard let scratch = try? SecureBytes.scratch(count: shareBytes + 1) else { return }
        scratch.withUnsafeMutableBytes { buf in
            guard let p = buf.u8 else { return }
            for (i, v) in input.enumerated() {
                RecoveryCodeCorrection.setSymbol(p, i, v == RecoveryCodeCodec.unknownSymbol ? 0 : v)
            }
            body(p)
        }
    }

    @inline(__always)
    private static func valid(_ p: UnsafeMutablePointer<UInt8>) -> Bool {
        isValid(UnsafeRawBufferPointer(start: p, count: shareBytes))
    }

    /// Kandidaten einer Stufe (Prüfsumme und x gültig, noch ohne pk-Vergleich):
    ///   Stufe 0: die Eingabe selbst bzw. alle Belegungen der "?" (nur bei "?" gibt es keine weiteren Stufen),
    ///   Stufe 1: ein ersetztes Zeichen oder vertauschte Nachbarn, Stufe 2: zwei ersetzte Zeichen.
    static func candidates(_ input: [UInt8], tier: Int, limit: Int = 4096) -> [Candidate] {
        precondition(input.count == symbolCount, "shamir.symbolCount")
        let n = symbolCount
        let unknown = input.indices.filter { input[$0] == RecoveryCodeCodec.unknownSymbol }
        let out = Collector(limit: limit)
        switch tier {
        case 0 where !unknown.isEmpty:
            let total = 1 << (5 * unknown.count)
            let chunk = 4096
            DispatchQueue.concurrentPerform(iterations: (total + chunk - 1) / chunk) { c in
                withPacked(input) { p in
                    for combo in (c * chunk)..<min(total, (c + 1) * chunk) {
                        var v = combo
                        for pos in unknown {
                            RecoveryCodeCorrection.setSymbol(p, pos, UInt8(v & 31))
                            v >>= 5
                        }
                        if valid(p) { out.add(p, changed: unknown) }
                    }
                }
            }
        case 0:
            withPacked(input) { p in if valid(p) { out.add(p, changed: []) } }
        case 1 where unknown.isEmpty:
            DispatchQueue.concurrentPerform(iterations: n) { i in
                withPacked(input) { p in
                    for v in 0..<32 where UInt8(v) != input[i] {
                        RecoveryCodeCorrection.setSymbol(p, i, UInt8(v))
                        if valid(p) { out.add(p, changed: [i]) }
                    }
                    RecoveryCodeCorrection.setSymbol(p, i, input[i])
                    if i + 1 < n, input[i] != input[i + 1] {
                        RecoveryCodeCorrection.setSymbol(p, i, input[i + 1])
                        RecoveryCodeCorrection.setSymbol(p, i + 1, input[i])
                        if valid(p) { out.add(p, changed: [i, i + 1]) }
                    }
                }
            }
        case 2 where unknown.isEmpty:
            var pairs = [(Int, Int)]()
            pairs.reserveCapacity(n * (n - 1) / 2)
            for i in 0..<n { for j in (i + 1)..<n { pairs.append((i, j)) } }
            let list = pairs
            DispatchQueue.concurrentPerform(iterations: list.count) { idx in
                let (i, j) = list[idx]
                withPacked(input) { p in
                    for vi in 0..<32 where UInt8(vi) != input[i] {
                        RecoveryCodeCorrection.setSymbol(p, i, UInt8(vi))
                        for vj in 0..<32 where UInt8(vj) != input[j] {
                            RecoveryCodeCorrection.setSymbol(p, j, UInt8(vj))
                            if valid(p) { out.add(p, changed: [i, j]) }
                        }
                    }
                }
            }
        default:
            break
        }
        // Deterministische Reihenfolge (parallel gesammelt): wenige Änderungen zuerst, dann nach Position.
        return out.all.sorted { a, b in
            a.changed.count != b.changed.count ? a.changed.count < b.changed.count
                : a.changed.lexicographicallyPrecedes(b.changed)
        }
    }

    /// Sucht zwei Kandidaten (je einer pro Teil, verschiedene x), deren R die öffentlichen Schlüssel ergibt.
    /// Stufen werden in der Reihenfolge der Gesamtänderungen probiert und erst bei Bedarf berechnet.
    static func searchPair(_ a: [UInt8], _ b: [UInt8],
                           isMatch: (SecureBytes) -> Bool) -> (Candidate, Candidate)? {
        var cacheA: [Int: [Candidate]] = [:]
        var cacheB: [Int: [Candidate]] = [:]
        func list(_ input: [UInt8], _ tier: Int, _ cache: inout [Int: [Candidate]]) -> [Candidate] {
            if let c = cache[tier] { return c }
            let c = candidates(input, tier: tier)
            cache[tier] = c
            return c
        }
        for total in 0...4 {
            for ta in 0...2 {
                let tb = total - ta
                guard tb >= 0, tb <= 2 else { continue }
                let la = list(a, ta, &cacheA)
                guard !la.isEmpty else { continue }
                let lb = list(b, tb, &cacheB)
                for ca in la {
                    for cb in lb where ca.x != cb.x {
                        guard let ya = try? ca.y(), let yb = try? cb.y(),
                              let r = try? combine(x1: ca.x, y1: ya, x2: cb.x, y2: yb) else { continue }
                        if isMatch(r) { return (ca, cb) }
                    }
                }
            }
        }
        return nil
    }
}
