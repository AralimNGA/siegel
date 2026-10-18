import CryptoKit
import Foundation

/// Notfallcode (SPEC §1.5): R[32] ‖ Prüfsumme[2], Crockford-Base32 MSB-first, 55 Zeichen (3 Füllbits = 0),
/// 11 Gruppen à 5, getrennt mit "-". Kit-Kennung: 8 Zeichen "XXXX-XXXX".
///
/// Prüfsummen- und Kit-Label bleiben in allen Formatversionen "Siegel v1 …": Sie gehören zum gedruckten Kit, nicht
/// zur Datei. Ein v1-Tresor wird beim Speichern zu v2 und behält sein R; mit einem v2-Label passten die Prüfsumme
/// des gedruckten Codes und die Kit-Kennung auf dem Blatt nicht mehr (Abweichung von §13.2, siehe KERN-NOTIZEN.md).
enum RecoveryCodeCodec {
    static let alphabet: [UInt8] = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8)
    static let symbolCount = 55
    static let groupCount = 11
    static let groupSize = 5
    /// R ‖ Prüfsumme
    static let payloadBytes = 34
    /// 275 Bit → 35 Byte (die letzten 5 Bit immer 0)
    static let packedBytes = 35
    static let unknownSymbol: UInt8 = 0xFF
    static let maxUnknown = 4

    static let checksumLabel = Array("Siegel v1 recovery checksum".utf8)
    static let kitLabel = Array("Siegel v1 kit id".utf8)

    /// ASCII → Symbolwert (Gross/Klein egal, O→0, I/L→1, U ungültig); -1 = ungültig.
    private static let decodeTable: [Int8] = {
        var t = [Int8](repeating: -1, count: 128)
        for (i, c) in alphabet.enumerated() {
            t[Int(c)] = Int8(i)
            if c >= 65, c <= 90 { t[Int(c) + 32] = Int8(i) }
        }
        for (c, v) in [(UInt8(ascii: "O"), Int8(0)), (UInt8(ascii: "I"), 1), (UInt8(ascii: "L"), 1)] {
            t[Int(c)] = v
            t[Int(c) + 32] = v
        }
        return t
    }()

    static func symbolValue(_ ascii: UInt8) -> UInt8? {
        guard ascii < 128 else { return nil }
        let v = decodeTable[Int(ascii)]
        return v < 0 ? nil : UInt8(v)
    }

    // MARK: Eingabe

    /// Eingabe → `count` Symbole (Notfallcode 55, Teil 56). Unicode-White_Space und "-" werden ignoriert; "?" nur
    /// mit `allowUnknown` (höchstens 4). Sonst `invalidRecoveryCodeFormat`.
    static func parseSymbols(_ input: String, allowUnknown: Bool, count symbolCount: Int = symbolCount) throws -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(symbolCount)
        var unknown = 0
        for scalar in input.unicodeScalars {
            if scalar.properties.isWhitespace || scalar == "-" { continue }
            if scalar == "?" {
                unknown += 1
                guard allowUnknown, unknown <= maxUnknown else { throw SiegelError.invalidRecoveryCodeFormat }
                out.append(unknownSymbol)
            } else {
                guard scalar.isASCII, let v = symbolValue(UInt8(scalar.value)) else {
                    throw SiegelError.invalidRecoveryCodeFormat
                }
                out.append(v)
            }
            guard out.count <= symbolCount else { throw SiegelError.invalidRecoveryCodeFormat }
        }
        guard out.count == symbolCount else { throw SiegelError.invalidRecoveryCodeFormat }
        return out
    }

    // MARK: Bits

    /// `count` Symbole → Bytes, MSB-first (Notfallcode: 55 → 35 Byte, Füllbits = unterste 3 Bit von Byte 34).
    static func pack(_ symbols: UnsafeRawBufferPointer, into out: UnsafeMutableRawBufferPointer,
                     count symbolCount: Int = symbolCount) {
        var acc: UInt32 = 0
        var bits = 0
        var o = 0
        for i in 0..<symbolCount {
            acc = (acc << 5) | UInt32(symbols[i] & 31)
            bits += 5
            if bits >= 8 {
                bits -= 8
                out[o] = UInt8(truncatingIfNeeded: acc >> UInt32(bits))
                o += 1
                acc &= (UInt32(1) << UInt32(bits)) - 1
            }
        }
        if bits > 0 { out[o] = UInt8(truncatingIfNeeded: acc << UInt32(8 - bits)) }
    }

    /// Bytes → Base32-Symbole (MSB-first, letzte Bits mit 0 aufgefüllt).
    static func symbols(fromBytes bytes: UnsafeRawBufferPointer) -> [UInt8] {
        var out = [UInt8]()
        var acc: UInt32 = 0
        var bits = 0
        for b in bytes {
            acc = (acc << 8) | UInt32(b)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(UInt8((acc >> UInt32(bits)) & 31))
            }
            acc &= (UInt32(1) << UInt32(bits)) - 1
        }
        if bits > 0 { out.append(UInt8((acc << UInt32(5 - bits)) & 31)) }
        return out
    }

    /// Prüfsumme über R (2 Byte); `label` für andere Codes desselben Formats (QR-Karte).
    static func checksum(_ r: UnsafeRawBufferPointer, label: [UInt8] = checksumLabel) -> (UInt8, UInt8) {
        var h = SHA3_256()
        h.update(data: label)
        h.update(bufferPointer: r)
        var a: UInt8 = 0
        var b: UInt8 = 0
        h.finalize().withUnsafeBytes { d in
            a = d[0]
            b = d[1]
        }
        return (a, b)
    }

    /// Gepackter Puffer (35 Byte): Füllbits 0 und Prüfsumme korrekt?
    static func packedIsValid(_ packed: UnsafeRawBufferPointer,
                              label: [UInt8] = checksumLabel) -> (paddingOK: Bool, checksumOK: Bool) {
        let paddingOK = packed[34] == 0
        let (a, b) = checksum(UnsafeRawBufferPointer(rebasing: packed[0..<32]), label: label)
        return (paddingOK, a == packed[32] && b == packed[33])
    }

    // MARK: Ausgabe

    /// Symbolfolge → "XXXXX-XXXXX-…" (Gruppen à `groupSize`).
    static func formatSymbols(_ symbols: [UInt8], groupSize: Int) -> String {
        var out = [UInt8]()
        for (i, s) in symbols.enumerated() {
            if i > 0, i % groupSize == 0 { out.append(UInt8(ascii: "-")) }
            out.append(alphabet[Int(s & 31)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// R → formatierter Notfallcode.
    static func format(r: SecureBytes) throws -> String {
        precondition(r.count == RecoveryKEM.rBytes, "recovery.rLength")
        let payload = try SecureBytes(count: payloadBytes) { out in
            r.withUnsafeBytes { src in
                for i in 0..<32 { out[i] = src[i] }
                let (a, b) = checksum(src)
                out[32] = a
                out[33] = b
            }
        }
        var symbols = payload.withUnsafeBytes { symbols(fromBytes: $0) }
        defer { for i in symbols.indices { symbols[i] = 0 } }
        return formatSymbols(symbols, groupSize: groupSize)
    }

    /// Kit-Kennung = Base32 von SHA3-256("Siegel v1 kit id" ‖ pkM ‖ pkX)[0..<5] → "XXXX-XXXX".
    static func kitID(pkM: [UInt8], pkX: [UInt8]) -> String {
        var h = SHA3_256()
        h.update(data: kitLabel)
        h.update(data: pkM)
        h.update(data: pkX)
        let digest = Array(h.finalize())
        let symbols = Array(digest[0..<5]).withUnsafeBytes { symbols(fromBytes: $0) }
        return formatSymbols(symbols, groupSize: 4)
    }

    // MARK: Dekodieren (exakt)

    /// Exakter Code → R. Formatfehler/Füllbits → `invalidRecoveryCodeFormat`, Prüfsumme → `recoveryCodeChecksum`.
    static func decode(_ input: String) throws -> SecureBytes {
        var symbols = try parseSymbols(input, allowUnknown: false)
        defer { for i in symbols.indices { symbols[i] = 0 } }
        let packed = try SecureBytes.scratch(count: packedBytes)
        try packed.withUnsafeMutableBytes { out in
            symbols.withUnsafeBytes { pack($0, into: out) }
            let v = packedIsValid(UnsafeRawBufferPointer(out))
            guard v.paddingOK else { throw SiegelError.invalidRecoveryCodeFormat }
            guard v.checksumOK else { throw SiegelError.recoveryCodeChecksum }
        }
        return try packed.slice(0..<32)
    }

    /// Normalisiert eine eingetippte Gruppe (Bestätigung) auf Alphabet-Zeichen; nil bei ungültigen Zeichen.
    static func normalizedGroup(_ input: String) -> String? {
        var out = [UInt8]()
        for scalar in input.unicodeScalars {
            if scalar.properties.isWhitespace || scalar == "-" { continue }
            guard scalar.isASCII, let v = symbolValue(UInt8(scalar.value)) else { return nil }
            out.append(alphabet[Int(v)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}

// MARK: - Fehlerkorrektur

/// Sucht zu einem fehlerhaften Code den richtigen (SPEC §1.5): alle Belegungen der "?"; sonst 1 oder 2
/// ersetzte Zeichen und vertauschte Nachbarn. Kandidat = Füllbits 0, Prüfsumme stimmt und `isMatch`
/// (abgeleitete pkM/pkX = Kopf) ist wahr. Parallel über alle Kerne. Pro Kandidat werden nur die 5 geänderten
/// Bits im gepackten Puffer (sichere Rechenfläche) neu gesetzt.
enum RecoveryCodeCorrection {
    struct Hit: Sendable {
        let symbols: [UInt8]
        let changed: [Int]
    }

    /// Gemeinsamer Zustand der Suche (Treffer + Abbruch).
    private final class SearchState: @unchecked Sendable {
        private let lock = NSLock()
        private var hit: Hit?
        var found: Bool { lock.withLock { hit != nil } }
        func offer(_ h: Hit) {
            lock.withLock {
                if let cur = hit, cur.changed.count <= h.changed.count { return }
                hit = h
            }
        }
        var result: Hit? { lock.withLock { hit } }
    }

    /// Setzt das 5-Bit-Symbol an Position `pos` im gepackten Puffer (35 Byte, MSB-first).
    @inline(__always)
    static func setSymbol(_ p: UnsafeMutablePointer<UInt8>, _ pos: Int, _ value: UInt8) {
        let bit = 5 * pos
        let k = bit >> 3
        let shift = UInt16(11 - (bit & 7))
        let mask = UInt16(0x1F) << shift
        var w = (UInt16(p[k]) << 8) | UInt16(p[k + 1])
        w = (w & ~mask) | (UInt16(value & 31) << shift)
        p[k] = UInt8(truncatingIfNeeded: w >> 8)
        p[k + 1] = UInt8(truncatingIfNeeded: w)
    }

    /// Füllbits 0, Prüfsumme, dann der teure pk-Vergleich.
    @inline(__always)
    private static func check(_ p: UnsafeMutablePointer<UInt8>,
                              isMatch: (UnsafeRawBufferPointer) -> Bool) -> Bool {
        guard p[34] == 0 else { return false }
        let r = UnsafeRawBufferPointer(start: p, count: 32)
        let (a, b) = RecoveryCodeCodec.checksum(r)
        guard a == p[32], b == p[33] else { return false }
        return isMatch(r)
    }

    /// Gepackte Eingabe (unbekannte Stellen = 0) in einer sicheren Rechenfläche.
    private static func withPacked(_ input: [UInt8], _ body: (UnsafeMutablePointer<UInt8>) -> Void) {
        guard let scratch = try? SecureBytes.scratch(count: RecoveryCodeCodec.packedBytes + 1) else { return }
        scratch.withUnsafeMutableBytes { buf in
            guard let p = buf.u8 else { return }
            for (i, v) in input.enumerated() { setSymbol(p, i, v == RecoveryCodeCodec.unknownSymbol ? 0 : v) }
            body(p)
        }
    }

    /// Symbole eines Treffers aus dem gepackten Puffer.
    private static func symbols(_ p: UnsafeMutablePointer<UInt8>) -> [UInt8] {
        let all = RecoveryCodeCodec.symbols(fromBytes: UnsafeRawBufferPointer(start: p, count: RecoveryCodeCodec.packedBytes))
        return Array(all.prefix(RecoveryCodeCodec.symbolCount))
    }

    static func search(_ input: [UInt8], isMatch: @escaping @Sendable (UnsafeRawBufferPointer) -> Bool) -> Hit? {
        let n = RecoveryCodeCodec.symbolCount
        precondition(input.count == n, "recovery.symbolCount")
        let unknownPositions = input.indices.filter { input[$0] == RecoveryCodeCodec.unknownSymbol }
        let state = SearchState()

        if !unknownPositions.isEmpty {
            // Alle Belegungen der "?" (≤ 32^4), in Blöcken parallel.
            let k = unknownPositions.count
            let total = 1 << (5 * k)
            let chunk = 4096
            let chunks = (total + chunk - 1) / chunk
            DispatchQueue.concurrentPerform(iterations: chunks) { c in
                if state.found { return }
                withPacked(input) { p in
                    for combo in (c * chunk)..<min(total, (c + 1) * chunk) {
                        var x = combo
                        for pos in unknownPositions {
                            setSymbol(p, pos, UInt8(x & 31))
                            x >>= 5
                        }
                        if check(p, isMatch: isMatch) {
                            state.offer(Hit(symbols: symbols(p), changed: unknownPositions))
                            return
                        }
                    }
                }
            }
            return state.result
        }

        // 1 ersetztes Zeichen und vertauschte Nachbarn (billig, zuerst).
        DispatchQueue.concurrentPerform(iterations: n) { i in
            if state.found { return }
            withPacked(input) { p in
                for v in 0..<32 where UInt8(v) != input[i] {
                    setSymbol(p, i, UInt8(v))
                    if check(p, isMatch: isMatch) {
                        state.offer(Hit(symbols: symbols(p), changed: [i]))
                        return
                    }
                }
                setSymbol(p, i, input[i])
                if i + 1 < n, input[i] != input[i + 1] {
                    setSymbol(p, i, input[i + 1])
                    setSymbol(p, i + 1, input[i])
                    if check(p, isMatch: isMatch) {
                        state.offer(Hit(symbols: symbols(p), changed: [i, i + 1]))
                    }
                }
            }
        }
        if let hit = state.result { return hit }

        // 2 ersetzte Zeichen: alle Paare i < j, je 31 × 31 Werte.
        var pairs = [(Int, Int)]()
        pairs.reserveCapacity(n * (n - 1) / 2)
        for i in 0..<n { for j in (i + 1)..<n { pairs.append((i, j)) } }
        let pairList = pairs
        DispatchQueue.concurrentPerform(iterations: pairList.count) { idx in
            if state.found { return }
            let (i, j) = pairList[idx]
            withPacked(input) { p in
                for vi in 0..<32 where UInt8(vi) != input[i] {
                    setSymbol(p, i, UInt8(vi))
                    for vj in 0..<32 where UInt8(vj) != input[j] {
                        setSymbol(p, j, UInt8(vj))
                        if check(p, isMatch: isMatch) {
                            state.offer(Hit(symbols: symbols(p), changed: [i, j]))
                            return
                        }
                    }
                }
            }
        }
        return state.result
    }
}
