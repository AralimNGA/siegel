import Foundation

/// Minimaler, strikter CBOR-Teil (RFC 8949) für CTAP2. Daten vom USB-Gerät sind Angriffsfläche (SPEC §14.3):
/// Der Dekodierer akzeptiert nur die kanonische CTAP2-Form – kürzeste Längen, keine unbestimmten Längen, keine
/// Tags, keine Gleitkommazahlen, gültiges UTF-8, Map-Schlüssel ohne Doppel und in kanonischer Reihenfolge – mit
/// Tiefen-, Anzahl- und Längengrenzen. Der Kodierer schreibt Anfragen immer kanonisch.
package indirect enum CBOR: Equatable, Sendable {
    case unsigned(UInt64)
    /// Wert = −1 − n
    case negative(UInt64)
    case bytes([UInt8])
    case text(String)
    case array([CBOR])
    /// Paare in Kodierreihenfolge.
    case map([CBORPair])
    case bool(Bool)
    case null

    package static func int(_ v: Int64) -> CBOR {
        v >= 0 ? .unsigned(UInt64(v)) : .negative(UInt64(-(v + 1)))
    }

    package var intValue: Int64? {
        switch self {
        case .unsigned(let u): u <= UInt64(Int64.max) ? Int64(u) : nil
        case .negative(let n): n <= UInt64(Int64.max) ? -1 - Int64(n) : nil
        default: nil
        }
    }

    package var unsignedValue: UInt64? { if case .unsigned(let u) = self { u } else { nil } }
    package var bytesValue: [UInt8]? { if case .bytes(let b) = self { b } else { nil } }
    package var textValue: String? { if case .text(let t) = self { t } else { nil } }
    package var boolValue: Bool? { if case .bool(let b) = self { b } else { nil } }
    package var arrayValue: [CBOR]? { if case .array(let a) = self { a } else { nil } }
    package var mapValue: [CBORPair]? { if case .map(let m) = self { m } else { nil } }

    /// Wert zu einem Map-Schlüssel (nil, wenn kein Map oder Schlüssel fehlt).
    package subscript(key: CBOR) -> CBOR? {
        mapValue?.first(where: { $0.key == key })?.value
    }

    package subscript(int key: Int64) -> CBOR? { self[.int(key)] }
    package subscript(text key: String) -> CBOR? { self[.text(key)] }
}

package struct CBORPair: Equatable, Sendable {
    package let key: CBOR
    package let value: CBOR
    package init(_ key: CBOR, _ value: CBOR) {
        self.key = key
        self.value = value
    }
}

package enum CBORError: Error, Equatable, Sendable {
    case truncated
    case trailingBytes
    case nonMinimal
    case indefiniteLength
    case reservedInfo
    case unsupportedType
    case tooDeep
    case tooManyItems
    case tooLong
    case invalidUTF8
    case invalidKey
    case duplicateKey
    case unorderedKeys
}

package struct CBORLimits: Sendable {
    package var maxDepth = 8
    package var maxItems = 4096
    package var maxStringLength = 8192
    package init() {}
    package static let standard = CBORLimits()
}

// MARK: - Kodierer (kanonisch, CTAP2 §8)

package enum CBOREncoder {
    package static func encode(_ value: CBOR) throws(CBORError) -> [UInt8] {
        var out: [UInt8] = []
        try encode(value, into: &out, depth: 0)
        return out
    }

    private static func encode(_ value: CBOR, into out: inout [UInt8], depth: Int) throws(CBORError) {
        guard depth < CBORLimits.standard.maxDepth else { throw .tooDeep }
        switch value {
        case .unsigned(let u): head(0, u, into: &out)
        case .negative(let n): head(1, n, into: &out)
        case .bytes(let b):
            head(2, UInt64(b.count), into: &out)
            out += b
        case .text(let t):
            let utf8 = Array(t.utf8)
            head(3, UInt64(utf8.count), into: &out)
            out += utf8
        case .array(let items):
            head(4, UInt64(items.count), into: &out)
            for item in items { try encode(item, into: &out, depth: depth + 1) }
        case .map(let pairs):
            var encoded: [(key: [UInt8], pair: CBORPair)] = []
            encoded.reserveCapacity(pairs.count)
            for pair in pairs {
                var k: [UInt8] = []
                try encode(pair.key, into: &k, depth: depth + 1)
                encoded.append((k, pair))
            }
            encoded.sort { canonicalOrder($0.key, $1.key) < 0 }
            for i in encoded.indices.dropFirst() where encoded[i - 1].key == encoded[i].key {
                throw .duplicateKey
            }
            head(5, UInt64(encoded.count), into: &out)
            for e in encoded {
                out += e.key
                try encode(e.pair.value, into: &out, depth: depth + 1)
            }
        case .bool(let b): out.append(b ? 0xF5 : 0xF4)
        case .null: out.append(0xF6)
        }
    }

    static func head(_ major: UInt8, _ value: UInt64, into out: inout [UInt8]) {
        let m = major << 5
        switch value {
        case 0..<24:
            out.append(m | UInt8(value))
        case 24...0xFF:
            out.append(m | 24); out.append(UInt8(value))
        case 0x100...0xFFFF:
            out.append(m | 25)
            out.append(UInt8(value >> 8)); out.append(UInt8(value & 0xFF))
        case 0x10000...0xFFFF_FFFF:
            out.append(m | 26)
            for shift in stride(from: 24, through: 0, by: -8) { out.append(UInt8((value >> UInt64(shift)) & 0xFF)) }
        default:
            out.append(m | 27)
            for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((value >> UInt64(shift)) & 0xFF)) }
        }
    }

    /// Kanonische Reihenfolge nach CTAP2: zuerst Haupttyp, dann Länge der Kodierung, dann Bytes.
    /// Ergebnis < 0: `a` vor `b`.
    package static func canonicalOrder(_ a: some Collection<UInt8>, _ b: some Collection<UInt8>) -> Int {
        let ma = (a.first ?? 0) >> 5, mb = (b.first ?? 0) >> 5
        if ma != mb { return ma < mb ? -1 : 1 }
        if a.count != b.count { return a.count < b.count ? -1 : 1 }
        for (x, y) in zip(a, b) where x != y { return x < y ? -1 : 1 }
        return 0
    }
}

// MARK: - Dekodierer (strikt)

package struct CBORDecoder {
    private let bytes: [UInt8]
    private let limits: CBORLimits
    private(set) var offset: Int
    private var items = 0

    private init(_ bytes: [UInt8], offset: Int, limits: CBORLimits) {
        self.bytes = bytes
        self.offset = offset
        self.limits = limits
    }

    /// Genau ein Datenelement, keine Restbytes.
    package static func decode(_ bytes: [UInt8], limits: CBORLimits = .standard) throws(CBORError) -> CBOR {
        var d = CBORDecoder(bytes, offset: 0, limits: limits)
        let value = try d.item(depth: 0)
        guard d.offset == bytes.count else { throw .trailingBytes }
        return value
    }

    /// Ein Datenelement ab `offset`; liefert es und die Position danach (für authenticatorData).
    package static func decodePrefix(_ bytes: [UInt8], at offset: Int,
                                     limits: CBORLimits = .standard) throws(CBORError) -> (CBOR, Int) {
        guard offset >= 0, offset <= bytes.count else { throw .truncated }
        var d = CBORDecoder(bytes, offset: offset, limits: limits)
        let value = try d.item(depth: 0)
        return (value, d.offset)
    }

    private var remaining: Int { bytes.count - offset }

    private mutating func byte() throws(CBORError) -> UInt8 {
        guard offset < bytes.count else { throw .truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    /// Kopf lesen: Haupttyp, Zusatzinfo, Wert (kürzeste Form erzwungen).
    private mutating func head() throws(CBORError) -> (major: UInt8, info: UInt8, value: UInt64) {
        let ib = try byte()
        let major = ib >> 5, info = ib & 0x1F
        switch info {
        case 0..<24:
            return (major, info, UInt64(info))
        case 24:
            let v = UInt64(try byte())
            guard v >= 24 || major == 7 else { throw .nonMinimal }
            return (major, info, v)
        case 25, 26, 27:
            let n = info == 25 ? 2 : (info == 26 ? 4 : 8)
            guard remaining >= n else { throw .truncated }
            var v: UInt64 = 0
            for _ in 0..<n { v = v << 8 | UInt64(try byte()) }
            if major != 7 {
                let minimum: UInt64 = info == 25 ? 0x100 : (info == 26 ? 0x1_0000 : 0x1_0000_0000)
                guard v >= minimum else { throw .nonMinimal }
            }
            return (major, info, v)
        case 31:
            throw .indefiniteLength
        default:
            throw .reservedInfo
        }
    }

    private mutating func item(depth: Int) throws(CBORError) -> CBOR {
        guard depth < limits.maxDepth else { throw .tooDeep }
        items += 1
        guard items <= limits.maxItems else { throw .tooManyItems }
        let h = try head()
        switch h.major {
        case 0:
            return .unsigned(h.value)
        case 1:
            return .negative(h.value)
        case 2, 3:
            guard h.value <= UInt64(limits.maxStringLength) else { throw .tooLong }
            let n = Int(h.value)
            guard n <= remaining else { throw .truncated }
            let slice = Array(bytes[offset..<(offset + n)])
            offset += n
            if h.major == 2 { return .bytes(slice) }
            guard let text = String(validating: slice, as: UTF8.self) else { throw .invalidUTF8 }
            return .text(text)
        case 4:
            // Jedes Element braucht mindestens ein Byte: grössere Angaben sind sicher falsch (keine Riesen-Allokation).
            guard h.value <= UInt64(remaining) else { throw .truncated }
            var out: [CBOR] = []
            out.reserveCapacity(Int(h.value))
            for _ in 0..<Int(h.value) { out.append(try item(depth: depth + 1)) }
            return .array(out)
        case 5:
            guard h.value <= UInt64(remaining / 2) else { throw .truncated }
            var pairs: [CBORPair] = []
            pairs.reserveCapacity(Int(h.value))
            var previousKey: ArraySlice<UInt8>?
            for _ in 0..<Int(h.value) {
                let keyStart = offset
                let key = try item(depth: depth + 1)
                switch key {
                case .unsigned, .negative, .text, .bytes: break
                default: throw .invalidKey
                }
                let keyBytes = bytes[keyStart..<offset]
                if let previousKey {
                    let order = CBOREncoder.canonicalOrder(previousKey, keyBytes)
                    if order == 0 { throw .duplicateKey }
                    if order > 0 { throw .unorderedKeys }
                }
                previousKey = keyBytes
                let value = try item(depth: depth + 1)
                pairs.append(CBORPair(key, value))
            }
            return .map(pairs)
        case 6:
            throw .unsupportedType
        default: // 7
            switch h.info {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            default: throw .unsupportedType
            }
        }
    }
}
