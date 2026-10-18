import Foundation
import Testing
@testable import SiegelHardware

@Suite("CBOR (strikt, kanonisch)")
struct CBORTests {
    /// Testvektoren aus RFC 8949, Anhang A (nur der von CTAP2 erlaubte Teil).
    static let vectors: [(CBOR, String)] = [
        (.unsigned(0), "00"), (.unsigned(1), "01"), (.unsigned(10), "0a"), (.unsigned(23), "17"),
        (.unsigned(24), "1818"), (.unsigned(25), "1819"), (.unsigned(100), "1864"), (.unsigned(1000), "1903e8"),
        (.unsigned(1_000_000), "1a000f4240"), (.unsigned(1_000_000_000_000), "1b000000e8d4a51000"),
        (.unsigned(UInt64.max), "1bffffffffffffffff"),
        (.negative(UInt64.max), "3bffffffffffffffff"),
        (.int(-1), "20"), (.int(-10), "29"), (.int(-100), "3863"), (.int(-1000), "3903e7"),
        (.bytes([]), "40"), (.bytes([1, 2, 3, 4]), "4401020304"),
        (.text(""), "60"), (.text("a"), "6161"), (.text("IETF"), "6449455446"), (.text("\"\\"), "62225c"),
        (.text("\u{00fc}"), "62c3bc"), (.text("\u{6c34}"), "63e6b0b4"), (.text("\u{10151}"), "64f0908591"),
        (.array([]), "80"), (.array([.unsigned(1), .unsigned(2), .unsigned(3)]), "83010203"),
        (.array([.unsigned(1), .array([.unsigned(2), .unsigned(3)]), .array([.unsigned(4), .unsigned(5)])]), "8301820203820405"),
        (.array((1...25).map { .unsigned($0) }), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
        (.map([]), "a0"),
        (.map([CBORPair(.unsigned(1), .unsigned(2)), CBORPair(.unsigned(3), .unsigned(4))]), "a201020304"),
        (.map([CBORPair(.text("a"), .unsigned(1)), CBORPair(.text("b"), .array([.unsigned(2), .unsigned(3)]))]), "a26161016162820203"),
        (.array([.text("a"), .map([CBORPair(.text("b"), .text("c"))])]), "826161a161626163"),
        (.bool(false), "f4"), (.bool(true), "f5"), (.null, "f6"),
    ]

    @Test func rfc8949Vektoren() throws {
        for (value, expected) in Self.vectors {
            #expect(hexString(try CBOREncoder.encode(value)) == expected)
            #expect(try CBORDecoder.decode(hex(expected)) == value)
        }
    }

    @Test func kanonischeSchluesselReihenfolge() throws {
        // CTAP2: Haupttyp zuerst, dann Länge, dann Bytes → 10, 100, -1, "a", "b", "aa"
        let map: CBOR = .map([
            CBORPair(.text("aa"), .null), CBORPair(.text("b"), .null), CBORPair(.int(-1), .null),
            CBORPair(.text("a"), .null), CBORPair(.unsigned(100), .null), CBORPair(.unsigned(10), .null),
        ])
        #expect(hexString(try CBOREncoder.encode(map)) == "a6" + "0af6" + "1864f6" + "20f6" + "6161f6" + "6162f6" + "626161f6")
        #expect(throws: CBORError.duplicateKey) {
            try CBOREncoder.encode(.map([CBORPair(.unsigned(1), .null), CBORPair(.unsigned(1), .bool(true))]))
        }
    }

    @Test(arguments: [
        ("1800", CBORError.nonMinimal), ("190017", .nonMinimal), ("1a0000ffff", .nonMinimal),
        ("1b00000000ffffffff", .nonMinimal), ("3800", .nonMinimal), ("5800", .nonMinimal), ("9800", .nonMinimal),
        ("9fff", .indefiniteLength), ("5f4100ff", .indefiniteLength), ("7f6161ff", .indefiniteLength), ("bfff", .indefiniteLength),
        ("1c", .reservedInfo), ("3d", .reservedInfo), ("5e", .reservedInfo),
        ("c074323031332d30332d32315432303a30343a30305a", .unsupportedType), ("f97c00", .unsupportedType),
        ("fa47c35000", .unsupportedType), ("fb3ff199999999999a", .unsupportedType), ("f7", .unsupportedType),
        ("f0", .unsupportedType), ("f820", .unsupportedType), ("f818", .unsupportedType),
        ("a201010102", .duplicateKey), ("a202000100", .unorderedKeys), ("a2616100 0100", .unorderedKeys),
        ("a2626161006162 00", .unorderedKeys), ("a18000", .invalidKey), ("a1a00000", .invalidKey), ("a1f500", .invalidKey),
        ("62c328", .invalidUTF8), ("61ff", .invalidUTF8), ("63eda080", .invalidUTF8),
        ("0000", .trailingBytes), ("a0a0", .trailingBytes),
        ("", .truncated), ("18", .truncated), ("19ff", .truncated), ("81", .truncated), ("a101", .truncated),
        ("4401", .truncated), ("5affffffff", .tooLong), ("7b0000000100000000", .tooLong),
        ("9bffffffffffffffff", .truncated), ("bbffffffffffffffff", .truncated), ("9a00010000", .truncated),
    ])
    func strikteAblehnung(input: String, error: CBORError) {
        #expect(throws: error) { try CBORDecoder.decode(hex(input)) }
    }

    @Test func tiefenUndAnzahlGrenzen() throws {
        let deep = [UInt8](repeating: 0x81, count: 8) + [0x00]
        #expect(throws: CBORError.tooDeep) { try CBORDecoder.decode(deep) }
        _ = try CBORDecoder.decode([UInt8](repeating: 0x81, count: 7) + [0x00])
        var limits = CBORLimits()
        limits.maxItems = 10
        #expect(throws: CBORError.tooManyItems) {
            try CBORDecoder.decode(try CBOREncoder.encode(.array((0..<20).map { .unsigned($0) })), limits: limits)
        }
        limits = CBORLimits()
        limits.maxStringLength = 4
        #expect(throws: CBORError.tooLong) { try CBORDecoder.decode(hex("4501 02030405"), limits: limits) }
        #expect(throws: CBORError.tooDeep) {
            var v: CBOR = .null
            for _ in 0..<10 { v = .array([v]) }
            _ = try CBOREncoder.encode(v)
        }
    }

    @Test func praefixDekodieren() throws {
        let bytes = hex("a10102") + [0xEE]
        let (value, next) = try CBORDecoder.decodePrefix(bytes, at: 0)
        #expect(value == .map([CBORPair(.unsigned(1), .unsigned(2))]))
        #expect(next == 3)
        #expect(throws: CBORError.truncated) { try CBORDecoder.decodePrefix(bytes, at: 4) }
        #expect(throws: CBORError.truncated) { try CBORDecoder.decodePrefix(bytes, at: 99) }
    }

    @Test func zugriffshilfen() throws {
        let v = try CBORDecoder.decode(try CBOREncoder.encode(.map([
            CBORPair(.int(1), .text("x")), CBORPair(.int(-2), .bytes([1])), CBORPair(.text("k"), .bool(true)),
        ])))
        #expect(v[int: 1]?.textValue == "x")
        #expect(v[int: -2]?.bytesValue == [1])
        #expect(v[text: "k"]?.boolValue == true)
        #expect(v[int: 7] == nil)
        #expect(CBOR.unsigned(5)[int: 1] == nil)
        #expect(CBOR.negative(UInt64.max).intValue == nil)
        #expect(CBOR.int(Int64.min).intValue == Int64.min)
        #expect(CBOR.unsigned(UInt64(Int64.max) + 1).intValue == nil)
    }

    /// Zufällige Strukturen: kodieren → dekodieren → gleich, und erneut kodieren → dieselben Bytes.
    @Test func zufallsRundlauf() throws {
        var rng = SplitMix64(seed: 42)
        func random(_ depth: Int) -> CBOR {
            switch Int.random(in: 0..<(depth >= 4 ? 6 : 8), using: &rng) {
            case 0: return .unsigned(UInt64.random(in: 0...UInt64.max, using: &rng) >> UInt64.random(in: 0...63, using: &rng))
            case 1: return .negative(UInt64.random(in: 0...UInt64.max, using: &rng) >> UInt64.random(in: 0...63, using: &rng))
            case 2: return .bytes(rng.bytes(Int.random(in: 0...40, using: &rng)))
            case 3: return .text(String((0..<Int.random(in: 0...12, using: &rng)).map { _ in "aZ9ü水€ :".randomElement(using: &rng) ?? "a" }))
            case 4: return [.bool(true), .bool(false), .null][Int.random(in: 0...2, using: &rng)]
            case 5: return .unsigned(UInt64.random(in: 0...30, using: &rng))
            case 6: return .array((0..<Int.random(in: 0...5, using: &rng)).map { _ in random(depth + 1) })
            default:
                var pairs: [CBORPair] = []
                var used = Set<Int64>()
                for _ in 0..<Int.random(in: 0...5, using: &rng) {
                    let k = Int64.random(in: -300...300, using: &rng)
                    if used.insert(k).inserted { pairs.append(CBORPair(.int(k), random(depth + 1))) }
                }
                return .map(pairs)
            }
        }
        for _ in 0..<3000 {
            let value = random(0)
            let bytes = try CBOREncoder.encode(value)
            let decoded = try CBORDecoder.decode(bytes)
            #expect(try CBOREncoder.encode(decoded) == bytes)
        }
    }
}
