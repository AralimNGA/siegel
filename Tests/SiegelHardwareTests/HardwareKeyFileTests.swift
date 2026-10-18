import CryptoKit
import Foundation
import SiegelCore
import Testing
@testable import SiegelHardware

@Suite("Schlüsseldatei .siegelhw")
struct HardwareKeyFileTests {
    let id = UUID()
    let point = P256.KeyAgreement.PrivateKey().publicKey.x963Representation

    func sample(kind: HardwareKeyFile.Kind = .unlock, blobLength: Int = 120) -> HardwareKeyFile {
        HardwareKeyFile(kind: kind, keyID: id, blob: Data((0..<blobLength).map { UInt8($0 & 0xff) }), point: point)
    }

    /// Prüfsumme neu rechnen (Angreifer, der gezielt ändert).
    func resealed(_ bytes: [UInt8]) -> [UInt8] {
        let body = Array(bytes.dropLast(32))
        return body + HardwareKeyFile.checksum(body)
    }

    @Test func rundlauf() throws {
        for kind in [HardwareKeyFile.Kind.unlock, .entry] {
            let f = sample(kind: kind)
            let decoded = try HardwareKeyFile.decode(try f.encoded(), expectedKeyID: id, expectedKind: kind)
            #expect(decoded == f)
        }
        let encoded = try sample().encoded()
        #expect(encoded.count == 8 + 2 + 1 + 16 + 2 + 120 + 65 + 32)
        #expect(Array(encoded.prefix(8)) == Array("SIEGELHW".utf8))
    }

    @Test func jedesGekippteByteWirdErkannt() throws {
        let bytes = try sample(blobLength: 40).encoded()
        for i in bytes.indices {
            var b = bytes
            b[i] ^= 0x01
            #expect(throws: SiegelError.self) { try HardwareKeyFile.decode(b, expectedKeyID: id, expectedKind: .unlock) }
        }
    }

    @Test func gezielteAenderungenMitNeuerPruefsumme() throws {
        let bytes = try sample().encoded()
        func expectCode(_ code: String, _ mutate: (inout [UInt8]) -> Void) {
            var b = bytes
            mutate(&b)
            #expect(throws: SiegelError.corruptFile(code)) {
                try HardwareKeyFile.decode(resealed(b), expectedKeyID: id, expectedKind: .unlock)
            }
        }
        expectCode("hw.magic") { $0[0] = UInt8(ascii: "X") }
        expectCode("hw.version") { $0[8] = 2 }
        expectCode("hw.kind") { $0[10] = 2 }
        expectCode("hw.kind") { $0[10] = 9 }
        expectCode("hw.keyid") { $0[11] ^= 0xff }
        expectCode("hw.blob") { $0[27] = 0; $0[28] = 0 }
        expectCode("hw.blob") { $0[27] = 0x01; $0[28] = 0x10 }   // 4097
        expectCode("hw.length") { $0[27] = 121 }
        expectCode("hw.point") { $0[29 + 120] = 0x02 }
        expectCode("hw.point") { $0[29 + 120 + 64] ^= 0x01 }
    }

    @Test func laengen() throws {
        let bytes = try sample().encoded()
        #expect(throws: SiegelError.corruptFile("hw.length")) {
            try HardwareKeyFile.decode([], expectedKeyID: id, expectedKind: .unlock)
        }
        #expect(throws: SiegelError.self) {
            try HardwareKeyFile.decode(bytes + [0], expectedKeyID: id, expectedKind: .unlock)
        }
        #expect(throws: SiegelError.self) {
            try HardwareKeyFile.decode(Array(bytes.dropLast()), expectedKeyID: id, expectedKind: .unlock)
        }
        #expect(throws: SiegelError.corruptFile("hw.length")) {
            try HardwareKeyFile.decode(resealed(bytes + [UInt8](repeating: 0, count: 10_000)), expectedKeyID: id,
                                       expectedKind: .unlock)
        }
        #expect(throws: SiegelError.crypto("hw.blob")) { try sample(blobLength: 0).encoded() }
        #expect(throws: SiegelError.crypto("hw.blob")) { try sample(blobLength: 4097).encoded() }
        _ = try sample(blobLength: 4096).encoded()
    }

    @Test func schreibenUeberschreibtNie() throws {
        let dir = tempDirectory()
        try sample().write(to: dir)
        #expect(throws: SiegelError.io("hw.write")) { try sample().write(to: dir) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).count == 1)
    }

    @Test func dateiStattOrdnerUndSymlink() throws {
        let base = tempDirectory()
        let notDir = base.appendingPathComponent("datei")
        try Data([1]).write(to: notDir)
        #expect(throws: SiegelError.io("hw.directory")) { try sample().write(to: notDir) }

        // Symlink statt Datei wird nicht gelesen.
        let dir = tempDirectory()
        let real = dir.appendingPathComponent("echt")
        try Data(try sample().encoded()).write(to: real)
        try FileManager.default.createSymbolicLink(at: HardwareKeyFile.fileURL(keyID: id, directory: dir), withDestinationURL: real)
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try HardwareKeyFile.read(keyID: id, kind: .unlock, directory: dir)
        }
    }

    @Test func umbenannteDateiPasstNicht() throws {
        let dir = tempDirectory()
        try sample().write(to: dir)
        let other = UUID()
        try FileManager.default.moveItem(at: HardwareKeyFile.fileURL(keyID: id, directory: dir),
                                         to: HardwareKeyFile.fileURL(keyID: other, directory: dir))
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try HardwareKeyFile.read(keyID: other, kind: .unlock, directory: dir)
        }
    }

    @Test func fuzzOhneAbsturz() throws {
        var rng = SplitMix64(seed: 0x5E61_E1)
        let valid = try sample(blobLength: 64).encoded()
        for round in 0..<4000 {
            var b: [UInt8]
            if round % 2 == 0 {
                b = valid
                for _ in 0..<Int.random(in: 1...6, using: &rng) {
                    b[Int.random(in: 0..<b.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
                }
                if round % 4 == 0 { b = resealed(b) }
            } else {
                b = rng.bytes(Int.random(in: 0...400, using: &rng))
            }
            _ = try? HardwareKeyFile.decode(b, expectedKeyID: id, expectedKind: .unlock)
        }
    }
}
