import CryptoKit
import Foundation
import SiegelCore
import Testing
@testable import SiegelHardware

/// Fuzz-artige Tests der Parser, die Daten vom USB-Gerät lesen: kein Absturz, kein Hänger, nur feste Fehler.
/// Reproduzierbar (fester Seed). Der grosse Fuzzer `SiegelFuzz` (SPEC §21) kann dieselben `package`-Einstiege nutzen.
@Suite("Fuzz: CBOR, CTAPHID, CTAP2")
struct FuzzTests {
    /// Gültige Beispiel-Kodierungen als Saat für Mutationen.
    static func seeds() throws -> [[UInt8]] {
        let key = P256.KeyAgreement.PrivateKey().publicKey
        return [
            try CBOREncoder.encode(.map([
                CBORPair(.int(1), .array([.text("FIDO_2_0"), .text("FIDO_2_1")])),
                CBORPair(.int(2), .array([.text("hmac-secret")])),
                CBORPair(.int(3), .bytes([UInt8](repeating: 1, count: 16))),
                CBORPair(.int(4), .map([CBORPair(.text("rk"), .bool(true)), CBORPair(.text("clientPin"), .bool(false))])),
                CBORPair(.int(5), .int(1200)),
                CBORPair(.int(6), .array([.int(2), .int(1)])),
            ])),
            try CBOREncoder.encode(.map([CBORPair(.int(1), PinUvSession.coseKey(key))])),
            try CBOREncoder.encode(.map([
                CBORPair(.int(1), .map([CBORPair(.text("id"), .bytes([UInt8](repeating: 2, count: 64))),
                                        CBORPair(.text("type"), .text("public-key"))])),
                CBORPair(.int(2), .bytes([UInt8](repeating: 3, count: 120))),
                CBORPair(.int(3), .bytes([UInt8](repeating: 4, count: 71))),
            ])),
            hex("a26161016162820203"),
            hex("8301820203820405"),
        ]
    }

    static func mutate(_ input: [UInt8], _ rng: inout SplitMix64) -> [UInt8] {
        var b = input
        for _ in 0..<Int.random(in: 1...4, using: &rng) {
            switch Int.random(in: 0..<6, using: &rng) {
            case 0 where !b.isEmpty: b[Int.random(in: 0..<b.count, using: &rng)] ^= UInt8(1 << Int.random(in: 0..<8, using: &rng))
            case 1 where !b.isEmpty: b[Int.random(in: 0..<b.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
            case 2 where !b.isEmpty: b.remove(at: Int.random(in: 0..<b.count, using: &rng))
            case 3: b.insert(UInt8.random(in: 0...255, using: &rng), at: Int.random(in: 0...b.count, using: &rng))
            case 4 where !b.isEmpty: b = Array(b.prefix(Int.random(in: 0..<b.count, using: &rng)))
            default:
                let interesting: [UInt8] = [0x18, 0x19, 0x1A, 0x1B, 0x1F, 0x5F, 0x7F, 0x9F, 0xBF, 0xFF, 0xF9, 0xFB, 0xC0, 0x9B, 0xBB]
                if !b.isEmpty { b[Int.random(in: 0..<b.count, using: &rng)] = interesting[Int.random(in: 0..<interesting.count, using: &rng)] }
            }
        }
        return b
    }

    /// Eigenschaft: was der strikte Dekodierer annimmt, kodiert der Kodierer Byte für Byte gleich zurück.
    @Test func cborMutationenUndZufall() throws {
        var rng = SplitMix64(seed: 0xF1D0)
        let seeds = try Self.seeds()
        var accepted = 0
        for round in 0..<40_000 {
            let input: [UInt8] = round % 3 == 0
                ? rng.bytes(Int.random(in: 0...64, using: &rng))
                : Self.mutate(seeds[round % seeds.count], &rng)
            if let value = try? CBORDecoder.decode(input) {
                accepted += 1
                #expect(try CBOREncoder.encode(value) == input)
            }
        }
        #expect(accepted > 100)
    }

    @Test func authenticatorDatenUndInfo() throws {
        var rng = SplitMix64(seed: 0xA07D)
        let auth = VirtualAuthenticator()
        let enrollment = try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .test).register()
        _ = enrollment
        var samples: [[UInt8]] = []
        auth.responseMutator = { cmd, bytes in
            if cmd == CTAPCommand.getAssertion || cmd == CTAPCommand.makeCredential,
               let v = try? CBORDecoder.decode(Array(bytes.dropFirst())), let a = v[int: 2]?.bytesValue {
                samples.append(a)
            }
        }
        _ = try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .test).register()
        #expect(samples.count == 2)
        let info = try Self.seeds()[0]
        for round in 0..<20_000 {
            let base = samples[round % samples.count]
            _ = try? AuthenticatorData.parse(round % 5 == 0 ? rng.bytes(Int.random(in: 0...200, using: &rng)) : Self.mutate(base, &rng))
            if let v = try? CBORDecoder.decode(Self.mutate(info, &rng)) { _ = try? AuthenticatorInfo.parse(v) }
        }
    }

    /// Der ganze Ablauf mit zufällig beschädigten Antworten: entweder ein fester Fehler oder ein Ergebnis mit
    /// 32 Byte; nie ein Absturz, nie länger als die Fristen.
    @Test func ablaufMitBeschaedigtenAntworten() throws {
        var rng = SplitMix64(seed: 0xBAD_F1D0)
        let clock = ContinuousClock()
        let start = clock.now
        var outcomes: [String: Int] = [:]
        for round in 0..<240 {
            let auth = VirtualAuthenticator()
            auth.config.keepalivesBeforeTouch = round % 3
            let enrollment = try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .test).register()
            let seed = rng.next()
            let mode = round % 3
            let state = MutationState(seed: seed)
            if mode == 0 {
                auth.responseMutator = { _, bytes in bytes = state.mutate(bytes) }
            } else {
                auth.packetMutator = { packets in packets = state.mutatePackets(packets) }
            }
            do {
                if round % 2 == 0 {
                    let s = try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .fuzz)
                        .secret(credentialID: enrollment.credentialID, salt: enrollment.salt)
                    #expect(s.testBytes.count == 32)
                    outcomes["ok", default: 0] += 1
                } else {
                    let e = try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .fuzz).register()
                    #expect(e.output.testBytes.count == 32)
                    outcomes["ok", default: 0] += 1
                }
            } catch {
                let mapped = error.siegelError
                #expect(FIDOError.isAllowedOutward(mapped) && mapped != .crypto("fido.input"))
                outcomes["fehler", default: 0] += 1
            }
        }
        #expect((outcomes["fehler"] ?? 0) > 0)
        #expect((outcomes["ok"] ?? 0) > 0)
        #expect(start.duration(to: clock.now) < .seconds(120))
    }
}

/// Zustand für Mutationen innerhalb einer Closure (Referenz, damit der Zufall fortschreitet).
final class MutationState: @unchecked Sendable {
    var rng: SplitMix64
    init(seed: UInt64) { rng = SplitMix64(seed: seed) }

    func mutate(_ bytes: [UInt8]) -> [UInt8] {
        guard Int.random(in: 0..<3, using: &rng) == 0 else { return bytes }
        return FuzzTests.mutate(bytes, &rng)
    }

    func mutatePackets(_ packets: [[UInt8]]) -> [[UInt8]] {
        var out = packets
        guard !out.isEmpty, Int.random(in: 0..<3, using: &rng) == 0 else { return out }
        switch Int.random(in: 0..<5, using: &rng) {
        case 0:
            let i = Int.random(in: 0..<out.count, using: &rng)
            out[i][Int.random(in: 0..<64, using: &rng)] ^= UInt8(1 << Int.random(in: 0..<8, using: &rng))
        case 1:
            out.remove(at: Int.random(in: 0..<out.count, using: &rng))
        case 2:
            let i = Int.random(in: 0..<out.count, using: &rng)
            out.insert(out[i], at: i)
        case 3:
            out.shuffle(using: &rng)
        default:
            let i = Int.random(in: 0..<out.count, using: &rng)
            out[i] = Array(out[i].prefix(Int.random(in: 0..<64, using: &rng)))
        }
        return out
    }
}
