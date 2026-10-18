import CryptoKit
import Foundation
import Testing
@testable import SiegelHardware

@Suite("CTAPHID-Rahmung")
struct CTAPHIDTests {
    let cid: UInt32 = 0x1234_5678

    @Test(arguments: [0, 1, 56, 57, 58, 116, 117, 1000, 7608, 7609])
    func zerlegenUndZusammensetzen(length: Int) throws {
        let payload = (0..<length).map { UInt8($0 % 251) }
        let packets = try CTAPHID.fragment(cid: cid, command: CTAPHID.Command.cbor, payload: payload)
        let expectedCount = length <= 57 ? 1 : 1 + (length - 57 + 58) / 59
        #expect(packets.count == expectedCount)
        #expect(packets.allSatisfy { $0.count == 64 })
        #expect(packets.first?[4] == 0x90)
        for (i, p) in packets.dropFirst().enumerated() { #expect(p[4] == UInt8(i)) }
        var r = CTAPHID.Reassembler(cid: cid)
        var result: CTAPHID.Message?
        for (i, p) in packets.enumerated() {
            result = try r.feed(p)
            if i < packets.count - 1 { #expect(result == nil) }
        }
        #expect(result == CTAPHID.Message(cid: cid, command: 0x90, payload: payload))
    }

    @Test func zuLangUndUngueltigerBefehl() {
        #expect(throws: FIDOError.hid("hid.length")) {
            try CTAPHID.fragment(cid: cid, command: 0x90, payload: [UInt8](repeating: 0, count: 7610))
        }
        #expect(throws: FIDOError.hid("hid.command")) { try CTAPHID.fragment(cid: cid, command: 0x10, payload: []) }
    }

    @Test func fremdeKanaeleWerdenUebergangen() throws {
        var r = CTAPHID.Reassembler(cid: cid)
        let foreign = try CTAPHID.fragment(cid: 0xAAAA_AAAA, command: 0x90, payload: [1, 2, 3])
        #expect(try r.feed(foreign[0]) == nil)
        let own = try CTAPHID.fragment(cid: cid, command: 0x90, payload: [9])
        #expect(try r.feed(own[0])?.payload == [9])
    }

    @Test func strikteFolge() throws {
        let packets = try CTAPHID.fragment(cid: cid, command: 0x90, payload: [UInt8](repeating: 7, count: 200))
        #expect(packets.count == 4)

        var r = CTAPHID.Reassembler(cid: cid)
        #expect(throws: FIDOError.hid("hid.continuation")) { try r.feed(packets[1]) }

        r = CTAPHID.Reassembler(cid: cid)
        _ = try r.feed(packets[0])
        #expect(throws: FIDOError.hid("hid.sequence")) { try r.feed(packets[2]) }

        r = CTAPHID.Reassembler(cid: cid)
        _ = try r.feed(packets[0])
        #expect(throws: FIDOError.hid("hid.interrupted")) { try r.feed(packets[0]) }

        r = CTAPHID.Reassembler(cid: cid)
        #expect(throws: FIDOError.hid("hid.report")) { try r.feed(Array(packets[0].dropLast())) }
        #expect(throws: FIDOError.hid("hid.report")) { try r.feed(packets[0] + [0]) }

        var tooLong = packets[0]
        tooLong[5] = 0x1D; tooLong[6] = 0xBA   // 7610
        r = CTAPHID.Reassembler(cid: cid)
        #expect(throws: FIDOError.hid("hid.length")) { try r.feed(tooLong) }
    }

    @Test func fuzzReassembler() {
        var rng = SplitMix64(seed: 0xC7A9_1D)
        for _ in 0..<20_000 {
            var r = CTAPHID.Reassembler(cid: UInt32.random(in: 0...3, using: &rng))
            for _ in 0..<Int.random(in: 1...8, using: &rng) {
                var p = rng.bytes(Int.random(in: 0...2, using: &rng) == 0 ? Int.random(in: 0...70, using: &rng) : 64)
                if p.count >= 4 { p[0] = 0; p[1] = 0; p[2] = 0; p[3] = UInt8.random(in: 0...3, using: &rng) }
                _ = try? r.feed(p)
            }
        }
    }
}

@Suite("CTAPHID-Kanal gegen den virtuellen Authenticator")
struct CTAPHIDChannelTests {
    @Test func initVergibtKanal() throws {
        let auth = VirtualAuthenticator()
        let transport = VirtualHIDTransport(auth)
        let channel = try CTAPHIDChannel(transport: transport, timeouts: .test)
        #expect(channel.cid != CTAPHID.broadcastCID)
        #expect(channel.capabilities & CTAPHID.Capability.cbor != 0)
        #expect(try channel.transact(command: CTAPHID.Command.ping, payload: Array(0..<200), userPresence: false) == Array(0..<200))
    }

    @Test func fremdeInitAntwortenUndPaketeWerdenUebergangen() throws {
        let auth = VirtualAuthenticator()
        let transport = VirtualHIDTransport(auth)
        // Vor jeder Antwort: INIT-Antwort mit fremder Nonce auf dem Broadcast-Kanal und ein Paket eines anderen Kanals.
        var foreignInit = [UInt8](repeating: 0x55, count: 17)
        foreignInit[12] = 2
        transport.interleave = (try CTAPHID.fragment(cid: CTAPHID.broadcastCID, command: CTAPHID.Command.initialize, payload: foreignInit))
            + (try CTAPHID.fragment(cid: 0x0BAD_0BAD, command: CTAPHID.Command.cbor, payload: [0x01]))
        let channel = try CTAPHIDChannel(transport: transport, timeouts: .test)
        #expect(try channel.transact(command: CTAPHID.Command.ping, payload: [1, 2], userPresence: false) == [1, 2])
    }

    @Test func ohneCBORFaehigkeitAbgelehnt() {
        var config = VirtualAuthenticator.Configuration()
        config.capabilities = CTAPHID.Capability.wink | CTAPHID.Capability.nmsg
        let transport = VirtualHIDTransport(VirtualAuthenticator(config))
        #expect(throws: FIDOError.unsupported("ctap2")) { try CTAPHIDChannel(transport: transport, timeouts: .test) }
    }

    @Test func falscheProtokollversion() {
        var config = VirtualAuthenticator.Configuration()
        config.hidVersion = 1
        let transport = VirtualHIDTransport(VirtualAuthenticator(config))
        #expect(throws: FIDOError.unsupported("hid.version")) { try CTAPHIDChannel(transport: transport, timeouts: .test) }
    }

    @Test func ungueltigeKanalnummer() {
        let auth = VirtualAuthenticator()
        auth.packetMutator = { packets in
            // INIT-Antwort: neue CID auf 0 setzen (Nutzlast ab Byte 7, CID ab Nutzlast-Byte 8).
            if packets.first?[4] == CTAPHID.Command.initialize { for i in 15..<19 { packets[0][i] = 0 } }
        }
        #expect(throws: FIDOError.hid("hid.init.cid")) {
            try CTAPHIDChannel(transport: VirtualHIDTransport(auth), timeouts: .test)
        }
    }

    @Test func keineAntwortIstZeitueberschreitung() throws {
        let auth = VirtualAuthenticator()
        auth.packetMutator = { $0 = [] }
        let clock = ContinuousClock()
        let start = clock.now
        #expect(throws: FIDOError.timeout) { try CTAPHIDChannel(transport: VirtualHIDTransport(auth), timeouts: .test) }
        #expect(start.duration(to: clock.now) < .seconds(2))
    }

    @Test func fehlerpaketWirdGemeldet() throws {
        let auth = VirtualAuthenticator()
        let transport = VirtualHIDTransport(auth)
        let channel = try CTAPHIDChannel(transport: transport, timeouts: .test)
        #expect(throws: FIDOError.hidError(CTAPHID.ErrorCode.invalidCommand)) {
            try channel.transact(command: CTAPHID.Command.wink, payload: [], userPresence: false)
        }
    }

    @Test func belegterKanalWirdWiederholt() throws {
        let auth = VirtualAuthenticator()
        let transport = VirtualHIDTransport(auth)
        let channel = try CTAPHIDChannel(transport: transport, timeouts: .test)
        var busy = 2
        auth.packetMutator = { packets in
            guard busy > 0, let first = packets.first, first[4] == CTAPHID.Command.ping else { return }
            busy -= 1
            packets = (try? CTAPHID.fragment(cid: first.readBE32(at: 0), command: CTAPHID.Command.error,
                                             payload: [CTAPHID.ErrorCode.channelBusy])) ?? []
        }
        #expect(try channel.transact(command: CTAPHID.Command.ping, payload: [5], userPresence: false) == [5])
        #expect(transport.sentCommands.filter { $0 == CTAPHID.Command.ping }.count == 3)
    }

    @Test func ungueltigesKeepalive() throws {
        let auth = VirtualAuthenticator()
        let transport = VirtualHIDTransport(auth)
        let channel = try CTAPHIDChannel(transport: transport, timeouts: .test)
        auth.packetMutator = { packets in
            guard let first = packets.first else { return }
            packets.insert((try? CTAPHID.fragment(cid: first.readBE32(at: 0), command: CTAPHID.Command.keepalive,
                                                  payload: [9]))?.first ?? [], at: 0)
        }
        #expect(throws: FIDOError.hid("hid.keepalive")) {
            try channel.transact(command: CTAPHID.Command.ping, payload: [5], userPresence: false)
        }
    }
}

@Suite("PIN/UV-Protokolle")
struct PinUvProtocolTests {
    @Test(arguments: PinUvProtocol.allCases)
    func ableitungWieUnabhaengigeUmsetzung(version: PinUvProtocol) throws {
        let a = P256.KeyAgreement.PrivateKey(), b = P256.KeyAgreement.PrivateKey()
        let z = try a.sharedSecretFromKeyAgreement(with: b.publicKey)
        let (h, k) = PinUvSession.derive(version, z: z)
        let expected = Gegenseite.pinSecret(version.rawValue, z: z.withUnsafeBytes { Array($0) })
        #expect(h.withUnsafeBytes { Array($0) } == expected.hmac)
        #expect(k.withUnsafeBytes { Array($0) } == expected.aes)
        if version == .two { #expect(expected.hmac != expected.aes) }
    }

    @Test(arguments: PinUvProtocol.allCases)
    func verschluesselnEntschluesselnAuthentisieren(version: PinUvProtocol) throws {
        let authenticator = P256.KeyAgreement.PrivateKey()
        let session = try PinUvSession.establish(version, authenticatorKey: authenticator.publicKey)
        let plain = (0..<64).map { UInt8($0) }
        let enc = try session.encrypt(plain)
        #expect(enc.count == session.ciphertextLength(64))
        #expect(enc.count == (version == .one ? 64 : 80))
        #expect(try session.decrypt(enc).testBytes == plain)
        #expect(session.authenticate(enc).count == (version == .one ? 16 : 32))

        // Gegenseite rechnet mit dem COSE-Schlüssel der Plattform dasselbe Geheimnis.
        let platform = try PinUvSession.publicKey(fromCOSE: session.platformKey)
        let z = try authenticator.sharedSecretFromKeyAgreement(with: platform).withUnsafeBytes { Array($0) }
        let keys = Gegenseite.pinSecret(version.rawValue, z: z)
        let iv = version == .one ? [UInt8](repeating: 0, count: 16) : Array(enc.prefix(16))
        let body = version == .one ? enc : Array(enc.dropFirst(16))
        #expect(Gegenseite.aes(false, key: keys.aes, iv: iv, body) == plain)
        let tag = Gegenseite.hmac(keys.hmac, enc)
        #expect(session.authenticate(enc) == (version == .one ? Array(tag.prefix(16)) : tag))

        #expect(throws: FIDOError.response("pin.length")) { try session.decrypt(Array(enc.dropLast())) }
        #expect(throws: FIDOError.response("pin.length")) { try session.decrypt([]) }
        #expect(throws: FIDOError.response("pin.length")) { try session.encrypt([1, 2, 3]) }
    }

    @Test func protokollZweiNutztZufaelligenIV() throws {
        let session = try PinUvSession.establish(.two, authenticatorKey: P256.KeyAgreement.PrivateKey().publicKey)
        let plain = [UInt8](repeating: 1, count: 32)
        #expect(try session.encrypt(plain) != (try session.encrypt(plain)))
        let fixed = try session.encrypt(plain, iv: [UInt8](repeating: 9, count: 16))
        #expect(Array(fixed.prefix(16)) == [UInt8](repeating: 9, count: 16))
    }

    @Test func coseSchluesselStrikt() throws {
        let key = P256.KeyAgreement.PrivateKey().publicKey
        let good = PinUvSession.coseKey(key)
        #expect(try PinUvSession.publicKey(fromCOSE: good).x963Representation == key.x963Representation)
        let x963 = Array(key.x963Representation)
        func cose(kty: Int64 = 2, crv: Int64 = 1, x: [UInt8]? = nil, y: [UInt8]? = nil) -> CBOR {
            var pairs = [CBORPair(.int(1), .int(kty)), CBORPair(.int(3), .int(-25)), CBORPair(.int(-1), .int(crv))]
            if let x { pairs.append(CBORPair(.int(-2), .bytes(x))) }
            if let y { pairs.append(CBORPair(.int(-3), .bytes(y))) }
            return .map(pairs)
        }
        let x = Array(x963[1..<33]), y = Array(x963[33...])
        var yOff = y
        yOff[31] ^= 1
        #expect(throws: FIDOError.response("cose.key")) { try PinUvSession.publicKey(fromCOSE: cose(kty: 1, x: x, y: y)) }
        #expect(throws: FIDOError.response("cose.key")) { try PinUvSession.publicKey(fromCOSE: cose(crv: 2, x: x, y: y)) }
        #expect(throws: FIDOError.response("cose.key")) { try PinUvSession.publicKey(fromCOSE: cose(x: x)) }
        #expect(throws: FIDOError.response("cose.key")) { try PinUvSession.publicKey(fromCOSE: cose(x: Array(x.dropLast()), y: y)) }
        #expect(throws: FIDOError.response("cose.key")) { try PinUvSession.publicKey(fromCOSE: .bytes(x963)) }
        #expect(throws: FIDOError.response("cose.point")) { try PinUvSession.publicKey(fromCOSE: cose(x: x, y: yOff)) }
        #expect(throws: FIDOError.response("cose.point")) {
            try PinUvSession.publicKey(fromCOSE: cose(x: [UInt8](repeating: 0, count: 32), y: [UInt8](repeating: 0, count: 32)))
        }
    }
}
