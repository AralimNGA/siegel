import CryptoKit
import Foundation
import SiegelCore
@testable import SiegelHardware

/// Gegenseite eines FIDO2-Sicherheitsschlüssels nach CTAP 2.1 (nur Tests).
///
/// Setzt CTAPHID (INIT, CBOR, PING, CANCEL, KEEPALIVE, ERROR, Kanäle, Zerlegung) und CTAP2 um: getInfo,
/// clientPIN getKeyAgreement (PIN/UV-Protokoll 1 und 2), makeCredential mit hmac-secret (nicht resident) und
/// getAssertion mit hmac-secret (ein oder zwei Salze, saltAuth geprüft). Die Krypto der Gegenseite ist unabhängig
/// vom Client geschrieben (`Gegenseite`), damit Fehler nicht auf beiden Seiten gleich verschwinden.
/// Fehlerinjektion: `responseMutator` (CBOR-Antwort), `packetMutator` (HID-Pakete), Konfiguration.
final class VirtualAuthenticator: @unchecked Sendable {
    struct Configuration {
        var versions = ["FIDO_2_0", "FIDO_2_1"]
        var extensions = ["hmac-secret"]
        var pinProtocols: [Int]? = [2, 1]
        var clientPin: Bool?
        var makeCredUvNotRqd: Bool? = true
        var alwaysUv: Bool?
        /// Eingebaute, eingerichtete UV (Option "uv").
        var builtInUV: Bool?
        var capabilities: UInt8 = CTAPHID.Capability.wink | CTAPHID.Capability.cbor
        var hidVersion: UInt8 = 2
        var maxMsgSize: Int? = 1200
        var credentialIDLength = 64
        var presence: Presence = .touch
        var keepalivesBeforeTouch = 2
        var setUVFlag = false
        /// Fehlerhaftes Gerät: dieselbe Ausgabe für alle Salze.
        var sameOutputForAllSalts = false
        var aaguid = [UInt8](repeating: 0xA5, count: 16)
    }

    enum Presence {
        case touch
        /// Nutzer lehnt ab (CTAP2_ERR_OPERATION_DENIED).
        case deny
        /// Keepalives, dann Stille bis CTAPHID_CANCEL (Antwort KEEPALIVE_CANCEL).
        case timeout
        /// Gar keine Antwort.
        case silent
    }

    private struct Partial {
        let command: UInt8
        let length: Int
        var data: [UInt8]
        var seq: UInt8
    }

    private struct Credential {
        let rpID: String
        let signingKey: P256.Signing.PrivateKey
        let credRandomWithoutUV: [UInt8]
        let credRandomWithUV: [UInt8]
    }

    private let lock = NSRecursiveLock()
    var config: Configuration
    var responseMutator: ((UInt8, inout [UInt8]) -> Void)?
    var packetMutator: ((inout [[UInt8]]) -> Void)?

    private(set) var touches = 0
    private(set) var ctapCommands: [UInt8] = []
    private(set) var pinProtocolsUsed: [Int] = []
    private(set) var saltCounts: [Int] = []
    private(set) var cancels = 0
    private(set) var lastMakeCredentialOptions: CBOR?
    private(set) var lastAssertionHadProtocolKey: Bool?

    private var channels: Set<UInt32> = []
    private var nextCID: UInt32 = 0x0100_0001
    private var partial: [UInt32: Partial] = [:]
    private var credentials: [[UInt8]: Credential] = [:]
    private let keyAgreementKey = P256.KeyAgreement.PrivateKey()
    private var waitingForCancel: Set<UInt32> = []

    init(_ config: Configuration = Configuration()) {
        self.config = config
    }

    var credentialCount: Int { lock.withLock { credentials.count } }

    /// Fremden Schlüssel löschen (simuliert „anderes Gerät“).
    func forgetCredentials() { lock.withLock { credentials.removeAll() } }

    // MARK: CTAPHID

    /// Ein Ausgabebericht des Clients → Antwortberichte (in Reihenfolge).
    func receive(report: [UInt8]) -> [[UInt8]] {
        lock.withLock {
            var out = handle(report: report)
            packetMutator?(&out)
            return out
        }
    }

    private func handle(report: [UInt8]) -> [[UInt8]] {
        guard report.count == CTAPHID.reportSize else { return [] }
        let cid = report.readBE32(at: 0)
        let type = report[4]
        if type & 0x80 != 0 {
            let length = Int(report.readBE16(at: 5))
            if type == CTAPHID.Command.initialize {
                guard length == 8 else { return error(cid, CTAPHID.ErrorCode.invalidLength) }
                return initialize(cid: cid, nonce: Array(report[7..<15]))
            }
            guard channels.contains(cid) else { return error(cid, CTAPHID.ErrorCode.invalidChannel) }
            if type == CTAPHID.Command.cancel {
                guard waitingForCancel.remove(cid) != nil else { return [] }
                cancels += 1
                return packets(cid, CTAPHID.Command.cbor, [CTAPStatus.keepaliveCancel])
            }
            guard length <= CTAPHID.maxPayload else { return error(cid, CTAPHID.ErrorCode.invalidLength) }
            let n = min(length, CTAPHID.initDataSize)
            if length <= CTAPHID.initDataSize {
                return dispatch(cid: cid, command: type, payload: Array(report[7..<(7 + n)]))
            }
            partial[cid] = Partial(command: type, length: length, data: Array(report[7..<(7 + n)]), seq: 0)
            return []
        }
        guard var p = partial[cid] else { return error(cid, CTAPHID.ErrorCode.invalidSequence) }
        guard type == p.seq else {
            partial[cid] = nil
            return error(cid, CTAPHID.ErrorCode.invalidSequence)
        }
        let n = min(p.length - p.data.count, CTAPHID.contDataSize)
        p.data += report[5..<(5 + n)]
        p.seq += 1
        if p.data.count == p.length {
            partial[cid] = nil
            return dispatch(cid: cid, command: p.command, payload: p.data)
        }
        partial[cid] = p
        return []
    }

    private func initialize(cid: UInt32, nonce: [UInt8]) -> [[UInt8]] {
        let newCID = nextCID
        nextCID += 1
        channels.insert(newCID)
        var payload = nonce
        payload.appendBE32(newCID)
        payload += [config.hidVersion, 2, 1, 0, config.capabilities]
        return packets(cid, CTAPHID.Command.initialize, payload)
    }

    private func dispatch(cid: UInt32, command: UInt8, payload: [UInt8]) -> [[UInt8]] {
        switch command {
        case CTAPHID.Command.ping:
            return packets(cid, CTAPHID.Command.ping, payload)
        case CTAPHID.Command.cbor:
            guard let cmd = payload.first else { return error(cid, CTAPHID.ErrorCode.invalidLength) }
            ctapCommands.append(cmd)
            let outcome = ctap(cmd, Array(payload.dropFirst()))
            var result: [[UInt8]] = []
            for _ in 0..<outcome.keepalives { result += packets(cid, CTAPHID.Command.keepalive, [2]) }
            switch outcome.response {
            case .some(var bytes):
                responseMutator?(cmd, &bytes)
                result += packets(cid, CTAPHID.Command.cbor, bytes)
            case .none:
                if outcome.waitForCancel { waitingForCancel.insert(cid) }
            }
            return result
        default:
            return error(cid, CTAPHID.ErrorCode.invalidCommand)
        }
    }

    private func packets(_ cid: UInt32, _ command: UInt8, _ payload: [UInt8]) -> [[UInt8]] {
        (try? CTAPHID.fragment(cid: cid, command: command, payload: payload)) ?? []
    }

    private func error(_ cid: UInt32, _ code: UInt8) -> [[UInt8]] {
        packets(cid, CTAPHID.Command.error, [code])
    }

    // MARK: CTAP2

    private struct Outcome {
        var keepalives = 0
        var response: [UInt8]?
        var waitForCancel = false
        static func status(_ s: UInt8) -> Outcome { Outcome(response: [s]) }
        static func ok(_ value: CBOR) -> Outcome {
            Outcome(response: [CTAPStatus.ok] + ((try? CBOREncoder.encode(value)) ?? []))
        }
    }

    private func ctap(_ cmd: UInt8, _ body: [UInt8]) -> Outcome {
        var params: CBOR?
        if !body.isEmpty {
            guard let decoded = try? CBORDecoder.decode(body) else { return .status(CTAPStatus.invalidCBOR) }
            params = decoded
        }
        switch cmd {
        case CTAPCommand.getInfo: return getInfo()
        case CTAPCommand.clientPIN: return clientPIN(params)
        case CTAPCommand.makeCredential: return makeCredential(params)
        case CTAPCommand.getAssertion: return getAssertion(params)
        default: return .status(CTAPStatus.invalidCommand)
        }
    }

    private func getInfo() -> Outcome {
        var options: [CBORPair] = [CBORPair(.text("rk"), .bool(true)), CBORPair(.text("up"), .bool(true)),
                                   CBORPair(.text("plat"), .bool(false))]
        if let v = config.clientPin { options.append(CBORPair(.text("clientPin"), .bool(v))) }
        if let v = config.makeCredUvNotRqd { options.append(CBORPair(.text("makeCredUvNotRqd"), .bool(v))) }
        if let v = config.alwaysUv { options.append(CBORPair(.text("alwaysUv"), .bool(v))) }
        if let v = config.builtInUV { options.append(CBORPair(.text("uv"), .bool(v))) }
        var map: [CBORPair] = [
            CBORPair(.int(1), .array(config.versions.map { .text($0) })),
            CBORPair(.int(2), .array(config.extensions.map { .text($0) })),
            CBORPair(.int(3), .bytes(config.aaguid)),
            CBORPair(.int(4), .map(options)),
        ]
        if let m = config.maxMsgSize { map.append(CBORPair(.int(5), .int(Int64(m)))) }
        if let p = config.pinProtocols { map.append(CBORPair(.int(6), .array(p.map { .int(Int64($0)) }))) }
        return .ok(.map(map))
    }

    private var supportedProtocols: [Int] { config.pinProtocols ?? [1] }

    private func clientPIN(_ params: CBOR?) -> Outcome {
        guard let params, let p = params[int: 1]?.intValue, let sub = params[int: 2]?.intValue else {
            return .status(CTAPStatus.missingParameter)
        }
        guard supportedProtocols.contains(Int(p)) else { return .status(CTAPStatus.invalidParameter) }
        guard sub == 2 else { return .status(CTAPStatus.invalidSubcommand) }
        pinProtocolsUsed.append(Int(p))
        let x963 = Array(keyAgreementKey.publicKey.x963Representation)
        let cose: CBOR = .map([CBORPair(.int(1), .int(2)), CBORPair(.int(3), .int(-25)), CBORPair(.int(-1), .int(1)),
                               CBORPair(.int(-2), .bytes(Array(x963[1..<33]))), CBORPair(.int(-3), .bytes(Array(x963[33...])))])
        return .ok(.map([CBORPair(.int(1), cose)]))
    }

    private func presence(_ success: () -> [UInt8]) -> Outcome {
        switch config.presence {
        case .touch:
            touches += 1
            return Outcome(keepalives: config.keepalivesBeforeTouch, response: success())
        case .deny:
            return Outcome(keepalives: config.keepalivesBeforeTouch, response: [CTAPStatus.operationDenied])
        case .timeout:
            return Outcome(keepalives: config.keepalivesBeforeTouch, response: nil, waitForCancel: true)
        case .silent:
            return Outcome(keepalives: 0, response: nil)
        }
    }

    private func makeCredential(_ params: CBOR?) -> Outcome {
        guard let params,
              let clientDataHash = params[int: 1]?.bytesValue,
              let rpID = params[int: 2]?[text: "id"]?.textValue,
              let userID = params[int: 3]?[text: "id"]?.bytesValue,
              let algs = params[int: 4]?.arrayValue else { return .status(CTAPStatus.missingParameter) }
        guard clientDataHash.count == 32, userID.count <= 64 else { return .status(CTAPStatus.invalidLength) }
        guard algs.contains(where: { $0[text: "alg"]?.intValue == -7 && $0[text: "type"]?.textValue == "public-key" }) else {
            return .status(CTAPStatus.unsupportedAlgorithm)
        }
        let options = params[int: 7]
        lastMakeCredentialOptions = options
        if options?[text: "up"] != nil { return .status(CTAPStatus.invalidOption) }
        if options?[text: "uv"]?.boolValue == true { return .status(CTAPStatus.invalidOption) }
        if config.alwaysUv == true { return .status(CTAPStatus.puatRequired) }
        if config.clientPin == true, config.makeCredUvNotRqd != true { return .status(CTAPStatus.puatRequired) }
        if config.builtInUV == true, config.makeCredUvNotRqd != true, config.versions.contains("FIDO_2_1") {
            return .status(CTAPStatus.puatRequired)
        }
        let wantsHmacSecret = config.extensions.contains("hmac-secret")
            && params[int: 6]?[text: "hmac-secret"]?.boolValue == true

        return presence {
            let credentialID = (0..<config.credentialIDLength).map { _ in UInt8.random(in: 0...255) }
            let key = P256.Signing.PrivateKey()
            credentials[credentialID] = Credential(rpID: rpID, signingKey: key,
                                                   credRandomWithoutUV: (0..<32).map { _ in UInt8.random(in: 0...255) },
                                                   credRandomWithUV: (0..<32).map { _ in UInt8.random(in: 0...255) })
            let x963 = Array(key.publicKey.x963Representation)
            let cose: CBOR = .map([CBORPair(.int(1), .int(2)), CBORPair(.int(3), .int(-7)), CBORPair(.int(-1), .int(1)),
                                   CBORPair(.int(-2), .bytes(Array(x963[1..<33]))),
                                   CBORPair(.int(-3), .bytes(Array(x963[33...])))])
            var flags = AuthenticatorData.flagUP | AuthenticatorData.flagAT
            if wantsHmacSecret { flags |= AuthenticatorData.flagED }
            var authData = Array(SHA256.hash(data: Data(rpID.utf8))) + [flags, 0, 0, 0, 1] + config.aaguid
            authData.appendBE16(UInt16(credentialID.count))
            authData += credentialID
            authData += (try? CBOREncoder.encode(cose)) ?? []
            if wantsHmacSecret {
                authData += (try? CBOREncoder.encode(.map([CBORPair(.text("hmac-secret"), .bool(true))]))) ?? []
            }
            let response: CBOR = .map([CBORPair(.int(1), .text("none")), CBORPair(.int(2), .bytes(authData)),
                                       CBORPair(.int(3), .map([]))])
            return [CTAPStatus.ok] + ((try? CBOREncoder.encode(response)) ?? [])
        }
    }

    private func getAssertion(_ params: CBOR?) -> Outcome {
        guard let params, let rpID = params[int: 1]?.textValue, let clientDataHash = params[int: 2]?.bytesValue,
              clientDataHash.count == 32 else { return .status(CTAPStatus.missingParameter) }
        let allow = params[int: 3]?.arrayValue ?? []
        guard let (credentialID, credential) = allow.lazy.compactMap({ d -> ([UInt8], Credential)? in
            guard let id = d[text: "id"]?.bytesValue, let c = self.credentials[id], c.rpID == rpID else { return nil }
            return (id, c)
        }).first else { return .status(CTAPStatus.noCredentials) }
        if params[int: 5]?[text: "uv"]?.boolValue == true { return .status(CTAPStatus.invalidOption) }
        if config.alwaysUv == true { return .status(CTAPStatus.puatRequired) }

        var extensionOutput: CBOR?
        if config.extensions.contains("hmac-secret"), let input = params[int: 4]?[text: "hmac-secret"] {
            let version = Int(input[int: 4]?.intValue ?? 1)
            lastAssertionHadProtocolKey = input[int: 4] != nil
            guard supportedProtocols.contains(version) else { return .status(CTAPStatus.invalidParameter) }
            guard let cose = input[int: 1], let saltEnc = input[int: 2]?.bytesValue,
                  let saltAuth = input[int: 3]?.bytesValue,
                  let x = cose[int: -2]?.bytesValue, let y = cose[int: -3]?.bytesValue, x.count == 32, y.count == 32,
                  cose[int: 1]?.intValue == 2, cose[int: -1]?.intValue == 1,
                  let platform = try? P256.KeyAgreement.PublicKey(x963Representation: [0x04] + x + y),
                  let z = try? keyAgreementKey.sharedSecretFromKeyAgreement(with: platform) else {
                return .status(CTAPStatus.invalidParameter)
            }
            let keys = Gegenseite.pinSecret(version, z: z.withUnsafeBytes { Array($0) })
            let expectedAuth = Gegenseite.hmac(keys.hmac, saltEnc)
            guard saltAuth == (version == 1 ? Array(expectedAuth[0..<16]) : expectedAuth) else {
                return .status(CTAPStatus.pinAuthInvalid)
            }
            let iv = version == 1 ? [UInt8](repeating: 0, count: 16) : Array(saltEnc.prefix(16))
            let body = version == 1 ? saltEnc : Array(saltEnc.dropFirst(16))
            guard let salts = Gegenseite.aes(false, key: keys.aes, iv: iv, body), salts.count == 32 || salts.count == 64 else {
                return .status(CTAPStatus.invalidLength)
            }
            saltCounts.append(salts.count / 32)
            let credRandom = config.setUVFlag ? credential.credRandomWithUV : credential.credRandomWithoutUV
            var outputs: [UInt8] = []
            for i in 0..<(salts.count / 32) {
                let j = config.sameOutputForAllSalts ? 0 : i
                outputs += Gegenseite.hmac(credRandom, Array(salts[(j * 32)..<(j * 32 + 32)]))
            }
            let outIV = version == 1 ? [UInt8](repeating: 0, count: 16) : (0..<16).map { _ in UInt8.random(in: 0...255) }
            guard let enc = Gegenseite.aes(true, key: keys.aes, iv: outIV, outputs) else {
                return .status(CTAPStatus.invalidParameter)
            }
            extensionOutput = .map([CBORPair(.text("hmac-secret"), .bytes(version == 1 ? enc : outIV + enc))])
        }

        return presence {
            var flags = AuthenticatorData.flagUP
            if config.setUVFlag { flags |= AuthenticatorData.flagUV }
            if extensionOutput != nil { flags |= AuthenticatorData.flagED }
            var authData = Array(SHA256.hash(data: Data(rpID.utf8))) + [flags, 0, 0, 0, 2]
            if let extensionOutput { authData += (try? CBOREncoder.encode(extensionOutput)) ?? [] }
            let signature = (try? credential.signingKey.signature(for: authData + clientDataHash).derRepresentation) ?? Data()
            let response: CBOR = .map([
                CBORPair(.int(1), .map([CBORPair(.text("id"), .bytes(credentialID)), CBORPair(.text("type"), .text("public-key"))])),
                CBORPair(.int(2), .bytes(authData)),
                CBORPair(.int(3), .bytes(Array(signature))),
            ])
            return [CTAPStatus.ok] + ((try? CBOREncoder.encode(response)) ?? [])
        }
    }
}

/// Transport, der direkt mit dem virtuellen Authenticator spricht.
final class VirtualHIDTransport: CTAPHIDTransport, @unchecked Sendable {
    let authenticator: VirtualAuthenticator
    private let lock = NSLock()
    private var outbox: [[UInt8]] = []
    private(set) var sent: [[UInt8]] = []
    private(set) var closed = false
    /// Berichte, die vor jeder Antwort eingeschoben werden (z. B. Pakete anderer Kanäle).
    var interleave: [[UInt8]] = []
    var failSend = false

    init(_ authenticator: VirtualAuthenticator) { self.authenticator = authenticator }

    func send(report: [UInt8]) throws {
        let fail = lock.withLock { failSend }
        if fail { throw FIDOError.transport }
        let answer = authenticator.receive(report: report)
        lock.withLock {
            sent.append(report)
            if !answer.isEmpty { outbox += interleave }
            outbox += answer
        }
    }

    func receive(timeout: Duration) throws -> [UInt8]? {
        if let next = lock.withLock({ outbox.isEmpty ? nil : outbox.removeFirst() }) { return next }
        let wait = min(CTAPHIDChannel.seconds(timeout), 0.002)
        if wait > 0 { Thread.sleep(forTimeInterval: wait) }
        return nil
    }

    func close() { lock.withLock { closed = true } }

    var sentCommands: [UInt8] {
        lock.withLock { sent.compactMap { $0[4] & 0x80 != 0 ? $0[4] : nil } }
    }
}
