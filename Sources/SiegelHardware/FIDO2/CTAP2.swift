import CryptoKit
import Foundation
import SiegelCore

// CTAP2-Befehle für den Sicherheitsschlüssel (SPEC §14.3): authenticatorGetInfo, authenticatorClientPIN
// (getKeyAgreement), authenticatorMakeCredential, authenticatorGetAssertion mit hmac-secret.

package enum CTAPCommand {
    package static let makeCredential: UInt8 = 0x01
    package static let getAssertion: UInt8 = 0x02
    package static let getInfo: UInt8 = 0x04
    package static let clientPIN: UInt8 = 0x06
}

/// Antwort von authenticatorGetInfo (nur die gebrauchten Felder, Typen strikt geprüft).
package struct AuthenticatorInfo: Equatable, Sendable {
    package var versions: [String]
    package var extensions: [String]
    package var aaguid: [UInt8]
    package var options: [String: Bool]
    package var maxMsgSize: Int?
    package var pinUvAuthProtocols: [Int]?

    package static func parse(_ cbor: CBOR) throws(FIDOError) -> AuthenticatorInfo {
        guard cbor.mapValue != nil else { throw .response("info.map") }
        guard let versionItems = cbor[int: 1]?.arrayValue else { throw .response("info.versions") }
        var versions: [String] = []
        for v in versionItems {
            guard let t = v.textValue else { throw .response("info.versions") }
            versions.append(t)
        }
        var extensions: [String] = []
        if let ext = cbor[int: 2] {
            guard let items = ext.arrayValue else { throw .response("info.extensions") }
            for e in items {
                guard let t = e.textValue else { throw .response("info.extensions") }
                extensions.append(t)
            }
        }
        guard let aaguid = cbor[int: 3]?.bytesValue, aaguid.count == 16 else { throw .response("info.aaguid") }
        var options: [String: Bool] = [:]
        if let opt = cbor[int: 4] {
            guard let pairs = opt.mapValue else { throw .response("info.options") }
            for pair in pairs {
                guard let k = pair.key.textValue, let b = pair.value.boolValue else { throw .response("info.options") }
                options[k] = b
            }
        }
        var maxMsgSize: Int?
        if let m = cbor[int: 5] {
            guard let u = m.unsignedValue, u <= 1 << 20 else { throw .response("info.maxmsg") }
            maxMsgSize = Int(u)
        }
        var protocols: [Int]?
        if let p = cbor[int: 6] {
            guard let items = p.arrayValue else { throw .response("info.protocols") }
            var list: [Int] = []
            for item in items {
                guard let u = item.unsignedValue, u <= 255 else { throw .response("info.protocols") }
                list.append(Int(u))
            }
            protocols = list
        }
        return AuthenticatorInfo(versions: versions, extensions: extensions, aaguid: aaguid, options: options,
                                 maxMsgSize: maxMsgSize, pinUvAuthProtocols: protocols)
    }

    package var supportsCTAP2: Bool {
        versions.contains { $0 == "FIDO_2_0" || $0 == "FIDO_2_1" || $0 == "FIDO_2_1_PRE" || $0 == "FIDO_2_2" }
    }

    /// Prüft vor jeder Berührung, ob hmac-secret ohne UV möglich ist (SPEC §14.3).
    package func requireUsable(forRegistration: Bool) throws(FIDOError) {
        guard supportsCTAP2 else { throw .unsupported("ctap2") }
        guard extensions.contains("hmac-secret") else { throw .unsupported("hmac-secret") }
        if options["alwaysUv"] == true { throw .unsupported("uv") }
        guard forRegistration, options["makeCredUvNotRqd"] != true else { return }
        // Mit gesetzter PIN verlangt makeCredential sonst eine PIN – Siegel fragt keine PIN ab.
        if options["clientPin"] == true { throw .unsupported("pin") }
        // CTAP 2.1: eingerichtete eingebaute UV (z. B. Fingerabdruck am Schlüssel) verlangt ebenfalls UV.
        if options["uv"] == true, versions.contains("FIDO_2_1") { throw .unsupported("uv") }
    }

    /// Protokoll 2 bevorzugt, sonst 1. Fehlt die Liste (CTAP 2.0), gilt Protokoll 1.
    package func preferredPinProtocol() throws(FIDOError) -> PinUvProtocol {
        guard let list = pinUvAuthProtocols else { return .one }
        if list.contains(2) { return .two }
        if list.contains(1) { return .one }
        throw .unsupported("pin.protocol")
    }
}

/// authenticatorData (WebAuthn §6.1), strikt gelesen.
package struct AuthenticatorData: Sendable {
    package static let flagUP: UInt8 = 0x01
    package static let flagUV: UInt8 = 0x04
    package static let flagAT: UInt8 = 0x40
    package static let flagED: UInt8 = 0x80
    package static let maxLength = 4096

    package let rpIDHash: [UInt8]
    package let flags: UInt8
    package let signCount: UInt32
    package let credentialID: [UInt8]?
    package let credentialPublicKey: CBOR?
    package let extensions: CBOR?

    package static func parse(_ b: [UInt8]) throws(FIDOError) -> AuthenticatorData {
        guard b.count >= 37, b.count <= maxLength else { throw .response("authdata.length") }
        let flags = b[32]
        var offset = 37
        var credentialID: [UInt8]?
        var publicKey: CBOR?
        var limits = CBORLimits()
        limits.maxDepth = 4
        limits.maxItems = 256
        if flags & flagAT != 0 {
            guard b.count >= offset + 18 else { throw .response("authdata.length") }
            offset += 16   // AAGUID
            let length = Int(b.readBE16(at: offset))
            offset += 2
            guard length >= 1, length <= 1024, b.count >= offset + length else { throw .response("authdata.credential") }
            credentialID = Array(b[offset..<(offset + length)])
            offset += length
            do {
                let (key, next) = try CBORDecoder.decodePrefix(b, at: offset, limits: limits)
                guard key.mapValue != nil else { throw FIDOError.response("authdata.publickey") }
                publicKey = key
                offset = next
            } catch let e as CBORError {
                throw .cbor(e)
            } catch {
                throw .response("authdata.publickey")
            }
        }
        var extensions: CBOR?
        if flags & flagED != 0 {
            do {
                let (ext, next) = try CBORDecoder.decodePrefix(b, at: offset, limits: limits)
                guard ext.mapValue != nil else { throw FIDOError.response("authdata.extensions") }
                extensions = ext
                offset = next
            } catch let e as CBORError {
                throw .cbor(e)
            } catch {
                throw .response("authdata.extensions")
            }
        }
        guard offset == b.count else { throw .response("authdata.trailing") }
        return AuthenticatorData(rpIDHash: Array(b[0..<32]), flags: flags, signCount: b.readBE32(at: 33),
                                 credentialID: credentialID, credentialPublicKey: publicKey, extensions: extensions)
    }
}

/// CTAP2-Befehle über einen CTAPHID-Kanal.
final class CTAP2Client {
    static let rpID = "siegel"
    static let rpName = "Siegel"
    static var rpIDHash: [UInt8] { Array(SHA256.hash(data: Data(rpID.utf8))) }

    let channel: CTAPHIDChannel
    var maxMsgSize: Int?

    init(channel: CTAPHIDChannel) { self.channel = channel }

    /// Sendet einen Befehl; Status ≠ 0 → `ctap(status)`. Antwort strikt dekodiert (nil = leer).
    func command(_ cmd: UInt8, _ params: CBOR?, userPresence: Bool) throws(FIDOError) -> CBOR? {
        var request: [UInt8] = [cmd]
        if let params {
            do { request += try CBOREncoder.encode(params) } catch { throw .cbor(error) }
        }
        if let maxMsgSize, request.count > maxMsgSize { throw .unsupported("msgsize") }
        let (status, body) = try channel.cbor(request, userPresence: userPresence)
        guard status == CTAPStatus.ok else { throw .ctap(status) }
        guard !body.isEmpty else { return nil }
        do { return try CBORDecoder.decode(body) } catch { throw .cbor(error) }
    }

    func getInfo() throws(FIDOError) -> AuthenticatorInfo {
        guard let response = try command(CTAPCommand.getInfo, nil, userPresence: false) else {
            throw .response("info.empty")
        }
        return try AuthenticatorInfo.parse(response)
    }

    func keyAgreement(_ version: PinUvProtocol) throws(FIDOError) -> P256.KeyAgreement.PublicKey {
        let params: CBOR = .map([CBORPair(.int(1), .int(Int64(version.rawValue))), CBORPair(.int(2), .int(2))])
        guard let response = try command(CTAPCommand.clientPIN, params, userPresence: false),
              let cose = response[int: 1] else { throw .response("pin.keyagreement") }
        return try PinUvSession.publicKey(fromCOSE: cose)
    }

    /// Registriert einen nicht residenten Schlüssel mit hmac-secret (Berührung). Liefert die credentialID.
    func makeCredential(clientDataHash: [UInt8], userID: [UInt8]) throws(FIDOError) -> [UInt8] {
        let params: CBOR = .map([
            CBORPair(.int(1), .bytes(clientDataHash)),
            CBORPair(.int(2), .map([CBORPair(.text("id"), .text(Self.rpID)), CBORPair(.text("name"), .text(Self.rpName))])),
            CBORPair(.int(3), .map([CBORPair(.text("id"), .bytes(userID)), CBORPair(.text("name"), .text("siegel")),
                                    CBORPair(.text("displayName"), .text("Siegel"))])),
            CBORPair(.int(4), .array([.map([CBORPair(.text("alg"), .int(-7)), CBORPair(.text("type"), .text("public-key"))])])),
            CBORPair(.int(6), .map([CBORPair(.text("hmac-secret"), .bool(true))])),
            CBORPair(.int(7), .map([CBORPair(.text("rk"), .bool(false))])),
        ])
        guard let response = try command(CTAPCommand.makeCredential, params, userPresence: true) else {
            throw .response("makecred.empty")
        }
        guard response[int: 1]?.textValue != nil else { throw .response("makecred.fmt") }
        guard response[int: 3]?.mapValue != nil else { throw .response("makecred.attstmt") }
        guard let raw = response[int: 2]?.bytesValue else { throw .response("makecred.authdata") }
        let authData = try AuthenticatorData.parse(raw)
        guard authData.rpIDHash == Self.rpIDHash else { throw .response("makecred.rpid") }
        guard authData.flags & AuthenticatorData.flagUP != 0 else { throw .response("makecred.up") }
        guard authData.flags & AuthenticatorData.flagAT != 0, let credentialID = authData.credentialID,
              let key = authData.credentialPublicKey, key[int: 1] != nil else { throw .response("makecred.credential") }
        guard authData.extensions?[text: "hmac-secret"]?.boolValue == true else { throw .unsupported("hmac-secret") }
        return credentialID
    }

    struct Assertion {
        let authData: AuthenticatorData
        let encryptedOutput: [UInt8]
    }

    /// getAssertion mit hmac-secret (Berührung, ohne UV).
    func getAssertion(credentialID: [UInt8], clientDataHash: [UInt8], hmacSecret: CBOR) throws(FIDOError) -> Assertion {
        let descriptor: CBOR = .map([CBORPair(.text("id"), .bytes(credentialID)), CBORPair(.text("type"), .text("public-key"))])
        let params: CBOR = .map([
            CBORPair(.int(1), .text(Self.rpID)),
            CBORPair(.int(2), .bytes(clientDataHash)),
            CBORPair(.int(3), .array([descriptor])),
            CBORPair(.int(4), .map([CBORPair(.text("hmac-secret"), hmacSecret)])),
            CBORPair(.int(5), .map([CBORPair(.text("up"), .bool(true))])),
        ])
        guard let response = try command(CTAPCommand.getAssertion, params, userPresence: true) else {
            throw .response("assert.empty")
        }
        if let credential = response[int: 1] {
            guard credential[text: "id"]?.bytesValue == credentialID else { throw .response("assert.credential") }
            if let type = credential[text: "type"], type.textValue != "public-key" { throw .response("assert.credential") }
        }
        guard response[int: 3]?.bytesValue != nil else { throw .response("assert.signature") }
        guard let raw = response[int: 2]?.bytesValue else { throw .response("assert.authdata") }
        let authData = try AuthenticatorData.parse(raw)
        guard authData.rpIDHash == Self.rpIDHash else { throw .response("assert.rpid") }
        guard authData.flags & AuthenticatorData.flagUP != 0 else { throw .response("assert.up") }
        // Mit UV rechnet der Schlüssel mit einem anderen CredRandom: Ausgabe wäre nicht stabil.
        guard authData.flags & AuthenticatorData.flagUV == 0 else { throw .unsupported("uv") }
        guard authData.flags & AuthenticatorData.flagAT == 0 else { throw .response("assert.at") }
        guard let output = authData.extensions?[text: "hmac-secret"]?.bytesValue else {
            throw .response("assert.hmac-secret")
        }
        return Assertion(authData: authData, encryptedOutput: output)
    }
}

/// Abläufe für SecurityKeyFactor, unabhängig vom Transport (Tests: virtueller Authenticator).
package struct FIDO2Flows {
    package static let credentialIDRange = 16...1024
    package static let saltLength = 32

    let transport: any CTAPHIDTransport
    let timeouts: CTAPHIDTimeouts
    /// Abbruch durch die Oberfläche (v4.4): offene Anfrage mit CTAPHID_CANCEL beenden, `cancelled` melden.
    let cancellation: SecurityKeyCancellation?

    package init(transport: any CTAPHIDTransport, timeouts: CTAPHIDTimeouts = .standard,
                 cancellation: SecurityKeyCancellation? = nil) {
        self.transport = transport
        self.timeouts = timeouts
        self.cancellation = cancellation
    }

    private func channel() throws(FIDOError) -> CTAPHIDChannel {
        guard cancellation?.isCancelled != true else { throw .cancelled }
        return try CTAPHIDChannel(transport: transport, timeouts: timeouts, cancellation: cancellation)
    }

    /// makeCredential (Berührung 1) + getAssertion mit beiden Salzen in einer Anfrage (Berührung 2).
    package func register() throws(FIDOError) -> SecurityKeyEnrollment {
        let client = CTAP2Client(channel: try channel())
        let info = try client.getInfo()
        try info.requireUsable(forRegistration: true)
        let version = try info.preferredPinProtocol()
        client.maxMsgSize = info.maxMsgSize
        let credentialID = try client.makeCredential(clientDataHash: try random(32), userID: try random(16))
        guard Self.credentialIDRange.contains(credentialID.count) else { throw .unsupported("credential.length") }
        let salt = try random(Self.saltLength)
        let entrySalt = try random(Self.saltLength)
        guard salt != entrySalt else { throw .input("salt") }
        let outputs = try hmacSecret(client, version: version, credentialID: credentialID, salts: [salt, entrySalt])
        // Gleiche Ausgaben für verschiedene Salze hiesse: Entsperren und Einträge wären nicht getrennt.
        let distinct = outputs.withUnsafeBytes { buf in
            !constantTimeEqual(UnsafeRawBufferPointer(rebasing: buf[0..<32]), UnsafeRawBufferPointer(rebasing: buf[32..<64]))
        }
        guard distinct else { throw .response("output.same") }
        do {
            return SecurityKeyEnrollment(credentialID: Data(credentialID), salt: Data(salt),
                                         output: try outputs.factorSecret(0..<32), entrySalt: Data(entrySalt),
                                         entryOutput: try outputs.factorSecret(32..<64))
        } catch {
            throw .response("output")
        }
    }

    /// Eine hmac-secret-Ausgabe (Berührung).
    package func secret(credentialID: Data, salt: Data) throws(FIDOError) -> FactorSecret {
        try Self.validate(credentialID: credentialID, salt: salt)
        let client = CTAP2Client(channel: try channel())
        let info = try client.getInfo()
        try info.requireUsable(forRegistration: false)
        let version = try info.preferredPinProtocol()
        client.maxMsgSize = info.maxMsgSize
        let output = try hmacSecret(client, version: version, credentialID: Array(credentialID), salts: [Array(salt)])
        do { return try output.factorSecret(0..<32) } catch { throw .response("output") }
    }

    package static func validate(credentialID: Data, salt: Data) throws(FIDOError) {
        guard credentialIDRange.contains(credentialID.count) else { throw .input("credential") }
        guard salt.count == saltLength else { throw .input("salt") }
    }

    /// Schlüsselvereinbarung, Salze verschlüsseln und authentisieren, Ausgabe prüfen und entschlüsseln.
    private func hmacSecret(_ client: CTAP2Client, version: PinUvProtocol, credentialID: [UInt8],
                            salts: [[UInt8]]) throws(FIDOError) -> SecretScratch {
        let session = try PinUvSession.establish(version, authenticatorKey: try client.keyAgreement(version))
        let plain = salts.flatMap { $0 }
        let saltEnc = try session.encrypt(plain)
        var input: [CBORPair] = [
            CBORPair(.int(1), session.platformKey),
            CBORPair(.int(2), .bytes(saltEnc)),
            CBORPair(.int(3), .bytes(session.authenticate(saltEnc))),
        ]
        // Schlüssel 4 nur bei Protokoll 2: CTAP-2.0-Geräte kennen ihn nicht (Protokoll 1 ist dort Standard).
        if version == .two { input.append(CBORPair(.int(4), .int(2))) }
        let assertion = try client.getAssertion(credentialID: credentialID, clientDataHash: try random(32),
                                                hmacSecret: .map(input))
        guard assertion.encryptedOutput.count == session.ciphertextLength(plain.count) else {
            throw .response("assert.output.length")
        }
        let output = try session.decrypt(assertion.encryptedOutput)
        guard output.count == plain.count else { throw .response("assert.output.length") }
        return output
    }

    private func random(_ n: Int) throws(FIDOError) -> [UInt8] {
        do { return try SecureRandom.bytes(n) } catch { throw .transport }
    }
}
