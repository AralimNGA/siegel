import CommonCrypto
import CryptoKit
import Foundation

/// PIN/UV-Auth-Protokolle 1 und 2 (CTAP 2.1 §6.5.6/§6.5.7), hier nur für die Verschlüsselung der
/// hmac-secret-Salze und -Ausgaben (keine PIN-Eingabe).
package enum PinUvProtocol: Int, Sendable, CaseIterable {
    case one = 1
    case two = 2
}

/// Eine Schlüsselvereinbarung mit dem Authenticator: Plattform-Schlüssel (COSE) und abgeleitete Schlüssel.
/// Protokoll 1: ein Schlüssel `SHA-256(Z)` für HMAC und AES. Protokoll 2: `HKDF-SHA-256(salt = 32 × 0, Z,
/// "CTAP2 HMAC key")` und `… "CTAP2 AES key"`. CryptoKit nullt `SymmetricKey` beim Freigeben.
struct PinUvSession {
    let version: PinUvProtocol
    let hmacKey: SymmetricKey
    let aesKey: SymmetricKey
    /// COSE_Key der Plattform: kty 2 (EC2), alg −25, crv 1 (P-256), x, y.
    let platformKey: CBOR

    static func establish(_ version: PinUvProtocol, authenticatorKey: P256.KeyAgreement.PublicKey) throws(FIDOError) -> PinUvSession {
        let platform = P256.KeyAgreement.PrivateKey()
        let z: SharedSecret
        do { z = try platform.sharedSecretFromKeyAgreement(with: authenticatorKey) } catch { throw .response("pin.ecdh") }
        let (hmac, aes) = derive(version, z: z)
        return PinUvSession(version: version, hmacKey: hmac, aesKey: aes, platformKey: coseKey(platform.publicKey))
    }

    static func derive(_ version: PinUvProtocol, z: SharedSecret) -> (hmac: SymmetricKey, aes: SymmetricKey) {
        switch version {
        case .one:
            var h = SHA256()
            z.withUnsafeBytes { h.update(bufferPointer: $0) }
            let key = SymmetricKey(data: h.finalize())
            return (key, key)
        case .two:
            let zeroSalt = Data(repeating: 0, count: 32)
            let hmac = z.hkdfDerivedSymmetricKey(using: SHA256.self, salt: zeroSalt,
                                                 sharedInfo: Data("CTAP2 HMAC key".utf8), outputByteCount: 32)
            let aes = z.hkdfDerivedSymmetricKey(using: SHA256.self, salt: zeroSalt,
                                                sharedInfo: Data("CTAP2 AES key".utf8), outputByteCount: 32)
            return (hmac, aes)
        }
    }

    /// Protokoll 1: AES-256-CBC mit IV = 0. Protokoll 2: zufälliger IV, Ausgabe `IV ‖ Chiffrat`.
    func encrypt(_ plaintext: [UInt8]) throws(FIDOError) -> [UInt8] {
        switch version {
        case .one:
            return try Self.aesCBC(encrypt: true, key: aesKey, iv: [UInt8](repeating: 0, count: 16), input: plaintext)
        case .two:
            let iv: [UInt8]
            do { iv = try SecureRandom.bytes(16) } catch { throw .transport }
            return try encrypt(plaintext, iv: iv)
        }
    }

    /// Nur Protokoll 2, mit festem IV (Tests).
    func encrypt(_ plaintext: [UInt8], iv: [UInt8]) throws(FIDOError) -> [UInt8] {
        guard version == .two else { return try encrypt(plaintext) }
        return iv + (try Self.aesCBC(encrypt: true, key: aesKey, iv: iv, input: plaintext))
    }

    /// Entschlüsselt in einen Geheimnis-Puffer (die hmac-secret-Ausgaben sind Faktor-Geheimnisse).
    func decrypt(_ ciphertext: [UInt8]) throws(FIDOError) -> SecretScratch {
        let iv: [UInt8], body: [UInt8]
        switch version {
        case .one:
            iv = [UInt8](repeating: 0, count: 16)
            body = ciphertext
        case .two:
            guard ciphertext.count >= 16 else { throw .response("pin.length") }
            iv = Array(ciphertext[0..<16])
            body = Array(ciphertext[16...])
        }
        guard !body.isEmpty, body.count % 16 == 0 else { throw .response("pin.length") }
        let out = SecretScratch(count: body.count)
        let ok = out.withUnsafeMutableBytes { dst in
            body.withUnsafeBytes { src in Self.cbc(encrypt: false, key: aesKey, iv: iv, input: src, output: dst) }
        }
        guard ok else { throw .response("pin.aes") }
        return out
    }

    /// Protokoll 1: HMAC-SHA-256, die ersten 16 Byte. Protokoll 2: volle 32 Byte.
    func authenticate(_ message: [UInt8]) -> [UInt8] {
        let tag = Array(HMAC<SHA256>.authenticationCode(for: message, using: hmacKey))
        return version == .one ? Array(tag[0..<16]) : tag
    }

    /// Länge der verschlüsselten Darstellung von `count` Byte Klartext.
    func ciphertextLength(_ count: Int) -> Int { version == .one ? count : count + 16 }

    // MARK: COSE

    static func coseKey(_ key: P256.KeyAgreement.PublicKey) -> CBOR {
        let x963 = Array(key.x963Representation)
        return .map([
            CBORPair(.int(1), .int(2)),
            CBORPair(.int(3), .int(-25)),
            CBORPair(.int(-1), .int(1)),
            CBORPair(.int(-2), .bytes(Array(x963[1..<33]))),
            CBORPair(.int(-3), .bytes(Array(x963[33..<65]))),
        ])
    }

    /// COSE_Key des Authenticators (EC2, P-256). Der Punkt muss auf der Kurve liegen.
    static func publicKey(fromCOSE cose: CBOR) throws(FIDOError) -> P256.KeyAgreement.PublicKey {
        guard cose.mapValue != nil, cose[int: 1]?.intValue == 2, cose[int: -1]?.intValue == 1,
              let x = cose[int: -2]?.bytesValue, x.count == 32,
              let y = cose[int: -3]?.bytesValue, y.count == 32 else { throw .response("cose.key") }
        guard let key = try? P256.KeyAgreement.PublicKey(x963Representation: [0x04] + x + y) else {
            throw .response("cose.point")
        }
        return key
    }

    // MARK: AES-256-CBC ohne Auffüllen (CommonCrypto)

    static func aesCBC(encrypt: Bool, key: SymmetricKey, iv: [UInt8], input: [UInt8]) throws(FIDOError) -> [UInt8] {
        guard !input.isEmpty, input.count % 16 == 0 else { throw .response("pin.length") }
        var out = [UInt8](repeating: 0, count: input.count)
        let ok = out.withUnsafeMutableBytes { dst in
            input.withUnsafeBytes { src in cbc(encrypt: encrypt, key: key, iv: iv, input: src, output: dst) }
        }
        guard ok else { throw .response("pin.aes") }
        return out
    }

    static func cbc(encrypt: Bool, key: SymmetricKey, iv: [UInt8], input: UnsafeRawBufferPointer,
                    output: UnsafeMutableRawBufferPointer) -> Bool {
        guard iv.count == 16, key.bitCount == 256, input.count % 16 == 0, output.count >= input.count else { return false }
        var moved = 0
        let status = key.withUnsafeBytes { k in
            iv.withUnsafeBytes { v in
                CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                        k.baseAddress, k.count, v.baseAddress, input.baseAddress, input.count,
                        output.baseAddress, output.count, &moved)
            }
        }
        return status == CCCryptorStatus(kCCSuccess) && moved == input.count
    }
}
