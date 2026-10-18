import Clibsodium
import Foundation

/// XChaCha20-Poly1305-IETF (SPEC §1.4): 24-Byte-Zufallsnonce pro Verschlüsselung, 16-Byte-Tag.
enum AEAD {
    static let nonceBytes = 24
    static let tagBytes = 16
    static let keyBytes = 32
    /// nonce[24] ‖ ct[32] ‖ tag[16]
    static let wrappedBytes = 72

    private struct OpenFailed: Error {}

    /// Verpackt einen 32-Byte-Schlüssel: nonce ‖ ct ‖ tag (72 Byte).
    static func wrap(kek: SecureBytes, secret: SecureBytes, ad: [UInt8]) throws -> [UInt8] {
        guard kek.count == keyBytes, secret.count == keyBytes else { throw SiegelError.crypto("aead.keyLength") }
        var out = [UInt8](repeating: 0, count: wrappedBytes)
        let rc: Int32 = out.withUnsafeMutableBytes { o in
            guard let op = o.u8 else { return -1 }
            randombytes_buf(op, nonceBytes)
            return kek.withUnsafeBytes { k in
                secret.withUnsafeBytes { m in
                    ad.withUnsafeBytes { a in
                        var clen: UInt64 = 0
                        guard let kp = k.u8, let mp = m.u8 else { return -1 }
                        return crypto_aead_xchacha20poly1305_ietf_encrypt(
                            op + nonceBytes, &clen, mp, UInt64(keyBytes), a.u8, UInt64(ad.count), nil, op, kp)
                    }
                }
            }
        }
        guard rc == 0 else { throw SiegelError.crypto("aead.encrypt") }
        return out
    }

    /// Entpackt; nil bei falschem Schlüssel/AD/manipulierten Bytes.
    static func unwrap(kek: SecureBytes, blob: [UInt8], ad: [UInt8]) -> SecureBytes? {
        guard kek.count == keyBytes, blob.count == wrappedBytes else { return nil }
        return try? SecureBytes(count: keyBytes) { out in
            let rc: Int32 = blob.withUnsafeBytes { b in
                kek.withUnsafeBytes { k in
                    ad.withUnsafeBytes { a in
                        var mlen: UInt64 = 0
                        guard let bp = b.u8, let kp = k.u8, let op = out.u8 else { return -1 }
                        return crypto_aead_xchacha20poly1305_ietf_decrypt(
                            op, &mlen, nil, bp + nonceBytes, UInt64(keyBytes + tagBytes),
                            a.u8, UInt64(ad.count), bp, kp)
                    }
                }
            }
            guard rc == 0 else { throw OpenFailed() }
        }
    }

    /// Verschlüsselt einen Klartext-Puffer; liefert (nonce, ct ‖ tag).
    static func seal(key: SecureBytes, plaintext: SecureBytes, ad: [UInt8]) throws -> (nonce: [UInt8], ciphertext: [UInt8]) {
        guard key.count == keyBytes else { throw SiegelError.crypto("aead.keyLength") }
        let nonce = randomBytes(nonceBytes)
        var ct = [UInt8](repeating: 0, count: plaintext.count + tagBytes)
        let rc: Int32 = ct.withUnsafeMutableBytes { c in
            plaintext.withUnsafeBytes { m in
                key.withUnsafeBytes { k in
                    ad.withUnsafeBytes { a in
                        nonce.withUnsafeBytes { n in
                            var clen: UInt64 = 0
                            guard let cp = c.u8, let kp = k.u8, let np = n.u8 else { return -1 }
                            return crypto_aead_xchacha20poly1305_ietf_encrypt(
                                cp, &clen, m.u8, UInt64(plaintext.count), a.u8, UInt64(ad.count), nil, np, kp)
                        }
                    }
                }
            }
        }
        guard rc == 0 else { throw SiegelError.crypto("aead.encrypt") }
        return (nonce, ct)
    }

    /// Entschlüsselt in `SecureBytes`; nil bei Authentisierungsfehler.
    static func open(key: SecureBytes, nonce: [UInt8], ciphertext: [UInt8], ad: [UInt8]) -> SecureBytes? {
        guard key.count == keyBytes, nonce.count == nonceBytes, ciphertext.count >= tagBytes else { return nil }
        return try? SecureBytes(count: ciphertext.count - tagBytes) { out in
            let rc: Int32 = ciphertext.withUnsafeBytes { c in
                key.withUnsafeBytes { k in
                    ad.withUnsafeBytes { a in
                        nonce.withUnsafeBytes { n in
                            var mlen: UInt64 = 0
                            // SecureBytes hat immer eine Adresse (mind. 1 Byte reserviert).
                            guard let cp = c.u8, let kp = k.u8, let np = n.u8, let op = out.u8 else { return -1 }
                            return crypto_aead_xchacha20poly1305_ietf_decrypt(
                                op, &mlen, nil, cp, UInt64(ciphertext.count), a.u8, UInt64(ad.count), np, kp)
                        }
                    }
                }
            }
            guard rc == 0 else { throw OpenFailed() }
        }
    }
}
