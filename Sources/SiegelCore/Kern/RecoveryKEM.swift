import CryptoKit
import Foundation

/// Öffentliche Notfallschlüssel aus dem KOPF: ML-KEM-1024 (1568 B) und X25519 (32 B).
struct RecoveryPublicKeys: Equatable, Sendable {
    static let pkMBytes = 1568
    static let pkXBytes = 32

    let pkM: [UInt8]
    let pkX: [UInt8]

    /// Kit-Kennung "XXXX-XXXX" (nicht geheim).
    var kitID: String { RecoveryCodeCodec.kitID(pkM: pkM, pkX: pkX) }
}

/// Ergebnis des Kapselns: KEK_rec und die beiden Chiffrate für den recSlot.
struct RecoveryEncapsulation {
    let kek: SecureBytes
    let ctM: [UInt8]
    let ctX: [UInt8]
}

/// Geprüfte private Hybrid-Schlüssel (ML-KEM-1024 + X25519) samt den öffentlichen, zu denen sie passen.
struct HybridPrivateKeys {
    let skM: MLKEM1024.PrivateKey
    let skX: Curve25519.KeyAgreement.PrivateKey
    let pk: RecoveryPublicKeys
}

/// Hybrider Notfallschlüssel ML-KEM-1024 + X25519 (SPEC §1.3).
enum RecoveryKEM {
    static let rBytes = 32
    static let ctMBytes = 1568
    static let ctXBytes = 32
    /// Feste Seed-Länge: CryptoKit beendet bei anderer Länge den Prozess.
    static let seedBytes = 64

    /// HKDF-Infos für R bleiben in allen Formatversionen "Siegel v1 …" (gedruckte Codes bleiben gültig, §13.2).
    static let seedInfo = Array("Siegel v1 recovery ML-KEM-1024 seed".utf8)
    static let x25519Info = Array("Siegel v1 recovery X25519".utf8)
    /// Kombinierer-Label der Formatversion 1; v2 nimmt `FileFormat.Labels.hybridKEM` ("Siegel v2 hybrid KEM").
    static let combinerLabel = Array("Siegel v1 hybrid KEM".utf8)

    /// `HKDF<SHA512>(ikm, salt = vaultID, info, L)` in `SecureBytes`.
    static func hkdf(_ r: SecureBytes, vaultID: [UInt8], info: [UInt8], count: Int) throws -> SecureBytes {
        let ikm = r.withUnsafeBytes { SymmetricKey(data: $0) }
        let key = HKDF<SHA512>.deriveKey(inputKeyMaterial: ikm, salt: vaultID, info: info, outputByteCount: count)
        return try key.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    /// ML-KEM-Schlüssel aus dem Seed. Die Länge ist die Konstante 64 und wird vorher geprüft (CryptoKit-Falle);
    /// der Getter `seedRepresentation` wird nie aufgerufen.
    static func mlkemPrivateKey(seed: SecureBytes, publicKey: MLKEM1024.PublicKey?) throws -> MLKEM1024.PrivateKey {
        precondition(seed.count == seedBytes, "mlkem.seedLength")
        return try seed.withUnsafeBytes { try MLKEM1024.PrivateKey(seedRepresentation: $0, publicKey: publicKey) }
    }

    static func mlkemSeed(r: SecureBytes, vaultID: [UInt8], info: [UInt8] = seedInfo) throws -> SecureBytes {
        try hkdf(r, vaultID: vaultID, info: info, count: seedBytes)
    }

    static func x25519PrivateKey(r: SecureBytes, vaultID: [UInt8],
                                 info: [UInt8] = x25519Info) throws -> Curve25519.KeyAgreement.PrivateKey {
        let raw = try hkdf(r, vaultID: vaultID, info: info, count: 32)
        do {
            return try raw.withUnsafeBytes { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
        } catch {
            throw SiegelError.crypto("kem.x25519")
        }
    }

    /// pkM/pkX aus R ableiten (braucht vaultID als HKDF-Salz).
    static func derivePublicKeys(r: SecureBytes, vaultID: [UInt8]) throws -> RecoveryPublicKeys {
        try derivePublicKeys(ikm: r, vaultID: vaultID, seedInfo: seedInfo, x25519Info: x25519Info)
    }

    /// Hybrid-Schlüsselpaar aus einem 32-Byte-Geheimnis mit eigenen HKDF-Infos (Notfall: R; Einträge §16.1:
    /// Karte q bzw. FIDO-Ausgabe y2 mit "Siegel v2 card entry …"/"Siegel v2 fido entry …").
    static func derivePublicKeys(ikm r: SecureBytes, vaultID: [UInt8], seedInfo: [UInt8],
                                 x25519Info: [UInt8]) throws -> RecoveryPublicKeys {
        let seed = try mlkemSeed(r: r, vaultID: vaultID, info: seedInfo)
        let skM: MLKEM1024.PrivateKey
        do {
            skM = try mlkemPrivateKey(seed: seed, publicKey: nil)
        } catch {
            throw SiegelError.crypto("kem.keygen")
        }
        let skX = try x25519PrivateKey(r: r, vaultID: vaultID, info: x25519Info)
        let pk = RecoveryPublicKeys(pkM: Array(skM.publicKey.rawRepresentation),
                                    pkX: Array(skX.publicKey.rawRepresentation))
        guard pk.pkM.count == RecoveryPublicKeys.pkMBytes, pk.pkX.count == RecoveryPublicKeys.pkXBytes else {
            throw SiegelError.crypto("kem.keygen")
        }
        return pk
    }

    /// Prüft, ob R genau diese öffentlichen Schlüssel ergibt (zuerst das billige X25519, dann ML-KEM).
    static func matches(r: SecureBytes, vaultID: [UInt8], expected: RecoveryPublicKeys) -> Bool {
        guard let skX = try? x25519PrivateKey(r: r, vaultID: vaultID),
              Array(skX.publicKey.rawRepresentation) == expected.pkX,
              let seed = try? mlkemSeed(r: r, vaultID: vaultID),
              let skM = try? mlkemPrivateKey(seed: seed, publicKey: nil) else { return false }
        return Array(skM.publicKey.rawRepresentation) == expected.pkM
    }

    /// Kapseln für den recSlot: braucht nur die öffentlichen Schlüssel (nicht R). `label` = Kombinierer-Label der
    /// Formatversion des Kopfes.
    static func encapsulate(to pk: RecoveryPublicKeys, label: [UInt8]) throws -> RecoveryEncapsulation {
        let ssM: SymmetricKey
        let ctM: [UInt8]
        do {
            let pub = try MLKEM1024.PublicKey(rawRepresentation: pk.pkM)
            let result = try pub.encapsulate()
            ssM = result.sharedSecret
            ctM = Array(result.encapsulated)
        } catch {
            throw SiegelError.crypto("kem.encapsulate")
        }
        guard ctM.count == ctMBytes else { throw SiegelError.crypto("kem.encapsulate") }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ctX = Array(ephemeral.publicKey.rawRepresentation)
        let ssX: SharedSecret
        do {
            ssX = try ephemeral.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: pk.pkX))
        } catch {
            throw SiegelError.crypto("kem.x25519")
        }
        let kek = try ssM.withUnsafeBytes { m in
            try ssX.withUnsafeBytes { x in
                try combine(label: label, ssM: m, ssX: x, ctX: ctX, pkX: pk.pkX, ctM: ctM, pkM: pk.pkM)
            }
        }
        return RecoveryEncapsulation(kek: kek, ctM: ctM, ctX: ctX)
    }

    /// Entkapseln mit R. Vor bestandener pk-Prüfung → `wrongRecoveryCode`, danach jedes Scheitern `corruptFile`.
    static func decapsulate(r: SecureBytes, vaultID: [UInt8], pk: RecoveryPublicKeys,
                            ctM: [UInt8], ctX: [UInt8], label: [UInt8]) throws -> SecureBytes {
        let derived = try derivePublicKeys(r: r, vaultID: vaultID)
        let codeKit = derived.kitID
        let vaultKit = pk.kitID
        guard codeKit == vaultKit else { throw SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: vaultKit) }
        let seed = try mlkemSeed(r: r, vaultID: vaultID)
        let skM: MLKEM1024.PrivateKey
        do {
            skM = try mlkemPrivateKey(seed: seed, publicKey: MLKEM1024.PublicKey(rawRepresentation: pk.pkM))
        } catch {
            // u. a. KEM.Errors.publicKeyMismatchDuringInitialization
            throw SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: vaultKit)
        }
        let skX = try x25519PrivateKey(r: r, vaultID: vaultID)
        guard Array(skX.publicKey.rawRepresentation) == pk.pkX else {
            throw SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: vaultKit)
        }
        // pk-Prüfung bestanden: ab hier nur noch corruptFile.
        do {
            guard ctM.count == ctMBytes, ctX.count == ctXBytes else { throw SiegelError.corruptFile("rec.length") }
            let ssM = try skM.decapsulate(Data(ctM))
            let ssX = try skX.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: ctX))
            return try ssM.withUnsafeBytes { m in
                try ssX.withUnsafeBytes { x in
                    try combine(label: label, ssM: m, ssX: x, ctX: ctX, pkX: pk.pkX, ctM: ctM, pkM: pk.pkM)
                }
            }
        } catch {
            throw SiegelError.corruptFile("rec.decapsulate")
        }
    }

    /// KEK_rec = SHA3-256(label ‖ ssM ‖ ssX ‖ ctX ‖ pkX ‖ SHA3-256(ctM) ‖ SHA3-256(pkM)), label = "Siegel v1 hybrid
    /// KEM" bzw. "Siegel v2 hybrid KEM". Generischer Kombinierer, feste Längen, genau diese Reihenfolge.
    /// Nicht „vereinfachen“.
    static func combine(label: [UInt8], ssM: UnsafeRawBufferPointer, ssX: UnsafeRawBufferPointer,
                        ctX: [UInt8], pkX: [UInt8], ctM: [UInt8], pkM: [UInt8]) throws -> SecureBytes {
        guard ssM.count == 32, ssX.count == 32, ctX.count == ctXBytes, pkX.count == RecoveryPublicKeys.pkXBytes,
              ctM.count == ctMBytes, pkM.count == RecoveryPublicKeys.pkMBytes else {
            throw SiegelError.crypto("kem.combine")
        }
        var h = SHA3_256()
        h.update(data: label)
        h.update(bufferPointer: ssM)
        h.update(bufferPointer: ssX)
        h.update(data: ctX)
        h.update(data: pkX)
        h.update(data: Array(SHA3_256.hash(data: ctM)))
        h.update(data: Array(SHA3_256.hash(data: pkM)))
        let digest = h.finalize()
        return try digest.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    // MARK: - Variante mit Zusatzfeld (Eintrags-Schutz §16.1)

    /// Wie `combine(label:…)`, mit einem festen Zusatzfeld direkt nach dem Label (Eintrags- bzw. Gruppenkennung,
    /// 16 Byte): SHA3-256(label ‖ context ‖ ssM ‖ ssX ‖ ctX ‖ pkX ‖ SHA3-256(ctM) ‖ SHA3-256(pkM)).
    /// Die Variante ohne Zusatzfeld bleibt unverändert (Testvektor (c) und KEK v2 hängen daran).
    static func combine(label: [UInt8], context: [UInt8], ssM: UnsafeRawBufferPointer, ssX: UnsafeRawBufferPointer,
                        ctX: [UInt8], pkX: [UInt8], ctM: [UInt8], pkM: [UInt8]) throws -> SecureBytes {
        guard context.count == 16, ssM.count == 32, ssX.count == 32, ctX.count == ctXBytes,
              pkX.count == RecoveryPublicKeys.pkXBytes, ctM.count == ctMBytes,
              pkM.count == RecoveryPublicKeys.pkMBytes else {
            throw SiegelError.crypto("kem.combine")
        }
        var h = SHA3_256()
        h.update(data: label)
        h.update(data: context)
        h.update(bufferPointer: ssM)
        h.update(bufferPointer: ssX)
        h.update(data: ctX)
        h.update(data: pkX)
        h.update(data: Array(SHA3_256.hash(data: ctM)))
        h.update(data: Array(SHA3_256.hash(data: pkM)))
        let digest = h.finalize()
        return try digest.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    /// Kapseln an beliebige Hybrid-Schlüssel (Karte, Sicherheitsschlüssel, Notfall-Gruppe, Kit) mit Zusatzfeld.
    static func encapsulate(to pk: RecoveryPublicKeys, label: [UInt8],
                            context: [UInt8]) throws -> RecoveryEncapsulation {
        let ssM: SymmetricKey
        let ctM: [UInt8]
        do {
            let pub = try MLKEM1024.PublicKey(rawRepresentation: pk.pkM)
            let result = try pub.encapsulate()
            ssM = result.sharedSecret
            ctM = Array(result.encapsulated)
        } catch {
            throw SiegelError.crypto("kem.encapsulate")
        }
        guard ctM.count == ctMBytes else { throw SiegelError.crypto("kem.encapsulate") }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ctX = Array(ephemeral.publicKey.rawRepresentation)
        let ssX: SharedSecret
        do {
            ssX = try ephemeral.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: pk.pkX))
        } catch {
            throw SiegelError.crypto("kem.x25519")
        }
        let kek = try ssM.withUnsafeBytes { m in
            try ssX.withUnsafeBytes { x in
                try combine(label: label, context: context, ssM: m, ssX: x, ctX: ctX, pkX: pk.pkX, ctM: ctM, pkM: pk.pkM)
            }
        }
        return RecoveryEncapsulation(kek: kek, ctM: ctM, ctX: ctX)
    }

    /// Private Hybrid-Schlüssel aus einem 32-Byte-Geheimnis (eigene HKDF-Infos), nur wenn sie genau `expected`
    /// ergeben; sonst nil (falsches Geheimnis). Die ML-KEM-Prüfung macht CryptoKit beim Erzeugen (`publicKey:`).
    static func privateKeys(ikm: SecureBytes, vaultID: [UInt8], seedInfo: [UInt8], x25519Info: [UInt8],
                            expected: RecoveryPublicKeys) -> HybridPrivateKeys? {
        guard let skX = try? x25519PrivateKey(r: ikm, vaultID: vaultID, info: x25519Info),
              Array(skX.publicKey.rawRepresentation) == expected.pkX,
              let pub = try? MLKEM1024.PublicKey(rawRepresentation: expected.pkM),
              let seed = try? mlkemSeed(r: ikm, vaultID: vaultID, info: seedInfo),
              let skM = try? mlkemPrivateKey(seed: seed, publicKey: pub) else { return nil }
        return HybridPrivateKeys(skM: skM, skX: skX, pk: expected)
    }

    /// Entkapseln mit schon geprüften privaten Schlüsseln (Kombinierer mit Zusatzfeld). Jedes Scheitern →
    /// `crypto("kem.decapsulate")`; die Aufrufer bilden das auf ihren Fehler ab.
    static func decapsulate(_ keys: HybridPrivateKeys, ctM: [UInt8], ctX: [UInt8], label: [UInt8],
                            context: [UInt8]) throws -> SecureBytes {
        do {
            guard ctM.count == ctMBytes, ctX.count == ctXBytes else { throw SiegelError.crypto("kem.decapsulate") }
            let ssM = try keys.skM.decapsulate(Data(ctM))
            let ssX = try keys.skX.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: ctX))
            return try ssM.withUnsafeBytes { m in
                try ssX.withUnsafeBytes { x in
                    try combine(label: label, context: context, ssM: m, ssX: x, ctX: ctX, pkX: keys.pk.pkX, ctM: ctM,
                                pkM: keys.pk.pkM)
                }
            }
        } catch {
            throw SiegelError.crypto("kem.decapsulate")
        }
    }

    #if DEBUG
    /// Nur Tests (Exit-Test): ruft die ML-KEM-Ableitung mit falscher Seed-Länge auf → Vorbedingung greift.
    static func seedLengthTrapForTesting() {
        guard let wrong = try? SecureBytes(count: 63, { _ in }) else { return }
        _ = try? mlkemPrivateKey(seed: wrong, publicKey: nil)
    }
    #endif
}
