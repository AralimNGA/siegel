import Clibsodium
import CryptoKit
import Foundation

/// Ein geöffneter Tresor (noch ohne Sitzung).
struct OpenedVault {
    let file: VaultFile
    let dek: SecureBytes
    let content: VaultContent
    /// Nur bei Format v1 über den Passwortweg: KEK_pw für einen Kopf v2 mit demselben Salz und ohne Faktoren
    /// (`HKDF(p, kdfSalt, "Siegel v2 kek" ‖ 0)`), damit das erste Speichern ohne zweites Argon2 migrieren kann.
    var migrationKEK: SecureBytes? = nil
}

/// Bauen und Öffnen von Tresordateien (SPEC §1–§3).
enum VaultCrypto {
    /// pwSlot und recSlot für einen (neuen) DEK. Kapselt auf die übergebenen, authentifizierten KOPF-Bytes
    /// (Labels der Formatversion des Kopfes).
    static func makeSlots(header: VaultHeader, kekPw: SecureBytes, dek: SecureBytes) throws -> VaultSlots {
        let pwSlot = try AEAD.wrap(kek: kekPw, secret: dek, ad: VaultSlots.pwAD(header))
        let enc = try RecoveryKEM.encapsulate(to: header.pk, label: header.labels.hybridKEM)
        let recSlot = try AEAD.wrap(kek: enc.kek, secret: dek, ad: VaultSlots.recAD(header))
        return VaultSlots(pwSlot: pwSlot, ctM: enc.ctM, ctX: enc.ctX, recSlot: recSlot)
    }

    /// Ganze Datei bauen. Liefert die Bytes und SHA-256 des JSON (für die Rücklese-Prüfung).
    static func buildFile(header: VaultHeader, slots: VaultSlots, generation: UInt64, dek: SecureBytes,
                          content: VaultContent) throws -> (bytes: [UInt8], digest: [UInt8]) {
        let (padded, digest) = try PayloadCodec.encode(content)
        let ad = VaultFile.payloadAD(header: header, slots: slots, generation: generation)
        let sealed = try AEAD.seal(key: dek, plaintext: padded, ad: ad)
        let file = VaultFile(header: header, slots: slots, generation: generation,
                             nonce: sealed.nonce, ciphertext: sealed.ciphertext)
        return (file.serialize(), digest)
    }

    /// Inhalt mit dem DEK entschlüsseln. Jeder Fehler ist `corruptFile`. Die Stufe im Inhalt muss genau die
    /// Faktoren des Kopfes verlangen (beide werden immer zusammen geschrieben).
    static func decryptPayload(_ file: VaultFile, dek: SecureBytes) throws -> (content: VaultContent, digest: [UInt8]) {
        guard let padded = AEAD.open(key: dek, nonce: file.nonce, ciphertext: file.ciphertext, ad: file.payloadAD) else {
            throw SiegelError.corruptFile("payload.auth")
        }
        let decoded = try PayloadCodec.decode(padded)
        guard decoded.content.level.factors == file.header.factors else { throw SiegelError.corruptFile("payload.level") }
        guard decoded.content.destructionKeysAvoid(header: file.header) else {
            throw SiegelError.corruptFile("payload.destruction")
        }
        return decoded
    }

    /// Passwortweg: Faktoren vorhanden/Karte (`factorMissing`/`wrongCard`) → KDF-Bereich → Argon2 (`kdfFailed`) →
    /// Faktoren einrechnen → pwSlot (`wrongPassword`: Passwort oder ein Faktor falsch) → Inhalt (`corruptFile`).
    static func openWithPassword(_ file: VaultFile, password: SecureBytes, factors: FactorSecrets = FactorSecrets(),
                                 limits: KDFLimits, cache: KEKCache? = nil) throws -> OpenedVault {
        let (kek, p) = try FactorKDF.deriveKEK(header: file.header, password: password, factors: factors,
                                               limits: limits, cache: cache)
        guard let dek = AEAD.unwrap(kek: kek, blob: file.slots.pwSlot, ad: VaultSlots.pwAD(file.header)) else {
            throw SiegelError.wrongPassword
        }
        let (content, _) = try decryptPayload(file, dek: dek)
        var opened = OpenedVault(file: file, dek: dek, content: content)
        if file.header.formatVersion == 1 {
            opened.migrationKEK = try FactorKDF.kek(p: p, factorKeys: [], salt: file.header.salt, mask: 0)
        }
        return opened
    }

    /// Notfallweg: Kit-Prüfung (`wrongRecoveryCode`), danach jedes Scheitern `corruptFile`.
    static func openWithRecovery(_ file: VaultFile, r: SecureBytes) throws -> OpenedVault {
        let kek = try RecoveryKEM.decapsulate(r: r, vaultID: file.header.vaultID, pk: file.header.pk,
                                              ctM: file.slots.ctM, ctX: file.slots.ctX,
                                              label: file.header.labels.hybridKEM)
        guard let dek = AEAD.unwrap(kek: kek, blob: file.slots.recSlot, ad: VaultSlots.recAD(file.header)) else {
            throw SiegelError.corruptFile("rec.slot")
        }
        let (content, _) = try decryptPayload(file, dek: dek)
        return OpenedVault(file: file, dek: dek, content: content)
    }
}

/// Master-Tag (SPEC §1.6): `crypto_generichash(key: HKDF(DEK, "Siegel v1 master tag", 32), pw)`.
enum MasterTag {
    static let info = Array("Siegel v1 master tag".utf8)

    static func key(dek: SecureBytes) throws -> SecureBytes {
        let ikm = dek.withUnsafeBytes { SymmetricKey(data: $0) }
        let k = HKDF<SHA512>.deriveKey(inputKeyMaterial: ikm, info: info, outputByteCount: 32)
        return try k.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    static func tag(key: SecureBytes, password: UnsafeRawBufferPointer) throws -> SecureBytes {
        try SecureBytes(count: 32) { out in
            let rc: Int32 = key.withUnsafeBytes { k in
                guard let o = out.u8, let kp = k.u8 else { return -1 }
                return crypto_generichash(o, 32, password.u8, UInt64(password.count), kp, k.count)
            }
            guard rc == 0 else { throw SiegelError.crypto("generichash") }
        }
    }

    static func tag(key: SecureBytes, password: SecureBytes) throws -> SecureBytes {
        try password.withUnsafeBytes { try tag(key: key, password: $0) }
    }

    /// Tag eines Eintragspassworts (gleich normalisiert wie das Master-Passwort).
    static func tag(key: SecureBytes, entryPassword: String) -> SecureBytes? {
        var n = PasswordNormalizer.normalize(entryPassword)
        return n.withUTF8 { try? tag(key: key, password: UnsafeRawBufferPointer($0)) }
    }

    /// Einträge, deren Passwort oder Verlaufswert dem Master-Passwort entspricht.
    static func reuse(entries: [VaultEntry], key: SecureBytes, masterTag: SecureBytes) -> Set<UUID> {
        var out = Set<UUID>()
        for e in entries {
            let candidates = [e.password] + e.history.map(\.password)
            for p in candidates where !p.isEmpty {
                if let t = tag(key: key, entryPassword: p), t.constantTimeEquals(masterTag) {
                    out.insert(e.id)
                    break
                }
            }
        }
        return out
    }

    /// Kommt das (normalisierte) Passwort als Eintragspasswort vor? Vergleich über Tags mit Wegwerf-Schlüssel.
    static func isUsedByEntries(_ password: SecureBytes, entries: [VaultEntry]) throws -> Bool {
        let k = try SecureBytes.random(count: 32)
        let t = try tag(key: k, password: password)
        return !reuse(entries: entries, key: k, masterTag: t).isEmpty
    }
}
