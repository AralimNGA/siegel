import Clibsodium
import CryptoKit
import Foundation

// Eintrags-Schutz (SPEC §16.1): Geheimteile pro Eintrag versiegeln, mit den Faktoren aufdecken, Notfall-Umschläge
// und Notfall-Gruppen. Reine Kryptografie ohne Zustand; die Regeln stehen in UnlockedVault+Schutz.swift,
// die Tabellen im Inhalt in VaultContent+Schutz.swift.
//
//   base   = HKDF-SHA512(EBK, salt = entryID, info = "Siegel v2 entry dek", 32)        (EBK: Grundschlüssel im Inhalt)
//   ss_se  = HKDF-SHA512(ECDH(k, seEntryPub), salt = entryID, info = "Siegel v2 entry se", 32), k ephemer (Software)
//   ss_card/ss_fido = hybride Kapselung an cardPK/fidoPK, Kombinierer §1.3 mit entryID nach dem Label
//   K      = HKDF-SHA512(base ‖ [ss_se] ‖ [ss_card] ‖ [ss_fido], salt = entryID, info = "Siegel v2 entry key" ‖ s ‖ M, 32)
//   Blob   = XChaCha20-Poly1305(K, pad256(JSON der Geheimteile), AD = "Siegel v2 entry" ‖ vaultID ‖ entryID ‖ s ‖ M)
//   Notfall-Umschlag = hybride Kapselung an die Notfall-Gruppe der Maske M ("Siegel v2 entry recovery"), verpackt K.
//   Notfall-Gruppe   = Schlüsselpaar aus ERS (32 Zufallsbyte); ERS an das Kit gekapselt ("Siegel v2 entry recovery kit")
//                      und als Anker unter den Faktoren der Maske versiegelt (s = 0, "Siegel v2 entry anchor").
//
// Vernichtbare Einträge (§23.1, nur Schutz 4/5): statt des Eintrags-SE-Schlüssels der Vernichtungsschlüssel V,
// eigene Labels, **kein** Notfall-Umschlag:
//   ss_v   = HKDF-SHA512(ECDH(k, vPub), salt = entryID, info = "Siegel v2 entry destruction", 32), k ephemer
//   K      = HKDF-SHA512(base ‖ ss_v ‖ ss_card ‖ [ss_fido], salt = entryID,
//                        info = "Siegel v2 entry key destructible" ‖ s ‖ M, 32)
//   Blob   = XChaCha20-Poly1305(K, …, AD = "Siegel v2 entry destructible" ‖ vaultID ‖ entryID ‖ s ‖ M)
// Der ephemere Schlüssel steht wie sonst im Feld "se" des Blobs (M enthält das SE-Bit: V ist ein SE-Schlüssel).

/// Zwei Chiffrate einer hybriden Kapselung (ML-KEM-1024 1568 B + X25519 32 B).
struct HybridCapsule: Equatable, Sendable {
    var ctM: [UInt8]
    var ctX: [UInt8]

    init(ctM: [UInt8], ctX: [UInt8]) {
        self.ctM = ctM
        self.ctX = ctX
    }

    init(_ e: RecoveryEncapsulation) {
        ctM = e.ctM
        ctX = e.ctX
    }

    var isWellFormed: Bool { ctM.count == RecoveryKEM.ctMBytes && ctX.count == RecoveryKEM.ctXBytes }
}

/// Hybride Kapselung plus damit verpackter 32-Byte-Schlüssel (nonce ‖ ct ‖ tag = 72 B).
struct HybridWrap: Equatable, Sendable {
    var capsule: HybridCapsule
    var wrapped: [UInt8]

    var isWellFormed: Bool { capsule.isWellFormed && wrapped.count == AEAD.wrappedBytes }
}

/// Faktor-Teile einer Versiegelung: genau die der Maske. Der Gerätefaktor (Bit 0) ist entweder die Mac-Art
/// (`seEphemeral`, ECDH mit dem Eintrags-SE-Schlüssel) oder – in einem unter Windows eingerichteten Tresor – die
/// Windows-Hello-Art (`hello`, v4.6), nie beide.
struct SealedFactors: Equatable, Sendable {
    /// Windows-Hello-Teil (v4.6, `windows/SPEC-WINDOWS.md` W4.1): Salz der eintragsspezifischen Herausforderung. Den
    /// Faktorwert gibt es nur über eine Windows-Hello-Signatur; auf dem Mac ist ein solches Siegel nicht zu öffnen
    /// (`factorUnavailable(.secureEnclave)`), der Notfallweg (Umschlag an die Gruppe) bleibt.
    struct Hello: Equatable, Sendable {
        static let saltBytes = 32
        var salt: [UInt8]
        var version: Int

        var isWellFormed: Bool { salt.count == Self.saltBytes && version == EntryFactorKeys.WindowsHelloKey.version }
    }

    /// Ephemerer öffentlicher P-256-Schlüssel (x963, 65 B) für die ECDH mit dem Eintrags-SE-Schlüssel.
    var seEphemeral: [UInt8]?
    var card: HybridCapsule?
    var fido: HybridCapsule?
    var hello: Hello? = nil

    var mask: FactorSet {
        var m: FactorSet = []
        if seEphemeral != nil || hello != nil { m.insert(.secureEnclave) }
        if card != nil { m.insert(.card) }
        if fido != nil { m.insert(.securityKey) }
        return m
    }

    var isWellFormed: Bool {
        if seEphemeral != nil, hello != nil { return false }
        if let e = seEphemeral, e.count != 65 || e.first != 0x04 { return false }
        if let h = hello, !h.isWellFormed { return false }
        if let c = card, !c.isWellFormed { return false }
        if let f = fido, !f.isWellFormed { return false }
        return true
    }
}

/// Mit K verschlüsselter Klartext samt den Faktor-Teilen, aus denen K entsteht.
struct SealedBlob: Equatable, Sendable {
    var factors: SealedFactors
    var nonce: [UInt8]
    var ciphertext: [UInt8]

    var isWellFormed: Bool {
        factors.isWellFormed && nonce.count == AEAD.nonceBytes && ciphertext.count >= AEAD.tagBytes
    }
}

/// Versiegelte Geheimteile eines Eintrags (§16.1).
struct SealedSecrets: Equatable, Sendable {
    var blob: SealedBlob
    /// K, gekapselt an die Notfall-Gruppe der Maske (mit dem Notfallcode lesbar).
    var recovery: HybridWrap
}

/// Notfall-Gruppe pro Faktormaske. Die Umschläge der Einträge gehen an `pk`; das Geheimnis dazu (ERS) liegt an das
/// Kit gekapselt (`kit`) und unter den Faktoren der Maske versiegelt (`anchor`). So bleibt jeder versiegelte Eintrag
/// mit dem Notfallcode lesbar, auch nach einem neuen Kit (dann wird nur `kit` neu gekapselt).
struct RecoveryGroup: Equatable, Sendable {
    var id: UUID
    var mask: FactorSet
    var pk: RecoveryPublicKeys
    var kit: HybridWrap
    var anchor: SealedBlob
}

/// Metadaten für den Offline-Sicherheitsbericht (§17), auch für versiegelte Einträge lesbar.
struct EntryMeta: Equatable, Sendable {
    /// reuseTag (16 B); nil = kein Passwort.
    var tag: [UInt8]?
    /// `PasswordStrength.Level.rawValue`; nil = kein Passwort.
    var strength: Int?
    /// Letzte Passwortänderung.
    var changed: Date?
}

/// Stabiler Eintrags-Grundschlüssel (32 B) im verschlüsselten Inhalt. Er überlebt jede DEK-Rotation, damit
/// versiegelte Einträge und Wiederverwendungs-Kennungen ohne Faktoren gültig bleiben (siehe KERN-NOTIZEN.md).
struct EntryBaseKey: Equatable, Sendable {
    let key: SecureBytes

    init(key: SecureBytes) throws {
        guard key.count == 32 else { throw SiegelError.crypto("entry.baseKey") }
        self.key = key
    }

    static func generate() throws -> EntryBaseKey { try EntryBaseKey(key: try SecureBytes.random(count: 32)) }

    static func == (a: EntryBaseKey, b: EntryBaseKey) -> Bool { a.key.constantTimeEquals(b.key) }
}

enum EntrySealing {
    static let dekInfo = Array("Siegel v2 entry dek".utf8)
    static let keyInfo = Array("Siegel v2 entry key".utf8)
    static let seInfo = Array("Siegel v2 entry se".utf8)
    static let cardLabel = Array("Siegel v2 entry card".utf8)
    static let fidoLabel = Array("Siegel v2 entry fido".utf8)
    static let entryAD = Array("Siegel v2 entry".utf8)
    static let recoveryLabel = Array("Siegel v2 entry recovery".utf8)
    static let groupSeedInfo = Array("Siegel v2 entry recovery ML-KEM-1024 seed".utf8)
    static let groupX25519Info = Array("Siegel v2 entry recovery X25519".utf8)
    static let kitLabel = Array("Siegel v2 entry recovery kit".utf8)
    static let anchorAD = Array("Siegel v2 entry anchor".utf8)
    static let reuseInfo = Array("Siegel v2 reuse tag".utf8)
    /// Schutz-Byte der Anker (Einträge haben 2…5).
    static let anchorProtection: UInt8 = 0
    /// Polsterung der Geheimteile (verbirgt kleine Längenunterschiede auch vor dem Inhaber des DEK).
    static let secretsBlock = 256
    static let reuseTagBytes = 16
    /// Masken, die als Eintrags-Schutz vorkommen (Schutz 2/3, 4, 5).
    static let validMasks: [FactorSet] = [[.secureEnclave], [.secureEnclave, .card], .all]
    /// Vernichtbare Variante (§23.1).
    static let destructionInfo = Array("Siegel v2 entry destruction".utf8)
    static let destructibleKeyInfo = Array("Siegel v2 entry key destructible".utf8)
    static let destructibleAD = Array("Siegel v2 entry destructible".utf8)

    /// Woher der SE-Teil eines Siegels kommt: Eintrags-SE-Schlüssel (§16.1) oder Vernichtungsschlüssel V (§23.1).
    enum SEPart {
        case entryKey
        case destruction(keyID: UUID, publicKey: [UInt8])

        var info: [UInt8] {
            switch self {
            case .entryKey: EntrySealing.seInfo
            case .destruction: EntrySealing.destructionInfo
            }
        }

        var keyInfo: [UInt8] {
            switch self {
            case .entryKey: EntrySealing.keyInfo
            case .destruction: EntrySealing.destructibleKeyInfo
            }
        }

        /// Faktoren, die für Einträge eingerichtet sein müssen (V ersetzt den Eintrags-SE-Schlüssel).
        func required(_ mask: FactorSet) -> FactorSet {
            switch self {
            case .entryKey: mask
            case .destruction: mask.subtracting(.secureEnclave)
            }
        }
    }

    /// Öffentliches Material zum Versiegeln (kein Faktor nötig).
    struct Keys {
        let vaultID: [UInt8]
        let base: SecureBytes
        let factors: EntryFactorKeys
    }

    static func idBytes(_ id: UUID) -> [UInt8] { VaultHeader.bytes(of: id) }

    static func ad(_ label: [UInt8], vaultID: [UInt8], id: [UInt8], s: UInt8, mask: FactorSet) -> [UInt8] {
        label + vaultID + id + [s, mask.rawValue]
    }

    /// Der Schutz verlangt eingerichtete Faktoren (§16): der erste fehlende in Ableitungsreihenfolge → `factorMissing`.
    static func requireEnrolled(_ mask: FactorSet, _ keys: EntryFactorKeys) throws {
        for kind in mask.kinds where !keys.enrolled.contains(kind) { throw SiegelError.factorMissing(kind) }
    }

    /// Siegel der Windows-Hello-Art (v4.6) sind auf dem Mac ein anderes Gerät: `factorUnavailable(.secureEnclave)`,
    /// ohne den Provider zu fragen (nur der Notfallweg öffnet sie hier).
    static func requireUsableHere(_ factors: SealedFactors) throws {
        if factors.hello != nil { throw SiegelError.factorUnavailable(.secureEnclave) }
    }

    // MARK: - Schlüssel

    static func base(_ ebk: SecureBytes, id: [UInt8]) throws -> SecureBytes {
        try ebk.withUnsafeBytes { try FactorKDF.hkdf($0, salt: id, info: dekInfo, count: 32) }
    }

    static func seSecret(_ ecdh: UnsafeRawBufferPointer, id: [UInt8], info: [UInt8] = seInfo) throws -> SecureBytes {
        guard ecdh.count == 32 else { throw SiegelError.crypto("entry.ecdh") }
        return try FactorKDF.hkdf(ecdh, salt: id, info: info, count: 32)
    }

    /// K = HKDF-SHA512(base ‖ [ss_se] ‖ [ss_card] ‖ [ss_fido], salt = id, info = "Siegel v2 entry key" ‖ s ‖ M, 32)
    /// (vernichtbar: info = "Siegel v2 entry key destructible" ‖ s ‖ M).
    static func entryKey(parts: [SecureBytes], id: [UInt8], s: UInt8, mask: FactorSet,
                         info: [UInt8] = keyInfo) throws -> SecureBytes {
        guard parts.count == 1 + mask.kinds.count, parts.allSatisfy({ $0.count == 32 }) else {
            throw SiegelError.crypto("entry.key")
        }
        let ikm = try SecureBytes(count: 32 * parts.count) { out in
            for (i, part) in parts.enumerated() {
                part.withUnsafeBytes { src in
                    if let sp = src.baseAddress, let d = out.baseAddress { (d + 32 * i).copyMemory(from: sp, byteCount: 32) }
                }
            }
        }
        return try ikm.withUnsafeBytes { try FactorKDF.hkdf($0, salt: id, info: info + [s, mask.rawValue], count: 32) }
    }

    // MARK: - Versiegeln (nur öffentliche Schlüssel)

    /// Versiegelt `plaintext` für Maske `mask` (Eintrag: s = Schutz, Anker: s = 0). Liefert Blob und K.
    static func seal(_ plaintext: SecureBytes, id: UUID, s: UInt8, mask: FactorSet, adLabel: [UInt8],
                     keys: Keys) throws -> (blob: SealedBlob, k: SecureBytes) {
        try seal(plaintext, id: id, s: s, mask: mask, adLabel: adLabel, keys: keys, se: .entryKey)
    }

    /// Vernichtbar versiegeln (§23.1): V statt Eintrags-SE-Schlüssel, eigene Labels. Nur Schutz 4/5 (Maske mit Karte).
    static func sealDestructible(_ plaintext: SecureBytes, id: UUID, s: UInt8, mask: FactorSet, vKeyID: UUID,
                                 vPublicKey: [UInt8], keys: Keys) throws -> SealedBlob {
        guard mask.contains(.secureEnclave), mask.contains(.card) else { throw SiegelError.notAllowedAtLevel }
        return try seal(plaintext, id: id, s: s, mask: mask, adLabel: destructibleAD, keys: keys,
                        se: .destruction(keyID: vKeyID, publicKey: vPublicKey)).blob
    }

    static func seal(_ plaintext: SecureBytes, id: UUID, s: UInt8, mask: FactorSet, adLabel: [UInt8],
                     keys: Keys, se part: SEPart) throws -> (blob: SealedBlob, k: SecureBytes) {
        try requireEnrolled(part.required(mask), keys.factors)
        let idb = idBytes(id)
        var parts: [SecureBytes] = [try base(keys.base, id: idb)]
        var factors = SealedFactors()
        if mask.contains(.secureEnclave) {
            let publicKey: [UInt8]
            switch part {
            case .entryKey:
                guard let se = keys.factors.secureEnclave else {
                    // Gerätefaktor eines Windows-Tresors (v4.6): Versiegeln braucht dort eine Windows-Hello-Signatur.
                    if keys.factors.windowsHello != nil { throw SiegelError.factorUnavailable(.secureEnclave) }
                    throw SiegelError.factorMissing(.secureEnclave)
                }
                publicKey = se.publicKey
            case let .destruction(_, vPub):
                // V der Windows-Hello-Art (v4.6) hat keinen öffentlichen Schlüssel.
                guard !vPub.isEmpty else { throw SiegelError.factorUnavailable(.secureEnclave) }
                publicKey = vPub
            }
            let pub: P256.KeyAgreement.PublicKey
            do {
                pub = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
            } catch {
                throw SiegelError.crypto("entry.sePublicKey")
            }
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let shared: SharedSecret
            do {
                shared = try ephemeral.sharedSecretFromKeyAgreement(with: pub)
            } catch {
                throw SiegelError.crypto("entry.ecdh")
            }
            parts.append(try shared.withUnsafeBytes { try seSecret($0, id: idb, info: part.info) })
            factors.seEphemeral = Array(ephemeral.publicKey.x963Representation)
        }
        if mask.contains(.card) {
            guard let card = keys.factors.card else { throw SiegelError.factorMissing(.card) }
            let enc = try RecoveryKEM.encapsulate(to: card.pk, label: cardLabel, context: idb)
            parts.append(enc.kek)
            factors.card = HybridCapsule(enc)
        }
        if mask.contains(.securityKey) {
            guard let key = keys.factors.securityKey else { throw SiegelError.factorMissing(.securityKey) }
            let enc = try RecoveryKEM.encapsulate(to: key.pk, label: fidoLabel, context: idb)
            parts.append(enc.kek)
            factors.fido = HybridCapsule(enc)
        }
        let k = try entryKey(parts: parts, id: idb, s: s, mask: mask, info: part.keyInfo)
        let sealed = try AEAD.seal(key: k, plaintext: plaintext,
                                   ad: ad(adLabel, vaultID: keys.vaultID, id: idb, s: s, mask: mask))
        return (SealedBlob(factors: factors, nonce: sealed.nonce, ciphertext: sealed.ciphertext), k)
    }

    // MARK: - Aufdecken (Faktoren über den Provider)

    /// Holt über den Provider genau die Faktoren der Maske (Reihenfolge SE, Karte, Schlüssel) und rechnet jeden sofort
    /// zu ss_… um; die Rohwerte werden danach freigegeben (`FactorSecret` → `sodium_free`). Falsche Karte → `wrongCard`
    /// (Kennung bzw. öffentliche Schlüssel), falscher Sicherheitsschlüssel → `wrongPassword`.
    static func release(_ factors: SealedFactors, id: UUID, mask: FactorSet, keys: EntryFactorKeys, vaultID: [UInt8],
                        provider: EntryFactorProvider, se part: SEPart = .entryKey) async throws -> [SecureBytes] {
        try requireEnrolled(part.required(mask), keys)
        guard factors.mask == mask else { throw SiegelError.corruptFile("entry.sealed") }
        let idb = idBytes(id)
        var out: [SecureBytes] = []
        if mask.contains(.secureEnclave) {
            try requireUsableHere(factors)
            guard let eph = factors.seEphemeral else { throw SiegelError.corruptFile("entry.sealed") }
            let keyID: UUID
            switch part {
            case .entryKey:
                guard let se = keys.secureEnclave else { throw SiegelError.corruptFile("entry.sealed") }
                keyID = se.keyID
            case let .destruction(id, _):
                keyID = id
            }
            let raw = try await call(.secureEnclave) {
                try await provider.secureEnclaveSharedSecret(keyID: keyID, ephemeralPublicKey: Data(eph))
            }
            out.append(try raw.withUnsafeBytes { try seSecret($0, id: idb, info: part.info) })
        }
        if mask.contains(.card) {
            guard let card = keys.card, let capsule = factors.card else { throw SiegelError.corruptFile("entry.sealed") }
            let q = try await call(.card) { try await provider.cardSecret() }
            guard constantTimeEqual(CardCode.tagBytes(q: q, vaultID: vaultID), card.tag),
                  let sk = RecoveryKEM.privateKeys(ikm: q.storage, vaultID: vaultID,
                                                   seedInfo: EntryKeyDerivation.cardSeedInfo,
                                                   x25519Info: EntryKeyDerivation.cardX25519Info,
                                                   expected: card.pk) else {
                throw SiegelError.wrongCard
            }
            out.append(try decapsulate(sk, capsule, label: cardLabel, id: idb))
        }
        if mask.contains(.securityKey) {
            guard let key = keys.securityKey, let capsule = factors.fido else {
                throw SiegelError.corruptFile("entry.sealed")
            }
            let y2 = try await call(.securityKey) {
                try await provider.securityKeyOutput(credentialID: Data(key.credentialID), salt: Data(key.entrySalt))
            }
            guard let sk = RecoveryKEM.privateKeys(ikm: y2.storage, vaultID: vaultID,
                                                   seedInfo: EntryKeyDerivation.fidoSeedInfo,
                                                   x25519Info: EntryKeyDerivation.fidoX25519Info,
                                                   expected: key.pk) else {
                throw SiegelError.wrongPassword
            }
            out.append(try decapsulate(sk, capsule, label: fidoLabel, id: idb))
        }
        return out
    }

    /// Provider-Aufruf: `SiegelError` bleibt; Abbruch der Task → `factorCancelled`; alles andere →
    /// `factorUnavailable(kind)` (fremde Fehlertexte gelangen nie nach aussen).
    private static func call(_ kind: FactorKind,
                             _ body: () async throws -> FactorSecret) async throws -> FactorSecret {
        do {
            return try await body()
        } catch let e as SiegelError {
            throw e
        } catch is CancellationError {
            throw SiegelError.factorCancelled
        } catch {
            throw SiegelError.factorUnavailable(kind)
        }
    }

    private static func decapsulate(_ sk: HybridPrivateKeys, _ capsule: HybridCapsule, label: [UInt8],
                                    id: [UInt8]) throws -> SecureBytes {
        do {
            return try RecoveryKEM.decapsulate(sk, ctM: capsule.ctM, ctX: capsule.ctX, label: label, context: id)
        } catch {
            throw SiegelError.corruptFile("entry.sealed")
        }
    }

    /// Öffnet einen Blob mit den freigegebenen ss-Werten. nil = ein Faktor stimmt nicht (der Blob selbst ist durch
    /// den DEK des Inhalts authentisiert).
    static func open(_ blob: SealedBlob, id: UUID, s: UInt8, mask: FactorSet, adLabel: [UInt8], base ebk: SecureBytes,
                     vaultID: [UInt8], released: [SecureBytes], keyInfo info: [UInt8] = keyInfo) throws -> SecureBytes? {
        let idb = idBytes(id)
        let k = try entryKey(parts: [try base(ebk, id: idb)] + released, id: idb, s: s, mask: mask, info: info)
        return AEAD.open(key: k, nonce: blob.nonce, ciphertext: blob.ciphertext,
                         ad: ad(adLabel, vaultID: vaultID, id: idb, s: s, mask: mask))
    }

    // MARK: - Notfall-Umschläge und Gruppen

    /// K an die Notfall-Gruppe kapseln.
    static func recoveryWrap(k: SecureBytes, id: UUID, s: UInt8, mask: FactorSet, group pk: RecoveryPublicKeys,
                             vaultID: [UInt8]) throws -> HybridWrap {
        let idb = idBytes(id)
        let enc = try RecoveryKEM.encapsulate(to: pk, label: recoveryLabel, context: idb)
        let wrapped = try AEAD.wrap(kek: enc.kek, secret: k,
                                    ad: ad(recoveryLabel, vaultID: vaultID, id: idb, s: s, mask: mask))
        return HybridWrap(capsule: HybridCapsule(enc), wrapped: wrapped)
    }

    /// K aus dem Notfall-Umschlag (mit den privaten Schlüsseln der Gruppe). Jedes Scheitern → `corruptFile`.
    static func openRecoveryWrap(_ w: HybridWrap, id: UUID, s: UInt8, mask: FactorSet, group: HybridPrivateKeys,
                                 vaultID: [UInt8]) throws -> SecureBytes {
        let idb = idBytes(id)
        guard let kek = try? RecoveryKEM.decapsulate(group, ctM: w.capsule.ctM, ctX: w.capsule.ctX,
                                                     label: recoveryLabel, context: idb),
              let k = AEAD.unwrap(kek: kek, blob: w.wrapped,
                                  ad: ad(recoveryLabel, vaultID: vaultID, id: idb, s: s, mask: mask)) else {
            throw SiegelError.corruptFile("entry.recovery")
        }
        return k
    }

    static func groupPublicKeys(ers: SecureBytes, vaultID: [UInt8]) throws -> RecoveryPublicKeys {
        try RecoveryKEM.derivePublicKeys(ikm: ers, vaultID: vaultID, seedInfo: groupSeedInfo, x25519Info: groupX25519Info)
    }

    static func groupPrivateKeys(ers: SecureBytes, vaultID: [UInt8], expected: RecoveryPublicKeys) -> HybridPrivateKeys? {
        RecoveryKEM.privateKeys(ikm: ers, vaultID: vaultID, seedInfo: groupSeedInfo, x25519Info: groupX25519Info,
                                expected: expected)
    }

    /// Neue Gruppe für eine Maske: ERS ziehen, Schlüsselpaar ableiten, ERS an das Kit kapseln und als Anker versiegeln.
    static func makeGroup(mask: FactorSet, keys: Keys, kit: RecoveryPublicKeys) throws -> RecoveryGroup {
        guard validMasks.contains(mask) else { throw SiegelError.crypto("entry.mask") }
        let id = UUID()
        let ers = try SecureBytes.random(count: 32)
        let pk = try groupPublicKeys(ers: ers, vaultID: keys.vaultID)
        let kitWrap = try wrapToKit(ers: ers, groupID: id, mask: mask, kit: kit, vaultID: keys.vaultID)
        let anchor = try seal(ers, id: id, s: anchorProtection, mask: mask, adLabel: anchorAD, keys: keys).blob
        return RecoveryGroup(id: id, mask: mask, pk: pk, kit: kitWrap, anchor: anchor)
    }

    /// ERS an das Kit (pkM/pkX des Kopfes) kapseln.
    static func wrapToKit(ers: SecureBytes, groupID: UUID, mask: FactorSet, kit: RecoveryPublicKeys,
                          vaultID: [UInt8]) throws -> HybridWrap {
        let gid = idBytes(groupID)
        let enc = try RecoveryKEM.encapsulate(to: kit, label: kitLabel, context: gid)
        let wrapped = try AEAD.wrap(kek: enc.kek, secret: ers,
                                    ad: ad(kitLabel, vaultID: vaultID, id: gid, s: anchorProtection, mask: mask))
        return HybridWrap(capsule: HybridCapsule(enc), wrapped: wrapped)
    }

    /// Private Kit-Schlüssel aus R (nur wenn R genau das Kit des Kopfes ergibt).
    static func kitPrivateKeys(r: SecureBytes, header: VaultHeader) -> HybridPrivateKeys? {
        RecoveryKEM.privateKeys(ikm: r, vaultID: header.vaultID, seedInfo: RecoveryKEM.seedInfo,
                                x25519Info: RecoveryKEM.x25519Info, expected: header.pk)
    }

    /// Notfall: private Schlüssel einer Gruppe über das Kit. Jedes Scheitern → `corruptFile`.
    static func openGroup(_ group: RecoveryGroup, kit: HybridPrivateKeys, vaultID: [UInt8]) throws -> HybridPrivateKeys {
        let gid = idBytes(group.id)
        guard let kek = try? RecoveryKEM.decapsulate(kit, ctM: group.kit.capsule.ctM, ctX: group.kit.capsule.ctX,
                                                     label: kitLabel, context: gid),
              let ers = AEAD.unwrap(kek: kek, blob: group.kit.wrapped,
                                    ad: ad(kitLabel, vaultID: vaultID, id: gid, s: anchorProtection, mask: group.mask)),
              let keys = groupPrivateKeys(ers: ers, vaultID: vaultID, expected: group.pk) else {
            throw SiegelError.corruptFile("entry.recovery")
        }
        return keys
    }

    /// Anker freigeben: ERS einer Gruppe über die Faktoren ihrer Maske (eine Freigabe pro Gruppe).
    static func releaseAnchor(_ group: RecoveryGroup, keys: Keys, provider: EntryFactorProvider) async throws -> SecureBytes {
        let released = try await release(group.anchor.factors, id: group.id, mask: group.mask, keys: keys.factors,
                                         vaultID: keys.vaultID, provider: provider)
        guard let ers = try open(group.anchor, id: group.id, s: anchorProtection, mask: group.mask, adLabel: anchorAD,
                                 base: keys.base, vaultID: keys.vaultID, released: released) else {
            throw SiegelError.wrongPassword
        }
        guard ers.count == 32, groupPrivateKeys(ers: ers, vaultID: keys.vaultID, expected: group.pk) != nil else {
            throw SiegelError.corruptFile("entry.anchor")
        }
        return ers
    }

    // MARK: - Geheimteile als JSON (gepolstert, nur in SecureBytes)

    private struct HistoryDTO: Codable {
        var password: String
        var changed: Date
    }

    private struct SecretsDTO: Codable {
        var password: String
        var notes: String
        var totp: String
        var history: [HistoryDTO]
    }

    static func encodeSecrets(_ s: EntrySecrets) throws -> SecureBytes {
        _ = Sodium.ready
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        var json: Data
        do {
            json = try encoder.encode(SecretsDTO(password: s.password, notes: s.notes, totp: s.totp,
                                                 history: s.history.map { HistoryDTO(password: $0.password,
                                                                                     changed: $0.changed) }))
        } catch {
            throw SiegelError.io("entry.encode")
        }
        defer { json.withUnsafeMutableBytes { if let p = $0.baseAddress { sodium_memzero(p, $0.count) } } }
        let unpadded = json.count
        let padded = (unpadded / secretsBlock + 1) * secretsBlock
        return try SecureBytes(count: padded) { out in
            try json.withUnsafeBytes { src in
                guard let o = out.u8, let sp = src.baseAddress else { throw SiegelError.io("entry.encode") }
                UnsafeMutableRawPointer(o).copyMemory(from: sp, byteCount: unpadded)
                var result = 0
                guard sodium_pad(&result, o, unpadded, secretsBlock, padded) == 0, result == padded else {
                    throw SiegelError.io("entry.pad")
                }
            }
        }
    }

    static func decodeSecrets(_ padded: SecureBytes) throws -> EntrySecrets {
        _ = Sodium.ready
        return try padded.withUnsafeBytes { buf in
            guard let p = buf.u8, buf.count > 0, buf.count % secretsBlock == 0 else {
                throw SiegelError.corruptFile("entry.padding")
            }
            var unpadded = 0
            guard sodium_unpad(&unpadded, p, buf.count, secretsBlock) == 0,
                  let base = UnsafeRawBufferPointer(rebasing: buf[0..<unpadded]).baseAddress else {
                throw SiegelError.corruptFile("entry.padding")
            }
            let data = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: base), count: unpadded, deallocator: .none)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            let dto: SecretsDTO
            do {
                dto = try decoder.decode(SecretsDTO.self, from: data)
            } catch {
                throw SiegelError.corruptFile("entry.json")
            }
            return EntrySecrets(password: dto.password, notes: dto.notes, totp: dto.totp,
                                history: dto.history.map { PasswordHistoryItem(password: $0.password, changed: $0.changed) })
        }
    }

    // MARK: - Wiederverwendungs-Kennung (§17)

    /// HKDF-SHA512(EBK, info = "Siegel v2 reuse tag", 32).
    static func reuseKey(_ ebk: SecureBytes) throws -> SecureBytes {
        let ikm = ebk.withUnsafeBytes { SymmetricKey(data: $0) }
        let k = HKDF<SHA512>.deriveKey(inputKeyMaterial: ikm, info: reuseInfo, outputByteCount: 32)
        return try k.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    /// reuseTag = crypto_generichash(key, OpaqueString(password))[0..<16]: dieselbe Abbildung wie beim Master-Passwort
    /// (§1.1: Zs → U+0020, dann NFC; v4.4, vorher nur NFC), sonst fände der Vergleich mit dem Master-Passwort Einträge
    /// mit z. B. U+00A0 nicht. nil bei leerem Passwort.
    static func reuseTag(key: SecureBytes, password: String) -> [UInt8]? {
        guard !password.isEmpty else { return nil }
        var normalized = PasswordNormalizer.normalize(password)
        return normalized.withUTF8 { reuseTag(key: key, bytes: UnsafeRawBufferPointer($0)) }
    }

    /// Tag nach der Formel bis v4.3 (nur NFC). nil, wenn er dem heutigen gleicht (kein Zs-Zeichen ausser U+0020)
    /// oder das Passwort leer ist – dann gibt es keinen alten Tag, der abweichen könnte.
    static func legacyReuseTag(key: SecureBytes, password: String) -> [UInt8]? {
        guard !password.isEmpty else { return nil }
        var nfc = password.precomposedStringWithCanonicalMapping
        guard Array(nfc.utf8) != Array(PasswordNormalizer.normalize(password).utf8) else { return nil }
        return nfc.withUTF8 { reuseTag(key: key, bytes: UnsafeRawBufferPointer($0)) }
    }

    /// reuseTag schon normalisierter Bytes (Master-Passwort, §1.1).
    static func reuseTag(key: SecureBytes, bytes: UnsafeRawBufferPointer) -> [UInt8]? {
        guard bytes.count > 0, let t = try? MasterTag.tag(key: key, password: bytes) else { return nil }
        return t.withUnsafeBytes { Array($0.prefix(reuseTagBytes)) }
    }

    /// Metadaten zu einem (Klartext-)Passwort. `previous` bleibt gültig, solange sich das Passwort nicht geändert hat;
    /// ohne frühere Metadaten gilt `fallbackChanged` als letzte Änderung.
    static func meta(password: String, previous: EntryMeta?, reuseKey: SecureBytes, fallbackChanged: Date,
                     now: Date) -> EntryMeta {
        let tag = reuseTag(key: reuseKey, password: password)
        if let previous, previous.tag == tag, tag == nil || previous.strength != nil {
            return previous
        }
        // Tag noch nach der Formel bis v4.3 (v4.4): dasselbe Passwort, nur neu gerechnet – keine Passwortänderung.
        var previous = previous
        if var p = previous, let old = p.tag, let legacy = legacyReuseTag(key: reuseKey, password: password),
           constantTimeEqual(old, legacy) {
            p.tag = tag
            if p.strength != nil { return p }
            previous = p
        }
        let strength = tag == nil ? nil : PasswordStrength.estimate(password).level.rawValue
        let changed: Date
        if let previous, previous.tag != tag {
            changed = now
        } else {
            changed = previous?.changed ?? fallbackChanged
        }
        return EntryMeta(tag: tag, strength: strength, changed: Clock.canonical(changed))
    }
}
