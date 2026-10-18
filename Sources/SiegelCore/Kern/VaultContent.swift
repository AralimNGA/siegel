import Clibsodium
import CryptoKit
import Foundation

/// Öffentliche Teile der für Einträge eingerichteten Faktoren (SPEC §16, §16.1), im verschlüsselten Inhalt.
/// Schreiben (Versiegeln) geht damit ohne Faktor; nur das Aufdecken braucht ihn.
struct EntryFactorKeys: Sendable, Equatable {
    /// Eintrags-SE-Schlüssel (eigener Schlüssel, nicht der Entsperr-Schlüssel): P-256, x963, 65 Byte.
    struct SecureEnclaveKey: Sendable, Equatable {
        var keyID: UUID
        var publicKey: [UInt8]
    }

    /// Karte: Kennung (wie im Kopf) und Hybrid-pk aus q ("Siegel v2 card entry …").
    struct CardKey: Sendable, Equatable {
        var tag: [UInt8]
        var pk: RecoveryPublicKeys
    }

    /// Sicherheitsschlüssel: Credential, Entsperr-Salz (+ Prüfwert seiner Ausgabe), Eintrags-Salz und Hybrid-pk
    /// aus dessen Ausgabe y2 ("Siegel v2 fido entry …").
    struct SecurityKey: Sendable, Equatable {
        var credentialID: [UInt8]
        var salt: [UInt8]
        var check: [UInt8]
        var entrySalt: [UInt8]
        var pk: RecoveryPublicKeys
    }

    /// Eintrags-Gerätefaktor eines unter Windows eingerichteten Tresors (Windows Hello, v4.6, SPEC §12 und
    /// `windows/SPEC-WINDOWS.md` W4.1): nur Kennung und Version, kein öffentlicher Schlüssel (Versiegeln braucht dort
    /// eine Signatur). Auf dem Mac ein **anderes Gerät**: Siegel dieser Art lassen sich hier weder aufdecken noch neu
    /// schreiben (`factorUnavailable(.secureEnclave)`), bleiben aber beim Speichern unverändert erhalten. Nie zusammen
    /// mit `secureEnclave`.
    struct WindowsHelloKey: Sendable, Equatable {
        static let version = 1
        var keyID: UUID
        var version: Int
    }

    var secureEnclave: SecureEnclaveKey?
    var card: CardKey?
    var securityKey: SecurityKey?
    var windowsHello: WindowsHelloKey? = nil

    static let none = EntryFactorKeys(secureEnclave: nil, card: nil, securityKey: nil)

    /// Der Gerätefaktor (Maskenbit 0) zählt in beiden Arten (Mac: Secure Enclave, Windows: Windows Hello).
    var enrolled: FactorSet {
        var s: FactorSet = []
        if secureEnclave != nil || windowsHello != nil { s.insert(.secureEnclave) }
        if card != nil { s.insert(.card) }
        if securityKey != nil { s.insert(.securityKey) }
        return s
    }

    /// Kennung des Eintrags-Gerätefaktors (beide Arten), für die paarweise Verschiedenheit (§23).
    var deviceKeyID: UUID? { secureEnclave?.keyID ?? windowsHello?.keyID }

    /// Längenprüfung (beim Lesen `corruptFile("payload.factors")`).
    func validate() throws {
        if secureEnclave != nil, windowsHello != nil { throw SiegelError.corruptFile("payload.factors") }
        if let h = windowsHello, h.version != WindowsHelloKey.version { throw SiegelError.corruptFile("payload.factors") }
        if let se = secureEnclave, se.publicKey.count != 65 || se.publicKey.first != 0x04 {
            throw SiegelError.corruptFile("payload.factors")
        }
        if let c = card, c.tag.count != VaultHeader.cardTagBytes || !Self.pkValid(c.pk) {
            throw SiegelError.corruptFile("payload.factors")
        }
        if let k = securityKey {
            guard k.credentialID.count >= VaultHeader.minFidoCredential,
                  k.credentialID.count <= VaultHeader.maxFidoCredential,
                  k.salt.count == VaultHeader.fidoSaltBytes, k.entrySalt.count == VaultHeader.fidoSaltBytes,
                  k.check.count == FactorKDF.fidoCheckBytes, Self.pkValid(k.pk) else {
                throw SiegelError.corruptFile("payload.factors")
            }
        }
    }

    private static func pkValid(_ pk: RecoveryPublicKeys) -> Bool {
        pk.pkM.count == RecoveryPublicKeys.pkMBytes && pk.pkX.count == RecoveryPublicKeys.pkXBytes
    }
}

/// Klartext-Inhalt (SPEC §3, v4), nur im Speicher:
/// `{ "v": 2, "savedAt": …, "recoveryConfirmedAt": null, "level": 1, "factors": { … }, "entries": [ … ] }`
/// Inhalte mit `"v": 1` (Format v1) werden weiter gelesen: Stufe 1, keine Faktoren, Einträge ohne TOTP/Schutz.
struct VaultContent: Sendable, Equatable {
    static let version = 2
    static let historyMax = 10
    static let historyHardMax = 30
    static let historyProtectedAge: TimeInterval = 30 * 86_400
    static let deletedRetention: TimeInterval = 30 * 86_400

    // Feldgrenzen in UTF-8-Byte
    static let maxTitle = 2 << 10
    static let maxUsername = 2 << 10
    static let maxURL = 2 << 10
    static let maxPassword = 4 << 10
    static let maxNotes = 256 << 10
    static let maxTOTP = 4 << 10

    var savedAt: Date
    var recoveryConfirmedAt: Date?
    /// Tresor-Stufe (Regeln der Oberfläche; die Faktoren zum Öffnen stehen im Kopf und müssen dazu passen).
    var level: SecurityLevel
    /// Für Einträge eingerichtete Faktoren (öffentliche Teile).
    var entryFactors: EntryFactorKeys
    var entries: [VaultEntry]
    /// Eintrags-Grundschlüssel (§16.1, §17); stabil über DEK-Rotationen. nil nur in älteren Inhalten.
    var entryKey: EntryBaseKey?
    /// Versiegelte Geheimteile pro Eintrag (Schutz ≥ 2); im JSON beim Eintrag (`sealed`).
    var sealed: [UUID: SealedSecrets] = [:]
    /// Metadaten für den Sicherheitsbericht (§17); im JSON beim Eintrag (`meta`).
    var meta: [UUID: EntryMeta] = [:]
    /// Notfall-Gruppen (eine pro Faktormaske versiegelter Einträge).
    var recoveryGroups: [RecoveryGroup] = []
    /// Vernichtbare Einträge (§23.1): wie `sealed`, aber an den Vernichtungsschlüssel V versiegelt und **ohne**
    /// Notfall-Umschlag. Im JSON beim Eintrag (`"sealed": {"blob": …, "recovery": null}`).
    var destructible: [UUID: SealedBlob] = [:]
    /// Selbstvernichtung (§23): Einstellungen, öffentlicher Teil von V, Vernichtungs-Passwort (öffentlich). nil = aus.
    var destruction: DestructionConfig?

    init(savedAt: Date, recoveryConfirmedAt: Date?, level: SecurityLevel = .standard,
         entryFactors: EntryFactorKeys = .none, entries: [VaultEntry]) {
        self.savedAt = savedAt
        self.recoveryConfirmedAt = recoveryConfirmedAt
        self.level = level
        self.entryFactors = entryFactors
        self.entries = entries
    }

    static func empty(now: Date) -> VaultContent {
        VaultContent(savedAt: now, recoveryConfirmedAt: nil, entries: [])
    }

    /// Nach einer Wiederherstellung über den Notfallcode (SPEC §16.1): Stufe 1, keine Faktoren mehr eingerichtet,
    /// alle Einträge Schutz 1. Vorher muss alles entsiegelt sein (`unsealAll(r:header:)`), sonst
    /// `crypto("recovery.sealed")` – nie still Geheimteile verwerfen.
    mutating func resetAfterRecovery() throws {
        guard sealed.isEmpty, !entries.contains(where: \.secretsSealed) else {
            throw SiegelError.crypto("recovery.sealed")
        }
        guard destructible.isEmpty else { throw SiegelError.crypto("recovery.sealed") }
        level = .standard
        entryFactors = .none
        recoveryGroups = []
        destruction = nil
        for i in entries.indices { entries[i].protection = .normal }
    }

    /// Prüft die Feldgrenzen eines Eintrags (inkl. Verlauf).
    static func validate(_ e: VaultEntry) throws {
        guard e.title.utf8.count <= maxTitle else { throw SiegelError.io("entry.titleTooLong") }
        guard e.username.utf8.count <= maxUsername else { throw SiegelError.io("entry.usernameTooLong") }
        guard e.url.utf8.count <= maxURL else { throw SiegelError.io("entry.urlTooLong") }
        guard e.password.utf8.count <= maxPassword else { throw SiegelError.io("entry.passwordTooLong") }
        guard e.notes.utf8.count <= maxNotes else { throw SiegelError.io("entry.notesTooLong") }
        guard e.totp.utf8.count <= maxTOTP else { throw SiegelError.io("entry.totpTooLong") }
        for h in e.history where h.password.utf8.count > maxPassword {
            throw SiegelError.io("entry.passwordTooLong")
        }
    }

    /// Verlauf: höchstens 10, Einträge jünger als 30 Tage werden nie verdrängt (harte Obergrenze 30).
    static func applyHistoryRule(_ history: [PasswordHistoryItem], now: Date) -> [PasswordHistoryItem] {
        let sorted = history.sorted { $0.changed > $1.changed }
        let young = sorted.filter { now.timeIntervalSince($0.changed) < historyProtectedAge }.count
        let keep = min(historyHardMax, max(historyMax, young))
        return Array(sorted.prefix(keep))
    }

    /// Vor jedem Speichern: abgelaufene gelöschte Einträge endgültig entfernen, Zeitpunkte kanonisieren.
    mutating func prepareForSave(now: Date) {
        entries.removeAll { e in
            guard let d = e.deletedAt else { return false }
            return now.timeIntervalSince(d) >= VaultContent.deletedRetention
        }
        savedAt = now
        recoveryConfirmedAt = recoveryConfirmedAt.map(Clock.canonical)
        for i in entries.indices {
            entries[i].created = Clock.canonical(entries[i].created)
            entries[i].modified = Clock.canonical(entries[i].modified)
            entries[i].deletedAt = entries[i].deletedAt.map(Clock.canonical)
            for j in entries[i].history.indices {
                entries[i].history[j].changed = Clock.canonical(entries[i].history[j].changed)
            }
        }
    }
}

// MARK: - JSON (sortedKeys, secondsSince1970, null explizit)

private struct HistoryDTO: Codable {
    var password: String
    var changed: Date
}

private struct EntryDTO: Codable {
    var id: UUID
    var title: String
    var username: String
    var password: String
    var url: String
    var notes: String
    var created: Date
    var modified: Date
    var deletedAt: Date?
    var history: [HistoryDTO]
    var totp: String
    var protection: EntryProtection
    var meta: MetaDTO?
    var sealed: SealedDTO?

    enum CodingKeys: String, CodingKey {
        case id, title, username, password, url, notes, created, modified, deletedAt, history, totp, protection, meta, sealed
    }

    init(_ e: VaultEntry, meta: EntryMeta?, sealed: SealedSecrets?, destructible: SealedBlob? = nil) {
        id = e.id
        title = e.title
        username = e.username
        password = e.password
        url = e.url
        notes = e.notes
        created = e.created
        modified = e.modified
        deletedAt = e.deletedAt
        history = e.history.map { HistoryDTO(password: $0.password, changed: $0.changed) }
        totp = e.totp
        protection = e.protection
        self.meta = meta.map(MetaDTO.init)
        if let sealed {
            self.sealed = SealedDTO(sealed)
        } else {
            self.sealed = destructible.map(SealedDTO.init(destructible:))
        }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        title = try c.decode(String.self, forKey: .title)
        username = try c.decode(String.self, forKey: .username)
        password = try c.decode(String.self, forKey: .password)
        url = try c.decode(String.self, forKey: .url)
        notes = try c.decode(String.self, forKey: .notes)
        created = try c.decode(Date.self, forKey: .created)
        modified = try c.decode(Date.self, forKey: .modified)
        deletedAt = try c.decodeIfPresent(Date.self, forKey: .deletedAt)
        history = try c.decode([HistoryDTO].self, forKey: .history)
        // v1-Inhalte kennen TOTP und Schutz nicht.
        totp = try c.decodeIfPresent(String.self, forKey: .totp) ?? ""
        protection = try c.decodeIfPresent(EntryProtection.self, forKey: .protection) ?? .normal
        // Stufe A und v1 kennen meta/sealed nicht.
        meta = try c.decodeIfPresent(MetaDTO.self, forKey: .meta)
        sealed = try c.decodeIfPresent(SealedDTO.self, forKey: .sealed)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(title, forKey: .title)
        try c.encode(username, forKey: .username)
        try c.encode(password, forKey: .password)
        try c.encode(url, forKey: .url)
        try c.encode(notes, forKey: .notes)
        try c.encode(created, forKey: .created)
        try c.encode(modified, forKey: .modified)
        if let d = deletedAt { try c.encode(d, forKey: .deletedAt) } else { try c.encodeNil(forKey: .deletedAt) }
        try c.encode(history, forKey: .history)
        if !legacyV1(encoder) {
            try c.encode(totp, forKey: .totp)
            try c.encode(protection, forKey: .protection)
            if let m = meta { try c.encode(m, forKey: .meta) } else { try c.encodeNil(forKey: .meta) }
            if let x = sealed { try c.encode(x, forKey: .sealed) } else { try c.encodeNil(forKey: .sealed) }
        }
    }

    /// Versiegelte Einträge: `secretsSealed = true` (nur der Kern setzt das).
    var entry: VaultEntry {
        var e = VaultEntry(title: title, username: username, password: password, url: url, notes: notes,
                           totp: totp, protection: protection)
        e.id = id
        e.created = created
        e.modified = modified
        e.deletedAt = deletedAt
        e.history = history.map { PasswordHistoryItem(password: $0.password, changed: $0.changed) }
        e.secretsSealed = sealed != nil
        return e
    }
}

/// `"meta": {"changed": …|null, "strength": …|null, "tag": b64|null}` (§17).
private struct MetaDTO: Codable {
    var changed: Date?
    var strength: Int?
    var tag: Data?

    enum CodingKeys: String, CodingKey { case changed, strength, tag }

    init(_ m: EntryMeta) {
        changed = m.changed
        strength = m.strength
        tag = m.tag.map { Data($0) }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        changed = try c.decodeIfPresent(Date.self, forKey: .changed)
        strength = try c.decodeIfPresent(Int.self, forKey: .strength)
        tag = try c.decodeIfPresent(Data.self, forKey: .tag)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        if let v = changed { try c.encode(v, forKey: .changed) } else { try c.encodeNil(forKey: .changed) }
        if let v = strength { try c.encode(v, forKey: .strength) } else { try c.encodeNil(forKey: .strength) }
        if let v = tag { try c.encode(v, forKey: .tag) } else { try c.encodeNil(forKey: .tag) }
    }

    var value: EntryMeta { EntryMeta(tag: tag.map { Array($0) }, strength: strength, changed: changed) }
}

private struct CapsuleDTO: Codable {
    var ctM: Data
    var ctX: Data
    init(_ c: HybridCapsule) {
        ctM = Data(c.ctM)
        ctX = Data(c.ctX)
    }
    var value: HybridCapsule { HybridCapsule(ctM: Array(ctM), ctX: Array(ctX)) }
}

/// Hybride Kapselung + verpackter Schlüssel: `{"ctM", "ctX", "key"}`.
private struct WrapDTO: Codable {
    var ctM: Data
    var ctX: Data
    var key: Data
    init(_ w: HybridWrap) {
        ctM = Data(w.capsule.ctM)
        ctX = Data(w.capsule.ctX)
        key = Data(w.wrapped)
    }
    var value: HybridWrap { HybridWrap(capsule: HybridCapsule(ctM: Array(ctM), ctX: Array(ctX)), wrapped: Array(key)) }
}

/// Windows-Hello-Teil eines Siegels (v4.6): `{"salt": b64 (32 B), "version": 1}`.
private struct HelloDTO: Codable {
    var salt: Data
    var version: Int
}

/// `{"card": …|null, "ct", "fido": …|null, "nonce", "se": b64|null}` (null explizit). Siegel der Windows-Hello-Art
/// (v4.6) tragen zusätzlich `"hello": {…}` (und `"se": null`); das Feld steht nur dann im JSON, damit Mac-Inhalte
/// bytegleich bleiben.
private struct BlobDTO: Codable {
    var nonce: Data
    var ct: Data
    var se: Data?
    var card: CapsuleDTO?
    var fido: CapsuleDTO?
    var hello: HelloDTO?

    enum CodingKeys: String, CodingKey { case nonce, ct, se, card, fido, hello }

    init(_ b: SealedBlob) {
        nonce = Data(b.nonce)
        ct = Data(b.ciphertext)
        se = b.factors.seEphemeral.map { Data($0) }
        card = b.factors.card.map(CapsuleDTO.init)
        fido = b.factors.fido.map(CapsuleDTO.init)
        hello = b.factors.hello.map { HelloDTO(salt: Data($0.salt), version: $0.version) }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        nonce = try c.decode(Data.self, forKey: .nonce)
        ct = try c.decode(Data.self, forKey: .ct)
        se = try c.decodeIfPresent(Data.self, forKey: .se)
        card = try c.decodeIfPresent(CapsuleDTO.self, forKey: .card)
        fido = try c.decodeIfPresent(CapsuleDTO.self, forKey: .fido)
        hello = try c.decodeIfPresent(HelloDTO.self, forKey: .hello)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(nonce, forKey: .nonce)
        try c.encode(ct, forKey: .ct)
        if let v = se { try c.encode(v, forKey: .se) } else { try c.encodeNil(forKey: .se) }
        if let v = card { try c.encode(v, forKey: .card) } else { try c.encodeNil(forKey: .card) }
        if let v = fido { try c.encode(v, forKey: .fido) } else { try c.encodeNil(forKey: .fido) }
        try c.encodeIfPresent(hello, forKey: .hello)
    }

    var value: SealedBlob {
        SealedBlob(factors: SealedFactors(seEphemeral: se.map { Array($0) }, card: card?.value, fido: fido?.value,
                                          hello: hello.map { SealedFactors.Hello(salt: Array($0.salt), version: $0.version) }),
                   nonce: Array(nonce), ciphertext: Array(ct))
    }
}

/// `"sealed": {"blob": …, "recovery": …}`; vernichtbare Einträge (§23.1) haben `"recovery": null`.
private struct SealedDTO: Codable {
    var blob: BlobDTO
    var recovery: WrapDTO?

    enum CodingKeys: String, CodingKey { case blob, recovery }

    init(_ s: SealedSecrets) {
        blob = BlobDTO(s.blob)
        recovery = WrapDTO(s.recovery)
    }

    init(destructible b: SealedBlob) {
        blob = BlobDTO(b)
        recovery = nil
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        blob = try c.decode(BlobDTO.self, forKey: .blob)
        recovery = try c.decodeIfPresent(WrapDTO.self, forKey: .recovery)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(blob, forKey: .blob)
        if let r = recovery { try c.encode(r, forKey: .recovery) } else { try c.encodeNil(forKey: .recovery) }
    }

    /// nil = vernichtbar (kein Notfall-Umschlag).
    var value: SealedSecrets? { recovery.map { SealedSecrets(blob: blob.value, recovery: $0.value) } }
    var blobValue: SealedBlob { blob.value }
}

/// `{"anchor", "id", "kit", "mask", "pkM", "pkX"}`.
private struct GroupDTO: Codable {
    var id: UUID
    var mask: UInt8
    var pkM: Data
    var pkX: Data
    var kit: WrapDTO
    var anchor: BlobDTO
    init(_ g: RecoveryGroup) {
        id = g.id
        mask = g.mask.rawValue
        pkM = Data(g.pk.pkM)
        pkX = Data(g.pk.pkX)
        kit = WrapDTO(g.kit)
        anchor = BlobDTO(g.anchor)
    }
    var value: RecoveryGroup {
        RecoveryGroup(id: id, mask: FactorSet(rawValue: mask), pk: RecoveryPublicKeys(pkM: Array(pkM), pkX: Array(pkX)),
                      kit: kit.value, anchor: anchor.value)
    }
}

/// Nur Tests: Inhalt im alten v1-Schema kodieren (Migrations-Tests mit selbst gebauten v1-Dateien).
private let legacyV1Key = CodingUserInfoKey(rawValue: "siegel.legacyV1")

private func legacyV1(_ encoder: Encoder) -> Bool {
    guard let key = legacyV1Key else { return false }
    return encoder.userInfo[key] as? Bool == true
}

private struct PublicKeyDTO: Codable {
    var pkM: Data
    var pkX: Data
    init(_ pk: RecoveryPublicKeys) {
        pkM = Data(pk.pkM)
        pkX = Data(pk.pkX)
    }
    var value: RecoveryPublicKeys { RecoveryPublicKeys(pkM: Array(pkM), pkX: Array(pkX)) }
}

private struct SecureEnclaveKeyDTO: Codable {
    var keyID: UUID
    var publicKey: Data
}

private struct CardKeyDTO: Codable {
    var tag: Data
    var pkM: Data
    var pkX: Data
}

private struct SecurityKeyDTO: Codable {
    var credentialID: Data
    var salt: Data
    var check: Data
    var entrySalt: Data
    var pkM: Data
    var pkX: Data
}

/// Eintrags-Gerätefaktor der Windows-Hello-Art (v4.6): `{"keyID", "version"}`.
private struct WindowsHelloKeyDTO: Codable {
    var keyID: UUID
    var version: Int
}

/// `"factors": {"card": …|null, "secureEnclave": …|null, "securityKey": …|null}` (null explizit). Ein unter Windows
/// eingerichteter Gerätefaktor steht als `"windowsHello": {…}` dabei (v4.6), nur wenn vorhanden.
private struct FactorsDTO: Codable {
    var secureEnclave: SecureEnclaveKeyDTO?
    var card: CardKeyDTO?
    var securityKey: SecurityKeyDTO?
    var windowsHello: WindowsHelloKeyDTO?

    enum CodingKeys: String, CodingKey { case secureEnclave, card, securityKey, windowsHello }

    init(_ f: EntryFactorKeys) {
        secureEnclave = f.secureEnclave.map { SecureEnclaveKeyDTO(keyID: $0.keyID, publicKey: Data($0.publicKey)) }
        card = f.card.map { CardKeyDTO(tag: Data($0.tag), pkM: Data($0.pk.pkM), pkX: Data($0.pk.pkX)) }
        securityKey = f.securityKey.map {
            SecurityKeyDTO(credentialID: Data($0.credentialID), salt: Data($0.salt), check: Data($0.check),
                           entrySalt: Data($0.entrySalt), pkM: Data($0.pk.pkM), pkX: Data($0.pk.pkX))
        }
        windowsHello = f.windowsHello.map { WindowsHelloKeyDTO(keyID: $0.keyID, version: $0.version) }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        secureEnclave = try c.decodeIfPresent(SecureEnclaveKeyDTO.self, forKey: .secureEnclave)
        card = try c.decodeIfPresent(CardKeyDTO.self, forKey: .card)
        securityKey = try c.decodeIfPresent(SecurityKeyDTO.self, forKey: .securityKey)
        windowsHello = try c.decodeIfPresent(WindowsHelloKeyDTO.self, forKey: .windowsHello)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        if let v = secureEnclave { try c.encode(v, forKey: .secureEnclave) } else { try c.encodeNil(forKey: .secureEnclave) }
        if let v = card { try c.encode(v, forKey: .card) } else { try c.encodeNil(forKey: .card) }
        if let v = securityKey { try c.encode(v, forKey: .securityKey) } else { try c.encodeNil(forKey: .securityKey) }
        try c.encodeIfPresent(windowsHello, forKey: .windowsHello)
    }

    var value: EntryFactorKeys {
        EntryFactorKeys(
            secureEnclave: secureEnclave.map { .init(keyID: $0.keyID, publicKey: Array($0.publicKey)) },
            card: card.map { .init(tag: Array($0.tag), pk: RecoveryPublicKeys(pkM: Array($0.pkM), pkX: Array($0.pkX))) },
            securityKey: securityKey.map {
                .init(credentialID: Array($0.credentialID), salt: Array($0.salt), check: Array($0.check),
                      entrySalt: Array($0.entrySalt), pk: RecoveryPublicKeys(pkM: Array($0.pkM), pkX: Array($0.pkX)))
            },
            windowsHello: windowsHello.map { .init(keyID: $0.keyID, version: $0.version) })
    }
}

private struct ContentDTO: Codable {
    var v: Int
    var savedAt: Date
    var recoveryConfirmedAt: Date?
    var level: SecurityLevel
    var factors: FactorsDTO
    var entries: [EntryDTO]
    /// Eintrags-Grundschlüssel (fehlt in Inhalten von Stufe A und v1).
    var entryKey: Data?
    var recoveryGroups: [GroupDTO]
    /// Selbstvernichtung (§23); fehlt in älteren Inhalten.
    var destruction: DestructionDTO?

    enum CodingKeys: String, CodingKey {
        case v, savedAt, recoveryConfirmedAt, level, factors, entries, entryKey, recoveryGroups, destruction
    }

    init(_ c: VaultContent, version: Int) {
        v = version
        savedAt = c.savedAt
        recoveryConfirmedAt = c.recoveryConfirmedAt
        level = c.level
        factors = FactorsDTO(c.entryFactors)
        entries = c.entries.map {
            EntryDTO($0, meta: c.meta[$0.id], sealed: c.sealed[$0.id], destructible: c.destructible[$0.id])
        }
        entryKey = c.entryKey.map { k in k.key.withUnsafeBytes { Data($0) } }
        recoveryGroups = c.recoveryGroups.map(GroupDTO.init)
        destruction = c.destruction.map(DestructionDTO.init)
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(Int.self, forKey: .v)
        savedAt = try c.decode(Date.self, forKey: .savedAt)
        recoveryConfirmedAt = try c.decodeIfPresent(Date.self, forKey: .recoveryConfirmedAt)
        if v >= 2 {
            level = try c.decode(SecurityLevel.self, forKey: .level)
            factors = try c.decode(FactorsDTO.self, forKey: .factors)
            entryKey = try c.decodeIfPresent(Data.self, forKey: .entryKey)
            recoveryGroups = try c.decodeIfPresent([GroupDTO].self, forKey: .recoveryGroups) ?? []
            destruction = try c.decodeIfPresent(DestructionDTO.self, forKey: .destruction)
        } else {
            level = .standard
            factors = FactorsDTO(.none)
            entryKey = nil
            recoveryGroups = []
            destruction = nil
        }
        entries = try c.decode([EntryDTO].self, forKey: .entries)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(v, forKey: .v)
        try c.encode(savedAt, forKey: .savedAt)
        if let d = recoveryConfirmedAt {
            try c.encode(d, forKey: .recoveryConfirmedAt)
        } else {
            try c.encodeNil(forKey: .recoveryConfirmedAt)
        }
        if v >= 2 {
            try c.encode(level, forKey: .level)
            try c.encode(factors, forKey: .factors)
            if let k = entryKey { try c.encode(k, forKey: .entryKey) } else { try c.encodeNil(forKey: .entryKey) }
            try c.encode(recoveryGroups, forKey: .recoveryGroups)
            // Nur geschrieben, wenn eingerichtet: Inhalte ohne Selbstvernichtung bleiben bytegleich wie bisher.
            if let d = destruction { try c.encode(d, forKey: .destruction) }
        }
        try c.encode(entries, forKey: .entries)
    }

    /// best effort: Schlüsselkopie nach dem Kodieren nullen.
    mutating func wipe() {
        entryKey?.withUnsafeMutableBytes { if let p = $0.baseAddress { sodium_memzero(p, $0.count) } }
        entryKey = nil
    }
}

/// `"destruction": {"duress": null|{"check","fileID","pkM","pkX","salt"}, "settings": {…},
/// "vKey": null|{"keyID","publicKey"}}` (§23). Fehlt der Schlüssel, ist die Selbstvernichtung aus. Ein unter Windows
/// eingerichtetes V (v4.6) steht als `{"keyID", "windowsHello": 1}` ohne `publicKey`.
private struct DestructionDTO: Codable {
    struct VKeyDTO: Codable {
        var keyID: UUID
        var publicKey: Data?
        var windowsHello: Int?

        enum CodingKeys: String, CodingKey { case keyID, publicKey, windowsHello }

        init(keyID: UUID, publicKey: Data?, windowsHello: Int?) {
            self.keyID = keyID
            self.publicKey = publicKey
            self.windowsHello = windowsHello
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            keyID = try c.decode(UUID.self, forKey: .keyID)
            publicKey = try c.decodeIfPresent(Data.self, forKey: .publicKey)
            windowsHello = try c.decodeIfPresent(Int.self, forKey: .windowsHello)
            // Mac-Art verlangt publicKey (wie bisher); nur die Windows-Hello-Art kommt ohne aus.
            if (windowsHello ?? 0) == 0, publicKey == nil {
                throw DecodingError.keyNotFound(CodingKeys.publicKey, .init(codingPath: c.codingPath, debugDescription: ""))
            }
        }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(keyID, forKey: .keyID)
            try c.encodeIfPresent(publicKey, forKey: .publicKey)
            try c.encodeIfPresent(windowsHello, forKey: .windowsHello)
        }
    }

    struct DuressDTO: Codable {
        var fileID: UUID
        var salt: Data
        var check: Data
        var pkM: Data
        var pkX: Data
    }

    var settings: DestructionSettings
    var vKey: VKeyDTO?
    var duress: DuressDTO?

    enum CodingKeys: String, CodingKey { case settings, vKey, duress }

    init(_ d: DestructionConfig) {
        settings = d.settings
        vKey = d.vKey.map {
            $0.windowsHello != nil ? VKeyDTO(keyID: $0.keyID, publicKey: nil, windowsHello: $0.windowsHello)
                : VKeyDTO(keyID: $0.keyID, publicKey: Data($0.publicKey), windowsHello: nil)
        }
        duress = d.duress.map {
            DuressDTO(fileID: $0.fileID, salt: Data($0.salt), check: Data($0.check), pkM: Data($0.pk.pkM),
                      pkX: Data($0.pk.pkX))
        }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        settings = try c.decode(DestructionSettings.self, forKey: .settings)
        vKey = try c.decodeIfPresent(VKeyDTO.self, forKey: .vKey)
        duress = try c.decodeIfPresent(DuressDTO.self, forKey: .duress)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(settings, forKey: .settings)
        if let v = vKey { try c.encode(v, forKey: .vKey) } else { try c.encodeNil(forKey: .vKey) }
        if let v = duress { try c.encode(v, forKey: .duress) } else { try c.encodeNil(forKey: .duress) }
    }

    /// Längen streng prüfen (sonst `corruptFile("payload.destruction")`); die Regeln prüft `checkSealing`.
    func value() throws -> DestructionConfig {
        var out = DestructionConfig(settings: settings, vKey: nil, duress: nil)
        if let v = vKey {
            let hello = v.windowsHello ?? 0
            if hello == 0, let pub = v.publicKey {
                guard pub.count == 65, pub.first == 0x04 else { throw SiegelError.corruptFile("payload.destruction") }
                out.vKey = .init(keyID: v.keyID, publicKey: Array(pub))
            } else if hello != 0, v.publicKey == nil {
                // Windows-Hello-Art (v4.6): auf dem Mac nicht nutzbar, aber unverändert weiterzuschreiben.
                out.vKey = .init(keyID: v.keyID, publicKey: [], windowsHello: hello)
                guard out.vKey?.isWellFormed == true else { throw SiegelError.corruptFile("payload.destruction") }
            } else {
                throw SiegelError.corruptFile("payload.destruction")
            }
        }
        if let d = duress {
            guard d.salt.count == DuressCrypto.saltBytes, d.check.count == DuressCrypto.checkBytes,
                  d.pkM.count == RecoveryPublicKeys.pkMBytes, d.pkX.count == RecoveryPublicKeys.pkXBytes else {
                throw SiegelError.corruptFile("payload.destruction")
            }
            out.duress = .init(fileID: d.fileID, salt: Array(d.salt), check: Array(d.check),
                               pk: RecoveryPublicKeys(pkM: Array(d.pkM), pkX: Array(d.pkX)))
        }
        return out
    }
}

/// JSON ↔ gepolsterter Klartext in `SecureBytes` (SPEC §1.4, §5).
enum PayloadCodec {
    static let blockSize = 16_384

    /// Kodiert und polstert (`sodium_pad`, immer ≥ 1 Byte). Liefert zusätzlich SHA-256 des JSON (Rücklese-Prüfung).
    static func encode(_ content: VaultContent) throws -> (padded: SecureBytes, digest: [UInt8]) {
        try encode(content, legacyV1: false)
    }

    static func encode(_ content: VaultContent, legacyV1: Bool) throws -> (padded: SecureBytes, digest: [UInt8]) {
        _ = Sodium.ready
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.dataEncodingStrategy = .base64
        if legacyV1, let key = legacyV1Key { encoder.userInfo[key] = true }
        // Nie einen inkonsistenten Eintrags-Schutz schreiben (Programmfehler fallen hier auf, nicht beim Lesen).
        if !legacyV1 { try content.checkSealing { SiegelError.crypto($0) } }
        var dto = ContentDTO(content, version: legacyV1 ? 1 : VaultContent.version)
        defer { dto.wipe() }
        var json: Data
        do {
            json = try encoder.encode(dto)
        } catch {
            throw SiegelError.io("payload.encode")
        }
        defer {
            // best effort: kodiertes JSON nullen
            json.withUnsafeMutableBytes { if let p = $0.baseAddress { sodium_memzero(p, $0.count) } }
        }
        let unpadded = json.count
        let padded = (unpadded / blockSize + 1) * blockSize
        guard padded + AEAD.tagBytes <= FileFormat.maxCiphertext else { throw SiegelError.io("payload.tooLarge") }
        let digest: [UInt8] = json.withUnsafeBytes { Array(SHA256.hash(data: $0)) }
        let buffer = try SecureBytes(count: padded) { out in
            try json.withUnsafeBytes { src in
                guard let o = out.u8, let s = src.baseAddress else { throw SiegelError.io("payload.encode") }
                UnsafeMutableRawPointer(o).copyMemory(from: s, byteCount: unpadded)
                var result = 0
                guard sodium_pad(&result, o, unpadded, blockSize, padded) == 0, result == padded else {
                    throw SiegelError.io("payload.pad")
                }
            }
        }
        return (buffer, digest)
    }

    /// Entfernt das Padding und dekodiert direkt aus dem sicheren Puffer (`bytesNoCopy`).
    static func decode(_ padded: SecureBytes) throws -> (content: VaultContent, digest: [UInt8]) {
        try padded.withUnsafeBytes { buf in
            guard let p = buf.u8, buf.count > 0, buf.count % blockSize == 0 else {
                throw SiegelError.corruptFile("payload.padding")
            }
            var unpadded = 0
            guard sodium_unpad(&unpadded, p, buf.count, blockSize) == 0 else {
                throw SiegelError.corruptFile("payload.padding")
            }
            let raw = UnsafeRawBufferPointer(rebasing: buf[0..<unpadded])
            let digest = Array(SHA256.hash(data: raw))
            guard let base = raw.baseAddress else { throw SiegelError.corruptFile("payload.json") }
            let data = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: base), count: unpadded, deallocator: .none)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            decoder.dataDecodingStrategy = .base64
            let dto: ContentDTO
            do {
                dto = try decoder.decode(ContentDTO.self, from: data)
            } catch {
                throw SiegelError.corruptFile("payload.json")
            }
            guard dto.v == 1 || dto.v == VaultContent.version else { throw SiegelError.corruptFile("payload.version") }
            let factors = dto.factors.value
            try factors.validate()
            var content = VaultContent(savedAt: dto.savedAt, recoveryConfirmedAt: dto.recoveryConfirmedAt,
                                       level: dto.level, entryFactors: factors, entries: dto.entries.map(\.entry))
            if var k = dto.entryKey {
                defer { k.withUnsafeMutableBytes { if let p = $0.baseAddress { sodium_memzero(p, $0.count) } } }
                guard k.count == 32 else { throw SiegelError.corruptFile("payload.entryKey") }
                content.entryKey = try EntryBaseKey(key: try SecureBytes.copy(k))
            }
            var ids = Set<UUID>()
            for e in dto.entries {
                // Jede Kennung nur einmal (v4.8, Befund robust-8): mit Schutzdaten würden Geheimteile vertauscht, und
                // ohne würde das Speichern (meta je Kennung) einen Inhalt schreiben, der nicht wieder lesbar ist.
                guard ids.insert(e.id).inserted else { throw SiegelError.corruptFile("payload.duplicateID") }
                if let m = e.meta { content.meta[e.id] = m.value }
                if let x = e.sealed {
                    if let normal = x.value {
                        content.sealed[e.id] = normal
                    } else {
                        content.destructible[e.id] = x.blobValue
                    }
                }
            }
            content.recoveryGroups = dto.recoveryGroups.map(\.value)
            if let d = dto.destruction { content.destruction = try d.value() }
            try content.checkSealing { SiegelError.corruptFile($0) }
            return (content, digest)
        }
    }

    #if DEBUG
    /// Nur Tests: JSON-Text eines gepolsterten Klartexts.
    static func jsonStringForTesting(_ padded: SecureBytes) -> String? {
        padded.withUnsafeBytes { buf in
            guard let p = buf.u8 else { return nil }
            var n = 0
            guard sodium_unpad(&n, p, buf.count, blockSize) == 0 else { return nil }
            return String(decoding: UnsafeRawBufferPointer(rebasing: buf[0..<n]), as: UTF8.self)
        }
    }
    #endif
}
