import Foundation

// Gemeinsame Typen der Härtestufe (SPEC v4 §13–§22). Eingefroren wie Model.swift: Kern, Hardware-Modul und
// Oberfläche bauen parallel gegen genau diese Definitionen. Faktor-Werte zwischen den Modulen sind immer roh
// (ECDH_SE, q, hmac-secret-Ausgabe je 32 Byte); die HKDFs aus §13.1 rechnet nur der Kern.

public enum FactorKind: UInt8, Sendable, CaseIterable, Codable {
    case secureEnclave = 1
    case card = 2
    case securityKey = 4

    public var title: String {
        switch self {
        case .secureEnclave: "Fingerabdruck"
        case .card: "QR-Schlüsselkarte"
        case .securityKey: "Sicherheitsschlüssel"
        }
    }
}

public struct FactorSet: OptionSet, Sendable, Hashable, Codable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let secureEnclave = FactorSet(rawValue: FactorKind.secureEnclave.rawValue)
    public static let card = FactorSet(rawValue: FactorKind.card.rawValue)
    public static let securityKey = FactorSet(rawValue: FactorKind.securityKey.rawValue)
    public static let all: FactorSet = [.secureEnclave, .card, .securityKey]

    public func contains(_ kind: FactorKind) -> Bool { contains(FactorSet(rawValue: kind.rawValue)) }
    /// In der Reihenfolge der Schlüsselableitung (§13.1): Secure Enclave, Karte, Sicherheitsschlüssel.
    public var kinds: [FactorKind] { FactorKind.allCases.filter { contains($0) } }
}

public enum RecoveryScheme: UInt8, Sendable, Codable {
    case single = 1
    case shamir2of3 = 2
}

/// Regeln einer Stufe, die die Oberfläche durchsetzt (die Faktoren selbst erzwingt die Kryptografie).
public struct LevelPolicy: Sendable, Equatable {
    public let touchIDBeforeReveal: Bool
    public let lockOnDeactivate: Bool
    public let clipboardSecondsMax: Int?
    public let autoLockMinutesMax: Int?
    public let allowCSVExport: Bool
    public let allowKeePassExport: Bool
    public let autofillAllowed: Bool
    /// Vorgabe für neue Einträge (§16).
    public let defaultEntryProtection: EntryProtection

    public init(touchIDBeforeReveal: Bool, lockOnDeactivate: Bool, clipboardSecondsMax: Int?, autoLockMinutesMax: Int?,
                allowCSVExport: Bool, allowKeePassExport: Bool, autofillAllowed: Bool,
                defaultEntryProtection: EntryProtection) {
        self.touchIDBeforeReveal = touchIDBeforeReveal
        self.lockOnDeactivate = lockOnDeactivate
        self.clipboardSecondsMax = clipboardSecondsMax
        self.autoLockMinutesMax = autoLockMinutesMax
        self.allowCSVExport = allowCSVExport
        self.allowKeePassExport = allowKeePassExport
        self.autofillAllowed = autofillAllowed
        self.defaultEntryProtection = defaultEntryProtection
    }
}

/// Tresor-Stufe (§13): was zum Öffnen nötig ist, plus Regeln.
public enum SecurityLevel: Int, Codable, Sendable, CaseIterable, Comparable {
    case standard = 1, erhoeht, hoch, maximal, festung

    public static func < (a: SecurityLevel, b: SecurityLevel) -> Bool { a.rawValue < b.rawValue }

    public var title: String {
        switch self {
        case .standard: "Standard"
        case .erhoeht: "Erhöht"
        case .hoch: "Hoch"
        case .maximal: "Maximal"
        case .festung: "Festung"
        }
    }

    /// Zum Öffnen nötige Faktoren (zusätzlich zum Master-Passwort).
    public var factors: FactorSet {
        switch self {
        case .standard: []
        case .erhoeht, .hoch: [.secureEnclave]
        case .maximal: [.secureEnclave, .card]
        case .festung: [.secureEnclave, .card, .securityKey]
        }
    }

    public var kdf: KDFParameters {
        switch self {
        case .standard, .erhoeht: .standard
        case .hoch, .maximal, .festung: .strong
        }
    }

    public var recoveryScheme: RecoveryScheme {
        self >= .maximal ? .shamir2of3 : .single
    }

    public var policy: LevelPolicy {
        switch self {
        case .standard, .erhoeht:
            LevelPolicy(touchIDBeforeReveal: false, lockOnDeactivate: false, clipboardSecondsMax: nil,
                        autoLockMinutesMax: nil, allowCSVExport: true, allowKeePassExport: true,
                        autofillAllowed: true, defaultEntryProtection: .normal)
        case .hoch:
            LevelPolicy(touchIDBeforeReveal: true, lockOnDeactivate: true, clipboardSecondsMax: 15,
                        autoLockMinutesMax: 2, allowCSVExport: true, allowKeePassExport: true,
                        autofillAllowed: true, defaultEntryProtection: .normal)
        case .maximal, .festung:
            LevelPolicy(touchIDBeforeReveal: true, lockOnDeactivate: true, clipboardSecondsMax: 15,
                        autoLockMinutesMax: 2, allowCSVExport: false, allowKeePassExport: false,
                        autofillAllowed: false, defaultEntryProtection: .fingerabdruck)
        }
    }
}

/// Schutz pro Eintrag (§16): was zusätzlich zum offenen Tresor nötig ist, um die Geheimteile aufzudecken.
public enum EntryProtection: Int, Codable, Sendable, CaseIterable, Comparable {
    case normal = 1, fingerabdruck, hoch, maximal, festung

    public static func < (a: EntryProtection, b: EntryProtection) -> Bool { a.rawValue < b.rawValue }

    public var title: String {
        switch self {
        case .normal: "Normal"
        case .fingerabdruck: "Fingerabdruck"
        case .hoch: "Hoch"
        case .maximal: "Maximal"
        case .festung: "Festung"
        }
    }

    /// Pro Aufdecken nötige Faktoren.
    public var factors: FactorSet {
        switch self {
        case .normal: []
        case .fingerabdruck, .hoch: [.secureEnclave]
        case .maximal: [.secureEnclave, .card]
        case .festung: [.secureEnclave, .card, .securityKey]
        }
    }

    /// Höchstdauer in der Zwischenablage (nil = Einstellung des Nutzers).
    public var clipboardSecondsMax: Int? { self >= .hoch ? 15 : nil }
    public var autofillAllowed: Bool { self < .hoch }
    public var exportAllowed: Bool { self < .maximal }
}

/// 32 geheime Bytes eines Faktors in `sodium_malloc`-Speicher, beim Freigeben genullt.
public final class FactorSecret: @unchecked Sendable {
    let storage: SecureBytes

    /// Genau 32 Byte, sonst `crypto("factor.length")`.
    public init(copying bytes: some ContiguousBytes) throws {
        let s = try bytes.withUnsafeBytes { raw -> SecureBytes in
            guard raw.count == 32 else { throw SiegelError.crypto("factor.length") }
            return try SecureBytes(copying: raw)
        }
        storage = s
    }

    init(storage: SecureBytes) throws {
        guard storage.count == 32 else { throw SiegelError.crypto("factor.length") }
        self.storage = storage
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }
}

public struct FactorSecrets: Sendable {
    public var secureEnclave: FactorSecret?
    public var card: FactorSecret?
    public var securityKey: FactorSecret?

    public init(secureEnclave: FactorSecret? = nil, card: FactorSecret? = nil, securityKey: FactorSecret? = nil) {
        self.secureEnclave = secureEnclave
        self.card = card
        self.securityKey = securityKey
    }

    public var available: FactorSet {
        var s: FactorSet = []
        if secureEnclave != nil { s.insert(.secureEnclave) }
        if card != nil { s.insert(.card) }
        if securityKey != nil { s.insert(.securityKey) }
        return s
    }
}

public struct SEEnrollment: Sendable {
    public let keyID: UUID
    /// Rohes ECDH_SE (32 B) aus der Einrichtung.
    public let secret: FactorSecret
    public init(keyID: UUID, secret: FactorSecret) {
        self.keyID = keyID
        self.secret = secret
    }
}

public struct EntryKeyEnrollment: Sendable {
    public let keyID: UUID
    /// Öffentlicher Eintrags-SE-Schlüssel, x963 (65 B).
    public let publicKey: Data
    public init(keyID: UUID, publicKey: Data) {
        self.keyID = keyID
        self.publicKey = publicKey
    }
}

public struct CardEnrollment: Sendable {
    /// Rohes Kartengeheimnis q (32 B).
    public let q: FactorSecret
    public init(q: FactorSecret) { self.q = q }
}

public struct SecurityKeyEnrollment: Sendable {
    public let credentialID: Data
    /// hmac-secret-Salz für das Öffnen (32 B) und dessen Ausgabe.
    public let salt: Data
    public let output: FactorSecret
    /// Zweites Salz für Einträge (32 B) und dessen Ausgabe.
    public let entrySalt: Data
    public let entryOutput: FactorSecret
    public init(credentialID: Data, salt: Data, output: FactorSecret, entrySalt: Data, entryOutput: FactorSecret) {
        self.credentialID = credentialID
        self.salt = salt
        self.output = output
        self.entrySalt = entrySalt
        self.entryOutput = entryOutput
    }
}

public struct NewFactorMaterial: Sendable {
    public var secureEnclave: SEEnrollment?
    public var entryKey: EntryKeyEnrollment?
    public var card: CardEnrollment?
    public var securityKey: SecurityKeyEnrollment?
    public init(secureEnclave: SEEnrollment? = nil, entryKey: EntryKeyEnrollment? = nil,
                card: CardEnrollment? = nil, securityKey: SecurityKeyEnrollment? = nil) {
        self.secureEnclave = secureEnclave
        self.entryKey = entryKey
        self.card = card
        self.securityKey = securityKey
    }
}

/// Liefert beim Aufdecken eines geschützten Eintrags die Faktoren (Oberfläche + SiegelHardware).
/// Der Kern ruft nur die Methoden, die der Schutz des Eintrags verlangt; jeder Aufruf ist eine eigene
/// Freigabe (Touch ID, Karte scannen, Schlüssel berühren).
public protocol EntryFactorProvider: Sendable {
    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret
    func cardSecret() async throws -> FactorSecret
    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret
}

/// Kopf-Auskunft ohne Geheimnis (§13.3).
public struct VaultHeaderInfo: Sendable, Equatable {
    public let formatVersion: UInt16
    public let vaultID: UUID
    public let factors: FactorSet
    public let recoveryScheme: RecoveryScheme
    public let seKeyID: UUID?
    public let cardTag: Data?
    public let fidoCredentialID: Data?
    public let fidoSalt: Data?
    public let kdf: KDFParameters
    public let kitID: String

    public init(formatVersion: UInt16, vaultID: UUID, factors: FactorSet, recoveryScheme: RecoveryScheme,
                seKeyID: UUID?, cardTag: Data?, fidoCredentialID: Data?, fidoSalt: Data?,
                kdf: KDFParameters, kitID: String) {
        self.formatVersion = formatVersion
        self.vaultID = vaultID
        self.factors = factors
        self.recoveryScheme = recoveryScheme
        self.seKeyID = seKeyID
        self.cardTag = cardTag
        self.fidoCredentialID = fidoCredentialID
        self.fidoSalt = fidoSalt
        self.kdf = kdf
        self.kitID = kitID
    }
}

/// Aufgedeckte Geheimteile eines Eintrags.
public struct EntrySecrets: Sendable, Equatable {
    public var password: String
    public var notes: String
    public var totp: String
    public var history: [PasswordHistoryItem]

    public init(password: String = "", notes: String = "", totp: String = "", history: [PasswordHistoryItem] = []) {
        self.password = password
        self.notes = notes
        self.totp = totp
        self.history = history
    }
}

public struct SecurityReport: Sendable, Equatable {
    public let weak: [UUID]
    public let reused: [[UUID]]
    public let old: [UUID]
    public let sameAsMaster: [UUID]
    public let total: Int

    public init(weak: [UUID], reused: [[UUID]], old: [UUID], sameAsMaster: [UUID], total: Int) {
        self.weak = weak
        self.reused = reused
        self.old = old
        self.sameAsMaster = sameAsMaster
        self.total = total
    }
}

/// Ein Teil des geteilten Notfallcodes (§15).
public struct RecoveryShare: Sendable {
    public let index: Int
    public let formatted: String
    public let kitID: String

    init(index: Int, formatted: String, kitID: String) {
        self.index = index
        self.formatted = formatted
        self.kitID = kitID
    }

    public var groups: [String] { formatted.split(separator: "-").map(String.init) }
}

// MARK: - Geschwärzte Beschreibungen (SPEC §5)

extension FactorSecret: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "FactorSecret(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: KeyValuePairs<String, Any>(), displayStyle: .class) }
}

extension EntrySecrets: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "EntrySecrets(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: KeyValuePairs<String, Any>(), displayStyle: .struct) }
}

extension RecoveryShare: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "RecoveryShare(\(index), kit: \(kitID), redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["index": index, "kitID": kitID], displayStyle: .struct) }
}
