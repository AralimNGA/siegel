import Foundation

// Gemeinsame Datentypen von SiegelCore (SPEC §8). Reine Werte ohne Kryptografie.
// Alle Typen mit Geheimnissen schwärzen ihre Beschreibung (SPEC §5): String(describing:), debugDescription
// und dump() zeigen nie Passwörter, Notizen oder Codes.

/// Alle Fehler, die SiegelCore nach aussen gibt. Die Oberfläche übersetzt sie in deutsche Meldungen.
/// String-Nutzlasten sind nur feste Codes (z. B. "header.length"), nie Inhalte.
public enum SiegelError: Error, Equatable, Sendable {
    case wrongPassword
    /// Der Code ist formal gültig, gehört aber zu einem anderen Notfallkit (Kit-Kennungen zum Anzeigen).
    case wrongRecoveryCode(codeKit: String, vaultKit: String)
    case invalidRecoveryCodeFormat
    case recoveryCodeChecksum
    case recoveryConfirmationMismatch
    case passwordTooWeak(bits: Double)
    case masterPasswordReused
    case corruptFile(String)
    case unsupportedVersion(UInt16)
    case kdfParametersOutOfRange
    /// crypto_pwhash ist gescheitert (meist zu wenig freier Arbeitsspeicher) – nie mit wrongPassword verwechseln.
    case kdfFailed
    case vaultAlreadyExists
    case vaultMissing
    /// Die Datei auf der Platte hat nicht die erwartete Generation (anderer Schreiber); nichts wurde überschrieben.
    case vaultChangedOnDisk
    case notEnoughDiskSpace
    case csvInvalid(line: Int, reason: String)
    case exportLocationRejected(String)
    case io(String)
    case crypto(String)
    // v4 (§13–§22)
    /// Die Datei verlangt diesen Faktor, er wurde aber nicht mitgegeben.
    case factorMissing(FactorKind)
    /// Der Faktor ist auf diesem Mac nicht nutzbar (Schlüssel fehlt, Biometrie geändert, Gerät fehlt).
    case factorUnavailable(FactorKind)
    case factorCancelled
    /// Die gescannte Karte gehört nicht zu diesem Tresor (Karten-Kennung).
    case wrongCard
    case notAllowedAtLevel
    case totpInvalid(String)
    // v4.4 (Hardware-Befunde, §12)
    /// Der Faktor geht gerade nicht, ist aber nicht verloren: erneut versuchen, kein Notfallweg. Feste Codes:
    /// `"se.lockout"` (Touch ID nach zu vielen Fehlversuchen gesperrt), `"se.notReachable"` (Sensor nicht erreichbar,
    /// z. B. Deckel zu oder Tastatur mit Touch ID nicht verbunden), `"fido.busy"` (Sicherheitsschlüssel belegt).
    case factorTemporarilyUnavailable(FactorKind, String)
    /// Der eingesteckte Sicherheitsschlüssel kennt die Registrierung nicht (anderer oder zurückgesetzter Schlüssel,
    /// CTAP2_ERR_NO_CREDENTIALS).
    case wrongSecurityKey
}

/// Argon2id-Parameter (libsodium: opslimit = Durchläufe t, memlimit = Speicher in Byte, Parallelität fest 1).
public struct KDFParameters: Equatable, Sendable {
    public let opsLimit: UInt32
    public let memLimitBytes: UInt64

    public init(opsLimit: UInt32, memLimitBytes: UInt64) {
        self.opsLimit = opsLimit
        self.memLimitBytes = memLimitBytes
    }

    /// 1 GiB, t = 3 (≈1.2 s auf M5 Max).
    public static let standard = KDFParameters(opsLimit: 3, memLimitBytes: 1 << 30)
    /// 2 GiB, t = 4 (≈3.3 s auf M5 Max).
    public static let strong = KDFParameters(opsLimit: 4, memLimitBytes: 2 << 30)
}

public struct PasswordHistoryItem: Codable, Equatable, Hashable, Sendable {
    public var password: String
    public var changed: Date

    public init(password: String, changed: Date) {
        self.password = password
        self.changed = changed
    }
}

public struct VaultEntry: Codable, Identifiable, Equatable, Hashable, Sendable {
    public var id: UUID
    public var title: String
    public var username: String
    public var password: String
    public var url: String
    public var notes: String
    public var created: Date
    public var modified: Date
    /// Gesetzt = in „Zuletzt gelöscht“ (30 Tage), danach endgültig entfernt.
    public var deletedAt: Date?
    public var history: [PasswordHistoryItem]
    /// TOTP-Geheimnis (otpauth-URI oder Base32), §18. Leer = keins.
    public var totp: String
    /// Schutz pro Eintrag (§16).
    public var protection: EntryProtection
    /// Nur der Kern setzt das: true = Geheimteile versiegelt (password/notes/totp/history sind dann leer);
    /// `UnlockedVault.revealSecrets` deckt sie mit den nötigen Faktoren auf.
    public internal(set) var secretsSealed: Bool

    public init(title: String = "", username: String = "", password: String = "",
                url: String = "", notes: String = "", totp: String = "",
                protection: EntryProtection = .normal) {
        let now = Date()
        self.id = UUID()
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.created = now
        self.modified = now
        self.deletedAt = nil
        self.history = []
        self.totp = totp
        self.protection = protection
        self.secretsSealed = false
    }

    enum CodingKeys: String, CodingKey {
        case id, title, username, password, url, notes, created, modified, deletedAt, history, totp, protection, secretsSealed
    }

    /// Ältere Inhalte (v1) kennen totp/protection/secretsSealed nicht: Standardwerte.
    public init(from decoder: Decoder) throws {
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
        history = try c.decode([PasswordHistoryItem].self, forKey: .history)
        totp = try c.decodeIfPresent(String.self, forKey: .totp) ?? ""
        protection = try c.decodeIfPresent(EntryProtection.self, forKey: .protection) ?? .normal
        secretsSealed = try c.decodeIfPresent(Bool.self, forKey: .secretsSealed) ?? false
    }
}

/// Der Notfallcode. Wird nie gespeichert, nur angezeigt/gedruckt.
public struct RecoveryCode: Sendable {
    /// "XXXXX-XXXXX-…" (11 Gruppen à 5 Zeichen, Crockford-Base32)
    public let formatted: String
    /// Kit-Kennung "XXXX-XXXX" (nicht geheim)
    public let kitID: String

    init(formatted: String, kitID: String) {
        self.formatted = formatted
        self.kitID = kitID
    }

    public var groups: [String] {
        formatted.split(separator: "-").map(String.init)
    }
}

/// Ein vorbereitetes Notfallkit. Bei `create` ist es bereits gültig (aber unbestätigt),
/// bei `prepareRecovery` ist noch nichts geschrieben.
public struct PendingRecovery: Sendable {
    public let code: RecoveryCode
    /// Zwei verschiedene Gruppenindizes 0…10, die zur Bestätigung eingetippt werden (bei `.single`).
    public let confirmationGroups: [Int]
    /// v4: `.single` = ein Code; `.shamir2of3` = drei Teile (`shares`), `code` ist dann nur intern relevant.
    public let scheme: RecoveryScheme
    /// Drei Teile bei `.shamir2of3`, sonst leer.
    public let shares: [RecoveryShare]
    /// Bei `.shamir2of3`: je Teil ein Gruppenindex zur Bestätigung (gleiche Reihenfolge wie `shares`).
    public let shareConfirmationGroups: [Int]

    init(code: RecoveryCode, confirmationGroups: [Int], scheme: RecoveryScheme = .single,
         shares: [RecoveryShare] = [], shareConfirmationGroups: [Int] = []) {
        self.code = code
        self.confirmationGroups = confirmationGroups
        self.scheme = scheme
        self.shares = shares
        self.shareConfirmationGroups = shareConfirmationGroups
    }
}

public enum RecoveryCodeMatch: Sendable, Equatable {
    case exact
    /// Korrigierter Code; Positionen (0…54) im 55-Zeichen-Code ohne Bindestriche.
    case corrected(formatted: String, changedPositions: [Int])
}

public struct BackupInfo: Sendable, Equatable, Identifiable {
    public var id: URL { url }
    public let url: URL
    public let date: Date
    public let generation: UInt64
    /// Aus dem Kopf gelesen; nil = unlesbar.
    public let vaultID: UUID?
    /// Anlass bei angehefteten Sicherungen ("import", "passwortwechsel", …), sonst nil.
    public let reason: String?
    public let isExternal: Bool

    public init(url: URL, date: Date, generation: UInt64, vaultID: UUID?, reason: String?, isExternal: Bool) {
        self.url = url
        self.date = date
        self.generation = generation
        self.vaultID = vaultID
        self.reason = reason
        self.isExternal = isExternal
    }
}

/// Ergebnis von `purgeBackups` (SPEC v3.1): Was liess sich nicht entfernen? Die Oberfläche meldet nur dann
/// „Alte Sicherungen entfernt“, wenn `isComplete` gilt.
public struct PurgeReport: Sendable, Equatable {
    /// Entfernte Sicherungsdateien (lokal und am zweiten Ort).
    public var removed = 0
    /// Dateien, die sich nicht entfernen liessen (bleiben mit dem alten Zugang lesbar).
    public var failed = 0
    /// Der zweite Sicherungsort ist gesetzt, liess sich aber nicht lesen (z. B. Stick ausgesteckt).
    public var secondaryUnreachable = false
    /// Das Entfernen brach mit einem Fehler ab (nach dem Speichern, das bleibt gültig): ältere Sicherungen können
    /// noch da sein, wie viele, ist unbekannt (SPEC v4.4, Befund datei-1).
    public var interrupted = false

    public init() {}

    public var isComplete: Bool { failed == 0 && !secondaryUnreachable && !interrupted }
}

/// Ergebnis des letzten Versuchs, am zweiten Sicherungsort zu sichern (SPEC v3.1).
public enum SecondaryBackupResult: Sendable, Equatable {
    /// Kopie geschrieben (Zeitpunkt).
    case written(Date)
    /// Nicht fällig (höchstens 1× pro Stunde).
    case notDue
    /// Kein Ort gesetzt oder Ordner nicht lesbar.
    case unreachable
    /// Schreiben gescheitert.
    case failed
}

public struct ImportReport: Sendable, Equatable {
    public var added = 0
    public var skippedDuplicates = 0
    public var conflicts = 0
    public var withOTPSecret = 0
    public var movedToNotes = 0
    public var passwordsWithControlCharacters = 0
    public var apostrophePrefixed = 0

    public init() {}
}

public struct CSVImportResult: Sendable {
    public enum Format: String, Sendable { case applePasswords, chrome, firefox, bitwarden }
    public let format: Format
    public let entries: [VaultEntry]
    /// Vorläufig: Dubletten werden erst bei `importEntries` gezählt.
    public let report: ImportReport

    public init(format: Format, entries: [VaultEntry], report: ImportReport) {
        self.format = format
        self.entries = entries
        self.report = report
    }
}

// MARK: - Geschwärzte Beschreibungen (SPEC §5)

extension PasswordHistoryItem: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "PasswordHistoryItem(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: KeyValuePairs<String, Any>(), displayStyle: .struct) }
}

extension VaultEntry: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "VaultEntry(id: \(id.uuidString), redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["id": id], displayStyle: .struct) }
}

extension RecoveryCode: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "RecoveryCode(kit: \(kitID), redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["kitID": kitID], displayStyle: .struct) }
}

extension PendingRecovery: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "PendingRecovery(kit: \(code.kitID), redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["kitID": code.kitID], displayStyle: .struct) }
}
