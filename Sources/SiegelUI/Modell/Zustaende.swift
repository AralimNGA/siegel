import AppKit
import Foundation
import Observation
import SiegelCore

// Formular- und Ablaufzustände der einzelnen Bildschirme. Sie liegen im AppModel (nicht in @State), damit
// Sperren sie gezielt verwerfen kann und Snapshots sie füllen können. Beim Sperren entstehen neue Instanzen.

/// Abbildung nach RFC 8265 (wie im Kern, SPEC §1.1): Zs → U+0020, dann NFC. Nur für die Anzeige
/// „Wiederholung weicht ab“; die Gleichheit prüft der Kern (`VaultStore.passwordsMatch`), genau wie beim Ableiten.
enum PasswordNormalization {
    static func normalize(_ password: String) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in password.unicodeScalars {
            scalars.append(scalar.properties.generalCategory == .spaceSeparator ? " " : scalar)
        }
        return String(scalars).precomposedStringWithCanonicalMapping
    }

    static func equal(_ a: String, _ b: String) -> Bool {
        VaultStore.passwordsMatch(a, b)
    }
}

/// Bewertung eines Master-Passworts für die Anzeige.
public struct PasswordAssessment: Equatable, Sendable {
    public var bits: Double
    public var level: PasswordStrength.Level
    public var meetsPolicy: Bool
    public var isEmpty: Bool

    /// Eine einzige Schätzung (Befund #48): Bit, Wort und Regel stammen alle aus `MasterPasswordPolicy.check`
    /// (mit Namensteilen und Umschriften). Vorher kam das Wort aus einer zweiten Schätzung ohne Namensteile –
    /// „Stark · 32 Bit“ war möglich.
    public static func of(_ password: String) -> PasswordAssessment {
        guard !password.isEmpty else {
            return PasswordAssessment(bits: 0, level: .veryWeak, meetsPolicy: false, isEmpty: true)
        }
        let policy = MasterPasswordPolicy.check(password)
        return PasswordAssessment(bits: policy.bits, level: level(forBits: policy.bits), meetsPolicy: policy.ok,
                                  isEmpty: false)
    }

    /// Stufen wie `PasswordStrength.level(forBits:)` im Kern (dort nicht öffentlich): < 28 sehr schwach, < 36
    /// schwach, < 60 mittel, < 80 stark, sonst sehr stark.
    public static func level(forBits bits: Double) -> PasswordStrength.Level {
        if bits < 28 { return .veryWeak }
        if bits < 36 { return .weak }
        if bits < 60 { return .fair }
        if bits < 80 { return .strong }
        return .veryStrong
    }
}

/// Merkt sich die letzte Bewertung (ein Eintrag), damit Anzeige und Knopf-Zustand pro Tastendruck nur einmal
/// schätzen (Befund #48: sonst vier volle zxcvbn-Läufe pro Tastendruck auf dem Main-Thread).
struct AssessmentCache {
    private var input: String?
    private var value = PasswordAssessment.of("")

    mutating func assess(_ password: String) -> PasswordAssessment {
        if input != password {
            value = .of(password)
            input = password
        }
        return value
    }

    mutating func clear() {
        input = nil
        value = .of("")
    }
}

// MARK: - Einrichtung

@MainActor
@Observable
public final class SetupState {
    public enum Mode: Sendable { case passphrase, own }

    public var mode: Mode = .passphrase
    /// Vorgeschlagene Passphrase (6 Wörter).
    public var passphrase: String = PassphraseGenerator.generate(words: 6)
    /// Wiederholung der Passphrase (zeigt, dass sie sich tippen lässt).
    public var passphraseRepeat = ""
    public var password = ""
    public var passwordRepeat = ""
    public var error: String?
    /// FileVault-Status des Tresor-Ordners (nil = unbekannt).
    public var fileVaultEncrypted: Bool?
    @ObservationIgnored private var cache = AssessmentCache()

    public init() {}

    /// Das Passwort, das angelegt würde.
    public var candidate: String { mode == .passphrase ? passphrase : password }
    var repeated: String { mode == .passphrase ? passphraseRepeat : passwordRepeat }

    public var assessment: PasswordAssessment { cache.assess(candidate) }

    public var repeatMatches: Bool {
        !repeated.isEmpty && PasswordNormalization.equal(candidate, repeated)
    }

    /// Wiederholung ist ausgefüllt und weicht ab (Hinweis zeigen).
    public var repeatMismatch: Bool {
        !repeated.isEmpty && !PasswordNormalization.normalize(candidate).hasPrefix(PasswordNormalization.normalize(repeated))
            && !repeatMatches
    }

    public var canCreate: Bool { assessment.meetsPolicy && repeatMatches }

    public func reroll() {
        passphrase = PassphraseGenerator.generate(words: 6)
        passphraseRepeat = ""
        error = nil
    }

    public var passphraseEntropyBits: Int { Int(PassphraseGenerator.entropyBits(words: 6).rounded()) }
}

// MARK: - Gesperrt

@MainActor
@Observable
public final class UnlockState {
    public var password = ""
    public var error: String?
    /// Zähler fürs Schütteln (mit Animation hochzählen).
    public var shakes = 0
    /// Riegel der Bildmarke (0 Ruhe, 1 offen).
    public var riegel: CGFloat = 0
    /// Kopf-Auskunft ohne Geheimnis (§13.3): welche Faktoren zum Öffnen nötig sind.
    public internal(set) var header: VaultHeaderInfo?
    /// Faktoren des laufenden Versuchs (nach jedem Versuch verworfen).
    public internal(set) var collection: FactorCollection?
    /// Faktoren werden eingesammelt (Touch ID, Karte, Schlüssel).
    public internal(set) var collecting = false
    /// Vor dem Einsammeln (Totmann-Prüfung, Kopf): ein zweites Enter startet keinen zweiten Versuch.
    @ObservationIgnored var preparing = false

    public init() {}

    /// Zum Öffnen nötige Faktoren (leer = nur das Master-Passwort).
    public var factors: FactorSet { header?.factors ?? [] }
}

// MARK: - Notfallcode-Weg (gesperrt)

@MainActor
@Observable
public final class RecoveryState {
    public enum Step: Equatable, Sendable {
        case enterCode
        case confirmCorrection(formatted: String, changedPositions: [Int])
        /// Geteilter Code (§15): Korrekturen je Teil bestätigen (Index 0/1, Text, Stellen).
        case confirmShareCorrections([ShareCorrection])
        case newPassword
        case done
    }

    public struct ShareCorrection: Equatable, Sendable {
        public let index: Int
        public let formatted: String
        public let changedPositions: [Int]
    }

    /// Woher der Notfallweg kommt (v4.4): Sperrbildschirm (Tresordatei da, evtl. beschädigt), „Tresor fehlt“
    /// (neueste Sicherung, die der Code öffnet) oder eine vom Nutzer gewählte Sicherungsdatei (genau diese).
    public enum Origin: Equatable, Sendable {
        case lock
        case missingVault
        case file(URL)
    }

    public internal(set) var origin: Origin = .lock
    public var step: Step = .enterCode
    public var code = ""
    public var confirmedCode: String?
    /// Kopf-Auskunft: ein Code oder zwei von drei Teilen (§15), Faktoren vor der Wiederherstellung. Belegt die Wahl
    /// Code/Teile vor, solange der Nutzer nicht selbst umgeschaltet hat (Befund datei-4).
    public internal(set) var header: VaultHeaderInfo?
    /// Kopf aus der Zieldatei selbst und mit Prüfsumme gelesen: dann braucht es keinen Umschalter Code/Teile.
    public internal(set) var schemeCertain = false
    /// Ein Code oder zwei Teile (§15). Vom Kopf vorbelegt; ist er unsicher (beschädigt, aus einer Sicherung, fehlt),
    /// schaltet der Nutzer um (Befund datei-4).
    public internal(set) var usesShares = false
    @ObservationIgnored var schemeChosenByUser = false

    /// Kopf setzen; belegt Code/Teile vor, solange der Nutzer nicht selbst gewählt hat.
    func setHeader(_ info: VaultHeaderInfo?, certain: Bool) {
        header = info
        schemeCertain = certain && info != nil
        if !schemeChosenByUser { usesShares = info?.recoveryScheme == .shamir2of3 }
    }

    /// Umschalter „Ich habe ein Kit in drei Teilen“ / „Ich habe einen einzelnen Code“.
    func chooseScheme(shares: Bool) {
        schemeChosenByUser = true
        usesShares = shares
        error = nil
    }
    /// Zwei Teile des geteilten Notfallcodes.
    public var shares = ["", ""]
    public var confirmedShares: [String]?
    public var newPassword = ""
    public var newPasswordRepeat = ""
    public var error: String?
    /// Die Tresordatei ist beschädigt: Wiederherstellen über die neueste Sicherung, die der Code öffnet.
    public var useBackup = false
    /// Nach `corruptFile` beim Wiederherstellen: Knopf „Neueste lesbare Sicherung mit dem Notfallcode öffnen“.
    public var offerBackup = false
    /// Nach der Wiederherstellung: geöffneter Tresor (noch nicht angezeigt) und Zusammenfassung.
    var vault: UnlockedVault?
    public var entryCount = 0
    public var lastModified: Date?
    /// Wiederhergestellt aus dieser Sicherung (nur Sicherungsweg).
    public var restoredBackup: BackupInfo?
    /// Das Profil Stark scheiterte am Arbeitsspeicher (`kdfFailed`): Knopf „Mit Profil Standard wiederherstellen“
    /// statt still herabzustufen (Befund #21).
    public var offerStandardProfile = false
    /// Bewusst gewählt: mit Profil Standard wiederherstellen.
    public var forceStandardProfile = false
    @ObservationIgnored private var cache = AssessmentCache()

    public init() {}

    public var assessment: PasswordAssessment { cache.assess(newPassword) }

    /// Profil der neuen Datei: wie bisher (Befund #21: Stark bleibt Stark). Der Kopf ist vor der Wiederherstellung
    /// nicht authentifiziert; darum nur die zwei bekannten Profile, nie ein beliebiger Wert aus der Datei.
    public var kdfToKeep: KDFParameters { header?.kdf == .strong ? .strong : .standard }
    public var repeatMatches: Bool {
        !newPasswordRepeat.isEmpty && PasswordNormalization.equal(newPassword, newPasswordRepeat)
    }
    public var canSubmit: Bool { assessment.meetsPolicy && repeatMatches }

    /// Gewählte Sicherungsdatei (Notfallweg für genau diese Datei, v4.4).
    public var sourceFile: URL? {
        if case let .file(url) = origin { return url }
        return nil
    }

    /// Hatte der Tresor vor der Wiederherstellung Faktoren oder Teile? (Hinweis: alles wieder Stufe 1, §16.1)
    public var hadHardening: Bool {
        guard let header else { return false }
        return !header.factors.isEmpty || header.recoveryScheme == .shamir2of3
    }
}

// MARK: - Notfallkit

@MainActor
@Observable
public final class KitState {
    public enum Origin: Sendable, Equatable {
        /// Direkt nach dem Anlegen (Code ist schon gültig, nur unbestätigt).
        case setup
        /// Neues Kit aus Einstellungen oder Banner (noch nichts geschrieben).
        case newKit
        /// Teil des Stufen-Assistenten: Bestätigung wird mit dem Stufenwechsel geschrieben.
        case levelChange
    }

    public enum Method: Sendable, Equatable { case handwritten, printed }

    public enum Step: Sendable, Equatable {
        case show
        case confirm
        /// Nach neuem Kit: alte Sicherungen entfernen?
        case purgeQuestion
    }

    public let pending: PendingRecovery
    public let origin: Origin
    public var step: Step = .show
    public var method: Method?
    public var confirmation: [String]
    public var error: String?
    /// Warnung vor unverschlüsseltem (bzw. nicht prüfbarem) Drucker ist offen.
    public var printWarning = false
    /// Text der Warnung (Netzwerkdrucker bzw. nicht prüfbar).
    public var printWarningText = ""
    public var printFailed = false
    /// Im Druckdialog wurde keine Ausgabe auf Papier gewählt (PDF, Vorschau, Cloud): kein Code ausgegeben.
    public var printNotPaper = false
    /// Im Druckdialog gewählte Einstellungen (Drucker), bis „Trotzdem drucken“.
    var chosenPrintInfo: NSPrintInfo?
    /// Geteilter Code: gezeigter Teil (0…2) und je Teil, wie er festgehalten wurde.
    public var shareIndex = 0
    public var shareMethods: [Int: Method] = [:]

    public init(pending: PendingRecovery, origin: Origin) {
        self.pending = pending
        self.origin = origin
        self.confirmation = Array(repeating: "", count: Self.confirmationCount(pending))
    }

    static func confirmationCount(_ pending: PendingRecovery) -> Int {
        pending.scheme == .shamir2of3 ? pending.shares.count : pending.confirmationGroups.count
    }

    public var isShared: Bool { pending.scheme == .shamir2of3 && !pending.shares.isEmpty }

    /// Gruppennummern für die Bestätigung, 1-basiert für die Anzeige.
    public var confirmationNumbers: [Int] {
        isShared ? pending.shareConfirmationGroups.map { $0 + 1 } : pending.confirmationGroups.map { $0 + 1 }
    }

    /// Erwartete Länge je Bestätigungsfeld (die letzte Gruppe eines Teils kann kürzer sein).
    public func expectedLength(_ index: Int) -> Int {
        guard isShared else { return 5 }
        guard index < pending.shares.count, index < pending.shareConfirmationGroups.count else { return 5 }
        let gruppen = pending.shares[index].groups
        let g = pending.shareConfirmationGroups[index]
        return g < gruppen.count ? gruppen[g].count : 5
    }

    public var canConfirm: Bool {
        confirmation.indices.allSatisfy { RecoveryCodeFormatting.significant(confirmation[$0]).count == expectedLength($0) }
    }

    /// Alle drei Teile festgehalten (gedruckt oder abgeschrieben)?
    public var allSharesRecorded: Bool {
        pending.shares.indices.allSatisfy { shareMethods[$0] != nil }
    }

    /// Gruppen des gezeigten Codes bzw. Teils.
    public var shownGroups: [String] {
        guard isShared else { return pending.code.groups }
        return shareIndex < pending.shares.count ? pending.shares[shareIndex].groups : []
    }
}

// MARK: - Tresor fehlt

@MainActor
@Observable
public final class MissingVaultState {
    public var backups: [BackupInfo] = []
    public var selection: URL?
    public var password = ""
    public var error: String?
    public var confirmingNewVault = false
    /// Faktoren der gewählten Sicherung (falls sie welche verlangt).
    public internal(set) var collection: FactorCollection?
    /// Vom Nutzer gewählte Sicherungsdatei (z. B. vom USB-Stick), steht zuoberst in der Liste (Befund datei-3).
    public internal(set) var chosenFile: URL?
    /// Aus der Einrichtung gekommen („Aus Sicherung wiederherstellen…“): Titel „Sicherung wiederherstellen“,
    /// „Zurück“ statt „Neuen leeren Tresor anlegen…“.
    public internal(set) var fromSetup = false
    /// Die Sicherungen werden im Hintergrund gelesen (Befund ablaeufe-10).
    public internal(set) var searching = false
    /// Laufende Nummer der Suche (ältere Ergebnisse werden verworfen).
    var searchRun = 0

    public init() {}

    public var selectedBackup: BackupInfo? {
        backups.first { $0.url == selection }
    }
}

// MARK: - Beschädigt

@MainActor
@Observable
public final class CorruptState {
    public enum Kind: Sendable, Equatable {
        case damaged
        case newerVersion(UInt16)
    }

    public var kind: Kind = .damaged
    /// Das eben eingegebene Master-Passwort (nur solange dieser Bildschirm offen ist).
    public var password = ""
    public var error: String?
    var vault: UnlockedVault?
    public var restoredBackup: BackupInfo?
    public var entryCount = 0
    /// Kit-Kennung des geöffneten Stands und ob sie bestätigt ist (Befund #3).
    public var kitID = ""
    public var kitConfirmed = true
    /// Faktoren der Sicherung (falls sie welche verlangt).
    public internal(set) var collection: FactorCollection?
    /// Sicherungsdatei, für die `collection` gilt („Sicherung aus Datei einspielen…“); nil = neueste lesbare.
    var collectionFile: URL?

    public init() {}
}

// MARK: - Rollback-Frage

@MainActor
@Observable
public final class RollbackState {
    let vault: UnlockedVault
    public let seenGeneration: UInt64
    public let fileGeneration: UInt64

    init(vault: UnlockedVault, seenGeneration: UInt64, fileGeneration: UInt64) {
        self.vault = vault
        self.seenGeneration = seenGeneration
        self.fileGeneration = fileGeneration
    }
}

// MARK: - Einstellungen

@MainActor
@Observable
public final class SettingsState {
    public enum Page: Sendable, Equatable {
        case overview
        case changePassword
        /// Profilwechsel: Master-Passwort erneut abfragen.
        case kdfProfile(strong: Bool)
        case checkCode
        /// Notfallkit nicht bestätigt: vorhandenes Blatt prüfen oder neues Kit.
        case unconfirmedKit
        /// Neues Notfallkit: Master-Passwort erneut abfragen.
        case newKit
        /// Nach einem Zugangswechsel: alte Sicherungen entfernen? (keine anderen Ausgänge, Befund #34)
        case purgeBackups(PurgeReason)
        /// „Ältere Sicherungen entfernen…“ (Befund #41): Master-Passwort, dann alle Sicherungen weg.
        case purgeOld
        /// Automatisches Ausfüllen: ehrlicher Stand (§20)
        case autofill
        /// Info → Lizenzen (Befund #44)
        case licenses
        /// Übersicht der fünf Sicherheitsstufen (§13)
        case securityLevel
        /// Stufen-Assistent bzw. Faktoren für Einträge einrichten (`model.wizard`)
        case wizard
        /// Selbstvernichtung (SPEC v4.3 §23, nur Stufe 4/5; `model.destructionState`)
        case destruction
    }

    public enum CodeCheckResult: Sendable, Equatable {
        case exact
        case corrected(formatted: String, changedPositions: [Int])
    }

    public var page: Page = .overview
    public var currentPassword = ""
    public var newPassword = ""
    public var newPasswordRepeat = ""
    public var code = ""
    public var codeResult: CodeCheckResult?
    /// Notfallcode in Teilen (Stufen 4/5, §15): zwei Teile prüfen bzw. als bestätigt markieren.
    public var shares = ["", ""]
    public var shareResult: [CodeCheckResult]?
    public var error: String?
    public var fileVaultEncrypted: Bool?
    /// Aktuelle Faktoren für heikle Aktionen (Passwortwechsel, Profil, neues Kit) ab Stufe 2.
    public internal(set) var collection: FactorCollection?
    /// In der Stufen-Übersicht gewählte Zielstufe.
    public var chosenLevel: SecurityLevel?
    @ObservationIgnored private var cache = AssessmentCache()

    public init() {}

    public var assessment: PasswordAssessment { cache.assess(newPassword) }
    public var repeatMatches: Bool {
        !newPasswordRepeat.isEmpty && PasswordNormalization.equal(newPassword, newPasswordRepeat)
    }

    func resetFields() {
        currentPassword = ""
        newPassword = ""
        newPasswordRepeat = ""
        code = ""
        codeResult = nil
        shares = ["", ""]
        shareResult = nil
        error = nil
        collection?.reset()
        collection = nil
        cache.clear()
    }
}

/// Anlass der Frage „Alte Sicherungen entfernen?“ (SPEC §4).
public enum PurgeReason: String, Sendable, Equatable, Codable {
    case passwordChange
    case newKit
    case levelChange

    var title: String {
        switch self {
        case .passwordChange: "Master-Passwort geändert"
        case .newKit: "Neues Notfallkit gespeichert"
        case .levelChange: "Sicherheitsstufe geändert"
        }
    }

    var question: String {
        switch self {
        case .passwordChange: "Die bisherigen Sicherungen lassen sich mit dem alten Passwort öffnen. Entfernen?"
        case .newKit: "Die bisherigen Sicherungen lassen sich mit dem alten Notfallcode öffnen. Entfernen?"
        case .levelChange: "Die bisherigen Sicherungen lassen sich mit dem bisherigen Zugang öffnen – mit der alten Stufe und ihren Faktoren. Entfernen?"
        }
    }

    var keptNotice: String {
        switch self {
        case .passwordChange: "Master-Passwort geändert"
        case .newKit: "Neues Notfallkit gespeichert"
        case .levelChange: "Sicherheitsstufe geändert"
        }
    }
}

/// Abläufe, die Stufe 2 baut (Einstiegspunkte im AppModel, SPEC §7.7–7.9).
public enum PendingFlow: Sendable, Hashable {
    case csvImport
    case csvExport
    case backupExport
    case backupImport
    /// KeePass-Export KDBX 4.1 (§19)
    case keepassExport
}

/// Befehle aus dem Menü für die Tresor-Ansicht (Stufe 2).
public enum VaultCommand: Sendable, Equatable {
    case newEntry
    case find
    case edit
}

/// Dezente Rückmeldezeile.
public struct Notice: Equatable, Sendable, Identifiable {
    public let id = UUID()
    public var text: String
    public var symbol: String

    public init(_ text: String, symbol: String = "checkmark") {
        self.text = text
        self.symbol = symbol
    }
}
