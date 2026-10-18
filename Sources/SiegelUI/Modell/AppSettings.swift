import Foundation
import Observation
import SiegelCore

/// Einstellungen (SPEC §6: `UserDefaults` nur für Einstellungen, nie für Inhalte).
@MainActor
@Observable
public final class AppSettings {
    public static let autoLockChoices = [1, 5, 15, 30]
    public static let clipboardChoices = [15, 30, 60, 90]

    enum Key {
        static let autoLock = "autoLockMinutes"
        static let clipboard = "clipboardSeconds"
        static let external = "showSecretsOnExternalDisplays"
        static let bookmark = "secondaryBackupBookmark"
        static let lastExternal = "lastExternalBackupAt"
        static let lastSecondary = "lastSecondaryBackupAt"
        static let pendingPurgeVault = "pendingSecondaryPurgeVaultID"
        static let pendingPurgeDate = "pendingSecondaryPurgeBefore"
        static let entryProtection = "defaultEntryProtection"
        static let purgeQuestionVault = "pendingPurgeQuestionVaultID"
        static let purgeQuestionReason = "pendingPurgeQuestionReason"
        static let rollbackVault = "acceptedRollbackVaultID"
        static let rollbackGeneration = "acceptedRollbackGeneration"
        static let rollbackDigest = "acceptedRollbackDigest"
    }

    @ObservationIgnored private let defaults: UserDefaults

    /// Auto-Sperre in Minuten (1/5/15/30, Standard 5).
    public var autoLockMinutes: Int {
        didSet { defaults.set(autoLockMinutes, forKey: Key.autoLock) }
    }

    /// Zwischenablage leeren nach Sekunden (15/30/60/90, Standard 30).
    public var clipboardSeconds: Int {
        didSet { defaults.set(clipboardSeconds, forKey: Key.clipboard) }
    }

    /// Geheimnisse auf externen Bildschirmen zeigen (Standard aus).
    public var showSecretsOnExternalDisplays: Bool {
        didSet { defaults.set(showSecretsOnExternalDisplays, forKey: Key.external) }
    }

    /// Security-scoped Bookmark des zweiten Sicherungsorts (App-Ebene).
    public var secondaryBackupBookmark: Data? {
        didSet { defaults.set(secondaryBackupBookmark, forKey: Key.bookmark) }
    }

    /// Zeitpunkt der letzten Sicherung ausserhalb dieses Macs.
    public var lastExternalBackupAt: Date? {
        didSet { defaults.set(lastExternalBackupAt, forKey: Key.lastExternal) }
    }

    /// Zeitpunkt der letzten Kopie am zweiten Sicherungsort (SPEC §6 „Zeit der letzten externen Sicherung“).
    public var lastSecondaryBackupAt: Date? {
        didSet { defaults.set(lastSecondaryBackupAt, forKey: Key.lastSecondary) }
    }

    /// Ausstehendes Entfernen am zweiten Ort (nach „Alte Sicherungen entfernen“, als der Ort nicht erreichbar
    /// war): vaultID und Zeitpunkt; alle Kopien dieser vaultID von davor werden nachgeholt entfernt. Nur
    /// Kennung und Zeit, kein Inhalt (SPEC v3.1 §6).
    public var pendingSecondaryPurge: (vaultID: UUID, before: Date)? {
        didSet {
            defaults.set(pendingSecondaryPurge?.vaultID.uuidString, forKey: Key.pendingPurgeVault)
            defaults.set(pendingSecondaryPurge?.before, forKey: Key.pendingPurgeDate)
        }
    }

    /// Vorgabe für den Schutz neuer Einträge (§16, 1–5). Die Stufe kann sie anheben (Stufe 4/5: mindestens 2).
    public var defaultEntryProtection: EntryProtection {
        didSet { defaults.set(defaultEntryProtection.rawValue, forKey: Key.entryProtection) }
    }

    /// Offene Frage „Alte Sicherungen entfernen?“ nach einem Zugangswechsel (Befund #34): bleibt über Sperren und
    /// Neustart stehen, bis sie beantwortet ist. Nur Kennung und Anlass, kein Inhalt.
    public var pendingPurgeQuestion: PendingPurgeQuestion? {
        didSet {
            defaults.set(pendingPurgeQuestion?.vaultID.uuidString, forKey: Key.purgeQuestionVault)
            defaults.set(pendingPurgeQuestion?.reason.rawValue, forKey: Key.purgeQuestionReason)
        }
    }

    /// Bewusst angenommene ältere Tresordatei (Befund #28/#33): vaultID, Generation und SHA-256 genau dieser
    /// verschlüsselten Datei. Dieselbe Datei fragt dann nicht bei jedem Entsperren erneut; jede andere ältere
    /// Datei warnt weiter. Nicht geheim (der Prüfwert eines Chiffrats).
    public var acceptedRollback: AcceptedRollback? {
        didSet {
            defaults.set(acceptedRollback?.vaultID.uuidString, forKey: Key.rollbackVault)
            defaults.set(acceptedRollback.map { String($0.generation) }, forKey: Key.rollbackGeneration)
            defaults.set(acceptedRollback?.digest, forKey: Key.rollbackDigest)
        }
    }

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let id = defaults.string(forKey: Key.purgeQuestionVault).flatMap(UUID.init(uuidString:)),
           let reason = defaults.string(forKey: Key.purgeQuestionReason).flatMap(PurgeReason.init(rawValue:)) {
            pendingPurgeQuestion = PendingPurgeQuestion(vaultID: id, reason: reason)
        } else {
            pendingPurgeQuestion = nil
        }
        if let id = defaults.string(forKey: Key.rollbackVault).flatMap(UUID.init(uuidString:)),
           let generation = defaults.string(forKey: Key.rollbackGeneration).flatMap(UInt64.init),
           let digest = defaults.data(forKey: Key.rollbackDigest), digest.count == 32 {
            acceptedRollback = AcceptedRollback(vaultID: id, generation: generation, digest: digest)
        } else {
            acceptedRollback = nil
        }
        defaultEntryProtection = EntryProtection(rawValue: defaults.integer(forKey: Key.entryProtection)) ?? .normal
        let minuten = defaults.object(forKey: Key.autoLock) as? Int ?? 5
        autoLockMinutes = Self.autoLockChoices.contains(minuten) ? minuten : 5
        let sekunden = defaults.object(forKey: Key.clipboard) as? Int ?? 30
        clipboardSeconds = Self.clipboardChoices.contains(sekunden) ? sekunden : 30
        showSecretsOnExternalDisplays = defaults.bool(forKey: Key.external)
        secondaryBackupBookmark = defaults.data(forKey: Key.bookmark)
        lastExternalBackupAt = defaults.object(forKey: Key.lastExternal) as? Date
        lastSecondaryBackupAt = defaults.object(forKey: Key.lastSecondary) as? Date
        if let id = defaults.string(forKey: Key.pendingPurgeVault).flatMap(UUID.init(uuidString:)),
           let date = defaults.object(forKey: Key.pendingPurgeDate) as? Date {
            pendingSecondaryPurge = (id, date)
        } else {
            pendingSecondaryPurge = nil
        }
    }
}

/// Eine bewusst angenommene ältere Tresordatei (siehe `AppSettings.acceptedRollback`).
public struct AcceptedRollback: Sendable, Equatable {
    public let vaultID: UUID
    public let generation: UInt64
    /// SHA-256 der ganzen Datei.
    public let digest: Data
}
