import Foundation
import Observation
import SiegelCore

// Zustände der Tresor-Ansicht (Stufe 2). Wie in Stufe 1 liegen sie im AppModel, nicht in @State:
// Sperren ersetzt sie durch neue Instanzen, Snapshots können sie füllen.

/// Auswahl, Modus und Aufdeck-Zustände der Tresor-Ansicht.
@MainActor
@Observable
public final class VaultBrowserState {
    public enum Mode: Sendable, Equatable {
        /// Liste + Detail
        case browse
        /// Bearbeiten (oder neuer Eintrag) mit Generator
        case edit
        /// „Zuletzt gelöscht“
        case trash
        /// Offline-Sicherheitsbericht (§17)
        case report
    }

    public var mode: Mode = .browse
    public var selection: UUID?
    /// Eintrag, dessen Passwort gerade aufgedeckt ist (nur einer, fällt beim Auswahlwechsel weg).
    public var revealedPassword: UUID?
    public var historyExpanded = false
    /// Aufgedeckte Zeilen im Verlauf (Index in `history`).
    public var revealedHistory: Set<Int> = []
    public var confirmingClearHistory = false
    public var editor: EntryEditorState?
    /// „Zuletzt gelöscht“: Eintrag, dessen endgültiges Löschen gerade bestätigt wird.
    public var confirmingPurge: UUID?
    /// Fehlerzeile der Detailansicht (Speichern gescheitert usw.).
    public var error: String?
    /// Zähler, die die Ansicht beobachtet, um den Fokus zu setzen (⌘F, Pfeil aus der Suche).
    public var searchFocusRequest = 0
    public var listFocusRequest = 0
    /// Aufgedeckte Geheimteile (geschützter Eintrag bzw. Stufe 3+): nur einer, fällt beim Auswahlwechsel weg.
    public internal(set) var unlockedSecrets: UnlockedSecrets?
    /// Eintrag, dessen Faktoren gerade eingesammelt werden (Touch ID, Karte, Schlüssel).
    public internal(set) var revealing: UUID?

    public init() {}

    /// Aufdeck-Zustände beim Wechsel der Auswahl verwerfen.
    func resetDetailState() {
        revealedPassword = nil
        historyExpanded = false
        revealedHistory = []
        confirmingClearHistory = false
        error = nil
        unlockedSecrets = nil
    }
}

/// Aufgedeckte Geheimteile eines Eintrags (nur im Speicher, geschwärzte Beschreibung über `EntrySecrets`).
public struct UnlockedSecrets: Sendable, Equatable {
    public let id: UUID
    public var secrets: EntrySecrets
}

/// Bearbeiten eines Eintrags (oder neuer Eintrag) mit eingebautem Generator (SPEC §7.5, §6 b).
@MainActor
@Observable
public final class EntryEditorState {
    /// Stand beim Öffnen (nil = neuer Eintrag).
    public let original: VaultEntry?
    public var draft: VaultEntry
    /// Der Eintrag existiert im Tresor (bestehend oder durch „Übernehmen“ angelegt).
    public internal(set) var persisted: Bool
    /// Mindestens ein Generator-Passwort wurde mit „Übernehmen“ gespeichert.
    public internal(set) var appliedGenerated = false
    public var generatorOpen = false
    public var options = PasswordGenerator.Options()
    /// Aktuelles Generator-Ergebnis (Geheimnis, nur im Speicher).
    public var generated = ""
    public var error: String?
    /// Versiegelte Geheimteile noch nicht aufgedeckt: Passwort, Notizen und 2FA sind gesperrt (Titel, Benutzer und
    /// Website lassen sich ohne Faktoren ändern, §16).
    public internal(set) var secretsLocked = false
    /// Geheimteile beim Aufdecken (für den Verlauf und „Abbrechen nach Übernehmen“).
    @ObservationIgnored var baseline: EntrySecrets?
    @ObservationIgnored var initialSecrets: EntrySecrets?

    public init(original: VaultEntry?, secrets: EntrySecrets? = nil) {
        self.original = original
        var entwurf = original ?? VaultEntry()
        self.persisted = original != nil
        if let original {
            if let secrets {
                entwurf.password = secrets.password
                entwurf.notes = secrets.notes
                entwurf.totp = secrets.totp
                entwurf.history = secrets.history
                baseline = secrets
            } else if original.secretsSealed {
                secretsLocked = true
            } else {
                baseline = EntrySecrets(password: original.password, notes: original.notes, totp: original.totp,
                                        history: original.history)
            }
        }
        initialSecrets = baseline
        self.draft = entwurf
    }

    public var isNew: Bool { original == nil }

    /// Schutz beim Öffnen (neuer Eintrag: normal).
    public var originalProtection: EntryProtection { original?.protection ?? .normal }

    /// Läuft das Speichern über die versiegelten Geheimteile (`setProtection`) statt über `upsert`?
    public var usesSealedPath: Bool { originalProtection > .normal || draft.protection > .normal }

    /// Geheimteile im Formular nach dem Aufdecken (nil = gesperrt).
    var draftSecrets: EntrySecrets? {
        guard !secretsLocked else { return nil }
        return EntrySecrets(password: draft.password, notes: draft.notes, totp: draft.totp, history: baseline?.history ?? [])
    }

    var metadataChanged: Bool {
        guard let original else { return true }
        return original.title != draft.title || original.username != draft.username || original.url != draft.url
    }

    var secretsChanged: Bool {
        guard !secretsLocked else { return false }
        guard let baseline else { return !draft.password.isEmpty || !draft.notes.isEmpty || !draft.totp.isEmpty }
        return baseline.password != draft.password || baseline.notes != draft.notes || baseline.totp != draft.totp
    }

    /// Hat sich gegenüber dem Öffnen etwas geändert?
    public var hasChanges: Bool {
        guard let original else { return !EntryRules.isBlank(draft) }
        return metadataChanged || secretsChanged || original.protection != draft.protection
    }

    /// Feldgrenzen (SPEC §3) verletzt? Dann Meldung statt Speichern.
    public var limitViolation: String? { EntryRules.limitViolation(draft) }

    public var entropyBits: Int { Int(PasswordGenerator.entropyBits(options).rounded()) }
}

/// Regeln für Einträge, die die Oberfläche selbst prüft (Grenzen wie im Kern, Titel-Ersatz).
enum EntryRules {
    static let maxShort = 2048
    static let maxPassword = 4096
    static let maxNotes = 262_144

    static func isBlank(_ entry: VaultEntry) -> Bool {
        entry.title.isEmpty && entry.username.isEmpty && entry.password.isEmpty && entry.url.isEmpty
            && entry.notes.isEmpty && entry.totp.isEmpty
    }

    /// Verlauf nach einem Passwortwechsel an versiegelten Geheimteilen (die Oberfläche pflegt ihn hier selbst,
    /// weil der Kern das alte Passwort ohne Faktoren nicht kennt): altes Passwort hinein, das aktuelle nie.
    static func history(after baseline: EntrySecrets, newPassword: String, now: Date = Date()) -> [PasswordHistoryItem] {
        var verlauf = baseline.history
        if baseline.password != newPassword, !baseline.password.isEmpty {
            verlauf.append(PasswordHistoryItem(password: baseline.password, changed: now))
        }
        verlauf.removeAll { $0.password == newPassword }
        verlauf.sort { $0.changed > $1.changed }
        return Array(verlauf.prefix(30))
    }

    static func sameContent(_ a: VaultEntry, _ b: VaultEntry) -> Bool {
        a.title == b.title && a.username == b.username && a.password == b.password && a.url == b.url
            && a.notes == b.notes
    }

    static let maxTotp = 2048

    static func limitViolation(_ entry: VaultEntry) -> String? {
        if entry.totp.utf8.count > maxTotp { return "Das 2FA-Geheimnis ist zu lang (höchstens 2 KiB)." }
        if entry.title.utf8.count > maxShort { return "Der Titel ist zu lang (höchstens 2 KiB)." }
        if entry.username.utf8.count > maxShort { return "Der Benutzername ist zu lang (höchstens 2 KiB)." }
        if entry.url.utf8.count > maxShort { return "Die Website ist zu lang (höchstens 2 KiB)." }
        if entry.password.utf8.count > maxPassword { return "Das Passwort ist zu lang (höchstens 4 KiB)." }
        if entry.notes.utf8.count > maxNotes { return "Die Notizen sind zu lang (höchstens 256 KiB)." }
        return nil
    }

    /// Titel für das Speichern: eingegeben, sonst der Host der Website, sonst nil (ungültig).
    static func effectiveTitle(_ entry: VaultEntry) -> String? {
        let titel = entry.title.trimmingCharacters(in: .whitespacesAndNewlines)
        if !titel.isEmpty { return entry.title }
        if let host = Website.parse(entry.url)?.displayHost, !host.isEmpty { return host }
        return nil
    }

    /// „Entwurf 16.10.2026, 21:30“ für ungültige Bearbeitungen beim Sperren (SPEC §6 a).
    static func draftTitle(_ date: Date = Date()) -> String {
        "Entwurf " + Anzeige.kurz(date)
    }

    /// Kürzt ein Feld auf höchstens `limit` UTF-8-Bytes, ohne ein Zeichen zu zerschneiden.
    static func clamp(_ text: String, _ limit: Int) -> String {
        guard text.utf8.count > limit else { return text }
        var out = ""
        var bytes = 0
        for ch in text {
            let n = String(ch).utf8.count
            if bytes + n > limit { break }
            out.append(ch)
            bytes += n
        }
        return out
    }

    /// Letzter Ausweg beim Sperren: alle Felder in die Grenzen bringen (nur wenn das Speichern sonst scheitert).
    static func clamped(_ entry: VaultEntry) -> VaultEntry {
        var e = entry
        e.title = clamp(e.title, maxShort)
        e.username = clamp(e.username, maxShort)
        e.url = clamp(e.url, maxShort)
        e.password = clamp(e.password, maxPassword)
        e.notes = clamp(e.notes, maxNotes)
        e.totp = clamp(e.totp, maxTotp)
        return e
    }
}

/// Sortierte und gefilterte Liste (Zwischenspeicher nach `revision` und Suchtext).
struct VaultListCache {
    var revision: Int
    var query: String
    var entries: [VaultEntry]
}

// MARK: - Abläufe (CSV, Sicherungen)

/// Zwischenstände der Abläufe aus den Einstellungen und der Seitenleiste (SPEC §7.7–7.9).
@MainActor
@Observable
public final class FlowState {
    public enum Step: Sendable, Equatable {
        // CSV-Import
        case importIntro
        case importPreview
        case importReport
        // CSV-Export
        case exportIntro
        case exportUnencrypted
        case exportPassword
        case exportDone
        // Verschlüsselte Sicherung exportieren
        case backupExportIntro
        case backupExportDone
        // Sicherung einspielen
        case backupImportIntro
        case backupImportPassword
        // KeePass-Export (§19)
        case keepassIntro
        case keepassPassword
        case keepassDone
    }

    public let kind: PendingFlow
    public var step: Step
    public var error: String?
    /// Master-Passwort (CSV-Export, Sicherung einspielen); nur solange der Schritt offen ist.
    public var password = ""
    /// Faktoren (CSV-Export ab Stufe 2; Sicherung, die Faktoren verlangt).
    public internal(set) var collection: FactorCollection?

    // CSV-Import
    public internal(set) var sourceURL: URL?
    public internal(set) var importResult: CSVImportResult?
    public internal(set) var importPreview: ImportPreview?
    public internal(set) var importReport: ImportReport?
    /// nil = noch nicht entschieden, true = gelöscht, false = behalten
    public internal(set) var sourceDeleted: Bool?

    // CSV-Export
    public internal(set) var exportFolder: URL?
    public internal(set) var exportFolderEncrypted: Bool?
    public internal(set) var exportedURL: URL?

    // KeePass-Export: eigenes Export-Passwort (nur solange der Schritt offen ist)
    public var exportPassword = ""
    public var exportPasswordRepeat = ""
    @ObservationIgnored private var exportCache = AssessmentCache()
    /// Bewertung des Export-Passworts (MasterPasswordPolicy, §19).
    public var exportAssessment: PasswordAssessment { exportCache.assess(exportPassword) }
    public var exportRepeatMatches: Bool {
        !exportPasswordRepeat.isEmpty && PasswordNormalization.equal(exportPassword, exportPasswordRepeat)
    }

    func clearExportPasswords() {
        exportPassword = ""
        exportPasswordRepeat = ""
        exportCache.clear()
    }

    // Sicherungen
    public internal(set) var backupURL: URL?
    /// Sicherung liegt ausserhalb dieses Macs (anderes Volume oder iCloud Drive)?
    public internal(set) var backupIsExternal = false

    public init(_ kind: PendingFlow) {
        self.kind = kind
        switch kind {
        case .csvImport: step = .importIntro
        case .csvExport: step = .exportIntro
        case .backupExport: step = .backupExportIntro
        case .backupImport: step = .backupImportIntro
        case .keepassExport: step = .keepassIntro
        }
    }
}

/// Vorschau eines CSV-Imports (SPEC §7.8): Format, Anzahl, Spalten, Konflikte, 2FA-Hinweis.
public struct ImportPreview: Sendable, Equatable {
    public var format: CSVImportResult.Format
    public var count: Int
    /// Dubletten (gleicher Host, Benutzer, Passwort) – werden übersprungen.
    public var duplicates: Int
    /// Gleicher Host und Benutzer mit anderem Passwort – kommen als „… (Import)“ dazu.
    public var conflicts: Int
    public var withOTPSecret: Int
    public var movedToNotes: Int
    public var controlCharacters: Int
    public var apostrophePrefixed: Int
    /// Die ersten Titel (zur Kontrolle, ohne Passwörter).
    public var sample: [ImportSampleRow]

    public init(format: CSVImportResult.Format, count: Int, duplicates: Int, conflicts: Int, withOTPSecret: Int,
                movedToNotes: Int, controlCharacters: Int, apostrophePrefixed: Int, sample: [ImportSampleRow]) {
        self.format = format
        self.count = count
        self.duplicates = duplicates
        self.conflicts = conflicts
        self.withOTPSecret = withOTPSecret
        self.movedToNotes = movedToNotes
        self.controlCharacters = controlCharacters
        self.apostrophePrefixed = apostrophePrefixed
        self.sample = sample
    }

    /// Schätzt Dubletten und Konflikte wie `importEntries` (Host klein + IDNA, Benutzer, Passwort).
    public static func make(_ result: CSVImportResult, existing: [VaultEntry]) -> ImportPreview {
        var bestand: [String: [String]] = [:]
        for entry in existing {
            bestand[key(entry), default: []].append(entry.password)
        }
        var duplicates = 0
        var conflicts = 0
        for entry in result.entries {
            let k = key(entry)
            if let passwoerter = bestand[k] {
                if passwoerter.contains(entry.password) {
                    duplicates += 1
                    continue
                }
                conflicts += 1
            }
            bestand[k, default: []].append(entry.password)
        }
        let sample = result.entries.prefix(5).map {
            ImportSampleRow(title: $0.title.isEmpty ? (Website.parse($0.url)?.displayHost ?? "Ohne Titel") : $0.title,
                            username: $0.username)
        }
        return ImportPreview(format: result.format, count: result.entries.count, duplicates: duplicates,
                             conflicts: conflicts, withOTPSecret: result.report.withOTPSecret,
                             movedToNotes: result.report.movedToNotes,
                             controlCharacters: result.report.passwordsWithControlCharacters,
                             apostrophePrefixed: result.report.apostrophePrefixed, sample: Array(sample))
    }

    private static func key(_ entry: VaultEntry) -> String {
        (Website.parse(entry.url)?.asciiHost ?? entry.url.lowercased()) + "\u{1F}" + entry.username
    }
}

public struct ImportSampleRow: Sendable, Equatable, Hashable {
    public var title: String
    public var username: String
}
