import Foundation
import Observation
import SiegelCore

// Selbstvernichtung (SPEC v4.3 §23): Entwurf der Einstellungen, Regeln für den Sperrbildschirm und Texte.
// Nur Tresor-Stufe 4/5, nur Einträge mit Schutz 4/5. Die Oberfläche liest den Zustand über §23.3
// (`destructionStatus`, `destroyedEntries`, `isDuressSession`) und die markierten Einträge über `destructibleEntries`
// (Zusatz des Kerns zu §23.3, siehe `DestructionAccess`).

/// Einziger Zugriff auf die vernichtbaren Einträge (`UnlockedVault.destructibleEntries`, Zusatz zu §23.3; in einer
/// Vernichtungs-Sitzung leer). Die Oberfläche braucht sie für die Auswahl in den Einstellungen und die Markierung
/// „vernichtbar“ im Detail.
enum DestructionAccess {
    static func destructible(_ vault: UnlockedVault) -> Set<UUID> {
        vault.destructibleEntries
    }
}

/// Grenzen aus §23.2 und die Auswahl, die die Oberfläche anbietet.
public enum DestructionRules {
    public static let deadmanRange = DestructionSettings.deadmanDaysRange
    public static let attemptsRange = DestructionSettings.maxFailedAttemptsRange
    public static let deadmanChoices = [7, 14, 30, 90, 180, 365]
    public static let attemptsChoices = [10, 20, 30, 50, 100]
    public static let defaultDeadmanDays = 30
    public static let defaultAttempts = 20
    /// Wort, das beim Einschalten abgetippt wird.
    public static let confirmWord = "VERNICHTEN"
    /// Einträge, die sich markieren lassen (§23: Schutz 4/5).
    public static func isSelectable(_ entry: VaultEntry) -> Bool {
        entry.protection >= .maximal && entry.deletedAt == nil
    }

    /// Frist auf dem Sperrbildschirm erst ab 25 % Restzeit (§23.2, `deadlineIsNear` des Kerns); abgelaufen → nichts.
    /// Nach einer Vernichtung ebenfalls nichts (Befund hygiene-5): Der Totmann-Schalter löst dann nicht mehr aus, und
    /// eine stehen gebliebene Frist verriete nach einer Vernichtungs-Sitzung, dass nicht das Master-Passwort genannt
    /// wurde (es hätte sie verschoben). Der Vermerk steht in `zustand.json`, gilt also auch nach einem Neustart.
    public static func showsDeadline(_ status: DestructionStatus?, now: Date) -> Date? {
        guard let status, status.destroyedAt == nil, status.settings.deadmanDays != nil, let ende = status.deadline,
              ende > now, status.deadlineIsNear(now: now) else { return nil }
        return ende
    }

    /// Verbleibende Versuche ab N/2 Fehlversuchen (§23.2, Regel des Kerns); nil = keine Warnung (auch bei 0).
    public static func remainingAttempts(_ status: DestructionStatus?) -> Int? {
        guard let status, status.shouldWarnAboutAttempts, let rest = status.remainingAttempts, rest > 0 else {
            return nil
        }
        return rest
    }

    /// Ist überhaupt ein Auslöser an?
    public static func isActive(_ settings: DestructionSettings?) -> Bool {
        settings?.anyTriggerEnabled ?? false
    }

    /// Ist die Selbstvernichtung eingerichtet – ein Auslöser an oder Einträge markiert (Schlüssel V)? Massgeblich
    /// für die Warnung im Notfallweg (Befund ablaeufe-5): Markierte Einträge fallen dort auch ohne Auslöser weg.
    public static func isConfigured(_ status: DestructionStatus?) -> Bool {
        guard let status else { return false }
        return status.settings.anyTriggerEnabled || status.keyConfigured
    }
}

/// Texte der Selbstvernichtung (Schweiz, per du).
public enum DestructionTexts {
    public static let title = "Selbstvernichtung"
    public static let intro = "Vernichtet ausgewählte Einträge endgültig, wenn ein Auslöser greift. Der Tresor und alle anderen Einträge bleiben, wie sie sind."
    public static let noRecovery = "Für vernichtbare Einträge gibt es keinen Notfallweg – auch der Notfallcode öffnet sie nicht. Vernichtet heisst: für immer weg, auch in jeder Sicherung."
    public static let noRecoveryShort = "Kein Notfallweg"
    public static let honest = "Ehrlich: Wer die Festplatte vorher kopiert, umgeht Zähler und Totmann-Schalter. Die Vernichtung wirkt trotzdem, weil der Schlüssel dazu nur in der Secure Enclave dieses Macs liegt und deinen Finger braucht. Auf einer SSD ohne FileVault können Reste liegen bleiben – nutzbar nur mit diesem Mac und deinem Finger. Läuft Siegel nie, vernichtet der Totmann-Schalter nichts."
    public static let deadmanText = "Vernichtet, wenn du Siegel so lange nicht mit dem Master-Passwort entsperrt hast. Geprüft beim Start, beim Aktivieren und alle 10 Minuten. Ab einem Viertel der Restzeit zeigt der Sperrbildschirm die Frist."
    public static let counterText = "Vernichtet nach so vielen falschen Passwörtern in Folge. Ab der Hälfte warnt Siegel bei jeder Eingabe des Master-Passworts – auch beim Wiederherstellen einer Sicherung. Deine eigenen Tippfehler zählen mit."
    public static let duressText = "Ein zweites Passwort für den Notfall, wenn du eines nennen musst: Es öffnet den Tresor scheinbar normal und vernichtet vorher still die ausgewählten Einträge. Es muss sich vom Master-Passwort unterscheiden."
    public static let duressEqualsMaster = "Das Vernichtungs-Passwort muss sich vom Master-Passwort unterscheiden."
    public static let onlyLevel = "Nur in den Stufen Maximal und Festung."
    public static let recoveryDropsDestructible = "Für die Selbstvernichtung markierte Einträge haben keinen Notfallweg: Sie fallen bei der Wiederherstellung weg, und die Selbstvernichtung ist danach aus."
    public static let levelBlocked = "Schalte zuerst die Selbstvernichtung aus (Sicherheitsstufe → Selbstvernichtung) – sie gibt es nur in den Stufen Maximal und Festung."
    public static let confirmWordHint = "Tippe VERNICHTEN, um einzuschalten."
    public static let confirmWordWrong = "Tippe VERNICHTEN in Grossbuchstaben, um einzuschalten."
    public static let destroyedDetail = "Passwort, Notizen, frühere Passwörter und 2FA-Code sind nicht mehr lesbar – auch nicht mit dem Notfallcode."

    public static func trigger(_ t: DestructionTrigger?) -> String {
        switch t {
        case .deadman: "Totmann-Schalter"
        case .failedAttempts: "Fehlversuch-Zähler"
        case .duressPassword: "Vernichtungs-Passwort"
        case nil: "Selbstvernichtung"
        }
    }

    public static func days(_ n: Int) -> String { n == 1 ? "1 Tag" : "\(n) Tage" }

    public static func attempts(_ n: Int) -> String { "Nach \(n) Fehlversuchen" }

    /// „Noch 4 Versuche bis zur Vernichtung“
    public static func remaining(_ n: Int) -> String {
        n == 1 ? "Noch 1 Versuch bis zur Vernichtung" : "Noch \(n) Versuche bis zur Vernichtung"
    }

    /// „Frist endet am 17. November 2026 um 09:12“
    public static func deadline(_ date: Date) -> String { "Frist endet am " + Anzeige.datum(date) }

    /// Banner nach einer Vernichtung (§23.2): „3 Einträge wurden vernichtet“
    public static func destroyedTitle(_ n: Int) -> String {
        switch n {
        case 0: "Selbstvernichtung ausgelöst"
        case 1: "1 Eintrag wurde vernichtet"
        default: "\(n) Einträge wurden vernichtet"
        }
    }

    /// Markierte Einträge ohne Auslöser (Befund ablaeufe-5): nichts wird vernichtet, der Notfallweg fehlt trotzdem.
    public static let marksWithoutTrigger = "Ohne Auslöser wird nichts vernichtet – die markierten Einträge haben trotzdem keinen Notfallweg."

    /// Kurzstand für die Zeile in den Einstellungen (ohne Anzahl der Einträge). `configured`: Einträge markiert bzw.
    /// Schlüssel V eingerichtet – dann nie „Aus“, auch ohne Auslöser (Befund ablaeufe-5).
    public static func summary(_ settings: DestructionSettings?, configured: Bool = false) -> String {
        guard let settings, DestructionRules.isActive(settings) else {
            return configured ? "Einträge markiert · kein Auslöser" : "Aus"
        }
        var teile: [String] = []
        if let d = settings.deadmanDays { teile.append("Totmann " + days(d)) }
        if let n = settings.maxFailedAttempts { teile.append("Zähler \(n)") }
        if settings.duressEnabled { teile.append("Vernichtungs-Passwort") }
        return "An · " + teile.joined(separator: " · ")
    }

    /// Fehler beim Sichern der Einstellungen.
    public static func error(_ error: SiegelError, wrongPassword: String) -> String {
        switch error {
        case .wrongPassword:
            return wrongPassword
        case .passwordTooWeak:
            return "Das Vernichtungs-Passwort ist zu schwach. Nötig sind mindestens 12 Zeichen und 60 Bit."
        case .masterPasswordReused:
            return duressEqualsMaster
        case .notAllowedAtLevel:
            return "Die Selbstvernichtung gibt es nur in den Stufen Maximal und Festung und nur für Einträge mit Schutz 4 oder 5. Öffne die Seite neu."
        case .factorMissing(.secureEnclave):
            return "Für die Selbstvernichtung braucht es einen eigenen Touch-ID-Schlüssel. Versuche es erneut."
        case .factorCancelled:
            return "Abgebrochen. Nichts wurde geändert."
        default:
            return Fehlertexte.text(error)
        }
    }
}

// MARK: - Entwurf der Einstellungen

/// Einstellungen → Sicherheitsstufe → Selbstvernichtung: Entwurf (Auswahl, Auslöser, Vernichtungs-Passwort) und
/// Bestätigung (VERNICHTEN, Master-Passwort, alle Faktoren). Geschrieben wird erst mit `configureDestruction`.
@MainActor
@Observable
public final class DestructionState {
    public enum Step: Sendable, Equatable {
        case edit
        case confirm
    }

    public var step: Step = .edit
    // Gespeicherter Stand (beim Öffnen bzw. nach dem letzten Sichern gelesen)
    public internal(set) var savedDestructible: Set<UUID>
    public internal(set) var savedDeadmanDays: Int?
    public internal(set) var savedMaxAttempts: Int?
    public internal(set) var savedDuress: Bool
    /// Vernichtung schon geschehen (Vernichtungs-Schlüssel weg) – nur echte Sitzung. Dann lässt der Kern erst nach
    /// „Entfernen“ wieder Änderungen zu (`io("destruction.destroyed")`); die Seite ist bis dahin gesperrt.
    public internal(set) var destroyed: Bool
    /// Ein gültiger Vernichtungs-Schlüssel V ist eingerichtet (`UnlockedVault.destructionKeyID`).
    public internal(set) var keyAvailable: Bool

    // Entwurf
    public var selection: Set<UUID>
    public var deadmanOn: Bool
    public var deadmanDays: Int
    public var counterOn: Bool
    public var maxAttempts: Int
    /// Vernichtungs-Passwort im Entwurf an (das gespeicherte bleibt, ausser ein neues wird eingegeben).
    public var duressOn: Bool
    /// Eingabefelder für ein neues Vernichtungs-Passwort sind offen.
    public var duressEditing = false
    public var duressPassword = ""
    public var duressRepeat = ""

    // Bestätigung
    public var confirmWord = ""
    public var masterPassword = ""
    public var error: String?
    /// Faktoren der Stufe (jede Änderung verlangt alle, §23.3).
    public internal(set) var collection: FactorCollection?
    /// Der Vernichtungs-Schlüssel wird gerade mit Touch ID angelegt.
    public internal(set) var creatingKey = false
    @ObservationIgnored private var cache = AssessmentCache()

    public init(status: DestructionStatus?, destructible: Set<UUID>, destroyed: Bool, keyAvailable: Bool) {
        let s = status?.settings
        savedDestructible = destructible
        savedDeadmanDays = s?.deadmanDays
        savedMaxAttempts = s?.maxFailedAttempts
        savedDuress = s?.duressEnabled ?? false
        self.destroyed = destroyed
        self.keyAvailable = keyAvailable
        selection = destructible
        deadmanOn = s?.deadmanDays != nil
        deadmanDays = s?.deadmanDays ?? DestructionRules.defaultDeadmanDays
        counterOn = s?.maxFailedAttempts != nil
        maxAttempts = s?.maxFailedAttempts ?? DestructionRules.defaultAttempts
        duressOn = s?.duressEnabled ?? false
    }

    public var duressAssessment: PasswordAssessment { cache.assess(duressPassword) }

    public var duressRepeatMatches: Bool {
        !duressRepeat.isEmpty && PasswordNormalization.equal(duressPassword, duressRepeat)
    }

    /// Neues Vernichtungs-Passwort (nil = unverändert bzw. aus).
    public var newDuressPassword: String? { duressOn && duressEditing ? duressPassword : nil }

    /// Vernichtungs-Passwort im Entwurf vollständig (aus, unverändert gesetzt oder neu und gültig).
    public var duressReady: Bool {
        guard duressOn else { return true }
        if duressEditing { return duressAssessment.meetsPolicy && duressRepeatMatches }
        return savedDuress
    }

    public var deadmanValue: Int? { deadmanOn ? deadmanDays : nil }
    public var attemptsValue: Int? { counterOn ? maxAttempts : nil }

    public var hasChanges: Bool {
        selection != savedDestructible || deadmanValue != savedDeadmanDays || attemptsValue != savedMaxAttempts
            || duressOn != savedDuress || (duressOn && duressEditing)
    }

    /// Schaltet etwas ein (neuer Auslöser oder neu markierte Einträge) → „VERNICHTEN“ abtippen.
    public var arms: Bool {
        (deadmanOn && savedDeadmanDays == nil) || (counterOn && savedMaxAttempts == nil)
            || (duressOn && !savedDuress) || !selection.subtracting(savedDestructible).isEmpty
    }

    public var canContinue: Bool { !destroyed && hasChanges && duressReady }

    public var confirmWordMatches: Bool {
        confirmWord.trimmingCharacters(in: .whitespaces) == DestructionRules.confirmWord
    }

    /// Selbstvernichtung nach dem Entwurf eingeschaltet (ein Auslöser oder markierte Einträge) – dann verlangt der
    /// Kern einen Vernichtungs-Schlüssel V.
    public var willBeActive: Bool {
        !selection.isEmpty || deadmanOn || counterOn || duressOn
    }

    /// Ein neuer Vernichtungs-Schlüssel V ist nötig: eingeschaltet, aber noch keiner eingerichtet (nie oder nach
    /// „Entfernen“). Nach einer Vernichtung zuerst „Entfernen“.
    public var needsNewKey: Bool {
        !destroyed && willBeActive && !keyAvailable
    }

    /// Werden Einträge neu markiert? Dann entfernt der Kern beim Sichern die älteren Sicherungen (sie enthielten die
    /// Einträge noch mit Notfallweg).
    public var marksNewEntries: Bool { !selection.subtracting(savedDestructible).isEmpty }

    /// Alles aus (Entwurf): keine Einträge, keine Auslöser.
    func turnEverythingOff() {
        selection = []
        deadmanOn = false
        counterOn = false
        duressOn = false
        duressEditing = false
        duressPassword = ""
        duressRepeat = ""
        cache.clear()
    }

    func cancelDuressEditing() {
        duressEditing = false
        duressOn = savedDuress
        duressPassword = ""
        duressRepeat = ""
        cache.clear()
    }

    /// Eingaben der Bestätigung verwerfen (zurück zum Entwurf).
    func resetConfirmation() {
        confirmWord = ""
        masterPassword = ""
        error = nil
        collection?.reset()
        collection = nil
        creatingKey = false
    }

    /// Alles Geheime verwerfen (Sperren, Verlassen der Seite).
    func wipe() {
        resetConfirmation()
        duressPassword = ""
        duressRepeat = ""
        cache.clear()
    }
}

/// Banner nach einer Vernichtung (nur in echter Sitzung).
public struct DestructionBanner: Equatable, Sendable {
    public let title: String
    /// Auslöser („Fehlversuch-Zähler“)
    public let trigger: String
    /// Datum („12.10.2026“)
    public let date: String
    /// „Fehlversuch-Zähler, 12.10.2026“
    public var detail: String { trigger + ", " + date }
}
