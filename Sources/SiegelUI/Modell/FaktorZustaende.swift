import AppKit
import Foundation
import Observation
import SiegelCore
import SiegelHardware

// Zustände der Härtestufe (SPEC v4 §13–§16): Faktoren einsammeln, Karte scannen, Schlüssel berühren,
// Stufen-Assistent. Wie alle Formularzustände liegen sie im AppModel und werden beim Sperren verworfen.
// Faktor-Geheimnisse (`FactorSecret`) halten nur `@ObservationIgnored`-Felder; sie werden nach dem Aufruf
// fallen gelassen (sodium-Speicher, beim Freigeben genullt).

/// Stand eines einzelnen Faktors beim Einsammeln.
public enum FactorStepStatus: Sendable, Equatable {
    case pending
    case active
    case done
    case failed
}

/// Ein Faktor liess sich nicht einsammeln.
public struct FactorFailure: Sendable, Equatable {
    public let kind: FactorKind
    public let message: String
    /// Faktor ist auf diesem Mac nicht nutzbar: Notfallweg anbieten.
    public let offerRecovery: Bool
    /// Vom Nutzer abgebrochen (erneut versuchen genügt).
    public let cancelled: Bool
    /// Faktor geht gerade nicht (Touch ID gesperrt, Sensor nicht erreichbar, Schlüssel belegt): „Erneut versuchen“
    /// ist der Hauptknopf, kein Notfallweg (v4.4, Befund hardware-1).
    public let temporary: Bool
}

/// Sammelt die Faktoren ein, die ein Tresor-Kopf verlangt (Reihenfolge §13.1: Touch ID, Karte, Schlüssel).
@MainActor
@Observable
public final class FactorCollection {
    public let header: VaultHeaderInfo
    public internal(set) var status: [FactorKind: FactorStepStatus] = [:]
    public internal(set) var active: FactorKind?
    public internal(set) var failure: FactorFailure?
    @ObservationIgnored var secrets = FactorSecrets()

    public init(header: VaultHeaderInfo) {
        self.header = header
        for kind in header.factors.kinds { status[kind] = .pending }
    }

    public var kinds: [FactorKind] { header.factors.kinds }
    public var isEmpty: Bool { kinds.isEmpty }
    public var isComplete: Bool { kinds.allSatisfy { status[$0] == .done } }
    public var doneCount: Int { kinds.filter { status[$0] == .done }.count }

    /// Alle Geheimnisse verwerfen (nach jedem Versuch, beim Sperren).
    func reset() {
        secrets = FactorSecrets()
        for kind in kinds { status[kind] = .pending }
        active = nil
        failure = nil
    }

    func store(_ secret: FactorSecret, for kind: FactorKind) {
        switch kind {
        case .secureEnclave: secrets.secureEnclave = secret
        case .card: secrets.card = secret
        case .securityKey: secrets.securityKey = secret
        }
        status[kind] = .done
    }
}

// MARK: - Karte scannen

/// Kamera-Sheet für die QR-Schlüsselkarte (mit Abtipp-Notlösung).
@MainActor
@Observable
public final class CardScanState {
    public enum Purpose: Sendable, Equatable {
        /// Entsperren/Bestätigen: Karten-Kennung aus dem Kopf prüfen (nil = keine Prüfung möglich).
        case vault(vaultID: UUID, tag: Data?)
        /// Geschützter Eintrag: der Kern prüft.
        case entry
        /// Neu gedruckte Karte zur Bestätigung scannen.
        case confirmNew
    }

    public enum Camera: Sendable, Equatable {
        case starting
        case running
        /// Kein Kamerabild (Attrappe, Snapshot): Platzhalter
        case placeholder
        case denied
        case unavailable
    }

    public let purpose: Purpose
    public let title: String
    /// Kopfzeile im Kamera-Modus.
    public let message: String
    /// Kopfzeile beim Abtippen (Befund design-4: eigener Text, damit beide Modi stimmen – auch nach „Zur Kamera“).
    public let typingMessage: String
    public var typing = false
    public var typed = ""
    public var camera: Camera = .starting
    public var error: String?
    /// Kurz nach einer erfolgreichen Erkennung (Häkchen).
    public var recognized = false
    @ObservationIgnored var expected: FactorSecret?
    @ObservationIgnored var continuation: CheckedContinuation<FactorSecret, Error>?
    @ObservationIgnored var scanner: (any CardScanning)?

    /// Standard beim Abtippen: der Code steht auf der Karte rechts neben dem QR-Code (wie auf dem Kartenblatt).
    public static let defaultTypingMessage = "Tippe den Code ab, der auf der Karte neben dem QR-Code steht."

    init(purpose: Purpose, title: String, message: String, typingMessage: String = CardScanState.defaultTypingMessage) {
        self.purpose = purpose
        self.title = title
        self.message = message
        self.typingMessage = typingMessage
    }

    public var previewLayer: CALayer? { scanner?.previewLayer }
}

// MARK: - Sicherheitsschlüssel berühren

enum KeyTouchResult: Sendable {
    case secret(FactorSecret)
    case enrollment(SecurityKeyEnrollment, name: String)
}

@MainActor
@Observable
public final class KeyTouchState {
    public enum Purpose: Sendable, Equatable {
        case secret(credentialID: Data, salt: Data)
        case register
    }

    public enum Phase: Sendable, Equatable {
        /// Noch kein Schlüssel angeschlossen
        case searching
        /// Mehrere: auswählen
        case choose
        /// Wartet auf die Berührung (Name des Schlüssels)
        case touching(String)
    }

    public let purpose: Purpose
    public let title: String
    public let message: String
    public internal(set) var devices: [SecurityKeyChoice] = []
    public internal(set) var phase: Phase = .searching
    public var error: String?
    @ObservationIgnored var continuation: CheckedContinuation<KeyTouchResult, Error>?
    @ObservationIgnored var pollTask: Task<Void, Never>?
    @ObservationIgnored var attempt = 0
    /// Abbruch des laufenden Versuchs (v4.4, Befund hardware-4): „Abbrechen“ und Sperren setzen ihn, damit der
    /// Vorgang im Hintergrund nicht bis zur Berührung oder 30 s weiterläuft.
    @ObservationIgnored var cancellation: SecurityKeyCancellation?

    init(purpose: Purpose, title: String, message: String) {
        self.purpose = purpose
        self.title = title
        self.message = message
    }
}

// MARK: - Stufen-Assistent (§13) und Einrichten für Einträge (§16)

@MainActor
@Observable
public final class SecurityWizardState {
    public enum Mode: Sendable, Equatable {
        /// Tresor-Stufe wechseln
        case changeLevel(SecurityLevel)
        /// Faktoren für Einträge einrichten (`enrollFactors`)
        case enroll(FactorSet)
    }

    public enum Step: Sendable, Equatable {
        /// Vergleich: was sich ändert
        case intro
        /// Master-Passwort und aktuelle Faktoren
        case verify
        case touchID
        case card
        case securityKey
        /// Notfallkit (Code oder drei Teile) – zeigt den Notfallkit-Bildschirm
        case recovery
        /// Zusammenfassung und Schreiben
        case apply
        /// Alte Sicherungen entfernen?
        case done
    }

    public let mode: Mode
    public let from: SecurityLevel
    public let header: VaultHeaderInfo
    /// Für Einträge schon eingerichtete Faktoren (beim Öffnen des Assistenten).
    public let enrolledAtStart: FactorSet
    public internal(set) var steps: [Step] = []
    public internal(set) var step: Step = .intro
    public var password = ""
    public let collection: FactorCollection
    public internal(set) var verified = false
    public var error: String?
    /// Nach dem Einrichten zurück in die Bearbeitung des Eintrags.
    public var returnsToEditor = false

    // Touch ID
    public internal(set) var touchIDDone = false
    @ObservationIgnored var newSE: SEEnrollment?
    @ObservationIgnored var newEntryKey: EntryKeyEnrollment?

    // Karte
    public internal(set) var cardReuse = false
    @ObservationIgnored var cardQ: FactorSecret?
    /// Gruppierter Kartencode für Anzeige und Druck (Geheimnis, nur solange der Schritt offen ist).
    public internal(set) var cardText = ""
    public internal(set) var cardPayload = ""
    /// QR-Bild der Karte (aus SiegelHardware; nil = nicht verfügbar).
    @ObservationIgnored var cardImage: CGImage?
    public internal(set) var cardMethod: KitState.Method?
    public internal(set) var cardConfirmed = false
    public var cardPrintWarning = false
    public var cardPrintWarningText = ""
    public var cardPrintNotPaper = false
    @ObservationIgnored var cardPrintInfo: NSPrintInfo?

    // Sicherheitsschlüssel
    @ObservationIgnored var keyEnrollment: SecurityKeyEnrollment?
    public internal(set) var keyName: String?
    /// Für Einträge schon eingerichteter Schlüssel dient künftig auch zum Öffnen (Stufe 5): nicht neu registrieren,
    /// sondern die Ausgabe zum Entsperr-Salz holen (`UnlockedVault.securityKeyCredential`); der Kern prüft sie über
    /// den Prüfwert. Sonst wären Einträge mit Schutz 5 nur noch über den Notfallcode lesbar.
    public internal(set) var keyReuse = false
    @ObservationIgnored var keyReuseSecret: FactorSecret?

    // Notfallkit
    public internal(set) var kit: KitState?
    public internal(set) var recoveryConfirmed = false
    @ObservationIgnored var recoveryConfirmation: [String] = []

    /// Nach dem Schreiben (für die Frage nach alten Sicherungen).
    public internal(set) var applied = false

    init(mode: Mode, from: SecurityLevel, header: VaultHeaderInfo, enrolled: FactorSet) {
        self.mode = mode
        self.from = from
        self.header = header
        self.enrolledAtStart = enrolled
        self.collection = FactorCollection(header: header)
        steps = Self.plan(mode: mode, header: header, enrolled: enrolled)
        step = steps.first ?? .verify
        if case .changeLevel = mode, enrolled.contains(.securityKey), !header.factors.contains(.securityKey) {
            keyReuse = true
        }
    }

    public var target: SecurityLevel? {
        if case let .changeLevel(level) = mode { return level }
        return nil
    }

    /// Faktoren, die neu dazukommen (zum Öffnen bzw. für Einträge).
    public var newFactors: FactorSet {
        switch mode {
        case let .changeLevel(level): level.factors.subtracting(header.factors)
        case let .enroll(kinds): kinds
        }
    }

    /// Wechselt das Notfall-Schema (ein Code ↔ drei Teile)?
    public var changesRecoveryScheme: Bool {
        guard let target else { return false }
        return target.recoveryScheme != header.recoveryScheme
    }

    static func plan(mode: Mode, header: VaultHeaderInfo, enrolled: FactorSet) -> [Step] {
        var steps: [Step] = []
        switch mode {
        case let .changeLevel(level):
            steps.append(.intro)
            steps.append(.verify)
            let neu = level.factors.subtracting(header.factors)
            // Touch ID: Entsperr-Schlüssel, dazu der Eintrags-Schlüssel, falls noch keiner da ist.
            if neu.contains(.secureEnclave) { steps.append(.touchID) }
            if neu.contains(.card) { steps.append(.card) }
            if neu.contains(.securityKey) { steps.append(.securityKey) }
            if level.recoveryScheme != header.recoveryScheme { steps.append(.recovery) }
            steps.append(.apply)
        case let .enroll(kinds):
            steps.append(.verify)
            if kinds.contains(.secureEnclave) { steps.append(.touchID) }
            if kinds.contains(.card) { steps.append(.card) }
            if kinds.contains(.securityKey) { steps.append(.securityKey) }
            steps.append(.apply)
        }
        steps.append(.done)
        return steps
    }

    /// Position für die Anzeige „Schritt n von m“ (ohne Abschluss).
    public var stepNumber: (current: Int, total: Int) {
        let zaehlbar = steps.filter { $0 != .done }
        let index = zaehlbar.firstIndex(of: step) ?? zaehlbar.count - 1
        return (index + 1, zaehlbar.count)
    }

    func next() {
        guard let index = steps.firstIndex(of: step), index + 1 < steps.count else { return }
        error = nil
        step = steps[index + 1]
    }

    func back() {
        guard let index = steps.firstIndex(of: step), index > 0 else { return }
        error = nil
        step = steps[index - 1]
    }

    /// Alle Geheimnisse verwerfen.
    func wipe() {
        password = ""
        collection.reset()
        newSE = nil
        newEntryKey = nil
        cardQ = nil
        cardText = ""
        cardPayload = ""
        cardImage = nil
        keyEnrollment = nil
        keyReuseSecret = nil
        recoveryConfirmation = []
        kit = nil
        cardPrintInfo = nil
    }

    /// Material für `changeSecurityLevel` / `enrollFactors`. Eine vorhandene (für Einträge eingerichtete) Karte bzw.
    /// ein vorhandener Schlüssel ist kein neues Material: beide gehen als aktuelle Faktoren an den Kern
    /// (`currentFactors`), der sie gegen Kennung bzw. Prüfwert prüft (`wrongCard`/`wrongPassword`).
    var material: NewFactorMaterial {
        NewFactorMaterial(secureEnclave: newSE, entryKey: newEntryKey,
                          card: cardReuse ? nil : cardQ.map(CardEnrollment.init(q:)),
                          securityKey: keyEnrollment)
    }

    /// Aktuelle Faktoren für den Kern: die beim Bestätigen eingesammelten plus vorhandene Karte/Schlüssel.
    var currentFactors: FactorSecrets {
        var out = collection.secrets
        if cardReuse, let cardQ { out.card = cardQ }
        if keyReuse, let keyReuseSecret { out.securityKey = keyReuseSecret }
        return out
    }

    /// Sind alle Einrichtungs-Schritte erledigt?
    var setupComplete: Bool {
        for s in steps {
            switch s {
            case .touchID where !touchIDDone: return false
            case .card where !cardConfirmed: return false
            case .securityKey where keyEnrollment == nil && keyReuseSecret == nil: return false
            case .recovery where !recoveryConfirmed: return false
            default: continue
            }
        }
        return verified
    }
}
