import AppKit
import Observation
import SiegelCore
import SiegelHardware
import SwiftUI

/// Zustandsmaschine der App (SPEC §6, §7). Läuft auf dem Main-Actor; schwere Aufrufe (Argon2,
/// Code-Korrektur, Datei-I/O) laufen per `Task.detached` im Hintergrund.
///
/// Bildschirme: Einrichtung → Notfallkit → Tresor; Gesperrt (mit Notfallcode-Weg); Tresor fehlt;
/// Beschädigt; Rollback-Frage; Einstellungen als Seite im entsperrten Zustand.
@MainActor
@Observable
public final class AppModel {
    public enum Screen: Hashable, Sendable {
        case setup
        case recoveryKit
        case locked
        case recovery
        case missingVault
        case corrupt
        case rollback
        case unlocked
        case blocked(BlockReason)
    }

    public enum BlockReason: Hashable, Sendable {
        /// Eine andere Instanz hält die Sperrdatei.
        case alreadyRunning
        /// Nicht im Sandbox-Container gestartet (nur über ./build.sh run).
        case sandboxMissing
        /// Der Datenordner liess sich nicht anlegen.
        case storageFailed
        /// Die Signatur des eigenen Bündels ist ungültig (SPEC §21, Befund hardware-2): kein Entsperren.
        case signatureInvalid
    }

    // MARK: Zustand

    public internal(set) var screen: Screen
    public let settings: AppSettings
    @ObservationIgnored let store: VaultStore?
    @ObservationIgnored let rollbackGuard: RollbackGuard

    /// Der geöffnete Tresor (nur entsperrt und während des Notfallkits nach der Einrichtung).
    public internal(set) var vault: UnlockedVault?
    /// Ein Hintergrundaufruf läuft (Argon2 usw.); Eingaben sperren, Fortschrittslinie zeigen.
    public internal(set) var busy = false
    /// Steigt bei jedem Sperren; Ansichten können sich daran neu aufbauen (`.id(model.lockGeneration)`).
    public internal(set) var lockGeneration = 0
    /// Steigt bei jeder Änderung am Tresor (Stufe 2 kann darauf reagieren).
    public internal(set) var revision = 0

    // Abbild des Tresors für die Oberfläche (nach jedem Entsperren und jeder Änderung neu gelesen)
    public internal(set) var entries: [VaultEntry] = []
    public internal(set) var deletedEntries: [VaultEntry] = []
    public internal(set) var recoveryConfirmed = true
    public internal(set) var kitID = ""
    public internal(set) var kdf: KDFParameters = .standard
    public internal(set) var lastModified: Date?
    public internal(set) var masterPasswordReuse: Set<UUID> = []

    /// Suchtext der Tresor-Ansicht (wird beim Sperren geleert).
    public var searchText = ""
    /// Dezente Rückmeldezeile unten im Fenster.
    public var notice: Notice?
    /// Einstellungen als Seite im Hauptfenster (⌘,).
    public internal(set) var showsSettings = false
    /// Ablauf, den Stufe 2 anzeigt (CSV-Import/-Export, Sicherung exportieren/einspielen).
    public var pendingFlow: PendingFlow?
    /// Stufe 2 setzt das, wenn ein Eintrag ausgewählt ist (aktiviert ⌘E).
    public var canEditEntry = false
    /// Stufe 2 empfängt hier ⌘N, ⌘F, ⌘E.
    @ObservationIgnored public var commandHandler: (@MainActor (VaultCommand) -> Void)?

    // Bildschirm-Zustände
    public internal(set) var setup = SetupState()
    public internal(set) var unlock = UnlockState()
    public internal(set) var recovery = RecoveryState()
    public internal(set) var kit: KitState?
    public internal(set) var missing = MissingVaultState()
    public internal(set) var corrupt = CorruptState()
    public internal(set) var rollback: RollbackState?
    public internal(set) var settingsState = SettingsState()
    /// Tresor-Ansicht (Auswahl, Bearbeiten, Generator, „Zuletzt gelöscht“). Beim Sperren neu.
    public internal(set) var browser = VaultBrowserState()
    /// Laufender Ablauf (CSV, Sicherungen) mit seinen Zwischenständen. Beim Sperren verworfen.
    public internal(set) var flowState: FlowState?
    /// Exportierte CSV-Datei: Zeile „Exportdatei endgültig löschen“, bis erledigt oder weggeklickt.
    /// Nur der Pfad (kein Inhalt), nicht gespeichert; bleibt über das Sperren hinweg stehen.
    public internal(set) var exportedCSV: URL?

    /// Laufende Schreibvorgänge (Speichern, Zugangswechsel, Wiederherstellen). Beobachtbar, damit Abbrechen-
    /// Knöpfe während des Speicherns gesperrt sind (Befund #11).
    public internal(set) var savesInFlight = 0
    public var isSaving: Bool { savesInFlight > 0 }
    /// Offene Frage „Alte Sicherungen entfernen?“ (SPEC §4, Befund #34): gesetzt, sobald ein Zugangswechsel
    /// geschrieben ist, gelöscht erst mit der Antwort. Ging sie durch Sperren verloren, kommt sie nach dem nächsten
    /// Entsperren wieder (auch nach einem Neustart). Nicht geheim.
    public var pendingPurgeQuestion: PendingPurgeQuestion? {
        get { settings.pendingPurgeQuestion }
        set { settings.pendingPurgeQuestion = newValue }
    }
    /// Hinweis auf dem Sperrbildschirm (Befund #27/#31): Eine offene Bearbeitung liess sich vor dem Sperren nicht
    /// speichern. Nur der Fehlertext, nie Inhalt; bleibt bis zum nächsten Entsperren stehen.
    public internal(set) var lockNotice: String?
    /// Offline-Sicherheitsbericht (§17) des geöffneten Tresors; nur Kennungen, kein Inhalt. Beim Sperren weg.
    public internal(set) var securityReport: SecurityReport?
    /// Seit dem letzten Schreiben am zweiten Sicherungsort wurde gespeichert, ohne dass er erreichbar war.
    public internal(set) var savedWithoutSecondary = false
    /// Name des gespeicherten, aber gerade nicht erreichbaren zweiten Sicherungsorts.
    public internal(set) var secondaryStoredName: String?

    // Härtestufe (SPEC v4 §13–§16), nach jedem Entsperren und jeder Änderung neu gelesen
    /// Tresor-Stufe des geöffneten Tresors.
    public internal(set) var level: SecurityLevel = .standard
    /// Regeln der Stufe (die Oberfläche setzt sie durch).
    public internal(set) var policy: LevelPolicy = SecurityLevel.standard.policy
    /// Kopf-Auskunft des geöffneten Tresors (Faktoren zum Öffnen, Schlüssel-Kennungen).
    public internal(set) var vaultHeader: VaultHeaderInfo?
    /// Für Einträge eingerichtete Faktoren.
    public internal(set) var enrolledFactors: FactorSet = []
    /// Kamera-Sheet (QR-Schlüsselkarte) bzw. Schlüssel-Sheet, solange sie offen sind.
    public internal(set) var cardScan: CardScanState?
    public internal(set) var keyTouch: KeyTouchState?
    /// Der Touch-ID-Dialog des Systems ist offen.
    public internal(set) var touchIDActive = false
    /// Stufen-Assistent bzw. Einrichten für Einträge (Einstellungen).
    public internal(set) var wizard: SecurityWizardState?

    // Selbstvernichtung (SPEC v4.3 §23)
    /// Zustand im Container (nicht geheim): Einstellungen, Frist, Fehlversuche, Vernichtung. Auch gesperrt gelesen
    /// (Sperrbildschirm: Frist ab 25 % Restzeit, Zähler-Warnung ab N/2).
    public internal(set) var destruction: DestructionStatus?
    /// Als vernichtbar markierte Einträge des geöffneten Tresors (in einer Vernichtungs-Sitzung leer).
    public internal(set) var destructibleEntries: Set<UUID> = []
    /// Vernichtete Einträge, die noch im Tresor stehen (nur echte Sitzung, bis „Entfernen“).
    public internal(set) var destroyedEntries: [UUID] = []
    /// Vernichtungs-Sitzung (§23.2.3). Die Oberfläche zeigt dann nichts, was auf eine Vernichtung hindeutet – sie
    /// verzweigt sonst nirgends danach.
    public internal(set) var isDuressSession = false
    /// Selbstvernichtung im geöffneten Tresor eingerichtet (Auslöser, markierte Einträge oder Schlüssel V). Dann
    /// verbietet der Kern Stufen unter 4 (§23); in einer Vernichtungs-Sitzung gleich wie in der echten.
    public internal(set) var destructionConfigured = false
    /// Einstellungen → Sicherheitsstufe → Selbstvernichtung (Entwurf, Bestätigung).
    public internal(set) var destructionState: DestructionState?

    // Intern
    @ObservationIgnored var epoch = 0
    @ObservationIgnored private var lockParticipants: [(id: String, action: @MainActor (UnlockedVault, LockAttempt) -> LockParticipantResult)] = []
    @ObservationIgnored private var noticeTask: Task<Void, Never>?
    @ObservationIgnored var autoLock: AutoLock?
    @ObservationIgnored private var secondaryAccessURL: URL?
    @ObservationIgnored private var secondaryObservers: [(NotificationCenter, NSObjectProtocol)] = []
    /// Sortierte/gefilterte Liste der Tresor-Ansicht (nach revision + Suchtext).
    @ObservationIgnored var listCache: VaultListCache?
    /// Faktor-Hardware (SiegelHardware; Snapshots setzen eine Attrappe ein).
    @ObservationIgnored var hardware: any FactorHardware = SystemFactorHardware()
    /// Laufende Faktor-Vorgänge (Touch ID, Kamera, Schlüssel): währenddessen sperrt ein App-Wechsel erst danach.
    @ObservationIgnored var factorOperations = 0
    @ObservationIgnored var deactivateLockPending = false
    /// Höchstdauer der Auto-Sperre aus der Stufe des zuletzt geöffneten Tresors (nicht geheim).
    @ObservationIgnored var lastAutoLockMax: Int?
    /// Höchstdauer der Zwischenablage aus der Stufe des zuletzt geöffneten Tresors – gilt gesperrt für ⌘C aus den
    /// Notfallcode-Feldern (Befund ablaeufe-8, wie `lastAutoLockMax`).
    @ObservationIgnored var lastClipboardMax: Int?
    /// Laufende Berechnung des Sicherheitsberichts.
    @ObservationIgnored var reportTask: Task<Void, Never>?
    /// ⌘L wurde abgelehnt, weil eine Bearbeitung nicht gespeichert werden konnte: ein zweites ⌘L kurz danach
    /// sperrt trotzdem (Befund #31).
    @ObservationIgnored var lockRefusedAt: ContinuousClock.Instant?
    /// Totmann-Prüfung alle 10 Minuten (§23.2), auch gesperrt.
    @ObservationIgnored var deadmanTimer: Timer?
    /// Laufende Nummer der Status-Ladevorgänge (ältere Ergebnisse werden verworfen).
    @ObservationIgnored var destructionLoads = 0

    // MARK: Erzeugen

    /// Für Tests und Snapshots: Temp-Ordner + `InMemoryRollbackGuard` übergeben.
    public init(store: VaultStore?, rollbackGuard: RollbackGuard, settings: AppSettings, blocked: BlockReason? = nil,
                routeImmediately: Bool = true) {
        self.store = store
        self.rollbackGuard = rollbackGuard
        self.settings = settings
        self.screen = blocked.map { .blocked($0) } ?? .locked
        wireDestructionKeyEraser()
        installFieldCopyLifetime()
        if blocked == nil, routeImmediately {
            route()
        }
    }

    /// Die App selbst: Signatur, Sandbox-Ordner, Einzelinstanz, UserDefaults.
    ///
    /// Die Signatur wird zuerst und synchron geprüft (SPEC §21, Befund hardware-2), vor dem Datenordner und der
    /// Einzelinstanz: Ohne `store` gibt es kein Zeitfenster für Entsperren, Wiederherstellen oder Einspielen. Das
    /// Bündel ist klein, die Prüfung dauert Millisekunden. `signatureIsValid` ist für Tests austauschbar.
    public static func production(signatureIsValid: () -> Bool = CodeSignatureCheck.mainBundleIsValid) -> AppModel {
        let settings = AppSettings(defaults: .standard)
        let rollbackGuard = UserDefaultsRollbackGuard()
        guard signatureIsValid() else {
            return AppModel(store: nil, rollbackGuard: rollbackGuard, settings: settings, blocked: .signatureInvalid)
        }
        let directory: URL
        do {
            directory = try dataDirectory()
        } catch {
            return AppModel(store: nil, rollbackGuard: rollbackGuard, settings: settings, blocked: .sandboxMissing)
        }
        switch SingleInstance.acquire(directory: directory) {
        case .alreadyRunning:
            return AppModel(store: nil, rollbackGuard: rollbackGuard, settings: settings, blocked: .alreadyRunning)
        case .failed:
            return AppModel(store: nil, rollbackGuard: rollbackGuard, settings: settings, blocked: .storageFailed)
        case .acquired:
            break
        }
        // Erst den zweiten Sicherungsort auflösen, dann den Startbildschirm bestimmen: „Tresor fehlt“ muss auch
        // die Sicherungen am zweiten Ort sehen (Befund #13).
        let model = AppModel(store: VaultStore(directory: directory, rollbackGuard: rollbackGuard),
                             rollbackGuard: rollbackGuard, settings: settings, routeImmediately: false)
        model.resolveSecondaryBackupLocation()
        model.route()
        return model
    }

    private static func dataDirectory() throws -> URL {
        #if DEBUG
        // Nur Debug-Bau: eigener Ordner zum Ausprobieren ohne Sandbox (z. B. swift run Siegel).
        if let pfad = ProcessInfo.processInfo.environment["SIEGEL_DEBUG_DIRECTORY"], !pfad.isEmpty {
            return URL(fileURLWithPath: pfad, isDirectory: true)
        }
        #endif
        return try VaultStore.defaultDirectory()
    }

    /// Startet Auto-Sperre und Plattform-Dienste (einmal, aus dem App-Delegate).
    public func startPlatformServices() {
        guard autoLock == nil else { return }
        let lock = AutoLock(
            minutes: { [weak self] in self?.effectiveAutoLockMinutes ?? 5 },
            isArmed: { [weak self] in
                guard let self else { return false }
                return self.holdsOpenVault || self.holdsPendingSecret
            },
            lockNow: { [weak self] reason in self?.lock(reason: reason) }
        )
        lock.start()
        autoLock = lock
        observeSecondaryBackupLocation()
        observeDeactivation()
        startDeadmanChecks()
        SecretPasteboard.onCopy = { [weak self] lifetime in
            self?.show(Notice("Kopiert – wird in \(Int(lifetime)) s gelöscht", symbol: "doc.on.doc"))
        }
    }

    // MARK: Abfragen

    public var isUnlocked: Bool { screen == .unlocked && vault != nil }

    /// Hält das Modell irgendeinen geöffneten Tresor (auch während Notfallkit, Rollback-Frage usw.)?
    public var holdsOpenVault: Bool {
        vault != nil || rollback != nil || recovery.vault != nil || corrupt.vault != nil
    }

    /// Hält ein Bildschirm ausserhalb des offenen Tresors ein Zugangsgeheimnis (Notfallcode, eingetipptes
    /// Master-Passwort) oder läuft ein Argon2-Lauf? Dann gilt die Auto-Sperre wie bei offenem Tresor (B4,
    /// Befund #5): Inaktivität, Ruhezustand, Bildschirmsperre und Benutzerwechsel verwerfen die Eingaben, und
    /// `epoch` steigt, damit ein laufendes Entsperren den Tresor nicht hinter der Sperre öffnet. Die Einrichtung
    /// ist ausgenommen (noch kein Tresor; die notierte Passphrase darf nicht neu gewürfelt werden).
    public var holdsPendingSecret: Bool {
        if screen == .setup { return false }
        return recovery.confirmedCode != nil || !recovery.code.isEmpty || !recovery.newPassword.isEmpty
            || recovery.shares.contains { !$0.isEmpty } || recovery.confirmedShares != nil
            || !recovery.newPasswordRepeat.isEmpty || !corrupt.password.isEmpty || !missing.password.isEmpty
            || !unlock.password.isEmpty || busy
    }

    /// Ort der Tresordatei (für „Tresor im Finder zeigen“).
    public var vaultDirectory: URL? { store?.vaultURL.deletingLastPathComponent() }

    /// Zeile „Notfallkit nicht bestätigt – jetzt einrichten“ (nicht wegklickbar).
    public var needsRecoveryKitConfirmation: Bool { isUnlocked && !recoveryConfirmed }

    /// Zeile „Keine Sicherung ausserhalb dieses Macs“: ohne zweiten Ort, bis 30 Tage nach der letzten
    /// externen Sicherung ausgeblendet.
    public var showsExternalBackupHint: Bool {
        guard settings.secondaryBackupBookmark == nil else { return false }
        guard let letzte = settings.lastExternalBackupAt else { return true }
        return Date().timeIntervalSince(letzte) > 30 * 24 * 3600
    }

    /// Ist ein zweiter Sicherungsort gewählt, aber gerade nicht erreichbar (Stick ausgesteckt, Ordner weg)?
    public var secondaryBackupUnreachable: Bool {
        guard settings.secondaryBackupBookmark != nil, store != nil else { return false }
        if store?.secondaryBackupDirectory == nil { return true }
        if case .unreachable? = store?.lastSecondaryBackupResult { return true }
        return false
    }

    /// Zeile „Zweiter Sicherungsort nicht verbunden“ (Befund #8/#14): gewählt, aber nicht erreichbar, und dort
    /// fehlt etwas – seit dem letzten Schreiben dort wurde gespeichert, es gab nie eine Kopie dort, oder sie ist
    /// älter als 30 Tage. Das letzte Schreiben dort scheiterte → ebenfalls.
    public var showsSecondaryBackupWarning: Bool {
        guard settings.secondaryBackupBookmark != nil else { return false }
        if case .failed? = store?.lastSecondaryBackupResult { return true }
        guard secondaryBackupUnreachable else { return false }
        if savedWithoutSecondary { return true }
        guard let letzte = settings.lastSecondaryBackupAt else { return true }
        return Date().timeIntervalSince(letzte) > 30 * 24 * 3600
    }

    // MARK: Navigation

    /// Bestimmt den Startbildschirm aus dem Dateizustand.
    func route() {
        guard let store else { return }
        if store.vaultExists {
            screen = .locked
            loadLockHeader()
        } else if !Self.mayHaveBackups(store) {
            // Keine Sicherungsdatei und kein zweiter Ort (nur Verzeichnisse gelistet): sofort zur Einrichtung.
            prepareSetup()
            screen = .setup
        } else {
            // Befund ablaeufe-10: Die Sicherungen ganz zu lesen (jede Datei mit Prüfsumme, am zweiten Ort z. B. aus
            // iCloud Drive nachgeladen) dauert – im Hintergrund, bis dahin „Sicherungen werden gesucht…“.
            let state = MissingVaultState()
            state.searching = true
            missing = state
            screen = .missingVault
            loadBackups(into: state, setupIfNone: true)
            // §23.2: Fehlversuch-Zähler auch hier zeigen (die Sicherungswege zählen mit, Befund datei-5).
            reloadDestructionStatus()
        }
    }

    /// Gibt es lokal eine Sicherungsdatei oder einen zweiten Sicherungsort? Listet nur Verzeichnisse, liest nichts.
    nonisolated static func mayHaveBackups(_ store: VaultStore) -> Bool {
        if store.secondaryBackupDirectory != nil { return true }
        let fm = FileManager.default
        guard let ordner = try? fm.contentsOfDirectory(atPath: store.backupsDirectory.path) else { return false }
        return ordner.contains { name in
            let pfad = store.backupsDirectory.appendingPathComponent(name, isDirectory: true).path
            return ((try? fm.contentsOfDirectory(atPath: pfad)) ?? []).contains { !$0.hasPrefix(".") }
        }
    }

    /// Liest die Sicherungen im Hintergrund (Befund ablaeufe-10) und übernimmt sie, solange `state` gilt; eine vom
    /// Nutzer gewählte Datei bleibt zuoberst. `setupIfNone`: ohne jede Sicherung zur Einrichtung (§4).
    func loadBackups(into state: MissingVaultState, setupIfNone: Bool) {
        guard let store else { return }
        state.searching = true
        state.searchRun += 1
        let lauf = state.searchRun
        Task { @MainActor [weak self, weak state] in
            let result = await Self.background { store.backups() }
            guard let self, let state, self.missing === state, state.searchRun == lauf else { return }
            state.searching = false
            let gefunden = (try? result.get()) ?? []
            if setupIfNone, gefunden.isEmpty, state.chosenFile == nil, self.screen == .missingVault {
                self.missing = MissingVaultState()
                self.prepareSetup()
                self.go(.setup, animated: false)
                return
            }
            let gewaehlt = state.chosenFile.flatMap { url in state.backups.first { $0.url == url } }
            state.backups = (gewaehlt.map { [$0] } ?? []) + gefunden.filter { $0.url != gewaehlt?.url }
            if state.selectedBackup == nil { state.selection = state.backups.first?.url }
        }
    }

    func prepareSetup() {
        let state = SetupState()
        if let dir = vaultDirectory {
            state.fileVaultEncrypted = FileVaultCheck.isEncrypted(dir)
        }
        setup = state
    }

    func go(_ ziel: Screen, animated: Bool = true) {
        // Sicherheitsnetz (Befund #35): Ohne offenen Tresor nie in die Tresor-Ansicht – ein später Abschluss-Handler
        // darf die Sperr-Ansicht nicht überschreiben.
        if ziel == .unlocked, vault == nil {
            route()
            return
        }
        if animated {
            withAnimation(.easeInOut(duration: 0.22)) { screen = ziel }
        } else {
            screen = ziel
        }
    }

    // MARK: Rückmeldungen

    public func show(_ notice: Notice, seconds: Double = 4) {
        noticeTask?.cancel()
        withAnimation(.easeOut(duration: 0.15)) { self.notice = notice }
        let id = notice.id
        noticeTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, let self, self.notice?.id == id else { return }
            withAnimation(.easeIn(duration: 0.2)) { self.notice = nil }
        }
    }

    /// Kopiert ein Geheimnis über die SecretPasteboard (einziger Weg in die Zwischenablage). Die Dauer ist die
    /// Einstellung, gekürzt durch die Stufe (§13) und den Schutz des Eintrags (§16).
    public func copySecret(_ secret: String, protection: EntryProtection = .normal) {
        // Befund #24: nie nach dem Sperren (ein Tastenkürzel der alten Ansicht kann noch ankommen).
        guard isUnlocked else { return }
        let sekunden = effectiveClipboardSeconds(protection)
        SecretPasteboard.copy(secret, lifetime: TimeInterval(sekunden))
        show(Notice("Kopiert – wird in \(sekunden) s gelöscht", symbol: "doc.on.doc"), seconds: Double(sekunden))
    }

    /// ⌘C aus Geheimnis-Feldern (Befund hygiene-3): Dauer erst beim Kopieren bestimmen, nach Einstellung, Stufe und
    /// dem Schutz des bearbeiteten Eintrags – so gibt es keinen veralteten Wert nach einer Änderung der Einstellung.
    func installFieldCopyLifetime() {
        SecretPasteboard.fieldCopyLifetimeProvider = { [weak self] in
            guard let self else { return SecretPasteboard.strictestLifetime }
            return TimeInterval(self.effectiveClipboardSeconds(self.activeFieldProtection))
        }
    }

    /// Schutz, der für ⌘C aus Geheimnis-Feldern gilt: beim Bearbeiten der höhere von gewähltem und bisherigem Schutz,
    /// sonst Schutz 1 (z. B. Generator ohne Eintrag, Notfallcode-Eingabe).
    var activeFieldProtection: EntryProtection {
        guard let editor = browser.editor else { return .normal }
        return max(editor.draft.protection, editor.originalProtection)
    }

    /// Zwischenablage-Dauer nach Einstellung, Stufe und Eintrags-Schutz.
    public func effectiveClipboardSeconds(_ protection: EntryProtection = .normal) -> Int {
        var sekunden = settings.clipboardSeconds
        // Gesperrt gilt die Grenze der zuletzt geöffneten Stufe (Befund ablaeufe-8), nicht die der Stufe 1.
        let stufe = vault != nil ? policy.clipboardSecondsMax : lastClipboardMax
        if let max = stufe { sekunden = min(sekunden, max) }
        if let max = protection.clipboardSecondsMax { sekunden = min(sekunden, max) }
        return sekunden
    }

    /// Auto-Sperre nach Einstellung, gekürzt durch die Stufe (auch im gesperrten Zustand die zuletzt bekannte).
    public var effectiveAutoLockMinutes: Int {
        let max = vault != nil ? policy.autoLockMinutesMax : lastAutoLockMax
        guard let max else { return settings.autoLockMinutes }
        return min(settings.autoLockMinutes, max)
    }

    /// Merkt einen Beobachter (lebt so lange wie das Modell).
    func keepObserver(_ center: NotificationCenter, _ token: NSObjectProtocol) {
        secondaryObservers.append((center, token))
    }

    /// Sperre beim App-Wechsel (Stufe 3+). Während eines Faktor-Vorgangs (Touch-ID-Dialog des Systems) erst danach.
    func observeDeactivation() {
        let center = NotificationCenter.default
        secondaryObservers.append((center, center.addObserver(forName: NSApplication.didResignActiveNotification,
                                                              object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.holdsOpenVault, self.policy.lockOnDeactivate else { return }
                if self.factorOperations > 0 {
                    self.deactivateLockPending = true
                } else {
                    self.lock(reason: .deactivated)
                }
            }
        }))
    }

    // MARK: Menübefehle

    public func send(_ command: VaultCommand) {
        guard isUnlocked, !showsSettings else { return }
        if command == .edit && !canEditEntry { return }
        commandHandler?(command)
    }

    public var vaultCommandsEnabled: Bool { isUnlocked && !showsSettings && pendingFlow == nil }

    // MARK: Tresor-Zugriff für die Tresor-Ansicht (Stufe 2)

    /// Führt eine Änderung am Tresor im Hintergrund aus (transaktional im Kern) und liest danach das
    /// Abbild neu. Gibt den Fehler zurück (die Oberfläche behält dann ihre Eingabe).
    @discardableResult
    public func perform(_ change: @escaping @Sendable (UnlockedVault) throws -> Void) async -> SiegelError? {
        guard let vault else { return .io("vault.locked") }
        let start = epoch
        savesInFlight += 1
        defer { savesInFlight -= 1 }
        let result = await Self.background { try change(vault) }
        guard start == epoch else { return .io("vault.locked") }
        refreshSnapshot()
        if case let .failure(error) = result { return error }
        return nil
    }

    /// Variante mit Rückgabewert (z. B. `importEntries`).
    public func performReturning<T: Sendable>(_ work: @escaping @Sendable (UnlockedVault) throws -> T) async -> Result<T, SiegelError> {
        guard let vault else { return .failure(.io("vault.locked")) }
        let start = epoch
        savesInFlight += 1
        defer { savesInFlight -= 1 }
        let result = await Self.background { try work(vault) }
        guard start == epoch else { return .failure(.io("vault.locked")) }
        refreshSnapshot()
        return result
    }

    /// Liest Einträge, Status und Kennungen neu aus dem Tresor.
    public func refreshSnapshot() {
        syncSecondaryBackupStatus()
        guard let vault, !vault.isLocked else {
            entries = []
            deletedEntries = []
            masterPasswordReuse = []
            lastModified = nil
            destructibleEntries = []
            destroyedEntries = []
            isDuressSession = false
            destructionConfigured = false
            return
        }
        entries = vault.entries
        deletedEntries = vault.deletedEntries
        recoveryConfirmed = vault.recoveryConfirmed
        kitID = vault.kitID
        kdf = vault.kdf
        lastModified = vault.lastModified
        masterPasswordReuse = vault.masterPasswordReuse
        level = vault.level
        policy = vault.policy
        vaultHeader = vault.headerInfo
        enrolledFactors = vault.enrolledFactors
        lastAutoLockMax = policy.autoLockMinutesMax
        lastClipboardMax = policy.clipboardSecondsMax
        readDestructionSession(vault)
        revision += 1
        scheduleSecurityReport()
    }

    // MARK: Sperren

    /// Registriert eine Aktion, die vor dem Sperren synchron läuft (der Tresor ist noch offen). Stufe 2
    /// speichert hier offene Bearbeitungen per `upsert` (ungültige als „Entwurf <Datum>“). Das Ergebnis meldet, ob
    /// etwas verloren ging bzw. ob ein ⌘L abgelehnt werden soll (Befund #27/#31).
    func addLockParticipant(id: String,
                            _ action: @escaping @MainActor (UnlockedVault, LockAttempt) -> LockParticipantResult) {
        lockParticipants.removeAll { $0.id == id }
        lockParticipants.append((id, action))
    }

    public func removeLockParticipant(id: String) {
        lockParticipants.removeAll { $0.id == id }
    }

    /// Sperrt sofort (⌘L, Auto-Sperre, Ruhezustand, Beenden). Synchron: Nach der Rückkehr sind DEK und
    /// Inhalt verworfen, Fenster aufgeräumt, die Wurzelansicht ersetzt.
    public func lock(reason: LockReason = .manual) {
        // (a) Offene Bearbeitungen sichern, solange der DEK da ist. Scheitert das bei ⌘L, wird nicht gesperrt (die
        // Eingabe bliebe sonst ohne Spur weg); ein zweites ⌘L innerhalb von 20 s sperrt trotzdem. Auto-Sperre,
        // Ruhezustand, Bildschirmsperre und Beenden sperren immer.
        var verloren: SiegelError?
        var hinweis: String?
        if let vault, !vault.isLocked {
            let erzwingen = lockRefusedAt.map { ContinuousClock.now < $0.advanced(by: .seconds(20)) } ?? false
            let attempt = LockAttempt(reason: reason, mayRefuse: reason == .manual && !erzwingen)
            for participant in lockParticipants {
                switch participant.action(vault, attempt) {
                case .done: break
                case let .doneWithNotice(text): hinweis = text
                case let .lost(error, text):
                    verloren = error
                    hinweis = text
                case .refused:
                    // Den Grund nennt die Bearbeitung selbst (Fehlerzeile im Formular).
                    lockRefusedAt = .now
                    show(Notice("Nicht gesperrt – die Bearbeitung liess sich nicht speichern. Nochmals ⌘L sperrt trotzdem.",
                                symbol: "exclamationmark.circle"), seconds: 10)
                    return
                }
            }
        }
        lockRefusedAt = nil
        // (d) Sheets, Alerts, Popover, Panels schliessen; Kamera und Schlüssel-Sheet abbrechen.
        WindowCleanup.dismissTransientWindows()
        cancelFactorSheets()
        wizard?.wipe()
        wizard = nil
        unlock.collection?.reset()

        vault?.lock()
        rollback?.vault.lock()
        recovery.vault?.lock()
        corrupt.vault?.lock()

        vault = nil
        rollback = nil
        kit = nil
        reportTask?.cancel()
        reportTask = nil
        securityReport = nil
        // Befund #24: keine Rückmeldung (z. B. „Kopiert“) über die Sperr-Ansicht stehen lassen.
        noticeTask?.cancel()
        noticeTask = nil
        notice = nil
        if let hinweis {
            lockNotice = hinweis
        } else if let verloren {
            lockNotice = "Die offene Bearbeitung liess sich vor dem Sperren nicht speichern (" + Self.shortReason(verloren)
                + ") und ist verloren."
        }
        entries = []
        deletedEntries = []
        masterPasswordReuse = []
        lastModified = nil
        kitID = ""
        searchText = ""
        showsSettings = false
        pendingFlow = nil
        canEditEntry = false
        setup = SetupState()
        unlock = UnlockState()
        recovery = RecoveryState()
        missing = MissingVaultState()
        corrupt = CorruptState()
        settingsState = SettingsState()
        browser = VaultBrowserState()
        flowState = nil
        listCache = nil
        level = .standard
        policy = SecurityLevel.standard.policy
        vaultHeader = nil
        enrolledFactors = []
        destructionState?.wipe()
        destructionState = nil
        destructibleEntries = []
        destroyedEntries = []
        isDuressSession = false
        destructionConfigured = false
        // Befund ablaeufe-3: Der Stand der eben gesperrten Sitzung gilt nicht für den Sperrbildschirm – in einer
        // Vernichtungs-Sitzung ist er absichtlich ohne Vernichtung (alte Frist), er verriete die Sitzung. Bis
        // `route()` den Stand aus `zustand.json` gelesen hat, zeigt der Sperrbildschirm weder Frist noch Zähler.
        destructionLoads += 1
        destruction = nil
        touchIDActive = false
        deactivateLockPending = false
        busy = false
        epoch += 1
        lockGeneration += 1

        autoLock?.vaultDidClose()
        // Befund hygiene-2: Die Sperre beim App-Wechsel (Stufe 3+) lässt ein eben kopiertes Geheimnis bis zu seinem
        // Ablauf (≤ 15 s) stehen – sonst liesse es sich im anderen Programm nie einfügen. Jeder andere Anlass leert
        // sofort; Ruhezustand, Bildschirmsperre und Benutzerwechsel leeren auch nach dieser Sperre (AutoLock).
        if reason != .deactivated { SecretPasteboard.clearIfOwned() }
        // Befund #32: ein eingefügtes Master-Passwort auch beim Sperren entfernen (nur wenn unverändert).
        _ = MasterPasswordPasteTracker.clearIfUnchanged()
        MasterPasswordPasteTracker.reset()
        SecureEventInput.disable()
        WindowCleanup.scrubResponders()

        route()
    }

    /// Für `applicationShouldTerminate`: wartet auf laufende Speichervorgänge (max. 5 s), sperrt dann.
    public func prepareForTermination(_ done: @escaping @MainActor () -> Void) -> Bool {
        if savesInFlight == 0 {
            lock(reason: .terminate)
            return true
        }
        Task { @MainActor [weak self] in
            let ende = ContinuousClock.now.advanced(by: .seconds(5))
            while let self, self.savesInFlight > 0, ContinuousClock.now < ende {
                try? await Task.sleep(for: .milliseconds(50))
            }
            self?.lock(reason: .terminate)
            done()
        }
        return false
    }

    // MARK: Öffnen

    /// Zeigt den geöffneten Tresor (nach Entsperren, Wiederherstellung, Rollback-Bestätigung).
    func open(_ opened: UnlockedVault) {
        retrySecondaryBackupLocation()
        vault = opened
        refreshSnapshot()
        reloadDestructionStatus()
        autoLock?.vaultDidOpen()
        unlock = UnlockState()
        recovery = RecoveryState()
        corrupt = CorruptState()
        missing = MissingVaultState()
        rollback = nil
        showsSettings = false
        go(.unlocked)
        clearPastedMasterPassword()
        // Befund #27/#31: verlorene Bearbeitung vor dem letzten Sperren ehrlich melden.
        if let text = lockNotice {
            lockNotice = nil
            show(Notice(text, symbol: "exclamationmark.circle"), seconds: 10)
        }
        // Ein Zugangswechsel wurde geschrieben, die Frage nach den alten Sicherungen aber nie beantwortet: jetzt.
        if let frage = pendingPurgeQuestion {
            if frage.vaultID == opened.vaultID {
                openSettings()
                settingsShow(.purgeBackups(frage.reason))
            } else {
                pendingPurgeQuestion = nil
            }
        }
    }

    /// Kurzer Grund für den Sperrbildschirm (ohne Handlungsanweisung, die dort nicht passt).
    static func shortReason(_ error: SiegelError) -> String {
        switch error {
        case .notEnoughDiskSpace: "zu wenig freier Speicherplatz"
        case .vaultChangedOnDisk: "die Tresordatei wurde ausserhalb von Siegel geändert"
        case .io("save.verify"): "die Prüfung nach dem Speichern ist gescheitert"
        default: "Speichern gescheitert"
        }
    }

    /// Befund #32: Wurde ein Master-Passwort eingefügt und ist die Zwischenablage seither unverändert, wird sie
    /// geleert – nach Entsperren, Einrichten, Passwortwechsel und jeder Bestätigung mit dem Master-Passwort.
    func clearPastedMasterPassword() {
        if MasterPasswordPasteTracker.clearIfUnchanged() {
            show(Notice(Fehlertexte.clipboardCleared, symbol: "clipboard"), seconds: 6)
        }
    }

    // MARK: Hintergrund

    nonisolated static func background<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async -> Result<T, SiegelError> {
        await Task.detached(priority: .userInitiated) { () -> Result<T, SiegelError> in
            do {
                return .success(try work())
            } catch let error as SiegelError {
                return .failure(error)
            } catch {
                return .failure(.io("unexpected"))
            }
        }.value
    }

    /// Wie `background`, für die async-Varianten des Kerns (Freigaben über einen `EntryFactorProvider`, §16).
    /// Der Aufruf startet nie auf dem Main-Thread (der Kern prüft das mit `dispatchPrecondition`).
    nonisolated static func backgroundAsync<T: Sendable>(_ work: @escaping @Sendable () async throws -> T)
        async -> Result<T, SiegelError> {
        await Task.detached(priority: .userInitiated) { () -> Result<T, SiegelError> in
            do {
                return .success(try await work())
            } catch let error as SiegelError {
                return .failure(error)
            } catch {
                return .failure(.io("unexpected"))
            }
        }.value
    }

    /// Führt einen schweren Aufruf aus und verwirft das Ergebnis, wenn inzwischen gesperrt wurde.
    /// `writes`: Der Aufruf schreibt die Tresordatei (Zugangswechsel, Wiederherstellen, Einspielen …). Er zählt
    /// dann als laufendes Speichern, damit Beenden darauf wartet (SPEC §6 c, Befund #10). `whenDiscarded` sieht
    /// ein Ergebnis, das wegen Sperrens verworfen wird (z. B. um eine offene Frage zu merken).
    func heavy<T: Sendable>(writes: Bool = false, _ work: @escaping @Sendable () throws -> T,
                            whenDiscarded: (@MainActor (Result<T, SiegelError>) -> Void)? = nil)
        async -> Result<T, SiegelError>? {
        await heavyAsync(writes: writes, { try work() }, whenDiscarded: whenDiscarded)
    }

    /// Wie `heavy`, für die async-Varianten des Kerns, die unterwegs Faktoren über die Oberfläche einholen
    /// (Touch ID, Karte, Schlüssel – z. B. neues Kit oder Export mit versiegelten Einträgen, §16).
    func heavyAsync<T: Sendable>(writes: Bool = false, _ work: @escaping @Sendable () async throws -> T,
                                 whenDiscarded: (@MainActor (Result<T, SiegelError>) -> Void)? = nil)
        async -> Result<T, SiegelError>? {
        let start = epoch
        busy = true
        if writes { savesInFlight += 1 }
        defer { if writes { savesInFlight -= 1 } }
        let result = await Self.backgroundAsync(work)
        guard start == epoch else {
            whenDiscarded?(result)
            // Inzwischen gesperrt: einen eben geöffneten Tresor sofort wieder schliessen.
            if case let .success(value) = result { Self.discard(value) }
            return nil
        }
        busy = false
        if writes { syncSecondaryBackupStatus() }
        return result
    }

    private static func discard<T>(_ value: T) {
        if let vault = value as? UnlockedVault { vault.lock() }
        let outcome = (value as? UnlockOutcome) ?? (value as? UnlockAttemptResult)?.outcome
        if let outcome {
            switch outcome {
            case let .unlocked(vault): vault.lock()
            case let .rollbackSuspected(vault, _, _): vault.lock()
            }
        }
        if let pair = value as? (UnlockedVault, PendingRecovery) { pair.0.lock() }
        if let pair = value as? (UnlockedVault, BackupInfo) { pair.0.lock() }
    }

    // MARK: Zweiter Sicherungsort

    /// Löst das gespeicherte Bookmark auf und startet den Zugriff. Ohne Erfolg bleibt der Ort leer, der Name aus
    /// dem Bookmark wird aber für die Anzeige „nicht verbunden“ gemerkt. Automatische Versuche hängen nichts ein
    /// (`.withoutMounting`: kein Mount-Dialog, kein Warten auf Netzlaufwerke im Main-Thread).
    func resolveSecondaryBackupLocation() {
        guard let data = settings.secondaryBackupBookmark, let store else {
            secondaryStoredName = nil
            return
        }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: data, options: [.withSecurityScope, .withoutMounting],
                                 relativeTo: nil, bookmarkDataIsStale: &stale),
              FileManager.default.fileExists(atPath: url.path) else {
            markSecondaryUnreachable(bookmark: data)
            return
        }
        if let alt = secondaryAccessURL, alt != url {
            alt.stopAccessingSecurityScopedResource()
            secondaryAccessURL = nil
        }
        if secondaryAccessURL == nil {
            guard url.startAccessingSecurityScopedResource() else {
                markSecondaryUnreachable(bookmark: data)
                return
            }
            secondaryAccessURL = url
        }
        store.secondaryBackupDirectory = url
        secondaryStoredName = nil
        if stale, let neu = try? url.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil,
                                                 relativeTo: nil) {
            settings.secondaryBackupBookmark = neu
        }
        completePendingSecondaryPurge()
    }

    private func markSecondaryUnreachable(bookmark data: Data) {
        if let alt = secondaryAccessURL {
            alt.stopAccessingSecurityScopedResource()
            secondaryAccessURL = nil
        }
        store?.secondaryBackupDirectory = nil
        secondaryStoredName = URL.resourceValues(forKeys: [.nameKey], fromBookmarkData: data)?.name
            ?? "Gewählter Ordner"
    }

    /// Ist ein Ort gespeichert, aber nicht aufgelöst: erneut versuchen (Aktivieren der App, Datenträger
    /// eingehängt, vor dem Entsperren). Ein ausgehängter Datenträger setzt den Ort zurück.
    func retrySecondaryBackupLocation() {
        guard settings.secondaryBackupBookmark != nil else { return }
        if let dir = store?.secondaryBackupDirectory, FileManager.default.fileExists(atPath: dir.path) { return }
        resolveSecondaryBackupLocation()
        if screen == .missingVault { reloadBackups() }
        // Einrichtung, weil beim Start keine Sicherung zu sehen war: Liegen am eben verbundenen Ort Sicherungen,
        // gilt SPEC §4 („Tresor fehlt“ statt neuem leeren Tresor). Gelesen im Hintergrund (Befund ablaeufe-10).
        if screen == .setup, !busy, let store, !store.vaultExists, store.secondaryBackupDirectory != nil {
            let einrichtung = setup
            Task { @MainActor [weak self] in
                let result = await Self.background { store.backups() }
                guard let self, self.screen == .setup, self.setup === einrichtung, !self.busy, !store.vaultExists,
                      case let .success(gefunden) = result, !gefunden.isEmpty else { return }
                let state = MissingVaultState()
                state.backups = gefunden
                state.selection = gefunden.first?.url
                self.missing = state
                self.go(.missingVault)
                self.reloadDestructionStatus()
            }
        }
    }

    /// Beobachter für Datenträger und App-Aktivierung (einmal, aus `startPlatformServices`).
    func observeSecondaryBackupLocation() {
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didMountNotification, NSWorkspace.didUnmountNotification] {
            secondaryObservers.append((workspace, workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.retrySecondaryBackupLocation() }
            }))
        }
        let app = NotificationCenter.default
        secondaryObservers.append((app, app.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil,
                                                        queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.retrySecondaryBackupLocation() }
        }))
    }

    func setSecondaryBackupLocation(_ url: URL?) {
        if let alt = secondaryAccessURL {
            alt.stopAccessingSecurityScopedResource()
            secondaryAccessURL = nil
        }
        guard let url else {
            settings.secondaryBackupBookmark = nil
            settings.lastSecondaryBackupAt = nil
            settings.pendingSecondaryPurge = nil
            store?.secondaryBackupDirectory = nil
            secondaryStoredName = nil
            savedWithoutSecondary = false
            return
        }
        guard let data = try? url.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil,
                                               relativeTo: nil) else {
            show(Notice("Der Ordner liess sich nicht merken.", symbol: "exclamationmark.circle"))
            return
        }
        settings.secondaryBackupBookmark = data
        settings.lastSecondaryBackupAt = nil
        resolveSecondaryBackupLocation()
    }

    /// Name des zweiten Sicherungsorts für die Anzeige (auch wenn er gerade nicht verbunden ist).
    public var secondaryBackupName: String? {
        store?.secondaryBackupDirectory?.lastPathComponent ?? secondaryStoredName
    }

    /// Ergebnis des letzten Schreibens am zweiten Ort übernehmen: Zeitpunkt merken bzw. festhalten, dass seit
    /// der letzten Kopie dort ohne den Ort gespeichert wurde.
    func syncSecondaryBackupStatus() {
        guard let result = store?.lastSecondaryBackupResult, settings.secondaryBackupBookmark != nil else { return }
        switch result {
        case let .written(date):
            if settings.lastSecondaryBackupAt.map({ $0 < date }) ?? true { settings.lastSecondaryBackupAt = date }
            savedWithoutSecondary = false
        case .unreachable, .failed:
            savedWithoutSecondary = true
        case .notDue:
            break
        }
    }

    /// Nach „Alte Sicherungen entfernen“: Was am zweiten Ort nicht erreichbar war, wird gemerkt und nachgeholt.
    func notePurgeReport(_ report: PurgeReport, vaultID: UUID) {
        let ortFehlt = settings.secondaryBackupBookmark != nil && store?.secondaryBackupDirectory == nil
        if report.secondaryUnreachable || ortFehlt {
            settings.pendingSecondaryPurge = (vaultID, Date())
        }
    }

    /// Text für das Ergebnis von „Alte Sicherungen entfernen“ (nie Erfolg melden, wenn etwas übrig blieb).
    func purgeNotice(_ report: PurgeReport) -> Notice {
        let ortFehlt = settings.secondaryBackupBookmark != nil && store?.secondaryBackupDirectory == nil
        if report.secondaryUnreachable || ortFehlt {
            let name = secondaryBackupName.map { "„" + $0 + "“" } ?? "am zweiten Ort"
            return Notice("Sicherungen \(name) sind noch da – sie öffnen sich weiter mit dem alten Zugang. Siegel entfernt sie, sobald der Ort wieder verbunden ist.",
                          symbol: "exclamationmark.circle")
        }
        if report.interrupted {
            // Befund datei-1: Das Speichern gilt, nur das Entfernen brach ab – wie viele übrig sind, ist unbekannt.
            return Notice("Ältere Sicherungen liessen sich nicht entfernen – sie öffnen sich weiter mit dem alten Zugang.",
                          symbol: "exclamationmark.circle")
        }
        if report.failed > 0 {
            return Notice("\(report.failed) Sicherungen liessen sich nicht entfernen – sie öffnen sich weiter mit dem alten Zugang.",
                          symbol: "exclamationmark.circle")
        }
        return Notice("Alte Sicherungen entfernt")
    }

    /// Holt ein ausstehendes Entfernen am zweiten Ort nach (Ort wieder erreichbar).
    func completePendingSecondaryPurge() {
        guard let pending = settings.pendingSecondaryPurge, let store, store.secondaryBackupDirectory != nil else { return }
        Task { @MainActor [weak self] in
            let report = await Self.background { store.purgeSecondaryBackups(vaultID: pending.vaultID, before: pending.before) }
            guard let self, case let .success(report) = report else { return }
            if report.isComplete, self.settings.pendingSecondaryPurge?.vaultID == pending.vaultID {
                self.settings.pendingSecondaryPurge = nil
                self.syncSecondaryBackupStatus()
                self.show(Notice("Alte Sicherungen am zweiten Ort entfernt"))
            }
        }
    }

    /// Stufe 2 meldet eine erfolgte Sicherung ausserhalb dieses Macs.
    public func noteExternalBackup() {
        settings.lastExternalBackupAt = Date()
    }
}

/// Offene Frage nach einem Zugangswechsel: bis zur Antwort gemerkt (auch über Sperren und Neustart).
public struct PendingPurgeQuestion: Sendable, Equatable {
    public let vaultID: UUID
    public let reason: PurgeReason
}

// MARK: - Snapshots (SPI)

extension AppModel {
    /// Nur für SiegelSnapshots: Bildschirm direkt setzen.
    @_spi(Snapshots) public func snapshotSetScreen(_ screen: Screen) {
        self.screen = screen
    }

    @_spi(Snapshots) public func snapshotSetBusy(_ busy: Bool) {
        self.busy = busy
    }

    @_spi(Snapshots) public func snapshotSetSetup(_ state: SetupState) {
        setup = state
    }

    @_spi(Snapshots) public func snapshotSetCorrupt(_ state: CorruptState) {
        corrupt = state
    }

    @_spi(Snapshots) public func snapshotResolveSecondary() {
        resolveSecondaryBackupLocation()
    }

    @_spi(Snapshots) public func snapshotOpenSettings(page: SettingsState.Page) {
        showsSettings = true
        settingsState.page = page
    }

    /// Nur für SiegelSnapshots: Faktor-Hardware ersetzen (keine Touch-ID-Dialoge, keine Kamera).
    @_spi(Snapshots) public func snapshotUseHardware(_ hardware: any FactorHardware) {
        self.hardware = hardware
        wireDestructionKeyEraser()
    }
}

/// Sperr-Versuch, wie ihn die Teilnehmer sehen.
struct LockAttempt {
    let reason: LockReason
    /// ⌘L darf abgelehnt werden, wenn sonst eine Eingabe verloren ginge.
    let mayRefuse: Bool
}

/// Ergebnis eines Teilnehmers vor dem Sperren.
enum LockParticipantResult {
    /// Gespeichert oder nichts zu tun.
    case done
    /// Gespeichert, aber nicht so wie in der Bearbeitung gewählt (anderer Schutz, eigener Entwurf): Der Hinweis steht
    /// auf dem Sperrbildschirm und nach dem Entsperren (Befund hygiene-1).
    case doneWithNotice(String)
    /// Nicht (vollständig) gespeichert, die Eingabe ist verloren (Grund zum Melden). `notice` ersetzt den allgemeinen
    /// Hinweis, wenn ein Teil gespeichert ist (z. B. Titel und Benutzername, nicht aber die Geheimteile).
    case lost(SiegelError, notice: String?)
    /// Nicht gespeichert, Sperren abgelehnt (nur bei `mayRefuse`); die Eingabe bleibt offen.
    case refused(SiegelError)
}
