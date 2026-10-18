import AppKit

/// Anlass einer Sperre (nur für die Oberfläche, nie protokolliert).
public enum LockReason: Sendable, Equatable {
    case manual
    case inactivity
    case sleep
    case screenLocked
    case sessionSwitch
    case terminate
    /// App-Wechsel in Stufe 3+ (SPEC v4 §13)
    case deactivated
    /// Totmann-Schalter hat während einer offenen Sitzung vernichtet (SPEC v4.3 §23.2)
    case deadman
}

/// Automatische Sperre (SPEC §6). Inaktivität = keine Eingabe in Siegel. Gemerkt wird der Zeitpunkt der letzten
/// Eingabe (`ContinuousClock`, läuft auch im Ruhezustand weiter); die Minuten werden erst bei der Prüfung gelesen,
/// damit eine geänderte Einstellung beim nächsten Tick gilt (Befund #30). Geprüft wird bei jedem Tick, beim
/// Aktivieren der App und bei Änderungen der Fenster-Sichtbarkeit – jeweils bevor Inhalt gezeigt wird.
/// Ruhezustand, Bildschirmsperre, Bildschirm aus und Benutzerwechsel sperren sofort; `willSleep` synchron
/// im Handler, damit die sodium-Puffer vor dem Ruhezustandsabbild genullt sind.
@MainActor
public final class AutoLock {
    private let clock = ContinuousClock()
    private var lastInput: ContinuousClock.Instant
    private var minutes: () -> Int
    private var isArmed: () -> Bool
    private var lockNow: (LockReason) -> Void
    private var monitor: Any?
    private var timer: Timer?
    private var tokens: [(NotificationCenter, NSObjectProtocol)] = []
    private var activity: NSObjectProtocol?

    public init(minutes: @escaping () -> Int, isArmed: @escaping () -> Bool, lockNow: @escaping (LockReason) -> Void) {
        self.minutes = minutes
        self.isArmed = isArmed
        self.lockNow = lockNow
        self.lastInput = ContinuousClock().now
    }

    public func start() {
        guard monitor == nil else { return }
        touch()
        monitor = NSEvent.addLocalMonitorForEvents(matching: [
            .keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .leftMouseDragged, .scrollWheel,
        ]) { event in
            // Erst prüfen (abgelaufene Frist nicht durch eine Eingabe verlängern), dann verlängern. Löst genau
            // diese Eingabe die Sperre aus, wird sie verschluckt (Befund #24): Sonst würde ein Tastenkürzel noch
            // gegen die alte, nicht neu aufgebaute Ansicht ausgeführt (⇧⌘C kopierte das Passwort nach dem Sperren).
            let gesperrt = MainActor.assumeIsolated { () -> Bool in
                let gesperrt = AutoLockRegistry.current?.check() ?? false
                if !gesperrt { AutoLockRegistry.current?.touch() }
                return gesperrt
            }
            return gesperrt ? nil : event
        }
        AutoLockRegistry.current = self

        let tick = Timer(timeInterval: 5, repeats: true) { _ in
            MainActor.assumeIsolated { _ = AutoLockRegistry.current?.check() }
        }
        RunLoop.main.add(tick, forMode: .common)
        timer = tick

        let app = NotificationCenter.default
        observe(app, NSApplication.didBecomeActiveNotification) { _ = $0.check() }
        observe(app, NSWindow.didChangeOcclusionStateNotification) { _ = $0.check() }
        observe(app, NSApplication.didBecomeActiveNotification) { _ in SecretPasteboard.clearIfExpired() }

        let workspace = NSWorkspace.shared.notificationCenter
        observe(workspace, NSWorkspace.willSleepNotification) { $0.fire(.sleep) }
        observe(workspace, NSWorkspace.screensDidSleepNotification) { $0.fire(.screenLocked) }
        observe(workspace, NSWorkspace.sessionDidResignActiveNotification) { $0.fire(.sessionSwitch) }

        let distributed = DistributedNotificationCenter.default()
        observe(distributed, Notification.Name("com.apple.screenIsLocked")) { $0.fire(.screenLocked) }
    }

    public func stop() {
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
        timer?.invalidate()
        timer = nil
        for (center, token) in tokens { center.removeObserver(token) }
        tokens.removeAll()
        if AutoLockRegistry.current === self { AutoLockRegistry.current = nil }
    }

    /// Solange ein Tresor offen ist: App Nap verhindern, damit der Prüf-Takt der Auto-Sperre auch im
    /// Hintergrund pünktlich läuft (sonst drosselt macOS die Timer und der Tresor bliebe länger offen).
    public func vaultDidOpen() {
        touch()
        guard activity == nil else { return }
        activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiatedAllowingIdleSystemSleep],
                                                         reason: "Auto-Sperre")
    }

    public func vaultDidClose() {
        if let activity { ProcessInfo.processInfo.endActivity(activity) }
        activity = nil
    }

    /// Letzte Eingabe merken (Eingabe, Entsperren).
    public func touch() {
        lastInput = clock.now
    }

    /// Sperrt, wenn seit der letzten Eingabe die (aktuell eingestellte) Frist abgelaufen ist. true = gesperrt.
    @discardableResult
    public func check() -> Bool {
        guard isArmed() else { return false }
        guard clock.now >= lastInput.advanced(by: .seconds(max(1, minutes()) * 60)) else { return false }
        lockNow(.inactivity)
        return true
    }

    /// Ruhezustand, Bildschirm aus, Bildschirmsperre, Benutzerwechsel. Die Zwischenablage wird vor der Prüfung
    /// geleert (Befund hygiene-2): Nach der Sperre beim App-Wechsel ist nichts mehr scharf, ein kopiertes Geheimnis
    /// liegt aber noch bis zu 15 s dort.
    private func fire(_ reason: LockReason) {
        SecretPasteboard.clearIfOwned()
        guard isArmed() else { return }
        lockNow(reason)
    }

    /// Beobachter mit `queue: nil`: läuft synchron im Thread des Absenders (für willSleep nötig).
    private func observe(_ center: NotificationCenter, _ name: Notification.Name,
                         _ action: @escaping @MainActor (AutoLock) -> Void) {
        let token = center.addObserver(forName: name, object: nil, queue: nil) { _ in
            AutoLock.onMain {
                guard let current = AutoLockRegistry.current else { return }
                action(current)
            }
        }
        tokens.append((center, token))
    }

    /// Führt synchron auf dem Main-Thread aus (auch wenn ein Absender aus einem anderen Thread meldet).
    nonisolated static func onMain(_ body: @escaping @MainActor () -> Void) {
        if Thread.isMainThread {
            MainActor.assumeIsolated { body() }
        } else {
            DispatchQueue.main.sync { MainActor.assumeIsolated { body() } }
        }
    }
}

/// Die eine aktive AutoLock-Instanz (die Ereignis-Blöcke sind nicht an `self` gebunden).
@MainActor
enum AutoLockRegistry {
    static weak var current: AutoLock?
}
