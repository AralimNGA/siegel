import AppKit

/// Fensterschutz (SPEC §6): setzt JEDES Fenster der App auf `sharingType = .none` – Hauptfenster,
/// Sheets, Alerts, Druck-, Sichern- und Öffnen-Panels sind eigene Fenster, der Wert vererbt sich nicht.
/// Bildschirmaufnahmen und Bildschirmfreigaben zeigen die Fenster dann nicht.
@MainActor
public final class WindowGuard {
    public static let shared = WindowGuard()

    private var observers: [NSObjectProtocol] = []
    private var started = false

    private init() {}

    public func start() {
        guard !started else { return }
        started = true
        let center = NotificationCenter.default
        let names: [Notification.Name] = [
            NSApplication.willUpdateNotification,
            NSApplication.didUpdateNotification,
            NSWindow.didBecomeKeyNotification,
            NSWindow.didBecomeMainNotification,
            NSWindow.didUpdateNotification,
        ]
        for name in names {
            let token = center.addObserver(forName: name, object: nil, queue: nil) { _ in
                // AppKit meldet diese Ereignisse auf dem Main-Thread.
                MainActor.assumeIsolated { WindowGuard.shared.protectAll() }
            }
            observers.append(token)
        }
        protectAll()
    }

    /// Setzt alle Fenster der App auf „nicht teilbar“.
    public func protectAll() {
        for window in NSApp.windows {
            protect(window)
        }
    }

    /// Ein Fenster schützen (auch direkt vor dem Zeigen eigener Alerts/Panels aufrufen).
    public func protect(_ window: NSWindow) {
        if window.sharingType != .none {
            window.sharingType = .none
        }
    }

    /// Geheimnis-Ansichten fragen vor dem Zeichnen: Ist das Fenster geschützt?
    public static func isProtected(_ window: NSWindow?) -> Bool {
        window?.sharingType == NSWindow.SharingType.none
    }
}
