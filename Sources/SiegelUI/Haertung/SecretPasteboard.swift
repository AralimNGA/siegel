import AppKit

/// Einziger Weg, auf dem Siegel etwas in die Zwischenablage legt (SPEC §6).
/// - nur dieser Mac (`.currentHostOnly`, kein Universal Clipboard)
/// - markiert als verborgen und flüchtig (nspasteboard.org: Zwischenablage-Verläufe übernehmen es nicht)
/// - wird nach Ablauf, beim Sperren (ausser bei der Sperre durch den App-Wechsel, Befund hygiene-2), bei Ruhezustand,
///   Bildschirmsperre und Benutzerwechsel, beim Beenden und beim nächsten Start geleert – jeweils nur, wenn der
///   `changeCount` noch unserer ist. Siegel liest den Inhalt der allgemeinen Zwischenablage nie.
/// - Solange ein Geheimnis dort liegt, verhindert eine Aktivität App Nap: Der Ablauf kommt auch im Hintergrund und bei
///   gesperrtem Tresor pünktlich.
@MainActor
public enum SecretPasteboard {
    static let changeCountKey = "SiegelPasteboardChangeCount"
    static let expiryKey = "SiegelPasteboardExpiry"
    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    /// Für Tests und Snapshots austauschbar.
    static var defaults: UserDefaults = .standard
    private static var clearTask: Task<Void, Never>?
    /// Gegen App Nap, solange ein Geheimnis in der Zwischenablage liegt (endet in `forget`).
    private static var activity: NSObjectProtocol?

    /// Legt ein Geheimnis in die Zwischenablage und leert sie nach `lifetime` Sekunden.
    public static func copy(_ secret: String, lifetime: TimeInterval) {
        let pb = NSPasteboard.general
        let cc = pb.prepareForNewContents(with: .currentHostOnly)
        pb.setString(secret, forType: .string)
        pb.setData(Data(), forType: concealedType)
        pb.setData(Data(), forType: transientType)
        defaults.set(cc, forKey: changeCountKey)
        defaults.set(Date().addingTimeInterval(lifetime).timeIntervalSince1970, forKey: expiryKey)
        startExpiry(lifetime)
    }

    /// Ablauf-Aufgabe (neu) starten und App Nap verhindern, bis `forget` läuft.
    static func startExpiry(_ lifetime: TimeInterval) {
        clearTask?.cancel()
        if activity == nil {
            activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiatedAllowingIdleSystemSleep],
                                                             reason: "Zwischenablage leeren")
        }
        clearTask = Task { @MainActor in
            try? await Task.sleep(for: .seconds(lifetime))
            guard !Task.isCancelled else { return }
            clearIfExpired()
        }
    }

    static var holdsActivity: Bool { activity != nil }

    /// Leert die Zwischenablage, wenn sie noch unseren Inhalt trägt (Sperren, Beenden, Start nach Absturz).
    public static func clearIfOwned() {
        guard defaults.object(forKey: changeCountKey) != nil else { return }
        let cc = defaults.integer(forKey: changeCountKey)
        let pb = NSPasteboard.general
        if pb.changeCount == cc {
            pb.clearContents()
        }
        forget()
    }

    /// Prüft die Ablaufzeit (Timer, App wird aktiv).
    public static func clearIfExpired() {
        guard defaults.object(forKey: expiryKey) != nil else { return }
        let ablauf = defaults.double(forKey: expiryKey)
        if Date().timeIntervalSince1970 >= ablauf {
            clearIfOwned()
        }
    }

    /// Liegt noch ein Geheimnis von uns in der Zwischenablage?
    public static var holdsSecret: Bool {
        guard defaults.object(forKey: changeCountKey) != nil else { return false }
        return NSPasteboard.general.changeCount == defaults.integer(forKey: changeCountKey)
    }

    private static func forget() {
        clearTask?.cancel()
        clearTask = nil
        defaults.removeObject(forKey: changeCountKey)
        defaults.removeObject(forKey: expiryKey)
        if let activity { ProcessInfo.processInfo.endActivity(activity) }
        activity = nil
    }
}

/// Nur für SiegelSnapshots: Merker der Zwischenablage prüfen, ohne die echte Zwischenablage zu berühren.
@_spi(Snapshots) @MainActor
public enum SecretPasteboardProbe {
    /// Eigene Ablage für die Merker (statt `.standard`); nil = zurück auf `.standard`.
    public static func useDefaults(_ defaults: UserDefaults?) {
        SecretPasteboard.defaults = defaults ?? .standard
    }

    /// Merker setzen wie nach einem Kopieren, aber mit einem fremden `changeCount` (die Zwischenablage zählt nur
    /// aufwärts): Ein Leeren entfernt dann nur den Merker und lässt die echte Zwischenablage stehen. Startet auch die
    /// Ablauf-Aufgabe und die Aktivität gegen App Nap wie `copy`.
    public static func rememberForeignCopy(lifetime: TimeInterval) {
        let d = SecretPasteboard.defaults
        d.set(NSPasteboard.general.changeCount - 1, forKey: SecretPasteboard.changeCountKey)
        d.set(Date().addingTimeInterval(lifetime).timeIntervalSince1970, forKey: SecretPasteboard.expiryKey)
        SecretPasteboard.startExpiry(lifetime)
    }

    /// Liegt (laut Merker) noch ein Geheimnis von Siegel in der Zwischenablage?
    public static var remembered: Bool {
        SecretPasteboard.defaults.object(forKey: SecretPasteboard.changeCountKey) != nil
    }

    /// Läuft die Aktivität gegen App Nap?
    public static var preventsAppNap: Bool { SecretPasteboard.holdsActivity }

    /// Dauer, die ⌘C aus einem Geheimnis-Feld jetzt bekäme (Befund hygiene-3).
    public static var fieldCopyLifetime: TimeInterval { SecretPasteboard.currentFieldCopyLifetime }
}

/// Merkt sich beim Einfügen ins Master-Passwort-Feld nur den `changeCount` der Zwischenablage.
/// Nach erfolgreichem Entsperren wird sie geleert, falls sie sich seither nicht verändert hat
/// (sie enthielt dann vermutlich das Master-Passwort). Der Inhalt wird nie gelesen.
@MainActor
public enum MasterPasswordPasteTracker {
    private static var pastedChangeCount: Int?

    static func notePaste() {
        pastedChangeCount = NSPasteboard.general.changeCount
    }

    /// Gibt true zurück, wenn geleert wurde.
    public static func clearIfUnchanged() -> Bool {
        defer { pastedChangeCount = nil }
        guard let cc = pastedChangeCount else { return false }
        let pb = NSPasteboard.general
        guard pb.changeCount == cc else { return false }
        pb.clearContents()
        return true
    }

    public static func reset() {
        pastedChangeCount = nil
    }
}
