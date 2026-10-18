import AppKit
import SiegelCore
import SwiftUI

/// Die App (SPEC §7 Szene): ein einziges Fenster „Siegel“, ohne Titelleiste, ohne Wiederherstellung.
public struct SiegelApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    public init() {}

    public var body: some Scene {
        Window("Siegel", id: "main") {
            RootView(model: appDelegate.model)
                .containerBackground(Theme.background, for: .window)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentMinSize)
        .defaultSize(width: 920, height: 600)
        .restorationBehavior(.disabled)
        .commands { SiegelCommands(model: appDelegate.model) }
    }
}

/// App-Delegate: Härtung beim Start, Beenden erst nach dem Speichern, Sperren beim Beenden.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model: AppModel

    override init() {
        ProcessHardening.applyEarly()
        model = AppModel.production()
        super.init()
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        ProcessHardening.applyAppKit()
        WindowGuard.shared.start()
        // Nach einem Absturz: eigenen Inhalt aus der Zwischenablage entfernen.
        SecretPasteboard.clearIfOwned()
        UserDefaults.standard.set(false, forKey: "NSQuitAlwaysKeepsWindows")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        model.startPlatformServices()
        ProcessHardening.scrubMenus()
        MenuScrubber.shared.start()
        if model.screen == .blocked(.alreadyRunning) {
            SingleInstance.activateOtherInstance()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Befund #26: Die Klartext-CSV eines Exports liegt noch da – die Erinnerung lebt nur im Speicher, also jetzt
        // fragen (auch wenn das Fenster schon zu ist).
        if model.exportedCSV != nil {
            switch ExportQuitQuestion.ask(folderName: model.exportedCSV?.deletingLastPathComponent().lastPathComponent) {
            case .delete:
                model.deleteExportedCSV()
                if let rest = model.exportedCSV {
                    ExportQuitQuestion.informNotDeleted(rest)
                }
            case .keep:
                break
            case .cancel:
                return .terminateCancel
            }
        }
        // (c) Erst beenden, wenn das Speichern fertig ist (höchstens 5 s).
        let sofort = model.prepareForTermination {
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return sofort ? .terminateNow : .terminateLater
    }

    func applicationWillTerminate(_ notification: Notification) {
        if model.holdsOpenVault { model.lock(reason: .terminate) }
        SecretPasteboard.clearIfOwned()
        SecureEventInput.disable()
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        false
    }
}

/// Entfernt AutoFill, Diktat und Zeichenpalette auch nach späteren Menü-Neuaufbauten durch SwiftUI.
@MainActor
final class MenuScrubber {
    static let shared = MenuScrubber()
    private var token: NSObjectProtocol?
    private var lastSignature = -1

    func start() {
        guard token == nil else { return }
        token = NotificationCenter.default.addObserver(forName: NSApplication.didUpdateNotification, object: nil,
                                                       queue: nil) { _ in
            MainActor.assumeIsolated { MenuScrubber.shared.scrubIfChanged() }
        }
    }

    private func scrubIfChanged() {
        guard let main = NSApp.mainMenu else { return }
        let signature = main.items.reduce(main.items.count) { $0 &* 31 &+ ($1.submenu?.items.count ?? 0) }
        guard signature != lastSignature else { return }
        ProcessHardening.scrubMenus()
        lastSignature = main.items.reduce(main.items.count) { $0 &* 31 &+ ($1.submenu?.items.count ?? 0) }
    }
}

/// Menübefehle (SPEC §7): ⌘N Neuer Eintrag, ⌘F Suchen, ⌘E Bearbeiten, ⌘L Sperren, ⌘, Einstellungen.
/// Dienste-Menü und Textbearbeitungs-Untermenüs (Rechtschreibung, Ersetzungen, Sprache) entfallen.
struct SiegelCommands: Commands {
    let model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .appSettings) {
            Button("Einstellungen…") { model.openSettings() }
                .keyboardShortcut(",", modifiers: .command)
                // Befund #36: nicht während einer Bearbeitung (wie das Zahnrad in der Seitenleiste).
                .disabled(!model.isUnlocked || model.browser.mode == .edit)
        }
        CommandGroup(replacing: .systemServices) {}
        CommandGroup(replacing: .newItem) {
            Button("Neuer Eintrag") { model.send(.newEntry) }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(!model.vaultCommandsEnabled)
        }
        CommandGroup(replacing: .saveItem) {}
        CommandGroup(replacing: .importExport) {}
        CommandGroup(replacing: .printItem) {}
        CommandGroup(replacing: .textEditing) {
            Button("Suchen") { model.send(.find) }
                .keyboardShortcut("f", modifiers: .command)
                .disabled(!model.vaultCommandsEnabled)
        }
        CommandGroup(replacing: .textFormatting) {}
        CommandMenu("Tresor") {
            Button("Bearbeiten") { model.send(.edit) }
                .keyboardShortcut("e", modifiers: .command)
                .disabled(!model.vaultCommandsEnabled || !model.canEditEntry)
            Divider()
            Button("Sperren") { model.lock(reason: .manual) }
                .keyboardShortcut("l", modifiers: .command)
                .disabled(!model.holdsOpenVault)
        }
        CommandGroup(replacing: .help) {}
    }
}

/// Frage beim Beenden, solange eine CSV-Exportdatei im Klartext liegt (Befund #26). Systemdialog, weil das Fenster
/// beim Beenden schon geschlossen sein kann; ohne Standardknopf (sonst Systemakzentfarbe), Esc = Abbrechen.
@MainActor
enum ExportQuitQuestion {
    enum Answer { case delete, keep, cancel }

    static func ask(folderName: String?) -> Answer {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Exportdatei noch vorhanden"
        alert.informativeText = text(folderName: folderName)
        alert.addButton(withTitle: "Löschen und beenden")
        alert.addButton(withTitle: "Behalten und beenden")
        alert.addButton(withTitle: "Abbrechen")
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[2].keyEquivalent = "\u{1b}"
        WindowGuard.shared.protect(alert.window)
        switch alert.runModal() {
        case .alertFirstButtonReturn: return .delete
        case .alertSecondButtonReturn: return .keep
        default: return .cancel
        }
    }

    static func text(folderName: String?) -> String {
        let ort = folderName.map { "im Ordner „" + $0 + "“" } ?? "auf diesem Mac"
        return "Die CSV-Datei mit allen Passwörtern im Klartext liegt noch " + ort
            + ". Nach dem Beenden erinnert Siegel nicht mehr daran. Jetzt endgültig löschen?"
    }

    static func informNotDeleted(_ url: URL) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Exportdatei liess sich nicht löschen"
        alert.informativeText = "Lösche sie im Finder und leere danach den Papierkorb: " + url.path
        alert.addButton(withTitle: "OK")
        alert.buttons[0].keyEquivalent = "\u{1b}"
        WindowGuard.shared.protect(alert.window)
        alert.runModal()
    }
}

/// Nur für SiegelSnapshots: Text der Frage beim Beenden.
@_spi(Snapshots) public enum ExportQuitQuestionProbe {
    @MainActor public static func text(_ folderName: String?) -> String {
        ExportQuitQuestion.text(folderName: folderName)
    }
}
