import AppKit
import Darwin

/// Prozess- und Menü-Härtung beim Start (SPEC §5, §6).
@MainActor
enum ProcessHardening {
    /// So früh wie möglich, noch vor dem ersten Fenster.
    static func applyEarly() {
        // Keine Speicherabbilder (Core Dumps) mit Klartext.
        var limit = rlimit(rlim_cur: 0, rlim_max: 0)
        _ = setrlimit(RLIMIT_CORE, &limit)
        UserDefaults.standard.register(defaults: [
            "NSDisabledDictationMenuItem": true,
            "NSDisabledCharacterPaletteMenuItem": true,
            // AutoFill-Vorschläge (Kontakte, Passwörter) in Textfeldern aus
            "NSAutoFillHeuristicControllerEnabled": false,
        ])
    }

    /// Sobald NSApp existiert.
    static func applyAppKit() {
        NSApp.appearance = NSAppearance(named: .aqua)
        NSWindow.allowsAutomaticWindowTabbing = false
        scrubMenus()
    }

    /// Entfernt AutoFill, Diktat und Zeichenpalette aus dem Hauptmenü. Mehrfach aufrufbar (SwiftUI baut
    /// Menüs neu auf); billig, weil nur wenige Einträge geprüft werden.
    static func scrubMenus() {
        guard let main = NSApp.mainMenu else { return }
        for (index, top) in main.items.enumerated().reversed() {
            guard let menu = top.submenu else { continue }
            for item in menu.items.reversed() where isUnwanted(item) {
                menu.removeItem(item)
            }
            tidySeparators(menu)
            // Leere Menüs (Format, Darstellung, Hilfe) entfernen; das App-Menü bleibt.
            if index > 0 && menu.items.allSatisfy(\.isSeparatorItem) {
                main.removeItem(top)
            }
        }
    }

    /// Keine doppelten, führenden oder abschliessenden Trennlinien.
    private static func tidySeparators(_ menu: NSMenu) {
        var vorher = true
        for item in menu.items {
            if item.isSeparatorItem {
                if vorher { menu.removeItem(item) } else { vorher = true }
            } else {
                vorher = false
            }
        }
        while let letztes = menu.items.last, letztes.isSeparatorItem {
            menu.removeItem(letztes)
        }
    }

    private static let unwantedTitles: Set<String> = [
        "AutoFill", "Automatisch ausfüllen", "Autom. ausfüllen",
        "Start Dictation…", "Diktat starten …", "Diktat starten…",
        "Emoji & Symbols", "Emoji & Symbole",
        "Writing Tools", "Schreibwerkzeuge",
    ]

    private static func isUnwanted(_ item: NSMenuItem) -> Bool {
        if unwantedTitles.contains(item.title) { return true }
        let kennung = (item.identifier?.rawValue ?? "").lowercased()
        if kennung.contains("autofill") { return true }
        if let action = item.action {
            let name = NSStringFromSelector(action).lowercased()
            if name.contains("autofill") || name.contains("startdictation") || name.contains("orderfrontcharacterpalette") {
                return true
            }
        }
        if let sub = item.submenu, !sub.items.isEmpty {
            let alle = sub.items.compactMap { $0.action.map { NSStringFromSelector($0).lowercased() } }
            if !alle.isEmpty, alle.allSatisfy({ $0.contains("autofill") || $0.contains("insertfrom") }) {
                return true
            }
        }
        return false
    }
}
