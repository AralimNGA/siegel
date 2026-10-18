import AppKit

/// Aufräumen beim Sperren (SPEC §6 „Sperren räumt auf“, „Sperren ohne Datenverlust“ (d)).
@MainActor
enum WindowCleanup {
    /// Alle eigenen Feld-Editoren (schwach gehalten), damit ihr Text beim Sperren geleert werden kann.
    private static let editors = NSHashTable<NSTextView>.weakObjects()

    static func register(_ editor: NSTextView) {
        editors.add(editor)
    }

    /// Schliesst Sheets, Alerts, Popover und Sichern/Öffnen-Panels (Abbrechen).
    static func dismissTransientWindows() {
        for window in NSApp.windows {
            if let panel = window as? NSSavePanel {
                // NSOpenPanel ist eine Unterklasse von NSSavePanel.
                panel.cancel(nil)
                continue
            }
            if let parent = window.sheetParent {
                parent.endSheet(window, returnCode: .cancel)
                continue
            }
            let klasse = NSStringFromClass(type(of: window))
            if klasse.contains("Popover") {
                window.close()
            }
        }
        if NSApp.modalWindow != nil {
            NSApp.abortModal()
        }
    }

    /// Erstantworter lösen, Feld-Editoren leeren, Undo-Verlauf löschen.
    static func scrubResponders() {
        for window in NSApp.windows {
            window.makeFirstResponder(nil)
            window.fieldEditor(false, for: nil)?.string = ""
            window.undoManager?.removeAllActions()
        }
        for editor in editors.allObjects {
            editor.string = ""
            editor.undoManager?.removeAllActions()
        }
    }
}
