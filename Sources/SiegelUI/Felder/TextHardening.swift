import AppKit
import SwiftUI

/// Gemeinsame Härtung aller Textansichten (SPEC §6): keine Rechtschreibprüfung, Ersetzungen,
/// Vervollständigung, Daten-/Link-Erkennung, Vorhersage und Writing Tools.
@MainActor
enum TextHardening {
    static func configure(_ view: NSTextView) {
        view.isContinuousSpellCheckingEnabled = false
        view.isGrammarCheckingEnabled = false
        view.isAutomaticSpellingCorrectionEnabled = false
        view.isAutomaticTextReplacementEnabled = false
        view.isAutomaticQuoteSubstitutionEnabled = false
        view.isAutomaticDashSubstitutionEnabled = false
        view.isAutomaticTextCompletionEnabled = false
        view.isAutomaticDataDetectionEnabled = false
        view.isAutomaticLinkDetectionEnabled = false
        view.inlinePredictionType = .no
        view.writingToolsBehavior = .none
        view.smartInsertDeleteEnabled = false
        view.isRichText = false
        view.importsGraphics = false
        view.usesFontPanel = false
        view.usesRuler = false
        view.isIncrementalSearchingEnabled = false
    }

    static func configure(_ field: NSTextField) {
        field.isAutomaticTextCompletionEnabled = false
        field.allowsCharacterPickerTouchBarItem = false
        field.contentType = nil
        if let editor = field.currentEditor() as? NSTextView {
            configure(editor)
        }
    }

    /// AX-Werte von Geheimnissen nur mit VoiceOver (SPEC §6 Bedienungshilfen).
    static var exposesSecretsToAccessibility: Bool {
        NSWorkspace.shared.isVoiceOverEnabled
    }
}

/// Gehärtete Textansicht: Grundlage für Feld-Editoren und mehrzeilige Felder.
class HardenedTextView: NSTextView {
    override init(frame frameRect: NSRect, textContainer container: NSTextContainer?) {
        super.init(frame: frameRect, textContainer: container)
        TextHardening.configure(self)
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        TextHardening.configure(self)
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        TextHardening.configure(self)
    }

    override func becomeFirstResponder() -> Bool {
        TextHardening.configure(self)
        return super.becomeFirstResponder()
    }

    // Keine Wortvervollständigung (Esc/⌥Esc öffnet sonst ein Fenster mit Wörtern aus dem Text).
    override func complete(_ sender: Any?) {}
}

/// Textansicht für Geheimnisse (Feld-Editor von SecretField, Notizen, Verlauf):
/// ⌘C/⌘X und Kontextmenü führen in die SecretPasteboard, kein Dienste-Menü, kein Ziehen,
/// eingeschränktes Kontextmenü, AX-Werte nur mit VoiceOver, Zeichnen nur in geschützten Fenstern.
class SecretTextViewCore: HardenedTextView {
    /// Kontextmenü beim Bearbeiten mit „Einfügen“ und „Alles auswählen“.
    var offersEditingItems: Bool { isEditable }

    override func copy(_ sender: Any?) {
        let range = selectedRange()
        guard range.length > 0, NSMaxRange(range) <= (string as NSString).length else { return }
        SecretPasteboard.copyFromField((string as NSString).substring(with: range))
    }

    override func cut(_ sender: Any?) {
        let range = selectedRange()
        guard range.length > 0 else { return }
        copy(sender)
        if isEditable, shouldChangeText(in: range, replacementString: "") {
            replaceCharacters(in: range, with: "")
            didChangeText()
        }
    }

    // Kein Dienste-Menü (weder senden noch empfangen).
    override func validRequestor(forSendType sendType: NSPasteboard.PasteboardType?,
                                 returnType: NSPasteboard.PasteboardType?) -> Any? {
        nil
    }

    // Nichts auf fremde Zwischenablagen schreiben (Ziehen, Dienste).
    override func writeSelection(to pboard: NSPasteboard, types: [NSPasteboard.PasteboardType]) -> Bool {
        false
    }

    override func writeSelection(to pboard: NSPasteboard, type: NSPasteboard.PasteboardType) -> Bool {
        false
    }

    override func dragSelection(with event: NSEvent, offset mouseOffset: NSSize, slideBack: Bool) -> Bool {
        false
    }

    override var acceptableDragTypes: [NSPasteboard.PasteboardType] { [] }

    override func menu(for event: NSEvent) -> NSMenu? {
        let menu = NSMenu(title: "")
        menu.allowsContextMenuPlugIns = false
        let kopieren = NSMenuItem(title: "Kopieren", action: #selector(copy(_:)), keyEquivalent: "")
        kopieren.target = self
        menu.addItem(kopieren)
        if offersEditingItems {
            let einfuegen = NSMenuItem(title: "Einfügen", action: #selector(paste(_:)), keyEquivalent: "")
            einfuegen.target = self
            menu.addItem(einfuegen)
            let alle = NSMenuItem(title: "Alles auswählen", action: #selector(selectAll(_:)), keyEquivalent: "")
            alle.target = self
            menu.addItem(alle)
        }
        return menu
    }

    override func draw(_ dirtyRect: NSRect) {
        guard WindowGuard.isProtected(window) else { return }
        super.draw(dirtyRect)
    }

    // MARK: Bedienungshilfen: Werte nur mit VoiceOver

    override func accessibilityValue() -> String? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityValue() : nil
    }

    override func accessibilitySelectedText() -> String? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilitySelectedText() : nil
    }

    override func accessibilityString(for range: NSRange) -> String? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityString(for: range) : nil
    }

    override func accessibilityAttributedString(for range: NSRange) -> NSAttributedString? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityAttributedString(for: range) : nil
    }

    override func accessibilityRTF(for range: NSRange) -> Data? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityRTF(for: range) : nil
    }

    override func accessibilityNumberOfCharacters() -> Int {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityNumberOfCharacters() : 0
    }

    override func accessibilityVisibleCharacterRange() -> NSRange {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityVisibleCharacterRange() : NSRange(location: 0, length: 0)
    }

    override func accessibilityLabel() -> String? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityLabel() : "Geheimnis, verborgen"
    }
}

/// Zweite Schicht (SPEC §6): Ohne VoiceOver ist die Geheimnis-Ansicht im AX-Baum verborgen; der Behälter
/// trägt nur eine Bezeichnung („Passwort, verborgen“). Mit VoiceOver bleibt alles bedienbar.
struct SecretAccessibility: ViewModifier {
    var label: String

    func body(content: Content) -> some View {
        if TextHardening.exposesSecretsToAccessibility {
            content
        } else {
            ZStack { content.accessibilityHidden(true) }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(label)
        }
    }
}

extension View {
    func secretAccessibility(_ label: String = "Passwort, verborgen") -> some View {
        modifier(SecretAccessibility(label: label))
    }
}

extension SecretPasteboard {
    /// Ablaufzeit für Kopien aus Geheimnis-Feldern, erst beim Kopieren bestimmt (Befund hygiene-3): Einstellung ∧
    /// Stufe ∧ Schutz des bearbeiteten Eintrags (vom AppModel gesetzt). Ohne Provider gilt der strengste Wert.
    static var fieldCopyLifetimeProvider: (@MainActor () -> TimeInterval)?
    /// Rückmeldung an die Oberfläche („Kopiert – wird in 30 s gelöscht“).
    static var onCopy: (@MainActor (TimeInterval) -> Void)?

    /// Strengster Wert (Stufe 3–5, Schutz 3–5), falls kein Modell die Dauer liefert.
    static let strictestLifetime: TimeInterval = 15

    static var currentFieldCopyLifetime: TimeInterval {
        fieldCopyLifetimeProvider?() ?? strictestLifetime
    }

    static func copyFromField(_ secret: String) {
        let lifetime = currentFieldCopyLifetime
        copy(secret, lifetime: lifetime)
        onCopy?(lifetime)
    }
}
