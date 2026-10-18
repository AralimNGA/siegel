import AppKit
import SwiftUI

// Klartext- und Geheimnis-Felder auf NSTextField-Basis (SPEC §6 Eingabefelder).
// Jedes Feld bekommt über seine Zelle einen eigenen, gehärteten Feld-Editor.

/// Grundklasse: meldet Fokus, kann beim Erscheinen den Fokus übernehmen, ohne Systemrahmen.
class SiegelTextField: NSTextField {
    var onFocusChange: ((Bool) -> Void)?
    var wantsInitialFocus = false
    private var didTakeInitialFocus = false

    override func becomeFirstResponder() -> Bool {
        let ok = super.becomeFirstResponder()
        if ok {
            TextHardening.configure(self)
            if let editor = currentEditor() as? NSTextView { TextHardening.style(editor) }
            onFocusChange?(true)
        }
        return ok
    }

    override func textDidEndEditing(_ notification: Notification) {
        super.textDidEndEditing(notification)
        onFocusChange?(false)
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        guard wantsInitialFocus, !didTakeInitialFocus, window != nil else { return }
        didTakeInitialFocus = true
        RunLoop.main.perform(inModes: [.common]) { [weak self] in
            MainActor.assumeIsolated {
                guard let self, let window = self.window else { return }
                window.makeFirstResponder(self)
                if let editor = self.currentEditor() {
                    editor.selectedRange = NSRange(location: (editor.string as NSString).length, length: 0)
                }
            }
        }
    }

    func applyCommonStyle(font: NSFont, placeholder: String) {
        isBordered = false
        isBezeled = false
        drawsBackground = false
        focusRingType = .none
        usesSingleLineMode = true
        lineBreakMode = .byClipping
        cell?.isScrollable = true
        cell?.wraps = false
        self.font = font
        textColor = Theme.nsText
        placeholderAttributedString = NSAttributedString(string: placeholder, attributes: [
            .foregroundColor: Theme.nsSecondary,
            .font: font,
        ])
        setContentHuggingPriority(.defaultLow, for: .horizontal)
        setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        TextHardening.configure(self)
    }
}

final class HardenedTextFieldCell: NSTextFieldCell {
    private var editor: HardenedTextView?

    override func fieldEditor(for controlView: NSView) -> NSTextView? {
        if let editor { return editor }
        let neu = HardenedTextView(frame: .zero)
        neu.isFieldEditor = true
        TextHardening.style(neu)
        WindowCleanup.register(neu)
        editor = neu
        return neu
    }
}

final class SecretTextFieldCell: NSTextFieldCell {
    private var editor: SecretTextViewCore?

    override func fieldEditor(for controlView: NSView) -> NSTextView? {
        if let editor { return editor }
        let neu = SecretTextViewCore(frame: .zero)
        neu.isFieldEditor = true
        TextHardening.style(neu)
        WindowCleanup.register(neu)
        editor = neu
        return neu
    }
}

/// Klartext-Feld (Benutzername, Website, Suche, Titel).
final class HardenedNSTextField: SiegelTextField {
    override class var cellClass: AnyClass? {
        get { HardenedTextFieldCell.self }
        set {}
    }
}

/// Geheimnis-Feld: eigener Feld-Editor mit SecretPasteboard, zeichnet nur in geschützten Fenstern,
/// AX-Wert nur mit VoiceOver.
class SecretNSTextField: SiegelTextField {
    override class var cellClass: AnyClass? {
        get { SecretTextFieldCell.self }
        set {}
    }

    /// Bezeichnung für den AX-Baum ohne VoiceOver (Unterklassen: z. B. „Notfallcode, verborgen“).
    var hiddenAccessibilityLabel: String { "Passwort, verborgen" }

    override func draw(_ dirtyRect: NSRect) {
        guard WindowGuard.isProtected(window) else { return }
        super.draw(dirtyRect)
    }

    // MARK: Bedienungshilfen: Text nur mit VoiceOver (SPEC §6)
    // Nicht nur der Wert: Auch die parametrisierten Attribute (AXStringForRange, AXAttributedStringForRange,
    // AXRTFForRange) und die Länge liefern sonst den Klartext an jedes Programm mit Bedienungshilfen-Recht.

    override func accessibilityValue() -> String? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityValue() : nil
    }

    override func accessibilityLabel() -> String? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityLabel() : hiddenAccessibilityLabel
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

    override func accessibilitySelectedText() -> String? {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilitySelectedText() : nil
    }

    override func accessibilityVisibleCharacterRange() -> NSRange {
        TextHardening.exposesSecretsToAccessibility ? super.accessibilityVisibleCharacterRange() : NSRange(location: 0, length: 0)
    }
}

extension TextHardening {
    /// Monochrome Auswahl und schwarze Einfügemarke.
    static func style(_ view: NSTextView) {
        view.insertionPointColor = Theme.nsText
        view.selectedTextAttributes = [
            .backgroundColor: Theme.nsHairline,
            .foregroundColor: Theme.nsText,
        ]
    }
}

// MARK: - Brücke zu SwiftUI

/// Gemeinsamer Koordinator für Textfelder: Text → Binding, Enter → onSubmit.
@MainActor
class TextFieldCoordinator: NSObject, NSTextFieldDelegate {
    var text: Binding<String>
    var onSubmit: () -> Void
    var onCancel: (() -> Void)?

    init(text: Binding<String>, onSubmit: @escaping () -> Void) {
        self.text = text
        self.onSubmit = onSubmit
    }

    func controlTextDidChange(_ notification: Notification) {
        guard let field = notification.object as? NSTextField else { return }
        if text.wrappedValue != field.stringValue {
            text.wrappedValue = field.stringValue
        }
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
        if selector == #selector(NSResponder.insertNewline(_:)) {
            onSubmit()
            return true
        }
        if selector == #selector(NSResponder.cancelOperation(_:)), let onCancel {
            onCancel()
            return true
        }
        return false
    }
}

@MainActor
func syncText(_ field: NSTextField, to text: String) {
    if let editor = field.currentEditor() {
        if editor.string != text { editor.string = text }
    } else if field.stringValue != text {
        field.stringValue = text
    }
}

struct HardenedTextFieldBridge: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var font: NSFont
    var autoFocus: Bool
    var secret: Bool
    var onSubmit: () -> Void
    var onFocus: (Bool) -> Void

    func makeCoordinator() -> TextFieldCoordinator {
        TextFieldCoordinator(text: $text, onSubmit: onSubmit)
    }

    func makeNSView(context: Context) -> SiegelTextField {
        let field: SiegelTextField = secret ? SecretNSTextField(frame: .zero) : HardenedNSTextField(frame: .zero)
        field.applyCommonStyle(font: font, placeholder: placeholder)
        field.stringValue = text
        field.delegate = context.coordinator
        field.wantsInitialFocus = autoFocus
        field.onFocusChange = onFocus
        if secret {
            field.setAccessibilityLabel("Passwort, verborgen")
        } else {
            field.setAccessibilityLabel(placeholder)
        }
        return field
    }

    func updateNSView(_ field: SiegelTextField, context: Context) {
        context.coordinator.text = $text
        context.coordinator.onSubmit = onSubmit
        field.onFocusChange = onFocus
        syncText(field, to: text)
    }
}

/// Klartext-Feld mit Rahmen (Haarlinie, bei Fokus schwarz).
public struct HardenedTextField: View {
    @Binding var text: String
    var placeholder: String
    var font: NSFont
    var autoFocus: Bool
    var framed: Bool
    var onSubmit: () -> Void
    @State private var focused = false

    public init(_ placeholder: String, text: Binding<String>, font: NSFont = Theme.nsFont(13),
                autoFocus: Bool = false, framed: Bool = true, onSubmit: @escaping () -> Void = {}) {
        self.placeholder = placeholder
        self._text = text
        self.font = font
        self.autoFocus = autoFocus
        self.framed = framed
        self.onSubmit = onSubmit
    }

    public var body: some View {
        let bridge = HardenedTextFieldBridge(text: $text, placeholder: placeholder, font: font, autoFocus: autoFocus,
                                             secret: false, onSubmit: onSubmit, onFocus: { focused = $0 })
        if framed {
            FieldFrame(focused: focused) { bridge }
        } else {
            bridge
        }
    }
}

/// Geheimnis-Feld zum Bearbeiten (Passwort beim Bearbeiten, Generator-Ergebnis). Klartext sichtbar,
/// aber ohne Dienste, Ziehen, Systemzwischenablage und AX-Wert (ausser VoiceOver).
public struct SecretField: View {
    @Binding var text: String
    var placeholder: String
    var font: NSFont
    var autoFocus: Bool
    var framed: Bool
    var onSubmit: () -> Void
    @State private var focused = false

    public init(_ placeholder: String, text: Binding<String>, font: NSFont = Theme.nsMono(13),
                autoFocus: Bool = false, framed: Bool = true, onSubmit: @escaping () -> Void = {}) {
        self.placeholder = placeholder
        self._text = text
        self.font = font
        self.autoFocus = autoFocus
        self.framed = framed
        self.onSubmit = onSubmit
    }

    public var body: some View {
        let bridge = HardenedTextFieldBridge(text: $text, placeholder: placeholder, font: font, autoFocus: autoFocus,
                                             secret: true, onSubmit: onSubmit, onFocus: { focused = $0 })
            .secretAccessibility("Passwort, verborgen")
        SecretGate {
            if framed {
                FieldFrame(focused: focused) { bridge }
            } else {
                bridge
            }
        } placeholder: { reveal in
            FieldFrame(focused: false) {
                HiddenSecretPlaceholder(reveal: reveal)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}
