import AppKit
import SwiftUI

/// Master-Passwort-Feld (SPEC §6): echtes `NSSecureTextField` (Punkte, Secure Event Input des Systems).
/// Beim Einfügen wird nur der `changeCount` der Zwischenablage gemerkt, nie ihr Inhalt.
final class MasterSecureTextField: NSSecureTextField {
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

    override func accessibilityValue() -> String? { nil }
}

@MainActor
final class MasterPasswordCoordinator: TextFieldCoordinator {
    private var lastLength = 0

    override func controlTextDidChange(_ notification: Notification) {
        guard let field = notification.object as? NSTextField else { return }
        let length = (field.stringValue as NSString).length
        // Einfügen erkennen, ohne die Zwischenablage zu lesen: Text wird länger, aber nicht durch
        // einfaches Tippen (⌘V, Menü „Einfügen“, Kontextmenü). Der Feld-Editor eines NSSecureTextField
        // ist eine private Klasse; `paste(_:)` lässt sich dort nicht direkt überschreiben.
        if length > lastLength, Self.isPasteLike(NSApp.currentEvent) {
            MasterPasswordPasteTracker.notePaste()
        }
        lastLength = length
        super.controlTextDidChange(notification)
    }

    func reset(length: Int) {
        lastLength = length
    }

    static func isPasteLike(_ event: NSEvent?) -> Bool {
        guard let event else { return true }
        if event.type == .keyDown {
            return event.modifierFlags.contains(.command)
        }
        return true
    }
}

struct MasterPasswordBridge: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var autoFocus: Bool
    var enabled: Bool
    var onSubmit: () -> Void
    var onFocus: (Bool) -> Void

    func makeCoordinator() -> MasterPasswordCoordinator {
        MasterPasswordCoordinator(text: $text, onSubmit: onSubmit)
    }

    func makeNSView(context: Context) -> MasterSecureTextField {
        let field = MasterSecureTextField(frame: .zero)
        let font = Theme.nsFont(14)
        field.isBordered = false
        field.isBezeled = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.usesSingleLineMode = true
        field.cell?.isScrollable = true
        field.cell?.wraps = false
        field.font = font
        field.textColor = Theme.nsText
        field.placeholderAttributedString = NSAttributedString(string: placeholder, attributes: [
            .foregroundColor: Theme.nsSecondary, .font: font,
        ])
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.stringValue = text
        field.delegate = context.coordinator
        field.wantsInitialFocus = autoFocus
        field.onFocusChange = onFocus
        field.isEnabled = enabled
        field.setAccessibilityLabel(placeholder)
        TextHardening.configure(field)
        context.coordinator.reset(length: (text as NSString).length)
        return field
    }

    func updateNSView(_ field: MasterSecureTextField, context: Context) {
        context.coordinator.text = $text
        context.coordinator.onSubmit = onSubmit
        field.onFocusChange = onFocus
        if field.isEnabled != enabled { field.isEnabled = enabled }
        if field.stringValue != text {
            syncText(field, to: text)
            context.coordinator.reset(length: (text as NSString).length)
        }
    }
}

/// Master-Passwort-Eingabe mit eigenem Rahmen.
public struct MasterPasswordField: View {
    @Binding var text: String
    var placeholder: String
    var autoFocus: Bool
    var enabled: Bool
    var showsSubmit: Bool
    var onSubmit: () -> Void
    @State private var focused = false

    public init(_ placeholder: String = "Master-Passwort", text: Binding<String>, autoFocus: Bool = false,
                enabled: Bool = true, showsSubmit: Bool = false, onSubmit: @escaping () -> Void = {}) {
        self.placeholder = placeholder
        self._text = text
        self.autoFocus = autoFocus
        self.enabled = enabled
        self.showsSubmit = showsSubmit
        self.onSubmit = onSubmit
    }

    public var body: some View {
        FieldFrame(focused: focused) {
            HStack(spacing: 8) {
                MasterPasswordBridge(text: $text, placeholder: placeholder, autoFocus: autoFocus, enabled: enabled,
                                     onSubmit: onSubmit, onFocus: { focused = $0 })
                if showsSubmit {
                    Button(action: onSubmit) {
                        Image(systemName: "arrow.right.circle.fill")
                            .font(.system(size: 19, weight: .regular))
                            .foregroundStyle(text.isEmpty || !enabled ? Theme.hairline : Theme.text)
                    }
                    .buttonStyle(.plain)
                    .focusable(false)
                    .disabled(text.isEmpty || !enabled)
                    .accessibilityLabel("Entsperren")
                }
            }
        }
    }
}
