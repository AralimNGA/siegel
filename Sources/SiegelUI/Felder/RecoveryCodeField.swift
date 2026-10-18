import AppKit
import SwiftUI

/// Gruppiert Notfallcode-Eingaben: gross, nur Base32-Zeichen und `?`, Bindestrich nach je 5 Zeichen.
/// Mehrdeutige Zeichen (O, I, L, U) lässt die Anzeige stehen; der Kern bildet O→0, I/L→1 ab und lehnt U ab.
public enum RecoveryCodeFormatting {
    public static let allowed = Set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ?")

    public static func significant(_ text: String) -> [Character] {
        text.uppercased().filter { allowed.contains($0) }
    }

    public static func format(_ chars: [Character], groups: Int) -> String {
        let limit = min(chars.count, groups * 5)
        var out = ""
        for (index, ch) in chars.prefix(limit).enumerated() {
            if index > 0, index % 5 == 0 { out.append("-") }
            out.append(ch)
        }
        return out
    }

    /// Position nach `n` signifikanten Zeichen im formatierten Text.
    public static func caret(afterSignificant n: Int) -> Int {
        n + (n > 0 ? (n - 1) / 5 : 0)
    }
}

/// Sichtbare Notfallcode-Eingabe: SF Mono, automatische Gruppierung, Secure Event Input bei Fokus.
final class RecoveryNSTextField: SecretNSTextField {
    private var tokens: [NSObjectProtocol] = []
    private var editing = false

    override var hiddenAccessibilityLabel: String { "Notfallcode, verborgen" }

    override func becomeFirstResponder() -> Bool {
        let ok = super.becomeFirstResponder()
        if ok {
            editing = true
            SecureEventInput.enable()
        }
        return ok
    }

    override func textDidEndEditing(_ notification: Notification) {
        super.textDidEndEditing(notification)
        editing = false
        SecureEventInput.disable()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        for token in tokens { NotificationCenter.default.removeObserver(token) }
        tokens.removeAll()
        guard window != nil else {
            if editing { SecureEventInput.disable() }
            editing = false
            return
        }
        let center = NotificationCenter.default
        tokens.append(center.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: nil) { _ in
            MainActor.assumeIsolated { SecureEventInput.disable() }
        })
        tokens.append(center.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: nil) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.editing, self.currentEditor() != nil else { return }
                SecureEventInput.enable()
            }
        })
    }
}

@MainActor
final class RecoveryCodeCoordinator: TextFieldCoordinator {
    var groups: Int
    /// Mehr Zeichen als Platz (z. B. ein Teil mit 56 Zeichen im Feld für den Code mit 55): ungekürzte Eingabe.
    var onOverflow: ((String) -> Void)?

    init(text: Binding<String>, groups: Int, onSubmit: @escaping () -> Void) {
        self.groups = groups
        super.init(text: text, onSubmit: onSubmit)
    }

    override func controlTextDidChange(_ notification: Notification) {
        guard let field = notification.object as? NSTextField else { return }
        let raw = field.stringValue
        let overflow = RecoveryCodeFormatting.significant(raw).count > groups * 5
        let formatted = RecoveryCodeFormatting.format(RecoveryCodeFormatting.significant(raw), groups: groups)
        if formatted != raw, let editor = field.currentEditor() {
            let caretRaw = min(editor.selectedRange.location, (raw as NSString).length)
            let before = (raw as NSString).substring(to: caretRaw)
            let n = RecoveryCodeFormatting.significant(before).count
            editor.string = formatted
            let caret = min(RecoveryCodeFormatting.caret(afterSignificant: n), (formatted as NSString).length)
            editor.selectedRange = NSRange(location: caret, length: 0)
        }
        if text.wrappedValue != formatted {
            text.wrappedValue = formatted
        }
        // Erst nach dem Nachführen: Der Empfänger darf das Feld leeren und die Ansicht wechseln.
        if overflow, let onOverflow { onOverflow(raw) }
    }
}

struct RecoveryCodeBridge: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var groups: Int
    var fontSize: CGFloat
    var centered: Bool
    var autoFocus: Bool
    var onSubmit: () -> Void
    var onFocus: (Bool) -> Void
    var onOverflow: ((String) -> Void)?

    func makeCoordinator() -> RecoveryCodeCoordinator {
        let c = RecoveryCodeCoordinator(text: $text, groups: groups, onSubmit: onSubmit)
        c.onOverflow = onOverflow
        return c
    }

    func makeNSView(context: Context) -> RecoveryNSTextField {
        let field = RecoveryNSTextField(frame: .zero)
        field.applyCommonStyle(font: Theme.nsMono(fontSize, weight: .medium), placeholder: placeholder)
        field.alignment = centered ? .center : .left
        field.stringValue = text
        field.delegate = context.coordinator
        field.wantsInitialFocus = autoFocus
        field.onFocusChange = onFocus
        field.setAccessibilityLabel("Notfallcode")
        return field
    }

    func updateNSView(_ field: RecoveryNSTextField, context: Context) {
        context.coordinator.text = $text
        context.coordinator.onSubmit = onSubmit
        context.coordinator.groups = groups
        context.coordinator.onOverflow = onOverflow
        field.onFocusChange = onFocus
        syncText(field, to: text)
    }
}

/// Notfallcode-Eingabe (ganzer Code mit 11 Gruppen oder einzelne Gruppe zur Bestätigung).
public struct RecoveryCodeField: View {
    @Binding var text: String
    var placeholder: String
    var groups: Int
    var fontSize: CGFloat
    var centered: Bool
    var autoFocus: Bool
    var onSubmit: () -> Void
    var onOverflow: ((String) -> Void)?
    @State private var focused = false

    public init(_ placeholder: String, text: Binding<String>, groups: Int = 11, fontSize: CGFloat = 15,
                centered: Bool = false, autoFocus: Bool = false, onSubmit: @escaping () -> Void = {}) {
        self.placeholder = placeholder
        self._text = text
        self.groups = groups
        self.fontSize = fontSize
        self.centered = centered
        self.autoFocus = autoFocus
        self.onSubmit = onSubmit
    }

    /// Meldet eine Eingabe mit mehr Zeichen, als das Feld fasst (ungekürzt), z. B. einen Teil im Feld für den Code.
    public func onOverflow(_ handler: ((String) -> Void)?) -> RecoveryCodeField {
        var copy = self
        copy.onOverflow = handler
        return copy
    }

    public var body: some View {
        SecretGate {
            FieldFrame(focused: focused, height: max(Theme.fieldHeight, fontSize + 24)) {
                RecoveryCodeBridge(text: $text, placeholder: placeholder, groups: groups, fontSize: fontSize,
                                   centered: centered, autoFocus: autoFocus, onSubmit: onSubmit,
                                   onFocus: { focused = $0 }, onOverflow: onOverflow)
                    .secretAccessibility("Notfallcode, verborgen")
            }
        } placeholder: { reveal in
            FieldFrame(focused: false, height: max(Theme.fieldHeight, fontSize + 24)) {
                HiddenSecretPlaceholder(reveal: reveal).frame(maxWidth: .infinity)
            }
        }
    }
}
