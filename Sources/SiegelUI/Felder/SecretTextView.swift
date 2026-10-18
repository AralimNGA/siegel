import AppKit
import SwiftUI

/// Mehrzeiliges Geheimnis-Feld (Notizen beim Bearbeiten). Gleiche Regeln wie `SecretField`.
struct SecretTextViewBridge: NSViewRepresentable {
    @Binding var text: String
    var editable: Bool
    var font: NSFont
    var onFocus: (Bool) -> Void

    @MainActor
    final class Coordinator: NSObject, NSTextViewDelegate {
        var text: Binding<String>
        var onFocus: (Bool) -> Void

        init(text: Binding<String>, onFocus: @escaping (Bool) -> Void) {
            self.text = text
            self.onFocus = onFocus
        }

        func textDidChange(_ notification: Notification) {
            guard let view = notification.object as? NSTextView else { return }
            if text.wrappedValue != view.string { text.wrappedValue = view.string }
        }

        func textDidBeginEditing(_ notification: Notification) { onFocus(true) }
        func textDidEndEditing(_ notification: Notification) { onFocus(false) }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text, onFocus: onFocus)
    }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView(frame: .zero)
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true

        let view = SecretTextViewCore(frame: .zero)
        view.isEditable = editable
        view.isSelectable = editable
        view.drawsBackground = false
        view.font = font
        view.textColor = Theme.nsText
        view.textContainerInset = NSSize(width: 0, height: 6)
        view.isVerticallyResizable = true
        view.isHorizontallyResizable = false
        view.autoresizingMask = [.width]
        view.textContainer?.widthTracksTextView = true
        view.allowsUndo = true
        view.string = text
        view.delegate = context.coordinator
        view.setAccessibilityLabel("Notizen, verborgen")
        TextHardening.style(view)
        WindowCleanup.register(view)
        scroll.documentView = view
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.text = $text
        context.coordinator.onFocus = onFocus
        guard let view = scroll.documentView as? SecretTextViewCore else { return }
        if view.string != text { view.string = text }
        if view.isEditable != editable {
            view.isEditable = editable
            view.isSelectable = editable
        }
    }
}

/// Mehrzeiliges Geheimnis-Feld mit Rahmen.
public struct SecretTextView: View {
    @Binding var text: String
    var editable: Bool
    var font: NSFont
    var minHeight: CGFloat
    @State private var focused = false

    public init(text: Binding<String>, editable: Bool = true, font: NSFont = Theme.nsFont(13), minHeight: CGFloat = 96) {
        self._text = text
        self.editable = editable
        self.font = font
        self.minHeight = minHeight
    }

    public var body: some View {
        SecretGate {
            SecretTextViewBridge(text: $text, editable: editable, font: font, onFocus: { focused = $0 })
                .secretAccessibility("Notizen, verborgen")
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .frame(minHeight: minHeight)
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                        .strokeBorder(focused ? Theme.text : Theme.hairline, lineWidth: focused ? 1.5 : 1)
                )
        } placeholder: { reveal in
            HiddenSecretPlaceholder(reveal: reveal)
                .frame(maxWidth: .infinity, minHeight: minHeight)
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                        .strokeBorder(Theme.hairline, lineWidth: 1)
                )
        }
    }
}
