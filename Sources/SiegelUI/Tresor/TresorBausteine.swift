import AppKit
import SiegelCore
import SwiftUI

// Bausteine der Tresor-Ansicht. Alles schwarz/weiss (SPEC §7), keine Systemakzentfarbe.

// MARK: - Geheimnis-Anzeige

/// Nicht bearbeitbare, nicht auswählbare Anzeige eines Geheimnisses (Passwort, Verlauf, Generator-Ergebnis)
/// auf Basis von `SecretNSTextField`: zeichnet nur in geschützten Fenstern, AX-Wert nur mit VoiceOver,
/// kein Kontextmenü, kein Ziehen, kein Erstantworter.
final class SecretLabelField: SecretNSTextField {
    override var acceptsFirstResponder: Bool { false }
    override func menu(for event: NSEvent) -> NSMenu? { nil }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}

struct SecretLabel: NSViewRepresentable {
    var text: String
    var font: NSFont = Theme.nsMono(13)
    var color: NSColor = Theme.nsText

    func makeNSView(context: Context) -> SecretLabelField {
        let field = SecretLabelField(frame: .zero)
        field.isEditable = false
        field.isSelectable = false
        field.isBordered = false
        field.isBezeled = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.usesSingleLineMode = false
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byCharWrapping
        field.cell?.wraps = true
        field.cell?.isScrollable = false
        field.font = font
        field.textColor = color
        field.stringValue = text
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.setContentHuggingPriority(.defaultHigh, for: .vertical)
        field.setAccessibilityLabel("Passwort, verborgen")
        return field
    }

    func updateNSView(_ field: SecretLabelField, context: Context) {
        if field.stringValue != text { field.stringValue = text }
        if field.font != font { field.font = font }
        if field.textColor != color { field.textColor = color }
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: SecretLabelField, context: Context) -> CGSize? {
        guard let cell = nsView.cell else { return nil }
        let breite = proposal.width.flatMap { $0.isFinite && $0 > 0 ? $0 : nil } ?? 100_000
        let groesse = cell.cellSize(forBounds: NSRect(x: 0, y: 0, width: breite, height: 100_000))
        return CGSize(width: min(ceil(groesse.width), breite), height: ceil(groesse.height))
    }
}

/// Notizen in der Detailansicht (SPEC §7.4): `SecretTextViewCore`, nicht bearbeitbar und nicht
/// auswählbar, Höhe nach Inhalt. Zeichnet nur in geschützten Fenstern; AX-Wert nur mit VoiceOver.
struct SecretNotesView: NSViewRepresentable {
    var text: String

    func makeNSView(context: Context) -> SecretTextViewCore {
        let storage = NSTextStorage()
        let layout = NSLayoutManager()
        storage.addLayoutManager(layout)
        let container = NSTextContainer(size: NSSize(width: 400, height: CGFloat.greatestFiniteMagnitude))
        container.widthTracksTextView = true
        container.lineFragmentPadding = 0
        layout.addTextContainer(container)
        let view = SecretTextViewCore(frame: .zero, textContainer: container)
        view.isEditable = false
        view.isSelectable = false
        view.drawsBackground = false
        view.textContainerInset = .zero
        view.isVerticallyResizable = false
        view.isHorizontallyResizable = false
        view.font = Theme.nsFont(13)
        view.textColor = Theme.nsText
        view.string = text
        view.setAccessibilityLabel("Notizen, verborgen")
        WindowCleanup.register(view)
        return view
    }

    func updateNSView(_ view: SecretTextViewCore, context: Context) {
        if view.string != text { view.string = text }
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: SecretTextViewCore, context: Context) -> CGSize? {
        guard let container = nsView.textContainer, let layout = nsView.layoutManager else { return nil }
        let breite = proposal.width.flatMap { $0.isFinite && $0 > 0 ? $0 : nil } ?? 400
        container.containerSize = NSSize(width: breite, height: CGFloat.greatestFiniteMagnitude)
        layout.ensureLayout(for: container)
        let hoehe = layout.usedRect(for: container).height
        return CGSize(width: breite, height: ceil(max(hoehe, 16)))
    }
}

/// Passwort-Zeile: verdeckt (Punkte, Länge verraten sie nicht) oder aufgedeckt in SF Mono.
/// Aufgedeckt nur in geschützten Fenstern und nicht auf externen Bildschirmen (SPEC §6).
struct PasswordValue: View {
    var password: String
    var revealed: Bool
    var size: CGFloat = 13

    var body: some View {
        Group {
            if revealed {
                SecretGate {
                    SecretLabel(text: password, font: Theme.nsMono(size, weight: .regular))
                        .secretAccessibility("Passwort, verborgen")
                        .frame(maxWidth: .infinity, alignment: .leading)
                } placeholder: { reveal in
                    HiddenSecretPlaceholder(reveal: reveal)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                Text(password.isEmpty ? "–" : "••••••••••")
                    .font(.system(size: size + 3, weight: .regular))
                    .kerning(0.6)
                    .foregroundStyle(password.isEmpty ? Theme.secondary : Theme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel(password.isEmpty ? "Kein Passwort" : "Passwort, verborgen")
            }
        }
    }
}

// MARK: - Knöpfe

/// Symbolknopf (28 × 28): schwarzes SF Symbol, beim Überfahren hairline-graue Fläche.
struct IconButton: View {
    var symbol: String
    var label: String
    var size: CGFloat = 14
    var quiet = false
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: size, weight: .regular))
                .frame(width: 28, height: 28)
                .contentShape(Rectangle())
        }
        .buttonStyle(IconButtonStyle(quiet: quiet))
        .help(label)
        .accessibilityLabel(label)
    }
}

struct IconButtonStyle: ButtonStyle {
    var quiet: Bool

    func makeBody(configuration: Configuration) -> some View {
        StyledBody(configuration: configuration, quiet: quiet)
    }

    private struct StyledBody: View {
        let configuration: Configuration
        let quiet: Bool
        @Environment(\.isEnabled) private var isEnabled
        @Environment(\.isFocused) private var isFocused
        @State private var hover = false

        var body: some View {
            configuration.label
                .foregroundStyle(!isEnabled ? Theme.hairline : (quiet && !hover ? Theme.secondary : Theme.text))
                .background(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(isEnabled && (hover || configuration.isPressed) ? Theme.hairline : Color.clear)
                )
                .onHover { hover = $0 }
                .overlay(FocusRing(visible: isFocused, inset: -2))
        }
    }
}

/// Kleiner Knopf für Kopfzeilen (Höhe 28): primär schwarz, sonst weiss mit Rahmen.
struct CompactButtonStyle: ButtonStyle {
    var primary = false
    /// Rahmen in Haarlinien-Grau statt Schwarz (Knöpfe in Listenzeilen).
    var quiet = false
    var height: CGFloat = 28

    func makeBody(configuration: Configuration) -> some View {
        StyledBody(configuration: configuration, primary: primary, quiet: quiet, height: height)
    }

    private struct StyledBody: View {
        let configuration: Configuration
        let primary: Bool
        let quiet: Bool
        let height: CGFloat
        @Environment(\.isEnabled) private var isEnabled
        @Environment(\.isFocused) private var isFocused

        var body: some View {
            configuration.label
                .font(Theme.caption.weight(.medium))
                .foregroundStyle(primary ? (isEnabled ? Theme.background : Theme.secondary)
                                         : (isEnabled ? Theme.text : Theme.secondary))
                .padding(.horizontal, 12)
                .frame(height: height)
                .background(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(primary ? (isEnabled ? Theme.text : Theme.hairline)
                                      : (configuration.isPressed ? Theme.hairline : Theme.background))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .strokeBorder(primary ? Color.clear : (isEnabled && !quiet ? Theme.text : Theme.hairline),
                                      lineWidth: 1)
                )
                .opacity(primary && configuration.isPressed ? 0.78 : 1)
                .overlay(FocusRing(visible: isFocused, inset: -3))
                .contentShape(Rectangle())
        }
    }
}

// MARK: - Generator-Steuerelemente

/// Kästchen in Schwarz/Weiss (statt des farbigen Systemkästchens).
struct MonoCheckbox: View {
    var title: String
    @Binding var isOn: Bool
    @FocusState private var focused: Bool

    var body: some View {
        Button {
            isOn.toggle()
        } label: {
            HStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 4, style: .continuous)
                        .fill(isOn ? Theme.text : Theme.background)
                    RoundedRectangle(cornerRadius: 4, style: .continuous)
                        .strokeBorder(isOn ? Theme.text : Theme.secondary, lineWidth: 1)
                    if isOn {
                        Image(systemName: "checkmark")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Theme.background)
                    }
                }
                .frame(width: 15, height: 15)
                Text(title)
                    .font(Theme.body)
                    .foregroundStyle(Theme.text)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable()
        .focused($focused)
        .focusEffectDisabled()
        .overlay(FocusRing(visible: focused, inset: -3))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        .accessibilityValue(isOn ? "an" : "aus")
        .accessibilityAddTraits(.isButton)
    }
}

/// Regler in Schwarz/Weiss (Länge 8–64). Pfeiltasten links/rechts ändern um 1.
struct MonoSlider: View {
    @Binding var value: Int
    var range: ClosedRange<Int>
    @FocusState private var focused: Bool

    var body: some View {
        GeometryReader { geo in
            let breite = max(geo.size.width - 16, 1)
            let anteil = CGFloat(value - range.lowerBound) / CGFloat(max(range.upperBound - range.lowerBound, 1))
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.hairline).frame(height: 3).padding(.horizontal, 8)
                Capsule().fill(Theme.text).frame(width: 8 + breite * anteil, height: 3)
                Circle()
                    .fill(Theme.background)
                    .overlay(Circle().strokeBorder(Theme.text, lineWidth: 1.5))
                    .frame(width: 16, height: 16)
                    .overlay(Circle().strokeBorder(Theme.text, lineWidth: 2).padding(-4).opacity(focused ? 1 : 0))
                    .offset(x: breite * anteil)
            }
            .frame(height: 24)
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0).onChanged { drag in
                let t = min(max((drag.location.x - 8) / breite, 0), 1)
                let neu = range.lowerBound + Int((t * CGFloat(range.upperBound - range.lowerBound)).rounded())
                if neu != value { value = neu }
            })
        }
        .frame(height: 24)
        .focusable()
        .focused($focused)
        .focusEffectDisabled()
        .onMoveCommand { richtung in
            switch richtung {
            case .left: value = max(range.lowerBound, value - 1)
            case .right: value = min(range.upperBound, value + 1)
            default: break
            }
        }
        .accessibilityElement()
        .accessibilityLabel("Länge")
        .accessibilityValue("\(value) Zeichen")
        .accessibilityAdjustableAction { richtung in
            switch richtung {
            case .increment: value = min(range.upperBound, value + 1)
            case .decrement: value = max(range.lowerBound, value - 1)
            @unknown default: break
            }
        }
    }
}

// MARK: - Suchfeld

/// Koordinator des Suchfelds: Pfeil runter / Enter → Liste, Esc → leeren.
@MainActor
final class SearchFieldCoordinator: TextFieldCoordinator {
    var onMoveDown: () -> Void = {}
    var onEscape: () -> Void = {}
    var lastFocusRequest = 0

    override func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
        if selector == #selector(NSResponder.moveDown(_:)) {
            onMoveDown()
            return true
        }
        if selector == #selector(NSResponder.cancelOperation(_:)) {
            onEscape()
            return true
        }
        return super.control(control, textView: textView, doCommandBy: selector)
    }
}

/// Suchfeld (SPEC §6): gehärtetes NSTextField ohne Verlauf/Recents. ⌘F setzt den Fokus.
struct SearchFieldBridge: NSViewRepresentable {
    @Binding var text: String
    var focusRequest: Int
    var onSubmit: () -> Void
    var onMoveDown: () -> Void
    var onFocus: (Bool) -> Void

    func makeCoordinator() -> SearchFieldCoordinator {
        let coordinator = SearchFieldCoordinator(text: $text, onSubmit: onSubmit)
        coordinator.lastFocusRequest = focusRequest
        return coordinator
    }

    func makeNSView(context: Context) -> SiegelTextField {
        let field = HardenedNSTextField(frame: .zero)
        field.applyCommonStyle(font: Theme.nsFont(13), placeholder: "Suchen")
        field.stringValue = text
        field.delegate = context.coordinator
        field.onFocusChange = onFocus
        field.setAccessibilityLabel("Suchen")
        return field
    }

    func updateNSView(_ field: SiegelTextField, context: Context) {
        let coordinator = context.coordinator
        coordinator.text = $text
        coordinator.onSubmit = onSubmit
        coordinator.onMoveDown = onMoveDown
        coordinator.onEscape = { [binding = $text] in binding.wrappedValue = "" }
        field.onFocusChange = onFocus
        syncText(field, to: text)
        if coordinator.lastFocusRequest != focusRequest {
            coordinator.lastFocusRequest = focusRequest
            RunLoop.main.perform(inModes: [.common]) { [weak field] in
                MainActor.assumeIsolated {
                    guard let field, let window = field.window else { return }
                    window.makeFirstResponder(field)
                    field.currentEditor()?.selectAll(nil)
                }
            }
        }
    }
}

struct SearchField: View {
    @Binding var text: String
    var focusRequest: Int
    var enabled: Bool
    var onSubmit: () -> Void
    var onMoveDown: () -> Void
    @State private var focused = false

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Theme.secondary)
            SearchFieldBridge(text: $text, focusRequest: focusRequest, onSubmit: onSubmit, onMoveDown: onMoveDown,
                              onFocus: { focused = $0 })
            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.secondary)
                }
                .buttonStyle(.plain)
                .focusable(false)
                .accessibilityLabel("Suche leeren")
            }
        }
        .padding(.horizontal, 10)
        .frame(height: 30)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(focused ? Theme.background : Theme.hairline)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(focused ? Theme.text : Color.clear, lineWidth: 1.5)
        )
        .disabled(!enabled)
    }
}

// MARK: - Kleine Texte

/// Abschnittsbeschriftung in Grossbuchstaben (wie in den Einstellungen).
struct SectionLabel: View {
    var text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(Theme.label)
            .foregroundStyle(Theme.secondary)
            .textCase(.uppercase)
            .kerning(0.6)
    }
}
