import SwiftUI

/// Primärknopf: schwarze Fläche, weisse Schrift (nicht `.borderedProminent`, SPEC §7).
public struct PrimaryButtonStyle: ButtonStyle {
    var fullWidth: Bool

    public init(fullWidth: Bool = false) {
        self.fullWidth = fullWidth
    }

    public func makeBody(configuration: Configuration) -> some View {
        StyledBody(configuration: configuration, fullWidth: fullWidth)
    }

    private struct StyledBody: View {
        let configuration: Configuration
        let fullWidth: Bool
        @Environment(\.isEnabled) private var isEnabled
        @Environment(\.isFocused) private var isFocused

        var body: some View {
            configuration.label
                .font(Theme.bodyMedium)
                .foregroundStyle(isEnabled ? Theme.background : Theme.secondary)
                .padding(.horizontal, 18)
                .frame(maxWidth: fullWidth ? .infinity : nil)
                .frame(height: Theme.buttonHeight)
                .background(
                    RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                        .fill(isEnabled ? Theme.text : Theme.hairline)
                )
                .opacity(configuration.isPressed ? 0.78 : 1)
                .overlay(FocusRing(visible: isFocused, inset: -3))
                .contentShape(Rectangle())
        }
    }
}

/// Zweitknopf: weiss mit Haarlinie, schwarze Schrift.
public struct SecondaryButtonStyle: ButtonStyle {
    var fullWidth: Bool

    public init(fullWidth: Bool = false) {
        self.fullWidth = fullWidth
    }

    public func makeBody(configuration: Configuration) -> some View {
        StyledBody(configuration: configuration, fullWidth: fullWidth)
    }

    private struct StyledBody: View {
        let configuration: Configuration
        let fullWidth: Bool
        @Environment(\.isEnabled) private var isEnabled
        @Environment(\.isFocused) private var isFocused

        var body: some View {
            configuration.label
                .font(Theme.bodyMedium)
                .foregroundStyle(isEnabled ? Theme.text : Theme.secondary)
                .padding(.horizontal, 18)
                .frame(maxWidth: fullWidth ? .infinity : nil)
                .frame(height: Theme.buttonHeight)
                .background(
                    RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                        .fill(configuration.isPressed ? Theme.hairline : Theme.background)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                        .strokeBorder(isEnabled ? Theme.text : Theme.hairline, lineWidth: 1)
                )
                .overlay(FocusRing(visible: isFocused, inset: -3))
                .contentShape(Rectangle())
        }
    }
}

/// Leiser Textknopf (Links wie „Notfallcode verwenden“): grau, beim Überfahren schwarz.
public struct QuietButtonStyle: ButtonStyle {
    var font: Font

    public init(font: Font = Theme.body) {
        self.font = font
    }

    public func makeBody(configuration: Configuration) -> some View {
        StyledBody(configuration: configuration, font: font)
    }

    private struct StyledBody: View {
        let configuration: Configuration
        let font: Font
        @Environment(\.isEnabled) private var isEnabled
        @Environment(\.isFocused) private var isFocused
        @State private var hover = false

        var body: some View {
            configuration.label
                .font(font)
                .foregroundStyle(isEnabled && (hover || configuration.isPressed) ? Theme.text : Theme.secondary)
                .underline(hover && isEnabled, color: Theme.text)
                .padding(.vertical, 2)
                .contentShape(Rectangle())
                .onHover { hover = $0 }
                .overlay(FocusRing(visible: isFocused, inset: -4))
        }
    }
}

/// Textknopf in Schwarz (Aktionen in Listen und Einstellungen).
public struct PlainActionButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        StyledBody(configuration: configuration)
    }

    private struct StyledBody: View {
        let configuration: Configuration
        @Environment(\.isEnabled) private var isEnabled
        @Environment(\.isFocused) private var isFocused

        var body: some View {
            configuration.label
                .font(Theme.body)
                .foregroundStyle(isEnabled ? Theme.text : Theme.secondary)
                .opacity(configuration.isPressed ? 0.6 : 1)
                .contentShape(Rectangle())
                .overlay(FocusRing(visible: isFocused, inset: -4))
        }
    }
}

/// Eigener schwarzer Fokusrahmen (statt des blauen Systemrahmens, `.focusEffectDisabled()`).
struct FocusRing: View {
    let visible: Bool
    var inset: CGFloat = -3

    var body: some View {
        RoundedRectangle(cornerRadius: Theme.corner + 2, style: .continuous)
            .strokeBorder(Theme.text, lineWidth: 2)
            .padding(inset)
            .opacity(visible ? 1 : 0)
            .allowsHitTesting(false)
    }
}
