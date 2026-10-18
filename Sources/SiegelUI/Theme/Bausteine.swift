import AppKit
import SiegelCore
import SwiftUI

// Kleine, wiederverwendbare Bausteine der Oberfläche. Alles schwarz/weiss nach SPEC §7.

/// Haarlinie #E5E5E5, waagrecht oder senkrecht.
public struct Hairline: View {
    var vertical: Bool

    public init(vertical: Bool = false) {
        self.vertical = vertical
    }

    public var body: some View {
        Rectangle()
            .fill(Theme.hairline)
            .frame(width: vertical ? Theme.hairlineWidth : nil, height: vertical ? nil : Theme.hairlineWidth)
    }
}

/// Feine Fortschrittslinie während Argon2 (unbestimmt): ein schwarzes Segment gleitet über eine Haarlinie.
public struct ProgressLine: View {
    var active: Bool

    public init(active: Bool) {
        self.active = active
    }

    public var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Rectangle().fill(Theme.hairline)
                if active {
                    TimelineView(.animation) { context in
                        let t = context.date.timeIntervalSinceReferenceDate
                        let phase = CGFloat(t.truncatingRemainder(dividingBy: 1.3) / 1.3)
                        let segment = geo.size.width * 0.28
                        Rectangle()
                            .fill(Theme.text)
                            .frame(width: segment)
                            .offset(x: -segment + (geo.size.width + segment) * phase)
                    }
                }
            }
            .clipped()
        }
        .frame(height: 1)
        .opacity(active ? 1 : 0)
        .accessibilityLabel(active ? "Bitte warten" : "")
    }
}

/// Stärke-Anzeige beim Master-Passwort: schwarzer Balken, Wort, „geschätzte Stärke (Bit)“.
public struct StrengthMeter: View {
    var bits: Double
    var level: PasswordStrength.Level
    var meetsPolicy: Bool
    var isEmpty: Bool

    public init(bits: Double, level: PasswordStrength.Level, meetsPolicy: Bool, isEmpty: Bool) {
        self.bits = bits
        self.level = level
        self.meetsPolicy = meetsPolicy
        self.isEmpty = isEmpty
    }

    public static func word(_ level: PasswordStrength.Level) -> String {
        switch level {
        case .veryWeak: "Sehr schwach"
        case .weak: "Schwach"
        case .fair: "Mittel"
        case .strong: "Stark"
        case .veryStrong: "Sehr stark"
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(Theme.hairline)
                        .frame(height: 3)
                    Capsule()
                        .fill(Theme.text)
                        .frame(width: isEmpty ? 0 : max(4, geo.size.width * min(bits, 100) / 100), height: 3)
                    // Marke bei 60 Bit (Mindestanforderung)
                    Rectangle()
                        .fill(Theme.secondary)
                        .frame(width: 1, height: 9)
                        .offset(x: geo.size.width * 0.6 - 0.5)
                        .opacity(meetsPolicy ? 0 : 1)
                }
                .frame(height: 9)
            }
            .frame(height: 9)
            HStack(spacing: 0) {
                if isEmpty {
                    Text("Mindestens 12 Zeichen und 60 Bit")
                        .foregroundStyle(Theme.secondary)
                    Spacer(minLength: 0)
                } else {
                    Text(Self.word(level))
                        .foregroundStyle(Theme.text)
                        .fontWeight(.medium)
                    Text("  ·  geschätzte Stärke \(Int(bits.rounded())) Bit")
                        .foregroundStyle(Theme.secondary)
                    Spacer(minLength: 8)
                    if !meetsPolicy {
                        Text("nötig: 60 Bit")
                            .foregroundStyle(Theme.secondary)
                    }
                }
            }
            .font(Theme.caption)
            .monospacedDigit()
        }
        .accessibilityElement(children: .combine)
    }
}

/// Kurzes Schütteln (falsches Passwort). `shakes` hochzählen, mit Animation.
public struct ShakeEffect: GeometryEffect {
    public var animatableData: CGFloat
    var travel: CGFloat = 7

    public init(shakes: Int) {
        animatableData = CGFloat(shakes)
    }

    public func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: travel * sin(animatableData * .pi * 6), y: 0))
    }
}

/// Rahmen um Eingabefelder: Haarlinie, bei Fokus schwarz (eigener Fokusrahmen).
public struct FieldFrame<Content: View>: View {
    var focused: Bool
    var height: CGFloat
    var content: Content

    public init(focused: Bool, height: CGFloat = Theme.fieldHeight, @ViewBuilder content: () -> Content) {
        self.focused = focused
        self.height = height
        self.content = content()
    }

    public var body: some View {
        content
            .padding(.horizontal, 12)
            .frame(height: height)
            .background(
                RoundedRectangle(cornerRadius: Theme.corner, style: .continuous).fill(Theme.background)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                    .strokeBorder(focused ? Theme.text : Theme.hairline, lineWidth: focused ? 1.5 : 1)
            )
    }
}

/// Segment-Auswahl in Schwarz/Weiss (statt des farbigen Systemsteuerelements).
public struct SegmentedChoice<Value: Hashable>: View {
    let options: [(value: Value, title: String)]
    @Binding var selection: Value
    @FocusState private var focused: Bool

    public init(_ options: [(value: Value, title: String)], selection: Binding<Value>) {
        self.options = options
        self._selection = selection
    }

    public var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(options.enumerated()), id: \.offset) { _, option in
                let selected = option.value == selection
                Button {
                    selection = option.value
                } label: {
                    Text(option.title)
                        .font(Theme.caption.weight(selected ? .semibold : .regular))
                        .foregroundStyle(selected ? Theme.background : Theme.text)
                        .padding(.horizontal, 12)
                        .frame(minWidth: 54)
                        .frame(height: 26)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(selected ? Theme.text : Color.clear)
                        )
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .focusable(false)
            }
        }
        .padding(2)
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(Theme.hairline, lineWidth: 1)
        )
        .focusable()
        .focused($focused)
        .focusEffectDisabled()
        .overlay(FocusRing(visible: focused, inset: -3))
        .onMoveCommand { richtung in
            guard let index = options.firstIndex(where: { $0.value == selection }) else { return }
            switch richtung {
            case .left where index > 0: selection = options[index - 1].value
            case .right where index < options.count - 1: selection = options[index + 1].value
            default: break
            }
        }
        .accessibilityElement(children: .contain)
    }
}

/// Schalter in Schwarz/Weiss.
public struct MonochromeToggleStyle: ToggleStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        StyledBody(configuration: configuration)
    }

    private struct StyledBody: View {
        let configuration: Configuration
        @Environment(\.isFocused) private var isFocused

        var body: some View {
            HStack(spacing: 12) {
                configuration.label
                Spacer(minLength: 0)
                ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                    Capsule()
                        .fill(configuration.isOn ? Theme.text : Theme.hairline)
                        .frame(width: 34, height: 20)
                    Circle()
                        .fill(Theme.background)
                        .frame(width: 16, height: 16)
                        .padding(2)
                }
                .overlay(
                    Capsule().strokeBorder(Theme.text, lineWidth: 2).padding(-3).opacity(isFocused ? 1 : 0)
                )
                .animation(.easeOut(duration: 0.15), value: configuration.isOn)
                .onTapGesture { configuration.isOn.toggle() }
            }
            .contentShape(Rectangle())
        }
    }
}

/// Dezente Rückmeldezeile („Kopiert – wird in 30 s gelöscht“).
public struct NoticeLine: View {
    var text: String
    var symbol: String

    public init(_ text: String, symbol: String = "checkmark") {
        self.text = text
        self.symbol = symbol
    }

    public var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol)
                .font(.system(size: 11, weight: .semibold))
            Text(text)
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.secondary)
    }
}

/// Fehler- oder Hinweistext unter einem Feld (schwarz, mit dezentem Symbol).
public struct MessageText: View {
    var text: String
    var symbol: String

    public init(_ text: String, symbol: String = "exclamationmark.circle") {
        self.text = text
        self.symbol = symbol
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol)
                .font(.system(size: 12, weight: .medium))
            Text(Typo.keepCompounds(text))
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.text)
    }
}

/// Bildschirm-Behälter: Inhalt mittig, bei kleinen Fenstern scrollbar.
public struct CenteredPage<Content: View>: View {
    var content: Content

    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    public var body: some View {
        GeometryReader { geo in
            ScrollView(.vertical) {
                content
                    .padding(.horizontal, 40)
                    .padding(.vertical, 28)
                    .frame(maxWidth: .infinity, minHeight: geo.size.height)
            }
            .scrollIndicators(.automatic)
        }
    }
}

/// Seitenkopf für Unterseiten: Titel links, optional Zurück-Knopf.
public struct PageTitle: View {
    var title: String
    var subtitle: String?

    public init(_ title: String, subtitle: String? = nil) {
        self.title = title
        self.subtitle = subtitle
    }

    public var body: some View {
        VStack(spacing: 8) {
            Text(title)
                .font(Theme.title)
                .foregroundStyle(Theme.text)
                .multilineTextAlignment(.center)
            if let subtitle {
                Text(Typo.keepCompounds(subtitle))
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                    .multilineTextAlignment(.center)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// Logo mit optionaler Wortmarke.
public struct SiegelLogo: View {
    var size: CGFloat
    var riegel: CGFloat

    public init(size: CGFloat = Theme.markLarge, riegel: CGFloat = 0) {
        self.size = size
        self.riegel = riegel
    }

    public var body: some View {
        SiegelMark(riegel: riegel)
            .fill(Theme.text)
            .frame(width: size, height: size)
            .accessibilityLabel("Siegel")
    }
}

/// Typografie-Helfer.
public enum Typo {
    /// Bindestriche in Zusammensetzungen nicht umbrechen („Master-Passwort“ bleibt zusammen): U+2011.
    public static func keepCompounds(_ text: String) -> String {
        text.replacingOccurrences(of: "-", with: "\u{2011}")
    }
}
