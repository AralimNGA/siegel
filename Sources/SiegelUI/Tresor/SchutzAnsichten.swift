import SiegelCore
import SwiftUI

// Bausteine für den Schutz pro Eintrag (SPEC v4 §16): Auswahl 1–5 im Bearbeiten, Kennzeichnung in Liste und
// Detail, Vorgabe in den Einstellungen, 2FA-Code (§18).

enum ProtectionTexts {
    static func short(_ p: EntryProtection) -> String {
        switch p {
        case .normal: "Nichts zusätzlich – der offene Tresor genügt."
        case .fingerabdruck: "Touch ID bei jedem Aufdecken."
        case .hoch: "Touch ID · Zwischenablage höchstens 15 s · nie Autofill."
        // Befund design-5: kurz genug für die Bearbeiten-Spalte (540 pt) neben „noch einrichten“ und drei Symbolen –
        // sonst fiel genau „nicht im Export“ weg; „berühren“ las sich auch auf Touch ID und Karte.
        case .maximal: "Touch ID und Karte · nicht im Export."
        case .festung: "Touch ID, Karte, Schlüssel · nicht im Export."
        }
    }

    /// Zeile im Detail: „Schutz 3 · Hoch“
    static func label(_ p: EntryProtection) -> String {
        "Schutz \(p.rawValue) · \(p.title)"
    }
}

/// Masse einer Zeile der Schutz-Auswahl (eine Quelle für die Ansicht und die Längenprüfung, Befund design-5).
enum ProtectionPickerMetrics {
    static let outerPadding: CGFloat = 4
    static let rowPadding: CGFloat = 12
    static let spacing: CGFloat = 12
    static let circle: CGFloat = 15
    static let number: CGFloat = 10
    static let spacerMin: CGFloat = 8
    static let hintFontSize: CGFloat = 10
    static let glyphSize: CGFloat = 11
    static let glyphSpacing: CGFloat = 4
}

/// Nur für SiegelSnapshots: Kurztexte und Masse der Schutz-Auswahl (Befund design-5: passt jede Zeile ungekürzt?).
@_spi(Snapshots) public enum ProtectionPickerProbe {
    public static func short(_ p: EntryProtection) -> String { ProtectionTexts.short(p) }
    /// Breite der Bearbeiten-Spalte, in der die Auswahl steht.
    public static var columnWidth: CGFloat { DetailMetrics.column }
    /// Feste Teile einer Zeile ohne Kurztext, Hinweis und Symbole (Ränder, Kreis, Nummer, Spacer).
    public static var fixedWidth: CGFloat {
        typealias M = ProtectionPickerMetrics
        return 2 * M.outerPadding + 2 * M.rowPadding + M.circle + M.number + M.spacerMin
    }
    public static var spacing: CGFloat { ProtectionPickerMetrics.spacing }
    public static var glyphSpacing: CGFloat { ProtectionPickerMetrics.glyphSpacing }
    public static var hintFontSize: CGFloat { ProtectionPickerMetrics.hintFontSize }
    public static var glyphFontSize: CGFloat { ProtectionPickerMetrics.glyphSize }
}

/// Faktor-Symbole eines Schutzes (für Liste und Detail), ohne Passwort.
struct ProtectionGlyphs: View {
    var protection: EntryProtection
    var size: CGFloat = 10

    var body: some View {
        HStack(spacing: ProtectionPickerMetrics.glyphSpacing) {
            ForEach(protection.factors.kinds, id: \.self) { kind in
                Image(systemName: FactorUI.symbol(kind))
            }
        }
        .font(.system(size: size, weight: .medium))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(ProtectionTexts.label(protection))
    }
}

/// Auswahl 1–5 im Bearbeiten: je Zeile Nummer, Name, kurze Erklärung und die nötigen Faktoren.
struct ProtectionPicker: View {
    @Binding var selection: EntryProtection
    var enabled: Bool
    /// Für Einträge eingerichtete Faktoren (fehlende werden markiert).
    var enrolled: FactorSet
    /// Tiefster wählbarer Schutz (vernichtbare Einträge, §23: mindestens 4).
    var minimum: EntryProtection = .normal

    var body: some View {
        VStack(spacing: 2) {
            ForEach(EntryProtection.allCases, id: \.self) { p in
                let gewaehlt = p == selection
                let fehlt = !p.factors.subtracting(enrolled).isEmpty
                let gesperrt = p < minimum
                Button {
                    selection = p
                } label: {
                    HStack(spacing: ProtectionPickerMetrics.spacing) {
                        ZStack {
                            Circle()
                                .strokeBorder(gewaehlt ? Theme.text : Theme.secondary, lineWidth: 1)
                                .frame(width: ProtectionPickerMetrics.circle, height: ProtectionPickerMetrics.circle)
                            if gewaehlt {
                                Circle().fill(Theme.text).frame(width: 7, height: 7)
                            }
                        }
                        Text("\(p.rawValue)")
                            .font(Theme.mono(12, weight: .semibold))
                            .frame(width: ProtectionPickerMetrics.number)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(p.title)
                                .font(gewaehlt ? Theme.bodyMedium : Theme.body)
                            Text(ProtectionTexts.short(p))
                                .font(Theme.caption)
                                .foregroundStyle(Theme.secondary)
                                .lineLimit(1)
                                .minimumScaleFactor(0.9)
                        }
                        Spacer(minLength: ProtectionPickerMetrics.spacerMin)
                        if gesperrt {
                            Text("vernichtbar")
                                .font(.system(size: ProtectionPickerMetrics.hintFontSize, weight: .medium))
                                .foregroundStyle(Theme.secondary)
                        } else if fehlt {
                            Text("noch einrichten")
                                .font(.system(size: ProtectionPickerMetrics.hintFontSize, weight: .medium))
                                .foregroundStyle(Theme.secondary)
                        }
                        ProtectionGlyphs(protection: p, size: ProtectionPickerMetrics.glyphSize)
                            .foregroundStyle(Theme.text)
                    }
                    .padding(.horizontal, ProtectionPickerMetrics.rowPadding)
                    .frame(height: 44)
                    .background(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .strokeBorder(gewaehlt ? Theme.text : Color.clear, lineWidth: 1.5)
                    )
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(gesperrt)
                .opacity(gesperrt ? 0.45 : 1)
                // Voller Text auch dann, wenn die Zeile ihn künftig kürzen müsste (wie bei ProtectionSegments).
                .help(ProtectionTexts.label(p) + " – " + ProtectionTexts.short(p))
                .accessibilityAddTraits(gewaehlt ? .isSelected : [])
                .accessibilityLabel(ProtectionTexts.label(p) + ". " + ProtectionTexts.short(p))
            }
        }
        .padding(ProtectionPickerMetrics.outerPadding)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.55)
    }
}

/// Vorgabe 1–5 in den Einstellungen (Stufen unter dem Mindestwert der Sicherheitsstufe gesperrt).
struct ProtectionSegments: View {
    @Binding var selection: EntryProtection
    var minimum: EntryProtection

    var body: some View {
        HStack(spacing: 0) {
            ForEach(EntryProtection.allCases, id: \.self) { p in
                let gewaehlt = p == selection
                let erlaubt = p >= minimum
                Button {
                    selection = p
                } label: {
                    Text("\(p.rawValue)")
                        .font(Theme.caption.weight(gewaehlt ? .semibold : .regular))
                        .foregroundStyle(gewaehlt ? Theme.background : (erlaubt ? Theme.text : Theme.hairline))
                        .frame(width: 34, height: 26)
                        .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(gewaehlt ? Theme.text : Color.clear))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(!erlaubt)
                .help(ProtectionTexts.label(p) + " – " + ProtectionTexts.short(p))
                .accessibilityLabel(ProtectionTexts.label(p))
                .accessibilityAddTraits(gewaehlt ? .isSelected : [])
            }
        }
        .padding(2)
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

/// 2FA-Code mit Restsekunden (§18): Code in SF Mono (wie ein Passwort nur in geschützten Fenstern gezeichnet),
/// daneben ein Ring, der mit der Periode abläuft, und die Restsekunden. Ein ungültiges Geheimnis zeigt einen
/// Hinweis statt eines Codes.
struct TOTPValue: View {
    var secret: String

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if let ablesung = TOTPDisplay.reading(secret, at: context.date) {
                HStack(spacing: 14) {
                    SecretLabel(text: ablesung.grouped, font: Theme.nsMono(17, weight: .medium))
                        .secretAccessibility("2FA-Code, verborgen")
                        .fixedSize()
                    HStack(spacing: 7) {
                        CountdownRing(remaining: ablesung.remaining, period: ablesung.period)
                        Text("\(ablesung.remaining) s")
                            .font(Theme.caption.weight(ablesung.remaining <= 5 ? .semibold : .regular))
                            .foregroundStyle(ablesung.remaining <= 5 ? Theme.text : Theme.secondary)
                            .monospacedDigit()
                            .frame(minWidth: 30, alignment: .leading)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("Noch \(ablesung.remaining) Sekunden gültig")
                }
            } else {
                Text("2FA-Geheimnis nicht lesbar – im Bearbeiten prüfen")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
            }
        }
    }
}

/// Kleiner Ring für die verbleibende Zeit eines 2FA-Codes.
struct CountdownRing: View {
    var remaining: Int
    var period: Int

    var body: some View {
        ZStack {
            Circle().stroke(Theme.hairline, lineWidth: 2)
            Circle()
                .trim(from: 0, to: CGFloat(remaining) / CGFloat(max(period, 1)))
                .stroke(Theme.text, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                .rotationEffect(.degrees(-90))
        }
        .frame(width: 15, height: 15)
        .accessibilityHidden(true)
    }
}
