import AppKit
import SiegelCore
import SwiftUI

/// Wurzelansicht: wählt den Bildschirm nach `model.screen`. Beim Sperren wird der ganze entsperrte
/// Teilbaum ersetzt (`.id(lockGeneration)`), damit alle `@State` wegfallen (SPEC §6).
public struct RootView: View {
    let model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            screen
                .id(ScreenKey(screen: model.screen, generation: model.lockGeneration))
                .transition(.opacity)
        }
        .overlay(alignment: .bottom) {
            if let notice = model.notice {
                NoticeLine(notice.text, symbol: notice.symbol)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(Capsule().fill(Theme.background))
                    .overlay(Capsule().strokeBorder(Theme.hairline, lineWidth: 1))
                    .padding(.bottom, 18)
                    .transition(.opacity)
                    .id(notice.id)
                    // In der Tresor-Ansicht mittig über dem Detailbereich (nicht über der Seitenleiste)
                    .padding(.leading, showsVault ? VaultView.sidebarWidth : 0)
            }
        }
        // Kamera- und Schlüssel-Sheet (Ebene im geschützten Hauptfenster, beim Sperren weg)
        .overlay {
            FactorSheetHost(model: model)
                .animation(.easeOut(duration: 0.15), value: model.cardScan == nil && model.keyTouch == nil)
        }
        .environment(model.settings)
        .environment(model)
        .frame(minWidth: 760, minHeight: 480)
        .foregroundStyle(Theme.text)
        .tint(Theme.text)
        .focusEffectDisabled()
        .preferredColorScheme(.light)
        .background(WindowProbe { window in
            guard let window else { return }
            WindowSetup.configure(window)
        })
    }

    @ViewBuilder
    private var screen: some View {
        switch model.screen {
        case .setup:
            SetupView(model: model, state: model.setup)
        case .recoveryKit:
            if let kit = model.kit {
                RecoveryKitView(model: model, kit: kit)
            }
        case .locked:
            LockView(model: model, state: model.unlock)
        case .recovery:
            RecoveryFlowView(model: model, state: model.recovery)
        case .missingVault:
            MissingVaultView(model: model, state: model.missing)
        case .corrupt:
            CorruptVaultView(model: model, state: model.corrupt)
        case .rollback:
            if let rollback = model.rollback {
                RollbackView(model: model, state: rollback)
            }
        case .unlocked:
            if let flow = model.flowState, model.pendingFlow != nil {
                FlowView(model: model, flow: flow)
            } else if model.showsSettings {
                SettingsView(model: model, state: model.settingsState)
            } else {
                VaultView(model: model, browser: model.browser)
            }
        case let .blocked(reason):
            BlockedView(reason: reason)
        }
    }

    private var showsVault: Bool {
        model.screen == .unlocked && model.pendingFlow == nil && !model.showsSettings
    }

    private struct ScreenKey: Hashable {
        var screen: AppModel.Screen
        var generation: Int
    }
}

/// Fenster-Einstellungen, die SwiftUI nicht direkt anbietet.
@MainActor
enum WindowSetup {
    static func configure(_ window: NSWindow) {
        WindowGuard.shared.protect(window)
        if window.title != "Siegel" { window.title = "Siegel" }
        window.isRestorable = false
        window.tabbingMode = .disallowed
        window.titlebarAppearsTransparent = true
        window.backgroundColor = Theme.nsBackground
    }
}

// MARK: - Gemeinsame Teile der Bildschirme

/// Knopfreihe unten in Formularen: links leise Aktion, rechts Haupt- und Nebenknopf.
struct ButtonRow<Leading: View, Trailing: View>: View {
    var leading: Leading
    var trailing: Trailing

    init(@ViewBuilder leading: () -> Leading, @ViewBuilder trailing: () -> Trailing) {
        self.leading = leading()
        self.trailing = trailing()
    }

    var body: some View {
        HStack(spacing: 12) {
            leading
            Spacer(minLength: 12)
            trailing
        }
    }
}

/// Zeile „Bezeichnung … Wert“ für Zusammenfassungen.
struct FactRow: View {
    var label: String
    var value: String
    var mono = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .font(Theme.body)
                .foregroundStyle(Theme.secondary)
            Spacer(minLength: 16)
            Text(value)
                .font(mono ? Theme.mono(13, weight: .medium) : Theme.bodyMedium)
                .foregroundStyle(Theme.text)
                .monospacedDigit()
        }
        .padding(.vertical, 10)
    }
}

/// Hinweisblock mit Haarlinien-Rahmen (z. B. Warnung im Notfallkit).
struct HintBox<Content: View>: View {
    var symbol: String
    var content: Content

    init(symbol: String = "info.circle", @ViewBuilder content: () -> Content) {
        self.symbol = symbol
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(Theme.text)
                .frame(width: 18)
                .padding(.top, 1)
            content
                .font(Theme.caption)
                .foregroundStyle(Theme.text)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
        )
    }
}

/// Code mit markierten (korrigierten) Stellen: markierte Zeichen schwarz hinterlegt.
struct CorrectedCodeView: View {
    var formatted: String
    var changedPositions: [Int]
    var fontSize: CGFloat = 17
    var alignment: HorizontalAlignment = .center

    var body: some View {
        let gruppen = formatted.split(separator: "-").map(Array.init)
        let markiert = Set(changedPositions)
        VStack(alignment: alignment, spacing: 10) {
            ForEach(Array(stride(from: 0, to: gruppen.count, by: 6)), id: \.self) { start in
                HStack(spacing: 14) {
                    ForEach(start..<min(start + 6, gruppen.count), id: \.self) { g in
                        HStack(spacing: 2) {
                            ForEach(0..<gruppen[g].count, id: \.self) { i in
                                let position = g * 5 + i
                                let hervor = markiert.contains(position)
                                Text(String(gruppen[g][i]))
                                    .font(Theme.mono(fontSize, weight: .medium))
                                    .foregroundStyle(hervor ? Theme.background : Theme.text)
                                    .frame(width: fontSize * 0.72, height: fontSize * 1.45)
                                    .background(
                                        RoundedRectangle(cornerRadius: 3, style: .continuous)
                                            .fill(hervor ? Theme.text : Color.clear)
                                    )
                            }
                        }
                    }
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Korrigierter Notfallcode, \(changedPositions.count) Stellen markiert")
    }
}

/// Datum für Anzeigen („14. Oktober 2026, 09:12“).
enum Anzeige {
    static func datum(_ date: Date?) -> String {
        guard let date else { return "–" }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "de_CH")
        formatter.dateStyle = .long
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    /// Kurz mit Sekunden („16.10.2026, 20:08:14“) für Sicherungen.
    static func zeitpunkt(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "de_CH")
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }

    static func eintraege(_ n: Int) -> String {
        n == 1 ? "1 Eintrag" : "\(n) Einträge"
    }

    static func anlass(_ reason: String?) -> String? {
        guard let reason else { return nil }
        switch reason {
        case "import": return "vor Import"
        case "passwortwechsel": return "vor Passwortwechsel"
        case "notfall": return "vor Notfall-Wiederherstellung"
        case "neues-kit": return "vor neuem Notfallkit"
        case "migration": return "vor Migration"
        case "migration-v1": return "vor Umstellung auf Format 2"
        case "stufenwechsel": return "vor Stufenwechsel"
        case "wiederherstellung": return "vor Wiederherstellung"
        default: return "angeheftet"
        }
    }
}
