import SiegelCore
import SwiftUI

/// Notfallkit (SPEC §7.6): Code in 11 Gruppen gross (SF Mono, nicht selektierbar), Kit-Kennung,
/// Warntext, zwei gleichwertige Wege „Von Hand abschreiben“ und „Drucken…“, danach Bestätigung
/// durch zwei zufällige Gruppen. Kein Kopieren, kein PDF.
struct RecoveryKitView: View {
    let model: AppModel
    @Bindable var kit: KitState

    var body: some View {
        CenteredPage {
            switch kit.step {
            case .show: showStep
            case .confirm: confirmStep
            case .purgeQuestion: purgeStep
            }
        }
    }

    // MARK: Code zeigen

    private var showStep: some View {
        VStack(spacing: 0) {
            PageTitle(kit.isShared ? "Dein Notfallkit in drei Teilen" : "Dein Notfallkit",
                      subtitle: kit.isShared
                        ? RecoveryKitTexts.shareIntro
                        : "Damit öffnest du den Tresor, falls du das Master-Passwort vergisst.")
                .frame(width: kit.isShared ? 520 : Theme.columnWidth)

            if kit.isShared {
                ShareTabs(count: kit.pending.shares.count, selected: kit.shareIndex,
                          recorded: Set(kit.shareMethods.keys)) { model.kitShowShare($0) }
                    .padding(.top, 24)
            }

            SecretGate {
                RecoveryCodeGrid(groups: kit.shownGroups)
                    .id(kit.shareIndex)
            } placeholder: { reveal in
                HiddenSecretPlaceholder(reveal: reveal)
                    .frame(width: 520, height: 176)
            }
            .padding(.top, kit.isShared ? 22 : 30)

            HStack(spacing: 8) {
                Text("Kit-Kennung")
                    .foregroundStyle(Theme.secondary)
                Text(kit.pending.code.kitID)
                    .font(Theme.mono(12, weight: .medium))
                    .foregroundStyle(Theme.text)
            }
            .font(Theme.caption)
            .padding(.top, 18)

            HintBox(symbol: "exclamationmark.triangle") {
                Text(kit.isShared ? RecoveryKitTexts.shareWarning : RecoveryKitTexts.warning)
            }
            .frame(width: 540)
            .padding(.top, 26)

            Group {
                if kit.printWarning {
                    printWarning
                } else if let method = currentMethod {
                    chosen(method)
                } else {
                    choice
                }
            }
            .frame(width: 540)
            .padding(.top, 24)
        }
    }

    /// Wie der gezeigte Code bzw. Teil festgehalten wurde.
    private var currentMethod: KitState.Method? {
        kit.isShared ? kit.shareMethods[kit.shareIndex] : kit.method
    }

    private var teil: String { "Teil \(kit.shareIndex + 1)" }

    private var choice: some View {
        VStack(spacing: 14) {
            HStack(spacing: 12) {
                Button(kit.isShared ? "\(teil) abschreiben" : "Von Hand abschreiben") { model.kitChooseHandwritten() }
                    .buttonStyle(SecondaryButtonStyle(fullWidth: true))
                Button(kit.isShared ? "\(teil) drucken…" : "Drucken…") { model.kitPrint() }
                    .buttonStyle(SecondaryButtonStyle(fullWidth: true))
            }
            .frame(width: 400)
            if kit.printNotPaper {
                MessageText(RecoveryKitPrinter.notPaperMessage, symbol: "printer")
                    .frame(width: 460, alignment: .leading)
            }
            cancelButton
        }
    }

    @ViewBuilder
    private var cancelButton: some View {
        switch kit.origin {
        case .newKit:
            Button("Abbrechen – der bisherige Code bleibt gültig") { model.kitCancel() }
                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                .disabled(model.busy)
        case .levelChange:
            Button("Zurück zum Assistenten – noch nichts geändert") { model.kitCancel() }
                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                .disabled(model.busy)
        case .setup:
            EmptyView()
        }
    }

    private func chosen(_ method: KitState.Method) -> some View {
        VStack(spacing: 14) {
            Text(chosenText(method))
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if kit.printNotPaper {
                MessageText(RecoveryKitPrinter.notPaperMessage, symbol: "printer")
                    .frame(width: 460, alignment: .leading)
            }
            HStack(spacing: 12) {
                Button(method == .printed ? "Nochmals drucken…" : "Doch drucken…") { model.kitPrint() }
                    .buttonStyle(SecondaryButtonStyle())
                if kit.isShared, let naechster = nextOpenShare {
                    Button("Weiter zu Teil \(naechster + 1)") { model.kitShowShare(naechster) }
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button("Weiter zur Bestätigung") { model.kitProceedToConfirm() }
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                }
            }
            cancelButton
        }
    }

    private func chosenText(_ method: KitState.Method) -> String {
        if kit.isShared {
            let wie = method == .printed ? "gedruckt" : "abgeschrieben"
            return nextOpenShare == nil
                ? "Alle drei Teile sind festgehalten. Bewahre sie getrennt auf und bestätige dann je eine Gruppe pro Teil."
                : "\(teil) ist \(wie). Lege das Blatt beiseite und halte den nächsten Teil fest."
        }
        return method == .printed
            ? "Gedruckt. Lege das Blatt an einen sicheren Ort und bestätige dann zwei Gruppen."
            : "Schreib den Code gut leserlich ab, Gruppe für Gruppe. Danach bestätigst du zwei Gruppen."
    }

    /// Nächster noch nicht festgehaltener Teil (nil = alle erledigt).
    private var nextOpenShare: Int? {
        let n = kit.pending.shares.count
        for offset in 1...max(n, 1) {
            let i = (kit.shareIndex + offset) % max(n, 1)
            if kit.shareMethods[i] == nil { return i }
        }
        return nil
    }

    private var printWarning: some View {
        VStack(spacing: 14) {
            MessageText(kit.printWarningText.isEmpty ? RecoveryKitPrinter.insecureWarning : kit.printWarningText,
                        symbol: "network")
                .frame(width: 460, alignment: .leading)
            HStack(spacing: 12) {
                Button("Abbrechen") { model.kitDismissPrintWarning() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Button("Trotzdem drucken") { model.kitPrintAnyway() }
                    .buttonStyle(PrimaryButtonStyle())
            }
        }
    }

    // MARK: Bestätigen

    private var confirmStep: some View {
        VStack(spacing: 0) {
            PageTitle("Notfallkit bestätigen",
                      subtitle: kit.isShared
                        ? "Tippe von jedem Teil die verlangte Gruppe ab. So prüfst du, ob alle drei richtig notiert sind."
                        : "Tippe zwei Gruppen von deinem Blatt ab. So prüfst du, ob der Code richtig notiert ist.")
                .frame(width: Theme.columnWidth)

            HStack(spacing: 28) {
                ForEach(Array(kit.confirmationNumbers.enumerated()), id: \.offset) { index, nummer in
                    VStack(spacing: 10) {
                        Text(kit.isShared ? "Teil \(index + 1) · Gruppe \(nummer)" : "Gruppe \(nummer)")
                            .font(Theme.caption.weight(.medium))
                            .foregroundStyle(Theme.secondary)
                        RecoveryCodeField("", text: binding(index), groups: 1, fontSize: 24, centered: true,
                                          autoFocus: index == 0) {
                            Task { await model.kitConfirm() }
                        }
                        .frame(width: 150)
                    }
                }
            }
            .padding(.top, 34)

            VStack(spacing: 0) {
                if let error = kit.error {
                    MessageText(error)
                }
            }
            .frame(width: 440, height: 48, alignment: .top)
            .padding(.top, 14)

            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    Button(kit.isShared ? "Teile nochmals zeigen" : "Code nochmals zeigen") { model.kitShowCodeAgain() }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(model.busy)
                    Button("Bestätigen") { Task { await model.kitConfirm() } }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(!kit.canConfirm || model.busy)
                        .keyboardShortcut(.defaultAction)
                }
                ProgressLine(active: model.busy)
                    .frame(width: 300)
                // Während des Schreibens gesperrt (Befund #11): sonst gälte das neue Kit trotz „Abbrechen“.
                if kit.origin == .setup {
                    Button("Später bestätigen") { model.kitSkip() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        .disabled(model.busy)
                        .padding(.top, 6)
                } else {
                    cancelButton
                        .padding(.top, 6)
                }
            }
        }
    }

    private func binding(_ index: Int) -> Binding<String> {
        Binding(
            get: { index < kit.confirmation.count ? kit.confirmation[index] : "" },
            set: { neu in if index < kit.confirmation.count { kit.confirmation[index] = neu } }
        )
    }

    // MARK: Alte Sicherungen

    private var purgeStep: some View {
        VStack(spacing: 0) {
            SiegelLogo(size: 42, riegel: 0)
            PageTitle("Neues Notfallkit gespeichert",
                      subtitle: "Die bisherigen Sicherungen lassen sich mit dem alten Notfallcode öffnen. Entfernen?")
                .frame(width: Theme.columnWidth)
                .padding(.top, 24)
            Text("Siegel legt danach sofort eine neue Sicherung des aktuellen Stands an.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .padding(.top, 10)
            HStack(spacing: 12) {
                Button("Behalten") { Task { await model.kitFinish(removeOldBackups: false) } }
                    .buttonStyle(SecondaryButtonStyle())
                Button("Entfernen") { Task { await model.kitFinish(removeOldBackups: true) } }
                    .buttonStyle(PrimaryButtonStyle())
            }
            .disabled(model.busy || model.isSaving)
            .padding(.top, 28)
            ProgressLine(active: model.busy)
                .frame(width: 240)
                .padding(.top, 14)
        }
    }
}

/// Reiter „Teil 1 · Teil 2 · Teil 3“ (schwarz/weiss), erledigte Teile mit Häkchen.
struct ShareTabs: View {
    var count: Int
    var selected: Int
    var recorded: Set<Int>
    var onSelect: (Int) -> Void

    var body: some View {
        HStack(spacing: 0) {
            ForEach(0..<count, id: \.self) { index in
                let aktiv = index == selected
                Button {
                    onSelect(index)
                } label: {
                    HStack(spacing: 6) {
                        if recorded.contains(index) {
                            Image(systemName: "checkmark")
                                .font(.system(size: 10, weight: .bold))
                        }
                        Text("Teil \(index + 1) von \(count)")
                            .font(Theme.caption.weight(aktiv ? .semibold : .regular))
                    }
                    .foregroundStyle(aktiv ? Theme.background : Theme.text)
                    .padding(.horizontal, 14)
                    .frame(minWidth: 108)
                    .frame(height: 28)
                    .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(aktiv ? Theme.text : Color.clear))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(aktiv ? .isSelected : [])
            }
        }
        .padding(2)
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

/// Der Notfallcode in 11 Gruppen (4 · 4 · 3), jede mit Nummer. Nicht selektierbar, AX nur mit VoiceOver.
struct RecoveryCodeGrid: View {
    var groups: [String]
    var fontSize: CGFloat = 25

    var body: some View {
        let voiceOver = TextHardening.exposesSecretsToAccessibility
        // Text für Bedienungshilfen verborgen, Behälter mit Bezeichnung (SPEC §6)
        ZStack {
            grid.accessibilityHidden(!voiceOver)
        }
        .accessibilityElement(children: voiceOver ? .contain : .ignore)
        .accessibilityLabel(voiceOver ? "Notfallcode" : "Notfallcode, verborgen")
    }

    private var grid: some View {
        let spalten = Array(repeating: GridItem(.fixed(118), spacing: 22, alignment: .leading), count: 4)
        return LazyVGrid(columns: spalten, alignment: .leading, spacing: 20) {
            ForEach(Array(groups.enumerated()), id: \.offset) { index, gruppe in
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(index + 1)")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Theme.secondary)
                        .monospacedDigit()
                    Text(gruppe)
                        .font(Theme.mono(fontSize, weight: .medium))
                        .kerning(1.5)
                        .foregroundStyle(Theme.text)
                        .fixedSize()
                }
            }
        }
        .frame(width: 4 * 118 + 3 * 22)
        .textSelection(.disabled)
    }
}
