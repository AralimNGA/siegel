import SiegelCore
import SwiftUI

/// Notfallcode-Weg im gesperrten Zustand (SPEC §7.2): Code-Eingabe mit `?` für Unleserliches,
/// Korrektur-Vorschlag mit markierten Stellen, neues Master-Passwort ×2, danach Eintragszahl,
/// letzte Änderung und Hinweis „Inhalt prüfen“.
struct RecoveryFlowView: View {
    let model: AppModel
    @Bindable var state: RecoveryState

    var body: some View {
        CenteredPage {
            switch state.step {
            case .enterCode: state.usesShares ? AnyView(enterShares) : AnyView(enterCode)
            case let .confirmCorrection(formatted, positions): correction(formatted, positions)
            case let .confirmShareCorrections(fixes): shareCorrections(fixes)
            case .newPassword: newPassword
            case .done: done
            }
        }
    }

    // MARK: Zwei Teile eingeben (§15)

    /// Zeichen eines Teils: x (1 B) ‖ Teil (32 B) ‖ Prüfsumme (2 B) = 35 Byte = 56 Zeichen Crockford-Base32.
    static let shareCharacters = 56

    private var enterShares: some View {
        VStack(spacing: 0) {
            PageTitle("Notfallcode verwenden",
                      subtitle: (state.schemeCertain ? "Dein Notfallcode ist in drei Teile geteilt. " : "")
                        + "Tippe zwei beliebige Teile ab. Unleserliche Zeichen als\u{00A0}„\u{2060}?\u{2060}“\u{00A0}eingeben."
                        + targetNote)
                .frame(width: Theme.columnWidth)

            VStack(alignment: .leading, spacing: 18) {
                shareField(0, title: "Erster Teil")
                shareField(1, title: "Zweiter Teil")
            }
            .frame(width: 640)
            .padding(.top, 28)

            // Befund #42: Platz für zwei Zeilen reserviert (der Block springt nicht) und Abstand zur Knopfreihe.
            errorArea
                .frame(width: 616)
                .frame(minHeight: 40, alignment: .topLeading)
                .padding(.top, 8)
                .padding(.bottom, 12)

            VStack(spacing: 12) {
                ButtonRow {
                    Button(backTitle) { model.cancelRecovery() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        .keyboardShortcut(.cancelAction)
                } trailing: {
                    Button("Teile prüfen") { Task { await model.checkRecoverySharesForRecovery() } }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(!sharesComplete || model.busy)
                        .keyboardShortcut(.defaultAction)
                }
                ProgressLine(active: model.busy)
                schemeToggle
            }
            .frame(width: 640)
            .padding(.top, 6)
        }
    }

    /// Befund datei-4: Ist der Kopf unsicher (Datei beschädigt, fehlt oder aus einer Sicherung gelesen), lässt sich
    /// zwischen einem Code und zwei Teilen umschalten.
    @ViewBuilder
    private var schemeToggle: some View {
        if !state.schemeCertain {
            Button(state.usesShares ? "Ich habe einen einzelnen Code" : "Ich habe ein Kit in drei Teilen") {
                model.recoveryChooseShares(!state.usesShares)
            }
            .buttonStyle(QuietButtonStyle(font: Theme.caption))
            .disabled(model.busy)
        }
    }

    /// „Zurück zum Entsperren“ nur, wenn es einen Sperrbildschirm gibt.
    private var backTitle: String {
        state.origin == .lock ? "Zurück zum Entsperren" : "Zurück"
    }

    /// Für welche Datei der Notfallweg gilt, wenn das nicht der Tresor ist (Befund datei-2/-3).
    private var targetNote: String {
        switch state.origin {
        case .lock: ""
        case .missingVault: " Die Tresordatei fehlt – Siegel stellt die neueste Sicherung wieder her, die dazu passt."
        case let .file(url): " Gilt für die Sicherung „\(url.lastPathComponent)“."
        }
    }

    private var sharesComplete: Bool {
        state.shares.allSatisfy { RecoveryCodeFormatting.significant($0).count == Self.shareCharacters }
    }

    private func shareField(_ index: Int, title: String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text(title)
                    .font(Theme.caption.weight(.medium))
                    .foregroundStyle(Theme.secondary)
                Spacer()
                Text("\(RecoveryCodeFormatting.significant(state.shares[index]).count) / \(Self.shareCharacters)")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .monospacedDigit()
            }
            .padding(.horizontal, 12)
            RecoveryCodeField("Teil mit 12 Gruppen", text: shareBinding(index), groups: 12, fontSize: 14,
                              autoFocus: index == 0) {
                Task { await model.checkRecoverySharesForRecovery() }
            }
        }
    }

    private func shareBinding(_ index: Int) -> Binding<String> {
        Binding(get: { index < state.shares.count ? state.shares[index] : "" },
                set: { neu in if index < state.shares.count { state.shares[index] = neu } })
    }

    private func shareCorrections(_ fixes: [RecoveryState.ShareCorrection]) -> some View {
        VStack(spacing: 0) {
            PageTitle("Stimmen diese Teile?",
                      subtitle: "Siegel hat Zeichen ergänzt oder korrigiert. Vergleiche die markierten Stellen mit deinen Blättern.")
                .frame(width: Theme.columnWidth)
            VStack(spacing: 18) {
                ForEach(Array(fixes.enumerated()), id: \.offset) { _, fix in
                    VStack(alignment: .leading, spacing: 10) {
                        Text(fix.index == 0 ? "Erster Teil" : "Zweiter Teil")
                            .font(Theme.caption.weight(.medium))
                            .foregroundStyle(Theme.secondary)
                        SecretGate {
                            CorrectedCodeView(formatted: fix.formatted, changedPositions: fix.changedPositions,
                                              fontSize: 17, alignment: .leading)
                        } placeholder: { reveal in
                            HiddenSecretPlaceholder(reveal: reveal).frame(height: 60)
                        }
                    }
                    .padding(.vertical, 20)
                    .padding(.horizontal, 26)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
                    )
                }
            }
            .frame(width: 560)
            .padding(.top, 28)
            HStack(spacing: 12) {
                Button("Nein, neu eingeben") { model.rejectCorrection() }
                    .buttonStyle(SecondaryButtonStyle())
                Button("Ja, stimmt") { model.acceptShareCorrections() }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 28)
        }
    }

    // MARK: Code eingeben

    private var enterCode: some View {
        VStack(spacing: 0) {
            PageTitle("Notfallcode verwenden",
                      subtitle: "Tippe den Code von deinem Notfallkit ab. Unleserliche Zeichen als\u{00A0}„\u{2060}?\u{2060}“\u{00A0}eingeben – Siegel ergänzt bis zu vier davon."
                        + targetNote)
                .frame(width: Theme.columnWidth)

            // Ein Teil (56 Zeichen) im Feld für den Code (55): zur Eingabe der Teile wechseln (Befund datei-4).
            RecoveryCodeField("Code mit 11 Gruppen", text: $state.code, groups: 11, fontSize: 15, autoFocus: true) {
                Task { await model.checkRecoveryCodeForRecovery() }
            }
            .onOverflow(state.schemeCertain ? nil : { model.recoveryCodeOverflow($0) })
            .frame(width: 640)
            .padding(.top, 32)

            HStack {
                Text("Gross- und Kleinschreibung und Bindestriche spielen keine Rolle.")
                Spacer()
                Text("\(RecoveryCodeFormatting.significant(state.code).count) / 55")
                    .monospacedDigit()
            }
            .font(Theme.caption)
            .foregroundStyle(Theme.secondary)
            .frame(width: 616)
            .padding(.top, 10)

            // Befund #42: Platz für zwei Zeilen reserviert (der Block springt nicht) und Abstand zur Knopfreihe.
            errorArea
                .frame(width: 616)
                .frame(minHeight: 40, alignment: .topLeading)
                .padding(.top, 8)
                .padding(.bottom, 12)

            VStack(spacing: 12) {
                ButtonRow {
                    Button(backTitle) { model.cancelRecovery() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        .keyboardShortcut(.cancelAction)
                } trailing: {
                    Button("Code prüfen") { Task { await model.checkRecoveryCodeForRecovery() } }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(RecoveryCodeFormatting.significant(state.code).count < 55 || model.busy)
                        .keyboardShortcut(.defaultAction)
                }
                ProgressLine(active: model.busy)
                schemeToggle
            }
            .frame(width: 640)
        }
    }

    // MARK: Korrektur bestätigen

    private func correction(_ formatted: String, _ positions: [Int]) -> some View {
        VStack(spacing: 0) {
            PageTitle("Ist das dein Code?",
                      subtitle: positions.count == 1
                        ? "Siegel hat 1 Stelle ergänzt oder korrigiert. Vergleiche das markierte Zeichen mit deinem Blatt."
                        : "Siegel hat \(positions.count) Stellen ergänzt oder korrigiert. Vergleiche die markierten Zeichen mit deinem Blatt.")
                .frame(width: Theme.columnWidth)

            SecretGate {
                CorrectedCodeView(formatted: formatted, changedPositions: positions, fontSize: 19)
            } placeholder: { reveal in
                HiddenSecretPlaceholder(reveal: reveal).frame(height: 80)
            }
            .padding(.vertical, 26)
            .padding(.horizontal, 30)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
            )
            .padding(.top, 30)

            HStack(spacing: 12) {
                Button("Nein, neu eingeben") { model.rejectCorrection() }
                    .buttonStyle(SecondaryButtonStyle())
                Button("Ja, stimmt") { model.acceptCorrection() }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 30)
        }
    }

    // MARK: Neues Master-Passwort

    private var newPassword: some View {
        VStack(spacing: 0) {
            PageTitle("Neues Master-Passwort", subtitle: newPasswordSubtitle)
                .frame(width: Theme.columnWidth)

            VStack(spacing: 12) {
                MasterPasswordField("Neues Master-Passwort", text: $state.newPassword, autoFocus: true,
                                    enabled: !model.busy)
                MasterPasswordField("Wiederholen", text: $state.newPasswordRepeat, enabled: !model.busy) {
                    Task { await model.submitRecovery() }
                }
                let assessment = state.assessment
                StrengthMeter(bits: assessment.bits, level: assessment.level, meetsPolicy: assessment.meetsPolicy,
                              isEmpty: assessment.isEmpty)
                    .padding(.top, 4)
                if state.kdfToKeep == .strong, !state.forceStandardProfile {
                    // Befund #21: Das Profil bleibt, wie es war.
                    Text("Die Schlüsselableitung bleibt Stark (2 GiB, etwa 3 s).")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                // §23: Vernichtbare Einträge haben keinen Notfallweg; der Kern lässt sie weg (Zahl gesperrt unbekannt).
                if DestructionRules.isConfigured(model.destruction) {
                    Text(DestructionTexts.recoveryDropsDestructible)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.text)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                errorArea
                VStack(spacing: 10) {
                    if state.offerStandardProfile {
                        Button("Mit Profil Standard wiederherstellen") {
                            Task { await model.submitRecoveryWithStandardProfile() }
                        }
                        .buttonStyle(SecondaryButtonStyle(fullWidth: true))
                        .disabled(!state.canSubmit || model.busy)
                    }
                    if state.offerBackup {
                        Button("Neueste lesbare Sicherung öffnen") {
                            Task { await model.submitRecoveryFromBackup() }
                        }
                        .buttonStyle(PrimaryButtonStyle(fullWidth: true))
                        .disabled(!state.canSubmit || model.busy)
                        .keyboardShortcut(.defaultAction)
                    } else {
                        Button(state.offerStandardProfile ? "Erneut versuchen" : "Tresor wiederherstellen") {
                            Task { await model.submitRecovery() }
                        }
                        .buttonStyle(PrimaryButtonStyle(fullWidth: true))
                        .disabled(!state.canSubmit || model.busy)
                        .keyboardShortcut(.defaultAction)
                    }
                    ProgressLine(active: model.busy)
                }
                // Während des Schreibens nicht abbrechbar: das neue Passwort gälte sonst ohne Rückmeldung.
                Button("Abbrechen") { model.cancelRecovery() }
                    .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    .keyboardShortcut(.cancelAction)
                    .disabled(model.busy)
                    .padding(.top, 4)
            }
            .frame(width: Theme.formWidth)
            .padding(.top, 30)
        }
    }

    private var newPasswordSubtitle: String {
        let was = state.usesShares ? "Die Teile passen" : "Der Code passt"
        switch state.origin {
        case let .file(url):
            return was + " zur Sicherung „\(url.lastPathComponent)“. Siegel setzt sie als Tresor ein – in Stufe 1 und mit einem neuen Master-Passwort. Ein bisheriger Tresor bleibt als Sicherung erhalten."
        case .missingVault where state.useBackup:
            return was + " zu deinen Sicherungen. Die Tresordatei fehlt – Siegel stellt die neueste Sicherung wieder her, die " + (state.usesShares ? "diese Teile öffnen" : "dieser Code öffnet") + ". Änderungen danach fehlen."
        default:
            if state.useBackup {
                return was + " zu deinen Sicherungen. Die Tresordatei ist beschädigt – Siegel stellt die neueste Sicherung wieder her, die " + (state.usesShares ? "diese Teile öffnen" : "dieser Code öffnet") + ". Änderungen danach fehlen."
            }
            return was + ". Wähle jetzt ein neues Master-Passwort für diesen Tresor."
        }
    }

    /// Hinweis nach der Wiederherstellung: was fehlt, wo die bisherige Datei liegt.
    private var doneHint: String {
        let pruefen = "Inhalt prüfen: Stimmen Anzahl und Stand mit dem überein, was du erwartest?"
        guard state.restoredBackup != nil else {
            return pruefen + " Der Notfallcode schützt die Vertraulichkeit, aber nicht vor einer untergeschobenen Datei."
        }
        switch state.origin {
        case .lock: return "Änderungen nach diesem Stand fehlen; die beschädigte Datei liegt unter „Sicherungen“. " + pruefen
        case .missingVault: return "Änderungen nach diesem Stand fehlen. " + pruefen
        case .file: return "Die Sicherung ist jetzt dein Tresor; ein bisheriger Tresor liegt unter „Sicherungen“. " + pruefen
        }
    }

    // MARK: Fertig

    private var done: some View {
        VStack(spacing: 0) {
            SiegelLogo(size: 42, riegel: 1)
            PageTitle("Tresor wiederhergestellt", subtitle: "Das neue Master-Passwort gilt ab sofort.")
                .padding(.top, 22)

            VStack(spacing: 0) {
                if let backup = state.restoredBackup {
                    FactRow(label: "Sicherung vom", value: Anzeige.datum(backup.date))
                    Hairline()
                    FactRow(label: "Stand", value: "\(backup.generation)")
                    Hairline()
                }
                FactRow(label: "Einträge", value: "\(state.entryCount)")
                Hairline()
                FactRow(label: "Letzte Änderung", value: Anzeige.datum(state.lastModified))
            }
            .frame(width: Theme.formWidth + 40)
            .padding(.top, 26)

            HintBox(symbol: "checklist") {
                Text(doneHint)
            }
            .frame(width: Theme.formWidth + 40)
            .padding(.top, 22)

            if state.hadHardening {
                HintBox(symbol: "shield") {
                    Text("Sicherheitsstufe und Schutz aller Einträge sind jetzt wieder 1 (Standard). Richte sie unter Einstellungen → Sicherheitsstufe neu ein.")
                }
                .frame(width: Theme.formWidth + 40)
                .padding(.top, 10)
            }

            Button("Tresor öffnen") { model.finishRecovery() }
                .buttonStyle(PrimaryButtonStyle())
                .keyboardShortcut(.defaultAction)
                .padding(.top, 28)
        }
    }

    @ViewBuilder
    private var errorArea: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let error = state.error {
                MessageText(error)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 22, alignment: .topLeading)
    }
}
