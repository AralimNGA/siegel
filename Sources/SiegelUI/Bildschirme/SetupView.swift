import SiegelCore
import SwiftUI

/// Einrichtung (SPEC §7.1): Logo, „Siegel“, Unterzeile. Standardweg „Passphrase vorschlagen“ (6 Wörter,
/// SF Mono, „Neu würfeln“), alternativ eigenes Passwort mit Wiederholung und Stärke-Anzeige.
/// „Tresor anlegen“ erst, wenn die Regel erfüllt ist und beide Eingaben gleich sind.
struct SetupView: View {
    let model: AppModel
    @Bindable var state: SetupState

    var body: some View {
        CenteredPage {
            VStack(spacing: 0) {
                SiegelLogo(size: Theme.markLarge)
                Text("Siegel")
                    .font(Theme.wordmark)
                    .padding(.top, 18)
                Text("Dein Tresor. Lokal. Quantensicher verschlüsselt.")
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                    .padding(.top, 6)

                VStack(spacing: 14) {
                    switch state.mode {
                    case .passphrase: passphraseForm
                    case .own: ownPasswordForm
                    }

                    if let error = state.error {
                        MessageText(error)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    VStack(spacing: 10) {
                        Button("Tresor anlegen") { Task { await model.createVault() } }
                            .buttonStyle(PrimaryButtonStyle(fullWidth: true))
                            .disabled(!state.canCreate || model.busy)
                            .keyboardShortcut(.defaultAction)
                        ProgressLine(active: model.busy)
                    }
                    .padding(.top, 4)

                    Button(state.mode == .passphrase ? "Lieber ein eigenes Passwort" : "Passphrase vorschlagen") {
                        model.setSetupMode(state.mode == .passphrase ? .own : .passphrase)
                    }
                    .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    .disabled(model.busy)

                    // Befund datei-3: neuer Mac – die Sicherung vom alten (z. B. USB-Stick) einspielen, auch nur mit
                    // dem Notfallkit, statt zuerst einen leeren Tresor anzulegen.
                    Button("Aus Sicherung wiederherstellen…") { model.chooseBackupFileForRestore() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        .disabled(model.busy)
                }
                .frame(width: Theme.formWidth)
                .padding(.top, 30)

                if state.fileVaultEncrypted == false {
                    FileVaultLine()
                        .frame(width: 540)
                        .padding(.top, 22)
                }
            }
        }
    }

    // MARK: Passphrase

    private var passphraseForm: some View {
        VStack(spacing: 14) {
            VStack(spacing: 14) {
                SecretGate {
                    Text(Self.twoLines(state.passphrase))
                        .font(Theme.mono(19, weight: .medium))
                        .multilineTextAlignment(.center)
                        .lineSpacing(6)
                        .foregroundStyle(Theme.text)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityHidden(!TextHardening.exposesSecretsToAccessibility)
                } placeholder: { reveal in
                    HiddenSecretPlaceholder(reveal: reveal)
                        .frame(height: 56)
                }
                .frame(maxWidth: .infinity, minHeight: 56)

                HStack {
                    Button {
                        state.reroll()
                    } label: {
                        Label("Neu würfeln", systemImage: "dice")
                    }
                    .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    .disabled(model.busy)
                    Spacer()
                    Text("Zufalls-Entropie \(state.passphraseEntropyBits) Bit")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .monospacedDigit()
                }
            }
            .padding(.horizontal, 18)
            .padding(.top, 18)
            .padding(.bottom, 12)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
            )
            .accessibilityElement(children: .contain)
            .accessibilityLabel(TextHardening.exposesSecretsToAccessibility
                                ? "Vorgeschlagene Passphrase" : "Vorgeschlagene Passphrase, verborgen")

            Text(Typo.keepCompounds("Merk sie dir gut – Siegel kann sie nicht zurücksetzen."))
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            MasterPasswordField("Passphrase zur Bestätigung eintippen", text: $state.passphraseRepeat,
                                enabled: !model.busy) {
                Task { await model.createVault() }
            }
            if state.repeatMismatch {
                MessageText("Stimmt noch nicht mit der Passphrase überein.")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    /// Sechs Wörter auf zwei Zeilen à drei Wörter.
    static func twoLines(_ passphrase: String) -> String {
        let woerter = passphrase.split(separator: "-").map(String.init)
        guard woerter.count > 3 else { return passphrase }
        let mitte = (woerter.count + 1) / 2
        return woerter[..<mitte].joined(separator: "-") + "-\n" + woerter[mitte...].joined(separator: "-")
    }

    // MARK: Eigenes Passwort

    private var ownPasswordForm: some View {
        VStack(spacing: 12) {
            MasterPasswordField("Master-Passwort", text: $state.password, autoFocus: true, enabled: !model.busy)
            MasterPasswordField("Wiederholen", text: $state.passwordRepeat, enabled: !model.busy) {
                Task { await model.createVault() }
            }
            let assessment = state.assessment
            StrengthMeter(bits: assessment.bits, level: assessment.level, meetsPolicy: assessment.meetsPolicy,
                          isEmpty: assessment.isEmpty)
                .padding(.top, 4)
            if state.repeatMismatch {
                MessageText("Die Wiederholung stimmt nicht überein.")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

/// FileVault-Hinweis als ruhige Zeile (Einrichtung).
struct FileVaultLine: View {
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "lock.open")
            Text(FileVaultCheck.hint)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Einschalten…") { FileVaultCheck.openSettings() }
                .buttonStyle(PlainActionButtonStyle())
                .fixedSize()
        }
        .font(Theme.caption)
    }
}

/// FileVault-Hinweis mit Knopf zu den Systemeinstellungen (SPEC §6).
struct FileVaultHint: View {
    var body: some View {
        HintBox(symbol: "lock.open") {
            VStack(alignment: .leading, spacing: 8) {
                Text(FileVaultCheck.hint)
                Button("FileVault-Einstellungen öffnen") { FileVaultCheck.openSettings() }
                    .buttonStyle(PlainActionButtonStyle())
                    .font(Theme.caption.weight(.medium))
            }
        }
    }
}
