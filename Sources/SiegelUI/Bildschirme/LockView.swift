import SiegelCore
import SwiftUI

/// Sperrbildschirm (SPEC §7.2, v4 §13): Logo mittig, Master-Passwort, Enter entsperrt, feine Fortschrittslinie
/// während Argon2. Verlangt der Tresor Faktoren, zeigt eine Reihe darunter, was nötig ist und was schon erledigt
/// ist (Passwort → Touch ID → Karte → Schlüssel). Falsch → Schütteln + Meldung. Unten leise „Notfallcode verwenden“.
struct LockView: View {
    let model: AppModel
    @Bindable var state: UnlockState

    private var collecting: Bool { state.collecting }

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 24)
            SiegelLogo(size: Theme.markLarge, riegel: state.riegel)
                .layoutProbe("lock.logo")
            // Abstand zum Feld: eine Scheibenhöhe (design/LOGO.md). Nachgiebig erst, wenn die Ränder schon auf ihrem
            // Minimum sind – sonst quillt der Inhalt im kleinsten Fenster (760×480) über (Befund design-2).
            Spacer(minLength: 24)
                .frame(maxHeight: Theme.markLarge)
                .layoutPriority(1)
            VStack(spacing: 0) {
                MasterPasswordField("Master-Passwort", text: $state.password, autoFocus: true,
                                    enabled: !model.busy && !collecting, showsSubmit: true) {
                    Task { await model.submitUnlock() }
                }
                .frame(width: 300)
                .modifier(ShakeEffect(shakes: state.shakes))
                .layoutProbe("lock.field")
                ProgressLine(active: model.busy)
                    .frame(width: 284)
                    .padding(.top, 10)
                if !state.factors.isEmpty {
                    // Feste Höhe: Fehlermeldungen schieben das Logo nicht.
                    factors
                        .frame(width: 440, height: 124, alignment: .top)
                        .padding(.top, 18)
                }
                VStack(spacing: 8) {
                    if let error = state.error {
                        MessageText(error)
                            .multilineTextAlignment(.center)
                    } else if let hinweis = model.lockNotice {
                        // Befund #27/#31: Eine Bearbeitung ging beim Sperren verloren (nur der Grund, kein Inhalt).
                        MessageText(hinweis)
                            .multilineTextAlignment(.center)
                    }
                    // §23.2: ab N/2 Fehlversuchen deutlich (eigene Tippfehler zählen mit).
                    if let rest = model.lockRemainingAttempts {
                        DestructionAttemptsWarning(remaining: rest)
                            .layoutProbe("lock.attempts")
                    }
                }
                .frame(width: 340, height: messageHeight, alignment: .top)
                .padding(.top, 10)
            }
            Spacer(minLength: 24)
            // §23.2: Totmann-Frist ab 25 % Restzeit, dezent über dem Notfallweg. Eine eigene Zeile im Layout (Befund
            // design-2): Als Überlagerung lief sie im kleinsten Fenster in die Zähler-Warnung. Sie ändert sich nicht,
            // während jemand tippt – das Logo springt also nicht.
            if let frist = model.lockDeadline {
                DestructionDeadlineHint(deadline: frist)
                    .fixedSize()
                    .layoutProbe("lock.deadline")
                    .padding(.bottom, 14)
            }
            // Bietet die Faktor-Zeile den Notfallweg schon an, hier nicht doppelt.
            Button("Notfallcode verwenden") { model.startRecovery() }
                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                .disabled(model.busy || collecting)
                .opacity(state.collection?.failure?.offerRecovery == true ? 0 : 1)
                .layoutProbe("lock.recovery")
                .padding(.bottom, 30)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// Platz der Meldungszeile (fest, damit das Logo nicht springt): mehr bei Hinweis. Die Zähler-Warnung (§23.2)
    /// passt zusammen mit einer einzeiligen Fehlermeldung in die 44 pt; nur neben dem Hinweis braucht sie mehr.
    private var messageHeight: CGFloat {
        guard model.lockNotice != nil else { return 44 }
        return model.lockRemainingAttempts == nil ? 62 : 84
    }

    private var factors: some View {
        let collection = state.collection
        let gestartet = collecting || model.busy || collection?.failure != nil
        return FactorProgressView(
            kinds: state.factors.kinds,
            status: collection?.status ?? [:],
            active: collecting ? collection?.active : nil,
            failure: collection?.failure,
            passwordStatus: gestartet ? .done : .pending,
            caption: gestartet ? nil : "Zum Öffnen nötig",
            opening: model.busy && !collecting,
            onRetry: { Task { await model.retryUnlockFactors() } },
            onRecovery: { model.startRecovery() })
    }
}
