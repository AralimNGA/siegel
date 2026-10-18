import SiegelCore
import SwiftUI

/// Bearbeiten bzw. neuer Eintrag (SPEC §7.5) mit eingebautem Generator (kein Popover, SPEC §6).
/// Klartext-Felder: `HardenedTextField`; Passwort: `SecretField`; Notizen: `SecretTextView`.
/// Esc = Abbrechen, ⌘S oder Enter in einem einzeiligen Feld = Sichern.
struct EntryEditView: View {
    let model: AppModel
    @Bindable var editor: EntryEditorState
    /// Befund #43: Passwort und 2FA-Geheimnis eines bestehenden Eintrags starten verdeckt (wie im Detail) und
    /// erscheinen erst nach einem Klick. Der Zustand lebt nur in dieser Ansicht (Abbrechen, Sichern, Sperren,
    /// anderer Eintrag verwerfen ihn).
    @State private var passwordShown = false
    @State private var totpShown = false

    private var showsPassword: Bool {
        editor.isNew || editor.appliedGenerated || passwordShown || (editor.baseline?.password.isEmpty ?? true)
    }

    private var showsTotp: Bool {
        editor.isNew || totpShown || (editor.baseline?.totp.isEmpty ?? true)
    }

    var body: some View {
        VStack(spacing: 0) {
            DetailHeader {
                // Während des Speicherns (z. B. „Übernehmen“) gesperrt: sonst ginge das alte Passwort nicht zurück.
                Button("Abbrechen") { Task { await model.cancelEdit() } }
                    .buttonStyle(CompactButtonStyle())
                    .keyboardShortcut(.cancelAction)
                    .disabled(model.busy || model.isSaving)
                Button("Sichern") { Task { await model.saveEdit() } }
                    .buttonStyle(CompactButtonStyle(primary: true))
                    .keyboardShortcut("s", modifiers: .command)
                    .disabled(model.busy || model.isSaving)
                    .help("Sichern (⌘S)")
            }
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 0) {
                    Text(editor.isNew ? "Neuer Eintrag" : "Eintrag bearbeiten")
                        .font(Theme.title)
                    if editor.appliedGenerated {
                        Text(Typo.keepCompounds("Das übernommene Passwort ist schon gespeichert. „Abbrechen“ stellt das bisherige wieder her; das neue bleibt unter „Frühere Passwörter“."))
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 6)
                    }
                    form
                        .padding(.top, 24)
                    if let error = editor.error {
                        MessageText(error)
                            .padding(.top, 14)
                    }
                    ProgressLine(active: model.busy)
                        .padding(.top, 18)
                }
                .frame(maxWidth: DetailMetrics.column, alignment: .leading)
                .padding(.horizontal, DetailMetrics.side)
                .padding(.top, TresorMetrics.contentTop)
                .padding(.bottom, 40)
                .frame(maxWidth: .infinity)
            }
            .scrollIndicators(.automatic)
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 18) {
            EditField("Titel") {
                HardenedTextField(titlePlaceholder, text: $editor.draft.title, autoFocus: editor.isNew) {
                    Task { await model.saveEdit() }
                }
            }
            EditField("Benutzername") {
                HardenedTextField("Name oder E-Mail", text: $editor.draft.username) {
                    Task { await model.saveEdit() }
                }
            }
            if editor.secretsLocked {
                lockedSecrets
            } else {
                EditField("Passwort") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 8) {
                            if showsPassword {
                                SecretField("Passwort", text: $editor.draft.password, autoFocus: passwordShown) {
                                    Task { await model.saveEdit() }
                                }
                            } else {
                                ConcealedField(label: "Passwort zeigen und bearbeiten") { passwordShown = true }
                            }
                            Button {
                                model.toggleGenerator()
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: "dice")
                                        .font(.system(size: 12))
                                    Text("Generator")
                                    Image(systemName: "chevron.down")
                                        .font(.system(size: 8, weight: .bold))
                                        .rotationEffect(.degrees(editor.generatorOpen ? 180 : 0))
                                }
                            }
                            .buttonStyle(CompactButtonStyle(primary: editor.generatorOpen, height: Theme.fieldHeight))
                            .accessibilityValue(editor.generatorOpen ? "offen" : "geschlossen")
                        }
                        if editor.generatorOpen {
                            GeneratorPanel(model: model, editor: editor)
                                .transition(.opacity)
                        }
                    }
                }
            }
            EditField("Website") {
                HardenedTextField("https://…", text: $editor.draft.url) {
                    Task { await model.saveEdit() }
                }
            }
            if !editor.secretsLocked {
                EditField("2FA-Geheimnis (optional)") {
                    VStack(alignment: .leading, spacing: 7) {
                        if showsTotp {
                            SecretField("otpauth://totp/… oder Base32-Geheimnis", text: $editor.draft.totp,
                                        autoFocus: totpShown) {
                                Task { await model.saveEdit() }
                            }
                        } else {
                            ConcealedField(label: "2FA-Geheimnis zeigen und bearbeiten") { totpShown = true }
                        }
                        TOTPHint(check: TOTPDisplay.check(editor.draft.totp))
                    }
                }
                EditField("Notizen") {
                    SecretTextView(text: $editor.draft.notes, minHeight: 110)
                }
            }
            EditField("Schutz") {
                VStack(alignment: .leading, spacing: 10) {
                    ProtectionPicker(selection: $editor.draft.protection, enabled: !editor.secretsLocked,
                                     enrolled: model.enrolledFactors,
                                     minimum: model.destructibleEntries.contains(editor.draft.id) ? .maximal : .normal)
                    protectionHint
                }
            }
        }
    }

    /// Versiegelte Geheimteile: erst aufdecken, dann bearbeiten (Titel, Benutzer und Website gehen ohne).
    private var lockedSecrets: some View {
        let faktoren = editor.originalProtection.factors
        let laeuft = model.browser.revealing == editor.draft.id
        return HStack(alignment: .center, spacing: 12) {
            Image(systemName: "lock")
                .font(.system(size: 14, weight: .medium))
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text("Passwort, 2FA und Notizen sind versiegelt")
                    .font(Theme.caption.weight(.semibold))
                Text(laeuft ? "Aufdecken …" : "Zum Bearbeiten aufdecken – braucht " + FactorUI.list(faktoren, long: true) + ".")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button {
                Task { await model.unlockEditorSecrets() }
            } label: {
                HStack(spacing: 6) {
                    ProtectionGlyphs(protection: editor.originalProtection, size: 10)
                    Text("Aufdecken")
                }
            }
            .buttonStyle(CompactButtonStyle(primary: true))
            .disabled(laeuft || model.factorInProgress)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.text, lineWidth: 1))
    }

    @ViewBuilder
    private var protectionHint: some View {
        let fehlend = model.missingFactors(for: editor.draft.protection)
        if model.destructibleEntries.contains(editor.draft.id), !editor.secretsLocked {
            Text("Vernichtbar: Schutz mindestens 4. Zum Senken zuerst unter Einstellungen → Selbstvernichtung abwählen.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        } else if editor.secretsLocked {
            Text("Zum Ändern des Schutzes zuerst die Geheimteile aufdecken.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
        } else if !fehlend.isEmpty {
            HStack(spacing: 10) {
                MessageText("Für Schutz \(editor.draft.protection.rawValue) fehlt noch: " + FactorUI.list(fehlend, long: true) + ".")
                Spacer(minLength: 8)
                Button("Jetzt einrichten…") { model.enrollForEditor() }
                    .buttonStyle(CompactButtonStyle())
            }
        } else if editor.draft.protection > .normal {
            Text("Geheimteile werden versiegelt gespeichert. Titel, Benutzername und Website bleiben ohne Faktoren lesbar.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var titlePlaceholder: String {
        if let host = Website.parse(editor.draft.url)?.displayHost, !host.isEmpty { return host }
        return "Titel"
    }
}

/// Beschriftetes Feld im Formular.
struct EditField<Content: View>: View {
    var title: String
    var content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(Theme.caption.weight(.medium))
                .foregroundStyle(Theme.secondary)
            content
        }
    }
}

/// Generator im Formular: Ergebnis, Länge 8–64, Zeichenklassen, „Ähnliche Zeichen vermeiden“,
/// Zufalls-Entropie, „Übernehmen“ (speichert sofort).
struct GeneratorPanel: View {
    let model: AppModel
    @Bindable var editor: EntryEditorState

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 10) {
                SecretGate {
                    SecretLabel(text: editor.generated, font: Theme.nsMono(15, weight: .medium))
                        .secretAccessibility("Generiertes Passwort, verborgen")
                        .frame(maxWidth: .infinity, alignment: .leading)
                } placeholder: { reveal in
                    HiddenSecretPlaceholder(reveal: reveal)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minHeight: 22)
                IconButton(symbol: "arrow.clockwise", label: "Neu erzeugen", size: 13) { model.regenerate() }
            }

            Hairline()

            HStack(spacing: 14) {
                Text("Länge")
                    .font(Theme.body)
                    .frame(width: 52, alignment: .leading)
                MonoSlider(value: Binding(get: { editor.options.length },
                                          set: { neu in model.updateGenerator { $0.length = neu } }),
                           range: 8...64)
                Text("\(editor.options.length)")
                    .font(Theme.mono(13, weight: .medium))
                    .monospacedDigit()
                    .frame(width: 26, alignment: .trailing)
            }

            Grid(alignment: .leading, horizontalSpacing: 26, verticalSpacing: 10) {
                GridRow {
                    MonoCheckbox(title: "Grossbuchstaben", isOn: option(\.uppercase))
                    MonoCheckbox(title: "Kleinbuchstaben", isOn: option(\.lowercase))
                }
                GridRow {
                    MonoCheckbox(title: "Ziffern", isOn: option(\.digits))
                    MonoCheckbox(title: "Symbole", isOn: option(\.symbols))
                }
                GridRow {
                    MonoCheckbox(title: "Ähnliche Zeichen vermeiden", isOn: option(\.avoidAmbiguous))
                        .gridCellColumns(2)
                        .help("Ohne 0/O, 1/l/I und ähnliche, die man leicht verwechselt")
                }
            }

            Hairline()

            HStack(spacing: 12) {
                Text("Zufalls-Entropie")
                    .foregroundStyle(Theme.secondary)
                Text("\(editor.entropyBits) Bit")
                    .fontWeight(.medium)
                    .monospacedDigit()
                Spacer(minLength: 8)
                Button("Übernehmen") { Task { await model.applyGenerated() } }
                    .buttonStyle(CompactButtonStyle(primary: true))
                    .disabled(model.busy || editor.generated.isEmpty)
                    .help("Wird sofort gespeichert; das bisherige Passwort kommt in den Verlauf.")
            }
            .font(Theme.caption)
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
        )
    }

    private func option(_ pfad: WritableKeyPath<PasswordGenerator.Options, Bool>) -> Binding<Bool> {
        Binding(get: { editor.options[keyPath: pfad] },
                set: { neu in model.updateGenerator { $0[keyPath: pfad] = neu } })
    }
}

/// Verdecktes Geheimnis im Bearbeiten (Befund #43): feste Punkte (verraten die Länge nicht), Auge daneben. Ein Klick
/// zeigt das Feld zum Bearbeiten.
struct ConcealedField: View {
    var label: String
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Text("••••••••••")
                    .font(.system(size: 16, weight: .regular))
                    .kerning(0.6)
                    .foregroundStyle(Theme.text)
                Spacer(minLength: 8)
                Image(systemName: "eye")
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(Theme.secondary)
            }
            .padding(.horizontal, 10)
            .frame(height: Theme.fieldHeight)
            .background(
                RoundedRectangle(cornerRadius: Theme.corner, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(label)
        .accessibilityLabel(label)
    }
}

/// Prüfung des 2FA-Geheimnisses unter dem Feld (über `TOTP.parse` im Kern, §18).
struct TOTPHint: View {
    var check: TOTPCheck

    var body: some View {
        switch check {
        case .empty:
            Text("Steht beim Einrichten der Zwei-Faktor-Anmeldung einer Website, meist als Text unter dem QR-Code.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
        case let .valid(digits, period):
            VStack(alignment: .leading, spacing: 3) {
                MessageText("Gültig – \(digits) Ziffern, neuer Code alle \(period) s.", symbol: "checkmark.circle")
                Text("Wer den Tresor öffnet, hat damit auch den zweiten Faktor.")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .padding(.leading, 18)
            }
        case .invalid:
            MessageText("Kein gültiges 2FA-Geheimnis. Erwartet wird ein otpauth://totp/…-Link oder das Geheimnis in Base32 (A–Z und 2–7).")
        }
    }
}
