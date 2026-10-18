import SiegelCore
import SwiftUI

// Einstellungen → Sicherheitsstufe → Selbstvernichtung (SPEC v4.3 §23.3): vernichtbare Einträge, Totmann-Schalter,
// Fehlversuch-Zähler, Vernichtungs-Passwort; danach Bestätigung mit VERNICHTEN (beim Einschalten), Master-Passwort
// und allen Faktoren. Dazu die Anzeigen ausserhalb der Seite: Sperrbildschirm, Banner, Markierung im Detail.

struct DestructionPage: View {
    let model: AppModel
    @Bindable var state: DestructionState

    var body: some View {
        switch state.step {
        case .edit: edit
        case .confirm: confirm
        }
    }

    // MARK: Entwurf

    private var edit: some View {
        SettingsForm(title: DestructionTexts.title, text: DestructionTexts.intro, width: 560) {
            if state.destroyed, let banner = model.destructionBanner {
                destroyedBox(banner)
                    .padding(.bottom, 6)
            }
            HintBox(symbol: "exclamationmark.triangle") {
                Text(DestructionTexts.noRecovery)
            }
            .padding(.bottom, 22)

            SettingsSection("Vernichtbare Einträge") {
                let liste = model.selectableDestructionEntries
                if state.destroyed {
                    Text("Wieder wählbar, sobald du die vernichteten Einträge entfernt hast.")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.vertical, 14)
                } else if liste.isEmpty {
                    Text("Keine Einträge mit Schutz 4 oder 5. Erhöhe den Schutz eines Eintrags beim Bearbeiten – dann lässt er sich hier auswählen.")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.vertical, 14)
                } else {
                    ForEach(liste) { entry in
                        DestructibleRow(entry: entry, selected: state.selection.contains(entry.id)) {
                            model.destructionToggle(entry)
                        }
                    }
                }
            }
            VStack(alignment: .leading, spacing: 0) {
                // Nach einer Vernichtung ohne Zählung (die Auswahl gilt erst nach „Entfernen“ wieder).
                if !state.destroyed { selectionFootnote }
            }
            .padding(.top, 8)
            .padding(.bottom, 26)

            // Nach einer Vernichtung lässt der Kern erst nach „Entfernen“ wieder Änderungen zu.
            SettingsSection("Auslöser") {
                triggerToggle("Totmann-Schalter", DestructionTexts.deadmanText, isOn: $state.deadmanOn) {
                    SegmentedChoice(choices(DestructionRules.deadmanChoices, current: state.deadmanDays)
                                        .map { ($0, DestructionTexts.days($0)) },
                                    selection: $state.deadmanDays)
                }
                triggerToggle("Fehlversuch-Zähler", DestructionTexts.counterText, isOn: $state.counterOn) {
                    SegmentedChoice(choices(DestructionRules.attemptsChoices, current: state.maxAttempts)
                                        .map { ($0, "\($0)") },
                                    selection: $state.maxAttempts)
                }
                duressBlock
            }
            .disabled(state.destroyed)
            .opacity(state.destroyed ? 0.5 : 1)

            Text(DestructionTexts.honest)
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .lineSpacing(2)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 14)

            if let error = state.error {
                MessageText(error).frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 12) {
                if !state.destroyed, state.savedDeadmanDays != nil || state.savedMaxAttempts != nil || state.savedDuress
                    || !state.savedDestructible.isEmpty {
                    Button("Alles ausschalten") { model.destructionTurnEverythingOff() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                }
                Spacer()
                Button(state.hasChanges ? "Verwerfen" : "Zurück") {
                    if state.hasChanges { model.destructionRevert() } else { model.settingsBack() }
                }
                .buttonStyle(SecondaryButtonStyle())
                .keyboardShortcut(.cancelAction)
                Button("Weiter…") { model.destructionContinue() }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(!state.canContinue || model.busy)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 10)
        }
    }

    /// Gespeicherter Wert, auch wenn er nicht unter den Vorschlägen ist (7…365 bzw. 10…100 erlaubt).
    private func choices(_ base: [Int], current: Int) -> [Int] {
        base.contains(current) ? base : (base + [current]).sorted()
    }

    @ViewBuilder
    private var selectionFootnote: some View {
        let weitere = model.unselectableDestructionCount
        let ausgewaehlt = state.selection.count
        // Neutral formuliert: Dieselbe Zeile erscheint auch in einer Vernichtungs-Sitzung (dort ist nichts markiert).
        let teil1 = ausgewaehlt == 0 ? "Keine Einträge ausgewählt."
            : (ausgewaehlt == 1 ? "1 Eintrag ausgewählt." : "\(ausgewaehlt) Einträge ausgewählt.")
        let teil2 = weitere == 0 ? ""
            : (weitere == 1 ? " 1 weiterer Eintrag hat einen tieferen Schutz – du kannst ihn beim Bearbeiten erhöhen."
               : " \(weitere) weitere Einträge haben einen tieferen Schutz – du kannst ihn beim Bearbeiten erhöhen.")
        Text(teil1 + teil2)
            .font(Theme.caption)
            .foregroundStyle(Theme.secondary)
            .fixedSize(horizontal: false, vertical: true)
        // Befund ablaeufe-5: Markiert, aber kein Auslöser – nichts wird vernichtet, der Notfallweg fehlt trotzdem.
        if !state.selection.isEmpty, !state.deadmanOn, !state.counterOn, !state.duressOn {
            Label(DestructionTexts.marksWithoutTrigger, systemImage: "exclamationmark.triangle")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 6)
        }
    }

    private func triggerToggle<Value: View>(_ title: String, _ text: String, isOn: Binding<Bool>,
                                           @ViewBuilder value: () -> Value) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Toggle(isOn: isOn) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(Theme.body)
                    Text(text)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.trailing, 24)
            }
            .toggleStyle(MonochromeToggleStyle())
            if isOn.wrappedValue {
                value()
            }
        }
        .padding(.vertical, 14)
    }

    // MARK: Vernichtungs-Passwort

    private var duressStatus: String {
        if state.duressEditing { return state.savedDuress ? "Wird geändert" : "Neu" }
        if state.duressOn { return "Gesetzt" }
        return state.savedDuress ? "Wird entfernt" : "Nicht gesetzt"
    }

    private var duressBlock: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Vernichtungs-Passwort")
                        .font(Theme.body)
                    Text(DestructionTexts.duressText)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 12)
                VStack(alignment: .trailing, spacing: 8) {
                    Text(duressStatus)
                        .font(Theme.bodyMedium)
                        .foregroundStyle(state.duressOn || state.savedDuress ? Theme.text : Theme.secondary)
                    if !state.duressEditing {
                        HStack(spacing: 8) {
                            if state.duressOn {
                                Button("Entfernen") { model.destructionRemoveDuress() }
                                    .buttonStyle(CompactButtonStyle(quiet: true))
                                Button("Ändern…") { model.destructionStartDuressEditing() }
                                    .buttonStyle(CompactButtonStyle())
                            } else if state.savedDuress {
                                Button("Rückgängig") { model.destructionCancelDuressEditing() }
                                    .buttonStyle(CompactButtonStyle())
                            } else {
                                Button("Setzen…") { model.destructionStartDuressEditing() }
                                    .buttonStyle(CompactButtonStyle())
                            }
                        }
                    }
                }
                .fixedSize()
            }
            if state.duressEditing {
                VStack(alignment: .leading, spacing: 10) {
                    FieldLabel(state.savedDuress ? "Neues Vernichtungs-Passwort" : "Vernichtungs-Passwort") {
                        MasterPasswordField("Vernichtungs-Passwort", text: $state.duressPassword, autoFocus: true,
                                            enabled: !model.busy)
                    }
                    MasterPasswordField("Wiederholen", text: $state.duressRepeat, enabled: !model.busy) {
                        model.destructionContinue()
                    }
                    let bewertung = state.duressAssessment
                    StrengthMeter(bits: bewertung.bits, level: bewertung.level, meetsPolicy: bewertung.meetsPolicy,
                                  isEmpty: bewertung.isEmpty)
                    HStack {
                        Text("Gleiche Regel wie beim Master-Passwort. Wähle eines, das du unter Druck sicher abrufen kannst.")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 12)
                        Button("Abbrechen") { model.destructionCancelDuressEditing() }
                            .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    }
                }
                .frame(width: 400, alignment: .leading)
                .padding(.leading, 2)
            }
        }
        .padding(.vertical, 14)
    }

    // MARK: Vernichtet (echte Sitzung)

    private func destroyedBox(_ banner: DestructionBanner) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "flame")
                .font(.system(size: 14, weight: .medium))
                .frame(width: 18)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                Text(banner.title)
                    .font(Theme.caption.weight(.semibold))
                Text(banner.detail + ". Der Schlüssel dazu ist vernichtet. Entferne zuerst die vernichteten Einträge – danach ist die Selbstvernichtung aus, und du kannst sie mit einem neuen Schlüssel wieder einrichten.")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Entfernen") { Task { await model.removeDestroyedEntriesNow() } }
                .buttonStyle(CompactButtonStyle())
                .disabled(model.busy)
                .help(model.destroyedEntries.isEmpty ? "Hinweis entfernen"
                      : "Die vernichteten, nicht mehr lesbaren Einträge aus dem Tresor entfernen")
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.text, lineWidth: 1))
    }

    // MARK: Bestätigung

    private var confirm: some View {
        SettingsForm(title: state.arms ? "Selbstvernichtung einschalten" : "Selbstvernichtung ändern",
                     text: "Siegel prüft dein Master-Passwort und alle Faktoren der Stufe. Erst dann gilt die neue Einstellung.",
                     width: 560) {
            VStack(spacing: 0) {
                Hairline()
                FactRow(label: "Vernichtbare Einträge", value: selectionSummary)
                Hairline()
                FactRow(label: "Totmann-Schalter",
                        value: change(state.deadmanValue.map(DestructionTexts.days), was: state.savedDeadmanDays.map(DestructionTexts.days)))
                Hairline()
                FactRow(label: "Fehlversuch-Zähler",
                        value: change(state.attemptsValue.map(DestructionTexts.attempts),
                                      was: state.savedMaxAttempts.map(DestructionTexts.attempts)))
                Hairline()
                FactRow(label: "Vernichtungs-Passwort", value: duressSummary)
                Hairline()
            }
            .padding(.bottom, 8)

            if state.arms {
                HintBox(symbol: "exclamationmark.triangle") {
                    Text("Ab jetzt kann ein Auslöser die ausgewählten Einträge endgültig vernichten – ohne Rückfrage und ohne Notfallweg."
                         + (state.marksNewEntries ? " Ältere Sicherungen enthalten neu markierte Einträge noch mit Notfallweg – Siegel entfernt sie beim Einschalten." : ""))
                }
                FieldLabel(DestructionTexts.confirmWordHint) {
                    HardenedTextField(DestructionRules.confirmWord, text: $state.confirmWord,
                                      font: Theme.nsMono(14, weight: .medium), autoFocus: true) {
                        Task { await model.destructionApply() }
                    }
                    .frame(width: 260)
                }
                .padding(.top, 4)
            }
            FieldLabel("Master-Passwort") {
                MasterPasswordField("Master-Passwort bestätigen", text: $state.masterPassword, autoFocus: !state.arms,
                                    enabled: !model.busy && !model.factorInProgress) {
                    Task { await model.destructionApply() }
                }
                .frame(width: 340)
            }
            .padding(.top, 4)
            if let collection = state.collection {
                CollectionProgress(collection: collection, onRetry: { Task { await model.destructionApply() } })
                    .padding(.top, 2)
            } else if let factors = model.vaultHeader?.factors, !factors.isEmpty {
                FactorRequirementLine(factors: factors, prefix: "Danach nötig:")
                    .padding(.top, 2)
            }
            if state.needsNewKey {
                HStack(spacing: 8) {
                    if state.creatingKey {
                        PulsingSymbol(symbol: "touchid", size: 13)
                    } else {
                        Image(systemName: "touchid")
                            .font(.system(size: 12, weight: .medium))
                    }
                    Text(state.creatingKey ? "Lege den Finger auf Touch ID – Siegel legt den Schlüssel für die Selbstvernichtung an."
                         : "Danach einmal Touch ID: Siegel legt einen eigenen Schlüssel für die Selbstvernichtung an.")
                        .fixedSize(horizontal: false, vertical: true)
                }
                .font(Theme.caption)
                .foregroundStyle(state.creatingKey ? Theme.text : Theme.secondary)
            }
            if state.selection != state.savedDestructible {
                // Der Kern versiegelt neu markierte und abgewählte Einträge neu (eine Freigabe je Schutzstufe, beim
                // Abwählen Touch ID je Eintrag).
                Text("Zum Neu-Versiegeln fragt Siegel danach die Faktoren der betroffenen Einträge ab.")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error = state.error {
                MessageText(error).frame(maxWidth: .infinity, alignment: .leading)
            }
            VStack(spacing: 10) {
                HStack(spacing: 12) {
                    Spacer()
                    Button("Zurück") { model.destructionBack() }
                        .buttonStyle(SecondaryButtonStyle())
                        .keyboardShortcut(.cancelAction)
                        .disabled(model.busy || model.factorInProgress)
                    Button(state.arms ? "Einschalten" : "Sichern") { Task { await model.destructionApply() } }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(!canApply || model.busy || model.factorInProgress)
                        .keyboardShortcut(.defaultAction)
                }
                ProgressLine(active: model.busy)
            }
            .padding(.top, 8)
        }
    }

    private var canApply: Bool {
        !state.masterPassword.isEmpty && (!state.arms || state.confirmWordMatches)
    }

    private var selectionSummary: String {
        let neu = state.selection.subtracting(state.savedDestructible).count
        let weg = state.savedDestructible.subtracting(state.selection).count
        var text = state.selection.isEmpty ? "Keine" : "\(state.selection.count)"
        var zusatz: [String] = []
        if neu > 0 { zusatz.append("\(neu) neu") }
        if weg > 0 { zusatz.append("\(weg) abgewählt") }
        if !zusatz.isEmpty { text += " (" + zusatz.joined(separator: ", ") + ")" }
        return text
    }

    /// „30 Tage (bisher aus)“
    private func change(_ neu: String?, was: String?) -> String {
        let jetzt = neu ?? "Aus"
        guard neu != was else { return jetzt }
        return jetzt + " (bisher " + (was ?? "aus") + ")"
    }

    private var duressSummary: String {
        if state.duressOn {
            if state.duressEditing { return state.savedDuress ? "Neues Passwort" : "Neu gesetzt" }
            return "Unverändert"
        }
        return state.savedDuress ? "Wird entfernt" : "Aus"
    }
}

/// Eine Zeile der Auswahl: Kästchen, Titel, Benutzer; markiert mit „Kein Notfallweg“.
struct DestructibleRow: View {
    var entry: VaultEntry
    var selected: Bool
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                CheckGlyph(on: selected)
                VStack(alignment: .leading, spacing: 2) {
                    Text(AppModel.listTitle(entry))
                        .font(Theme.body)
                        .lineLimit(1)
                    Text(entry.username.isEmpty ? " " : entry.username)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 12)
                if selected {
                    HStack(spacing: 5) {
                        Image(systemName: "exclamationmark.circle")
                            .font(.system(size: 11, weight: .medium))
                        Text(DestructionTexts.noRecoveryShort)
                    }
                    .font(Theme.caption.weight(.medium))
                    .foregroundStyle(Theme.text)
                }
                ProtectionGlyphs(protection: entry.protection, size: 10)
                    .foregroundStyle(Theme.secondary)
                    .frame(width: 44, alignment: .trailing)
            }
            .frame(minHeight: 50)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(AppModel.listTitle(entry) + (selected ? ", vernichtbar, kein Notfallweg" : ""))
        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
    }
}

/// Kästchen in Schwarz/Weiss (ohne eigenen Fokus – die Zeile ist der Knopf).
struct CheckGlyph: View {
    var on: Bool

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .fill(on ? Theme.text : Theme.background)
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .strokeBorder(on ? Theme.text : Theme.secondary, lineWidth: 1)
            if on {
                Image(systemName: "checkmark")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(Theme.background)
            }
        }
        .frame(width: 15, height: 15)
    }
}

// MARK: - Sperrbildschirm

/// Unter dem Sperrbildschirm-Feld: „Noch x Versuche bis zur Vernichtung“ (ab N/2, deutlich).
struct DestructionAttemptsWarning: View {
    var remaining: Int

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 11, weight: .semibold))
            Text(DestructionTexts.remaining(remaining))
        }
        .font(Theme.caption.weight(.semibold))
        .foregroundStyle(Theme.text)
        .accessibilityElement(children: .combine)
    }
}

/// Unten im Sperrbildschirm: „Frist endet am …“ (ab 25 % Restzeit, dezent).
struct DestructionDeadlineHint: View {
    var deadline: Date

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "hourglass")
                .font(.system(size: 10, weight: .medium))
            Text(DestructionTexts.deadline(deadline))
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.secondary)
        .help("Totmann-Schalter: Entsperre Siegel bis dahin mit dem Master-Passwort, sonst werden die vernichtbaren Einträge vernichtet.")
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Tresor

/// Banner in der Seitenleiste nach einer Vernichtung (nur echte Sitzung): „n Einträge wurden vernichtet
/// (Auslöser, Datum)“ mit „Entfernen“.
struct DestructionBannerView: View {
    let model: AppModel
    var banner: DestructionBanner

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "flame")
                .font(.system(size: 12, weight: .medium))
            VStack(alignment: .leading, spacing: 2) {
                Text(banner.title)
                    .font(Theme.caption.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(Typo.keepCompounds(banner.trigger))
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.85)
                HStack(alignment: .center) {
                    Text(banner.date)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                    Spacer(minLength: 8)
                    Button("Entfernen") { Task { await model.removeDestroyedEntriesNow() } }
                        .buttonStyle(CompactButtonStyle(height: 24))
                        .disabled(model.busy || model.browser.mode == .edit)
                        .help(model.destroyedEntries.isEmpty ? "Hinweis entfernen"
                              : "Die vernichteten, nicht mehr lesbaren Einträge aus dem Tresor entfernen")
                }
                .padding(.top, 2)
            }
        }
        .foregroundStyle(Theme.text)
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Theme.text, lineWidth: 1))
        .accessibilityElement(children: .contain)
    }
}

/// Dezente Markierung im Detail: „Vernichtbar“.
struct DestructibleMark: View {
    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "flame")
                .font(.system(size: 9, weight: .medium))
            Text("Vernichtbar")
        }
        .help("Wird endgültig vernichtet, wenn ein Auslöser der Selbstvernichtung greift. Kein Notfallweg.")
        .accessibilityElement(children: .combine)
    }
}
