import SiegelCore
import SwiftUI

/// Einstellungen (SPEC §7.7) als Seite im Hauptfenster (⌘,), nur entsperrt.
/// Heikle Aktionen fragen das Master-Passwort erneut ab.
struct SettingsView: View {
    let model: AppModel
    @Bindable var state: SettingsState

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 0) {
                header
                    .padding(.bottom, state.page == .overview ? 30 : 22)
                switch state.page {
                case .overview: overview
                case .changePassword: changePassword
                case let .kdfProfile(strong): kdfProfile(strong)
                case .checkCode: checkCode
                case .unconfirmedKit: unconfirmedKit
                case .newKit: newKit
                case let .purgeBackups(reason): purgeBackups(reason)
                case .purgeOld: purgeOld
                case .autofill: AutofillPage(model: model)
                case .licenses: LicensesPage(model: model)
                case .securityLevel: SecurityLevelOverview(model: model, state: state)
                case .wizard:
                    if let wizard = model.wizard {
                        SecurityWizardView(model: model, wizard: wizard)
                    }
                case .destruction:
                    if let destruction = model.destructionState {
                        DestructionPage(model: model, state: destruction)
                    }
                }
            }
            .frame(width: 560, alignment: .leading)
            .padding(.top, 40)
            .padding(.bottom, 36)
            .frame(maxWidth: .infinity)
        }
        .scrollIndicators(.automatic)
        .onExitCommand {
            switch state.page {
            case .overview: model.closeSettings()
            case .wizard: model.wizardCancel()
            // Befund #34: Die Frage nach den alten Sicherungen hat nur „Behalten“ und „Entfernen“.
            case .purgeBackups: break
            case .destruction where model.destructionState?.step == .confirm: model.destructionBack()
            default: model.settingsBack()
            }
        }
    }

    // MARK: Kopf

    /// Frage nach den alten Sicherungen: kein „Zurück“, kein „Fertig“ (Befund #34).
    private var isPurgeQuestion: Bool {
        if case .purgeBackups = state.page { return true }
        return false
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            if isPurgeQuestion {
                // Kein Ausgang ausser der Antwort; Höhe wie die übrigen Köpfe.
                Color.clear.frame(height: Theme.buttonHeight)
            } else if state.page == .wizard {
                Button {
                    model.wizardCancel()
                } label: {
                    Label(model.wizard?.returnsToEditor == true ? "Zurück zum Eintrag" : "Sicherheitsstufe",
                          systemImage: "chevron.left")
                }
                .buttonStyle(QuietButtonStyle())
                .disabled(model.busy || model.isSaving || model.wizard?.step == .done)
            } else if state.page != .overview {
                Button {
                    model.settingsBack()
                } label: {
                    Label("Einstellungen", systemImage: "chevron.left")
                }
                .buttonStyle(QuietButtonStyle())
                .disabled(model.busy)
            } else {
                Text("Einstellungen")
                    .font(Theme.title)
            }
            Spacer()
            // Im Assistenten führen „Abbrechen“ bzw. der Abschluss zurück (kein zweiter Ausgang).
            if state.page != .wizard, !isPurgeQuestion {
                Button("Fertig") { model.closeSettings() }
                    .buttonStyle(SecondaryButtonStyle())
                    .disabled(model.busy || model.isSaving || model.factorInProgress)
            }
        }
    }

    // MARK: Übersicht

    private var overview: some View {
        VStack(alignment: .leading, spacing: 34) {
            SettingsSection("Sicherheitsstufe") {
                Button {
                    model.showSecurityLevels()
                } label: {
                    HStack(spacing: 14) {
                        LevelBadge(number: model.level.rawValue, filled: true)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Stufe \(model.level.rawValue) · \(model.level.title)")
                                .font(Theme.bodyMedium)
                            HStack(spacing: 8) {
                                FactorGlyphs(factors: model.level.factors, size: 10)
                                Text("Zum Öffnen: " + LevelTexts.open(model.level) + " · Notfall: "
                                     + LevelTexts.emergency(model.vaultHeader?.recoveryScheme ?? model.level.recoveryScheme))
                                    .font(Theme.caption)
                                    .foregroundStyle(Theme.secondary)
                                    .lineLimit(1)
                                    .minimumScaleFactor(0.85)
                            }
                        }
                        Spacer(minLength: 8)
                        Text("Ändern…")
                            .font(Theme.body)
                        Image(systemName: "chevron.right")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Theme.secondary)
                    }
                    .padding(.vertical, 12)
                    .contentShape(Rectangle())
                }
                .buttonStyle(PlainActionButtonStyle())
                VStack(alignment: .leading, spacing: 0) {
                    SettingsRow("Schutz neuer Einträge") {
                        ProtectionSegments(selection: Binding(get: { model.effectiveDefaultProtection },
                                                              set: { model.settings.defaultEntryProtection = $0 }),
                                           minimum: model.policy.defaultEntryProtection)
                    }
                    Text(ProtectionTexts.label(model.effectiveDefaultProtection) + ": "
                         + ProtectionTexts.short(model.effectiveDefaultProtection)
                         + (model.policy.defaultEntryProtection > .normal ? " Die Stufe verlangt mindestens Schutz \(model.policy.defaultEntryProtection.rawValue)." : ""))
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.bottom, 12)
                }
                VStack(alignment: .leading, spacing: 0) {
                    SettingsRow("Faktoren für Einträge") {
                        if model.enrolledFactors.isEmpty {
                            Text("Noch keine eingerichtet")
                                .font(Theme.body)
                                .foregroundStyle(Theme.secondary)
                        } else {
                            HStack(spacing: 8) {
                                FactorGlyphs(factors: model.enrolledFactors, password: false, size: 11)
                                Text(FactorUI.list(model.enrolledFactors))
                                    .font(Theme.body)
                            }
                        }
                    }
                    let fehlend = FactorSet.all.subtracting(model.enrolledFactors).kinds
                    if !fehlend.isEmpty {
                        HStack(spacing: 8) {
                            Text("Einrichten:")
                                .font(Theme.caption)
                                .foregroundStyle(Theme.secondary)
                            ForEach(fehlend, id: \.self) { kind in
                                Button {
                                    model.startEnroll(FactorSet(rawValue: kind.rawValue))
                                } label: {
                                    HStack(spacing: 6) {
                                        Image(systemName: FactorUI.symbol(kind))
                                            .font(.system(size: 11, weight: .medium))
                                        Text(FactorUI.longName(kind))
                                    }
                                }
                                .buttonStyle(CompactButtonStyle(quiet: true))
                            }
                        }
                        .padding(.bottom, 12)
                    }
                }
                // §23.3: nur in Stufe 4/5.
                if model.offersDestruction {
                    Button {
                        Task { await model.showDestruction() }
                    } label: {
                        HStack(spacing: 14) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(DestructionTexts.title)
                                    .font(Theme.body)
                                Text(DestructionTexts.summary(model.destruction?.settings, configured: model.destructionConfigured))
                                    .font(Theme.caption)
                                    .foregroundStyle(Theme.secondary)
                                    .lineLimit(1)
                            }
                            Spacer(minLength: 8)
                            Image(systemName: "chevron.right")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(Theme.secondary)
                        }
                        .padding(.vertical, 12)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(PlainActionButtonStyle())
                }
            }

            SettingsSection("Sperren") {
                VStack(alignment: .leading, spacing: 0) {
                    SettingsRow("Automatisch sperren nach") {
                        SegmentedChoice(AppSettings.autoLockChoices.map { ($0, "\($0) Min.") },
                                        selection: Bindable(model.settings).autoLockMinutes)
                    }
                    if let max = model.policy.autoLockMinutesMax, model.settings.autoLockMinutes > max {
                        policyNote("Stufe \(model.level.title): höchstens \(max) Min. – es gilt \(model.effectiveAutoLockMinutes) Min.")
                    }
                }
                VStack(alignment: .leading, spacing: 0) {
                    SettingsRow("Zwischenablage leeren nach") {
                        SegmentedChoice(AppSettings.clipboardChoices.map { ($0, "\($0) s") },
                                        selection: Bindable(model.settings).clipboardSeconds)
                    }
                    if let max = model.policy.clipboardSecondsMax, model.settings.clipboardSeconds > max {
                        policyNote("Stufe \(model.level.title): höchstens \(max) s – es gilt \(model.effectiveClipboardSeconds()) s.")
                    }
                }
                if model.policy.lockOnDeactivate || model.policy.touchIDBeforeReveal {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Regeln der Stufe \(model.level.title)")
                            .font(Theme.body)
                        Text("Touch ID vor jedem Aufdecken und Kopieren · sperrt beim Wechsel in ein anderes Programm.")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                    }
                    .padding(.vertical, 12)
                }
                Toggle(isOn: Bindable(model.settings).showSecretsOnExternalDisplays) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Geheimnisse auf externen Bildschirmen zeigen")
                            .font(Theme.body)
                        Text("Sidecar, AirPlay und angeschlossene Monitore. Standard: aus.")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                    }
                }
                .toggleStyle(MonochromeToggleStyle())
                .padding(.vertical, 12)
            }

            SettingsSection("Master-Passwort") {
                SettingsLink("Master-Passwort ändern…") { model.settingsShow(.changePassword) }
                VStack(alignment: .leading, spacing: 8) {
                    SettingsRow("Schlüsselableitung") {
                        SegmentedChoice([(false, "Standard"), (true, "Stark")],
                                        selection: Binding(get: { model.usesStrongProfile },
                                                           set: { model.requestKDFProfile(strong: $0) }))
                            .disabled(model.kdfFixedByLevel)
                    }
                    Text(model.kdfFixedByLevel
                         ? "Stark: 2 GiB Arbeitsspeicher, etwa 3 s zum Entsperren – ab Stufe Hoch fest."
                         : "Standard: 1 GiB Arbeitsspeicher, etwa 1 s zum Entsperren. Stark: 2 GiB, etwa 3 s.")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .padding(.bottom, 12)
                }
            }

            SettingsSection("Notfallkit") {
                SettingsRow("Kit-Kennung") {
                    Text(model.kitID)
                        .font(Theme.mono(13, weight: .medium))
                }
                if !model.recoveryConfirmed {
                    SettingsLink("Notfallkit nicht bestätigt – jetzt einrichten", symbol: "exclamationmark.circle") {
                        model.settingsShow(.unconfirmedKit)
                    }
                }
                SettingsLink("Notfallcode prüfen…") { model.settingsShow(.checkCode) }
                SettingsLink("Neues Notfallkit…") { model.settingsShow(.newKit) }
            }

            SettingsSection("Sicherungen") {
                SettingsRow("Zweiter Sicherungsort") {
                    HStack(spacing: 14) {
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(model.secondaryBackupName ?? "Nicht gewählt")
                                .font(Theme.body)
                                .foregroundStyle(model.secondaryBackupName == nil ? Theme.secondary : Theme.text)
                                .lineLimit(1)
                            if model.secondaryBackupUnreachable {
                                Text(secondaryStatus)
                                    .font(Theme.caption)
                                    .foregroundStyle(Theme.secondary)
                                    .lineLimit(1)
                            }
                        }
                        if model.secondaryBackupName != nil {
                            Button("Entfernen") { model.removeSecondaryBackupLocation() }
                                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        }
                        Button("Wählen…") { model.chooseSecondaryBackupLocation() }
                            .buttonStyle(PlainActionButtonStyle())
                    }
                }
                SettingsLink("Verschlüsselte Sicherung exportieren…") { model.request(.backupExport) }
                SettingsLink("Sicherung einspielen…") { model.request(.backupImport) }
                // Befund #41: Sicherungen enthalten frühere Stände – hier lassen sie sich bewusst entfernen.
                SettingsLink("Ältere Sicherungen entfernen…") { model.settingsShow(.purgeOld) }
                SettingsLink("Tresor im Finder zeigen", symbol: "folder") { model.revealVaultInFinder() }
            }

            SettingsSection("Import und Export") {
                SettingsLink("CSV importieren…") { model.request(.csvImport) }
                if model.policy.allowCSVExport {
                    SettingsLink("CSV exportieren…") { model.request(.csvExport) }
                } else {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text("CSV exportieren")
                                .font(Theme.body)
                                .foregroundStyle(Theme.secondary)
                            Spacer()
                            Image(systemName: "lock")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(Theme.secondary)
                        }
                        Text("In Stufe \(model.level.title) gesperrt – eine Klartext-Datei würde alle Faktoren umgehen.")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                    }
                    .padding(.vertical, 12)
                }
                if model.policy.allowKeePassExport {
                    SettingsLink("KeePass exportieren (verschlüsselt)…") { model.request(.keepassExport) }
                } else {
                    lockedLine("KeePass exportieren",
                               "In Stufe \(model.level.title) gesperrt – das Export-Passwort allein würde alle Faktoren umgehen.")
                }
            }

            SettingsSection("Automatisches Ausfüllen") {
                Button {
                    model.settingsShow(.autofill)
                } label: {
                    HStack(spacing: 14) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Vorbereitet, nicht aktiv")
                                .font(Theme.body)
                            Text("Braucht ein bezahltes Apple-Entwicklerkonto · mit dem System ungetestet")
                                .font(Theme.caption)
                                .foregroundStyle(Theme.secondary)
                        }
                        Spacer(minLength: 8)
                        Text("Mehr…")
                            .font(Theme.body)
                        Image(systemName: "chevron.right")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Theme.secondary)
                    }
                    .padding(.vertical, 12)
                    .contentShape(Rectangle())
                }
                .buttonStyle(PlainActionButtonStyle())
            }

            SettingsSection("Sicherheit") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(SecurityTexts.summary)
                    Text(SecurityTexts.quantum)
                    Text(SecurityTexts.factors)
                }
                .font(Theme.caption)
                .foregroundStyle(Theme.text)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.vertical, 14)
                if state.fileVaultEncrypted == false {
                    FileVaultHint().padding(.bottom, 14)
                } else {
                    SettingsRow("FileVault") {
                        Text(state.fileVaultEncrypted == true ? "An" : "Unbekannt")
                            .font(Theme.body)
                            .foregroundStyle(Theme.secondary)
                    }
                }
            }

            SettingsSection("Info") {
                SettingsRow("Version") {
                    Text(LicenseTexts.version)
                        .font(Theme.body)
                        .foregroundStyle(Theme.secondary)
                }
                SettingsLink("Lizenzen…") { model.settingsShow(.licenses) }
            }
        }
    }

    /// Gesperrte Zeile (Stufe 4/5): Name grau mit Schloss, darunter der Grund.
    private func lockedLine(_ title: String, _ reason: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(title)
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                Spacer()
                Image(systemName: "lock")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Theme.secondary)
            }
            Text(reason)
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
        }
        .padding(.vertical, 12)
    }

    // MARK: Unterseiten

    private var changePassword: some View {
        SettingsForm(title: "Master-Passwort ändern",
                     text: "Siegel verschlüsselt danach alles neu. Dein Notfallcode bleibt gültig.") {
            FieldLabel("Bisheriges Master-Passwort") {
                MasterPasswordField("Bisheriges Master-Passwort", text: $state.currentPassword, autoFocus: true,
                                    enabled: !model.busy)
            }
            FieldLabel("Neues Master-Passwort") {
                MasterPasswordField("Neues Master-Passwort", text: $state.newPassword, enabled: !model.busy)
            }
            .padding(.top, 6)
            MasterPasswordField("Wiederholen", text: $state.newPasswordRepeat, enabled: !model.busy) {
                Task { await model.changeMasterPassword() }
            }
            let assessment = state.assessment
            StrengthMeter(bits: assessment.bits, level: assessment.level, meetsPolicy: assessment.meetsPolicy,
                          isEmpty: assessment.isEmpty)
                .padding(.top, 4)
            factorLine { Task { await model.changeMasterPassword() } }
            errorLine
            formButtons(primary: "Ändern", enabled: model.canChangeMasterPassword && !model.factorInProgress) {
                Task { await model.changeMasterPassword() }
            }
        }
    }

    private func kdfProfile(_ strong: Bool) -> some View {
        SettingsForm(title: strong ? "Schlüsselableitung: Stark" : "Schlüsselableitung: Standard",
                     text: strong
                        ? "Argon2id mit 2 GiB Arbeitsspeicher und 4 Durchgängen. Entsperren dauert etwa 3 s, Raten wird nochmals deutlich teurer."
                        : "Argon2id mit 1 GiB Arbeitsspeicher und 3 Durchgängen. Entsperren dauert etwa 1 s.") {
            MasterPasswordField("Master-Passwort bestätigen", text: $state.currentPassword, autoFocus: true,
                                enabled: !model.busy && !model.factorInProgress) {
                Task { await model.applyKDFProfile() }
            }
            factorLine { Task { await model.applyKDFProfile() } }
            errorLine
            formButtons(primary: "Umstellen", enabled: !state.currentPassword.isEmpty && !model.factorInProgress) {
                Task { await model.applyKDFProfile() }
            }
        }
    }

    /// „Nicht verbunden – letzte Sicherung dort: …“
    private var secondaryStatus: String {
        guard let letzte = model.settings.lastSecondaryBackupAt else { return "Nicht verbunden" }
        return "Nicht verbunden · letzte Sicherung dort am " + Anzeige.tag(letzte)
    }

    /// Notfallkit nicht bestätigt: das vorhandene Blatt prüfen (ganzer Code) oder ein neues Kit erstellen.
    private var unconfirmedKit: some View {
        SettingsForm(title: "Notfallkit bestätigen",
                     text: "Hast du den Code schon abgeschrieben oder gedruckt? Dann tippe ihn ganz ab – passt er, gilt das Blatt als bestätigt. Sonst erstellt Siegel ein neues Notfallkit.") {
            VStack(spacing: 0) {
                Hairline()
                SettingsLink("Vorhandenes Blatt prüfen…") { model.settingsShow(.checkCode) }
                Hairline()
                SettingsLink("Neues Notfallkit…") { model.settingsShow(.newKit) }
                Hairline()
            }
        }
    }

    @ViewBuilder
    private var checkCode: some View {
        if model.settingsUsesShares {
            checkShares
        } else {
            checkSingleCode
        }
    }

    /// Stufen 4/5 (§15): zwei der drei Teile prüfen bzw. als bestätigt markieren.
    private var checkShares: some View {
        let vollstaendig = state.shares.allSatisfy {
            RecoveryCodeFormatting.significant($0).count == RecoveryFlowView.shareCharacters
        }
        let korrigiert = (state.shareResult ?? []).enumerated().compactMap { index, ergebnis -> (Int, String, [Int])? in
            if case let .corrected(formatted, positions) = ergebnis { return (index, formatted, positions) }
            return nil
        }
        return SettingsForm(title: "Notfallcode prüfen",
                            text: model.recoveryConfirmed
                                ? "Dein Notfallcode ist in drei Teile geteilt. Tippe zwei Teile ab. Siegel prüft nur, ob sie zu diesem Tresor passen, und ändert nichts."
                                : "Dein Notfallcode ist in drei Teile geteilt. Tippe zwei ganze Teile ab. Passen sie zu diesem Tresor, kannst du die Blätter als bestätigt markieren.",
                            width: 560) {
            VStack(alignment: .leading, spacing: 14) {
                RecoveryCodeField("Erster Teil (12 Gruppen)", text: shareBinding(0), groups: 12, fontSize: 13,
                                  autoFocus: true) {
                    Task { await model.checkRecoverySharesInSettings() }
                }
                RecoveryCodeField("Zweiter Teil (12 Gruppen)", text: shareBinding(1), groups: 12, fontSize: 13) {
                    Task { await model.checkRecoverySharesInSettings() }
                }
            }
            .onChange(of: state.shares) { state.shareResult = nil }
            if state.shareResult != nil {
                if korrigiert.isEmpty {
                    MessageText("Diese Teile passen zu diesem Tresor.", symbol: "checkmark.circle")
                } else {
                    VStack(alignment: .leading, spacing: 14) {
                        MessageText("Passt – mit Korrekturen. Berichtige die markierten Stellen auf deinen Blättern.",
                                    symbol: "checkmark.circle")
                        ForEach(korrigiert, id: \.0) { index, formatted, positions in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(index == 0 ? "Erster Teil" : "Zweiter Teil")
                                    .font(Theme.caption.weight(.medium))
                                    .foregroundStyle(Theme.secondary)
                                SecretGate {
                                    CorrectedCodeView(formatted: formatted, changedPositions: positions, fontSize: 15,
                                                      alignment: .leading)
                                } placeholder: { reveal in
                                    HiddenSecretPlaceholder(reveal: reveal)
                                }
                            }
                        }
                    }
                }
            }
            errorLine
            if state.shareResult != nil, !model.recoveryConfirmed {
                VStack(spacing: 10) {
                    HStack(spacing: 12) {
                        Spacer()
                        Button("Abbrechen") { model.settingsBack() }
                            .buttonStyle(SecondaryButtonStyle())
                            .keyboardShortcut(.cancelAction)
                        Button(korrigiert.isEmpty ? "Blätter als bestätigt markieren" : "Blätter berichtigt – bestätigen") {
                            Task { await model.confirmExistingKitInSettings() }
                        }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(model.busy)
                        .keyboardShortcut(.defaultAction)
                    }
                    ProgressLine(active: model.busy)
                }
                .padding(.top, 8)
            } else {
                formButtons(primary: "Prüfen", enabled: vollstaendig) {
                    Task { await model.checkRecoverySharesInSettings() }
                }
            }
        }
    }

    private func shareBinding(_ index: Int) -> Binding<String> {
        Binding(get: { index < state.shares.count ? state.shares[index] : "" },
                set: { neu in if index < state.shares.count { state.shares[index] = neu } })
    }

    private var checkSingleCode: some View {
        SettingsForm(title: "Notfallcode prüfen",
                     text: model.recoveryConfirmed
                        ? "Tippe den Code von deinem Blatt ab. Siegel prüft nur, ob er zu diesem Tresor passt, und ändert nichts."
                        : "Tippe den ganzen Code von deinem Blatt ab. Passt er zu diesem Tresor, kannst du das Blatt als bestätigt markieren.",
                     width: 560) {
            // Befund #39: so breit wie die Spalte (vorher 600 pt, 40 pt über „Fertig“ hinaus).
            RecoveryCodeField("Code mit 11 Gruppen", text: $state.code, groups: 11, fontSize: 13, autoFocus: true) {
                Task { await model.checkRecoveryCodeInSettings() }
            }
            // Geänderter Code: altes Prüfergebnis gilt nicht mehr
            .onChange(of: state.code) { state.codeResult = nil }
            switch state.codeResult {
            case .exact:
                MessageText("Dieser Notfallcode passt zu diesem Tresor.", symbol: "checkmark.circle")
            case let .corrected(formatted, positions):
                VStack(alignment: .leading, spacing: 14) {
                    MessageText(positions.count == 1
                                ? "Passt – mit 1 Korrektur. Berichtige die markierte Stelle auf deinem Blatt."
                                : "Passt – mit \(positions.count) Korrekturen. Berichtige die markierten Stellen auf deinem Blatt.",
                                symbol: "checkmark.circle")
                    SecretGate {
                        CorrectedCodeView(formatted: formatted, changedPositions: positions, fontSize: 15,
                                          alignment: .leading)
                    } placeholder: { reveal in
                        HiddenSecretPlaceholder(reveal: reveal)
                    }
                }
            case nil:
                EmptyView()
            }
            errorLine
            if state.codeResult != nil, !model.recoveryConfirmed {
                VStack(spacing: 10) {
                    HStack(spacing: 12) {
                        Spacer()
                        Button("Abbrechen") { model.settingsBack() }
                            .buttonStyle(SecondaryButtonStyle())
                            .keyboardShortcut(.cancelAction)
                        Button(state.codeResult == .exact ? "Blatt als bestätigt markieren" : "Blatt berichtigt – bestätigen") {
                            Task { await model.confirmExistingKitInSettings() }
                        }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(model.busy)
                        .keyboardShortcut(.defaultAction)
                    }
                    ProgressLine(active: model.busy)
                }
                .padding(.top, 8)
            } else {
                formButtons(primary: "Prüfen", enabled: RecoveryCodeFormatting.significant(state.code).count == 55) {
                    Task { await model.checkRecoveryCodeInSettings() }
                }
            }
        }
    }

    private var newKit: some View {
        SettingsForm(title: "Neues Notfallkit",
                     text: model.level.recoveryScheme == .shamir2of3
                        ? "Siegel erzeugt einen neuen Code in drei Teilen. Die bisherigen Teile bleiben gültig, bis du die neuen bestätigt hast."
                        : (model.settingsUsesShares
                           ? "Siegel erzeugt einen einzelnen neuen Code. Deine bisherigen drei Teile bleiben gültig, bis du das neue Kit mit zwei Gruppen bestätigt hast."
                           : "Siegel erzeugt einen neuen Code. Der bisherige bleibt gültig, bis du das neue Kit mit zwei Gruppen bestätigt hast.")) {
            MasterPasswordField("Master-Passwort bestätigen", text: $state.currentPassword, autoFocus: true,
                                enabled: !model.busy && !model.factorInProgress) {
                Task { await model.prepareNewRecoveryKit() }
            }
            factorLine { Task { await model.prepareNewRecoveryKit() } }
            errorLine
            formButtons(primary: "Weiter", enabled: !state.currentPassword.isEmpty && !model.factorInProgress) {
                Task { await model.prepareNewRecoveryKit() }
            }
        }
    }

    /// Ab Stufe 2: welche Faktoren die Aktion zusätzlich braucht, und ihr Fortschritt.
    @ViewBuilder
    private func factorLine(retry: @escaping () -> Void) -> some View {
        if let collection = state.collection {
            CollectionProgress(collection: collection, onRetry: retry)
                .padding(.top, 2)
        } else if let factors = model.vaultHeader?.factors, !factors.isEmpty {
            FactorRequirementLine(factors: factors, prefix: "Danach nötig:")
                .padding(.top, 2)
        }
    }

    private func policyNote(_ text: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "shield")
                .font(.system(size: 10, weight: .medium))
            Text(text)
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.secondary)
        .padding(.bottom, 10)
    }

    private func purgeBackups(_ reason: PurgeReason) -> some View {
        SettingsForm(title: reason.title, text: reason.question) {
            Text("Siegel legt danach sofort eine neue Sicherung des aktuellen Stands an.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
            errorLine
            VStack(spacing: 10) {
                HStack(spacing: 12) {
                    Spacer()
                    Button("Behalten") { Task { await model.finishPurgeQuestion(remove: false) } }
                        .buttonStyle(SecondaryButtonStyle())
                    Button("Entfernen") { Task { await model.finishPurgeQuestion(remove: true) } }
                        .buttonStyle(PrimaryButtonStyle())
                }
                .disabled(model.busy || model.isSaving)
                ProgressLine(active: model.busy)
            }
            .padding(.top, 8)
        }
    }

    /// „Ältere Sicherungen entfernen…“ (Befund #41).
    private var purgeOld: some View {
        SettingsForm(title: "Ältere Sicherungen entfernen",
                     text: "Sicherungen enthalten frühere Stände – auch gelöschte Einträge und frühere Passwörter. Siegel entfernt alle Sicherungen dieses Tresors, auch am zweiten Sicherungsort, und legt sofort eine neue des aktuellen Stands an.") {
            HintBox(symbol: "exclamationmark.triangle") {
                Text("Danach lässt sich kein früherer Stand mehr zurückholen. Exportierte Sicherungen (z. B. auf einem USB-Stick) und Time Machine bleiben unberührt.")
            }
            MasterPasswordField("Master-Passwort bestätigen", text: $state.currentPassword, autoFocus: true,
                                enabled: !model.busy && !model.factorInProgress) {
                Task { await model.purgeOldBackups() }
            }
            .padding(.top, 4)
            factorLine { Task { await model.purgeOldBackups() } }
            errorLine
            formButtons(primary: "Entfernen", enabled: !state.currentPassword.isEmpty && !model.factorInProgress) {
                Task { await model.purgeOldBackups() }
            }
        }
    }

    @ViewBuilder
    private var errorLine: some View {
        if let error = state.error {
            MessageText(error).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func formButtons(primary: String, enabled: Bool, action: @escaping () -> Void) -> some View {
        VStack(spacing: 10) {
            HStack(spacing: 12) {
                Spacer()
                Button("Abbrechen") { model.settingsBack() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Button(primary, action: action)
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(!enabled || model.busy)
                    .keyboardShortcut(.defaultAction)
            }
            ProgressLine(active: model.busy)
        }
        .padding(.top, 8)
    }
}

// MARK: - Bausteine der Einstellungen

/// Abschnitt mit Titel und Zeilen, getrennt durch Haarlinien.
struct SettingsSection<Content: View>: View {
    var title: String
    var content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title)
                .font(Theme.label)
                .foregroundStyle(Theme.secondary)
                .textCase(.uppercase)
                .kerning(0.6)
                .padding(.bottom, 8)
            Hairline()
            Group(subviews: content) { subviews in
                ForEach(subviews) { subview in
                    subview
                    if subview.id != subviews.last?.id {
                        Hairline()
                    }
                }
            }
            Hairline()
        }
    }
}

/// Zeile „Bezeichnung … Steuerelement“.
struct SettingsRow<Accessory: View>: View {
    var title: String
    var accessory: Accessory

    init(_ title: String, @ViewBuilder accessory: () -> Accessory) {
        self.title = title
        self.accessory = accessory()
    }

    var body: some View {
        HStack(spacing: 16) {
            Text(title)
                .font(Theme.body)
            Spacer(minLength: 12)
            accessory
        }
        .frame(minHeight: 46)
    }
}

/// Zeile, die eine Unterseite oder Aktion öffnet.
struct SettingsLink: View {
    var title: String
    var symbol: String?
    var action: () -> Void

    init(_ title: String, symbol: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.symbol = symbol
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                if let symbol {
                    Image(systemName: symbol)
                        .font(.system(size: 13))
                        .frame(width: 16)
                }
                Text(title)
                    .font(Theme.body)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.secondary)
            }
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(PlainActionButtonStyle())
    }
}

/// Formular einer Unterseite: Titel, Erklärung, Felder.
struct SettingsForm<Content: View>: View {
    var title: String
    var text: String
    var width: CGFloat = 400
    var content: Content

    init(title: String, text: String, width: CGFloat = 400, @ViewBuilder content: () -> Content) {
        self.title = title
        self.text = text
        self.width = width
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(Theme.title)
            Text(text)
                .font(Theme.body)
                .foregroundStyle(Theme.secondary)
                .lineSpacing(2)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.bottom, 14)
            content
        }
        .frame(width: width, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Kurze Erklärung der Verfahren (Einstellungen → Sicherheit).
enum SecurityTexts {
    // Befund #37: Mit zweitem Sicherungsort liegen verschlüsselte Kopien auch dort; „aus 256 werden 128 Bit“.
    static let summary = "Siegel arbeitet ohne Server und ohne Netzwerk. Der Tresor liegt auf diesem Mac – und, falls du einen zweiten Sicherungsort gewählt hast (z. B. iCloud Drive oder einen USB-Stick), als verschlüsselte Kopie auch dort. Verschlüsselt ist er mit XChaCha20-Poly1305 und einem 256-Bit-Schlüssel. Das Master-Passwort wird mit Argon2id und viel Arbeitsspeicher gestreckt, damit Raten teuer wird."
    static let quantum = "Der Notfallschlüssel ist hybrid: ML-KEM-1024 und X25519. Er hält, solange auch nur eines der beiden Verfahren hält. Ein künftiger Quantenrechner halbiert die wirksame Stärke symmetrischer Schlüssel höchstens: Aus 256 Bit werden 128 Bit – weiterhin ausser Reichweite."
    static let factors = "Touch ID, Schlüsselkarte und Sicherheitsschlüssel gehen in den Schlüssel ein – ohne sie entsteht ein falscher Schlüssel, keine Tür in der Oberfläche. Touch ID nutzt die Secure Enclave (P-256, klassisch); Karte und Sicherheitsschlüssel schützen Einträge zusätzlich hybrid gegen Quantenrechner."
}

/// Kleine Beschriftung über einem Feld (bei mehreren Passwortfeldern, deren Platzhalter verschwinden).
struct FieldLabel<Content: View>: View {
    var title: String
    var content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(Theme.caption.weight(.medium))
                .foregroundStyle(Theme.secondary)
            content
        }
    }
}
