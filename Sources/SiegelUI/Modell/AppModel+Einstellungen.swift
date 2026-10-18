import AppKit
import SiegelCore
import SwiftUI

// Einstellungen (SPEC §7.7): Seite im Hauptfenster, nur entsperrt bedienbar.

extension AppModel {
    public func openSettings() {
        // Befund #36: nicht während einer Bearbeitung (⌘, war der einzige offene Weg). Sonst könnte ein Sperren
        // während eines Passwortwechsels den Main-Thread über zwei Argon2-Läufe blockieren (Entwurf speichern wartet
        // auf den Schreib-Lock des Kerns).
        guard isUnlocked, browser.mode != .edit else { return }
        presentSettings()
    }

    /// Zeigt die Einstellungen ohne die Sperre aus Befund #36 – nur für „Jetzt einrichten…“ aus der Bearbeitung
    /// (Befund ablaeufe-7): Dort öffnet sich ausschliesslich der Assistent, der danach in die Bearbeitung zurückführt.
    /// Er schreibt mit einem einzigen Argon2 (`enrollFactors`); ein Sperren währenddessen wartet höchstens darauf.
    func presentSettings() {
        guard isUnlocked else { return }
        let state = SettingsState()
        if let dir = vaultDirectory { state.fileVaultEncrypted = FileVaultCheck.isEncrypted(dir) }
        settingsState = state
        withAnimation(.easeInOut(duration: 0.2)) { showsSettings = true }
    }

    public func closeSettings() {
        discardDestructionDraft()
        if let wizard {
            if !wizard.applied { removeUnusedKeys(wizard) }
            wizard.wipe()
            self.wizard = nil
        }
        settingsState = SettingsState()
        withAnimation(.easeInOut(duration: 0.2)) { showsSettings = false }
    }

    public func settingsShow(_ page: SettingsState.Page) {
        if page != .destruction { discardDestructionDraft() }
        settingsState.resetFields()
        settingsState.page = page
    }

    public func settingsBack() {
        discardDestructionDraft()
        settingsState.resetFields()
        settingsState.page = .overview
    }

    // MARK: Schlüsselableitung

    public var usesStrongProfile: Bool { kdf == .strong }

    /// Profilwechsel anfordern (fragt das Master-Passwort erneut ab).
    public func requestKDFProfile(strong: Bool) {
        guard strong != usesStrongProfile else { return }
        settingsShow(.kdfProfile(strong: strong))
    }

    /// Ab Stufe 3 legt die Sicherheitsstufe das Profil fest (Stark).
    public var kdfFixedByLevel: Bool { level.kdf == .strong && level >= .hoch }

    public func applyKDFProfile() async {
        guard let vault, !busy, case let .kdfProfile(strong) = settingsState.page else { return }
        let password = settingsState.currentPassword
        guard !password.isEmpty else { return }
        let target: KDFParameters = strong ? .strong : .standard
        settingsState.error = nil
        let state = settingsState
        guard let factors = await vaultFactors(existing: state.collection, assign: { state.collection = $0 },
                                               reason: "Profil umstellen"),
              settingsState === state else { return }
        guard let result = await heavy(writes: true, {
            try vault.changeMasterPassword(current: password, new: password, factors: factors, kdf: target)
        }) else { return }
        state.collection?.reset()
        switch result {
        case .success:
            refreshSnapshot()
            settingsBack()
            show(Notice(strong ? "Schlüsselableitung: Stark" : "Schlüsselableitung: Standard"))
            clearPastedMasterPassword()
        case let .failure(error):
            settingsState.currentPassword = ""
            settingsState.error = error == .wrongPassword ? wrongPasswordText : Fehlertexte.text(error)
        }
    }

    /// „Falsches Passwort“ bzw. ab Stufe 2 „Passwort oder ein Faktor stimmt nicht“ (§13.1).
    var wrongPasswordText: String {
        (vaultHeader?.factors.isEmpty ?? true) ? Fehlertexte.wrongPassword : Fehlertexte.wrongPasswordOrFactor
    }

    // MARK: Master-Passwort ändern

    public var canChangeMasterPassword: Bool {
        !settingsState.currentPassword.isEmpty && settingsState.assessment.meetsPolicy && settingsState.repeatMatches
    }

    public func changeMasterPassword() async {
        guard let vault, !busy, canChangeMasterPassword else { return }
        let current = settingsState.currentPassword
        let neu = settingsState.newPassword
        settingsState.error = nil
        let vaultID = vault.vaultID
        let state = settingsState
        guard let factors = await vaultFactors(existing: state.collection, assign: { state.collection = $0 },
                                               reason: "Master-Passwort ändern"),
              settingsState === state else { return }
        guard let result = await heavy(writes: true, {
            try vault.changeMasterPassword(current: current, new: neu, factors: factors)
        },
                                       whenDiscarded: { [weak self] result in
            // Gesperrt, während der Wechsel lief: Er ist geschrieben, die Frage nach den alten Sicherungen
            // kommt nach dem nächsten Entsperren (Befund #10).
            if case .success = result {
                self?.pendingPurgeQuestion = PendingPurgeQuestion(vaultID: vaultID, reason: .passwordChange)
            }
        }) else { return }
        state.collection?.reset()
        switch result {
        case .success:
            refreshSnapshot()
            settingsState.resetFields()
            // Bis zur Antwort gemerkt (Befund #34): Sperren oder Beenden lassen die Frage nicht verschwinden.
            pendingPurgeQuestion = PendingPurgeQuestion(vaultID: vaultID, reason: .passwordChange)
            settingsState.page = .purgeBackups(.passwordChange)
            clearPastedMasterPassword()
        case let .failure(error):
            if error == .wrongPassword { settingsState.currentPassword = "" }
            let falsch = (vaultHeader?.factors.isEmpty ?? true)
                ? "Das bisherige Master-Passwort stimmt nicht." : "Das bisherige Master-Passwort oder ein Faktor stimmt nicht."
            settingsState.error = error == .wrongPassword ? falsch : Fehlertexte.text(error)
        }
    }

    /// Nach einem Zugangswechsel: alte Sicherungen entfernen oder behalten (SPEC §4). „Entfernt“ wird nur
    /// gemeldet, wenn wirklich nichts übrig blieb (Befund #9); sonst eine Warnung, und das Entfernen am zweiten
    /// Ort wird nachgeholt, sobald er wieder verbunden ist.
    public func finishPurgeQuestion(remove: Bool) async {
        guard case let .purgeBackups(reason) = settingsState.page, !busy, savesInFlight == 0 else { return }
        if remove {
            guard let vaultID = vault?.vaultID else { return }
            let start = epoch
            busy = true
            let result = await performReturning({ try $0.purgeBackups() })
            guard start == epoch else { return }
            busy = false
            switch result {
            case let .success(report):
                notePurgeReport(report, vaultID: vaultID)
                show(purgeNotice(report), seconds: report.isComplete ? 4 : 10)
            case let .failure(error):
                settingsState.error = Fehlertexte.text(error)
                return
            }
        } else {
            show(Notice(reason.keptNotice))
        }
        pendingPurgeQuestion = nil
        settingsBack()
    }

    // MARK: Ältere Sicherungen entfernen (Befund #41)

    /// „Ältere Sicherungen entfernen…“: Master-Passwort (und Faktoren) prüfen, dann alle Sicherungen dieses Tresors
    /// entfernen (auch am zweiten Ort); der Kern legt sofort eine neue des aktuellen Stands an.
    public func purgeOldBackups() async {
        guard let vault, !busy, case .purgeOld = settingsState.page else { return }
        let password = settingsState.currentPassword
        guard !password.isEmpty else { return }
        settingsState.error = nil
        let state = settingsState
        guard let factors = await vaultFactors(existing: state.collection, assign: { state.collection = $0 },
                                               reason: "Sicherungen entfernen"),
              settingsState === state else { return }
        guard let geprueft = await heavy({ vault.verify(masterPassword: password, factors: factors) }),
              settingsState === state else { return }
        state.collection?.reset()
        guard case .success(true) = geprueft else {
            settingsState.currentPassword = ""
            settingsState.error = wrongPasswordText
            return
        }
        clearPastedMasterPassword()
        let vaultID = vault.vaultID
        let start = epoch
        busy = true
        let result = await performReturning({ try $0.purgeBackups() })
        if start == epoch { busy = false }
        guard start == epoch, settingsState === state else { return }
        switch result {
        case let .success(report):
            notePurgeReport(report, vaultID: vaultID)
            settingsBack()
            show(purgeNotice(report), seconds: report.isComplete ? 4 : 10)
        case let .failure(error):
            settingsState.error = Fehlertexte.text(error)
        }
    }

    // MARK: Notfallkit

    /// „Dieses Blatt als bestätigt markieren“ nach „Notfallcode prüfen…“ (Befund #16): Der ganze Code passt
    /// zum Tresor, also ist das vorhandene Blatt richtig – ohne neues Kit.
    public func confirmExistingKitInSettings() async {
        guard let vault, !busy else { return }
        let outcome: Result<Void, SiegelError>?
        if settingsUsesShares {
            // Zwei Teile (§15): die geprüften, ggf. korrigierten Teile.
            guard let results = settingsState.shareResult, results.count == settingsState.shares.count else { return }
            let teile = zip(settingsState.shares, results).map { eingabe, ergebnis -> String in
                if case let .corrected(formatted, _) = ergebnis { return formatted }
                return eingabe
            }
            settingsState.error = nil
            outcome = await heavy(writes: true, { try vault.confirmExistingRecovery(shares: teile) })
        } else {
            guard let result = settingsState.codeResult else { return }
            let code: String
            switch result {
            case .exact: code = settingsState.code
            case let .corrected(formatted, _): code = formatted
            }
            settingsState.error = nil
            outcome = await heavy(writes: true, { try vault.confirmExistingRecovery(code: code) })
        }
        guard let outcome else { return }
        switch outcome {
        case .success:
            refreshSnapshot()
            settingsState.resetFields()
            settingsState.page = .overview
            show(Notice("Notfallkit bestätigt"))
        case let .failure(error):
            settingsState.error = Fehlertexte.text(error)
        }
    }

    /// Ist der Notfallcode dieses Tresors in drei Teile geteilt (Kopf, §15)?
    public var settingsUsesShares: Bool { vaultHeader?.recoveryScheme == .shamir2of3 }

    /// „Notfallcode prüfen…“ mit zwei Teilen: nur lesen, nichts schreiben.
    public func checkRecoverySharesInSettings() async {
        guard let store, !busy else { return }
        let inputs = settingsState.shares
        guard inputs.allSatisfy({ !RecoveryCodeFormatting.significant($0).isEmpty }) else { return }
        settingsState.error = nil
        settingsState.shareResult = nil
        guard let result = await heavy({ try store.checkRecoveryShares(inputs) }) else { return }
        switch result {
        case let .success(matches):
            settingsState.shareResult = matches.map { match -> SettingsState.CodeCheckResult in
                switch match {
                case .exact: .exact
                case let .corrected(formatted, positions): .corrected(formatted: formatted, changedPositions: positions)
                }
            }
        case let .failure(error):
            settingsState.error = Self.shareErrorText(error, inputs: inputs)
        }
    }

    /// „Notfallcode prüfen…“: nur lesen, nichts schreiben.
    public func checkRecoveryCodeInSettings() async {
        guard let store, !busy else { return }
        let input = settingsState.code
        guard !input.isEmpty else { return }
        settingsState.error = nil
        settingsState.codeResult = nil
        guard let result = await heavy({ try store.checkRecoveryCode(input) }) else { return }
        switch result {
        case .success(.exact):
            settingsState.codeResult = .exact
        case let .success(.corrected(formatted, positions)):
            settingsState.codeResult = .corrected(formatted: formatted, changedPositions: positions)
        case let .failure(error):
            settingsState.error = Fehlertexte.recoveryCode(error, input: input)
        }
    }

    /// Zeile „Notfallkit nicht bestätigt – jetzt einrichten“: Auswahl zwischen „Vorhandenes Blatt prüfen“ und
    /// „Neues Notfallkit…“ (Befund #16: Ein schon abgeschriebenes Blatt lässt sich so noch bestätigen).
    public func startNewRecoveryKit() {
        guard isUnlocked, browser.mode != .edit else { return }
        if !showsSettings { openSettings() }
        settingsShow(recoveryConfirmed ? .newKit : .unconfirmedKit)
    }

    /// Master-Passwort geprüft → neues Kit vorbereiten (noch nichts geschrieben).
    public func prepareNewRecoveryKit() async {
        guard let vault, !busy else { return }
        let password = settingsState.currentPassword
        guard !password.isEmpty else { return }
        settingsState.error = nil
        let state = settingsState
        guard let factors = await vaultFactors(existing: state.collection, assign: { state.collection = $0 },
                                               reason: "Neues Notfallkit"),
              settingsState === state else { return }
        // Stufe 4/5: drei Teile (§15).
        let scheme = level.recoveryScheme
        guard let result = await heavy({
            try vault.prepareRecovery(masterPassword: password, factors: factors, scheme: scheme)
        }) else { return }
        state.collection?.reset()
        switch result {
        case let .success(pending):
            settingsState.resetFields()
            settingsState.page = .overview
            kit = KitState(pending: pending, origin: .newKit)
            go(.recoveryKit)
            clearPastedMasterPassword()
        case let .failure(error):
            settingsState.currentPassword = ""
            settingsState.error = error == .wrongPassword ? wrongPasswordText : Fehlertexte.text(error)
        }
    }

    // MARK: Sicherungen und Dateien

    /// „Zweiter Sicherungsort…“: Ordner wählen (security-scoped Bookmark).
    public func chooseSecondaryBackupLocation() {
        guard isUnlocked else { return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Wählen"
        panel.message = "Ordner für eine zweite Sicherung wählen, z. B. auf einem USB-Stick oder in iCloud Drive."
        WindowGuard.shared.protect(panel)
        let start = epoch
        let handler: (NSApplication.ModalResponse) -> Void = { [weak self, weak panel] response in
            MainActor.assumeIsolated {
                // Abschluss-Handler: bei inzwischen gesperrtem Tresor nichts tun.
                guard let self, start == self.epoch, self.isUnlocked else { return }
                guard response == .OK, let url = panel?.url else { return }
                self.setSecondaryBackupLocation(url)
            }
        }
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            panel.beginSheetModal(for: window, completionHandler: handler)
        } else {
            panel.begin(completionHandler: handler)
        }
    }

    public func removeSecondaryBackupLocation() {
        setSecondaryBackupLocation(nil)
    }

    public func revealVaultInFinder() {
        guard let url = store?.vaultURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    /// Einstiegspunkte für Stufe 2 (CSV-Import/-Export, Sicherung exportieren/einspielen).
    public func request(_ flow: PendingFlow) {
        // Befund #36: nicht während einer Bearbeitung.
        guard isUnlocked, !busy, browser.mode != .edit else { return }
        // Stufe 4/5: kein Klartext- und kein KeePass-Export (§13, §19).
        if flow == .csvExport, !policy.allowCSVExport { return }
        if flow == .keepassExport, !policy.allowKeePassExport { return }
        flowState = FlowState(flow)
        pendingFlow = flow
    }

    public func finishFlow() {
        flowState = nil
        pendingFlow = nil
    }
}
