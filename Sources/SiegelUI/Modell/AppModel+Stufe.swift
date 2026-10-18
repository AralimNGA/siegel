import AppKit
import SiegelCore
import SwiftUI

// Sicherheitsstufe wechseln (SPEC v4 §13) und Faktoren für Einträge einrichten (§16): ein Assistent in den
// Einstellungen. Ablauf: Vergleich → Master-Passwort + aktuelle Faktoren (verify) → neue Faktoren einrichten
// (Touch ID, Karte drucken + scannen, Schlüssel registrieren) → ggf. Notfallkit in neuer Form → Schreiben.
// Erst `changeSecurityLevel` bzw. `enrollFactors` schreibt; bis dahin bleibt alles beim Alten.

extension AppModel {
    // MARK: Einstieg

    public func showSecurityLevels() {
        guard isUnlocked else { return }
        if !showsSettings { openSettings() }
        settingsShow(.securityLevel)
        settingsState.chosenLevel = nil
    }

    /// Assistent für den Wechsel auf `target` starten.
    public func startLevelChange(to target: SecurityLevel) {
        guard isUnlocked, !busy, target != level, !blocksLevelChange(to: target), let header = vaultHeader else { return }
        wizard?.wipe()
        wizard = SecurityWizardState(mode: .changeLevel(target), from: level, header: header, enrolled: enrolledFactors)
        settingsShow(.wizard)
    }

    /// Faktoren für Einträge einrichten (fehlt für einen Schutz, §16). `fromEditor`: danach zurück in die
    /// Bearbeitung des Eintrags (der Entwurf bleibt stehen).
    public func startEnroll(_ kinds: FactorSet, fromEditor: Bool = false) {
        guard isUnlocked, !busy, let header = vaultHeader else { return }
        let fehlend = kinds.subtracting(enrolledFactors)
        guard !fehlend.isEmpty else { return }
        wizard?.wipe()
        let state = SecurityWizardState(mode: .enroll(fehlend), from: level, header: header, enrolled: enrolledFactors)
        state.returnsToEditor = fromEditor
        // Befund ablaeufe-7: `openSettings()` öffnet während einer Bearbeitung bewusst nichts (Befund #36) – aus der
        // Bearbeitung also direkt zeigen, sonst läge der Assistent unsichtbar im Modell.
        if !showsSettings { fromEditor ? presentSettings() : openSettings() }
        guard showsSettings else {
            state.wipe()
            wizard = nil
            return
        }
        wizard = state
        settingsShow(.wizard)
    }

    /// Abbrechen: nichts geschrieben. Schon angelegte Secure-Enclave-Schlüssel wieder entfernen.
    public func wizardCancel() {
        guard let wizard, !busy, !isSaving else { return }
        if !wizard.applied { removeUnusedKeys(wizard) }
        let zurueck = wizard.returnsToEditor
        wizard.wipe()
        self.wizard = nil
        if kit?.origin == .levelChange { kit = nil }
        if zurueck {
            closeSettings()
        } else {
            settingsShow(.securityLevel)
        }
    }

    func removeUnusedKeys(_ wizard: SecurityWizardState) {
        guard let directory = hardwareDirectory else { return }
        let ids = [wizard.newSE?.keyID, wizard.newEntryKey?.keyID].compactMap { $0 }
        guard !ids.isEmpty else { return }
        let hw = hardware
        Task.detached(priority: .utility) {
            for id in ids { try? hw.removeSecureEnclaveKey(keyID: id, directory: directory) }
        }
    }

    public func wizardBack() {
        guard let wizard, !busy, !factorInProgress else { return }
        wizard.back()
    }

    /// Weiter (nach dem Vergleich bzw. nach einem erledigten Einrichtungs-Schritt).
    public func wizardAdvance() {
        guard let wizard, !busy else { return }
        wizard.next()
        prepareWizardStep(wizard)
    }

    private func prepareWizardStep(_ wizard: SecurityWizardState) {
        if wizard.step == .card, wizard.cardQ == nil {
            if wizard.enrolledAtStart.contains(.card) {
                // Dieselbe Karte dient Einträgen und dem Öffnen (§16): vorhandene Karte scannen.
                wizard.cardReuse = true
            } else {
                let q = CardCode.generate()
                wizard.cardQ = q
                wizard.cardText = CardCode.groupedText(for: q)
                wizard.cardPayload = CardCode.payload(for: q)
                wizard.cardImage = hardware.cardImage(payload: wizard.cardPayload, pixels: 600)
            }
        }
    }

    // MARK: Passwort und aktuelle Faktoren

    public func wizardVerify() async {
        guard let wizard, let vault, !busy, !factorInProgress else { return }
        let password = wizard.password
        guard !password.isEmpty else { return }
        wizard.error = nil
        let start = epoch
        if !wizard.collection.isEmpty {
            guard await collect(wizard.collection, reason: "Sicherheitsstufe ändern"), start == epoch,
                  self.wizard === wizard else { return }
        }
        let factors = wizard.collection.secrets
        guard let result = await heavy({ vault.verify(masterPassword: password, factors: factors) }),
              self.wizard === wizard else { return }
        if case .success(true) = result {
            wizard.verified = true
            wizardAdvance()
        } else {
            wizard.collection.reset()
            wizard.password = ""
            wizard.error = wrongPasswordText
        }
    }

    // MARK: Touch ID einrichten

    /// Entsperr-Schlüssel (Stufenwechsel) und Eintrags-Schlüssel (falls noch keiner) in der Secure Enclave anlegen.
    public func wizardSetupTouchID() async {
        guard let wizard, let directory = hardwareDirectory, !busy, !factorInProgress else { return }
        guard hardware.secureEnclaveAvailable else {
            wizard.error = "Dieser Mac hat kein nutzbares Touch ID (oder keine Fingerabdrücke eingerichtet). Richte Touch ID in den Systemeinstellungen ein."
            return
        }
        wizard.error = nil
        let hw = hardware
        let start = epoch
        do {
            if wizard.target != nil, wizard.newSE == nil {
                wizard.newSE = try await factorOperation(touchID: true) { try hw.enrollSecureEnclave(directory: directory) }
            }
            guard start == epoch, self.wizard === wizard else { return }
            if !wizard.enrolledAtStart.contains(.secureEnclave), wizard.newEntryKey == nil {
                wizard.newEntryKey = try await factorOperation(touchID: true) { try hw.enrollEntryKey(directory: directory) }
            }
            guard start == epoch, self.wizard === wizard else { return }
            wizard.touchIDDone = true
        } catch {
            guard start == epoch, self.wizard === wizard else { return }
            wizard.error = Fehlertexte.text(error as? SiegelError ?? .factorCancelled)
        }
    }

    // MARK: Karte

    public func wizardCardHandwritten() {
        guard let wizard else { return }
        wizard.cardMethod = .handwritten
        wizard.cardPrintWarning = false
        wizard.cardPrintNotPaper = false
    }

    /// „Karte drucken…“: Druckdialog ohne Vorschau, dann den gewählten Drucker prüfen (wie beim Notfallkit).
    public func wizardPrintCard() {
        guard let wizard, !busy, let q = wizard.cardQ else { return }
        wizard.cardPrintNotPaper = false
        let start = epoch
        guard let info = RecoveryKitPrinter.choosePrinter() else { return }
        guard start == epoch, self.wizard === wizard else { return }
        guard RecoveryKitPrinter.isPaper(info) else {
            wizard.cardPrintNotPaper = true
            return
        }
        switch RecoveryKitPrinter.check(info) {
        case .secure:
            runCardPrint(wizard, q: q, info: info)
        case .insecure:
            wizard.cardPrintInfo = info
            wizard.cardPrintWarningText = RecoveryKitPrinter.insecureWarning
            wizard.cardPrintWarning = true
        case .unknown:
            wizard.cardPrintInfo = info
            wizard.cardPrintWarningText = RecoveryKitPrinter.unknownWarning
            wizard.cardPrintWarning = true
        }
    }

    public func wizardPrintCardAnyway() {
        guard let wizard, let info = wizard.cardPrintInfo, let q = wizard.cardQ else { return }
        wizard.cardPrintWarning = false
        wizard.cardPrintInfo = nil
        runCardPrint(wizard, q: q, info: info)
    }

    public func wizardDismissCardWarning() {
        wizard?.cardPrintWarning = false
        wizard?.cardPrintInfo = nil
    }

    private func runCardPrint(_ wizard: SecurityWizardState, q: FactorSecret, info: NSPrintInfo) {
        let start = epoch
        let content = PrintSheetContent.card(groups: CardCode.groupedText(for: q).split(separator: "-").map(String.init),
                                             qr: wizard.cardImage ?? hardware.cardImage(payload: CardCode.payload(for: q), pixels: 600))
        let outcome = RecoveryKitPrinter.printSheet(content, info: info)
        guard start == epoch, self.wizard === wizard else { return }
        switch outcome {
        case .paper: wizard.cardMethod = .printed
        case .notPaper: wizard.cardPrintNotPaper = true
        case .cancelled: break
        }
    }

    /// Karte scannen: neue Karte zur Bestätigung bzw. die vorhandene (für Einträge eingerichtete) Karte.
    public func wizardScanCard(typing: Bool = false) async {
        guard let wizard, !busy, !factorInProgress else { return }
        wizard.error = nil
        let start = epoch
        do {
            let q: FactorSecret
            if wizard.cardReuse {
                q = try await scanCard(purpose: .vault(vaultID: wizard.header.vaultID, tag: wizard.header.cardTag),
                                       title: "Vorhandene Karte scannen",
                                       message: "Diese Karte schützt schon Einträge. Sie dient künftig auch zum Öffnen.")
            } else {
                // Befund design-4: Kopfzeile je Modus – von Hand abgeschrieben gibt es keine Karte mit QR-Code.
                q = try await scanCard(purpose: .confirmNew, title: "Karte bestätigen",
                                       message: "Halte die eben gedruckte Karte vor die Kamera – so ist sicher, dass sie lesbar ist.",
                                       typingMessage: typing
                                         ? "Tippe den Code ab, den du eben notiert hast – so ist sicher, dass er stimmt."
                                         : CardScanState.defaultTypingMessage,
                                       expected: wizard.cardQ, startTyping: typing)
            }
            guard start == epoch, self.wizard === wizard else { return }
            wizard.cardQ = q
            wizard.cardConfirmed = true
        } catch {
            guard start == epoch, self.wizard === wizard else { return }
            if (error as? SiegelError) != .factorCancelled {
                wizard.error = Fehlertexte.text(error as? SiegelError ?? .factorCancelled)
            }
        }
    }

    // MARK: Sicherheitsschlüssel

    /// Stufe 5 mit einem schon für Einträge eingerichteten Schlüssel: denselben Schlüssel berühren (Ausgabe zum
    /// Entsperr-Salz), statt neu zu registrieren. Der Kern prüft sie über den Prüfwert.
    public func wizardTouchExistingKey() async {
        guard let wizard, let vault, !busy, !factorInProgress, wizard.keyReuse else { return }
        guard let credential = vault.securityKeyCredential else {
            wizard.error = Fehlertexte.text(.factorMissing(.securityKey))
            return
        }
        wizard.error = nil
        let start = epoch
        do {
            let result = try await touchSecurityKey(purpose: .secret(credentialID: credential.credentialID,
                                                                     salt: credential.salt),
                                                    title: "Vorhandenen Sicherheitsschlüssel berühren",
                                                    message: "Stecke den Schlüssel ein, der deine Einträge schützt, und berühre ihn.")
            guard start == epoch, self.wizard === wizard, case let .secret(secret) = result else { return }
            wizard.keyReuseSecret = secret
            wizard.keyName = "vorhandener Schlüssel"
        } catch {
            guard start == epoch, self.wizard === wizard else { return }
            if (error as? SiegelError) != .factorCancelled {
                wizard.error = Fehlertexte.text(error as? SiegelError ?? .factorCancelled)
            }
        }
    }

    public func wizardRegisterKey() async {
        guard let wizard, !busy, !factorInProgress else { return }
        wizard.error = nil
        let start = epoch
        do {
            let result = try await touchSecurityKey(purpose: .register, title: "Sicherheitsschlüssel registrieren",
                                                    message: "Stecke deinen FIDO2-Schlüssel ein und berühre ihn, sobald er blinkt.")
            guard start == epoch, self.wizard === wizard, case let .enrollment(enrollment, name) = result else { return }
            wizard.keyEnrollment = enrollment
            wizard.keyName = name
        } catch {
            guard start == epoch, self.wizard === wizard else { return }
            if (error as? SiegelError) != .factorCancelled {
                wizard.error = Fehlertexte.text(error as? SiegelError ?? .factorCancelled)
            }
        }
    }

    // MARK: Notfallkit in neuer Form (ein Code ↔ drei Teile)

    /// Bereitet das Kit vor (nichts geschrieben) und zeigt den Notfallkit-Bildschirm.
    public func wizardShowRecoveryKit() async {
        guard let wizard, let vault, let target = wizard.target, !busy else { return }
        if let vorhanden = wizard.kit {
            kit = vorhanden
            go(.recoveryKit)
            return
        }
        let password = wizard.password
        let factors = wizard.collection.secrets
        let scheme = target.recoveryScheme
        wizard.error = nil
        guard let result = await heavy({
            try vault.prepareRecovery(masterPassword: password, factors: factors, scheme: scheme)
        }), self.wizard === wizard else { return }
        switch result {
        case let .success(pending):
            let state = KitState(pending: pending, origin: .levelChange)
            wizard.kit = state
            kit = state
            go(.recoveryKit)
        case let .failure(error):
            wizard.error = Fehlertexte.text(error)
        }
    }

    /// Vom Notfallkit-Bildschirm: Gruppen lokal geprüft, zurück in den Assistenten.
    func wizardRecoveryConfirmed(_ confirmation: [String]) {
        guard let wizard else { return }
        wizard.recoveryConfirmation = confirmation
        wizard.recoveryConfirmed = true
        kit = nil
        go(.unlocked)
        wizardAdvance()
    }

    // MARK: Schreiben

    public func wizardApply() async {
        guard let wizard, let vault, !busy, wizard.setupComplete else { return }
        let password = wizard.password
        let current = wizard.currentFactors
        let material = wizard.material
        let vaultID = vault.vaultID
        let altSE = wizard.header.seKeyID
        wizard.error = nil
        let result: Result<Void, SiegelError>?
        switch wizard.mode {
        case let .changeLevel(target):
            let pending = wizard.kit?.pending
            let confirmation = wizard.recoveryConfirmation
            // Neues Kit + versiegelte Einträge (§16): der Kern holt nach der Passwortprüfung je Notfall-Gruppe eine
            // Freigabe über den Provider (sonst ruft er ihn nicht).
            let provider = UIEntryFactorProvider(model: self)
            result = await heavyAsync(writes: true, {
                try await vault.changeSecurityLevel(to: target, masterPassword: password, currentFactors: current,
                                                    newFactors: material, recovery: pending,
                                                    recoveryConfirmation: confirmation, entryFactors: provider)
            }, whenDiscarded: { [weak self] result in
                // Gesperrt, während geschrieben wurde: Frage nach den alten Sicherungen nach dem Entsperren.
                if case .success = result {
                    self?.pendingPurgeQuestion = PendingPurgeQuestion(vaultID: vaultID, reason: .levelChange)
                }
            })
        case .enroll:
            result = await heavy(writes: true, {
                try vault.enrollFactors(material, masterPassword: password, currentFactors: current)
            })
        }
        guard let result, self.wizard === wizard else { return }
        switch result {
        case .success:
            refreshSnapshot()
            wizard.applied = true
            // Stufenwechsel geschrieben: die Frage nach den alten Sicherungen bleibt bis zur Antwort (Befund #34).
            if case .changeLevel = wizard.mode {
                pendingPurgeQuestion = PendingPurgeQuestion(vaultID: vaultID, reason: .levelChange)
            }
            // Abwärts: Entsperr-Schlüssel erst nach erfolgreichem Schreiben entfernen (§13).
            if let altSE, !(vaultHeader?.factors.contains(.secureEnclave) ?? false), let directory = hardwareDirectory {
                let hw = hardware
                Task.detached(priority: .utility) { try? hw.removeSecureEnclaveKey(keyID: altSE, directory: directory) }
            }
            wizard.wipe()
            wizard.step = .done
            clearPastedMasterPassword()
        case let .failure(error):
            if error == .wrongPassword {
                // Zurück zur Bestätigung: Passwort und Faktoren neu.
                wizard.collection.reset()
                wizard.password = ""
                wizard.verified = false
                wizard.step = .verify
                wizard.error = wrongPasswordText
            } else if error == .wrongCard, wizard.cardReuse {
                // Vorhandene Karte passt nicht: neu scannen lassen.
                wizard.cardConfirmed = false
                wizard.cardQ = nil
                wizard.step = .card
                wizard.error = Fehlertexte.text(error)
            } else if error == .factorCancelled || error == .factorUnavailable(.secureEnclave) {
                wizard.error = Fehlertexte.protectedEntriesRelease(error)
            } else {
                wizard.error = Fehlertexte.text(error)
            }
        }
    }

    /// Abschluss: alte Sicherungen entfernen oder behalten (nur nach einem Stufenwechsel).
    public func wizardFinish(removeOldBackups: Bool) async {
        guard let wizard, !busy, savesInFlight == 0 else { return }
        let start = epoch
        if removeOldBackups, let vaultID = vault?.vaultID {
            let result = await performReturning({ try $0.purgeBackups() })
            guard start == epoch else { return }
            switch result {
            case let .success(report):
                notePurgeReport(report, vaultID: vaultID)
                show(purgeNotice(report), seconds: report.isComplete ? 4 : 10)
            case let .failure(error):
                wizard.error = Fehlertexte.text(error)
                return
            }
        } else {
            switch wizard.mode {
            case .changeLevel: show(Notice("Sicherheitsstufe: " + level.title))
            case let .enroll(kinds): show(Notice("Eingerichtet: " + FactorUI.list(kinds, long: true)))
            }
        }
        if pendingPurgeQuestion?.reason == .levelChange { pendingPurgeQuestion = nil }
        let zurueck = wizard.returnsToEditor
        self.wizard = nil
        if zurueck {
            closeSettings()
        } else {
            settingsShow(.overview)
        }
    }
}
