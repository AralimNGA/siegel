import AppKit
import SiegelCore
import SwiftUI

// Selbstvernichtung (SPEC v4.3 §23): Totmann-Schalter, Fehlversuch-Zähler, Vernichtungs-Passwort.
//
// - Prüfen: `checkDeadman` beim Start (vor dem Kopf des Sperrbildschirms), vor jedem Entsperren, beim Aktivieren der
//   App, nach dem Ruhezustand und alle 10 Minuten – auch gesperrt. Vernichtet er während einer offenen Sitzung,
//   wird gesperrt.
// - Anzeigen: Sperrbildschirm (Frist ab 25 % Restzeit, Zähler-Warnung ab N/2), Banner nach einer Vernichtung (nur
//   in echter Sitzung), Markierung „vernichtbar“ im Detail.
// - Vernichtungs-Sitzung: Die Oberfläche bekommt sie als gewöhnliches `.unlocked` und verhält sich genau gleich
//   (gleiche Faktor-Abfragen vorher, kein Banner, keine Hinweise); der Kern blendet die vernichteten Einträge aus.

extension AppModel {
    // MARK: Zustand lesen

    /// Nach jedem `refreshSnapshot`: markierte und vernichtete Einträge, Art der Sitzung.
    func readDestructionSession(_ vault: UnlockedVault) {
        let duress = vault.isDuressSession
        let vernichtet = duress ? [] : vault.destroyedEntries
        isDuressSession = duress
        destructibleEntries = duress ? [] : DestructionAccess.destructible(vault)
        destroyedEntries = vernichtet
        // Aus dem Inhalt (in beiden Sitzungsarten gleich): Auslöser, Markierungen oder ein Schlüssel V.
        destructionConfigured = vault.destructionSettings.anyTriggerEnabled || !destructibleEntries.isEmpty
            || vault.destructionKeyID != nil || !vernichtet.isEmpty
    }

    /// §23.1: Der Kern vernichtet V über diese Schicht (SiegelHardware `SecureEnclaveFactor.destroy`, in den
    /// Snapshots die Attrappe der Hardware). Bleibt die Datei liegen, löscht der Kern sie selbst.
    func wireDestructionKeyEraser() {
        guard let store else { return }
        let hw = hardware
        store.destructionKeyEraser = ClosureDestructionKeyEraser { keyID, directory in
            try hw.destroySecureEnclaveKey(keyID: keyID, directory: directory)
        }
    }

    /// Zustand neu lesen (im Hintergrund; ältere Ergebnisse werden verworfen).
    func reloadDestructionStatus() {
        Task { @MainActor [weak self] in await self?.refreshDestructionStatus() }
    }

    /// Offener Tresor: Stand passend zur Sitzung (`UnlockedVault.destructionStatus` verrät in einer
    /// Vernichtungs-Sitzung nichts); gesperrt: Kopie im Container (`VaultStore.destructionStatus()`).
    private var destructionStatusSource: @Sendable () -> DestructionStatus {
        let store = store
        let offen = vault.flatMap { $0.isLocked ? nil : $0 }
        return {
            if let offen, !offen.isLocked { return offen.destructionStatus }
            return store?.destructionStatus() ?? .off
        }
    }

    /// Wie `reloadDestructionStatus`, wartet aber auf das Ergebnis.
    public func refreshDestructionStatus() async {
        guard store != nil else { return }
        destructionLoads += 1
        let nummer = destructionLoads
        let lesen = destructionStatusSource
        let result = await Self.background { lesen() }
        guard destructionLoads == nummer, case let .success(status) = result else { return }
        destruction = status
    }

    /// Totmann-Schalter prüfen (§23.2). true = eben vernichtet.
    @discardableResult
    func checkDeadmanNow() async -> Bool {
        guard let store, store.vaultExists else { return false }
        let lesen = destructionStatusSource
        let result = await Self.background { () -> (Bool, DestructionStatus) in
            let vernichtet = (try? store.checkDeadman(now: Date())) ?? false
            return (vernichtet, lesen())
        }
        guard case let .success((vernichtet, status)) = result else { return false }
        destructionLoads += 1
        destruction = status
        return vernichtet
    }

    /// Start, Aktivieren, Aufwachen, alle 10 Minuten. Vernichtet der Schalter während einer offenen Sitzung, wird
    /// gesperrt: Aufgedeckte Geheimteile vernichteter Einträge verschwinden so aus dem Speicher.
    public func deadmanTick() async {
        let vernichtet = await checkDeadmanNow()
        guard vernichtet, holdsOpenVault else { return }
        lock(reason: .deadman)
        // Sperren verwirft den Stand der Sitzung (Befund ablaeufe-3): für den Sperrbildschirm neu aus `zustand.json`.
        await refreshDestructionStatus()
    }

    /// Einmal aus `startPlatformServices`: 10-Minuten-Takt (läuft auch gesperrt), Aktivieren, Aufwachen.
    func startDeadmanChecks() {
        guard deadmanTimer == nil else { return }
        let takt = Timer(timeInterval: 600, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.deadmanTick() }
            }
        }
        takt.tolerance = 30
        RunLoop.main.add(takt, forMode: .common)
        deadmanTimer = takt
        let app = NotificationCenter.default
        secondaryObserve(app, NSApplication.didBecomeActiveNotification)
        secondaryObserve(NSWorkspace.shared.notificationCenter, NSWorkspace.didWakeNotification)
    }

    private func secondaryObserve(_ center: NotificationCenter, _ name: Notification.Name) {
        keepObserver(center, center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.deadmanTick() }
            }
        })
    }

    // MARK: Anzeigen

    /// Sperrbildschirm: „Frist endet am …“ (ab 25 % Restzeit, dezent).
    public var lockDeadline: Date? { DestructionRules.showsDeadline(destruction, now: Date()) }

    /// Sperrbildschirm: „Noch x Versuche bis zur Vernichtung“ (ab N/2).
    public var lockRemainingAttempts: Int? { DestructionRules.remainingAttempts(destruction) }

    /// Banner „n Einträge wurden vernichtet (Auslöser, Datum)“ – nur in echter Sitzung (§23.2).
    public var destructionBanner: DestructionBanner? {
        guard isUnlocked, !isDuressSession, let status = destruction, let datum = status.destroyedAt else { return nil }
        return DestructionBanner(title: DestructionTexts.destroyedTitle(destroyedEntries.count),
                                 trigger: DestructionTexts.trigger(status.destroyedTrigger), date: Anzeige.tag(datum))
    }

    /// Selbstvernichtung in den Einstellungen anbieten (§23.3: nur Stufe 4/5).
    public var offersDestruction: Bool { level >= .maximal }

    /// Stufe unter 4, solange die Selbstvernichtung eingerichtet ist: Der Kern lehnt das ab (`notAllowedAtLevel`),
    /// die Oberfläche sagt es vor dem Assistenten.
    public func blocksLevelChange(to target: SecurityLevel) -> Bool {
        target < .maximal && destructionConfigured
    }

    public func isDestroyed(_ entry: VaultEntry) -> Bool { destroyedEntries.contains(entry.id) }
    public func isDestructible(_ entry: VaultEntry) -> Bool { destructibleEntries.contains(entry.id) }

    /// Einträge, die sich markieren lassen (Schutz 4/5, nicht vernichtet), in Listenreihenfolge.
    public var selectableDestructionEntries: [VaultEntry] {
        visibleEntriesSorted.filter { DestructionRules.isSelectable($0) && !destroyedEntries.contains($0.id) }
    }

    /// Einträge mit tieferem Schutz (nur ihre Anzahl wird genannt).
    public var unselectableDestructionCount: Int {
        entries.filter { !DestructionRules.isSelectable($0) }.count
    }

    private var visibleEntriesSorted: [VaultEntry] {
        entries.sorted { Self.listTitle($0).localizedStandardCompare(Self.listTitle($1)) == .orderedAscending }
    }

    // MARK: Banner

    /// „Entfernen“ im Banner: vernichtete (unlesbare) Einträge und den Vermerk entfernen.
    public func removeDestroyedEntriesNow() async {
        guard isUnlocked, !isDuressSession, !busy, destructionBanner != nil else { return }
        let start = epoch
        let fehler = await perform { try $0.removeDestroyedEntries() }
        guard start == epoch else { return }
        await refreshDestructionStatus()
        if let fehler {
            show(Notice(Fehlertexte.text(fehler), symbol: "exclamationmark.circle"), seconds: 6)
        } else {
            if let auswahl = browser.selection, !entries.contains(where: { $0.id == auswahl }) {
                select(entries.first?.id)
            }
            // Offene Seite der Einstellungen: Entwurf auf den neuen Stand (kein Vermerk, V muss neu angelegt werden).
            if let offen = destructionState, offen.step == .edit {
                offen.wipe()
                destructionState = savedDestructionState()
            }
            // Der Kern schaltet die Selbstvernichtung danach aus (V ist verbraucht).
            show(Notice("Vernichtete Einträge entfernt – die Selbstvernichtung ist aus"), seconds: 5)
        }
    }

    // MARK: Einstellungen

    /// Einstellungen → Sicherheitsstufe → „Selbstvernichtung“.
    public func showDestruction() async {
        guard isUnlocked, offersDestruction, browser.mode != .edit else { return }
        let start = epoch
        await refreshDestructionStatus()
        guard start == epoch, isUnlocked else { return }
        if !showsSettings { openSettings() }
        settingsShow(.destruction)
        destructionState?.wipe()
        destructionState = savedDestructionState()
    }

    /// Entwurf auf dem gespeicherten Stand des geöffneten Tresors (nach `refreshSnapshot` und
    /// `refreshDestructionStatus`).
    func savedDestructionState() -> DestructionState {
        DestructionState(status: destruction, destructible: destructibleEntries,
                         destroyed: !isDuressSession && destruction?.destroyedAt != nil,
                         keyAvailable: vault?.destructionKeyID != nil)
    }

    /// Entwurf verwerfen (Seite verlassen, Einstellungen schliessen, Sperren).
    func discardDestructionDraft() {
        destructionState?.wipe()
        destructionState = nil
    }

    public func destructionToggle(_ entry: VaultEntry) {
        guard let state = destructionState, state.step == .edit, DestructionRules.isSelectable(entry) else { return }
        if state.selection.contains(entry.id) {
            state.selection.remove(entry.id)
        } else {
            state.selection.insert(entry.id)
        }
        state.error = nil
    }

    public func destructionStartDuressEditing() {
        guard let state = destructionState, state.step == .edit else { return }
        state.duressOn = true
        state.duressEditing = true
        state.error = nil
    }

    public func destructionCancelDuressEditing() {
        destructionState?.cancelDuressEditing()
    }

    public func destructionRemoveDuress() {
        guard let state = destructionState, state.step == .edit else { return }
        state.cancelDuressEditing()
        state.duressOn = false
    }

    public func destructionTurnEverythingOff() {
        guard let state = destructionState, state.step == .edit else { return }
        state.turnEverythingOff()
        state.error = nil
    }

    /// Entwurf auf den gespeicherten Stand zurücksetzen.
    public func destructionRevert() {
        guard let state = destructionState else { return }
        state.wipe()
        destructionState = savedDestructionState()
    }

    /// „Weiter…“: Entwurf prüfen, dann Bestätigung.
    public func destructionContinue() {
        guard let state = destructionState, state.step == .edit, state.hasChanges else { return }
        if state.duressOn, state.duressEditing {
            guard state.duressAssessment.meetsPolicy else {
                state.error = Fehlertexte.text(.passwordTooWeak(bits: state.duressAssessment.bits))
                return
            }
            guard state.duressRepeatMatches else {
                state.error = "Die Wiederholung des Vernichtungs-Passworts stimmt nicht."
                return
            }
        }
        state.error = nil
        state.resetConfirmation()
        state.step = .confirm
    }

    public func destructionBack() {
        guard let state = destructionState, !busy, !factorInProgress else { return }
        state.resetConfirmation()
        state.step = .edit
    }

    /// Sichern: VERNICHTEN (beim Einschalten), Master-Passwort und alle Faktoren der Stufe, bei Bedarf ein neuer
    /// Vernichtungs-Schlüssel (Touch ID), dann `configureDestruction`.
    public func destructionApply() async {
        guard let vault, let state = destructionState, state.step == .confirm, !busy, !factorInProgress
        else { return }
        let master = state.masterPassword
        guard !master.isEmpty else { return }
        if state.arms, !state.confirmWordMatches {
            state.error = DestructionTexts.confirmWordWrong
            return
        }
        let neuesPasswort = state.newDuressPassword
        if let neu = neuesPasswort, VaultStore.passwordsMatch(neu, master) {
            state.masterPassword = ""
            state.error = DestructionTexts.duressEqualsMaster
            return
        }
        state.error = nil
        let start = epoch
        // Jede Änderung verlangt Master-Passwort und alle Faktoren der Stufe (§23.3).
        guard let factors = await vaultFactors(existing: state.collection, assign: { state.collection = $0 },
                                               reason: "Selbstvernichtung ändern"),
              start == epoch, destructionState === state else { return }

        // Neuer Vernichtungs-Schlüssel V (§23.1): erst das Passwort prüfen, dann Touch ID – sonst entstünde bei
        // einem Tippfehler ein Schlüssel umsonst.
        var neuerSchluessel: EntryKeyEnrollment?
        if state.needsNewKey {
            guard let geprueft = await heavy({ vault.verify(masterPassword: master, factors: factors) }),
                  start == epoch, destructionState === state else { return }
            guard case .success(true) = geprueft else {
                state.collection?.reset()
                state.masterPassword = ""
                state.error = wrongPasswordText
                return
            }
            guard let directory = hardwareDirectory, hardware.secureEnclaveAvailable else {
                state.error = "Dieser Mac hat kein nutzbares Touch ID. Für die Selbstvernichtung braucht es Touch ID mit eingerichtetem Fingerabdruck."
                return
            }
            let hw = hardware
            state.creatingKey = true
            do {
                neuerSchluessel = try await factorOperation(touchID: true) { try hw.enrollEntryKey(directory: directory) }
            } catch {
                state.creatingKey = false
                guard start == epoch, destructionState === state else { return }
                state.error = DestructionTexts.error(error as? SiegelError ?? .factorCancelled,
                                                     wrongPassword: wrongPasswordText)
                return
            }
            state.creatingKey = false
            guard start == epoch, destructionState === state else {
                if let v = neuerSchluessel { discardDestructionKey(v.keyID) }
                return
            }
        }

        let settings = DestructionSettings(deadmanDays: state.deadmanValue, maxFailedAttempts: state.attemptsValue,
                                           duressEnabled: state.duressOn)
        let auswahl = state.selection
        let vKey = neuerSchluessel
        let eingeschaltet = state.arms
        let vaultID = vault.vaultID
        // Stand vor dem Schreiben: Ein neues V darf nach einem Fehler nur weg, solange die Datei noch genau so ist.
        let generationVorher = vault.generation
        // Neu markierte bzw. entmarkierte Einträge versiegelt der Kern neu: Er prüft zuerst Passwort und Faktoren und
        // holt dann über den Provider die Freigaben (eine je Notfall-Gruppe, beim Entmarkieren Touch ID je Eintrag).
        let provider = UIEntryFactorProvider(model: self)
        guard let result = await heavyAsync(writes: true, {
            try await vault.configureDestruction(settings, duressPassword: neuesPasswort, destructible: auswahl,
                                                 masterPassword: master, factors: factors, vKey: vKey,
                                                 entryFactors: provider)
        }, whenDiscarded: { [weak self] result in
            switch result {
            case let .success(report):
                // Gesperrt, während geschrieben wurde: ein nicht vollständiges Entfernen alter Sicherungen merken.
                if let report { self?.notePurgeReport(report, vaultID: vaultID) }
            case .failure:
                // Befund datei-1: Hier V nie vernichten. Inzwischen gesperrt, ist offen, ob die Datei V schon nennt;
                // eine verwaiste V-Datei ist harmlos, ein fehlendes V mit Einträgen daran wäre Datenverlust.
                break
            }
        }) else { return }
        state.collection?.reset()
        switch result {
        case let .success(report):
            refreshSnapshot()
            await refreshDestructionStatus()
            // Neu markiert: Der Kern hat die älteren Sicherungen entfernt (sie enthielten die Einträge noch mit
            // Notfallweg). Was am zweiten Ort nicht erreichbar war, wird nachgeholt.
            if let report { notePurgeReport(report, vaultID: vaultID) }
            guard start == epoch, destructionState === state else { return }
            clearPastedMasterPassword()
            state.wipe()
            destructionState = savedDestructionState()
            if let report, !report.isComplete {
                show(purgeNotice(report), seconds: 10)
            } else {
                let text = eingeschaltet ? "Selbstvernichtung eingeschaltet" : "Selbstvernichtung gespeichert"
                show(Notice(report == nil ? text : text + " – ältere Sicherungen entfernt"), seconds: 5)
            }
        case let .failure(error):
            // Nur vernichten, wenn der Kern bestätigt, dass weder Datei noch Zustand V nennen (Befund datei-1).
            if let v = vKey { discardUnusedDestructionKey(v.keyID, vaultID: vaultID, generation: generationVorher) }
            if error == .wrongPassword { state.masterPassword = "" }
            state.error = DestructionTexts.error(error, wrongPassword: wrongPasswordText)
        }
    }

    /// Nicht übernommenen Vernichtungs-Schlüssel vernichten (überschreiben + löschen, §23.1). Nur für einen V, den
    /// `configureDestruction` nie gesehen hat (z. B. inzwischen gesperrt, bevor geschrieben wurde).
    func discardDestructionKey(_ keyID: UUID) {
        guard let directory = hardwareDirectory else { return }
        let hw = hardware
        Task.detached(priority: .utility) { try? hw.destroySecureEnclaveKey(keyID: keyID, directory: directory) }
    }

    /// Nach einem gescheiterten `configureDestruction`: V nur vernichten, wenn feststeht, dass weder `zustand.json`
    /// noch die Tresordatei ihn nennen (Datei noch auf dem Stand `generation`). Im Zweifel bleibt die V-Datei liegen
    /// (Befund datei-1).
    func discardUnusedDestructionKey(_ keyID: UUID, vaultID: UUID, generation: UInt64) {
        guard let directory = hardwareDirectory, let store else { return }
        let hw = hardware
        Task.detached(priority: .utility) {
            guard store.destructionKeyIsUnused(keyID, vaultID: vaultID, generation: generation) else { return }
            try? hw.destroySecureEnclaveKey(keyID: keyID, directory: directory)
        }
    }
}
