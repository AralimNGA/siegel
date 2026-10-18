import AppKit
import CryptoKit
import SiegelCore
import SwiftUI
import UniformTypeIdentifiers

/// Ergebnis der Code-Prüfung im Notfallweg: Treffer und ob er über die Sicherungen kam.
struct RecoveryCheck: Sendable {
    let match: RecoveryCodeMatch
    let viaBackup: Bool
}

// Abläufe ausserhalb des entsperrten Tresors: Einrichtung, Entsperren, Notfallcode-Weg, Notfallkit,
// Tresor fehlt, Beschädigt, Rollback-Frage.

extension AppModel {
    // MARK: Einrichtung

    public func setSetupMode(_ mode: SetupState.Mode) {
        setup.mode = mode
        setup.error = nil
    }

    /// „Tresor anlegen“: erst, wenn die Regel erfüllt ist und beide Eingaben gleich sind.
    public func createVault() async {
        guard let store, setup.canCreate, !busy else { return }
        let password = setup.candidate
        setup.error = nil
        guard let result = await heavy(writes: true, { try store.create(masterPassword: password) }) else { return }
        switch result {
        case let .success((opened, pending)):
            vault = opened
            refreshSnapshot()
            autoLock?.vaultDidOpen()
            prepareSetup()
            kit = KitState(pending: pending, origin: .setup)
            go(.recoveryKit)
            clearPastedMasterPassword()
        case let .failure(error):
            setup.error = Fehlertexte.text(error)
        }
    }

    // MARK: Entsperren

    /// Kopf lesen (ohne Geheimnis, §13.3), damit der Sperrbildschirm zeigt, welche Faktoren nötig sind. Vorher
    /// den Totmann-Schalter prüfen (§23.2: abgelaufen → vernichten, bevor etwas angezeigt wird) und den Zustand
    /// der Selbstvernichtung lesen (Frist, Zähler).
    func loadLockHeader() {
        guard let store else { return }
        let state = unlock
        destructionLoads += 1
        let nummer = destructionLoads
        Task { @MainActor [weak self] in
            let result = await Self.background { () -> (VaultHeaderInfo?, DestructionStatus) in
                _ = try? store.checkDeadman(now: Date())
                let status = store.destructionStatus()
                return (try? store.inspect(), status)
            }
            guard let self, case let .success((header, status)) = result else { return }
            if self.destructionLoads == nummer { self.destruction = status }
            guard self.unlock === state, let header else { return }
            state.header = header
        }
    }

    /// Enter im Sperrbildschirm: Passwort → Touch ID → Karte → Schlüssel → `unlock(masterPassword:factors:)`.
    /// Bereits eingesammelte Faktoren bleiben nach einem Abbruch erhalten („Erneut versuchen“ macht dort weiter);
    /// nach jedem Entsperr-Versuch werden alle verworfen.
    public func submitUnlock() async {
        guard let store, !busy, !unlock.collecting, !unlock.preparing else { return }
        let state = unlock
        let password = state.password
        guard !password.isEmpty else { return }
        let start = epoch
        state.error = nil
        state.preparing = true
        // §23.2: Totmann-Schalter vor jedem Öffnen prüfen (unabhängig vom Passwort – die Abfolge bleibt gleich).
        await checkDeadmanNow()
        if state.header == nil, start == epoch, unlock === state {
            let result = await Self.background { try store.inspect() }
            if case let .success(header) = result { state.header = header }
        }
        state.preparing = false
        guard start == epoch, unlock === state else { return }
        var factors = FactorSecrets()
        if let header = state.header, !header.factors.isEmpty {
            let collection = state.collection.flatMap { $0.header == header ? $0 : nil } ?? FactorCollection(header: header)
            state.collection = collection
            state.collecting = true
            let ok = await collect(collection, reason: "Siegel entsperren")
            guard start == epoch, unlock === state else { return }
            state.collecting = false
            guard ok else { return }
            factors = collection.secrets
        }
        let mitFaktoren = !factors.available.isEmpty
        let attempt = factors
        factors = FactorSecrets()
        // Bei Datei-Problemen wartet der Kern selbst 2 s und liest einmal neu (SPEC §4 „Beschädigt“);
        // die Oberfläche wiederholt nicht zusätzlich. Gibt es eine angenommene ältere Datei, wird deren Prüfwert
        // vorher gelesen (Befund #28/#33).
        let mitPruefwert = settings.acceptedRollback != nil
        let url = store.vaultURL
        guard let ergebnis = await heavy({ () throws -> UnlockAttemptResult in
            let pruefwert = mitPruefwert ? Self.fileDigest(url) : nil
            // Der Kern zählt Fehlversuche, prüft den Totmann-Schalter und erkennt das Vernichtungs-Passwort selbst
            // (§23.2); eine Vernichtungs-Sitzung kommt als gewöhnliches `.unlocked`.
            return UnlockAttemptResult(outcome: try store.unlock(masterPassword: password, factors: attempt),
                                       digest: pruefwert)
        }) else { return }
        // Zähler und Frist hat der Kern beim Entsperren nachgeführt (§23.2): Sperrbildschirm neu lesen.
        reloadDestructionStatus()
        let result = ergebnis.map(\.outcome)
        let pruefwert = (try? ergebnis.get())?.digest
        // Faktoren dieses Versuchs verwerfen.
        state.collection?.reset()
        state.collection = nil

        switch result {
        case let .success(.rollbackSuspected(opened, _, file))
            where settings.acceptedRollback == AcceptedRollback(vaultID: opened.vaultID, generation: file,
                                                                digest: pruefwert ?? Data()):
            // Genau diese ältere Datei wurde schon bewusst angenommen: nicht bei jedem Entsperren neu fragen.
            unlock.password = ""
            open(opened)
        case let .success(.unlocked(opened)):
            // Inzwischen gespeichert (Generation über der Marke): die Annahme ist erledigt.
            if settings.acceptedRollback?.vaultID == opened.vaultID { settings.acceptedRollback = nil }
            withAnimation(.easeOut(duration: 0.18)) { unlock.riegel = 1 }
            busy = true
            try? await Task.sleep(for: .milliseconds(200))
            guard start == epoch else {
                opened.lock()
                return
            }
            busy = false
            open(opened)
        case let .success(.rollbackSuspected(opened, seen, file)):
            unlock.password = ""
            rollback = RollbackState(vault: opened, seenGeneration: seen, fileGeneration: file)
            go(.rollback)
        case .failure(.wrongPassword):
            rejectPassword(mitFaktoren ? Fehlertexte.wrongPasswordOrFactor : Fehlertexte.wrongPassword)
        case .failure(.kdfFailed):
            unlock.error = Fehlertexte.kdfFailed
        case let .failure(.unsupportedVersion(version)):
            // Kein Wiederherstellen möglich (der Kern überschreibt eine neuere Datei nie): Passwort nicht behalten.
            let corruptState = CorruptState()
            corruptState.kind = .newerVersion(version)
            unlock.password = ""
            corrupt = corruptState
            go(.corrupt)
        case .failure(.corruptFile), .failure(.kdfParametersOutOfRange):
            let corruptState = CorruptState()
            corruptState.kind = .damaged
            corruptState.password = password
            unlock.password = ""
            corrupt = corruptState
            go(.corrupt)
        case .failure(.vaultMissing):
            unlock.password = ""
            route()
        case let .failure(error):
            unlock.error = Fehlertexte.text(error)
        }
    }

    /// „Erneut versuchen“ nach einem abgebrochenen Faktor.
    public func retryUnlockFactors() async {
        unlock.collection?.failure = nil
        await submitUnlock()
    }

    /// Falsches Passwort: Feld leeren, Schütteln, Riegel 0 → 0.15 → 0.
    func rejectPassword(_ message: String) {
        unlock.password = ""
        unlock.error = message
        withAnimation(.linear(duration: 0.42)) { unlock.shakes += 1 }
        withAnimation(.easeOut(duration: 0.1)) { unlock.riegel = 0.15 }
        let state = unlock
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(130))
            withAnimation(.easeIn(duration: 0.22)) { state.riegel = 0 }
        }
    }

    // MARK: Notfallcode-Weg

    /// „Notfallcode verwenden“ (Sperrbildschirm, „Tresor fehlt“, „Beschädigt“). Ein Code oder zwei Teile? Der Kopf
    /// sagt es (§15): bei intakter Datei geprüft; ist ein Byte im Inhalt gekippt, ungeprüft (Befund datei-4); fehlt die
    /// Datei, aus der neuesten lesbaren Sicherung (Befund datei-2). Bleibt es unsicher, schaltet der Nutzer um.
    public func startRecovery() {
        guard !busy, !unlock.collecting, let store else { return }
        let bekannt = unlock.header
        let state = beginRecovery(origin: store.vaultExists ? .lock : .missingVault)
        // Der Kopf des Sperrbildschirms ist geprüft gelesen (`inspect`).
        if let bekannt, state.origin == .lock {
            state.setHeader(bekannt, certain: true)
            return
        }
        Task { @MainActor [weak self] in
            let result = await Self.background { Self.recoveryHeader(store) }
            guard let self, self.recovery === state, case let .success((info, certain)) = result else { return }
            state.setHeader(info, certain: certain)
        }
    }

    /// Notfallweg für genau diese Sicherungsdatei (v4.4, Befund datei-3): neuer Mac (der Touch-ID-Schlüssel gilt nur
    /// auf dem alten), Sicherungen nach dem Abstufen, Karte oder Schlüssel verloren. Der Kern öffnet sie mit dem Code
    /// bzw. zwei Teilen und setzt sie mit Stufe 1 als Tresor ein; ein bisheriger Tresor bleibt als Sicherung.
    public func startRecovery(file url: URL) {
        guard !busy, !unlock.collecting else { return }
        let state = beginRecovery(origin: .file(url))
        Task { @MainActor [weak self] in
            let result = await Self.background { () -> (VaultHeaderInfo?, Bool) in
                if let info = try? VaultStore.inspect(fileAt: url) { return (info, true) }
                return (try? VaultStore.inspectHeaderUnverified(fileAt: url), false)
            }
            guard let self, self.recovery === state, case let .success((info, certain)) = result else { return }
            state.setHeader(info, certain: certain)
        }
    }

    /// Faktor-Sheets abbrechen, eingesammelte Faktoren und eingegebene Passwörter der anderen Bildschirme verwerfen,
    /// Notfallweg öffnen.
    private func beginRecovery(origin: RecoveryState.Origin) -> RecoveryState {
        cancelFactorSheets()
        unlock.collection?.reset()
        missing.collection?.reset()
        missing.password = ""
        corrupt.collection?.reset()
        corrupt.password = ""
        unlock = UnlockState()
        let state = RecoveryState()
        state.origin = origin
        recovery = state
        go(.recovery)
        return state
    }

    /// Kopf für die Wahl Code/Teile: geprüft aus der Tresordatei, sonst ihr Kopf ungeprüft, sonst der Kopf der neuesten
    /// lesbaren Sicherung. Das zweite Feld sagt, ob die Wahl damit sicher ist.
    nonisolated static func recoveryHeader(_ store: VaultStore) -> (VaultHeaderInfo?, Bool) {
        if let info = try? store.inspect() { return (info, true) }
        if let info = try? store.inspectHeaderUnverified() { return (info, false) }
        for backup in store.backups() where backup.vaultID != nil {
            if let info = try? VaultStore.inspect(fileAt: backup.url) { return (info, false) }
        }
        return (nil, false)
    }

    /// Umschalter im Code-Schritt (Befund datei-4): Kopf unsicher oder unbekannt, der Nutzer weiss es besser.
    public func recoveryChooseShares(_ shares: Bool) {
        guard recovery.step == .enterCode, !busy else { return }
        recovery.chooseScheme(shares: shares)
    }

    /// Im Feld für den einzelnen Code steht mehr als ein Code: Hat es genau die Länge eines Teils (56 Zeichen), ist es
    /// einer – dann zur Eingabe der Teile wechseln und ihn als ersten Teil übernehmen (Befund datei-4).
    public func recoveryCodeOverflow(_ raw: String) {
        guard recovery.step == .enterCode, !recovery.usesShares, !busy else { return }
        let zeichen = RecoveryCodeFormatting.significant(raw)
        guard zeichen.count == RecoveryFlowView.shareCharacters else { return }
        recovery.chooseScheme(shares: true)
        recovery.shares = [RecoveryCodeFormatting.format(zeichen, groups: 12), ""]
        recovery.code = ""
    }

    public func cancelRecovery() {
        // Im Schritt „Neues Master-Passwort“ schreibt der Kern nach Argon2 unumkehrbar: währenddessen nicht
        // abbrechen, sonst gälte das neue Passwort ohne Rückmeldung (Befund #11).
        if busy, recovery.step == .newPassword { return }
        recovery.vault?.lock()
        recovery = RecoveryState()
        epoch += 1
        busy = false
        SecureEventInput.disable()
        // Zurück dorthin, wo es passt: Sperrbildschirm, „Tresor fehlt“ oder Einrichtung (Befund datei-2).
        route()
    }

    /// Fehler beim Prüfen des Codes gegen die Tresordatei, bei denen die Sicherungen helfen können (Datei
    /// beschädigt, auch ein gekipptes Bit im Kopf, das als fremdes Kit erscheint; Datei fehlt, Befund datei-2).
    nonisolated static func mayTryBackups(_ error: SiegelError) -> Bool {
        switch error {
        case .corruptFile, .wrongRecoveryCode, .kdfParametersOutOfRange, .vaultMissing: return true
        default: return false
        }
    }

    /// Code gegen die Datei prüfen, sonst gegen die Sicherungen. Fehlt die Datei, zählt nur, was die Sicherungen sagen.
    nonisolated static func checkWithBackups<T>(_ direct: () throws -> T, backups: () throws -> T) throws -> (T, Bool) {
        do {
            return (try direct(), false)
        } catch let fehler as SiegelError where mayTryBackups(fehler) {
            do {
                return (try backups(), true)
            } catch let ueberSicherungen as SiegelError where fehler == .vaultMissing {
                throw ueberSicherungen
            } catch {
                throw fehler
            }
        }
    }

    /// Code prüfen (inkl. automatischer Korrektur im Kern). Ist die Tresordatei beschädigt, wird der Code gegen
    /// die Sicherungen geprüft; passt er dort, führt der Weg über die neueste passende Sicherung (Befund #4).
    public func checkRecoveryCodeForRecovery() async {
        guard let store, !busy else { return }
        let input = recovery.code
        guard !input.isEmpty else { return }
        let datei = recovery.sourceFile
        recovery.error = nil
        recovery.useBackup = false
        recovery.offerBackup = false
        guard let result = await heavy({ () throws -> RecoveryCheck in
            // Gewählte Sicherungsdatei: nur gegen genau diese (Befund datei-3).
            if let datei {
                return RecoveryCheck(match: try store.checkRecoveryCode(input, againstFile: datei), viaBackup: false)
            }
            let (match, viaBackup) = try AppModel.checkWithBackups({ try store.checkRecoveryCode(input) },
                                                                   backups: { try store.checkRecoveryCodeAgainstBackups(input) })
            return RecoveryCheck(match: match, viaBackup: viaBackup)
        }) else { return }
        switch result {
        case let .success(check):
            recovery.useBackup = check.viaBackup
            switch check.match {
            case .exact:
                recovery.confirmedCode = input
                recovery.step = .newPassword
            case let .corrected(formatted, positions):
                recovery.step = .confirmCorrection(formatted: formatted, changedPositions: positions)
            }
        case let .failure(error):
            if showCorruptAfterRecoveryCheck(error) { return }
            if let text = recoveryCheckFileText(error, shares: false) {
                recovery.error = text
                return
            }
            recovery.error = Fehlertexte.recoveryCode(error, input: input)
        }
    }

    /// Ohne Tresordatei bzw. für eine gewählte Sicherung: Was heisst ein Datei-Fehler hier? (nil = allgemeiner Text)
    private func recoveryCheckFileText(_ error: SiegelError, shares: Bool) -> String? {
        switch (recovery.origin, error) {
        case (.missingVault, .corruptFile), (.missingVault, .vaultMissing):
            return shares ? "Keine Sicherung lässt sich mit diesen Teilen öffnen."
                          : "Keine Sicherung lässt sich mit diesem Notfallcode öffnen."
        case (.file, .corruptFile), (.file, .kdfParametersOutOfRange):
            return "Diese Sicherung ist beschädigt. Wähle eine andere Sicherung."
        case (.file, .vaultMissing):
            return Fehlertexte.text(.io("backup.missing"))
        default:
            return nil
        }
    }

    /// Befund #22: Meldet die Prüfung des Codes bzw. der Teile `corruptFile` (Datei-Prüfsumme, auch Bitfäule im Kopf)
    /// und passt keine Sicherung, ist das kein „falsches Kit“: wie beim Entsperren auf „Tresordatei beschädigt“. Nur
    /// vom Sperrbildschirm aus – ohne Tresordatei oder für eine gewählte Sicherung gibt es nichts „Beschädigtes“ zu
    /// zeigen.
    private func showCorruptAfterRecoveryCheck(_ error: SiegelError) -> Bool {
        guard recovery.origin == .lock else { return false }
        switch error {
        case .corruptFile, .kdfParametersOutOfRange:
            let corruptState = CorruptState()
            corruptState.kind = .damaged
            recovery = RecoveryState()
            corrupt = corruptState
            go(.corrupt)
            reloadDestructionStatus()
            return true
        default:
            return false
        }
    }

    /// Zwei Teile des geteilten Codes prüfen (§15, inkl. Korrektur im Kern). Ist die Tresordatei beschädigt, werden
    /// die Teile gegen die Sicherungen geprüft; passen sie dort, führt der Weg über die neueste passende Sicherung.
    public func checkRecoverySharesForRecovery() async {
        guard let store, !busy else { return }
        let inputs = recovery.shares
        guard inputs.allSatisfy({ !RecoveryCodeFormatting.significant($0).isEmpty }) else { return }
        let datei = recovery.sourceFile
        recovery.error = nil
        recovery.useBackup = false
        recovery.offerBackup = false
        guard let result = await heavy({ () throws -> ([RecoveryCodeMatch], Bool) in
            if let datei { return (try store.checkRecoveryShares(inputs, againstFile: datei), false) }
            return try AppModel.checkWithBackups({ try store.checkRecoveryShares(inputs) },
                                                 backups: { try store.checkRecoverySharesAgainstBackups(inputs) })
        }) else { return }
        switch result.map(\.0) {
        case let .success(matches):
            recovery.useBackup = (try? result.get().1) ?? false
            guard matches.count == inputs.count else {
                recovery.error = Fehlertexte.text(.invalidRecoveryCodeFormat)
                return
            }
            var fixes: [RecoveryState.ShareCorrection] = []
            for (index, match) in matches.enumerated() {
                if case let .corrected(formatted, positions) = match {
                    fixes.append(.init(index: index, formatted: formatted, changedPositions: positions))
                }
            }
            if fixes.isEmpty {
                recovery.confirmedShares = inputs
                recovery.step = .newPassword
            } else {
                recovery.step = .confirmShareCorrections(fixes)
            }
        case let .failure(error):
            if showCorruptAfterRecoveryCheck(error) { return }
            if let text = recoveryCheckFileText(error, shares: true) {
                recovery.error = text
                return
            }
            recovery.error = Self.shareErrorText(error, inputs: inputs)
        }
    }

    static func shareErrorText(_ error: SiegelError, inputs: [String] = []) -> String {
        switch error {
        case .invalidRecoveryCodeFormat
            where !inputs.isEmpty && inputs.allSatisfy(VaultStore.recoveryShareInputIsComplete):
            // Befund #42 sinngemäss: volle Länge, aber nicht korrigierbar.
            return "Die Teile enthalten Fehler, die sich nicht automatisch korrigieren lassen. Vergleiche jede Gruppe mit deinen Blättern."
        case .invalidRecoveryCodeFormat:
            return "Das sind keine gültigen Teile. Jeder Teil hat 56 Zeichen (Ziffern und Buchstaben ausser U); unleserliche Zeichen als\u{00A0}„\u{2060}?\u{2060}“\u{00A0}eingeben."
        case .recoveryCodeChecksum:
            return "Die Teile enthalten Fehler, die sich nicht automatisch korrigieren lassen – oder es ist zweimal derselbe Teil. Prüfe jede Gruppe."
        case let .wrongRecoveryCode(_, vaultKit):
            return Fehlertexte.wrongKit(vaultKit, shares: true)
        default:
            return Fehlertexte.text(error)
        }
    }

    public func acceptShareCorrections() {
        guard case let .confirmShareCorrections(fixes) = recovery.step else { return }
        var teile = recovery.shares
        for fix in fixes where fix.index < teile.count { teile[fix.index] = fix.formatted }
        recovery.shares = teile
        recovery.confirmedShares = teile
        recovery.step = .newPassword
    }

    public func acceptCorrection() {
        guard case let .confirmCorrection(formatted, _) = recovery.step else { return }
        recovery.confirmedCode = formatted
        recovery.code = formatted
        recovery.step = .newPassword
    }

    public func rejectCorrection() {
        recovery.step = .enterCode
        recovery.error = nil
    }

    /// Neues Master-Passwort setzen und Tresor wiederherstellen.
    public func submitRecovery() async {
        if recovery.usesShares {
            await submitRecoveryWithShares()
            return
        }
        guard let store, !busy, recovery.canSubmit, let code = recovery.confirmedCode else { return }
        if let datei = recovery.sourceFile {
            await submitRecoveryFromFile(datei)
            return
        }
        if recovery.useBackup {
            await submitRecoveryFromBackup()
            return
        }
        let password = recovery.newPassword
        let profil = recoveryProfile
        recovery.error = nil
        recovery.offerBackup = false
        recovery.offerStandardProfile = false
        guard let result = await heavy(writes: true, {
            try store.recover(code: code, newMasterPassword: password, kdf: profil)
        }) else { return }
        switch result {
        case let .success(opened):
            showRecoverySummary(opened, backup: nil)
        case let .failure(error):
            if handleRecoveryKDFFailure(error, profile: profil) { return }
            switch error {
            case .wrongRecoveryCode, .invalidRecoveryCodeFormat, .recoveryCodeChecksum:
                recovery.step = .enterCode
                recovery.error = Fehlertexte.recoveryCode(error, input: code)
                return
            case .corruptFile, .kdfParametersOutOfRange:
                // Code und neues Passwort bleiben stehen; der Weg über die Sicherungen ist ein eigener Knopf.
                recovery.offerBackup = true
                recovery.error = "Die Tresordatei ist beschädigt. Siegel kann die neueste Sicherung öffnen, die dein Notfallcode öffnet – Änderungen danach fehlen."
                return
            default:
                break
            }
            recovery.error = Fehlertexte.text(error)
        }
    }

    /// Profil der wiederhergestellten Datei (Befund #21): wie bisher, ausser „Mit Profil Standard“ wurde gewählt.
    var recoveryProfile: KDFParameters {
        recovery.forceStandardProfile ? .standard : recovery.kdfToKeep
    }

    /// `kdfFailed` mit Profil Stark: nicht still herabstufen, sondern „Mit Profil Standard wiederherstellen“ anbieten.
    private func handleRecoveryKDFFailure(_ error: SiegelError, profile: KDFParameters) -> Bool {
        guard error == .kdfFailed, profile == .strong else { return false }
        recovery.offerStandardProfile = true
        recovery.error = "Für das Profil Stark fehlt Arbeitsspeicher (2 GiB). Schliesse andere Programme und versuche es erneut – oder stelle mit dem Profil Standard (1 GiB) wieder her."
        return true
    }

    /// „Mit Profil Standard wiederherstellen“ nach `kdfFailed` (bewusste Wahl, Befund #21).
    public func submitRecoveryWithStandardProfile() async {
        recovery.forceStandardProfile = true
        recovery.offerStandardProfile = false
        await submitRecovery()
    }

    /// Wiederherstellen mit zwei Teilen (§15). Danach gilt Stufe 1 für Tresor und Einträge (§16.1).
    private func submitRecoveryWithShares() async {
        guard let store, !busy, recovery.canSubmit, let teile = recovery.confirmedShares else { return }
        if let datei = recovery.sourceFile {
            await submitRecoveryFromFile(datei)
            return
        }
        if recovery.useBackup {
            await submitRecoveryFromBackup()
            return
        }
        let password = recovery.newPassword
        let profil = recoveryProfile
        recovery.error = nil
        recovery.offerStandardProfile = false
        guard let result = await heavy(writes: true, {
            try store.recover(shares: teile, newMasterPassword: password, kdf: profil)
        }) else { return }
        switch result {
        case let .success(opened):
            showRecoverySummary(opened, backup: nil)
        case let .failure(error):
            if handleRecoveryKDFFailure(error, profile: profil) { return }
            switch error {
            case .wrongRecoveryCode, .invalidRecoveryCodeFormat, .recoveryCodeChecksum:
                recovery.confirmedShares = nil
                recovery.step = .enterCode
                recovery.error = Self.shareErrorText(error, inputs: teile)
            case .corruptFile, .kdfParametersOutOfRange:
                // Teile und neues Passwort bleiben stehen; der Weg über die Sicherungen ist ein eigener Knopf.
                recovery.offerBackup = true
                recovery.error = "Die Tresordatei ist beschädigt. Siegel kann die neueste Sicherung öffnen, die deine Teile öffnen – Änderungen danach fehlen."
            default:
                recovery.error = Fehlertexte.text(error)
            }
        }
    }

    /// „Neueste lesbare Sicherung mit dem Notfallcode öffnen“ (Tresordatei beschädigt, Befund #4).
    public func submitRecoveryFromBackup() async {
        guard let store, !busy, recovery.canSubmit else { return }
        let teile = recovery.usesShares ? recovery.confirmedShares : nil
        let code = recovery.usesShares ? nil : recovery.confirmedCode
        guard teile != nil || code != nil else { return }
        let password = recovery.newPassword
        let profil = recoveryProfile
        recovery.error = nil
        recovery.offerBackup = false
        recovery.offerStandardProfile = false
        guard let result = await heavy(writes: true, { () throws -> (UnlockedVault, BackupInfo) in
            if let teile {
                return try store.recoverFromNewestReadableBackup(shares: teile, newMasterPassword: password, kdf: profil)
            }
            return try store.recoverFromNewestReadableBackup(code: code ?? "", newMasterPassword: password, kdf: profil)
        }) else { return }
        switch result {
        case let .success((opened, info)):
            showRecoverySummary(opened, backup: info)
        case let .failure(error) where handleRecoveryKDFFailure(error, profile: profil):
            return
        case .failure(.corruptFile):
            recovery.error = teile != nil
                ? "Keine Sicherung lässt sich mit diesen Teilen öffnen."
                : "Keine Sicherung lässt sich mit diesem Notfallcode öffnen."
        case let .failure(error):
            recovery.error = Fehlertexte.text(error)
        }
    }

    /// Gewählte Sicherungsdatei mit dem Notfallcode bzw. zwei Teilen einsetzen (Befund datei-3). Stand und Datum der
    /// Datei werden vorher gelesen (die Zusammenfassung nennt sie).
    private func submitRecoveryFromFile(_ url: URL) async {
        guard let store, !busy, recovery.canSubmit else { return }
        let teile = recovery.usesShares ? recovery.confirmedShares : nil
        let code = recovery.usesShares ? nil : recovery.confirmedCode
        guard teile != nil || code != nil else { return }
        let password = recovery.newPassword
        let profil = recoveryProfile
        recovery.error = nil
        recovery.offerBackup = false
        recovery.offerStandardProfile = false
        guard let result = await heavy(writes: true, { () throws -> (UnlockedVault, BackupInfo) in
            let info = try VaultStore.backupInfo(fileAt: url)
            if let teile {
                return (try store.recoverBackup(from: url, shares: teile, newMasterPassword: password, kdf: profil), info)
            }
            return (try store.recoverBackup(from: url, code: code ?? "", newMasterPassword: password, kdf: profil), info)
        }) else { return }
        switch result {
        case let .success((opened, info)):
            showRecoverySummary(opened, backup: info)
        case let .failure(error) where handleRecoveryKDFFailure(error, profile: profil):
            return
        case let .failure(error):
            switch error {
            case .wrongRecoveryCode, .invalidRecoveryCodeFormat, .recoveryCodeChecksum:
                recovery.confirmedShares = nil
                recovery.step = .enterCode
                recovery.error = teile != nil ? Self.shareErrorText(error, inputs: teile ?? [])
                                              : Fehlertexte.recoveryCode(error, input: code ?? "")
            default:
                recovery.error = recoveryCheckFileText(error, shares: teile != nil) ?? Fehlertexte.text(error)
            }
        }
    }

    private func showRecoverySummary(_ opened: UnlockedVault, backup: BackupInfo?) {
        recovery.vault = opened
        recovery.entryCount = opened.entries.count
        recovery.lastModified = opened.lastModified
        recovery.restoredBackup = backup
        recovery.newPassword = ""
        recovery.newPasswordRepeat = ""
        recovery.code = ""
        recovery.confirmedCode = nil
        recovery.shares = ["", ""]
        recovery.confirmedShares = nil
        recovery.offerBackup = false
        recovery.step = .done
    }

    /// Nach der Zusammenfassung: Tresor zeigen.
    public func finishRecovery() {
        guard let opened = recovery.vault else { return }
        recovery.vault = nil
        open(opened)
    }

    // MARK: Notfallkit

    public func kitChooseHandwritten() {
        guard let kit else { return }
        if kit.isShared {
            kit.shareMethods[kit.shareIndex] = .handwritten
        } else {
            kit.method = .handwritten
        }
        kit.printWarning = false
        kit.printNotPaper = false
    }

    /// Geteilter Code: anderen Teil zeigen.
    public func kitShowShare(_ index: Int) {
        guard let kit, kit.isShared, index >= 0, index < kit.pending.shares.count else { return }
        kit.shareIndex = index
        kit.printWarning = false
        kit.printNotPaper = false
        kit.chosenPrintInfo = nil
    }

    /// „Drucken…“: Druckdialog (ohne Vorschau), dann genau den gewählten Drucker prüfen (SPEC §7.6, Befund #15).
    public func kitPrint() {
        guard let kit, !busy else { return }
        kit.printFailed = false
        kit.printNotPaper = false
        let start = epoch
        guard let info = RecoveryKitPrinter.choosePrinter() else { return }
        // Während des Dialogs gesperrt oder Kit verworfen? Dann nichts mehr tun.
        guard start == epoch, self.kit === kit else { return }
        guard RecoveryKitPrinter.isPaper(info) else {
            kit.printNotPaper = true
            return
        }
        switch RecoveryKitPrinter.check(info) {
        case .secure:
            runKitPrint(info)
        case .insecure:
            kit.chosenPrintInfo = info
            kit.printWarningText = RecoveryKitPrinter.insecureWarning
            kit.printWarning = true
        case .unknown:
            kit.chosenPrintInfo = info
            kit.printWarningText = RecoveryKitPrinter.unknownWarning
            kit.printWarning = true
        }
    }

    /// „Trotzdem drucken“ nach der Druckerwarnung: mit genau dem geprüften Drucker, ohne zweiten Dialog.
    public func kitPrintAnyway() {
        guard let kit, let info = kit.chosenPrintInfo else { return }
        kit.printWarning = false
        kit.chosenPrintInfo = nil
        runKitPrint(info)
    }

    public func kitDismissPrintWarning() {
        kit?.printWarning = false
        kit?.chosenPrintInfo = nil
    }

    private func runKitPrint(_ info: NSPrintInfo) {
        guard let kit else { return }
        let start = epoch
        let teil = kit.shareIndex
        let content: PrintSheetContent = kit.isShared && teil < kit.pending.shares.count
            ? .share(kit.pending.shares[teil], total: kit.pending.shares.count)
            : .recovery(kit.pending.code)
        let outcome = RecoveryKitPrinter.printSheet(content, info: info)
        // Während des Druckens gesperrt? Dann nichts mehr tun.
        guard start == epoch, let current = self.kit, current === kit else { return }
        switch outcome {
        case .paper:
            if current.isShared { current.shareMethods[teil] = .printed } else { current.method = .printed }
        case .notPaper: current.printNotPaper = true
        case .cancelled: break
        }
    }

    public func kitProceedToConfirm() {
        guard let kit else { return }
        kit.error = nil
        kit.confirmation = Array(repeating: "", count: KitState.confirmationCount(kit.pending))
        kit.step = .confirm
    }

    /// Bestätigung lokal prüfen (Stufen-Assistent; der Kern prüft beim Schreiben erneut).
    static func confirmationMatches(_ kit: KitState) -> Bool {
        func norm(_ s: String) -> String {
            String(RecoveryCodeFormatting.significant(s).map { ch -> Character in
                switch ch {
                case "O": "0"
                case "I", "L": "1"
                default: ch
                }
            })
        }
        if kit.isShared {
            for (k, share) in kit.pending.shares.enumerated() {
                guard k < kit.confirmation.count, k < kit.pending.shareConfirmationGroups.count else { return false }
                let g = kit.pending.shareConfirmationGroups[k]
                guard g < share.groups.count, norm(kit.confirmation[k]) == share.groups[g] else { return false }
            }
            return true
        }
        let gruppen = kit.pending.code.groups
        for (k, g) in kit.pending.confirmationGroups.enumerated() {
            guard k < kit.confirmation.count, g < gruppen.count, norm(kit.confirmation[k]) == gruppen[g] else { return false }
        }
        return true
    }

    public func kitShowCodeAgain() {
        kit?.error = nil
        kit?.step = .show
    }

    /// Zwei Gruppen prüfen und das Kit schreiben (bei neuem Kit) bzw. als bestätigt markieren.
    public func kitConfirm() async {
        guard let kit, let vault, !busy, kit.canConfirm else { return }
        let pending = kit.pending
        let confirmation = kit.confirmation.map { String(RecoveryCodeFormatting.significant($0)) }
        if kit.origin == .levelChange {
            // Teil des Stufen-Assistenten: geschrieben wird mit dem Stufenwechsel.
            guard Self.confirmationMatches(kit) else {
                kit.error = Fehlertexte.text(.recoveryConfirmationMismatch)
                kit.confirmation = Array(repeating: "", count: KitState.confirmationCount(pending))
                return
            }
            wizardRecoveryConfirmed(confirmation)
            return
        }
        let vaultID = vault.vaultID
        kit.error = nil
        // Versiegelte Einträge (§16): ihre Notfall-Gruppen werden an das neue Kit gekapselt – dafür holt der Kern
        // je Gruppe eine Freigabe (Touch ID, ggf. Karte/Schlüssel) über den Provider. Ohne solche Einträge ruft er
        // den Provider nicht.
        let provider = UIEntryFactorProvider(model: self)
        guard let result = await heavyAsync(writes: true, {
            try await vault.commitRecovery(pending, confirmation: confirmation, entryFactors: provider)
        }, whenDiscarded: { [weak self] result in
            // Gesperrt, während das neue Kit geschrieben wurde: Frage nach den alten Sicherungen später stellen.
            if case .success = result, kit.origin == .newKit {
                self?.pendingPurgeQuestion = PendingPurgeQuestion(vaultID: vaultID, reason: .newKit)
            }
        }) else { return }
        switch result {
        case .success:
            refreshSnapshot()
            guard self.kit === kit else {
                // Inzwischen verlassen (sollte gesperrt sein): ehrlich melden, nicht still weiterschalten.
                if kit.origin == .newKit {
                    show(Notice("Neues Notfallkit ist aktiv (Kit-Kennung \(pending.code.kitID)) – der bisherige Code gilt nicht mehr",
                                symbol: "exclamationmark.circle"), seconds: 10)
                }
                return
            }
            switch kit.origin {
            case .setup, .levelChange:
                self.kit = nil
                go(.unlocked)
                show(Notice("Notfallkit bestätigt"))
            case .newKit:
                // Bis zur Antwort gemerkt (Befund #34): Sperren lässt die Frage nicht verschwinden.
                pendingPurgeQuestion = PendingPurgeQuestion(vaultID: vaultID, reason: .newKit)
                kit.step = .purgeQuestion
            }
        case let .failure(error):
            switch error {
            case .factorCancelled, .factorUnavailable, .factorTemporarilyUnavailable, .wrongCard, .wrongSecurityKey,
                 .wrongPassword:
                // Freigabe für die geschützten Einträge abgebrochen oder gescheitert: Bestätigung bleibt stehen.
                kit.error = Fehlertexte.protectedEntriesRelease(error)
            default:
                kit.error = Fehlertexte.text(error)
                kit.confirmation = Array(repeating: "", count: KitState.confirmationCount(pending))
            }
        }
    }

    /// Einrichtung: Bestätigung später (die Zeile „Notfallkit nicht bestätigt“ bleibt stehen; das Blatt lässt
    /// sich danach unter „Notfallcode prüfen…“ mit dem ganzen Code bestätigen).
    public func kitSkip() {
        guard !busy else { return }
        kit = nil
        go(.unlocked)
    }

    /// Neues Kit abbrechen: nichts geschrieben, der alte Code bleibt gültig. Während des Schreibens gesperrt
    /// (Befund #11): Dann würde das neue Kit trotzdem gelten.
    public func kitCancel() {
        guard !busy else { return }
        kit = nil
        go(.unlocked)
        // Stufen-Assistent: zurück zum Schritt „Notfallkit“ (das vorbereitete Kit bleibt im Assistenten).
    }

    /// Nach neuem Kit: alte Sicherungen entfernen oder behalten.
    public func kitFinish(removeOldBackups: Bool) async {
        guard !busy, savesInFlight == 0, let current = kit else { return }
        let start = epoch
        if removeOldBackups {
            guard let vaultID = vault?.vaultID else { return }
            busy = true
            let result = await performReturning({ try $0.purgeBackups() })
            if start == epoch { busy = false }
            // Inzwischen gesperrt (Befund #25/#35): lock() hat Kit und Tresor verworfen und den Sperrbildschirm
            // gesetzt – nichts mehr anzeigen, nicht in die Tresor-Ansicht wechseln. Die Frage bleibt gemerkt.
            guard start == epoch, vault != nil, screen == .recoveryKit, kit === current else { return }
            switch result {
            case let .success(report):
                notePurgeReport(report, vaultID: vaultID)
                show(purgeNotice(report), seconds: report.isComplete ? 4 : 10)
            case let .failure(error):
                show(Notice(Fehlertexte.text(error), symbol: "exclamationmark.circle"))
            }
        } else {
            show(Notice("Neues Notfallkit gespeichert"))
        }
        if pendingPurgeQuestion?.reason == .newKit { pendingPurgeQuestion = nil }
        kit = nil
        go(.unlocked)
    }

    // MARK: Tresor fehlt

    /// Falsches Passwort auf einem Sicherungsweg: Ist der Fehlversuch-Zähler an, sagt die Meldung, dass auch dieser
    /// Versuch zählt (Befund ablaeufe-6, §23.2) – ältere Sicherungen gehen mit früheren Passwörtern auf, das lädt zum
    /// Durchprobieren ein. Die Warnung „Noch x Versuche“ folgt ab der Hälfte.
    func countsAttempt(_ text: String) -> String {
        destruction?.settings.maxFailedAttempts == nil ? text : text + " Auch hier zählt jeder Fehlversuch."
    }

    public func restoreSelectedBackup() async {
        guard let store, !busy, let backup = missing.selectedBackup else { return }
        let password = missing.password
        guard !password.isEmpty else { return }
        missing.error = nil
        let state = missing
        // Verlangt die Sicherung Faktoren? Dann vorher einsammeln.
        guard let factors = await factorsForFile(backup.url, existing: state.collection,
                                                 assign: { state.collection = $0 }, reason: "Sicherung öffnen"),
              missing === state else { return }
        guard let result = await heavy(writes: true, {
            try store.restoreBackup(backup, masterPassword: password, factors: factors)
        }) else { return }
        state.collection?.reset()
        switch result {
        case let .success(opened):
            open(opened)
            noteRestoredKit()
        case let .failure(error):
            missing.password = ""
            missing.error = error == .wrongPassword ? countsAttempt("Falsches Passwort für diese Sicherung.")
                                                    : Fehlertexte.text(error)
            // §23.2: Auch dieser Weg zählt Fehlversuche – die Warnung ab N/2 gilt hier genauso (Befund datei-5).
            if error == .wrongPassword { await refreshDestructionStatus() }
        }
    }

    /// „Passwort vergessen? Notfallcode verwenden“ bzw. „Notfallcode verwenden“ nach einem nicht nutzbaren Faktor
    /// (Befund datei-2, §14.1): Ist eine selbst gewählte Sicherungsdatei ausgewählt, gilt der Weg genau ihr; sonst
    /// die neueste Sicherung, die der Code öffnet.
    public func missingUseRecovery() {
        guard screen == .missingVault, !busy else { return }
        if let gewaehlt = missing.chosenFile, missing.selection == gewaehlt || missing.fromSetup {
            startRecovery(file: gewaehlt)
        } else {
            startRecovery()
        }
    }

    public func requestNewVault() {
        missing.confirmingNewVault = true
    }

    public func cancelNewVault() {
        missing.confirmingNewVault = false
    }

    /// Zweiter Knopf mit Bestätigung: neuen leeren Tresor anlegen (Sicherungen bleiben).
    public func confirmNewVault() {
        missing.collection?.reset()
        missing = MissingVaultState()
        prepareSetup()
        go(.setup)
    }

    /// Liste neu lesen (zweiter Ort verbunden bzw. getrennt) – im Hintergrund (Befund ablaeufe-10).
    public func reloadBackups() {
        loadBackups(into: missing, setupIfNone: false)
    }

    // MARK: Sicherung aus Datei (Einrichtung, „Tresor fehlt“; Befund datei-3)

    /// „Aus Sicherung wiederherstellen…“ in der Einrichtung bzw. „Andere Sicherung wählen…“ bei „Tresor fehlt“: eine
    /// Sicherungsdatei wählen (z. B. vom USB-Stick auf einem neuen Mac). Danach wie „Tresor fehlt“: Master-Passwort der
    /// Sicherung mit ihren Faktoren – oder, wenn die fehlen, der Notfallcode für genau diese Datei.
    public func chooseBackupFileForRestore() {
        guard screen == .setup || screen == .missingVault, !busy else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Wählen"
        panel.message = "Siegel-Sicherung (.siegel) wählen, z. B. vom USB-Stick."
        if let typ = UTType(filenameExtension: "siegel", conformingTo: .data) {
            panel.allowedContentTypes = [typ]
        }
        WindowGuard.shared.protect(panel)
        let start = epoch
        let bildschirm = screen
        let handler: (NSApplication.ModalResponse) -> Void = { [weak self, weak panel] response in
            MainActor.assumeIsolated {
                guard let self, start == self.epoch, self.screen == bildschirm else { return }
                guard response == .OK, let url = panel?.url else { return }
                Task { await self.useBackupFileForRestore(url) }
            }
        }
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            panel.beginSheetModal(for: window, completionHandler: handler)
        } else {
            panel.begin(completionHandler: handler)
        }
    }

    /// Gewählte Datei prüfen (lesbar, Stand, vaultID) und als ausgewählte Sicherung zeigen.
    public func useBackupFileForRestore(_ url: URL) async {
        guard store != nil, screen == .setup || screen == .missingVault, !busy else { return }
        let start = epoch
        let result = await Self.background { try VaultStore.backupInfo(fileAt: url) }
        guard start == epoch, screen == .setup || screen == .missingVault else { return }
        switch result {
        case let .success(info):
            if screen == .setup {
                let state = MissingVaultState()
                state.fromSetup = true
                state.chosenFile = url
                state.backups = [info]
                state.selection = url
                missing = state
                setup.error = nil
                go(.missingVault)
                // Die übrigen Sicherungen dieses Macs kommen im Hintergrund dazu (Befund ablaeufe-10).
                loadBackups(into: state, setupIfNone: false)
                await refreshDestructionStatus()
            } else {
                let vorher = missing.chosenFile
                missing.collection?.reset()
                missing.collection = nil
                missing.chosenFile = url
                missing.backups = [info] + missing.backups.filter { $0.url != url && $0.url != vorher }
                missing.selection = url
                missing.error = nil
            }
        case let .failure(error):
            let text = error == .io("backup.missing") ? Fehlertexte.text(error)
                                                      : "Diese Datei ist keine lesbare Siegel-Sicherung."
            if screen == .setup { setup.error = text } else { missing.error = text }
        }
    }

    /// „Zurück“ aus „Sicherung wiederherstellen“ (aus der Einrichtung gekommen).
    public func leaveBackupFileRestore() {
        guard !busy else { return }
        missing.collection?.reset()
        missing = MissingVaultState()
        route()
    }

    // MARK: Beschädigt

    public func openNewestReadableBackup() async {
        guard let store, !busy else { return }
        let password = corrupt.password
        guard !password.isEmpty else { return }
        corrupt.error = nil
        let state = corrupt
        // Ein erst jetzt eingesteckter zweiter Sicherungsort zählt mit (Befund #29).
        retrySecondaryBackupLocation()
        // Faktoren nach dem Kopf der neuesten lesbaren Sicherung (die Tresordatei selbst ist beschädigt). Die Liste
        // im Hintergrund lesen, mit Fortschritt (Befund ablaeufe-10: am zweiten Ort z. B. aus iCloud Drive).
        guard let liste = await heavy({ store.backups() }), corrupt === state,
              case let .success(sicherungen) = liste else { return }
        let neueste = sicherungen.first { $0.vaultID != nil }
        var factors = FactorSecrets()
        state.collectionFile = nil
        if let neueste {
            guard let f = await factorsForFile(neueste.url, existing: state.collection,
                                               assign: { state.collection = $0 }, reason: "Sicherung öffnen"),
                  corrupt === state else { return }
            factors = f
        }
        let attempt = factors
        guard let result = await heavy(writes: true, {
            try store.restoreNewestReadableBackup(masterPassword: password, factors: attempt)
        }) else { return }
        state.collection?.reset()
        switch result {
        case let .success((opened, info)):
            corrupt.vault = opened
            corrupt.restoredBackup = info
            corrupt.entryCount = opened.entries.count
            corrupt.kitID = opened.kitID
            corrupt.kitConfirmed = opened.recoveryConfirmed
            corrupt.password = ""
        case .failure(.wrongPassword):
            corrupt.password = ""
            corrupt.error = countsAttempt("Keine Sicherung lässt sich mit diesem Passwort öffnen.")
            await refreshDestructionStatus()
        case .failure(.corruptFile):
            corrupt.error = "Es gibt keine lesbare Sicherung in Siegels Ordner. Hast du eine exportierte Sicherung (z. B. auf einem USB-Stick)? Dann „Sicherung aus Datei einspielen…“."
        case let .failure(error):
            corrupt.error = Fehlertexte.text(error)
        }
    }

    /// „Sicherung aus Datei einspielen…“ bei beschädigter Tresordatei (Befund #29): eine exportierte Sicherung
    /// öffnen, ohne dass ein Tresor entsperrt sein muss. Der Kern legt die beschädigte Datei vorher beiseite.
    public func corruptChooseBackupFile() {
        guard screen == .corrupt, case .damaged = corrupt.kind, !busy else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Einspielen"
        panel.message = "Exportierte Siegel-Sicherung (.siegel) wählen, z. B. vom USB-Stick."
        if let typ = UTType(filenameExtension: "siegel", conformingTo: .data) {
            panel.allowedContentTypes = [typ]
        }
        WindowGuard.shared.protect(panel)
        let start = epoch
        let state = corrupt
        let handler: (NSApplication.ModalResponse) -> Void = { [weak self, weak panel] response in
            MainActor.assumeIsolated {
                guard let self, start == self.epoch, self.corrupt === state, self.screen == .corrupt else { return }
                guard response == .OK, let url = panel?.url else { return }
                Task { await self.corruptImportBackup(url) }
            }
        }
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            panel.beginSheetModal(for: window, completionHandler: handler)
        } else {
            panel.begin(completionHandler: handler)
        }
    }

    /// Spielt die gewählte Sicherung mit dem eingegebenen Master-Passwort ein (Faktoren nach ihrem Kopf).
    public func corruptImportBackup(_ url: URL) async {
        guard let store, !busy else { return }
        let password = corrupt.password
        guard !password.isEmpty else {
            corrupt.error = "Gib zuerst das Master-Passwort dieser Sicherung ein."
            return
        }
        corrupt.error = nil
        let state = corrupt
        // Für „Notfallcode verwenden“ nach einem nicht nutzbaren Faktor: genau diese Datei (Befund datei-3).
        state.collectionFile = url
        guard let factors = await factorsForFile(url, existing: state.collection, assign: { state.collection = $0 },
                                                 reason: "Sicherung einspielen"),
              corrupt === state else { return }
        guard let result = await heavy(writes: true, {
            try store.importBackup(from: url, masterPassword: password, factors: factors)
        }) else { return }
        state.collection?.reset()
        switch result {
        case let .success(opened):
            let datum = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
            corrupt.vault = opened
            corrupt.restoredBackup = BackupInfo(url: url, date: datum ?? Date(), generation: opened.generation,
                                                vaultID: opened.vaultID, reason: nil, isExternal: true)
            corrupt.entryCount = opened.entries.count
            corrupt.kitID = opened.kitID
            corrupt.kitConfirmed = opened.recoveryConfirmed
            corrupt.password = ""
        case .failure(.wrongPassword):
            corrupt.password = ""
            corrupt.error = countsAttempt(state.collection == nil ? "Falsches Passwort für diese Sicherung."
                                                                  : "Passwort oder ein Faktor stimmt nicht für diese Sicherung.")
            await refreshDestructionStatus()
        case let .failure(error):
            corrupt.error = Fehlertexte.text(error)
        }
    }

    /// „Notfallcode verwenden“ bei „Beschädigt“ (auch nach einem nicht nutzbaren Faktor, §14.1): Galt die
    /// Faktor-Abfrage einer gewählten Sicherungsdatei, dann genau ihr (Befund datei-3); sonst der übliche Weg.
    public func corruptUseRecovery() {
        guard screen == .corrupt, !busy else { return }
        if let datei = corrupt.collectionFile, corrupt.collection?.failure?.offerRecovery == true {
            startRecovery(file: datei)
        } else {
            startRecovery()
        }
    }

    public func finishCorruptRestore() {
        guard let opened = corrupt.vault else { return }
        corrupt.vault = nil
        open(opened)
    }

    /// Nach einer Wiederherstellung aus einer Sicherung: Gilt deren Notfallkit nicht als bestätigt (anderes Kit
    /// als zuvor oder unbekannt), ausdrücklich darauf hinweisen (Befund #3). Die Statuszeile bleibt zusätzlich.
    func noteRestoredKit() {
        guard isUnlocked, !recoveryConfirmed else { return }
        show(Notice("Diese Sicherung nutzt Notfallkit \(kitID). Prüfe, ob dein Blatt dazu passt, oder erstelle ein neues Notfallkit.",
                    symbol: "exclamationmark.circle"), seconds: 10)
    }

    /// Zurück zum Sperrbildschirm (z. B. um es später erneut zu versuchen).
    public func leaveCorrupt() {
        corrupt.vault?.lock()
        corrupt = CorruptState()
        epoch += 1
        busy = false
        route()
    }

    // MARK: Rollback-Frage

    /// „Trotzdem öffnen“: ältere Datei akzeptieren. Der RollbackGuard merkt nur steigende Werte – ein `record` mit
    /// der kleineren Generation wirkte nie (Befund #28/#33). Darum merkt die Oberfläche genau diese Datei
    /// (vaultID, Generation, SHA-256): Dieselbe Datei öffnet danach ohne Frage, jede andere ältere warnt weiter.
    /// Nach dem nächsten Speichern liegt die Generation über der Marke, die Annahme wird dann gelöscht.
    public func acceptRollback() async {
        guard let rollback, let store, !busy else { return }
        let url = store.vaultURL
        let state = rollback
        let start = epoch
        let pruefwert = await Self.background { Self.fileDigest(url) }
        guard start == epoch, self.rollback === state else { return }
        if case let .success(digest?) = pruefwert {
            settings.acceptedRollback = AcceptedRollback(vaultID: state.vault.vaultID, generation: state.fileGeneration,
                                                         digest: digest)
        }
        let opened = state.vault
        self.rollback = nil
        open(opened)
    }

    /// SHA-256 der ganzen Datei (Chiffrat, nicht geheim); nil = nicht lesbar.
    nonisolated static func fileDigest(_ url: URL) -> Data? {
        guard let daten = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        return Data(SHA256.hash(data: daten))
    }

    public func rejectRollback() {
        rollback?.vault.lock()
        rollback = nil
        go(.locked)
    }
}

/// Ergebnis eines Entsperr-Versuchs mit dem Prüfwert der Datei (nur bei angenommener älterer Datei).
struct UnlockAttemptResult: Sendable {
    let outcome: UnlockOutcome
    let digest: Data?
}
