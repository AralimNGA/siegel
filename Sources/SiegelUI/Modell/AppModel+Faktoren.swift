import AppKit
import AVFoundation
import SiegelCore
import SiegelHardware
import SwiftUI

// Faktoren einsammeln (SPEC v4 §13–§16): Touch ID über die Secure Enclave, QR-Schlüsselkarte über die Kamera
// (oder abgetippt), Sicherheitsschlüssel per Berührung. Die Oberfläche reicht die rohen Werte (32 Byte) an den
// Kern weiter und verwirft sie danach. Kamera-Sheet und Schlüssel-Sheet sind Ebenen im Hauptfenster (geschützt
// wie das Fenster, beim Sperren weg); der Touch-ID-Dialog kommt vom System.

extension AppModel {
    // MARK: Abfragen

    /// Ordner der Hardware-Ablage (Secure-Enclave-Blobs, §14.1).
    var hardwareDirectory: URL? { store?.hardwareDirectory }

    /// Läuft gerade ein Faktor-Vorgang (Touch-ID-Dialog, Kamera, Schlüssel)?
    public var factorInProgress: Bool { touchIDActive || cardScan != nil || keyTouch != nil }

    // MARK: Touch ID

    /// Fragt Touch ID ab (Entsperr- oder Prüf-Schlüssel). Blockiert nur einen Hintergrund-Thread.
    func touchID(keyID: UUID, reason: String) async throws -> FactorSecret {
        guard let directory = hardwareDirectory else { throw SiegelError.factorUnavailable(.secureEnclave) }
        let hw = hardware
        return try await factorOperation(touchID: true) {
            try hw.secureEnclaveSecret(keyID: keyID, directory: directory, reason: reason)
        }
    }

    /// Eintrags-Schlüssel mit Touch ID (für `EntryFactorProvider`).
    func touchIDEntry(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        guard let directory = hardwareDirectory else { throw SiegelError.factorUnavailable(.secureEnclave) }
        let hw = hardware
        return try await factorOperation(touchID: true) {
            try hw.secureEnclaveSharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey,
                                             directory: directory, reason: "Eintrag aufdecken")
        }
    }

    /// Führt einen blockierenden Hardware-Aufruf im Hintergrund aus. Solange er läuft, sperrt ein App-Wechsel
    /// nicht sofort (der Touch-ID-Dialog des Systems kann Siegel kurz inaktiv machen); danach wird nachgeholt.
    func factorOperation<T: Sendable>(touchID: Bool = false,
                                      _ work: @escaping @Sendable () throws -> T) async throws -> T {
        factorOperations += 1
        if touchID { touchIDActive = true }
        let result = await Self.background(work)
        if touchID { touchIDActive = false }
        factorOperations -= 1
        afterFactorOperation()
        return try result.get()
    }

    /// Nach einem Faktor-Vorgang: aufgeschobene Sperre beim App-Wechsel nachholen (Stufe 3+).
    func afterFactorOperation() {
        guard factorOperations == 0, deactivateLockPending else { return }
        deactivateLockPending = false
        if !NSApp.isActive, holdsOpenVault, policy.lockOnDeactivate { lock(reason: .deactivated) }
    }

    // MARK: Karte scannen

    /// Öffnet das Kamera-Sheet und wartet auf eine gültige Karte (oder den abgetippten Code).
    func scanCard(purpose: CardScanState.Purpose, title: String, message: String,
                  typingMessage: String = CardScanState.defaultTypingMessage,
                  expected: FactorSecret? = nil, startTyping: Bool = false) async throws -> FactorSecret {
        cancelCardScan()
        factorOperations += 1
        defer {
            factorOperations -= 1
            afterFactorOperation()
        }
        let state = CardScanState(purpose: purpose, title: title, message: message, typingMessage: typingMessage)
        state.expected = expected
        state.typing = startTyping
        return try await withCheckedThrowingContinuation { continuation in
            state.continuation = continuation
            cardScan = state
            startCamera(state)
        }
    }

    private func startCamera(_ state: CardScanState) {
        let hw = hardware
        switch hw.cameraAuthorization() {
        case .authorized:
            runScanner(state)
        case .notDetermined:
            state.camera = .starting
            Task { @MainActor [weak self, weak state] in
                let ok = await hw.requestCameraAccess()
                guard let self, let state, self.cardScan === state else { return }
                if ok { self.runScanner(state) } else { state.camera = .denied }
            }
        default:
            state.camera = .denied
        }
    }

    private func runScanner(_ state: CardScanState) {
        let scanner = hardware.makeScanner { [weak self, weak state] payload in
            guard let self, let state else { return }
            self.cardPayloadReceived(payload, state: state)
        }
        state.scanner = scanner
        do {
            if !state.typing { try scanner.start() }
            state.camera = scanner.previewLayer == nil ? .placeholder : .running
        } catch {
            state.camera = .unavailable
            state.typing = true
        }
    }

    /// Erkannter QR-Inhalt (Kamera) bzw. abgetippter Code.
    func cardPayloadReceived(_ payload: String, state: CardScanState) {
        guard cardScan === state else { return }
        let q: FactorSecret
        do {
            q = try CardCode.decode(payload)
        } catch {
            state.error = "Das ist keine Siegel-Schlüsselkarte oder der Code ist unvollständig."
            restartScanner(state)
            return
        }
        switch state.purpose {
        case let .vault(vaultID, tag):
            if let tag, CardCode.tag(for: q, vaultID: vaultID) != tag {
                state.error = Fehlertexte.text(.wrongCard)
                restartScanner(state)
                return
            }
        case .confirmNew:
            if let expected = state.expected, !Self.sameSecret(expected, q) {
                state.error = "Das ist nicht die eben erzeugte Karte. Scanne die neu gedruckte Karte."
                restartScanner(state)
                return
            }
        case .entry:
            break
        }
        state.error = nil
        state.recognized = true
        state.scanner?.stop()
        state.scanner = nil
        let continuation = state.continuation
        state.continuation = nil
        cardScan = nil
        continuation?.resume(returning: q)
    }

    /// QRScanner stoppt nach einer Erkennung: nach kurzer Pause neu starten (falsche Karte, unlesbar).
    private func restartScanner(_ state: CardScanState) {
        guard state.camera == .running || state.camera == .placeholder, let scanner = state.scanner else { return }
        scanner.stop()
        Task { @MainActor [weak self, weak state] in
            try? await Task.sleep(for: .milliseconds(900))
            guard let self, let state, self.cardScan === state, !state.typing else { return }
            try? state.scanner?.start()
        }
    }

    public func cardScanShowTyping() {
        guard let state = cardScan else { return }
        state.typing = true
        state.error = nil
        // Ohne sichtbare Vorschau keine Kamera (§14.2, PRUEFLISTE §8; Befund hardware-4): Kontrolllicht aus, keine
        // Bildauswertung im Hintergrund. „Kamera verwenden“ startet sie wieder; `camera` bleibt dabei stehen.
        state.scanner?.stop()
    }

    public func cardScanShowCamera() {
        guard let state = cardScan, state.camera != .denied, state.camera != .unavailable else { return }
        state.typing = false
        state.error = nil
        try? state.scanner?.start()
    }

    public func cardScanSubmitTyped() {
        guard let state = cardScan else { return }
        let text = state.typed
        guard RecoveryCodeFormatting.significant(text).count == 55 else {
            state.error = "Der Kartencode hat 55 Zeichen in 11 Gruppen."
            return
        }
        cardPayloadReceived(text, state: state)
    }

    /// Nur für SiegelSnapshots: Kamera-Sheet ohne Ablauf öffnen (Zustände der Kamera zeigen).
    @_spi(Snapshots) public func scanCardForSnapshot() async throws -> FactorSecret {
        try await scanCard(purpose: .entry, title: "Schlüsselkarte scannen",
                           message: "Halte deine QR-Schlüsselkarte vor die Kamera.")
    }

    /// Nur für SiegelSnapshots: Schlüssel-Sheet zum Abrufen einer Ausgabe öffnen (wie beim Entsperren in Stufe 5).
    @_spi(Snapshots) public func touchSecurityKeyForSnapshot(credentialID: Data, salt: Data) async throws -> FactorSecret {
        let result = try await touchSecurityKey(purpose: .secret(credentialID: credentialID, salt: salt),
                                                title: "Sicherheitsschlüssel",
                                                message: "Stecke deinen Sicherheitsschlüssel ein und berühre ihn.")
        guard case let .secret(secret) = result else { throw SiegelError.factorUnavailable(.securityKey) }
        return secret
    }

    /// „Abbrechen“ im Kamera-Sheet.
    public func cancelCardScan() {
        guard let state = cardScan else { return }
        state.scanner?.stop()
        state.scanner = nil
        let continuation = state.continuation
        state.continuation = nil
        cardScan = nil
        continuation?.resume(throwing: SiegelError.factorCancelled)
    }

    public func openCameraSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Camera") {
            NSWorkspace.shared.open(url)
        }
    }

    static func sameSecret(_ a: FactorSecret, _ b: FactorSecret) -> Bool {
        a.withUnsafeBytes { pa in
            b.withUnsafeBytes { pb in
                guard pa.count == pb.count else { return false }
                var diff: UInt8 = 0
                for i in 0..<pa.count { diff |= pa[i] ^ pb[i] }
                return diff == 0
            }
        }
    }

    // MARK: Sicherheitsschlüssel

    /// Öffnet das Schlüssel-Sheet: Geräteliste, „einstecken und berühren“.
    func touchSecurityKey(purpose: KeyTouchState.Purpose, title: String, message: String) async throws -> KeyTouchResult {
        cancelKeyTouch()
        factorOperations += 1
        defer {
            factorOperations -= 1
            afterFactorOperation()
        }
        let state = KeyTouchState(purpose: purpose, title: title, message: message)
        return try await withCheckedThrowingContinuation { continuation in
            state.continuation = continuation
            keyTouch = state
            pollSecurityKeys(state)
        }
    }

    /// Sucht jede Sekunde nach angeschlossenen Schlüsseln; genau einer → sofort auf Berührung warten.
    private func pollSecurityKeys(_ state: KeyTouchState) {
        let hw = hardware
        state.pollTask = Task { @MainActor [weak self, weak state] in
            while !Task.isCancelled {
                let geraete = await Task.detached { hw.securityKeys() }.value
                guard let self, let state, self.keyTouch === state else { return }
                if case .touching = state.phase {
                    // Während der Berührung nicht neu auswählen.
                } else {
                    state.devices = geraete
                    if geraete.count == 1, state.error == nil, let einziger = geraete.first {
                        self.chooseSecurityKey(einziger)
                    } else {
                        state.phase = geraete.isEmpty ? .searching : .choose
                    }
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// Schlüssel gewählt: auf die Berührung warten (blockiert einen Hintergrund-Thread, Frist im Modul).
    public func chooseSecurityKey(_ key: SecurityKeyChoice) {
        guard let state = keyTouch else { return }
        if case .touching = state.phase { return }
        state.error = nil
        state.phase = .touching(key.name)
        state.attempt += 1
        let attempt = state.attempt
        let hw = hardware
        let purpose = state.purpose
        let cancellation = SecurityKeyCancellation()
        state.cancellation = cancellation
        Task { @MainActor [weak self, weak state] in
            let result = await Self.background { () throws -> KeyTouchResult in
                switch purpose {
                case let .secret(credentialID, salt):
                    return .secret(try hw.securityKeySecret(key, credentialID: credentialID, salt: salt,
                                                            cancellation: cancellation))
                case .register:
                    return .enrollment(try hw.registerSecurityKey(key, cancellation: cancellation), name: key.name)
                }
            }
            guard let self, let state, self.keyTouch === state, state.attempt == attempt else { return }
            switch result {
            case let .success(value):
                state.pollTask?.cancel()
                let continuation = state.continuation
                state.continuation = nil
                self.keyTouch = nil
                continuation?.resume(returning: value)
            case let .failure(error):
                state.error = error == .factorCancelled
                    ? "Keine Berührung erkannt. Berühre den Schlüssel, sobald er blinkt."
                    : Fehlertexte.text(error)
                state.phase = state.devices.isEmpty ? .searching : .choose
            }
        }
    }

    /// „Erneut versuchen“ nach einer Zeitüberschreitung.
    public func retrySecurityKey() {
        guard let state = keyTouch else { return }
        if state.devices.count == 1, let einziger = state.devices.first {
            state.error = nil
            chooseSecurityKey(einziger)
        } else {
            state.error = nil
        }
    }

    public func cancelKeyTouch() {
        guard let state = keyTouch else { return }
        // Den Vorgang im Hintergrund wirklich beenden (CTAPHID_CANCEL, Verbindung zu), nicht nur das Ergebnis
        // verwerfen: sonst blinkt der Schlüssel weiter, und die nächste Berührung ginge an ihn (Befund hardware-4).
        state.cancellation?.cancel()
        state.pollTask?.cancel()
        let continuation = state.continuation
        state.continuation = nil
        keyTouch = nil
        continuation?.resume(throwing: SiegelError.factorCancelled)
    }

    // MARK: Einsammeln für einen Tresor-Kopf

    /// Sammelt alle noch fehlenden Faktoren der Reihe nach ein. false: abgebrochen, gescheitert oder gesperrt
    /// (dann steht der Grund in `collection.failure`).
    func collect(_ collection: FactorCollection, reason: String) async -> Bool {
        let start = epoch
        collection.failure = nil
        for kind in collection.kinds where collection.status[kind] != .done {
            collection.active = kind
            collection.status[kind] = .active
            do {
                let secret = try await collectOne(kind, header: collection.header, reason: reason)
                guard start == epoch else { return false }
                collection.store(secret, for: kind)
            } catch {
                guard start == epoch else { return false }
                collection.status[kind] = .failed
                collection.active = nil
                collection.failure = Self.failure(kind, error as? SiegelError ?? .factorCancelled)
                return false
            }
        }
        collection.active = nil
        return collection.isComplete
    }

    private func collectOne(_ kind: FactorKind, header: VaultHeaderInfo, reason: String) async throws -> FactorSecret {
        switch kind {
        case .secureEnclave:
            guard let keyID = header.seKeyID else { throw SiegelError.factorUnavailable(.secureEnclave) }
            return try await touchID(keyID: keyID, reason: reason)
        case .card:
            return try await scanCard(purpose: .vault(vaultID: header.vaultID, tag: header.cardTag),
                                      title: "Schlüsselkarte scannen",
                                      message: "Halte deine QR-Schlüsselkarte vor die Kamera.")
        case .securityKey:
            guard let credential = header.fidoCredentialID, let salt = header.fidoSalt else {
                throw SiegelError.factorUnavailable(.securityKey)
            }
            let result = try await touchSecurityKey(purpose: .secret(credentialID: credential, salt: salt),
                                                    title: "Sicherheitsschlüssel",
                                                    message: "Stecke deinen Sicherheitsschlüssel ein und berühre ihn.")
            guard case let .secret(secret) = result else { throw SiegelError.factorUnavailable(.securityKey) }
            return secret
        }
    }

    /// Faktoren für eine Datei einsammeln (Sicherung wiederherstellen/einspielen), nach ihrem Kopf.
    /// Ohne Faktoren: leer. nil = abgebrochen/gescheitert (Grund in der Sammlung) oder inzwischen gesperrt.
    func factorsForFile(_ url: URL, existing: FactorCollection?, assign: (FactorCollection?) -> Void,
                        reason: String) async -> FactorSecrets? {
        let start = epoch
        let result = await Self.background { try VaultStore.inspect(fileAt: url) }
        guard start == epoch else { return nil }
        guard case let .success(header) = result, !header.factors.isEmpty else {
            assign(nil)
            return FactorSecrets()
        }
        return await factors(for: header, existing: existing, assign: assign, reason: reason)
    }

    /// Aktuelle Faktoren des geöffneten Tresors für heikle Aktionen (ab Stufe 2). Ohne Faktoren: leer.
    func vaultFactors(existing: FactorCollection?, assign: (FactorCollection?) -> Void,
                      reason: String) async -> FactorSecrets? {
        guard let header = vaultHeader, !header.factors.isEmpty else {
            assign(nil)
            return FactorSecrets()
        }
        return await factors(for: header, existing: existing, assign: assign, reason: reason)
    }

    private func factors(for header: VaultHeaderInfo, existing: FactorCollection?,
                         assign: (FactorCollection?) -> Void, reason: String) async -> FactorSecrets? {
        let collection = existing.flatMap { $0.header == header ? $0 : nil } ?? FactorCollection(header: header)
        assign(collection)
        let start = epoch
        guard await collect(collection, reason: reason), start == epoch else { return nil }
        return collection.secrets
    }

    static func failure(_ kind: FactorKind, _ error: SiegelError) -> FactorFailure {
        switch error {
        case .factorCancelled:
            let text: String
            switch kind {
            case .secureEnclave: text = "Touch ID abgebrochen."
            case .card: text = "Karte scannen abgebrochen."
            case .securityKey: text = "Sicherheitsschlüssel abgebrochen."
            }
            return FactorFailure(kind: kind, message: text, offerRecovery: false, cancelled: true, temporary: false)
        case .factorUnavailable:
            // Nur wenn der Schlüssel wirklich fehlt bzw. abgelehnt wurde (§14.1, v4.4).
            return FactorFailure(kind: kind, message: Fehlertexte.text(.factorUnavailable(kind)), offerRecovery: true,
                                 cancelled: false, temporary: false)
        case .wrongSecurityKey:
            // Anderer oder zurückgesetzter Schlüssel (Befund hardware-3): wie „nicht nutzbar“, mit Notfallweg.
            return FactorFailure(kind: kind, message: Fehlertexte.text(error), offerRecovery: true, cancelled: false,
                                 temporary: false)
        case .factorTemporarilyUnavailable:
            // Touch ID gesperrt oder nicht erreichbar, Schlüssel belegt: nichts ist verloren – erneut versuchen, den
            // Notfallweg (Stufe 1, vernichtbare Einträge fallen weg) nicht anbieten (Befund hardware-1).
            return FactorFailure(kind: kind, message: Fehlertexte.text(error), offerRecovery: false, cancelled: false,
                                 temporary: true)
        default:
            return FactorFailure(kind: kind, message: Fehlertexte.text(error), offerRecovery: false, cancelled: false,
                                 temporary: false)
        }
    }

    /// Läuft die Sitzung noch, in der eine Freigabe begann (Tresor offen, kein Sperren dazwischen)? Nicht
    /// `isUnlocked`: Das Notfallkit (`.recoveryKit`) holt Freigaben bei offenem Tresor auf einem eigenen Bildschirm.
    func isCurrentSession(_ start: Int) -> Bool {
        start == epoch && vault.map { !$0.isLocked } == true
    }

    /// Bricht laufende Sheets ab (Sperren). Wartende Abläufe erhalten `factorCancelled` und prüfen `epoch`.
    func cancelFactorSheets() {
        cancelCardScan()
        cancelKeyTouch()
    }

    // MARK: Stufenregel „Touch ID vor dem Aufdecken/Kopieren“ (Stufe 3+)

    /// true, wenn das Aufdecken/Kopieren erlaubt ist (Touch ID bestanden oder keine Regel).
    func passTouchIDGate() async -> Bool {
        guard policy.touchIDBeforeReveal else { return true }
        guard let keyID = vaultHeader?.seKeyID else {
            show(Notice("Touch ID ist für diesen Tresor nicht eingerichtet.", symbol: "exclamationmark.circle"))
            return false
        }
        let start = epoch
        do {
            _ = try await touchID(keyID: keyID, reason: "Passwort aufdecken")
            return start == epoch
        } catch let error as SiegelError {
            guard start == epoch else { return false }
            if error != .factorCancelled {
                show(Notice(Fehlertexte.text(error), symbol: "exclamationmark.circle"), seconds: 6)
            }
            return false
        } catch {
            return false
        }
    }
}

/// Liefert dem Kern beim Aufdecken eines geschützten Eintrags die Faktoren (§16): Touch ID, Karte scannen,
/// Schlüssel berühren – jeder Aufruf ist eine eigene Freigabe. Gebunden an die Sitzung, in der er entstand (Befund
/// ablaeufe-4): Nach einem Sperren öffnet keine Abfrage mehr ein Sheet, startet keine Kamera und keinen
/// Touch-ID-Dialog über dem Sperrbildschirm (der Kern ruft die Faktoren nacheinander ab und prüft selbst auch).
struct UIEntryFactorProvider: EntryFactorProvider {
    let model: AppModel
    let epoch: Int

    @MainActor
    init(model: AppModel) {
        self.model = model
        epoch = model.epoch
    }

    private func requireSession() async throws {
        guard await model.isCurrentSession(epoch) else { throw SiegelError.factorCancelled }
    }

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        try await requireSession()
        return try await model.touchIDEntry(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey)
    }

    func cardSecret() async throws -> FactorSecret {
        try await requireSession()
        return try await model.scanCard(purpose: .entry, title: "Schlüsselkarte scannen",
                                        message: "Dieser Eintrag ist mit der Karte geschützt. Halte sie vor die Kamera.")
    }

    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
        try await requireSession()
        let result = try await model.touchSecurityKey(purpose: .secret(credentialID: credentialID, salt: salt),
                                                      title: "Sicherheitsschlüssel",
                                                      message: "Dieser Eintrag ist mit dem Sicherheitsschlüssel geschützt. Berühre ihn.")
        guard case let .secret(secret) = result else { throw SiegelError.factorUnavailable(.securityKey) }
        return secret
    }
}
