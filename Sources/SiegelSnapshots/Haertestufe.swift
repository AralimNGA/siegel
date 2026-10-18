import AppKit
import AVFoundation
import CoreImage
import CryptoKit
import SiegelCore
import SiegelHardware
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Härtestufe (SPEC v4 §13–§16): Sicherheitsstufen, Assistent, Entsperren mit Faktoren, Kamera- und
// Schlüssel-Sheet, Schutz pro Eintrag, Notfallcode in Teilen. Bilder ab 80. Die Hardware ist eine Attrappe:
// kein Touch-ID-Dialog, keine Kamera (Platzhalter), kein USB. Zwischenzustände (Touch ID wartet, Sheet offen)
// entstehen, indem die Attrappe an einer Schranke wartet, während der Hauptcode kurz schläft und dann rendert.

// MARK: - Hardware-Attrappe

final class DemoHardware: FactorHardware, @unchecked Sendable {
    enum TouchIDResult { case ok, cancel, unavailable, lockedOut, notReachable }
    /// Ergebnis der Berührung: ok, anderer/zurückgesetzter Schlüssel, Schlüssel belegt.
    enum KeyResult { case ok, wrongKey, busy }

    private let lock = NSLock()
    private var _touchID: TouchIDResult = .ok
    private var _keys: [SecurityKeyChoice] = [SecurityKeyChoice(name: "YubiKey 5C NFC")]
    private var _touchGate: DispatchSemaphore?
    private var _keyGate: DispatchSemaphore?
    private var _camera: AVAuthorizationStatus = .authorized
    private(set) var removedKeys: [UUID] = []

    var camera: AVAuthorizationStatus {
        get { lock.withLock { _camera } }
        set { lock.withLock { _camera = newValue } }
    }

    var touchID: TouchIDResult {
        get { lock.withLock { _touchID } }
        set { lock.withLock { _touchID = newValue } }
    }

    var keys: [SecurityKeyChoice] {
        get { lock.withLock { _keys } }
        set { lock.withLock { _keys = newValue } }
    }

    /// Touch ID wartet, bis die Schranke freigegeben wird (Bild „Finger auflegen“).
    func holdTouchID() -> DispatchSemaphore {
        let s = DispatchSemaphore(value: 0)
        lock.withLock { _touchGate = s }
        return s
    }

    func holdKey() -> DispatchSemaphore {
        let s = DispatchSemaphore(value: 0)
        lock.withLock { _keyGate = s }
        return s
    }

    private func passTouchGate() throws {
        let gate = lock.withLock { () -> DispatchSemaphore? in
            let g = _touchGate
            _touchGate = nil
            return g
        }
        if let gate { gate.wait() }
        switch touchID {
        case .ok: return
        case .cancel: throw SiegelError.factorCancelled
        case .unavailable: throw SiegelError.factorUnavailable(.secureEnclave)
        case .lockedOut: throw SiegelError.factorTemporarilyUnavailable(.secureEnclave, "se.lockout")
        case .notReachable: throw SiegelError.factorTemporarilyUnavailable(.secureEnclave, "se.notReachable")
        }
    }

    static func secret(_ parts: [Data]) -> FactorSecret {
        var h = SHA256()
        for p in parts { h.update(data: p) }
        guard let s = try? FactorSecret(copying: Array(h.finalize())) else { fatalError("demo.secret") }
        return s
    }

    static func data(_ id: UUID) -> Data { withUnsafeBytes(of: id.uuid) { Data($0) } }

    var secureEnclaveAvailable: Bool { true }

    func enrollSecureEnclave(directory: URL) throws -> SEEnrollment {
        try passTouchGate()
        let id = UUID()
        return SEEnrollment(keyID: id, secret: Self.secret([Self.data(id)]))
    }

    /// Eintrags-Schlüssel als Software-P-256 (wie der Secure Enclave: ECDH mit dem ephemeren Schlüssel des Kerns).
    private var entryKeys: [UUID: P256.KeyAgreement.PrivateKey] = [:]

    func enrollEntryKey(directory: URL) throws -> EntryKeyEnrollment {
        try passTouchGate()
        let id = UUID()
        let key = P256.KeyAgreement.PrivateKey()
        lock.withLock { entryKeys[id] = key }
        return EntryKeyEnrollment(keyID: id, publicKey: key.publicKey.x963Representation)
    }

    func secureEnclaveSecret(keyID: UUID, directory: URL, reason: String) throws -> FactorSecret {
        try passTouchGate()
        note("touchid:" + reason)
        return Self.secret([Self.data(keyID)])
    }

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data, directory: URL,
                                   reason: String) throws -> FactorSecret {
        try passTouchGate()
        guard let key = lock.withLock({ entryKeys[keyID] }) else { throw SiegelError.factorUnavailable(.secureEnclave) }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        return try shared.withUnsafeBytes { try FactorSecret(copying: $0) }
    }

    func removeSecureEnclaveKey(keyID: UUID, directory: URL) throws {
        lock.withLock { removedKeys.append(keyID) }
    }

    /// Vernichten (§23.1): Schlüssel weg, danach unbrauchbar. Der Kern ruft das über `store.destructionKeyEraser`
    /// (die Oberfläche verdrahtet es mit dieser Hardware); die Attrappe legt keine Blob-Datei an.
    private(set) var destroyedKeys: [UUID] = []

    func destroySecureEnclaveKey(keyID: UUID, directory: URL) throws {
        lock.withLock {
            destroyedKeys.append(keyID)
            entryKeys[keyID] = nil
        }
    }

    /// Anzahl der angelegten Eintrags-Schlüssel (neuer Vernichtungs-Schlüssel V).
    var entryKeyCount: Int { lock.withLock { entryKeys.count } }

    /// Reihenfolge der Faktor-Abfragen (gleiche Abfolge bei echtem und Vernichtungs-Passwort, §23.2).
    private var _log: [String] = []
    var log: [String] { lock.withLock { _log } }
    func note(_ text: String) { lock.withLock { _log.append(text) } }
    func clearLog() { lock.withLock { _log = [] } }

    func cardImage(payload: String, pixels: Int) -> CGImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(payload.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let out = filter.outputImage else { return nil }
        let scale = CGFloat(pixels) / out.extent.width
        let scaled = out.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        return CIContext().createCGImage(scaled, from: scaled.extent)
    }

    @MainActor func cameraAuthorization() -> AVAuthorizationStatus { camera }
    @MainActor func requestCameraAccess() async -> Bool { true }

    @MainActor func makeScanner(onPayload: @escaping @MainActor (String) -> Void) -> any CardScanning {
        let scanner = DemoScanner(onPayload: onPayload)
        note("karte")
        DemoScanner.current = scanner
        return scanner
    }

    func securityKeys() -> [SecurityKeyChoice] { keys }

    static func output(_ credential: Data, _ salt: Data) -> FactorSecret {
        let mac = HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: credential))
        guard let s = try? FactorSecret(copying: Array(mac)) else { fatalError("demo.output") }
        return s
    }

    private var _keyResult: KeyResult = .ok
    var keyResult: KeyResult {
        get { lock.withLock { _keyResult } }
        set { lock.withLock { _keyResult = newValue } }
    }
    /// Abbruch-Token des letzten Versuchs und Zahl der Versuche, die über das Token endeten (Befund hardware-4).
    private var _lastCancellation: SecurityKeyCancellation?
    private var _cancelledTouches = 0
    var lastCancellation: SecurityKeyCancellation? { lock.withLock { _lastCancellation } }
    var cancelledTouches: Int { lock.withLock { _cancelledTouches } }

    /// Wartet an der Schranke wie ein echter Schlüssel auf die Berührung; das Abbruch-Token beendet das Warten
    /// (wie CTAPHID_CANCEL), sonst liefe der Vorgang verwaist weiter.
    private func passKeyGate(_ cancellation: SecurityKeyCancellation) throws {
        let gate = lock.withLock { () -> DispatchSemaphore? in
            _lastCancellation = cancellation
            let g = _keyGate
            _keyGate = nil
            return g
        }
        if let gate {
            while gate.wait(timeout: .now() + .milliseconds(20)) == .timedOut {
                if cancellation.isCancelled {
                    lock.withLock { _cancelledTouches += 1 }
                    throw SiegelError.factorCancelled
                }
            }
        }
        switch keyResult {
        case .ok: return
        case .wrongKey: throw SiegelError.wrongSecurityKey
        case .busy: throw SiegelError.factorTemporarilyUnavailable(.securityKey, "fido.busy")
        }
    }

    func registerSecurityKey(_ key: SecurityKeyChoice, cancellation: SecurityKeyCancellation) throws -> SecurityKeyEnrollment {
        try passKeyGate(cancellation)
        let credential = Data((0..<48).map { _ in UInt8.random(in: 0...255) })
        let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let entrySalt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        return SecurityKeyEnrollment(credentialID: credential, salt: salt, output: Self.output(credential, salt),
                                     entrySalt: entrySalt, entryOutput: Self.output(credential, entrySalt))
    }

    func securityKeySecret(_ key: SecurityKeyChoice, credentialID: Data, salt: Data,
                           cancellation: SecurityKeyCancellation) throws -> FactorSecret {
        try passKeyGate(cancellation)
        return Self.output(credentialID, salt)
    }
}

/// Scanner ohne Kamera: liefert, was die Snapshots über `deliver` hineingeben.
@MainActor
final class DemoScanner: CardScanning {
    static weak var current: DemoScanner?
    /// Attrappe eines Kamerabilds für die nächsten Scanner (Befund hygiene-4); nil = Platzhalter wie ohne Kamera.
    static var vorschau: CALayer?
    private let onPayload: @MainActor (String) -> Void
    private let preview: CALayer?
    private(set) var running = false

    init(onPayload: @escaping @MainActor (String) -> Void) {
        self.onPayload = onPayload
        self.preview = Self.vorschau
    }

    func start() throws { running = true }
    func stop() { running = false }
    var previewLayer: CALayer? { preview }

    func deliver(_ payload: String) {
        onPayload(payload)
    }
}

@MainActor
func warte(_ sekunden: Double) async {
    try? await Task.sleep(for: .seconds(sekunden))
}

/// Wartet, bis eine Bedingung gilt (höchstens `max` Sekunden), und gibt dem Main-Actor dabei Zeit.
@MainActor
func warteBis(_ max: Double = 20, _ bedingung: () -> Bool) async -> Bool {
    let ende = Date().addingTimeInterval(max)
    while !bedingung() {
        if Date() > ende { return false }
        try? await Task.sleep(for: .milliseconds(40))
    }
    return true
}

// MARK: - Abläufe

@MainActor
func haertestufeSnapshots() async {
    let demo = DemoHardware()
    let (model, _) = makeModel("haertestufe")
    model.snapshotUseHardware(demo)
    model.setup.passphrase = Demodaten.passphrase
    model.setup.passphraseRepeat = Demodaten.passphrase
    await model.createVault()
    if let kit = model.kit {
        let gruppen = kit.pending.code.groups
        kit.confirmation = kit.pending.confirmationGroups.map { gruppen[$0] }
    }
    await model.kitConfirm()
    let importiert = await model.performReturning { try $0.importEntries(Demodaten.entries()) }
    if case let .success(r) = importiert { check(r.added == Demodaten.entries().count, "v4: Demo-Import") }
    model.settings.lastExternalBackupAt = Date()
    check(model.level == .standard && model.vaultHeader?.factors.isEmpty == true, "v4: neuer Tresor = Stufe 1")

    // Fehlertexte für die neuen Fälle: deutsch, ohne Codes
    for fehler: SiegelError in [.factorMissing(.card), .factorUnavailable(.secureEnclave), .factorUnavailable(.securityKey),
                                .factorCancelled, .wrongCard, .notAllowedAtLevel, .totpInvalid("totp.base32"),
                                .factorTemporarilyUnavailable(.secureEnclave, "se.lockout"),
                                .factorTemporarilyUnavailable(.secureEnclave, "se.notReachable"),
                                .factorTemporarilyUnavailable(.securityKey, "fido.busy"),
                                .factorTemporarilyUnavailable(.card, "unbekannt"), .wrongSecurityKey] {
        let text = Fehlertexte.text(fehler)
        check(!text.isEmpty && !text.contains("totp.") && !text.contains("factor") && !text.contains("se.")
              && !text.contains("fido.") && !text.contains("unbekannt"), "Fehlertext ohne Code: \(text)")
    }
    // Befund hardware-1/-3: Vorübergehendes schickt nicht zum Notfallcode, der PIN-Satz gehört nicht zum fremden Schlüssel.
    check(!Fehlertexte.text(.factorTemporarilyUnavailable(.secureEnclave, "se.lockout")).contains("Notfallcode")
          && !Fehlertexte.text(.factorTemporarilyUnavailable(.secureEnclave, "se.notReachable")).contains("Notfallcode")
          && !Fehlertexte.text(.factorTemporarilyUnavailable(.secureEnclave, "se.lockout")).contains("Fingerabdrücke"),
          "hardware-1: Sperre/Deckel ohne Notfallcode-Hinweis")
    check(!Fehlertexte.wrongSecurityKey.contains("PIN"), "hardware-3: fremder Schlüssel ohne PIN-Hinweis")

    // MARK: Einstellungen und Stufen-Übersicht
    model.openSettings()
    model.settingsState.fileVaultEncrypted = true
    shot("80-einstellungen-sicherheitsstufe", model, size: CGSize(width: 920, height: 900))
    model.showSecurityLevels()
    check(model.settingsState.page == .securityLevel, "Sicherheitsstufe → Übersicht")
    model.settingsState.chosenLevel = .maximal
    shot("81-sicherheitsstufen", model, size: CGSize(width: 920, height: 1080))
    // Befund design-6: Tabelle und Detailbox nennen beide gesperrten Exporte (auch KeePass ist verschlüsselt, also kein
    // „Klartext“), gebunden an beide Regeln.
    check(LevelTextsProbe.rules(.maximal) == "Wie Hoch, dazu die QR-Schlüsselkarte. Kein CSV- und KeePass-Export."
          && !SecurityLevel.allCases.contains { LevelTextsProbe.rules($0).contains("Klartext") },
          "design-6: Stufe Maximal sperrt CSV- und KeePass-Export (Tabelle)")
    check(SecurityLevel.allCases.allSatisfy { stufe in
        let p = stufe.policy
        let gesperrt = LevelTextsProbe.rulesLong(stufe).contains("Kein CSV- und KeePass-Export")
        return gesperrt == (!p.allowCSVExport && !p.allowKeePassExport)
    }, "design-6: Detailbox folgt beiden Export-Regeln")

    // MARK: Assistent 1 → 4
    model.startLevelChange(to: .maximal)
    guard let wizard = model.wizard else {
        check(false, "Assistent fehlt")
        return
    }
    check(wizard.steps == [.intro, .verify, .touchID, .card, .recovery, .apply, .done], "Schritte 1 → 4")
    shot("82-assistent-vergleich", model, size: CGSize(width: 920, height: 760))
    model.wizardAdvance()
    wizard.password = "falsch-falsch-falsch"
    await model.wizardVerify()
    check(wizard.step == .verify && wizard.error != nil && wizard.password.isEmpty, "Assistent: falsches Passwort")
    wizard.password = Demodaten.masterPassword
    shot("83-assistent-bestaetigen", model)
    await model.wizardVerify()
    check(wizard.verified && wizard.step == .touchID, "Assistent: Passwort bestätigt → Touch ID")
    shot("84-assistent-touchid", model)
    // Befund design-7: „die Secure Enclave“ (wie Apple), nicht „im/den/dem Secure Enclave“ – in allen sichtbaren Sätzen.
    let enclave = LevelTextsProbe.secureEnclaveTexts
    check(enclave.allSatisfy { $0.contains("der Secure Enclave") || $0.contains("die Secure Enclave") }
          && !enclave.contains { t in ["im Secure", "den Secure", "dem Secure", "Der Secure"].contains { t.contains($0) } },
          "design-7: „in der/die Secure Enclave“")

    let touchSchranke = demo.holdTouchID()
    let einrichten = Task { await model.wizardSetupTouchID() }
    await warte(0.3)
    check(model.touchIDActive, "Touch ID wartet")
    shot("84b-assistent-touchid-laeuft", model)
    touchSchranke.signal()
    await einrichten.value
    check(wizard.touchIDDone, "Touch ID eingerichtet")
    model.wizardAdvance()
    check(wizard.step == .card && !wizard.cardText.isEmpty, "Karte erzeugt")
    let karte = wizard.cardText
    shot("85-assistent-karte", model, size: CGSize(width: 920, height: 760))
    model.wizardCardHandwritten()

    let scan = Task { await model.wizardScanCard() }
    _ = await warteBis { model.cardScan != nil }
    shot("86-karte-scannen", model)
    DemoScanner.current?.deliver(CardCode.payload(for: CardCode.generate()))
    check(model.cardScan?.error != nil, "Fremde Karte → Hinweis im Sheet")
    shot("86b-karte-falsch", model)
    // Nach der fremden Karte startet der Scanner nach kurzer Pause neu.
    check(await warteBis(5) { DemoScanner.current?.running == true }, "Kamera läuft im Sheet")
    model.cardScanShowTyping()
    // Befund hardware-4: Beim Abtippen ist keine Vorschau zu sehen, also läuft auch keine Kamera (Kontrolllicht aus).
    check(DemoScanner.current?.running == false, "hardware-4: Abtippen stoppt die Kamera")
    check(model.cardScan?.typingMessage == CardScanState.defaultTypingMessage, "design-4: Abtippen einer Karte → Kartentext")
    // Befund design-4: Von Hand abgeschrieben öffnet „Code zur Bestätigung abtippen…“ das Sheet direkt im Abtipp-Modus
    // (wie der Knopf im Assistenten). Die Kopfzeile spricht von der Abschrift, nicht von einer Karte mit QR-Code; das
    // Feld heisst neutral „Kartencode“ (früher „unter dem QR-Code“, die Karte hat ihn daneben).
    model.cancelCardScan()
    await scan.value
    check(model.wizard?.cardMethod == .handwritten && wizard.error == nil && model.cardScan == nil,
          "design-4: Kamera-Sheet abgebrochen, von Hand abgeschrieben")
    let abtippen = Task { await model.wizardScanCard(typing: true) }
    _ = await warteBis { model.cardScan != nil }
    check(model.cardScan?.typing == true && DemoScanner.current?.running == false, "design-4: Sheet im Abtipp-Modus")
    model.cardScan?.typed = String(karte.prefix(23))
    check(model.cardScan?.typingMessage.hasPrefix("Tippe den Code ab, den du eben notiert hast") == true
          && model.cardScan?.typingMessage.contains("QR-Code") == false,
          "design-4: Abtippen nach der Abschrift – eigene Kopfzeile ohne Karte mit QR-Code")
    shot("86c-karte-abtippen", model)
    model.cardScanShowCamera()
    check(DemoScanner.current?.running == true, "hardware-4: „Kamera verwenden“ startet sie wieder")
    check(model.cardScan?.message.hasPrefix("Halte die eben gedruckte Karte vor die Kamera") == true,
          "design-4: im Kamera-Modus der Kameratext (nicht „Tippe den Code ab“)")
    DemoScanner.current?.deliver(karte)
    await abtippen.value
    check(wizard.cardConfirmed && model.cardScan == nil, "Karte bestätigt")
    model.wizardAdvance()
    check(wizard.step == .recovery, "→ Notfallkit in Teilen")
    shot("87-assistent-notfallkit", model)

    await model.wizardShowRecoveryKit()
    guard let kit = model.kit, kit.isShared else {
        check(false, "Teile fehlen")
        return
    }
    let teile = kit.pending.shares.map(\.formatted)
    check(teile.count == 3, "Drei Teile")
    shot("88-teile-1", model, size: CGSize(width: 920, height: 760))
    model.kitChooseHandwritten()
    shot("88b-teile-1-notiert", model, size: CGSize(width: 920, height: 760))
    model.kitShowShare(1)
    model.kitChooseHandwritten()
    model.kitShowShare(2)
    model.kitChooseHandwritten()
    check(kit.allSharesRecorded, "Alle Teile festgehalten")
    shot("88c-teile-alle", model, size: CGSize(width: 920, height: 760))
    model.kitProceedToConfirm()
    check(kit.confirmation.count == 3, "Drei Bestätigungsfelder")
    shot("89-teile-bestaetigen", model)
    kit.confirmation = ["AAAAA", "BBBBB", "CCCCC"]
    await model.kitConfirm()
    check(kit.error != nil, "Falsche Gruppen der Teile → Fehler")
    kit.confirmation = kit.pending.shares.enumerated().map { k, share in share.groups[kit.pending.shareConfirmationGroups[k]] }
    await model.kitConfirm()
    check(wizard.recoveryConfirmed && wizard.step == .apply && model.screen == .unlocked, "Teile bestätigt → Zusammenfassung")
    shot("90-assistent-zusammenfassung", model)
    await model.wizardApply()
    check(model.level == .maximal && wizard.step == .done, "Stufe 4 aktiv")
    check(model.vaultHeader?.factors == [.secureEnclave, .card], "Kopf verlangt Touch ID + Karte")
    check(model.vaultHeader?.recoveryScheme == .shamir2of3, "Notfall: 2 aus 3")
    check(model.enrolledFactors.contains(.secureEnclave) && model.enrolledFactors.contains(.card), "Einträge: Touch ID + Karte")
    shot("91-assistent-fertig", model)
    await model.wizardFinish(removeOldBackups: false)
    check(model.wizard == nil && model.settingsState.page == .overview, "Assistent fertig → Übersicht")

    // Regeln der Stufe
    model.settings.clipboardSeconds = 30
    model.settings.autoLockMinutes = 5
    check(model.effectiveClipboardSeconds() == 15, "Stufe 4: Zwischenablage 15 s")
    check(model.effectiveAutoLockMinutes == 2, "Stufe 4: Auto-Sperre 2 Min.")
    check(!model.policy.allowCSVExport && model.policy.lockOnDeactivate && model.policy.touchIDBeforeReveal, "Stufe 4: Regeln")
    check(model.kdfFixedByLevel, "Stufe 4: Profil fest")
    model.request(.csvExport)
    check(model.pendingFlow == nil, "Stufe 4: CSV-Export gesperrt")
    check(model.effectiveDefaultProtection == .fingerabdruck, "Stufe 4: neue Einträge Schutz 2")
    model.settingsState.fileVaultEncrypted = true
    shot("92-einstellungen-stufe-maximal", model, size: CGSize(width: 920, height: 2180))
    model.settingsShow(.newKit)
    model.settingsState.currentPassword = Demodaten.masterPassword
    shot("92b-einstellungen-neues-kit-faktoren", model)
    model.closeSettings()

    // Kamera nicht erlaubt: Hinweis + Abtippen
    demo.camera = .denied
    let verweigert = Task { () -> Bool in
        (try? await model.scanCardForSnapshot()) != nil
    }
    _ = await warteBis { model.cardScan != nil }
    check(model.cardScan?.camera == .denied, "Kamera verweigert erkannt")
    shot("92c-karte-kamera-verweigert", model)
    model.cancelCardScan()
    _ = await verweigert.value
    demo.camera = .authorized

    // MARK: Entsperren mit Faktoren
    model.lock()
    _ = await warteBis { model.unlock.header != nil }
    check(model.unlock.factors == [.secureEnclave, .card], "Sperrbildschirm kennt die Faktoren")
    shot("93-gesperrt-faktoren", model)

    model.unlock.password = Demodaten.masterPassword
    var schranke = demo.holdTouchID()
    var entsperren = Task { await model.submitUnlock() }
    _ = await warteBis { model.touchIDActive }
    shot("94-gesperrt-touchid", model)
    schranke.signal()
    _ = await warteBis { model.cardScan != nil }
    shot("95-gesperrt-karte", model)
    DemoScanner.current?.deliver(CardCode.payload(for: CardCode.generate()))
    check(model.cardScan?.error == Fehlertexte.text(.wrongCard), "Falsche Karte erkannt (Karten-Kennung)")
    shot("95b-gesperrt-falsche-karte", model)
    model.cancelCardScan()
    await entsperren.value
    check(model.unlock.collection?.failure?.cancelled == true, "Karte abgebrochen → Hinweis")
    check(model.unlock.collection?.status[.secureEnclave] == .done, "Touch ID bleibt erledigt")
    shot("96-gesperrt-karte-abgebrochen", model)

    entsperren = Task { await model.retryUnlockFactors() }
    _ = await warteBis { model.cardScan != nil }
    DemoScanner.current?.deliver(karte)
    _ = await warteBis { model.busy && model.cardScan == nil }
    shot("97-gesperrt-oeffnen", model)
    await entsperren.value
    check(model.screen == .unlocked && model.level == .maximal, "Entsperrt mit Touch ID + Karte")

    // Touch ID nicht verfügbar → Notfallweg; abgebrochen → erneut versuchen
    model.lock()
    _ = await warteBis { model.unlock.header != nil }
    demo.touchID = .unavailable
    model.unlock.password = Demodaten.masterPassword
    await model.submitUnlock()
    check(model.unlock.collection?.failure?.offerRecovery == true, "Touch ID nicht verfügbar → Notfallweg angeboten")
    shot("98-gesperrt-touchid-nicht-verfuegbar", model)
    demo.touchID = .cancel
    await model.retryUnlockFactors()
    check(model.unlock.collection?.failure?.cancelled == true, "Touch ID abgebrochen")
    shot("98b-gesperrt-touchid-abgebrochen", model)
    // Befund hardware-1: Sperre nach Fehlversuchen bzw. zugeklappter Deckel sind vorübergehend – kein Notfallweg
    // (er setzte auf Stufe 1 zurück und liesse vernichtbare Einträge wegfallen), „Erneut versuchen“ als Hauptknopf.
    for (zustand, code, bild) in [(DemoHardware.TouchIDResult.lockedOut, "se.lockout", "98c-gesperrt-touchid-sperre"),
                                  (.notReachable, "se.notReachable", "98d-gesperrt-touchid-unerreichbar")] {
        demo.touchID = zustand
        await model.retryUnlockFactors()
        let f = model.unlock.collection?.failure
        check(f?.offerRecovery == false && f?.temporary == true && f?.cancelled == false
              && f?.message == Fehlertexte.text(.factorTemporarilyUnavailable(.secureEnclave, code))
              && f?.message.contains("Notfallcode") == false,
              "hardware-1: \(code) → erneut versuchen, kein Notfallweg")
        shot(bild, model)
    }
    demo.touchID = .ok
    entsperren = Task { await model.retryUnlockFactors() }
    _ = await warteBis { model.cardScan != nil }
    DemoScanner.current?.deliver(karte)
    await entsperren.value
    check(model.screen == .unlocked, "Danach entsperrt")

    // MARK: Schutz pro Eintrag
    model.newEntry()
    guard let editor = model.browser.editor else {
        check(false, "Editor fehlt")
        return
    }
    check(editor.draft.protection == .fingerabdruck, "Neuer Eintrag in Stufe 4: Schutz 2")
    editor.draft.title = "Krypto-Börse"
    editor.draft.username = "lena.muster"
    editor.draft.password = "Wb7#nQ2!zLm8xR4v"
    editor.draft.url = "https://boerse.example"
    editor.draft.notes = "Wiederherstellungswörter im Bankfach"
    editor.draft.protection = .festung
    shot("99-eintrag-schutz-fehlt", model, size: CGSize(width: 920, height: 1000))
    schutzTextePassenInDieSpalte()
    await model.saveEdit()
    check(editor.error != nil && model.browser.mode == .edit, "Schutz 5 ohne Schlüssel → nicht gespeichert")
    editor.error = nil
    editor.draft.protection = .maximal
    shot("100-eintrag-neu-schutz", model, size: CGSize(width: 920, height: 1000))
    await model.saveEdit()
    guard let boerse = model.entries.first(where: { $0.title == "Krypto-Börse" }) else {
        check(false, "Geschützter Eintrag fehlt")
        return
    }
    check(boerse.protection == .maximal && boerse.secretsSealed && boerse.password.isEmpty, "Versiegelt gespeichert")
    model.select(boerse.id)
    shot("101-detail-geschuetzt", model)

    schranke = demo.holdTouchID()
    let aufdecken = Task { await model.revealEntry(boerse) }
    _ = await warteBis { model.touchIDActive }
    shot("102-detail-aufdecken-touchid", model)
    schranke.signal()
    _ = await warteBis { model.cardScan != nil }
    shot("103-detail-aufdecken-karte", model)
    DemoScanner.current?.deliver(karte)
    await aufdecken.value
    check(model.visibleSecrets(boerse)?.password == "Wb7#nQ2!zLm8xR4v", "Aufgedeckt über Provider")
    shot("104-detail-aufgedeckt", model)

    // Bearbeiten: Geheimteile gesperrt, Titel ohne Faktoren
    model.hideEntrySecrets()
    model.editSelected()
    check(model.browser.editor?.secretsLocked == true, "Bearbeiten: versiegelt gesperrt")
    shot("105-bearbeiten-versiegelt", model, size: CGSize(width: 920, height: 800))
    model.browser.editor?.draft.title = "Krypto-Börse (Hauptkonto)"
    await model.saveEdit()
    let umbenannt = model.entries.first { $0.id == boerse.id }
    check(umbenannt?.title == "Krypto-Börse (Hauptkonto)" && umbenannt?.secretsSealed == true, "Umbenennen ohne Faktoren")

    // Liste mit Kennzeichnung, offener Eintrag in Stufe 4 (Touch ID vor dem Aufdecken)
    if let bank = model.entries.first(where: { $0.title == "Beispiel Bank" }) {
        model.select(bank.id)
        check(model.needsReveal(bank) && model.visibleSecrets(bank) == nil, "Stufe 4: auch offene Einträge erst aufdecken")
        shot("106-liste-schutz-stufe", model)
        // Nebenbefund hardware-1: Die Stufenregel nennt bei gesperrtem Touch ID die Sperre, nicht „Fingerabdrücke
        // geändert“.
        demo.touchID = .lockedOut
        await model.revealEntry(bank)
        check(model.visibleSecrets(bank) == nil
              && model.notice?.text == Fehlertexte.text(.factorTemporarilyUnavailable(.secureEnclave, "se.lockout")),
              "hardware-1: Stufenregel bei Sperre → Sperr-Hinweis")
        model.notice = nil
        demo.touchID = .ok
        await model.revealEntry(bank)
        check(model.visibleSecrets(bank)?.password == bank.password, "Stufe 4: Touch ID genügt für Schutz 1")
    }

    // Einrichten aus der Bearbeitung: Sicherheitsschlüssel für Schutz 5
    model.select(boerse.id)
    let aufdecken2 = Task { await model.revealEntry(boerse) }
    _ = await warteBis { model.cardScan != nil }
    DemoScanner.current?.deliver(karte)
    await aufdecken2.value
    model.editSelected()
    check(model.browser.editor?.secretsLocked == false, "Bearbeiten übernimmt aufgedeckte Geheimteile")
    model.browser.editor?.draft.protection = .festung
    model.enrollForEditor()
    guard let einrichtung = model.wizard else {
        check(false, "Einrichten fehlt")
        return
    }
    check(einrichtung.mode == .enroll(.securityKey) && einrichtung.returnsToEditor, "Einrichten: Schlüssel, zurück zum Eintrag")
    // Befund ablaeufe-7: Der Assistent ist sichtbar (früher lag er unsichtbar im Modell, die Bilder zeigten den Editor).
    check(model.showsSettings && model.settingsState.page == .wizard && model.browser.mode == .edit,
          "ablaeufe-7: „Jetzt einrichten…“ zeigt den Assistenten, die Bearbeitung bleibt dahinter")
    einrichtung.password = Demodaten.masterPassword
    shot("107-einrichten-bestaetigen", model)
    let bestaetigen = Task { await model.wizardVerify() }
    _ = await warteBis { model.cardScan != nil }
    DemoScanner.current?.deliver(karte)
    await bestaetigen.value
    check(einrichtung.step == .securityKey, "Einrichten: → Schlüssel")
    shot("108-einrichten-schluessel", model)

    demo.keys = []
    let registrieren = Task { await model.wizardRegisterKey() }
    _ = await warteBis { model.keyTouch != nil }
    await warte(0.2)
    shot("109-schluessel-suchen", model)
    demo.keys = [SecurityKeyChoice(name: "YubiKey 5C NFC"), SecurityKeyChoice(name: "SoloKey 2")]
    _ = await warteBis { model.keyTouch?.phase == .choose }
    shot("110-schluessel-auswahl", model)
    let keySchranke = demo.holdKey()
    model.chooseSecurityKey(SecurityKeyChoice(name: "YubiKey 5C NFC"))
    await warte(0.2)
    shot("111-schluessel-beruehren", model)
    // Befund hardware-4: belegter Schlüssel mit eigener Meldung (nicht „verlangt eine PIN-Prüfung“).
    demo.keyResult = .busy
    keySchranke.signal()
    _ = await warteBis { model.keyTouch?.error != nil }
    check(model.keyTouch?.error == Fehlertexte.text(.factorTemporarilyUnavailable(.securityKey, "fido.busy"))
          && model.keyTouch?.error?.contains("PIN") == false,
          "hardware-4: Schlüssel belegt → eigene Meldung")
    shot("111b-schluessel-belegt", model)
    demo.keyResult = .ok
    // Befund hardware-4: „Abbrechen“ (und Sperren) beendet den wartenden Vorgang über das Abbruch-Token, statt ihn bis
    // zur Berührung oder 30 s weiterlaufen zu lassen (die nächste Berührung ginge sonst an ihn).
    let vorher = demo.lastCancellation
    let abbruchSchranke = demo.holdKey()
    model.chooseSecurityKey(SecurityKeyChoice(name: "YubiKey 5C NFC"))
    _ = await warteBis { demo.lastCancellation !== vorher }
    let token = demo.lastCancellation
    check(token?.isCancelled == false, "hardware-4: Token pro Versuch, noch nicht abgebrochen")
    model.cancelKeyTouch()
    await registrieren.value
    check(token?.isCancelled == true, "hardware-4: Abbrechen setzt das Abbruch-Token")
    check(await warteBis(5) { demo.cancelledTouches == 1 }, "hardware-4: Vorgang im Hintergrund beendet")
    abbruchSchranke.signal()
    let registrierenNeu = Task { await model.wizardRegisterKey() }
    _ = await warteBis { model.keyTouch?.phase == .choose }
    model.chooseSecurityKey(SecurityKeyChoice(name: "YubiKey 5C NFC"))
    await registrierenNeu.value
    check(einrichtung.keyName == "YubiKey 5C NFC", "Schlüssel registriert")
    model.wizardAdvance()
    await model.wizardApply()
    check(model.enrolledFactors.contains(.securityKey) && einrichtung.step == .done, "Schlüssel für Einträge eingerichtet")
    shot("112-einrichten-fertig", model)
    // ablaeufe-7: drei verschiedene Schritte des Assistenten, nicht dreimal der Editor
    let einrichtenBilder = ["107-einrichten-bestaetigen", "108-einrichten-schluessel", "112-einrichten-fertig"]
        .map { try? Data(contentsOf: ziel.appendingPathComponent($0 + ".png")) }
    check(Set(einrichtenBilder.compactMap { $0 }).count == 3, "ablaeufe-7: Bilder 107, 108 und 112 unterscheiden sich")
    await model.wizardFinish(removeOldBackups: false)
    check(!model.showsSettings && model.browser.mode == .edit && model.browser.editor?.draft.protection == .festung,
          "Zurück zum Eintrag mit Entwurf")
    shot("113-bearbeiten-schutz-5", model, size: CGSize(width: 920, height: 1000))
    await model.cancelEdit()

    // Befund hardware-3: Beim Abrufen steckt ein anderer (Ersatz-)Schlüssel → „nicht der Schlüssel dieses Tresors“
    // mit Hinweis auf das Zurücksetzen, nicht „verlangt eine PIN-Prüfung“.
    let alleSchluessel = demo.keys
    demo.keys = [SecurityKeyChoice(name: "YubiKey 5C NFC (Ersatz)")]
    demo.keyResult = .wrongKey
    let fremd = Task { try? await model.touchSecurityKeyForSnapshot(credentialID: Data(repeating: 7, count: 48),
                                                                   salt: Data(repeating: 9, count: 32)) }
    check(await warteBis { model.keyTouch?.error != nil }, "hardware-3: Fehler im Schlüssel-Sheet")
    check(model.keyTouch?.error == Fehlertexte.wrongSecurityKey && model.keyTouch?.error?.contains("PIN") == false,
          "hardware-3: anderer Schlüssel → „nicht der Schlüssel dieses Tresors“")
    shot("113c-schluessel-fremd", model)
    model.cancelKeyTouch()
    _ = await fremd.value
    demo.keyResult = .ok
    demo.keys = alleSchluessel

    // Befund design-3: Die Sicherung ist eine Kopie der Datei – in Stufe 4 verlangt sie Touch ID dieses Macs und die
    // Karte, auf einem anderen Mac öffnen sie nur zwei der drei Teile. Der Text sagt das (früher: „Master-Passwort oder
    // Notfallcode“ und „übersteht einen verlorenen Mac“ in jeder Stufe).
    model.request(.backupExport)
    check(model.flowState?.step == .backupExportIntro, "design-3: Sicherung exportieren in Stufe 4")
    let kopf = model.vaultHeader
    let stufenText = BackupTexts.exportIntro(factors: kopf?.factors ?? [], scheme: kopf?.recoveryScheme ?? .single)
    check(stufenText.contains("dazu Touch ID dieses Macs und die Schlüsselkarte.")
          && stufenText.contains("Auf einem anderen Mac öffnen sie nur zwei der drei Teile des Notfallkits")
          && !stufenText.contains("Master-Passwort oder"),
          "design-3: Exporttext nach Stufe 4 (Touch ID, Karte, zwei Teile)")
    check(BackupTexts.exportHint(factors: kopf?.factors ?? []).contains("zusammen mit deinem Notfallkit"),
          "design-3: verlorener Mac nur mit dem Notfallkit")
    check(BackupTexts.exportIntro(factors: [], scheme: .single)
            == "Eine Kopie der Tresordatei, verschlüsselt wie der Tresor. Sie öffnet sich mit dem Master-Passwort oder dem Notfallcode, die beim Sichern gelten."
          && BackupTexts.exportIntro(factors: [.secureEnclave], scheme: .single)
            .hasSuffix("dazu Touch ID dieses Macs. Auf einem anderen Mac öffnet sie nur der Notfallcode, der beim Sichern gilt.")
          && BackupTexts.exportIntro(factors: [.secureEnclave, .card, .securityKey], scheme: .shamir2of3)
            .contains("dazu Touch ID dieses Macs, die Schlüsselkarte und den Sicherheitsschlüssel."),
          "design-3: Texte der Stufen 1, 2/3 und 5")
    shot("68b-sicherung-exportieren-stufe4", model) { messung in
        check(messung.rahmen["flow.backupExportHint"] != nil, "design-3: Seite „Sicherung exportieren“ gezeigt")
    }
    model.finishFlow()

    // MARK: Notfallcode in Teilen prüfen (Einstellungen, Stufe 4/5)
    model.openSettings()
    model.settingsShow(.checkCode)
    check(model.settingsUsesShares, "Einstellungen: Kit in Teilen erkannt")
    model.settingsState.shares = [teile[2], teile[0]]
    await model.checkRecoverySharesInSettings()
    check(model.settingsState.shareResult == [.exact, .exact] && model.settingsState.error == nil,
          "Einstellungen: zwei Teile passen")
    shot("113b-einstellungen-teile-pruefen", model)
    model.settingsState.shares = ["", ""]
    model.settingsState.shareResult = nil

    // MARK: Neues Kit mit versiegelten Einträgen (§16): Notfall-Gruppen ans neue Kit, je Gruppe eine Freigabe
    model.settingsShow(.newKit)
    model.settingsState.currentPassword = Demodaten.masterPassword
    let neuesKit = Task { await model.prepareNewRecoveryKit() }
    _ = await warteBis { model.cardScan != nil }
    DemoScanner.current?.deliver(karte)
    await neuesKit.value
    var aktuelleTeile = teile
    if let neu = model.kit, neu.isShared, neu.origin == .newKit {
        for teil in 0..<3 {
            model.kitShowShare(teil)
            model.kitChooseHandwritten()
        }
        model.kitProceedToConfirm()
        neu.confirmation = neu.pending.shares.enumerated().map { k, share in
            share.groups[neu.pending.shareConfirmationGroups[k]]
        }
        let schreiben = Task { await model.kitConfirm() }
        // Freigabe der Gruppe {Touch ID, Karte} (Krypto-Börse, Schutz 4): Touch ID läuft durch, Karte scannen
        check(await warteBis { model.cardScan != nil }, "Neues Kit: Freigabe verlangt die Karte")
        DemoScanner.current?.deliver(karte)
        await schreiben.value
        check(neu.error == nil && neu.step == .purgeQuestion, "Neues Kit mit versiegelten Einträgen geschrieben")
        aktuelleTeile = neu.pending.shares.map(\.formatted)
        await model.kitFinish(removeOldBackups: false)
    } else {
        check(false, "Neues Kit in Teilen erwartet")
    }
    model.closeSettings()

    // MARK: Notfallcode in Teilen (gesperrt)
    model.lock()
    model.startRecovery()
    _ = await warteBis { model.recovery.header != nil }
    check(model.recovery.usesShares, "Notfallweg verlangt zwei Teile")
    shot("114-notfall-teile", model)
    var zweiter = Array(aktuelleTeile[2])
    zweiter[8] = zweiter[8] == "7" ? "8" : "7"
    model.recovery.shares = [aktuelleTeile[0], String(zweiter)]
    await model.checkRecoverySharesForRecovery()
    if case let .confirmShareCorrections(fixes) = model.recovery.step {
        check(fixes.count == 1 && fixes.first?.index == 1, "Ein Teil korrigiert")
    } else {
        check(false, "Teile: Korrektur erwartet")
    }
    shot("115-notfall-teile-korrektur", model)
    model.acceptShareCorrections()
    model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
    model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
    await model.submitRecovery()
    check(model.recovery.step == .done, "Wiederhergestellt mit zwei Teilen")
    shot("116-notfall-teile-fertig", model, size: CGSize(width: 920, height: 700))
    model.finishRecovery()
    check(model.level == .standard && model.vaultHeader?.factors.isEmpty == true, "Nach Teilen: Stufe 1")
    let wieder = model.entries.first { $0.id == boerse.id }
    check(wieder?.protection == .normal && wieder?.secretsSealed == false && wieder?.password == "Wb7#nQ2!zLm8xR4v",
          "Nach Teilen: Einträge entsiegelt")

    // MARK: Abwärts: 1 → 2 → 1 (Entsperr-Schlüssel erst nach dem Schreiben entfernt)
    model.openSettings()
    model.startLevelChange(to: .erhoeht)
    if let hoch = model.wizard {
        // Nach der Wiederherstellung mit Teilen ist der Tresor Stufe 1, das Kit aber noch „2 aus 3“ (Kopf, §15:
        // das Schema beschreibt das Kit). Stufe 2 verlangt einen einzelnen Code → neues Kit im Assistenten.
        check(model.vaultHeader?.recoveryScheme == .shamir2of3, "Nach Teilen: Kit bleibt 2 aus 3")
        check(hoch.steps == [.intro, .verify, .touchID, .recovery, .apply, .done], "Schritte 1 → 2 (mit neuem Kit)")
        model.wizardAdvance()
        hoch.password = "Gletscher-Brise am Morgen 7"
        await model.wizardVerify()
        await model.wizardSetupTouchID()
        model.wizardAdvance()
        await model.wizardShowRecoveryKit()
        if let einzel = model.kit, !einzel.isShared {
            model.kitChooseHandwritten()
            model.kitProceedToConfirm()
            let gruppen = einzel.pending.code.groups
            einzel.confirmation = einzel.pending.confirmationGroups.map { gruppen[$0] }
            await model.kitConfirm()
        } else {
            check(false, "1 → 2: einzelner Code erwartet")
        }
        check(hoch.recoveryConfirmed && hoch.step == .apply, "1 → 2: neuer Code bestätigt")
        await model.wizardApply()
        check(model.level == .erhoeht && model.vaultHeader?.factors == [.secureEnclave]
              && model.vaultHeader?.recoveryScheme == .single, "Stufe 2 aktiv")
        await model.wizardFinish(removeOldBackups: true)
    }
    let seAlt = model.vaultHeader?.seKeyID
    model.startLevelChange(to: .standard)
    if let runter = model.wizard {
        check(runter.steps == [.intro, .verify, .apply, .done], "Schritte 2 → 1")
        shot("116b-assistent-senken", model, size: CGSize(width: 920, height: 700))
        model.wizardAdvance()
        runter.password = "Gletscher-Brise am Morgen 7"
        await model.wizardVerify()
        check(runter.collection.status[.secureEnclave] == .done, "Abwärts: aktuelle Faktoren (Touch ID) eingesammelt")
        await model.wizardApply()
        check(model.level == .standard && model.vaultHeader?.factors.isEmpty == true, "Zurück auf Stufe 1")
        _ = await warteBis(3) { seAlt.map { demo.removedKeys.contains($0) } ?? false }
        check(seAlt.map { demo.removedKeys.contains($0) } ?? false, "Alter Entsperr-Schlüssel nach dem Schreiben entfernt")
        await model.wizardFinish(removeOldBackups: false)
    }
    model.closeSettings()

    // MARK: Gedruckte Blätter (Vorschau)
    let q = CardCode.generate()
    let blatt = RecoveryKitPrinter.makeSheetView(.card(groups: CardCode.groupedText(for: q).split(separator: "-").map(String.init),
                                                       qr: demo.cardImage(payload: CardCode.payload(for: q), pixels: 600)))
    blatt.frame = NSRect(x: 0, y: 0, width: 595, height: 842)
    if let rep = bitmap(for: blatt) {
        blatt.cacheDisplay(in: blatt.bounds, to: rep)
        write(rep, "117-karte-blatt")
    }
    if let teil = kit.pending.shares.first {
        let teilBlatt = RecoveryKitPrinter.makeSheetView(.share(teil, total: 3))
        teilBlatt.frame = NSRect(x: 0, y: 0, width: 595, height: 842)
        if let rep = bitmap(for: teilBlatt) {
            teilBlatt.cacheDisplay(in: teilBlatt.bounds, to: rep)
            write(rep, "118-teil-blatt")
        }
    }
    model.lock()
}

/// Befund design-5: Jede Kurzbeschreibung der Schutz-Auswahl passt in die Bearbeiten-Spalte (540 pt) ungekürzt und
/// ohne Verkleinern – auch im ungünstigsten Fall mit „noch einrichten“ und allen Symbolen der Zeile (früher fiel bei
/// Schutz 5 genau „nicht im Export“ weg).
@MainActor
func schutzTextePassenInDieSpalte() {
    func breite(_ text: String, _ font: NSFont) -> CGFloat {
        ceil((text as NSString).size(withAttributes: [.font: font]).width)
    }
    let hinweis = breite("noch einrichten", .systemFont(ofSize: ProtectionPickerProbe.hintFontSize, weight: .medium))
    let symbol = NSImage.SymbolConfiguration(pointSize: ProtectionPickerProbe.glyphFontSize, weight: .medium)
    for p in EntryProtection.allCases {
        let symbole = p.factors.kinds.map { kind in
            NSImage(systemSymbolName: FactorUI.symbol(kind), accessibilityDescription: nil)?
                .withSymbolConfiguration(symbol)?.size.width ?? 16
        }
        let symbolBreite = symbole.reduce(0, +) + CGFloat(max(symbole.count - 1, 0)) * ProtectionPickerProbe.glyphSpacing
        // Kinder der Zeile: Kreis, Nummer, Texte, Spacer, Hinweis, Symbole → 5 Abstände
        let platz = ProtectionPickerProbe.columnWidth - ProtectionPickerProbe.fixedWidth - 5 * ProtectionPickerProbe.spacing
            - (p.factors.isEmpty ? 0 : hinweis) - symbolBreite
        let text = breite(ProtectionPickerProbe.short(p), .systemFont(ofSize: 12))
        check(text <= platz, "design-5: Kurztext von Schutz \(p.rawValue) passt (\(Int(text)) von \(Int(platz)) pt)")
    }
}
