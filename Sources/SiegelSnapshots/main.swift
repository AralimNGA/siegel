import AppKit
import CryptoKit
import SiegelCore
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Rendert alle Bildschirme (Stufe 1, 2 und Härtestufe v4) offscreen als PNG (SPEC §8) und prüft dabei die Abläufe.
// Aufruf: swift run SiegelSnapshots [Zielordner]   (Standard: ./snapshots)
// Nur Demodaten, Temp-Ordner, In-Memory-RollbackGuard. Exit-Code 1, wenn eine Prüfung scheitert.

_ = NSApplication.shared
NSApp.setActivationPolicy(.prohibited)
// Ohne sichtbares Fenster drosselt App Nap sonst Timer und Task.sleep (Lauf dauert dann Minuten).
let aktivitaet = ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .latencyCritical],
                                                       reason: "Snapshots")
NSApp.appearance = NSAppearance(named: .aqua)

let ziel = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "snapshots", isDirectory: true)
try? FileManager.default.createDirectory(at: ziel, withIntermediateDirectories: true)
if let alt = try? FileManager.default.contentsOfDirectory(at: ziel, includingPropertiesForKeys: nil) {
    for datei in alt where datei.pathExtension == "png" { try? FileManager.default.removeItem(at: datei) }
}

let tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent("siegel-snapshots-" + UUID().uuidString)
let defaultsSuite = "ch.siegel.snapshots." + UUID().uuidString
var fehler: [String] = []
var anzahl = 0

// MARK: Hilfen

@MainActor
func pump(_ sekunden: Double) {
    RunLoop.main.run(until: Date().addingTimeInterval(sekunden))
}

@MainActor
func check(_ bedingung: Bool, _ text: String) {
    if !bedingung { fehler.append(text) }
}

@MainActor
func makeModel(_ name: String, guardian: RollbackGuard = InMemoryRollbackGuard()) -> (AppModel, VaultStore) {
    let dir = tempRoot.appendingPathComponent(name, isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let store = VaultStore(directory: dir, rollbackGuard: guardian)
    let defaults = UserDefaults(suiteName: defaultsSuite) ?? .standard
    let model = AppModel(store: store, rollbackGuard: guardian, settings: AppSettings(defaults: defaults))
    return (model, store)
}

/// Rendert eine Ansicht in ein randloses Offscreen-Fenster und schreibt ein PNG (@2x).
@MainActor
func render<V: View>(_ name: String, size: CGSize = CGSize(width: 920, height: 600), protected: Bool = true,
                     inspect: ((NSView) -> Void)? = nil, @ViewBuilder _ view: () -> V) {
    let host = NSHostingView(rootView: view().transaction { $0.animation = nil })
    host.frame = CGRect(origin: .zero, size: size)
    let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
    window.appearance = NSAppearance(named: .aqua)
    window.isReleasedWhenClosed = false
    window.sharingType = protected ? .none : .readOnly
    window.backgroundColor = .white
    window.contentView = host
    pump(0.35)
    host.layoutSubtreeIfNeeded()
    pump(0.15)
    host.layoutSubtreeIfNeeded()
    if !protected { window.sharingType = .readOnly }
    guard let rep = bitmap(for: host) else {
        fehler.append("Bitmap fehlt: " + name)
        return
    }
    host.cacheDisplay(in: host.bounds, to: rep)
    write(rep, name)
    inspect?(host)
    window.contentView = nil
    window.close()
}

@MainActor
func bitmap(for view: NSView) -> NSBitmapImageRep? {
    if let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds), rep.pixelsWide >= Int(view.bounds.width * 2) {
        return rep
    }
    // Fallback, falls das Offscreen-Fenster nicht @2x meldet
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(view.bounds.width * 2),
                               pixelsHigh: Int(view.bounds.height * 2), bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0,
                               bitsPerPixel: 0)
    rep?.size = view.bounds.size
    return rep
}

@MainActor
func write(_ rep: NSBitmapImageRep, _ name: String) {
    guard let png = rep.representation(using: .png, properties: [:]) else {
        fehler.append("PNG fehlt: " + name)
        return
    }
    do {
        try png.write(to: ziel.appendingPathComponent(name + ".png"))
        anzahl += 1
    } catch {
        fehler.append("Schreiben: " + name)
    }
}

@MainActor
func shot(_ name: String, _ model: AppModel, size: CGSize = CGSize(width: 920, height: 600), protected: Bool = true,
          external: Bool = false, keepNotice: Bool = false, messen: ((Messung) -> Void)? = nil) {
    // Rückmeldungen früherer Schritte nicht ins Bild nehmen (im Programm verschwinden sie nach Sekunden)
    if !keepNotice { model.notice = nil }
    let sammler = messen == nil ? nil : LayoutRecorder()
    render(name, size: size, protected: protected, inspect: { host in
        if let messen, let sammler { messen(Messung(fenster: host.bounds, rahmen: sammler.frames)) }
    }) {
        RootView(model: model)
            .snapshotSecretGate(external ? .external : nil)
            .snapshotLayoutRecorder(sammler)
            .overlay(alignment: .topLeading) { Fensterknoepfe() }
    }
}

/// Gemessene Rahmen einer gerenderten Ansicht (`LayoutRecorder`, Fensterpunkte, Ursprung oben links) – für
/// Geometrie-Prüfungen (Befund design-2). Die Bedienungshilfen-Struktur von SwiftUI ist offscreen leer, darum melden
/// ausgewählte Ansichten ihre Rahmen selbst (`layoutProbe`, in der App ohne Sammler ohne Wirkung).
struct Messung {
    let fenster: CGRect
    let rahmen: [String: CGRect]
}

/// Aufräumen und Ergebnis melden (Exit-Code 1 bei gescheiterten Prüfungen).
@MainActor
func abschliessen() -> Never {
    try? FileManager.default.removeItem(at: tempRoot)
    UserDefaults.standard.removePersistentDomain(forName: defaultsSuite)
    UserDefaults.standard.removePersistentDomain(forName: defaultsSuite + ".rollback")
    ProcessInfo.processInfo.endActivity(aktivitaet)
    if fehler.isEmpty {
        FileHandle.standardOutput.write(Data("Snapshots: \(anzahl) Bilder, alle Prüfungen bestanden\n".utf8))
        exit(0)
    } else {
        FileHandle.standardError.write(Data(("Snapshots: \(anzahl) Bilder, \(fehler.count) Prüfungen gescheitert:\n- "
            + fehler.joined(separator: "\n- ") + "\n").utf8))
        exit(1)
    }
}

func offMain<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
    try await Task.detached { try work() }.value
}

/// Zwei Tippfehler (Gruppe 2, Zeichen 3 und Gruppe 7, Zeichen 1 ersetzt) für den Korrektur-Weg.
/// SPEC §1.5: Ohne `?` sucht der Kern 1 oder 2 ersetzte Zeichen und vertauschte Nachbarn.
func vertippt(_ code: String) -> String {
    var zeichen = Array(code)
    for i in [6 + 2, 36] {
        zeichen[i] = zeichen[i] == "7" ? "8" : "7"
    }
    return String(zeichen)
}

/// Zwei unleserliche Stellen als `?` (gleiche Positionen). SPEC §1.5: Mit `?` probiert der Kern alle
/// Belegungen der `?` (nicht zusätzlich Ersetzungen).
func unleserlich(_ code: String) -> String {
    var zeichen = Array(code)
    for i in [6 + 2, 36] { zeichen[i] = "?" }
    return String(zeichen)
}

// Nur Stufe B rendern (schneller beim Arbeiten an den neuen Bildern): SIEGEL_SNAPSHOTS_NUR=B
if ProcessInfo.processInfo.environment["SIEGEL_SNAPSHOTS_NUR"] == "B" {
    await stufeBSnapshots()
    abschliessen()
}
// Nur die Selbstvernichtung (v4.3, Bilder 139–158): SIEGEL_SNAPSHOTS_NUR=V43
if ProcessInfo.processInfo.environment["SIEGEL_SNAPSHOTS_NUR"] == "V43" {
    await selbstvernichtungSnapshots()
    abschliessen()
}
// Nur die Datei-Befunde (v4.4, Bilder 170–182): SIEGEL_SNAPSHOTS_NUR=DATEI
if ProcessInfo.processInfo.environment["SIEGEL_SNAPSHOTS_NUR"] == "DATEI" {
    await dateiBefundeSnapshots()
    abschliessen()
}
// Nur die Hygiene-Befunde (v4.4, Bilder 190–193; Probe B und der Totmann laufen in der Selbstvernichtung):
// SIEGEL_SNAPSHOTS_NUR=HYGIENE
if ProcessInfo.processInfo.environment["SIEGEL_SNAPSHOTS_NUR"] == "HYGIENE" {
    await hygieneBefundeSnapshots()
    await selbstvernichtungSnapshots()
    abschliessen()
}

// Nur die Ablauf-Befunde (v4.4, Bilder 230–233; ablaeufe-3 und -7 laufen in Selbstvernichtung bzw. Härtestufe):
// SIEGEL_SNAPSHOTS_NUR=ABLAEUFE
if ProcessInfo.processInfo.environment["SIEGEL_SNAPSHOTS_NUR"] == "ABLAEUFE" {
    await ablaeufeBefundeSnapshots()
    await selbstvernichtungSnapshots()
    abschliessen()
}

// MARK: Einrichtung

do {
    let (model, _) = makeModel("einrichtung")
    check(model.screen == .setup, "Leerer Ordner → Einrichtung")
    model.setup.passphraseRepeat = "etwas"
    check(!model.holdsPendingSecret, "Einrichtung: Auto-Sperre verwirft keine Eingaben (Befund #5)")
    model.setup.passphraseRepeat = ""
    model.setup.passphrase = Demodaten.passphrase
    model.setup.fileVaultEncrypted = true
    shot("01-einrichtung", model)

    model.setup.passphraseRepeat = Demodaten.passphrase
    check(model.setup.canCreate, "Passphrase + Wiederholung → anlegbar")
    shot("02-einrichtung-bestaetigt", model)

    model.setSetupMode(.own)
    model.setup.password = "Sommer2026!!!"
    model.setup.passwordRepeat = "Sommer20"
    shot("03-einrichtung-eigenes-schwach", model)

    model.setup.password = "Gletscher-Brise am Morgen 7"
    model.setup.passwordRepeat = "Gletscher-Brise am Morgen 7"
    shot("04-einrichtung-eigenes-stark", model)

    model.setSetupMode(.passphrase)
    model.setup.passphraseRepeat = ""
    model.setup.fileVaultEncrypted = false
    shot("05-einrichtung-filevault", model)

    model.setup.fileVaultEncrypted = true
    model.setup.passphraseRepeat = Demodaten.passphrase
    model.snapshotSetBusy(true)
    shot("06-einrichtung-laeuft", model)
    model.snapshotSetBusy(false)

    // Anlegen → Notfallkit
    await model.createVault()
    check(model.screen == .recoveryKit, "Anlegen → Notfallkit")
    check(model.kit?.origin == .setup, "Kit aus Einrichtung")
    check(model.recoveryConfirmed == false, "Neues Kit unbestätigt")
    shot("07-notfallkit", model)

    model.kitChooseHandwritten()
    shot("08-notfallkit-abgeschrieben", model)

    model.kit?.method = nil
    model.kit?.printWarning = true
    shot("09-notfallkit-druckerwarnung", model)
    model.kitDismissPrintWarning()
    // Befund #15: Drucker ohne lesbare Geräte-URI → ebenfalls Warnung
    model.kit?.printWarningText = RecoveryKitPrinter.unknownWarning
    model.kit?.printWarning = true
    shot("09b-notfallkit-druckerwarnung-unbekannt", model)
    model.kitDismissPrintWarning()
    // Befund #7: Im Druckdialog PDF gewählt → kein Code, kein „Gedruckt“
    model.kit?.printNotPaper = true
    shot("09c-notfallkit-kein-papier", model)
    model.kit?.printNotPaper = false

    model.kitChooseHandwritten()
    model.kitProceedToConfirm()
    check(model.kit?.step == .confirm, "Weiter → Bestätigung")
    shot("10-notfallkit-bestaetigen", model)

    if let kit = model.kit {
        kit.confirmation = ["ABCDE", "FGHJK"]
    }
    await model.kitConfirm()
    check(model.kit?.error != nil, "Falsche Gruppen → Fehler")
    check(model.recoveryConfirmed == false, "Falsche Gruppen → weiterhin unbestätigt")
    shot("11-notfallkit-bestaetigen-fehler", model)

    // Code für den Notfallweg merken, dann „Später bestätigen“
    let code = model.kit?.pending.code.formatted ?? ""
    model.kitSkip()
    check(model.screen == .unlocked, "Später bestätigen → Tresor")

    // Demo-Einträge über die öffentliche API
    let entries = Demodaten.entries()
    let report = await model.performReturning { try $0.importEntries(entries) }
    if case let .success(r) = report { check(r.added == entries.count, "Demo-Import vollständig") }
    check(model.entries.count == entries.count, "Abbild nach Import")
    check(model.needsRecoveryKitConfirmation, "Banner „Notfallkit nicht bestätigt“")
    shot("12-tresor-nach-einrichtung", model)

    // Einstellungen
    model.openSettings()
    model.settingsState.fileVaultEncrypted = true
    check(model.showsSettings, "⌘, öffnet Einstellungen")
    shot("13-einstellungen", model)
    shot("14-einstellungen-ganz", model, size: CGSize(width: 920, height: 2100))

    model.settingsShow(.changePassword)
    model.settingsState.currentPassword = "x"
    model.settingsState.newPassword = "Gletscher-Brise am Morgen 7"
    model.settingsState.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
    shot("15-einstellungen-passwort", model)

    model.settingsShow(.checkCode)
    model.settingsState.code = vertippt(code)
    await model.checkRecoveryCodeInSettings()
    if case let .corrected(_, positionen)? = model.settingsState.codeResult {
        check(positionen.count == 2, "Korrektur markiert 2 Stellen")
    } else {
        check(false, "Code prüfen → Korrektur erwartet")
    }
    shot("16-einstellungen-code-pruefen", model)

    // Befund #16: Das schon abgeschriebene Blatt lässt sich später mit dem ganzen Code bestätigen
    model.startNewRecoveryKit()
    check(model.settingsState.page == .unconfirmedKit, "„jetzt einrichten“ → Auswahl vorhandenes Blatt / neues Kit")
    shot("16b-einstellungen-kit-unbestaetigt", model)
    model.settingsShow(.checkCode)
    model.settingsState.code = code
    await model.checkRecoveryCodeInSettings()
    check(model.settingsState.codeResult == .exact, "Ganzer Code passt")
    shot("16c-einstellungen-blatt-bestaetigen", model)
    let kitVorher = model.kitID
    await model.confirmExistingKitInSettings()
    check(model.recoveryConfirmed && model.kitID == kitVorher, "Vorhandenes Blatt bestätigt, ohne neues Kit")

    model.settingsShow(.newKit)
    shot("17-einstellungen-neues-kit", model)

    model.settingsShow(.kdfProfile(strong: true))
    shot("18-einstellungen-profil", model)

    model.settingsShow(.purgeBackups(.passwordChange))
    shot("19-einstellungen-sicherungen-entfernen", model)

    // Neues Kit über die Einstellungen (Master-Passwort erneut)
    model.settingsShow(.newKit)
    model.settingsState.currentPassword = Demodaten.masterPassword
    await model.prepareNewRecoveryKit()
    check(model.screen == .recoveryKit && model.kit?.origin == .newKit, "Neues Kit → Kit-Bildschirm")
    model.kitCancel()
    check(model.screen == .unlocked && model.showsSettings, "Abbrechen → zurück in die Einstellungen")
    model.closeSettings()

    // Sperren
    let generationVorher = model.lockGeneration
    model.searchText = "bank"
    model.lock()
    check(model.screen == .locked, "⌘L → gesperrt")
    check(model.vault == nil && model.entries.isEmpty && model.searchText.isEmpty, "Sperren räumt auf")
    check(model.lockGeneration == generationVorher + 1, "Sperren erneuert die Ansicht")
    shot("20-gesperrt", model)

    model.unlock.password = "falsch-falsch-falsch"
    shot("21-gesperrt-tippen", model)
    await model.submitUnlock()
    check(model.unlock.error == Fehlertexte.wrongPassword, "Falsches Passwort → Meldung")
    check(model.unlock.password.isEmpty, "Falsches Passwort → Feld leer")
    shot("22-gesperrt-falsch", model)

    model.unlock.error = Fehlertexte.kdfFailed
    shot("23-gesperrt-arbeitsspeicher", model)
    model.unlock.error = nil

    // Befund #5: Ein eingetipptes Master-Passwort hält die Auto-Sperre scharf; sie leert das Feld
    model.unlock.password = Demodaten.masterPassword
    check(model.holdsPendingSecret, "Eingetipptes Passwort → Auto-Sperre scharf")
    model.lock(reason: .inactivity)
    check(model.unlock.password.isEmpty && model.screen == .locked, "Auto-Sperre leert das Passwortfeld")

    model.unlock.password = Demodaten.masterPassword
    model.snapshotSetBusy(true)
    shot("24-gesperrt-entsperrt", model)
    model.snapshotSetBusy(false)

    await model.submitUnlock()
    check(model.screen == .unlocked, "Richtiges Passwort → Tresor")
    check(model.entries.count == entries.count, "Einträge nach Entsperren")
    model.lock()

    // Notfallcode-Weg
    model.startRecovery()
    check(model.screen == .recovery, "Notfallcode verwenden → Code-Eingabe")
    shot("25-notfallcode", model)
    model.recovery.code = unleserlich(code)
    shot("26-notfallcode-eingabe", model)
    await model.checkRecoveryCodeForRecovery()
    if case let .confirmCorrection(_, positionen) = model.recovery.step {
        check(positionen == [7, 30], "Unleserliche Stellen → Korrektur an Position 7 und 30")
    } else {
        check(false, "Unleserliche Stellen → Korrektur-Vorschlag")
    }
    shot("27-notfallcode-korrektur", model)
    model.acceptCorrection()
    check(model.recovery.step == .newPassword, "Korrektur bestätigt → neues Passwort")
    check(model.holdsPendingSecret, "Bestätigter Notfallcode → Auto-Sperre scharf (Befund #5)")
    model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
    model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
    shot("28-notfallcode-neues-passwort", model)
    await model.submitRecovery()
    check(model.recovery.step == .done, "Wiederherstellung fertig")
    check(model.recovery.entryCount == entries.count, "Eintragszahl nach Wiederherstellung")
    shot("29-notfallcode-fertig", model)
    model.finishRecovery()
    check(model.screen == .unlocked, "Tresor öffnen nach Wiederherstellung")

    // Falscher Code (anderes Kit)
    model.lock()
    model.startRecovery()
    model.recovery.code = RecoveryCodeFormatting.format(Array(String(repeating: "Z", count: 55)), groups: 11)
    await model.checkRecoveryCodeForRecovery()
    check(model.recovery.error != nil, "Unbrauchbarer Code → Meldung")
    shot("30-notfallcode-fehler", model)
    model.cancelRecovery()
    check(model.screen == .locked, "Zurück zum Entsperren")
}

// MARK: Tresor fehlt

do {
    let (vorlage, store) = makeModel("fehlt")
    let pw = Demodaten.masterPassword
    _ = try await offMain { try store.create(masterPassword: pw) }
    _ = vorlage
    if case let .unlocked(vault) = try await offMain({ try store.unlock(masterPassword: pw) }) {
        for entry in Demodaten.entries().prefix(3) { try vault.upsert(entry) }
        vault.lock()
    }
    try FileManager.default.removeItem(at: store.vaultURL)
    let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                         settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
    check(model.screen == .missingVault, "Datei weg + Sicherungen → Tresor fehlt")
    await sicherungenGelesen(model)
    check(model.missing.backups.count >= 3, "Sicherungen gelistet")
    shot("31-tresor-fehlt", model)
    model.requestNewVault()
    shot("32-tresor-fehlt-neu", model)
    model.cancelNewVault()
    model.missing.password = pw
    await model.restoreSelectedBackup()
    check(model.screen == .unlocked, "Sicherung wiederhergestellt → Tresor")
} catch {
    fehler.append("Tresor fehlt: \(error)")
}

// MARK: Beschädigt

do {
    let (_, store) = makeModel("beschaedigt")
    let pw = Demodaten.masterPassword
    _ = try await offMain { try store.create(masterPassword: pw) }
    if case let .unlocked(vault) = try await offMain({ try store.unlock(masterPassword: pw) }) {
        for entry in Demodaten.entries() { try vault.upsert(entry) }
        vault.lock()
    }
    var daten = try Data(contentsOf: store.vaultURL)
    daten[daten.count / 2] ^= 0x5A
    try daten.write(to: store.vaultURL)
    let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                         settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
    model.unlock.password = pw
    await model.submitUnlock()
    check(model.screen == .corrupt, "Beschädigte Datei → Beschädigt")
    shot("33-beschaedigt", model)
    await model.openNewestReadableBackup()
    check(model.corrupt.restoredBackup != nil, "Neueste lesbare Sicherung geöffnet")
    shot("34-beschaedigt-geoeffnet", model)
    model.finishCorruptRestore()
    check(model.screen == .unlocked, "Danach Tresor")

    // Neuere Formatversion: Version 3 in den Kopf schreiben, Prüfsumme mit dem Label dieser Version neu berechnen
    // (SPEC §2, §13.2: „Siegel v<n> file check“) und echt entsperren. Der Kern meldet unsupportedVersion; die
    // Datei bleibt byte-gleich.
    model.lock()
    var v2 = try Data(contentsOf: store.vaultURL)
    v2[6] = 3
    v2[7] = 0
    var pruefInhalt = Data("Siegel v3 file check".utf8)
    pruefInhalt.append(v2.prefix(v2.count - 32))
    v2.replaceSubrange((v2.count - 32)..<v2.count, with: Data(SHA3_256.hash(data: pruefInhalt)))
    try v2.write(to: store.vaultURL)
    model.unlock.password = pw
    await model.submitUnlock()
    check(model.screen == .corrupt && model.corrupt.kind == .newerVersion(3), "Neuere Formatversion → Hinweis")
    check(model.corrupt.password.isEmpty, "Neuere Version: Passwort nicht behalten")
    shot("35-neuere-version", model)
    check((try? Data(contentsOf: store.vaultURL)) == v2, "Neuere Version: Datei unverändert")
    model.leaveCorrupt()
} catch {
    fehler.append("Beschädigt: \(error)")
}

// MARK: Notfallcode bei beschädigter Tresordatei (Befund #4)

do {
    let (_, store) = makeModel("notfall-beschaedigt")
    let pw = Demodaten.masterPassword
    let (vault, pending) = try await offMain { try store.create(masterPassword: pw) }
    for entry in Demodaten.entries().prefix(4) { try vault.upsert(entry) }
    vault.lock()
    var daten = try Data(contentsOf: store.vaultURL)
    daten[daten.count - 200] ^= 0x5A
    try daten.write(to: store.vaultURL)
    let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                         settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
    model.startRecovery()
    model.recovery.code = pending.code.formatted
    await model.checkRecoveryCodeForRecovery()
    check(model.recovery.step == .newPassword, "Beschädigt: Code passt (Kopf lesbar)")
    model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
    model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
    await model.submitRecovery()
    check(model.recovery.offerBackup && model.recovery.step == .newPassword, "Beschädigt → Weg über die Sicherungen angeboten")
    shot("33a-notfallcode-datei-beschaedigt", model)
    await model.submitRecoveryFromBackup()
    check(model.recovery.step == .done && model.recovery.restoredBackup != nil, "Notfallcode öffnet die neueste Sicherung")
    check(model.recovery.entryCount == 3, "Stand der neuesten Sicherung (3 Einträge)")
    shot("33b-notfallcode-aus-sicherung", model)
    model.finishRecovery()
    check(model.screen == .unlocked && model.recoveryConfirmed, "Danach Tresor, Kit bestätigt")
    model.lock()
} catch {
    fehler.append("Notfall beschädigt: \(error)")
}

// MARK: Tresor fehlt, nur Sicherungen am zweiten Ort (Befund #13)

do {
    let (_, store) = makeModel("fehlt-extern")
    let usb = tempRoot.appendingPathComponent("fehlt-extern-usb", isDirectory: true)
    try FileManager.default.createDirectory(at: usb, withIntermediateDirectories: true)
    store.secondaryBackupDirectory = usb
    let (vault, _) = try await offMain { try store.create(masterPassword: Demodaten.masterPassword) }
    try vault.upsert(VaultEntry(title: "Nur extern gesichert"))
    vault.lock()
    try FileManager.default.removeItem(at: store.vaultURL)
    try FileManager.default.removeItem(at: store.vaultURL.deletingLastPathComponent().appendingPathComponent("Sicherungen"))
    let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                         settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
    await sicherungenGelesen(model)
    check(model.screen == .missingVault && !model.missing.backups.isEmpty && model.missing.backups.allSatisfy(\.isExternal),
          "Nur Sicherungen am zweiten Ort → „Tresor fehlt“ statt Einrichtung")
} catch {
    fehler.append("Tresor fehlt extern: \(error)")
}

// MARK: Rollback

do {
    let guardian = InMemoryRollbackGuard()
    let (_, store) = makeModel("rollback", guardian: guardian)
    let pw = Demodaten.masterPassword
    _ = try await offMain { try store.create(masterPassword: pw) }
    let alt = try Data(contentsOf: store.vaultURL)
    if case let .unlocked(vault) = try await offMain({ try store.unlock(masterPassword: pw) }) {
        try vault.upsert(VaultEntry(title: "Neu"))
        try vault.upsert(VaultEntry(title: "Noch neuer"))
        vault.lock()
    }
    try alt.write(to: store.vaultURL)
    let model = AppModel(store: store, rollbackGuard: guardian,
                         settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
    model.unlock.password = pw
    await model.submitUnlock()
    check(model.screen == .rollback, "Ältere Datei → Rollback-Frage")
    shot("36-rollback", model)
    model.rejectRollback()
    check(model.screen == .locked, "Abbrechen → gesperrt")
} catch {
    fehler.append("Rollback: \(error)")
}

// MARK: Start blockiert, verdeckt, Druckblatt

do {
    let settings = AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard)
    let laeuft = AppModel(store: nil, rollbackGuard: InMemoryRollbackGuard(), settings: settings, blocked: .alreadyRunning)
    shot("37-laeuft-bereits", laeuft)
    let sandbox = AppModel(store: nil, rollbackGuard: InMemoryRollbackGuard(), settings: settings, blocked: .sandboxMissing)
    shot("38-sandbox-fehlt", sandbox)
    // Befund hardware-2: Signatur ungültig → gesperrt, bevor Datenordner oder Einzelinstanz angefasst werden (kein
    // Tresor, also auch kein Entsperren, Wiederherstellen oder Einspielen).
    let beschaedigt = AppModel.production(signatureIsValid: { false })
    check(beschaedigt.screen == .blocked(.signatureInvalid) && !beschaedigt.isUnlocked, "hardware-2: Signatur ungültig → gesperrt")
    await beschaedigt.submitUnlock()
    check(beschaedigt.screen == .blocked(.signatureInvalid) && !beschaedigt.isUnlocked, "hardware-2: kein Entsperren")
    shot("38b-signatur-ungueltig", beschaedigt)

    // Externer Bildschirm (erzwungen): Code verdeckt, mit „Hier zeigen“
    let (model, _) = makeModel("verdeckt")
    model.setup.passphrase = Demodaten.passphrase
    model.setup.passphraseRepeat = Demodaten.passphrase
    await model.createVault()
    render("39-notfallkit-externer-bildschirm") { RootView(model: model).snapshotSecretGate(.external) }

    // Ohne geschütztes Fenster dürfen Geheimnisse nie gezeichnet werden
    let offen = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 10, height: 10), styleMask: [.borderless],
                         backing: .buffered, defer: false)
    offen.sharingType = .readOnly
    check(!ExternalDisplayGuard.allowsSecrets(in: offen, allowExternal: true), "Ungeschütztes Fenster → verdeckt")
    check(!ExternalDisplayGuard.allowsSecrets(in: nil, allowExternal: true), "Ohne Fenster → verdeckt")
    WindowGuard.shared.protect(offen)
    check(ExternalDisplayGuard.allowsSecrets(in: offen, allowExternal: true), "WindowGuard schützt → sichtbar")

    if let kit = model.kit {
        let blatt = RecoveryKitPrinter.makeSheetView(kit.pending.code)
        blatt.frame = NSRect(x: 0, y: 0, width: 595, height: 842)
        if let rep = bitmap(for: blatt) {
            blatt.cacheDisplay(in: blatt.bounds, to: rep)
            write(rep, "40-notfallkit-blatt")
        }
        // Befund #7: Ausgabe als PDF/Vorschau → Blatt ohne Code
        let pdf = RecoveryKitPrinter.makeSheetViewWithoutPrinter(kit.pending.code)
        pdf.frame = NSRect(x: 0, y: 0, width: 595, height: 842)
        if let rep = bitmap(for: pdf) {
            pdf.cacheDisplay(in: pdf.bounds, to: rep)
            write(rep, "40b-notfallkit-blatt-ohne-drucker")
        }
    }
    check(RecoveryKitPrinter.classify(URL(string: "ipp://drucker.local/ipp/print")!) == .insecure, "ipp unsicher")
    check(RecoveryKitPrinter.classify(URL(string: "ipps://drucker.local/ipp/print")!) == .secure, "ipps sicher")
    check(RecoveryKitPrinter.classify(URL(string: "socket://10.0.0.5:9100")!) == .insecure, "socket unsicher")
    check(RecoveryKitPrinter.classify(URL(string: "dnssd://Drucker._ipp._tcp.local./?uuid=1")!) == .insecure, "dnssd _ipp unsicher")
    check(RecoveryKitPrinter.classify(URL(string: "dnssd://Drucker._ipps._tcp.local./?uuid=1")!) == .secure, "dnssd _ipps sicher")
    check(RecoveryKitPrinter.classify(URL(string: "dnssd://Drucker._pdl-datastream._tcp.local./")!) == .insecure, "dnssd pdl unsicher")
    check(RecoveryKitPrinter.classify(URL(string: "usb://Hersteller/Modell")!) == .secure, "usb sicher")

    // Notfallcode-Gruppierung
    check(RecoveryCodeFormatting.format(RecoveryCodeFormatting.significant("abcde fghij-k?"), groups: 11) == "ABCDE-FGHIJ-K?", "Gruppierung")
}

await tresorSnapshots()
await haertestufeSnapshots()
await stufeBSnapshots()
await selbstvernichtungSnapshots()
await dateiBefundeSnapshots()
await hygieneBefundeSnapshots()
await ablaeufeBefundeSnapshots()
abschliessen()
