import AppKit
import SiegelCore
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Ablauf-Befunde der zweiten Prüfung (SPEC v4.4): Sperren mit offener Bearbeitung in Stufe 1 (ablaeufe-1, genau die
// Probe Schutz 2 → 4 ohne Karte), Faktor-Abfragen nach dem Sperren (ablaeufe-4), markierte Einträge ohne Auslöser
// (ablaeufe-5), Grenze der Zwischenablage im gesperrten Zustand (ablaeufe-8), Sicherungen im Hintergrund lesen
// (ablaeufe-10). ablaeufe-3 prüft `selbstvernichtungSnapshots`, ablaeufe-6 `dateiBefundeSnapshots`, ablaeufe-7
// `haertestufeSnapshots`. Bilder 230–233. Hardware: `DemoHardware`, Tresore nur im Temp-Ordner.

@MainActor
func ablaeufeBefundeSnapshots() async {
    await ablaeufeEntwurfStufe1()
    await ablaeufeStufe4()
    await ablaeufeSicherungenImHintergrund()
}

/// Wartet, bis „Tresor fehlt“ die Sicherungen im Hintergrund gelesen hat (Befund ablaeufe-10).
@MainActor
func sicherungenGelesen(_ model: AppModel) async {
    _ = await warteBis(10) { !model.missing.searching }
}

// MARK: - ablaeufe-1: Stufe 1, Touch ID für Einträge, Schutz 2 → 4 ohne Karte, dann Sperren

@MainActor
func ablaeufeEntwurfStufe1() async {
    do {
        let demo = DemoHardware()
        let (_, store) = makeModel("ablaeufe-entwurf")
        let pw = Demodaten.masterPassword
        let (vault, _) = try await offMain { try store.create(masterPassword: pw) }
        let eintragsSchluessel = try demo.enrollEntryKey(directory: store.hardwareDirectory)
        try await offMain {
            try vault.enrollFactors(NewFactorMaterial(entryKey: eintragsSchluessel), masterPassword: pw,
                                    currentFactors: FactorSecrets())
        }
        let geheim = "GEHEIM-Bank-Passwort-9!"
        try vault.upsert(VaultEntry(title: "Beispiel Bank", username: "lena.muster", password: geheim,
                                    url: "https://bank.example", notes: "Notiz geheim", totp: "JBSWY3DPEHPK3PXP",
                                    protection: .fingerabdruck))
        vault.lock()
        let model = dateiModel(store, demo)
        for anlass in [LockReason.manual, .inactivity] {
            await hygieneEntsperren(model)
            guard model.screen == .unlocked, let bank = model.entries.first(where: { $0.title == "Beispiel Bank" }) else {
                check(false, "ablaeufe-1: Stufe 1 entsperrt")
                return
            }
            let anzahl = model.entries.count
            model.select(bank.id)
            model.editSelected()
            await model.unlockEditorSecrets()
            guard let editor = model.browser.editor, !editor.secretsLocked else {
                check(false, "ablaeufe-1: Geheimteile im Bearbeiten aufgedeckt")
                return
            }
            editor.draft.protection = .maximal
            await model.saveEdit()
            check(editor.error?.contains("QR-Schlüsselkarte") == true, "ablaeufe-1: Sichern lehnt Schutz 4 ohne Karte ab")
            model.lock(reason: anlass)
            check(model.screen == .locked && model.lockNotice?.contains("statt 4 gespeichert") == true,
                  "ablaeufe-1 (\(anlass)): Sperren meldet den gespeicherten Schutz (\(model.lockNotice ?? "kein Hinweis"))")
            await hygieneEntsperren(model)
            check(model.entries.count == anzahl && !model.entries.contains { $0.title.hasPrefix("Entwurf") },
                  "ablaeufe-1 (\(anlass)): kein „Entwurf“")
            check(!model.entries.contains { !$0.secretsSealed && ($0.password == geheim || $0.notes == "Notiz geheim") },
                  "ablaeufe-1 (\(anlass)): kein Eintrag mit offenem Geheimteil")
            let b = model.entries.first { $0.id == bank.id }
            check(b.map { $0.protection >= .fingerabdruck && $0.secretsSealed } == true,
                  "ablaeufe-1 (\(anlass)): Bank bleibt versiegelt, Schutz nicht tiefer")
            model.lock()
        }
    } catch {
        fehler.append("ablaeufe-1: \(error)")
    }
}

// MARK: - Stufe 4: ablaeufe-4 (Kamera nach dem Sperren), ablaeufe-5 (markiert ohne Auslöser), ablaeufe-8

@MainActor
func ablaeufeStufe4() async {
    do {
        let t = try await dateiStufe4("ablaeufe-stufe4")
        let model = dateiModel(t.store, t.demo)
        await hygieneEntsperren(model, karte: t.karte)
        guard model.screen == .unlocked, model.level == .maximal else {
            check(false, "ablaeufe: Stufe 4 entsperrt")
            return
        }
        let krypto = VaultEntry(title: "Krypto-Börse", username: "lena", password: "Seed-Wort-Kette-77",
                                url: "https://krypto.example", protection: .maximal)
        check(await model.perform { try $0.upsert(krypto) } == nil, "ablaeufe-4: Schutz-4-Eintrag angelegt")
        guard let e = model.entries.first(where: { $0.title == "Krypto-Börse" }) else {
            check(false, "ablaeufe-4: Krypto-Börse fehlt")
            return
        }

        // ablaeufe-4: Touch ID hält an (Dialog offen), die Auto-Sperre greift, dann der Finger → kein Kamera-Sheet.
        model.select(e.id)
        let schranke = t.demo.holdTouchID()
        let aufdecken = Task { await model.revealEntry(e) }
        check(await warteBis(5) { model.touchIDActive }, "ablaeufe-4: Touch ID läuft")
        model.lock(reason: .inactivity)
        check(model.screen == .locked && model.cardScan == nil, "ablaeufe-4: gesperrt, noch kein Kamera-Sheet")
        schranke.signal()
        await aufdecken.value
        await warte(0.3)
        check(model.cardScan == nil && DemoScanner.current?.running != true && !model.factorInProgress,
              "ablaeufe-4: nach dem Sperren weder Kamera-Sheet noch Kamera")
        _ = await warteBis(5) { model.unlock.header != nil }
        shot("230-gesperrt-nach-aufdecken", model)

        // ablaeufe-8: Gesperrt gilt die Grenze der zuletzt geöffneten Stufe (Notfallcode-Felder), nicht die Einstellung.
        model.settings.clipboardSeconds = 60
        check(model.effectiveClipboardSeconds() == 15 && SecretPasteboardProbe.fieldCopyLifetime == 15,
              "ablaeufe-8: gesperrt nach Stufe 4 → ⌘C aus Feldern höchstens 15 s (Einstellung 60 s)")
        model.settings.clipboardSeconds = 30

        // ablaeufe-5: markiert, aber kein Auslöser
        await hygieneEntsperren(model, karte: t.karte)
        guard model.screen == .unlocked, let e2 = model.entries.first(where: { $0.id == e.id }) else {
            check(false, "ablaeufe-5: wieder entsperrt")
            return
        }
        model.openSettings()
        model.settingsState.fileVaultEncrypted = true
        await model.showDestruction()
        guard let d = model.destructionState else {
            check(false, "ablaeufe-5: Seite Selbstvernichtung fehlt")
            return
        }
        model.destructionToggle(e2)
        check(!d.deadmanOn && !d.counterOn && !d.duressOn && d.canContinue,
              "ablaeufe-5: markiert ohne Auslöser lässt sich sichern")
        shot("231-selbstvernichtung-markiert-ohne-ausloeser", model, size: CGSize(width: 920, height: 1240))
        model.destructionContinue()
        d.confirmWord = DestructionRules.confirmWord
        d.masterPassword = Demodaten.masterPassword
        let an = Task { await model.destructionApply() }
        await karteBisFertig(t.karte, model, an)
        check(model.destructibleEntries == [e2.id] && model.destruction?.settings.anyTriggerEnabled == false,
              "ablaeufe-5: eingetragen, kein Auslöser (\(d.error ?? "ok"))")
        check(DestructionTexts.summary(model.destruction?.settings, configured: model.destructionConfigured)
              == "Einträge markiert · kein Auslöser", "ablaeufe-5: Zeile in den Einstellungen nicht „Aus“")
        check(DestructionRules.isConfigured(model.destruction), "ablaeufe-5: offen als eingerichtet erkannt")
        model.settingsBack()
        shot("232-einstellungen-markiert-ohne-ausloeser", model, size: CGSize(width: 920, height: 1100))
        model.closeSettings()

        model.lock()
        _ = await warteBis(5) { model.destruction != nil }
        check(DestructionRules.isConfigured(model.destruction) && model.destruction?.settings.anyTriggerEnabled == false,
              "ablaeufe-5: gesperrt als eingerichtet erkannt (Schlüssel V)")
        model.startRecovery()
        _ = await warteBis(5) { model.recovery.header != nil }
        model.recovery.shares = [t.teile[0], t.teile[2]]
        await model.checkRecoverySharesForRecovery()
        check(model.recovery.step == .newPassword, "ablaeufe-5: Teile passen (\(model.recovery.error ?? "ok"))")
        shot("233-notfall-warnt-markierte-eintraege", model, size: CGSize(width: 920, height: 760))
        model.cancelRecovery()
    } catch {
        fehler.append("ablaeufe Stufe 4: \(error)")
    }
}

// MARK: - ablaeufe-10: „Tresor fehlt“ liest die Sicherungen im Hintergrund

@MainActor
func ablaeufeSicherungenImHintergrund() async {
    do {
        // Leerer Ordner: ohne Sicherung sofort die Einrichtung (nichts zu lesen, nichts blitzt auf).
        let (leer, _) = makeModel("ablaeufe-leer")
        check(leer.screen == .setup && !leer.missing.searching, "ablaeufe-10: leerer Ordner → sofort Einrichtung")

        let (_, store) = makeModel("ablaeufe-sicherungen")
        let pw = Demodaten.masterPassword
        let (vault, _) = try await offMain { try store.create(masterPassword: pw) }
        for entry in Demodaten.entries().prefix(3) { try vault.upsert(entry) }
        vault.lock()
        try FileManager.default.removeItem(at: store.vaultURL)
        let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                             settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
        // Direkt nach dem Start: „Tresor fehlt“, die Liste kommt aus dem Hintergrund.
        check(model.screen == .missingVault && model.missing.searching && model.missing.backups.isEmpty,
              "ablaeufe-10: Sicherungen werden im Hintergrund gesucht")
        await sicherungenGelesen(model)
        check(!model.missing.searching && model.missing.backups.count >= 3 && model.missing.selection != nil,
              "ablaeufe-10: Liste und Auswahl aus dem Hintergrund")


        // Nur eine fremde Datei im Ordner der Sicherungen: gelesen wird im Hintergrund, danach die Einrichtung.
        let (_, ohne) = makeModel("ablaeufe-ohne-sicherung")
        let fremd = ohne.backupsDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: fremd, withIntermediateDirectories: true)
        try Data("keine Sicherung".utf8).write(to: fremd.appendingPathComponent("notiz.txt"))
        let leerModell = AppModel(store: ohne, rollbackGuard: InMemoryRollbackGuard(),
                                  settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
        check(leerModell.screen == .missingVault && leerModell.missing.searching,
              "ablaeufe-10: unbekannter Inhalt → erst suchen")
        check(await warteBis(10) { leerModell.screen == .setup }, "ablaeufe-10: keine lesbare Sicherung → Einrichtung")
    } catch {
        fehler.append("ablaeufe-10: \(error)")
    }
}
