import AppKit
import SiegelCore
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Selbstvernichtung (SPEC v4.3 §23): Einstellungen, Bestätigung, Sperrbildschirm (Frist, Zähler), Banner nach einer
// Vernichtung, Vernichtungs-Sitzung (sieht aus wie eine normale), Markierung im Detail. Bilder ab 139.
// Den Kern-Anteil von §23 (Zähler im Entsperren, Totmann-Schalter, Vernichtungs-Passwort) macht der echte Kern; die
// Oberfläche durchläuft denselben Weg wie in der App. Frist und Zähler für Bilder setzt `KernBruecke.swift`.
// Hardware: `DemoHardware` (der Kern vernichtet V über `destroySecureEnclaveKey`).

/// Zweites Passwort für die Vernichtungs-Sitzung (erfunden, erfüllt die Regel).
let vernichtungsPasswort = "Laterne-Moos7-Fjord-Kiesel-Abendrot"

@MainActor final class Erledigt { var ja = false }

/// Wartet auf `aufgabe` und liefert dabei die Karte bei jeder Kamera-Abfrage: Faktoren der Stufe und beim Markieren
/// die Freigabe je Notfall-Gruppe (§23.3, der Kern versiegelt neu). Gibt die Anzahl gelieferter Karten zurück.
@MainActor
@discardableResult
func karteBisFertig(_ karte: String, _ model: AppModel, _ aufgabe: Task<Void, Never>, max: Double = 60) async -> Int {
    let erledigt = Erledigt()
    let warten = Task { @MainActor in
        await aufgabe.value
        erledigt.ja = true
    }
    let ende = Date().addingTimeInterval(max)
    var anzahl = 0
    while !erledigt.ja, Date() < ende {
        if model.cardScan != nil, let scanner = DemoScanner.current, scanner.running {
            scanner.deliver(karte)
            anzahl += 1
            _ = await warteBis(5) { model.cardScan == nil || erledigt.ja }
        }
        try? await Task.sleep(for: .milliseconds(40))
    }
    await warten.value
    return anzahl
}

// MARK: - Prüfungen ohne Tresor

@MainActor
func selbstvernichtungPruefungen() {
    // Sperrbildschirm-Regeln (§23.2): Frist ab 25 % Restzeit, Warnung ab N/2.
    let jetzt = Date()
    func status(tage: Int?, letzte: Date?, n: Int?, f: Int) -> DestructionStatus? {
        kernStatus(totmann: tage, letztesEntsperren: letzte, zaehler: n, fehlversuche: f)
    }
    let tag: TimeInterval = 86_400
    let s74 = status(tage: 100, letzte: jetzt.addingTimeInterval(-74 * tag), n: nil, f: 0)
    let s76 = status(tage: 100, letzte: jetzt.addingTimeInterval(-76 * tag), n: nil, f: 0)
    let sVorbei = status(tage: 100, letzte: jetzt.addingTimeInterval(-101 * tag), n: nil, f: 0)
    check(DestructionRules.showsDeadline(s74, now: jetzt) == nil, "§23: Frist bei 26 % Restzeit verborgen")
    check(DestructionRules.showsDeadline(s76, now: jetzt) != nil, "§23: Frist bei 24 % Restzeit sichtbar")
    check(DestructionRules.showsDeadline(sVorbei, now: jetzt) == nil, "§23: abgelaufene Frist nicht mehr gezeigt")
    check(DestructionRules.showsDeadline(status(tage: nil, letzte: jetzt, n: nil, f: 0), now: jetzt) == nil,
          "§23: ohne Totmann keine Frist")
    let erwartet: [(Int, Int?)] = [(0, nil), (4, nil), (5, 5), (9, 1), (10, nil), (14, nil)]
    for (f, rest) in erwartet {
        check(DestructionRules.remainingAttempts(status(tage: nil, letzte: nil, n: 10, f: f)) == rest,
              "§23: Zähler N = 10, \(f) Fehlversuche → \(rest.map(String.init) ?? "keine Warnung")")
    }
    check(DestructionRules.remainingAttempts(status(tage: nil, letzte: nil, n: 11, f: 5)) == nil
          && DestructionRules.remainingAttempts(status(tage: nil, letzte: nil, n: 11, f: 6)) == 5, "§23: N ungerade")
    check(DestructionTexts.remaining(1) == "Noch 1 Versuch bis zur Vernichtung"
          && DestructionTexts.remaining(4) == "Noch 4 Versuche bis zur Vernichtung", "§23: Text der Warnung")
    check(DestructionTexts.destroyedTitle(1) == "1 Eintrag wurde vernichtet"
          && DestructionTexts.destroyedTitle(3) == "3 Einträge wurden vernichtet", "§23: Text des Banners")
    check(DestructionTexts.summary(nil) == "Aus", "§23: Zusammenfassung aus")
    // Befund hygiene-5: Nach einer Vernichtung keine Frist mehr (sie verriete eine Vernichtungs-Sitzung).
    let s76Vernichtet = DestructionStatus(settings: DestructionSettings(deadmanDays: 100), lastGenuineUnlock: s76?.lastGenuineUnlock,
                                          failedAttempts: 0, deadline: s76?.deadline, destroyedTrigger: .duressPassword,
                                          destroyedAt: jetzt.addingTimeInterval(-3600))
    check(DestructionRules.showsDeadline(s76Vernichtet, now: jetzt) == nil, "hygiene-5: nach einer Vernichtung keine Frist")
}

// MARK: - Abläufe

@MainActor
func selbstvernichtungSnapshots() async {
    selbstvernichtungPruefungen()

    let demo = DemoHardware()
    let (model, store) = makeModel("selbstvernichtung")
    model.snapshotUseHardware(demo)
    model.setup.passphrase = Demodaten.passphrase
    model.setup.passphraseRepeat = Demodaten.passphrase
    await model.createVault()
    if let kit = model.kit {
        let gruppen = kit.pending.code.groups
        kit.confirmation = kit.pending.confirmationGroups.map { gruppen[$0] }
    }
    await model.kitConfirm()
    _ = await model.performReturning { try $0.importEntries(Demodaten.entries()) }
    model.settings.lastExternalBackupAt = Date()
    check(!model.offersDestruction, "§23: Stufe 1 bietet keine Selbstvernichtung an")

    // MARK: Stufe 4 (wie im Assistenten)
    model.openSettings()
    model.startLevelChange(to: .maximal)
    guard let wizard = model.wizard else {
        check(false, "§23: Assistent fehlt")
        return
    }
    model.wizardAdvance()
    wizard.password = Demodaten.masterPassword
    await model.wizardVerify()
    await model.wizardSetupTouchID()
    model.wizardAdvance()
    model.wizardCardHandwritten()
    let karte = wizard.cardText
    let scan = Task { await model.wizardScanCard() }
    _ = await warteBis { model.cardScan != nil }
    DemoScanner.current?.deliver(karte)
    await scan.value
    model.wizardAdvance()
    await model.wizardShowRecoveryKit()
    if let kit = model.kit, kit.isShared {
        for teil in 0..<3 {
            model.kitShowShare(teil)
            model.kitChooseHandwritten()
        }
        model.kitProceedToConfirm()
        kit.confirmation = kit.pending.shares.enumerated().map { k, share in
            share.groups[kit.pending.shareConfirmationGroups[k]]
        }
        await model.kitConfirm()
    }
    await model.wizardApply()
    await model.wizardFinish(removeOldBackups: false)
    model.closeSettings()
    check(model.level == .maximal && model.offersDestruction, "§23: Stufe 4 bietet die Selbstvernichtung an")

    // Drei Einträge mit Schutz 4 (versiegelt beim Anlegen, nur öffentliche Schlüssel nötig)
    let geschuetzt = [
        VaultEntry(title: "Krypto-Börse", username: "lena.muster", password: "Wb7#nQ2!zLm8xR4v",
                   url: "https://boerse.example", notes: "Wiederherstellungswörter im Bankfach", protection: .maximal),
        VaultEntry(title: "Notar-Akten", username: "l.muster", password: "Akte-Ufer-93!kp",
                   url: "https://akten.notar-beispiel.example", protection: .maximal),
        VaultEntry(title: "Bergtagebuch", username: "lena", password: "Grat-Firn-Wolke-58",
                   url: "https://tagebuch.example", protection: .maximal),
    ]
    for eintrag in geschuetzt {
        let fehler = await model.perform { try $0.upsert(eintrag) }
        check(fehler == nil, "§23: Schutz-4-Eintrag angelegt")
    }
    let id = { (titel: String) in model.entries.first { $0.title == titel }?.id }
    guard let boerse = id("Krypto-Börse"), let notar = id("Notar-Akten"), let tagebuch = id("Bergtagebuch") else {
        check(false, "§23: Schutz-4-Einträge fehlen")
        return
    }

    // MARK: Einstellungen → Selbstvernichtung (aus)
    model.openSettings()
    model.settingsState.fileVaultEncrypted = true
    check(DestructionTexts.summary(model.destruction?.settings) == "Aus", "§23: Zeile „Aus“")
    shot("139-einstellungen-selbstvernichtung-aus", model, size: CGSize(width: 920, height: 760))
    await model.showDestruction()
    guard let entwurf = model.destructionState, model.settingsState.page == .destruction else {
        check(false, "§23: Seite Selbstvernichtung fehlt")
        return
    }
    check(model.selectableDestructionEntries.map(\.title) == ["Bergtagebuch", "Krypto-Börse", "Notar-Akten"],
          "§23: nur Schutz 4/5 auswählbar")
    check(!entwurf.hasChanges && !entwurf.canContinue, "§23: ohne Änderung kein „Weiter“")
    shot("140-selbstvernichtung-aus", model, size: CGSize(width: 920, height: 1240))

    // Entwurf: zwei Einträge, Totmann 30 Tage, Zähler 20, Vernichtungs-Passwort
    if let e = model.entries.first(where: { $0.id == boerse }) { model.destructionToggle(e) }
    if let e = model.entries.first(where: { $0.id == notar }) { model.destructionToggle(e) }
    if let bank = model.entries.first(where: { $0.title == "Beispiel Bank" }) {
        model.destructionToggle(bank)
        check(!entwurf.selection.contains(bank.id), "§23: Schutz-1-Eintrag lässt sich nicht markieren")
    }
    entwurf.deadmanOn = true
    entwurf.deadmanDays = 30
    entwurf.counterOn = true
    entwurf.maxAttempts = 20
    model.destructionStartDuressEditing()
    entwurf.duressPassword = vernichtungsPasswort
    entwurf.duressRepeat = vernichtungsPasswort
    check(entwurf.duressAssessment.meetsPolicy, "§23: Vernichtungs-Passwort erfüllt die Regel")
    check(entwurf.arms && entwurf.canContinue && entwurf.needsNewKey, "§23: Einschalten verlangt VERNICHTEN und V")
    shot("141-selbstvernichtung-entwurf", model, size: CGSize(width: 920, height: 1500))

    // Vernichtungs-Passwort gleich dem Master-Passwort → abgelehnt (vor jedem Faktor)
    entwurf.duressPassword = Demodaten.masterPassword
    entwurf.duressRepeat = Demodaten.masterPassword
    model.destructionContinue()
    guard entwurf.step == .confirm else {
        check(false, "§23: Weiter → Bestätigung")
        return
    }
    entwurf.confirmWord = "VERNICHTEN"
    entwurf.masterPassword = Demodaten.masterPassword
    await model.destructionApply()
    check(entwurf.error == DestructionTexts.duressEqualsMaster && entwurf.collection == nil,
          "§23: Vernichtungs-Passwort = Master-Passwort abgelehnt, ohne Faktoren")
    shot("142b-bestaetigen-gleich-wie-master", model, size: CGSize(width: 920, height: 900))
    model.destructionBack()
    check(entwurf.step == .edit && entwurf.masterPassword.isEmpty && entwurf.confirmWord.isEmpty,
          "§23: Zurück verwirft die Bestätigung")
    entwurf.duressPassword = vernichtungsPasswort
    entwurf.duressRepeat = vernichtungsPasswort
    model.destructionContinue()
    shot("142-bestaetigen-einschalten", model, size: CGSize(width: 920, height: 900))

    // Falsches Wort
    entwurf.confirmWord = "vernichten"
    entwurf.masterPassword = Demodaten.masterPassword
    await model.destructionApply()
    check(entwurf.error == DestructionTexts.confirmWordWrong && entwurf.collection == nil,
          "§23: VERNICHTEN muss genau stimmen")
    shot("143-bestaetigen-wort-falsch", model, size: CGSize(width: 920, height: 900))

    // Richtig: Touch ID + Karte (Faktoren der Stufe), Passwort prüfen, Touch ID für V, schreiben
    entwurf.confirmWord = "VERNICHTEN"
    entwurf.error = nil
    let schluesselVorher = demo.entryKeyCount
    let sichern = Task { await model.destructionApply() }
    _ = await warteBis { model.cardScan != nil }
    DemoScanner.current?.deliver(karte)
    let schranke = demo.holdTouchID()
    let wartet = await warteBis(30) { entwurf.creatingKey && model.touchIDActive }
    check(wartet, "§23: Touch ID für den Vernichtungs-Schlüssel")
    shot("144-bestaetigen-touchid-schluessel", model, size: CGSize(width: 920, height: 900))
    schranke.signal()
    // Danach versiegelt der Kern die zwei Einträge an V: eine Freigabe für ihre Notfall-Gruppe (Touch ID + Karte).
    let gruppenKarten = await karteBisFertig(karte, model, sichern)
    check(gruppenKarten == 1, "§23: eine Freigabe je Notfall-Gruppe (\(gruppenKarten) Karten)")
    guard model.destruction?.settings.duressEnabled == true else {
        check(false, "§23: Sichern gescheitert: \(entwurf.error ?? "?")")
        return
    }
    check(demo.entryKeyCount == schluesselVorher + 1, "§23: neuer Vernichtungs-Schlüssel V")
    let an = model.destruction?.settings
    check(an?.deadmanDays == 30 && an?.maxFailedAttempts == 20 && an?.duressEnabled == true, "§23: Einstellungen gespeichert")
    check(model.destructibleEntries == [boerse, notar], "§23: zwei Einträge vernichtbar")
    check(model.destructionState?.step == .edit && model.destructionState?.hasChanges == false,
          "§23: nach dem Sichern zurück zum gespeicherten Stand")
    shot("145-selbstvernichtung-an", model, size: CGSize(width: 920, height: 1240))
    model.settingsBack()
    check(model.destructionState == nil, "§23: Entwurf beim Verlassen verworfen")
    check(DestructionTexts.summary(model.destruction?.settings) == "An · Totmann 30 Tage · Zähler 20 · Vernichtungs-Passwort",
          "§23: Zeile in den Einstellungen")
    shot("146-einstellungen-selbstvernichtung-an", model, size: CGSize(width: 920, height: 760))
    model.closeSettings()

    // Markierung im Detail; Schutz lässt sich nicht unter 4 senken
    model.select(boerse)
    shot("147-detail-vernichtbar", model)
    if let e = model.entries.first(where: { $0.id == boerse }) {
        let aufdecken = Task { await model.revealEntry(e) }
        if await warteBis(10, { model.cardScan != nil }) { DemoScanner.current?.deliver(karte) }
        await aufdecken.value
        model.editSelected()
        shot("147b-bearbeiten-vernichtbar", model, size: CGSize(width: 920, height: 1000))
        await model.cancelEdit()
    }

    // MARK: Echte Sitzung und Vernichtungs-Sitzung: gleiche Abfolge, gleiches Aussehen
    func entsperren(_ passwort: String) async {
        model.unlock.password = passwort
        let t = Task { await model.submitUnlock() }
        _ = await warteBis { model.cardScan != nil }
        DemoScanner.current?.deliver(karte)
        await t.value
        await model.refreshDestructionStatus()
    }
    model.lock()
    _ = await warteBis { model.unlock.header != nil }
    demo.clearLog()
    await entsperren(Demodaten.masterPassword)
    let echteAbfolge = demo.log
    check(model.screen == .unlocked && !model.isDuressSession, "§23: echte Sitzung")
    check(model.destructionBanner == nil, "§23: kein Banner ohne Vernichtung")
    if let bank = id("Beispiel Bank") { model.select(bank) }
    shot("148-tresor-echte-sitzung", model)

    model.lock()
    _ = await warteBis { model.unlock.header != nil }
    // Befund hygiene-5: Frist im letzten Viertel (letzte echte Entsperrung vor 25 von 30 Tagen) – vorher sichtbar.
    check(kernZustand(store, letztesEntsperren: Date().addingTimeInterval(-25 * 86_400), fehlversuche: 0),
          "hygiene-5: Zustand gesetzt")
    await model.refreshDestructionStatus()
    check(model.lockDeadline != nil, "hygiene-5: Frist vor der Vernichtungs-Sitzung sichtbar")
    let gesperrtVorher = model.destruction
    demo.clearLog()
    await entsperren(vernichtungsPasswort)
    guard model.screen == .unlocked, model.isDuressSession else {
        check(false, "§23: Vernichtungs-Sitzung geöffnet (wie .unlocked)")
        return
    }
    check(demo.log == echteAbfolge && echteAbfolge == ["touchid:Siegel entsperren", "karte"],
          "§23: gleiche Abfolge der Faktor-Abfragen (\(demo.log))")
    check(model.destructionBanner == nil && model.notice == nil, "§23: kein Banner, kein Hinweis")
    check(model.destructibleEntries.isEmpty && model.destroyedEntries.isEmpty, "§23: keine Markierungen")
    check(!model.entries.contains { $0.id == boerse || $0.id == notar }, "§23: vernichtete Einträge unsichtbar")
    check(model.entries.contains { $0.id == tagebuch }, "§23: nicht markierte bleiben")
    if let bank = id("Beispiel Bank") { model.select(bank) }
    shot("149-tresor-vernichtungs-sitzung", model)
    model.openSettings()
    model.settingsState.fileVaultEncrypted = true
    shot("150-vernichtungs-sitzung-einstellungen", model, size: CGSize(width: 920, height: 760))
    await model.showDestruction()
    check(model.destructionState?.destroyed == false, "§23: Vernichtungs-Sitzung zeigt keine Vernichtung")
    shot("150b-vernichtungs-sitzung-selbstvernichtung", model, size: CGSize(width: 920, height: 1240))
    model.closeSettings()
    check(DestructionRules.showsDeadline(model.destruction, now: Date()) != nil,
          "ablaeufe-3: Stand der Vernichtungs-Sitzung trägt die alte Frist (darf nicht auf den Sperrbildschirm)")

    model.lock()
    // Befund ablaeufe-3: direkt nach dem Sperren, ohne ausdrückliches Neulesen – keine Frist aus der Sitzung.
    check(model.lockDeadline == nil && model.lockRemainingAttempts == nil,
          "ablaeufe-3: direkt nach dem Sperren keine Frist der Vernichtungs-Sitzung")
    _ = await warteBis { model.unlock.header != nil }
    _ = await warteBis(5) { model.destruction != nil }
    check(model.destruction?.destroyedTrigger == .duressPassword && model.lockDeadline == nil,
          "ablaeufe-3: nach dem Neulesen aus zustand.json weiter keine Frist")
    await model.refreshDestructionStatus()
    check(model.destruction?.lastGenuineUnlock == gesperrtVorher?.lastGenuineUnlock,
          "§23: Vernichtungs-Passwort verlängert die Frist nicht")
    // hygiene-5: Die Frist verschwindet wie nach einem echten Entsperren (das sie verschoben hätte).
    check(model.lockDeadline == nil && model.lockRemainingAttempts == nil,
          "§23/hygiene-5: Sperrbildschirm unauffällig, keine stehen gebliebene Frist")
    shot("151-gesperrt-nach-vernichtungs-sitzung", model)

    // Nächstes echtes Entsperren: Banner mit Auslöser und Datum, vernichtete Einträge markiert
    await entsperren(Demodaten.masterPassword)
    check(model.screen == .unlocked && !model.isDuressSession, "§23: wieder echte Sitzung")
    check(model.destroyedEntries.count == 2, "§23: zwei vernichtete Einträge gemeldet")
    check(model.destructionBanner?.title == "2 Einträge wurden vernichtet"
          && model.destructionBanner?.detail.hasPrefix("Vernichtungs-Passwort, ") == true, "§23: Banner")
    if let bank = id("Beispiel Bank") { model.select(bank) }
    shot("152-tresor-banner-vernichtet", model)
    model.select(boerse)
    if let e = model.entries.first(where: { $0.id == boerse }) {
        let aufdecken = Task { await model.revealEntry(e) }
        if await warteBis(3, { model.cardScan != nil }) { model.cancelCardScan() }
        await aufdecken.value
        check(model.visibleSecrets(e) == nil && model.browser.error != nil && model.cardScan == nil
              && !model.touchIDActive, "§23: vernichteter Eintrag lässt sich nicht aufdecken (ohne Faktor-Abfrage)")
        model.browser.error = nil
    }
    shot("153-detail-vernichtet", model)
    await model.showDestruction()
    check(model.destructionState?.destroyed == true && model.destructionState?.needsNewKey == false
          && model.destructionState?.canContinue == false, "§23: Seite zeigt die Vernichtung, gesperrt bis „Entfernen“")
    check(model.blocksLevelChange(to: .hoch) && !model.blocksLevelChange(to: .festung),
          "§23: Stufe unter 4 erst nach dem Ausschalten")
    shot("154-selbstvernichtung-nach-vernichtung", model, size: CGSize(width: 920, height: 1400))
    await model.removeDestroyedEntriesNow()
    check(!model.entries.contains { $0.id == boerse || $0.id == notar } && model.destructionBanner == nil
          && model.destroyedEntries.isEmpty, "§23: „Entfernen“ räumt Einträge und Banner weg")
    check(model.destruction?.destroyedAt == nil && model.destruction?.settings.anyTriggerEnabled == false
          && !model.destructionConfigured, "§23: Vermerk entfernt, Selbstvernichtung aus")
    check(model.destructionState?.destroyed == false && model.destructionState?.savedDestructible.isEmpty == true,
          "§23: offene Seite zeigt den neuen Stand")

    // MARK: Neu markieren (neuer Schlüssel V), dann Sperrbildschirm: Frist und Zähler
    await model.showDestruction()
    if let d = model.destructionState, let e = model.entries.first(where: { $0.id == tagebuch }) {
        model.destructionToggle(e)
        // Nach „Entfernen“ ist alles aus: Auslöser neu wählen.
        d.deadmanOn = true
        d.deadmanDays = 30
        d.counterOn = true
        d.maxAttempts = 20
        check(d.arms && d.needsNewKey && !d.duressEditing, "§23: neu markiert → VERNICHTEN, neuer Schlüssel")
        model.destructionContinue()
        d.confirmWord = "VERNICHTEN"
        d.masterPassword = Demodaten.masterPassword
        let schluessel = demo.entryKeyCount
        let neu = Task { await model.destructionApply() }
        await karteBisFertig(karte, model, neu)
        check(demo.entryKeyCount == schluessel + 1 && model.destructibleEntries == [tagebuch]
              && model.destruction?.settings.deadmanDays == 30, "§23: wieder eingeschaltet (\(d.error ?? "ok"))")
    }
    model.closeSettings()

    // Befund hygiene-1 (Probe B): Sperren mit nicht eingerichtetem Schutz 5 → keine Kopie des vernichtbaren Eintrags.
    await hygieneProbeB(model, karte: karte, eintrag: tagebuch, entsperren: entsperren)

    model.lock()
    _ = await warteBis { model.unlock.header != nil }
    check(kernZustand(store, letztesEntsperren: Date().addingTimeInterval(-24 * 86_400), fehlversuche: 0),
          "§23: Zustand für das Bild gesetzt")
    await model.refreshDestructionStatus()
    check(model.lockDeadline != nil && model.lockRemainingAttempts == nil, "§23: nur die Frist")
    shot("155-gesperrt-frist", model)

    check(kernZustand(store, letztesEntsperren: Date().addingTimeInterval(-24 * 86_400), fehlversuche: 10),
          "§23: Zähler für das Bild gesetzt")
    await model.refreshDestructionStatus()
    check(model.lockRemainingAttempts == 10, "§23: ab N/2 gewarnt")
    shot("156-gesperrt-zaehler", model)
    await entsperren("falsch-falsch-falsch-falsch")
    _ = await warteBis(5) { model.destruction?.failedAttempts == 11 }
    check(model.screen == .locked && model.unlock.error != nil, "§23: falsches Passwort")
    check(model.destruction?.failedAttempts == 11 && model.lockRemainingAttempts == 9,
          "§23: Fehlversuch gezählt, Warnung nachgeführt")
    shot("157-gesperrt-falsch-zaehler", model) { sperrbildschirmGeometrie($0, "157") }
    // Kleinstes Fenster (SPEC §7, 760×480): Befund design-2 – die Frist lief als Überlagerung in die Zähler-Warnung.
    // Gemessen an den Rahmen der zugänglichen Elemente, nicht nur behauptet.
    shot("157b-gesperrt-klein", model, size: CGSize(width: 760, height: 480)) { sperrbildschirmGeometrie($0, "157b") }

    // Totmann abgelaufen (gesperrt, beim nächsten Takt): vernichten, Frist verschwindet
    check(kernZustand(store, letztesEntsperren: Date().addingTimeInterval(-31 * 86_400), fehlversuche: 0),
          "§23: abgelaufene Frist gesetzt")
    await model.deadmanTick()
    check(model.destruction?.destroyedTrigger == .deadman && model.screen == .locked, "§23: Totmann vernichtet gesperrt")
    check(model.lockDeadline == nil && model.lockRemainingAttempts == nil, "§23: danach keine Frist mehr")
    await entsperren(Demodaten.masterPassword)
    check(model.destructionBanner?.title == "1 Eintrag wurde vernichtet"
          && model.destructionBanner?.detail.hasPrefix("Totmann-Schalter, ") == true, "§23: Banner nach Totmann")
    model.select(tagebuch)
    shot("158-tresor-banner-totmann", model)

    // Befund hygiene-1: Totmann während einer offenen Bearbeitung – keine Kopie der vernichteten Geheimteile.
    await hygieneTotmannBeimBearbeiten(model, store, karte: karte, entsperren: entsperren)
    model.lock()
}

/// Befund design-2: Auf dem Sperrbildschirm mit Fehlermeldung, Zähler-Warnung und Totmann-Frist schneidet sich nichts,
/// und alles liegt im Fenster (auch im kleinsten). Reihenfolge: Logo → Feld → Warnung → Frist → „Notfallcode verwenden“.
@MainActor
func sperrbildschirmGeometrie(_ messung: Messung, _ bild: String) {
    let r = messung.rahmen
    guard let logo = r["lock.logo"], let feld = r["lock.field"], let warnung = r["lock.attempts"],
          let frist = r["lock.deadline"], let notfall = r["lock.recovery"] else {
        check(false, "design-2 (\(bild)): Logo, Feld, Warnung, Frist oder Notfallweg nicht gemessen")
        return
    }
    check(logo.maxY <= feld.minY && feld.maxY <= warnung.minY && warnung.maxY <= frist.minY
          && frist.maxY <= notfall.minY,
          "design-2 (\(bild)): Warnung, Frist und Notfallweg überdecken sich nicht")
    check([logo, feld, warnung, frist, notfall].allSatisfy { messung.fenster.contains($0) },
          "design-2 (\(bild)): alles liegt im Fenster")
}
