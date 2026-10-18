import AppKit
import SiegelCore
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Hygiene-Befunde der zweiten Prüfung (SPEC v4.4): Sperren speichert eine offene Bearbeitung nie mit tieferem Schutz und
// legt keine Klartext-Kopie geschützter oder vernichtbarer Einträge an (hygiene-1: Probe A hier in Stufe 1, Probe B und
// der Totmann während der Bearbeitung in `selbstvernichtungSnapshots`), Zwischenablage bei der Sperre durch den
// App-Wechsel (hygiene-2), ⌘C aus Geheimnis-Feldern (hygiene-3), Kamera-Vorschau auf externen Bildschirmen (hygiene-4).
// hygiene-5 (Frist nach einer Vernichtungs-Sitzung) prüft `selbstvernichtungSnapshots`. Bilder ab 190.
// Die echte Zwischenablage bleibt unberührt: Die Prüfungen setzen nur den Merker, mit einem fremden `changeCount`.

@MainActor
func hygieneBefundeSnapshots() async {
    await hygieneOhneFaktor()
    await hygieneSchutzStufe1()
    await hygieneStufe4()
}

/// Öffnet einen gesperrten Tresor über die Oberfläche (Stufe 4: Touch ID der Attrappe läuft durch, Karte liefern).
/// Danach die Haken der Tresor-Ansicht wie bei ihrem Erscheinen (ohne Bild wäre „Sperren ohne Datenverlust“ nicht
/// eingehängt).
@MainActor
func hygieneEntsperren(_ model: AppModel, karte: String? = nil) async {
    _ = await warteBis(5) { model.unlock.header != nil }
    model.unlock.password = Demodaten.masterPassword
    let t = Task { await model.submitUnlock() }
    if let karte {
        await karteBisFertig(karte, model, t)
    } else {
        await t.value
    }
    if model.isUnlocked { model.installVaultHooks() }
}

// MARK: - hygiene-1: Stufe 1 ohne Touch ID (Schutz 1 bleibt der einzige mögliche)

@MainActor
func hygieneOhneFaktor() async {
    do {
        let (_, store) = makeModel("hygiene-ohne-faktor")
        let pw = Demodaten.masterPassword
        let (vault, _) = try await offMain { try store.create(masterPassword: pw) }
        try vault.upsert(VaultEntry(title: "Bibliothek", username: "lena", password: "Buch-Regal-Lampe-7",
                                    url: "https://bibliothek.example", totp: "JBSWY3DPEHPK3PXP"))
        vault.lock()
        let model = dateiModel(store, DemoHardware())
        await hygieneEntsperren(model)
        guard model.screen == .unlocked, let id = model.entries.first(where: { $0.title == "Bibliothek" })?.id else {
            check(false, "hygiene-1: Tresor ohne Faktor entsperrt")
            return
        }
        let anzahl = model.entries.count
        model.select(id)
        model.editSelected()
        model.browser.editor?.draft.password = "Buch-Regal-Lampe-8"
        model.browser.editor?.draft.protection = .fingerabdruck
        // ⌘L: Der gewählte Schutz ist nicht eingerichtet, gespeichert wird mit Schutz 1 – mit Hinweis, ohne Ablehnung.
        model.lock()
        check(model.screen == .locked && model.lockNotice
              == "Die offene Bearbeitung ist mit Schutz 1 statt 2 gespeichert – für Schutz 2 fehlt noch: Touch ID.",
              "hygiene-1: ohne Touch ID mit Schutz 1 gespeichert, Hinweis (\(model.lockNotice ?? "keiner"))")
        await hygieneEntsperren(model)
        let e = model.entries.first { $0.id == id }
        check(model.entries.count == anzahl && e?.password == "Buch-Regal-Lampe-8" && e?.protection == .normal
              && e?.totp == "JBSWY3DPEHPK3PXP", "hygiene-1: derselbe Eintrag gespeichert, keine Kopie")
        model.lock()
    } catch {
        fehler.append("hygiene-1 ohne Faktor: \(error)")
    }
}

// MARK: - hygiene-1 Probe A und hygiene-3 in Stufe 1 (Touch ID nur für Einträge)

@MainActor
func hygieneSchutzStufe1() async {
    do {
        let demo = DemoHardware()
        let (_, store) = makeModel("hygiene-stufe1")
        let pw = Demodaten.masterPassword
        let (vault, _) = try await offMain { try store.create(masterPassword: pw) }
        let eintragsSchluessel = try demo.enrollEntryKey(directory: store.hardwareDirectory)
        try await offMain {
            try vault.enrollFactors(NewFactorMaterial(entryKey: eintragsSchluessel), masterPassword: pw,
                                    currentFactors: FactorSecrets())
        }
        for entry in Demodaten.entries().prefix(3) { try vault.upsert(entry) }
        try vault.upsert(VaultEntry(title: "Bank", username: "lena.muster", password: "Fluss-Moos-Tanne-41",
                                    url: "https://bank.example", notes: "Kartennummer im Ordner", protection: .hoch))
        try vault.upsert(VaultEntry(title: "Velo-Verleih", username: "lena", password: "Kette-Sattel-Pedal-3",
                                    url: "https://velo.example"))
        vault.lock()
        let model = dateiModel(store, demo)
        await hygieneEntsperren(model)
        guard model.screen == .unlocked, let bank = model.entries.first(where: { $0.title == "Bank" })?.id,
              let velo = model.entries.first(where: { $0.title == "Velo-Verleih" })?.id else {
            check(false, "hygiene: Stufe 1 mit Eintrags-Touch-ID entsperrt")
            return
        }
        check(model.level == .standard && model.enrolledFactors == [.secureEnclave], "hygiene: Stufe 1, Touch ID für Einträge")
        let anzahl = model.entries.count

        // hygiene-3: Die Dauer für ⌘C aus Geheimnis-Feldern entsteht beim Kopieren (Einstellung ∧ Stufe ∧ Schutz).
        model.settings.clipboardSeconds = 90
        check(SecretPasteboardProbe.fieldCopyLifetime == 90, "hygiene-3: ohne Bearbeitung gilt die Einstellung (90 s)")
        model.select(bank)
        model.editSelected()
        check(model.browser.editor?.secretsLocked == true, "hygiene-1: Schutz 3 im Bearbeiten versiegelt")
        await model.unlockEditorSecrets()
        guard let editor = model.browser.editor, !editor.secretsLocked else {
            check(false, "hygiene-1: Geheimteile im Bearbeiten aufgedeckt")
            return
        }
        check(SecretPasteboardProbe.fieldCopyLifetime == 15,
              "hygiene-3: ⌘C beim Bearbeiten eines Schutz-3-Eintrags höchstens 15 s (Einstellung 90 s)")
        model.settings.clipboardSeconds = 30

        // Probe A: Schutz 4 gewählt (Karte nicht eingerichtet), dann Auto-Sperre → gespeichert mit Schutz 3, Hinweis.
        editor.draft.protection = .maximal
        check(!model.missingFactors(for: .maximal).isEmpty, "hygiene-1: Karte nicht eingerichtet")
        model.lock(reason: .inactivity)
        let hinweisA = "Die offene Bearbeitung ist mit Schutz 3 statt 4 gespeichert – für Schutz 4 fehlt noch: QR-Schlüsselkarte."
        check(model.screen == .locked && model.lockNotice == hinweisA,
              "hygiene-1 (Probe A): Hinweis auf dem Sperrbildschirm (\(model.lockNotice ?? "keiner"))")
        _ = await warteBis(5) { model.unlock.header != nil }
        shot("190-gesperrt-schutz-nicht-eingerichtet", model)
        await hygieneEntsperren(model)
        check(model.notice?.text == hinweisA, "hygiene-1 (Probe A): Hinweis nach dem Entsperren")
        check(model.entries.count == anzahl && !model.entries.contains { $0.title.hasPrefix("Entwurf") },
              "hygiene-1 (Probe A): kein zusätzlicher Entwurf")
        check(!model.entries.contains { $0.password == "Fluss-Moos-Tanne-41" },
              "hygiene-1 (Probe A): Passwort nirgends offen gespeichert")
        let a = model.entries.first { $0.id == bank }
        check(a?.protection == .hoch && a?.secretsSealed == true, "hygiene-1 (Probe A): Bank bleibt Schutz 3, versiegelt")

        // Probe A mit geänderten Geheimteilen und 2FA: Inhalt bleibt erhalten, mit Schutz 3 versiegelt.
        model.select(bank)
        model.editSelected()
        await model.unlockEditorSecrets()
        model.browser.editor?.draft.password = "Fluss-Moos-Tanne-42"
        model.browser.editor?.draft.totp = "JBSWY3DPEHPK3PXP"
        model.browser.editor?.draft.protection = .festung
        model.lock(reason: .inactivity)
        check(model.lockNotice?.hasPrefix("Die offene Bearbeitung ist mit Schutz 3 statt 5 gespeichert") == true,
              "hygiene-1: Schutz 5 → mit 3 gespeichert, Hinweis")
        await hygieneEntsperren(model)
        check(model.entries.count == anzahl && !model.entries.contains { $0.password == "Fluss-Moos-Tanne-42" },
              "hygiene-1: geänderte Geheimteile ohne Kopie")
        if let e = model.entries.first(where: { $0.id == bank }) {
            model.select(bank)
            await model.revealEntry(e)
            let offen = model.visibleSecrets(e)
            check(e.protection == .hoch && offen?.password == "Fluss-Moos-Tanne-42" && offen?.totp == "JBSWY3DPEHPK3PXP"
                  && offen?.history.contains { $0.password == "Fluss-Moos-Tanne-41" } == true,
                  "hygiene-1: Passwort, 2FA und Verlauf versiegelt gespeichert")
            model.hideEntrySecrets()
        }

        // Offener Eintrag, Schutz 4 gewählt: gespeichert mit dem höchsten eingerichteten (3), nicht offen gelassen.
        model.select(velo)
        model.editSelected()
        model.browser.editor?.draft.protection = .maximal
        model.lock(reason: .inactivity)
        check(model.lockNotice == hinweisA, "hygiene-1: offener Eintrag mit Schutz 3 statt 4 gespeichert")
        await hygieneEntsperren(model)
        let v = model.entries.first { $0.id == velo }
        check(model.entries.count == anzahl && v?.protection == .hoch && v?.secretsSealed == true,
              "hygiene-1: offener Eintrag versiegelt (Schutz 3), keine Kopie")
        model.lock()
    } catch {
        fehler.append("hygiene Stufe 1: \(error)")
    }
}

// MARK: - Stufe 4: Kamera-Vorschau (hygiene-4), ⌘C (hygiene-3), Zwischenablage beim App-Wechsel (hygiene-2)

/// Rendert die Wurzelansicht offscreen und sucht die Kamera-Vorschau (`CameraPreview`) im Ansichtsbaum.
@MainActor
func zeigtKameraVorschau(_ model: AppModel, external: Bool) -> Bool {
    let host = NSHostingView(rootView: RootView(model: model).snapshotSecretGate(external ? .external : nil))
    host.frame = CGRect(x: 0, y: 0, width: 920, height: 600)
    let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    window.sharingType = .none
    window.contentView = host
    pump(0.35)
    host.layoutSubtreeIfNeeded()
    pump(0.15)
    func enthaelt(_ view: NSView) -> Bool {
        String(describing: type(of: view)).contains("PreviewHostView") || view.subviews.contains(where: enthaelt)
    }
    let gefunden = enthaelt(host)
    window.contentView = nil
    window.close()
    return gefunden
}

@MainActor
func hygieneStufe4() async {
    do {
        let t = try await dateiStufe4("hygiene-stufe4")
        let model = dateiModel(t.store, t.demo)

        // hygiene-4: Kamerabild (Attrappe mit dem QR-Code der Karte) beim Entsperren
        let vorschau = CALayer()
        vorschau.backgroundColor = NSColor.darkGray.cgColor
        vorschau.contents = t.demo.cardImage(payload: t.karte, pixels: 320)
        vorschau.contentsGravity = .resizeAspect
        DemoScanner.vorschau = vorschau
        _ = await warteBis(5) { model.unlock.header != nil }
        model.unlock.password = Demodaten.masterPassword
        let entsperren = Task { await model.submitUnlock() }
        _ = await warteBis { model.cardScan != nil && DemoScanner.current?.running == true }
        check(model.cardScan?.camera == .running, "hygiene-4: Kamera läuft (Attrappe mit Vorschau)")
        check(zeigtKameraVorschau(model, external: false), "hygiene-4: Vorschau auf dem eingebauten Bildschirm sichtbar")
        check(!zeigtKameraVorschau(model, external: true), "hygiene-4: Vorschau auf externem Bildschirm verdeckt")
        shot("191-karte-scannen-vorschau", model)
        shot("192-karte-scannen-externer-bildschirm", model, external: true)
        check(DemoScanner.current?.running == true, "hygiene-4: Erkennung läuft trotz verdeckter Vorschau")
        DemoScanner.current?.deliver(t.karte)
        await entsperren.value
        DemoScanner.vorschau = nil
        guard model.screen == .unlocked, model.level == .maximal else {
            check(false, "hygiene: Stufe 4 entsperrt")
            return
        }

        // hygiene-3: Einstellung ändern, ohne refreshSnapshot → ⌘C bleibt bei der Grenze der Stufe.
        model.settings.clipboardSeconds = 60
        check(model.effectiveClipboardSeconds() == 15 && SecretPasteboardProbe.fieldCopyLifetime == 15,
              "hygiene-3: Stufe 4, Einstellung 60 s → ⌘C aus Feldern 15 s")
        model.settings.clipboardSeconds = 30

        // hygiene-2: Die Sperre beim App-Wechsel lässt ein eben kopiertes Geheimnis bis zum Ablauf stehen.
        SecretPasteboardProbe.useDefaults(UserDefaults(suiteName: defaultsSuite))
        defer { SecretPasteboardProbe.useDefaults(nil) }
        check(model.policy.lockOnDeactivate && model.effectiveClipboardSeconds() == 15, "hygiene-2: Stufe 4 sperrt beim Wechsel")
        SecretPasteboardProbe.rememberForeignCopy(lifetime: 15)
        check(SecretPasteboardProbe.remembered && SecretPasteboardProbe.preventsAppNap,
              "hygiene-2: Merker gesetzt, App Nap verhindert")
        model.lock(reason: .deactivated)
        check(model.screen == .locked && SecretPasteboardProbe.remembered && SecretPasteboardProbe.preventsAppNap,
              "hygiene-2: Sperre beim App-Wechsel leert die Zwischenablage nicht sofort")
        // Bildschirm aus (bzw. Ruhezustand, Bildschirmsperre, Benutzerwechsel) leert auch nach dieser Sperre, obwohl
        // die Auto-Sperre nichts mehr zu sperren hat.
        let auto = AutoLock(minutes: { 5 }, isArmed: { false }, lockNow: { _ in })
        auto.start()
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.screensDidSleepNotification, object: NSWorkspace.shared)
        check(!SecretPasteboardProbe.remembered && !SecretPasteboardProbe.preventsAppNap,
              "hygiene-2: Bildschirm aus leert nach der Sperre beim App-Wechsel")
        auto.stop()
        // Ablauf läuft auch bei gesperrtem Tresor
        SecretPasteboardProbe.rememberForeignCopy(lifetime: 0.3)
        check(await warteBis(5) { !SecretPasteboardProbe.remembered }, "hygiene-2: Ablauf leert auch gesperrt")
        check(!SecretPasteboardProbe.preventsAppNap, "hygiene-2: Aktivität gegen App Nap nach dem Ablauf beendet")
        // ⌘L und Inaktivität leeren weiter sofort.
        for anlass in [LockReason.manual, .inactivity] {
            await hygieneEntsperren(model, karte: t.karte)
            SecretPasteboardProbe.rememberForeignCopy(lifetime: 15)
            model.lock(reason: anlass)
            check(model.screen == .locked && !SecretPasteboardProbe.remembered, "hygiene-2: \(anlass) leert sofort")
        }
    } catch {
        fehler.append("hygiene Stufe 4: \(error)")
    }
}

// MARK: - hygiene-1 in Stufe 4 mit Selbstvernichtung (aus `selbstvernichtungSnapshots`)

/// Probe B: vernichtbarer Eintrag mit Schutz 4 (Totmann an), im Bearbeiten aufgedeckt, Passwort geändert, Schutz 5
/// gewählt (kein Sicherheitsschlüssel), Auto-Sperre → derselbe Eintrag mit Schutz 4, weiter vernichtbar, keine Kopie.
@MainActor
func hygieneProbeB(_ model: AppModel, karte: String, eintrag id: UUID,
                   entsperren: @MainActor (String) async -> Void) async {
    let anzahl = model.entries.count
    model.select(id)
    model.editSelected()
    let aufdecken = Task { await model.unlockEditorSecrets() }
    await karteBisFertig(karte, model, aufdecken)
    guard let editor = model.browser.editor, !editor.secretsLocked else {
        check(false, "hygiene-1 (Probe B): Geheimteile im Bearbeiten aufgedeckt")
        return
    }
    editor.draft.password = "Grat-Firn-Wolke-59"
    editor.draft.protection = .festung
    check(!model.missingFactors(for: .festung).isEmpty, "hygiene-1 (Probe B): Sicherheitsschlüssel nicht eingerichtet")
    model.lock(reason: .inactivity)
    check(model.screen == .locked && model.lockNotice
          == "Die offene Bearbeitung ist mit Schutz 4 statt 5 gespeichert – für Schutz 5 fehlt noch: Sicherheitsschlüssel.",
          "hygiene-1 (Probe B): Hinweis (\(model.lockNotice ?? "keiner"))")
    _ = await warteBis(5) { model.unlock.header != nil }
    await entsperren(Demodaten.masterPassword)
    check(model.entries.count == anzahl && !model.entries.contains { $0.title.hasPrefix("Entwurf") }
          && !model.entries.contains { $0.password == "Grat-Firn-Wolke-59" },
          "hygiene-1 (Probe B): keine Kopie des vernichtbaren Eintrags")
    let e = model.entries.first { $0.id == id }
    check(e?.protection == .maximal && e?.secretsSealed == true && model.destructibleEntries.contains(id),
          "hygiene-1 (Probe B): bleibt Schutz 4 und vernichtbar")
    if let e {
        model.select(id)
        let t = Task { await model.revealEntry(e) }
        await karteBisFertig(karte, model, t)
        check(model.visibleSecrets(e)?.password == "Grat-Firn-Wolke-59", "hygiene-1 (Probe B): geändertes Passwort gespeichert")
        model.hideEntrySecrets()
    }
}

/// Totmann während einer offenen Bearbeitung: `deadmanTick` vernichtet und sperrt; die eben vernichteten Geheimteile
/// landen nirgends (früher als „Entwurf“ mit Notfallweg), Titel und Benutzername bleiben, der Hinweis sagt es.
@MainActor
func hygieneTotmannBeimBearbeiten(_ model: AppModel, _ store: VaultStore, karte: String,
                                  entsperren: @MainActor (String) async -> Void) async {
    await model.removeDestroyedEntriesNow()
    let neu = VaultEntry(title: "Gipfelbuch", username: "lena", password: "Firn-Grat-Nebel-12",
                         url: "https://gipfel.example", protection: .maximal)
    check(await model.perform { try $0.upsert(neu) } == nil, "hygiene-1: Schutz-4-Eintrag angelegt")
    guard let id = model.entries.first(where: { $0.title == "Gipfelbuch" })?.id else {
        check(false, "hygiene-1: Gipfelbuch fehlt")
        return
    }
    await model.showDestruction()
    guard let d = model.destructionState, let e = model.entries.first(where: { $0.id == id }) else {
        check(false, "hygiene-1: Seite Selbstvernichtung fehlt")
        return
    }
    model.destructionToggle(e)
    d.deadmanOn = true
    d.deadmanDays = 30
    model.destructionContinue()
    d.confirmWord = "VERNICHTEN"
    d.masterPassword = Demodaten.masterPassword
    let an = Task { await model.destructionApply() }
    await karteBisFertig(karte, model, an)
    check(model.destructibleEntries == [id] && model.destruction?.settings.deadmanDays == 30,
          "hygiene-1: Gipfelbuch vernichtbar, Totmann 30 Tage (\(d.error ?? "ok"))")
    model.closeSettings()

    model.select(id)
    model.editSelected()
    let aufdecken = Task { await model.unlockEditorSecrets() }
    await karteBisFertig(karte, model, aufdecken)
    model.browser.editor?.draft.password = "Firn-Grat-Nebel-13"
    model.browser.editor?.draft.username = "lena.berg"
    check(model.browser.editor?.secretsLocked == false, "hygiene-1: Gipfelbuch im Bearbeiten aufgedeckt")
    let anzahl = model.entries.count
    check(kernZustand(store, letztesEntsperren: Date().addingTimeInterval(-31 * 86_400), fehlversuche: 0),
          "hygiene-1: abgelaufene Frist gesetzt")
    await model.deadmanTick()
    check(model.screen == .locked && model.destruction?.destroyedTrigger == .deadman,
          "hygiene-1: Totmann vernichtet während der Bearbeitung und sperrt")
    check(model.lockNotice == "Beim Sperren gingen die geänderten Geheimteile verloren (Speichern gescheitert); "
          + "Titel, Benutzer und Website sind gespeichert.",
          "hygiene-1: ehrlicher Hinweis (\(model.lockNotice ?? "keiner"))")
    _ = await warteBis(5) { model.unlock.header != nil }
    shot("193-gesperrt-totmann-bearbeitung", model)
    await entsperren(Demodaten.masterPassword)
    check(model.entries.count == anzahl && !model.entries.contains { $0.title.hasPrefix("Entwurf") }
          && !model.entries.contains { $0.password == "Firn-Grat-Nebel-12" || $0.password == "Firn-Grat-Nebel-13" },
          "hygiene-1: keine Kopie der vernichteten Geheimteile")
    let g = model.entries.first { $0.id == id }
    check(g?.username == "lena.berg" && model.isDestroyed(g ?? neu), "hygiene-1: Metadaten gespeichert, Eintrag vernichtet")
}
