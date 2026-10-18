import AppKit
import SiegelCore
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Stufe 2: Tresor-Hauptansicht, Bearbeiten mit Generator, „Zuletzt gelöscht“, Abläufe (CSV, Sicherungen).
// Bilder ab 41; dazu Prüfungen der Logik (Website/Punycode, Suche, Übernehmen/Abbrechen, Sperren mit Entwurf,
// Papierkorb, Import/Export). Die Zwischenablage wird nie berührt (Rückmeldung direkt über `show`).

/// Platzhalter für die Fensterknöpfe (im randlosen Offscreen-Fenster fehlen sie), nur zur Beurteilung.
struct Fensterknoepfe: View {
    var body: some View {
        HStack(spacing: 9) {
            ForEach(0..<3, id: \.self) { _ in
                Circle()
                    .fill(Color(white: 0.88))
                    .overlay(Circle().strokeBorder(Color(white: 0.78), lineWidth: 0.5))
                    .frame(width: 14, height: 14)
            }
        }
        .padding(.leading, 9)
        .padding(.top, 9)
        .allowsHitTesting(false)
    }
}

@MainActor
func eintrag(_ model: AppModel, _ titel: String) -> UUID? {
    (model.entries + model.deletedEntries).first { $0.title == titel }?.id
}

@MainActor
func tresorSnapshots() async {
    websitePruefungen()

    // MARK: Tresor mit bestätigtem Kit und Demodaten
    let (model, store) = makeModel("tresor")
    model.setup.passphrase = Demodaten.passphrase
    model.setup.passphraseRepeat = Demodaten.passphrase
    await model.createVault()
    if let kit = model.kit {
        let gruppen = kit.pending.code.groups
        kit.confirmation = kit.pending.confirmationGroups.map { gruppen[$0] }
    }
    await model.kitConfirm()
    check(model.recoveryConfirmed && model.screen == .unlocked, "Kit bestätigt → Tresor")

    let demo = Demodaten.entries()
    let geloescht = Demodaten.deletedEntries()
    let import1 = await model.performReturning { try $0.importEntries(demo + geloescht) }
    if case let .success(r) = import1 { check(r.added == demo.count + geloescht.count, "Demo-Import vollständig") }
    for entry in geloescht {
        if let id = eintrag(model, entry.title) { _ = await model.perform { try $0.delete(id: id) } }
    }
    check(model.entries.count == demo.count, "Demo: aktive Einträge")
    check(model.deletedEntries.count == geloescht.count, "Demo: gelöschte Einträge")
    model.settings.lastExternalBackupAt = Date()

    shot("41-tresor-liste", model)

    // Liste sortiert, Suche nur über Titel/Benutzer/Website
    let titel = model.visibleEntries.map(\.title)
    check(titel.first == "Beispiel Bank" && titel.last == "Wolkenspeicher", "Liste alphabetisch")
    model.searchText = "bank"
    check(model.visibleEntries.map(\.title) == ["Beispiel Bank"], "Suche über Titel")
    model.searchText = "S-2045"
    check(model.visibleEntries.map(\.title) == ["Bibliothek Seeland"], "Suche über Benutzername")
    model.searchText = "strom-nord"
    check(model.visibleEntries.map(\.title) == ["Stromversorger Nord"], "Suche über Website")
    model.searchText = "Vertragsnummer"
    check(model.visibleEntries.isEmpty, "Notizen werden nicht durchsucht")
    model.searchText = "STEUERN"
    check(model.visibleEntries.count == 1, "Suche ohne Gross/Klein")
    model.searchText = ""

    // Auswahl + Detail
    guard let bankID = eintrag(model, "Beispiel Bank") else {
        check(false, "Beispiel Bank fehlt")
        return
    }
    model.select(bankID)
    check(model.canEditEntry, "Auswahl → ⌘E aktiv")
    shot("42-tresor-auswahl", model)

    model.toggleReveal(bankID)
    model.show(Notice("Kopiert – wird in 30 s gelöscht", symbol: "doc.on.doc"), seconds: 30)
    shot("43-tresor-aufgedeckt", model, keepNotice: true)
    model.notice = nil

    model.toggleReveal(bankID)
    check(model.browser.revealedPassword == nil, "Auge schliesst wieder")
    model.toggleHistory()
    model.toggleHistoryReveal(0)
    shot("44-tresor-verlauf", model)
    model.browser.confirmingClearHistory = true
    shot("45-tresor-verlauf-leeren", model)
    model.browser.confirmingClearHistory = false

    // Tastatur: Pfeile
    model.moveSelection(by: 1)
    check(model.browser.selection == eintrag(model, "Bergbahnen Pass"), "Pfeil runter → nächster Eintrag")
    check(!model.browser.historyExpanded, "Auswahlwechsel klappt den Verlauf zu")
    model.moveSelection(by: -1)
    check(model.browser.selection == bankID, "Pfeil hoch → zurück")

    if let forum = eintrag(model, "Velo-Forum") {
        check(model.masterPasswordReuse.contains(forum), "Gleich wie Master-Passwort erkannt")
        model.select(forum)
        shot("46-tresor-gleich-wie-master", model)
    }
    if let paket = eintrag(model, "Paket-Dienst") {
        model.select(paket)
        let site = model.selectedEntry.flatMap { Website.parse($0.url) }
        check(site?.mixedScripts == true && site?.displayHost.hasPrefix("xn--") == true, "Gemischte Schrift → Punycode")
        shot("47-tresor-punycode", model)
    }

    // MARK: Bearbeiten
    model.select(bankID)
    model.editSelected()
    check(model.browser.mode == .edit && !model.canEditEntry, "⌘E → Bearbeiten")
    shot("48-tresor-bearbeiten", model)

    model.toggleGenerator()
    model.browser.editor?.generated = Demodaten.generated
    shot("49-tresor-generator", model)

    // Generator-Optionen: mindestens eine Klasse bleibt
    model.updateGenerator { $0.uppercase = false; $0.lowercase = false; $0.digits = false; $0.symbols = false }
    check(model.browser.editor?.options.symbols == true, "Generator: letzte Klasse bleibt an")
    model.updateGenerator { $0.length = 200 }
    check(model.browser.editor?.options.length == 64, "Generator: Länge höchstens 64")
    model.updateGenerator { $0.length = 24 }

    // Übernehmen speichert sofort; Abbrechen stellt das alte wieder her, das generierte bleibt im Verlauf
    let altesPasswort = model.selectedEntry?.password ?? ""
    model.browser.editor?.generated = Demodaten.generated
    model.browser.editor?.draft.title = "Beispiel Bank (geändert)"
    await model.applyGenerated()
    let nachUebernehmen = model.entries.first { $0.id == bankID }
    check(nachUebernehmen?.password == Demodaten.generated, "Übernehmen speichert sofort")
    check(nachUebernehmen?.title == "Beispiel Bank", "Übernehmen speichert nur das Passwort")
    check(nachUebernehmen?.history.contains { $0.password == altesPasswort } == true, "Altes Passwort im Verlauf")
    shot("50-tresor-uebernommen", model)
    await model.cancelEdit()
    let nachAbbrechen = model.entries.first { $0.id == bankID }
    check(nachAbbrechen?.password == altesPasswort, "Abbrechen stellt das alte Passwort wieder her")
    check(nachAbbrechen?.history.contains { $0.password == Demodaten.generated } == true, "Generiertes bleibt im Verlauf")
    check(nachAbbrechen?.title == "Beispiel Bank", "Abbrechen verwirft Formularänderungen")
    check(model.browser.mode == .browse && model.browser.selection == bankID, "Abbrechen → zurück zum Detail")

    // Sichern
    model.editSelected()
    model.browser.editor?.draft.username = "lena.muster.neu"
    await model.saveEdit()
    check(model.selectedEntry?.username == "lena.muster.neu", "Sichern speichert")
    model.editSelected()
    model.browser.editor?.draft.username = "lena.muster"
    await model.saveEdit()

    // Neuer Eintrag: leerer Titel ohne Website → Meldung, Eingabe bleibt
    model.newEntry()
    shot("51-tresor-neu", model)
    model.browser.editor?.draft.username = "nur-benutzer"
    await model.saveEdit()
    check(model.browser.editor?.error != nil && model.browser.mode == .edit, "Ohne Titel → Meldung, bleibt offen")
    model.browser.editor?.draft.url = "https://neu.example"
    await model.saveEdit()
    check(model.selectedEntry?.title == "neu.example", "Titel aus der Website")

    // Neuer Eintrag + Übernehmen + Abbrechen → „Zuletzt gelöscht“ (Passwort geht nicht verloren)
    let vorher = model.deletedEntries.count
    model.newEntry()
    model.toggleGenerator()
    model.browser.editor?.generated = "Generiert-Neu-12345!"
    await model.applyGenerated()
    check(model.entries.contains { $0.password == "Generiert-Neu-12345!" }, "Neu + Übernehmen legt an")
    await model.cancelEdit()
    check(model.deletedEntries.count == vorher + 1, "Neu + Übernehmen + Abbrechen → Zuletzt gelöscht")
    check(!model.entries.contains { $0.password == "Generiert-Neu-12345!" }, "… und nicht mehr in der Liste")

    // MARK: Suche
    model.select(bankID)
    model.searchText = "bank"
    shot("52-tresor-suche", model)
    model.searchText = "zzzz"
    shot("53-tresor-suche-leer", model)
    model.searchText = ""

    // MARK: Zuletzt gelöscht
    model.showTrash()
    shot("54-zuletzt-geloescht", model)
    if let kino = eintrag(model, "Kino-Club") {
        model.requestPurge(kino)
        shot("55-zuletzt-geloescht-bestaetigen", model)
        await model.purgeDeleted(kino)
        check(!model.deletedEntries.contains { $0.id == kino }, "Endgültig löschen")
    }
    if let abo = eintrag(model, "Altes Handy-Abo") {
        await model.restoreDeleted(abo)
        check(model.entries.contains { $0.id == abo }, "Wiederherstellen")
    }
    model.closeTrash()

    // Löschen → Zuletzt gelöscht, nächster Eintrag gewählt
    if let abo = eintrag(model, "Altes Handy-Abo") {
        model.select(abo)
        await model.deleteSelected()
        check(model.deletedEntries.contains { $0.id == abo }, "Löschen → Zuletzt gelöscht")
        check(model.browser.selection != nil && model.browser.selection != abo, "Nach dem Löschen nächster Eintrag")
    }

    // Verlauf leeren
    if let mail = eintrag(model, "Muster-Mail") {
        model.select(mail)
        await model.clearHistory(of: mail)
        check(model.selectedEntry?.history.isEmpty == true, "Verlauf leeren")
    }

    // MARK: Statuszeilen, externer Bildschirm, kleines Fenster
    model.select(bankID)
    model.toggleReveal(bankID)
    shot("56-tresor-extern", model, external: true)
    model.toggleReveal(bankID)
    shot("57-tresor-klein", model, size: CGSize(width: 760, height: 480))

    // MARK: Sperren speichert offene Bearbeitung (SPEC §6 a)
    model.select(bankID)
    model.editSelected()
    model.browser.editor?.draft.notes = "Entwurf vor dem Sperren"
    model.lock()
    check(model.screen == .locked && model.browser.editor == nil, "Sperren räumt die Bearbeitung weg")
    if case let .unlocked(v)? = try? await offMain({ try store.unlock(masterPassword: Demodaten.masterPassword) }) {
        check(v.entries.first { $0.id == bankID }?.notes == "Entwurf vor dem Sperren", "Sperren speichert die Bearbeitung")
        v.lock()
    }
    model.unlock.password = Demodaten.masterPassword
    await model.submitUnlock()
    check(model.screen == .unlocked, "Wieder entsperrt")
    model.settings.lastExternalBackupAt = Date()
    model.installVaultHooks()
    model.newEntry()
    model.browser.editor?.draft.password = "nur-ein-passwort"
    model.lock()
    model.unlock.password = Demodaten.masterPassword
    await model.submitUnlock()
    check(model.entries.contains { $0.title.hasPrefix("Entwurf ") && $0.password == "nur-ein-passwort" },
          "Ungültige Bearbeitung → „Entwurf <Datum>“")

    // MARK: Abläufe
    await ablaufSnapshots(model)

    // MARK: Leerer Tresor mit allen Statuszeilen
    let (leer, _) = makeModel("leer")
    leer.setup.passphrase = Demodaten.passphrase
    leer.setup.passphraseRepeat = Demodaten.passphrase
    await leer.createVault()
    leer.kitSkip()
    leer.settings.lastExternalBackupAt = nil
    check(leer.needsRecoveryKitConfirmation && leer.showsExternalBackupHint, "Leer: beide Statuszeilen")
    shot("58-tresor-leer", leer)
    let (banner, _) = makeModel("banner")
    banner.setup.passphrase = Demodaten.passphrase
    banner.setup.passphraseRepeat = Demodaten.passphrase
    await banner.createVault()
    banner.kitSkip()
    _ = await banner.performReturning { try $0.importEntries(Demodaten.entries()) }
    banner.settings.lastExternalBackupAt = nil
    banner.snapshotSetExportedCSV(tempRoot.appendingPathComponent("x.noindex/Siegel-Export.csv"))
    if let id = eintrag(banner, "Wolkenspeicher") { banner.select(id) }
    shot("59-tresor-statuszeilen", banner)
    banner.dismissExportedCSVLine()
    check(banner.exportedCSV == nil, "Exportzeile wegklicken")
    // Befund #8/#14: gewählter zweiter Ort nicht erreichbar → Zeile in der Seitenleiste, Einstellungen mit Namen
    banner.settings.secondaryBackupBookmark = Data("kein-gueltiges-bookmark".utf8)
    banner.snapshotResolveSecondary()
    check(banner.secondaryBackupUnreachable && banner.showsSecondaryBackupWarning && !banner.showsExternalBackupHint,
          "Zweiter Ort nicht verbunden → eigene Zeile")
    check(banner.secondaryBackupName != nil, "Nicht verbundener Ort: Name statt „Nicht gewählt“")
    shot("59b-tresor-zweiter-ort-fehlt", banner)
    banner.openSettings()
    shot("59c-einstellungen-zweiter-ort-fehlt", banner, size: CGSize(width: 920, height: 2100))
    banner.closeSettings()
    banner.removeSecondaryBackupLocation()
    check(banner.secondaryBackupName == nil && !banner.showsSecondaryBackupWarning, "Ort entfernen")
    banner.lock()
    leer.lock()
}

// MARK: - Abläufe

@MainActor
func ablaufSnapshots(_ model: AppModel) async {
    let ordner = tempRoot.appendingPathComponent("ablaeufe", isDirectory: true)
    try? FileManager.default.createDirectory(at: ordner, withIntermediateDirectories: true)

    // CSV-Import über den echten Leser (Apple-Passwörter-Format)
    model.openSettings()
    model.request(.csvImport)
    check(model.flowState?.step == .importIntro, "CSV-Import: Start")
    shot("60-csv-import", model)
    let quelle = ordner.appendingPathComponent("passwoerter.csv")
    try? Data(Demodaten.csvApple.utf8).write(to: quelle)
    let anzahlVorher = model.entries.count
    await model.csvImportLoad(quelle)
    check(model.flowState?.importResult?.format == .applePasswords, "CSV: Format Apple erkannt")
    if let r = model.flowState?.importResult?.report {
        check(r.withOTPSecret == 1 && r.apostrophePrefixed == 1, "CSV: 2FA und Apostroph gezählt")
    }
    if let p = model.flowState?.importPreview {
        check(p.count == 6 && p.duplicates == 1 && p.conflicts == 1, "Vorschau: Dubletten und Konflikte")
    } else {
        check(false, "Vorschau fehlt")
    }
    shot("61-csv-import-vorschau", model)
    shot("61b-csv-import-vorschau-ganz", model, size: CGSize(width: 920, height: 1100))
    await model.csvImportRun()
    if let r = model.flowState?.importReport {
        check(r.added == 5 && r.skippedDuplicates == 1 && r.conflicts == 1, "Import: Bericht")
    }
    check(model.entries.count == anzahlVorher + 5, "Import: nur angehängt")
    check(model.entries.contains { $0.title == "Velo-Shop (Import)" }, "Import: Konflikt mit Zusatz")
    shot("62-csv-import-bericht", model)
    model.csvImportDeleteSource()
    check(!FileManager.default.fileExists(atPath: quelle.path), "Quelldatei endgültig gelöscht")
    shot("63-csv-import-geloescht", model)
    model.finishFlow()
    check(model.showsSettings && model.pendingFlow == nil, "Fertig → zurück in die Einstellungen")

    // CSV-Export
    model.request(.csvExport)
    shot("64-csv-export", model)
    let exportOrdner = ordner.appendingPathComponent("export", isDirectory: true)
    try? FileManager.default.createDirectory(at: exportOrdner, withIntermediateDirectories: true)
    model.csvExportSetFolder(exportOrdner)
    let verschluesselt = model.flowState?.exportFolderEncrypted == true
    model.snapshotFlow { $0.snapshotSet(step: .exportUnencrypted, folder: URL(fileURLWithPath: "/Volumes/USB-Stick"),
                                        encrypted: false) }
    shot("65-csv-export-unverschluesselt", model)
    model.csvExportSetFolder(exportOrdner)
    if !verschluesselt { model.csvExportAcceptUnencrypted() }
    check(model.flowState?.step == .exportPassword, "Export: Passwort-Schritt")
    model.flowState?.password = "falsch-falsch"
    await model.csvExportRun()
    check(model.flowState?.error == Fehlertexte.wrongPassword, "Export: falsches Passwort")
    shot("66-csv-export-passwort", model)
    model.flowState?.password = Demodaten.masterPassword
    await model.csvExportRun()
    let datei = model.exportedCSV
    check(model.flowState?.step == .exportDone && datei != nil, "Export: fertig")
    if let datei {
        check(FileManager.default.fileExists(atPath: datei.path), "Export: Datei geschrieben")
        check(datei.deletingLastPathComponent().pathExtension == "noindex", "Export: .noindex-Ordner")
    }
    shot("67-csv-export-fertig", model)
    model.deleteExportedCSV()
    if let datei {
        check(!FileManager.default.fileExists(atPath: datei.path), "Exportdatei gelöscht")
        check(!FileManager.default.fileExists(atPath: datei.deletingLastPathComponent().path), "Exportordner entfernt")
    }
    check(model.exportedCSV == nil, "Exportzeile weg nach dem Löschen")
    model.finishFlow()

    // Verschlüsselte Sicherung exportieren
    model.request(.backupExport)
    shot("68-sicherung-exportieren", model)
    let sicherung = ordner.appendingPathComponent("Siegel-Sicherung.siegel")
    await model.backupExportRun(to: sicherung)
    check(FileManager.default.fileExists(atPath: sicherung.path), "Sicherung exportiert")
    check(model.flowState?.backupIsExternal == false, "Temp-Ordner gilt nicht als extern")
    model.snapshotFlow { $0.snapshotSet(step: .backupExportDone, backup: URL(fileURLWithPath: "/Volumes/USB-Stick/Siegel-Sicherung-2026-10-16.siegel"), external: true) }
    shot("69-sicherung-exportiert", model)
    model.finishFlow()

    // Sicherung einspielen (ersetzt den Tresor)
    let eintraegeVorher = model.entries.count
    model.request(.backupImport)
    shot("70-sicherung-einspielen", model)
    model.backupImportSetFile(sicherung)
    model.flowState?.password = "falsch-falsch"
    await model.backupImportRun()
    check(model.flowState?.error != nil, "Einspielen: falsches Passwort")
    model.flowState?.error = nil
    model.flowState?.password = ""
    shot("71-sicherung-einspielen-passwort", model) { messung in
        // Befund design-3: nennt, was eine Sicherung ab Stufe 2 dazu braucht (Touch ID des Macs, auf dem sie entstand).
        check(messung.rahmen["flow.backupImportFactors"].map { messung.fenster.contains($0) } == true
              && BackupTexts.importFactors.contains("Touch ID des Macs, auf dem sie entstand"),
              "design-3: Einspielen nennt die Faktoren der Sicherung")
    }
    model.flowState?.password = Demodaten.masterPassword
    await model.backupImportRun()
    check(model.screen == .unlocked && model.pendingFlow == nil && !model.showsSettings, "Eingespielt → Tresor")
    check(model.entries.count == eintraegeVorher, "Eingespielt: gleiche Einträge")
    check(model.vault?.isLocked == false, "Eingespielt: neuer Tresor offen")

    // Gesperrt während eines Ablaufs: Zustand weg
    model.request(.csvExport)
    model.lock()
    check(model.flowState == nil && model.pendingFlow == nil, "Sperren verwirft den Ablauf")
}

// MARK: - Website und Punycode

@MainActor
func websitePruefungen() {
    check(Punycode.encode("bücher") == "bcher-kva", "Punycode bücher")
    check(Punycode.encode("münchen") == "mnchen-3ya", "Punycode münchen")
    check(Punycode.encode("пример") == "e1afmkfd", "Punycode пример")
    check(Punycode.encode("他们为什么不说中文") == "ihqwcrb4cv8a8dqg056pqjye", "Punycode RFC 3492 (Chinesisch)")

    let gemischt = Website.parse("https://p\u{0430}ypal.example/login")
    check(gemischt?.mixedScripts == true, "Kyrillisch + Lateinisch gemischt")
    check(gemischt?.displayHost.hasPrefix("xn--") == true, "Gemischt → Punycode")
    check(gemischt?.isOpenable == true && gemischt?.openURL?.host() == gemischt?.asciiHost, "Öffnen mit ASCII-Host")
    let kyrillisch = Website.parse("https://пример.рф")
    check(kyrillisch?.mixedScripts == false && kyrillisch?.displayHost == "пример.рф", "Rein kyrillisch → Unicode")
    let japanisch = Website.parse("日本語のテスト.example")
    check(japanisch?.mixedScripts == false, "Han + Hiragana + Katakana sind erlaubt")
    // Befund #12: einschriftige Teile, aber gemischter Host (kyrillisches Label unter lateinischer Endung)
    for homograph in ["https://аррӏе.com/login", "ебау.com", "https://соогӏе.ch", "пример.com"] {
        let site = Website.parse(homograph)
        check(site?.mixedScripts == true && site?.displayHost.hasPrefix("xn--") == true, "Homograph → Punycode: \(homograph)")
    }
    check(Website.parse("日本語.jp")?.mixedScripts == false, "Han + lateinische Endung bleibt Unicode")
    check(Website.parse("한국어.kr")?.mixedScripts == false, "Hangul + lateinische Endung bleibt Unicode")
    check(Website.parse("ελλάδα.com")?.mixedScripts == true, "Griechisch + lateinische Endung → Punycode")
    let umlaut = Website.parse("bücher.example")
    check(umlaut?.displayHost == "bücher.example" && umlaut?.asciiHost == "xn--bcher-kva.example", "Umlaut-Domain")

    check(Website.parse("example.com")?.openURL?.absoluteString == "https://example.com", "Ohne Schema → https")
    check(Website.parse("http://x.example/a?b=1")?.isOpenable == true, "http erlaubt")
    check(Website.parse("javascript:alert(1)")?.isOpenable == false, "javascript: nie öffnen")
    check(Website.parse("mailto:a@b.example")?.isOpenable == false, "mailto: nie öffnen")
    check(Website.parse("ftp://x.example")?.isOpenable == false, "ftp nie öffnen")
    check(Website.parse("file:///etc/hosts")?.isOpenable == false, "file nie öffnen")
    check(Website.parse("localhost:8080/x")?.openURL?.absoluteString == "https://localhost:8080/x", "Host mit Port")
    check(Website.parse("https://user@bank.example:443/x")?.displayHost == "bank.example", "Benutzerangabe weg")
    check(Website.parse("   ") == nil, "Leer → keine Website")
    check(Website.parse("https://www.velo-shop.example/")?.display == "www.velo-shop.example", "Anzeige ohne Schema")
}
