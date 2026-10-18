import AppKit
import CryptoKit
import SiegelCore
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Härtestufe v4, Stufe B: 2FA-Codes (§18), Offline-Sicherheitsbericht (§17), KeePass-Export (§19), Autofill-Stand
// (§20), Lizenzen (Befund #44) und die Review-Befunde #19–#48 der Oberfläche. Bilder ab 119.
// Nur Demodaten; die Zwischenablage wird nie berührt.

// MARK: - 2FA-Attrappe (RFC 6238), solange der Kern-Platzhalter nichts rechnet

/// Rechnet TOTP nach RFC 6238/4648 für die Snapshots. Die App nutzt immer `TOTP.parse`/`TOTP.code` des Kerns;
/// sobald der echte Kern eingesetzt ist, prüfen die Snapshots automatisch ihn (siehe `stufeBSnapshots`).
struct DemoTOTP: TOTPSource {
    func reading(_ uriOrSecret: String, at date: Date) -> TOTPReading? {
        var geheimnis = uriOrSecret
        var ziffern = 6
        var periode = 30
        var algorithmus = "SHA1"
        if uriOrSecret.lowercased().hasPrefix("otpauth://") {
            guard let teile = URLComponents(string: uriOrSecret), teile.host?.lowercased() == "totp" else { return nil }
            let werte = teile.queryItems ?? []
            guard let s = werte.first(where: { $0.name.lowercased() == "secret" })?.value else { return nil }
            geheimnis = s
            if let d = werte.first(where: { $0.name.lowercased() == "digits" })?.value { ziffern = Int(d) ?? 0 }
            if let p = werte.first(where: { $0.name.lowercased() == "period" })?.value { periode = Int(p) ?? 0 }
            if let a = werte.first(where: { $0.name.lowercased() == "algorithm" })?.value { algorithmus = a.uppercased() }
        }
        guard [6, 8].contains(ziffern), (15...120).contains(periode),
              let schluessel = Self.base32(geheimnis), !schluessel.isEmpty else { return nil }
        let t = Int(date.timeIntervalSince1970)
        var zaehler = UInt64(t / periode).bigEndian
        let nachricht = withUnsafeBytes(of: &zaehler) { Data($0) }
        let key = SymmetricKey(data: schluessel)
        let mac: [UInt8]
        switch algorithmus {
        case "SHA1": mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: nachricht, using: key))
        case "SHA256": mac = Array(HMAC<SHA256>.authenticationCode(for: nachricht, using: key))
        case "SHA512": mac = Array(HMAC<SHA512>.authenticationCode(for: nachricht, using: key))
        default: return nil
        }
        let o = Int(mac[mac.count - 1] & 0x0F)
        let bin = (UInt32(mac[o] & 0x7F) << 24) | (UInt32(mac[o + 1]) << 16) | (UInt32(mac[o + 2]) << 8) | UInt32(mac[o + 3])
        var modulo: UInt32 = 1
        for _ in 0..<ziffern { modulo *= 10 }
        var code = String(bin % modulo)
        while code.count < ziffern { code = "0" + code }
        return TOTPReading(code: code, remaining: periode - t % periode, period: periode)
    }

    /// RFC 4648 Base32, tolerant (Leerzeichen, Kleinbuchstaben, fehlendes Padding).
    static func base32(_ text: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0
        var puffer = 0
        var out = Data()
        for ch in text.uppercased() where ch != " " && ch != "=" && ch != "-" {
            guard let wert = alphabet.firstIndex(of: ch) else { return nil }
            puffer = (puffer << 5) | wert
            bits += 5
            if bits >= 8 {
                out.append(UInt8((puffer >> (bits - 8)) & 0xFF))
                bits -= 8
                puffer &= (1 << bits) - 1
            }
        }
        return out
    }
}

/// Einträge für Bericht und 2FA: alt, wiederverwendet, schwach, mit 2FA-Geheimnis.
enum DemodatenB {
    static let totpURI = "otpauth://totp/Wolkenspeicher:lena?secret=JBSWY3DPEHPK3PXP&issuer=Wolkenspeicher"

    static func entries() -> [VaultEntry] {
        let vorZweiJahren = Date().addingTimeInterval(-730 * 86_400)
        var verein = VaultEntry(title: "Turnverein Seeland", username: "lmuster", password: "Sommer2024",
                                url: "https://tv-seeland.example")
        verein.created = vorZweiJahren
        verein.modified = vorZweiJahren
        var forum = VaultEntry(title: "Kochforum", username: "lena.kocht", password: "Velo!Kette-2019",
                               url: "https://kochforum.example")
        forum.created = vorZweiJahren
        forum.modified = vorZweiJahren
        let shop = VaultEntry(title: "Fotobuch-Shop", username: "lena.muster@example.ch", password: "Velo!Kette-2019",
                              url: "https://fotobuch.example")
        let cloud = VaultEntry(title: "Notizen-Cloud", username: "lena", password: "Hq4$mW8zKp2nVb6x-n",
                               url: "https://notizen.example", totp: totpURI)
        return [verein, forum, shop, cloud]
    }
}

// MARK: - Prüfungen ohne Tresor

@MainActor
func stufeBTextPruefungen() {
    // 2FA (§18): RFC-6238-Testvektoren über die Anzeige (Kern bzw. Attrappe)
    let vektor = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1"
    let a = TOTPDisplay.reading(vektor, at: Date(timeIntervalSince1970: 59))
    check(a?.code == "94287082" && a?.remaining == 1 && a?.period == 30, "2FA: RFC 6238 bei 59 s")
    check(TOTPDisplay.reading(vektor, at: Date(timeIntervalSince1970: 1_111_111_109))?.code == "07081804",
          "2FA: RFC 6238 bei 1111111109 s")
    check(TOTPDisplay.reading("jbsw y3dp ehpk 3pxp", at: Date(timeIntervalSince1970: 0))?.period == 30,
          "2FA: Base32 tolerant, Periode aus dem Code zum Zeitpunkt 0")
    check(TOTPDisplay.check("") == .empty, "2FA: leer")
    check(TOTPDisplay.check("kein geheimnis!") == .invalid, "2FA: ungültig")
    check(TOTPDisplay.check(DemodatenB.totpURI) == .valid(digits: 6, period: 30), "2FA: gültig, 6 Ziffern, 30 s")
    check(TOTPReading(code: "123456", remaining: 3, period: 30).grouped == "123 456", "2FA: Gruppierung")

    // Befund #19: keine erfundene Kit-Kennung nennen
    let text = Fehlertexte.text(.wrongRecoveryCode(codeKit: "A92J-HCAA", vaultKit: "0AYR-98DB"))
    check(!text.contains("A92J-HCAA") && text.contains("0AYR-98DB") && text.contains("anderen Tresor"),
          "Befund #19: Meldung nennt nur die Kennung des Tresors")
    // Befund #38: „?“ bricht nicht um
    check(Fehlertexte.text(.invalidRecoveryCodeFormat).contains("\u{00A0}„\u{2060}?\u{2060}“\u{00A0}"), "Befund #38: Fragezeichen geschützt")
    check(RecoveryKitTexts.howTo.contains("ergänzt") && !RecoveryKitTexts.howTo.contains("korrigiert"),
          "Befund #38: Blatt und Bildschirm sagen dasselbe")
    // Befund #48: Wort und Bit aus einer Schätzung
    for probe in ["Sommer2026!!!", "kiesel-wolke-tanne-faden-lampe-ufer", "Passwort1234!", "aB3$"] {
        let bewertung = PasswordAssessment.of(probe)
        check(bewertung.level == PasswordAssessment.level(forBits: bewertung.bits), "Befund #48: Stufe passt zu den Bit")
    }
    // Befund #40: Ziele auf demselben Mac gelten nie als extern
    check(!StorageLocationProbe.outside(sameVolume: true, isInternal: false, isDiskImage: false, isEjectable: true,
                                        isRemovable: true, isLocal: true), "Befund #40: gleiches Volume")
    check(!StorageLocationProbe.outside(sameVolume: false, isInternal: true, isDiskImage: false, isEjectable: false,
                                        isRemovable: false, isLocal: true), "Befund #40: zweites internes Volume")
    // gemessen mit hdiutil: eingebundenes DMG meldet internal = nil, ejectable, removable, Modell „Disk Image“
    check(!StorageLocationProbe.outside(sameVolume: false, isInternal: nil, isDiskImage: true, isEjectable: true,
                                        isRemovable: true, isLocal: true), "Befund #40: Disk-Image")
    check(!StorageLocationProbe.outside(sameVolume: false, isInternal: false, isDiskImage: nil, isEjectable: true,
                                        isRemovable: true, isLocal: true), "Befund #40: nicht feststellbar → nicht extern")
    check(StorageLocationProbe.outside(sameVolume: false, isInternal: false, isDiskImage: false, isEjectable: true,
                                       isRemovable: true, isLocal: true), "Befund #40: USB-Stick extern")
    check(StorageLocationProbe.outside(sameVolume: false, isInternal: nil, isDiskImage: nil, isEjectable: false,
                                       isRemovable: false, isLocal: false), "Befund #40: Netzlaufwerk extern")
    // Befund #26: Frage beim Beenden nennt den Ordner
    check(ExportQuitQuestionProbe.text("Siegel-Export-2026-10-17.noindex").contains("Siegel-Export-2026-10-17.noindex"),
          "Befund #26: Frage beim Beenden")
}

// MARK: - Abläufe

@MainActor
func stufeBSnapshots() async {
    // 2FA-Quelle: der Kern, sobald er rechnet; sonst die Attrappe.
    if (try? TOTP.parse("JBSWY3DPEHPK3PXP")) == nil {
        TOTPDisplay.snapshotUse(DemoTOTP())
    }
    stufeBTextPruefungen()

    let (model, store) = makeModel("stufe-b")
    model.setup.passphrase = Demodaten.passphrase
    model.setup.passphraseRepeat = Demodaten.passphrase
    await model.createVault()
    if let kit = model.kit {
        let gruppen = kit.pending.code.groups
        kit.confirmation = kit.pending.confirmationGroups.map { gruppen[$0] }
    }
    await model.kitConfirm()
    let alle = Demodaten.entries() + DemodatenB.entries()
    _ = await model.performReturning { try $0.importEntries(alle) }
    model.settings.lastExternalBackupAt = Date()
    check(model.entries.count == alle.count, "B: Demo-Einträge")

    // MARK: Sicherheitsbericht (§17)
    await model.updateSecurityReport()
    guard let bericht = model.reportSummary else {
        check(false, "Bericht fehlt")
        return
    }
    let id = { (titel: String) in model.entries.first { $0.title == titel }?.id }
    check(bericht.sameAsMaster == [id("Velo-Forum")].compactMap { $0 }, "Bericht: gleich wie Master")
    check(bericht.reused.contains { Set($0) == Set([id("Kochforum"), id("Fotobuch-Shop")].compactMap { $0 }) },
          "Bericht: wiederverwendet")
    check(id("Turnverein Seeland").map { bericht.weak.contains($0) && bericht.old.contains($0) } ?? false,
          "Bericht: schwach und alt")
    check(bericht.total == alle.count, "Bericht: Anzahl")

    guard let cloud = id("Notizen-Cloud") else {
        check(false, "Notizen-Cloud fehlt")
        return
    }
    model.select(cloud)
    shot("119-tresor-2fa-code", model)

    model.showSecurityReport()
    check(model.browser.mode == .report, "Seitenleiste → Bericht")
    shot("120-sicherheitsbericht", model, size: CGSize(width: 920, height: 1180))
    shot("120b-sicherheitsbericht-fenster", model)
    if let verein = id("Turnverein Seeland") {
        model.openReportEntry(verein)
        check(model.browser.mode == .browse && model.browser.selection == verein, "Bericht → Sprung zum Eintrag")
        shot("121-bericht-eintrag", model)
    }

    // MARK: Bearbeiten: verdeckt (Befund #43) und 2FA prüfen (§18)
    model.select(cloud)
    model.editSelected()
    check(model.browser.editor?.isNew == false, "Bearbeiten offen")
    shot("122-bearbeiten-verdeckt", model, size: CGSize(width: 920, height: 900))
    await model.cancelEdit()

    model.newEntry()
    model.browser.editor?.draft.title = "Mitgliederportal"
    model.browser.editor?.draft.username = "lena.muster"
    model.browser.editor?.draft.password = "Mq7!vR2#xLp9"
    model.browser.editor?.draft.totp = "kein geheimnis!"
    shot("123-2fa-ungueltig", model, size: CGSize(width: 920, height: 900))
    await model.saveEdit()
    // Meldung mit dem Grund aus TOTP.parse (fester Code, z. B. totp.base32), nie der Code selbst.
    let totpFehler = Fehlertexte.text(TOTPDisplay.problem("kein geheimnis!"))
    check(model.browser.editor?.error == totpFehler && model.browser.mode == .edit && !totpFehler.contains("totp."),
          "Ungültiges 2FA-Geheimnis → nicht gespeichert")
    model.browser.editor?.error = nil
    model.browser.editor?.draft.totp = "  JBSW Y3DP EHPK 3PXP  "
    shot("124-2fa-gueltig", model, size: CGSize(width: 920, height: 900))
    await model.saveEdit()
    check(model.selectedEntry?.totp == "JBSW Y3DP EHPK 3PXP", "2FA gespeichert (ohne Rand-Leerzeichen)")

    // Befund #36: Einstellungen nicht während einer Bearbeitung
    model.editSelected()
    model.openSettings()
    check(!model.showsSettings, "Befund #36: ⌘, beim Bearbeiten gesperrt")
    model.request(.backupExport)
    check(model.pendingFlow == nil, "Befund #36: Abläufe beim Bearbeiten gesperrt")
    await model.cancelEdit()

    // MARK: Einstellungen (KeePass, Autofill, Info)
    model.openSettings()
    model.settingsState.fileVaultEncrypted = true
    shot("125-einstellungen-ganz", model, size: CGSize(width: 920, height: 2080))

    // KeePass-Export (§19)
    model.request(.keepassExport)
    check(model.flowState?.step == .keepassIntro, "KeePass: Start")
    shot("126-keepass", model)
    let ordner = tempRoot.appendingPathComponent("keepass", isDirectory: true)
    try? FileManager.default.createDirectory(at: ordner, withIntermediateDirectories: true)
    model.keepassSetFolder(ordner)
    model.flowState?.password = Demodaten.masterPassword
    model.flowState?.exportPassword = "kurz-2026"
    model.flowState?.exportPasswordRepeat = "kurz"
    check(!model.canRunKeePassExport, "KeePass: schwaches Export-Passwort gesperrt")
    shot("127-keepass-schwach", model)
    model.flowState?.exportPassword = Demodaten.masterPassword
    model.flowState?.exportPasswordRepeat = Demodaten.masterPassword
    await model.keepassExportRun()
    check(model.flowState?.error?.contains("anderes Passwort") == true, "KeePass: nicht das Master-Passwort")
    model.flowState?.error = nil
    model.flowState?.exportPassword = "Gletscher-Brise am Morgen 7"
    model.flowState?.exportPasswordRepeat = "Gletscher-Brise am Morgen 7"
    shot("128-keepass-passwoerter", model)
    await model.keepassExportRun()
    let kdbx = model.flowState?.exportedURL
    check(model.flowState?.step == .keepassDone && kdbx != nil, "KeePass: exportiert")
    if let kdbx {
        check(FileManager.default.fileExists(atPath: kdbx.path) && kdbx.deletingLastPathComponent().pathExtension == "noindex",
              "KeePass: Datei im .noindex-Ordner")
    }
    shot("129-keepass-fertig", model)
    model.deleteExportedKeePass()
    if let kdbx { check(!FileManager.default.fileExists(atPath: kdbx.path), "KeePass: Exportdatei gelöscht") }
    model.finishFlow()

    model.settingsShow(.autofill)
    shot("130-autofill", model, size: CGSize(width: 920, height: 860))
    model.settingsShow(.licenses)
    shot("131-lizenzen", model, size: CGSize(width: 920, height: 1360))

    // Befund #41: Ältere Sicherungen entfernen (Master-Passwort)
    model.settingsShow(.purgeOld)
    shot("132-aeltere-sicherungen", model)
    let vaultID = model.vault?.vaultID
    model.settingsState.currentPassword = "falsch-falsch"
    await model.purgeOldBackups()
    check(model.settingsState.error != nil && model.settingsState.page == .purgeOld, "Ältere Sicherungen: falsches Passwort")
    model.settingsState.currentPassword = Demodaten.masterPassword
    await model.purgeOldBackups()
    let rest = store.backups().filter { $0.vaultID == vaultID }
    check(model.settingsState.page == .overview && rest.count == 1, "Ältere Sicherungen entfernt, eine neue angelegt")

    // MARK: Befund #34/#25/#35: Frage nach den alten Sicherungen übersteht das Sperren
    model.settingsShow(.newKit)
    model.settingsState.currentPassword = Demodaten.masterPassword
    await model.prepareNewRecoveryKit()
    if let kit = model.kit {
        let gruppen = kit.pending.code.groups
        kit.confirmation = kit.pending.confirmationGroups.map { gruppen[$0] }
    }
    await model.kitConfirm()
    check(model.kit?.step == .purgeQuestion && model.pendingPurgeQuestion?.reason == .newKit, "Neues Kit → Frage gemerkt")
    let entfernen = Task { await model.kitFinish(removeOldBackups: true) }
    await Task.yield()
    model.lock()
    await entfernen.value
    check(model.screen == .locked && model.vault == nil, "Befund #25/#35: Sperren während des Entfernens bleibt gesperrt")
    check(model.pendingPurgeQuestion?.reason == .newKit, "Befund #34: Frage bleibt nach dem Sperren")
    model.unlock.password = Demodaten.masterPassword
    await model.submitUnlock()
    check(model.showsSettings && model.settingsState.page == .purgeBackups(.newKit), "Befund #34: Frage nach dem Entsperren")
    shot("133-frage-nach-dem-sperren", model)
    await model.finishPurgeQuestion(remove: false)
    check(model.pendingPurgeQuestion == nil && model.settingsState.page == .overview, "Frage beantwortet")
    model.closeSettings()

    // MARK: Befund #27/#31: Bearbeitung, die sich nicht speichern lässt
    // Ein zweiter Zugriff schreibt dazwischen → das Speichern dieses Fensters scheitert (vaultChangedOnDisk).
    if case let .unlocked(zweiter)? = try? await offMain({ try store.unlock(masterPassword: Demodaten.masterPassword) }) {
        try? zweiter.upsert(VaultEntry(title: "Von einem zweiten Zugriff"))
        zweiter.lock()
    }
    model.select(cloud)
    model.editSelected()
    model.browser.editor?.draft.username = "lena.neu"
    model.lock()
    check(model.screen == .unlocked && model.browser.editor?.error != nil, "Befund #31: ⌘L abgelehnt, Bearbeitung bleibt")
    shot("134-sperren-abgelehnt", model, keepNotice: true)
    model.lock()
    check(model.screen == .locked && model.lockNotice != nil, "Befund #27: zweites ⌘L sperrt, Hinweis bleibt")
    _ = await warteBis { model.unlock.header != nil }
    shot("135-gesperrt-bearbeitung-verloren", model)
    model.unlock.password = Demodaten.masterPassword
    await model.submitUnlock()
    check(model.screen == .unlocked && model.lockNotice == nil && model.notice != nil, "Befund #27: Hinweis nach dem Entsperren")

    // Befund #24: Nach dem Sperren kopiert nichts mehr
    model.lock()
    model.copySecret("nie")
    check(model.notice == nil, "Befund #24: Kopieren nach dem Sperren wirkungslos")

    await rollbackAnnahme()
    await beschaedigtDatei()
    await profilStark()
    await fremderCode()
}

// MARK: - Befund #19: Code eines anderen Tresors

@MainActor
func fremderCode() async {
    do {
        let (_, storeA) = makeModel("fremd-a")
        let (_, storeB) = makeModel("fremd-b")
        let (a, _) = try await offMain { try storeA.create(masterPassword: Demodaten.masterPassword) }
        let (b, codeB) = try await offMain { try storeB.create(masterPassword: Demodaten.masterPassword) }
        let kitA = a.kitID
        let kitB = b.kitID
        a.lock()
        b.lock()
        let model = AppModel(store: storeA, rollbackGuard: InMemoryRollbackGuard(),
                             settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
        model.startRecovery()
        model.recovery.code = codeB.code.formatted
        await model.checkRecoveryCodeForRecovery()
        let text = model.recovery.error ?? ""
        check(text.contains(kitA) && !text.contains(kitB) && text.contains("anderen Tresor"),
              "Befund #19: fremder Code → nur die Kit-Kennung dieses Tresors")
        model.cancelRecovery()
    } catch {
        fehler.append("Fremder Code: \(error)")
    }
}

// MARK: - Befund #28/#33: „Trotzdem öffnen“ wirkt

@MainActor
func rollbackAnnahme() async {
    do {
        let guardian = InMemoryRollbackGuard()
        let (_, store) = makeModel("rollback-b", guardian: guardian)
        let pw = Demodaten.masterPassword
        _ = try await offMain { try store.create(masterPassword: pw) }
        let alt = try Data(contentsOf: store.vaultURL)
        var mittel = Data()
        if case let .unlocked(vault) = try await offMain({ try store.unlock(masterPassword: pw) }) {
            try vault.upsert(VaultEntry(title: "Neu"))
            mittel = try Data(contentsOf: store.vaultURL)
            try vault.upsert(VaultEntry(title: "Noch neuer"))
            vault.lock()
        }
        try alt.write(to: store.vaultURL)
        let model = AppModel(store: store, rollbackGuard: guardian,
                             settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite + ".rollback") ?? .standard))
        model.unlock.password = pw
        await model.submitUnlock()
        check(model.screen == .rollback, "Rollback-Frage")
        await model.acceptRollback()
        check(model.screen == .unlocked, "Trotzdem öffnen → Tresor")
        model.lock()
        model.unlock.password = pw
        await model.submitUnlock()
        check(model.screen == .unlocked, "Befund #28/#33: dieselbe ältere Datei fragt nicht erneut")
        model.lock()
        try mittel.write(to: store.vaultURL)
        model.unlock.password = pw
        await model.submitUnlock()
        check(model.screen == .rollback, "Befund #28/#33: eine andere ältere Datei warnt weiter")
        model.rejectRollback()
    } catch {
        fehler.append("Rollback B: \(error)")
    }
}

// MARK: - Befund #29: beschädigt, keine lokale Sicherung, exportierte Datei

@MainActor
func beschaedigtDatei() async {
    do {
        let (_, store) = makeModel("beschaedigt-b")
        let pw = Demodaten.masterPassword
        let (vault, _) = try await offMain { try store.create(masterPassword: pw) }
        for entry in Demodaten.entries().prefix(5) { try vault.upsert(entry) }
        let export = tempRoot.appendingPathComponent("usb-stick-Siegel-Sicherung.siegel")
        try await offMain { try store.exportBackup(to: export) }
        vault.lock()
        try? FileManager.default.removeItem(at: store.vaultURL.deletingLastPathComponent().appendingPathComponent("Sicherungen"))
        var daten = try Data(contentsOf: store.vaultURL)
        daten[daten.count / 2] ^= 0x5A
        try daten.write(to: store.vaultURL)
        let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                             settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
        model.unlock.password = pw
        await model.submitUnlock()
        check(model.screen == .corrupt, "B: beschädigt")
        await model.openNewestReadableBackup()
        check(model.corrupt.error?.contains("aus Datei") == true, "Befund #29: Hinweis auf den Datei-Weg")
        shot("136-beschaedigt-datei-einspielen", model, size: CGSize(width: 920, height: 680))
        await model.corruptImportBackup(export)
        check(model.corrupt.restoredBackup != nil && model.corrupt.entryCount == 5, "Befund #29: exportierte Sicherung eingespielt")
        model.finishCorruptRestore()
        check(model.screen == .unlocked && model.entries.count == 5, "Befund #29: danach Tresor")
        model.lock()
    } catch {
        fehler.append("Beschädigt B: \(error)")
    }
}

// MARK: - Befund #21: Profil Stark bleibt bei der Wiederherstellung

@MainActor
func profilStark() async {
    do {
        let (_, store) = makeModel("stark-b")
        let (vault, pending) = try await offMain { try store.create(masterPassword: Demodaten.masterPassword, kdf: .strong) }
        vault.lock()
        let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                             settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
        _ = await warteBis { model.unlock.header != nil }
        model.startRecovery()
        _ = await warteBis { model.recovery.header != nil }
        check(model.recovery.kdfToKeep == .strong, "Befund #21: Profil Stark erkannt")
        model.recovery.code = pending.code.formatted
        await model.checkRecoveryCodeForRecovery()
        model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
        model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
        shot("137-notfall-profil-stark", model)
        model.recovery.offerStandardProfile = true
        model.recovery.error = "Für das Profil Stark fehlt Arbeitsspeicher (2 GiB). Schliesse andere Programme und versuche es erneut – oder stelle mit dem Profil Standard (1 GiB) wieder her."
        shot("138-notfall-zu-wenig-speicher", model, size: CGSize(width: 920, height: 700))
        model.recovery.offerStandardProfile = false
        model.recovery.error = nil
        await model.submitRecovery()
        model.finishRecovery()
        check(model.screen == .unlocked && model.kdf == .strong, "Befund #21: nach der Wiederherstellung weiter Stark")
        let kopf = try? await offMain { try store.inspect() }
        check(kopf?.kdf == .strong, "Befund #21: Datei mit Profil Stark")
        model.lock()
    } catch {
        fehler.append("Profil Stark: \(error)")
    }
}
