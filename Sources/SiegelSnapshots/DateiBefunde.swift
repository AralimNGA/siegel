import AppKit
import SiegelCore
@_spi(Snapshots) import SiegelUI
import SwiftUI

// Datei-Befunde der zweiten Prüfung (SPEC v4.4): Notfallweg ohne Tresordatei (datei-2), für eine gewählte Sicherung
// auf einem neuen Mac (datei-3), Code oder Teile bei beschädigtem Inhalt in Stufe 4 (datei-4), Zähler-Warnung auf
// „Tresor fehlt“ (datei-5). Bilder ab 170. Hardware: `DemoHardware` (Touch ID „nicht nutzbar“ wie auf einem neuen Mac).

/// Testtresor der Stufe 4 (Touch ID + Karte, Kit in drei Teilen) direkt über den Kern; optional mit Zähler.
struct DateiStufe4 {
    let store: VaultStore
    let demo: DemoHardware
    let karte: String
    let teile: [String]
    let vaultID: UUID
}

@MainActor
func dateiStufe4(_ name: String, zaehler: Int? = nil) async throws -> DateiStufe4 {
    let demo = DemoHardware()
    let (_, store) = makeModel(name)
    let pw = Demodaten.masterPassword
    let (vault, _) = try await offMain { try store.create(masterPassword: pw) }
    let se = try demo.enrollSecureEnclave(directory: store.hardwareDirectory)
    let eintragsSchluessel = try demo.enrollEntryKey(directory: store.hardwareDirectory)
    let q = CardCode.generate()
    let kit = try await offMain {
        try vault.prepareRecovery(masterPassword: pw, factors: FactorSecrets(), scheme: .shamir2of3)
    }
    let bestaetigung = kit.shareConfirmationGroups.enumerated().map { k, g in kit.shares[k].groups[g] }
    let material = NewFactorMaterial(secureEnclave: se, entryKey: eintragsSchluessel, card: CardEnrollment(q: q))
    try await offMain {
        try vault.changeSecurityLevel(to: .maximal, masterPassword: pw, currentFactors: FactorSecrets(),
                                      newFactors: material, recovery: kit, recoveryConfirmation: bestaetigung)
    }
    if let zaehler {
        let v = try demo.enrollEntryKey(directory: store.hardwareDirectory)
        let faktoren = FactorSecrets(secureEnclave: DemoHardware.secret([DemoHardware.data(se.keyID)]), card: q)
        _ = try await offMain {
            try vault.configureDestruction(DestructionSettings(maxFailedAttempts: zaehler), duressPassword: nil,
                                           destructible: [], masterPassword: pw, factors: faktoren, vKey: v)
        }
    }
    for entry in Demodaten.entries().prefix(4) { try vault.upsert(entry) }
    let id = vault.vaultID
    vault.lock()
    return DateiStufe4(store: store, demo: demo, karte: CardCode.payload(for: q), teile: kit.shares.map(\.formatted),
                       vaultID: id)
}

@MainActor
func dateiModel(_ store: VaultStore, _ demo: DemoHardware) -> AppModel {
    let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                         settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
    model.snapshotUseHardware(demo)
    return model
}

@MainActor
func dateiBefundeSnapshots() async {
    await dateiTresorFehltCode()
    await dateiTresorFehltStufe4()
    await dateiBeschaedigtStufe4()
    await dateiNeuerMac()
}

// MARK: - datei-2: Tresor fehlt, Notfallcode (Stufe 1)

@MainActor
func dateiTresorFehltCode() async {
    do {
        let (_, store) = makeModel("datei-fehlt-code")
        let pw = Demodaten.masterPassword
        let (vault, pending) = try await offMain { try store.create(masterPassword: pw) }
        for entry in Demodaten.entries().prefix(3) { try vault.upsert(entry) }
        vault.lock()
        try FileManager.default.removeItem(at: store.vaultURL)
        let model = AppModel(store: store, rollbackGuard: InMemoryRollbackGuard(),
                             settings: AppSettings(defaults: UserDefaults(suiteName: defaultsSuite) ?? .standard))
        check(model.screen == .missingVault, "datei-2: Datei weg → Tresor fehlt")
        await sicherungenGelesen(model)
        shot("170-tresor-fehlt-notfallcode", model, size: CGSize(width: 920, height: 700))

        model.missingUseRecovery()
        check(model.screen == .recovery && model.recovery.origin == .missingVault, "datei-2: Notfallweg ohne Datei")
        model.cancelRecovery()
        check(model.screen == .missingVault, "datei-2: Zurück führt zu „Tresor fehlt“, nicht zum Sperrbildschirm")
        await sicherungenGelesen(model)

        model.missingUseRecovery()
        _ = await warteBis(5) { model.recovery.header != nil }
        check(model.recovery.header != nil && !model.recovery.usesShares && !model.recovery.schemeCertain,
              "datei-2: Schema aus der neuesten Sicherung (unsicher → Umschalter)")
        model.recovery.code = pending.code.formatted
        shot("171-notfallcode-tresor-fehlt", model)
        await model.checkRecoveryCodeForRecovery()
        check(model.recovery.step == .newPassword && model.recovery.useBackup, "datei-2: Code passt zu den Sicherungen")
        model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
        model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
        await model.submitRecovery()
        check(model.recovery.step == .done && model.recovery.restoredBackup != nil, "datei-2: aus Sicherung hergestellt")
        check(model.recovery.entryCount == 2, "datei-2: Stand der neuesten Sicherung (2 Einträge)")
        shot("172-notfallcode-tresor-fehlt-fertig", model, size: CGSize(width: 920, height: 700))
        model.finishRecovery()
        check(model.screen == .unlocked && store.vaultExists, "datei-2: danach Tresor")
        model.lock()
    } catch {
        fehler.append("datei-2 Code: \(error)")
    }
}

// MARK: - datei-5 und datei-2: Tresor fehlt in Stufe 4 (Zähler, Touch ID fehlt, zwei Teile)

@MainActor
func dateiTresorFehltStufe4() async {
    do {
        let t = try await dateiStufe4("datei-fehlt-stufe4", zaehler: 10)
        try FileManager.default.removeItem(at: t.store.vaultURL)
        check(kernZustand(t.store, letztesEntsperren: Date(), fehlversuche: 5), "datei-5: Zustand gesetzt")
        let model = dateiModel(t.store, t.demo)
        check(model.screen == .missingVault, "datei-5: Tresor fehlt")
        await sicherungenGelesen(model)
        _ = await warteBis(5) { model.lockRemainingAttempts != nil }
        check(model.lockRemainingAttempts == 5, "datei-5: Warnung ab N/2 auch bei „Tresor fehlt“")
        shot("173-tresor-fehlt-zaehler", model, size: CGSize(width: 920, height: 760))

        // Ein falsches (z. B. älteres) Passwort mit den Faktoren: zählt, die Warnung folgt sofort.
        model.missing.password = "Falsches-Passwort-von-frueher-1"
        let falsch = Task { await model.restoreSelectedBackup() }
        await karteBisFertig(t.karte, model, falsch)
        check(model.missing.error == "Falsches Passwort für diese Sicherung. Auch hier zählt jeder Fehlversuch.",
              "datei-5/ablaeufe-6: falsches Passwort gemeldet, mit Hinweis auf den Zähler")
        check(model.lockRemainingAttempts == 4, "datei-5: Zähler sichtbar nachgeführt (noch 4)")
        shot("174-tresor-fehlt-falsch-zaehler", model, size: CGSize(width: 920, height: 760))

        // Touch ID hier nicht nutzbar (Fingerabdrücke geändert): Notfallweg statt Sackgasse (§14.1).
        t.demo.touchID = .unavailable
        model.missing.password = Demodaten.masterPassword
        await model.restoreSelectedBackup()
        check(model.missing.collection?.failure?.offerRecovery == true, "datei-2: Faktor fehlt → Notfallweg angeboten")
        shot("175-tresor-fehlt-touchid-fehlt", model, size: CGSize(width: 920, height: 760))
        model.missingUseRecovery()
        _ = await warteBis(5) { model.recovery.header != nil }
        check(model.recovery.usesShares && !model.recovery.schemeCertain, "datei-2: zwei Teile (Kopf der Sicherung)")
        model.recovery.shares = [t.teile[0], t.teile[2]]
        shot("176-notfall-teile-tresor-fehlt", model)
        await model.checkRecoverySharesForRecovery()
        check(model.recovery.step == .newPassword && model.recovery.useBackup, "datei-2: Teile passen zu den Sicherungen")
        model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
        model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
        await model.submitRecovery()
        check(model.recovery.step == .done && model.recovery.restoredBackup != nil, "datei-2: Teile stellen her")
        check(model.recovery.entryCount == 3, "datei-2: Stand der neuesten Sicherung (3 Einträge)")
        shot("177-notfall-teile-tresor-fehlt-fertig", model, size: CGSize(width: 920, height: 760))
        model.finishRecovery()
        check(model.screen == .unlocked && model.level == .standard, "datei-2: danach Stufe 1")
        model.lock()
    } catch {
        fehler.append("datei-2/5 Stufe 4: \(error)")
    }
}

// MARK: - datei-4: beschädigter Inhalt in Stufe 4

@MainActor
func dateiBeschaedigtStufe4() async {
    do {
        let t = try await dateiStufe4("datei-beschaedigt-stufe4")
        var daten = try Data(contentsOf: t.store.vaultURL)
        daten[daten.count - 200] ^= 0x5A
        try daten.write(to: t.store.vaultURL)
        let model = dateiModel(t.store, t.demo)
        check(model.screen == .locked, "datei-4: Datei da → Sperrbildschirm")
        model.startRecovery()
        _ = await warteBis(5) { model.recovery.header != nil }
        check(model.recovery.usesShares && !model.recovery.schemeCertain, "datei-4: Kopf ungeprüft → zwei Teile")
        shot("178-notfall-beschaedigt-teile", model)

        // Umschalter und ein Teil im Feld für den Code: zurück zu den Teilen, der Teil bleibt.
        model.recoveryChooseShares(false)
        check(!model.recovery.usesShares, "datei-4: Umschalter → einzelner Code")
        model.recoveryCodeOverflow(t.teile[1])
        check(model.recovery.usesShares && model.recovery.shares[0] == t.teile[1] && model.recovery.code.isEmpty,
              "datei-4: Teil im Code-Feld → Eingabe der Teile")

        model.recovery.shares = [t.teile[1], t.teile[2]]
        await model.checkRecoverySharesForRecovery()
        check(model.recovery.step == .newPassword, "datei-4: Teile passen")
        model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
        model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
        await model.submitRecovery()
        if !model.recovery.useBackup {
            check(model.recovery.offerBackup, "datei-4: beschädigt → Weg über die Sicherungen")
            await model.submitRecoveryFromBackup()
        }
        check(model.recovery.step == .done && model.recovery.restoredBackup != nil, "datei-4: Teile öffnen die Sicherung")
        model.finishRecovery()
        check(model.screen == .unlocked, "datei-4: danach Tresor")
        model.lock()
    } catch {
        fehler.append("datei-4: \(error)")
    }
}

// MARK: - datei-3: neuer Mac, Sicherung vom Stick, nur mit dem Notfallkit

@MainActor
func dateiNeuerMac() async {
    do {
        let alt = try await dateiStufe4("datei-alter-mac")
        let stick = tempRoot.appendingPathComponent("datei-stick", isDirectory: true)
        try FileManager.default.createDirectory(at: stick, withIntermediateDirectories: true)
        let kopie = stick.appendingPathComponent("Siegel-Sicherung-2026-10-17.siegel")
        try FileManager.default.copyItem(at: alt.store.vaultURL, to: kopie)

        // Neuer Mac: leerer Ordner, Touch-ID-Schlüssel des alten Macs gibt es hier nicht.
        let demo = DemoHardware()
        demo.touchID = .unavailable
        let (_, store) = makeModel("datei-neuer-mac")
        let model = dateiModel(store, demo)
        check(model.screen == .setup, "datei-3: neuer Mac → Einrichtung")
        shot("179-einrichtung-aus-sicherung", model, size: CGSize(width: 920, height: 760))
        await model.useBackupFileForRestore(kopie)
        check(model.screen == .missingVault && model.missing.fromSetup && model.missing.selection == kopie,
              "datei-3: Sicherung gewählt → „Sicherung wiederherstellen“")
        model.missing.password = Demodaten.masterPassword
        await model.restoreSelectedBackup()
        check(model.missing.collection?.failure?.offerRecovery == true, "datei-3: Touch ID fehlt → Notfallweg angeboten")
        shot("180-sicherung-touchid-fehlt", model, size: CGSize(width: 920, height: 700))
        model.missingUseRecovery()
        check(model.recovery.sourceFile == kopie, "datei-3: Notfallweg für genau diese Datei")
        _ = await warteBis(5) { model.recovery.header != nil }
        check(model.recovery.usesShares && model.recovery.schemeCertain, "datei-3: Kopf der Datei geprüft → zwei Teile")
        model.recovery.shares = [alt.teile[2], alt.teile[0]]
        shot("181-notfall-teile-sicherung", model)
        await model.checkRecoverySharesForRecovery()
        check(model.recovery.step == .newPassword && !model.recovery.useBackup, "datei-3: Teile passen zur Datei")
        model.recovery.newPassword = "Gletscher-Brise am Morgen 7"
        model.recovery.newPasswordRepeat = "Gletscher-Brise am Morgen 7"
        shot("181b-notfall-sicherung-neues-passwort", model, size: CGSize(width: 920, height: 700))
        await model.submitRecovery()
        check(model.recovery.step == .done && model.recovery.restoredBackup?.url == kopie,
              "datei-3: Sicherung eingespielt (\(model.recovery.error ?? "–"))")
        check(model.recovery.entryCount == 4, "datei-3: alle Einträge der Sicherung")
        shot("182-notfall-sicherung-fertig", model, size: CGSize(width: 920, height: 760))
        model.finishRecovery()
        check(model.screen == .unlocked && model.level == .standard && model.vaultHeader?.vaultID == alt.vaultID,
              "datei-3: Tresor des alten Macs, Stufe 1")
        check((try? Data(contentsOf: kopie)) == (try? Data(contentsOf: alt.store.vaultURL)), "datei-3: Stick unverändert")
        model.lock()

        // Zurück aus „Sicherung wiederherstellen“ führt zur Einrichtung (leerer Ordner).
        let (_, leer) = makeModel("datei-neuer-mac-zurueck")
        let zweites = dateiModel(leer, demo)
        await zweites.useBackupFileForRestore(kopie)
        zweites.leaveBackupFileRestore()
        check(zweites.screen == .setup, "datei-3: Zurück → Einrichtung")
        await zweites.useBackupFileForRestore(stick.appendingPathComponent("fehlt.siegel"))
        check(zweites.screen == .setup && zweites.setup.error != nil, "datei-3: fehlende Datei → Meldung")
    } catch {
        fehler.append("datei-3: \(error)")
    }
}
