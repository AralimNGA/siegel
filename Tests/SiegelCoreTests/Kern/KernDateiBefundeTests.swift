import Foundation
import Testing
@testable import SiegelCore

// Befunde der Dimension „Datei“ (zweite Prüfung, SPEC v4.4): Schreiben nach dem Sperren, Notfallweg ohne Tresordatei,
// gezielt für eine gewählte Sicherung, Kopf bei beschädigtem Inhalt, Fehlversuche auf den Sicherungswegen.

/// Fehler eines synchronen Aufrufs (nil = kein Fehler).
private func dFehler(_ body: () throws -> Void) -> SiegelError? {
    do {
        try body()
        return nil
    } catch let e as SiegelError {
        return e
    } catch {
        return .io("test.fremd")
    }
}

@Suite("Datei-Befunde: Selbstvernichtung einrichten und Sperren (datei-1)")
struct KernDateiSperreTests {
    @Test("Sperre während des Argon2 fürs Vernichtungs-Passwort: Datei unverändert, V unbenutzt")
    func sperreWaehrendEinrichten() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let vault = v.vault
        let vaultID = vault.vaultID
        let generation = vault.generation
        let vorher = try FileIO.read(v.store.vaultURL, maxSize: FileFormat.maxFileBytes)
        let sicherungen = Set(v.store.backups().map(\.url))
        // Lauf 1: Passwortprüfung der async-Variante, Lauf 2: Argon2 des neuen Vernichtungs-Passworts (im Kern).
        let observer = TestHooks.KDFObserver { n in if n == 2 { vault.lock() } }
        let fehler = await TestHooks.$kdfObserver.withValue(observer) {
            await vFehler {
                try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW,
                                       markieren: [a.id])
            }
        }
        #expect(observer.runs == 2)
        #expect(fehler == .io("vault.locked"))
        // Entweder Erfolg mit Bericht oder: Datei unverändert und V unbenutzt (hier: gesperrt vor dem Schreiben).
        #expect(try FileIO.read(v.store.vaultURL, maxSize: FileFormat.maxFileBytes) == vorher)
        #expect(Set(v.store.backups().map(\.url)) == sicherungen)
        #expect(v.state() == nil)
        #expect(v.store.destructionKeyIsUnused(v.vKeyID, vaultID: vaultID, generation: generation))

        // Die Oberfläche darf V jetzt vernichten; der Eintrag hängt nicht daran.
        try FileDestructionKeyEraser().destroy(keyID: v.vKeyID, directory: v.hardware)
        try v.reopen()
        #expect(v.vault.destructibleEntries.isEmpty)
        #expect(v.vault.destructionKeyID == nil)
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
    }

    @Test("Nach erfolgreichem Einrichten nennt der Zustand V: nie als unbenutzt melden")
    func erfolgNenntV() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let vaultID = v.vault.vaultID
        let generation = v.vault.generation
        let report = try await v.einrichten(DestructionSettings(duressEnabled: true), duress: VTresor.duressPW,
                                            markieren: [a.id])
        #expect(report?.isComplete == true)
        #expect(!v.store.destructionKeyIsUnused(v.vKeyID, vaultID: vaultID, generation: generation))
        #expect(!v.store.destructionKeyIsUnused(v.vKeyID, vaultID: vaultID, generation: v.vault.generation))
        // Fehlt zustand.json (Schreiben gescheitert), schützt die neuere Generation auf der Platte.
        DestructionState.remove(in: v.hardware)
        #expect(!v.store.destructionKeyIsUnused(v.vKeyID, vaultID: vaultID, generation: generation))
        // Unbekannte Kennung, gleicher Stand: unbenutzt.
        #expect(v.store.destructionKeyIsUnused(UUID(), vaultID: vaultID, generation: v.vault.generation))
    }

    @Test("purgeBackups scheitert nach dem Schreiben: kein Fehler, Bericht unvollständig, Einträge an V")
    func entfernenScheitert() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        let vaultID = v.vault.vaultID
        let generation = v.vault.generation
        let report = try await TestHooks.$failPurgeBackups.withValue(true) {
            try await v.einrichten(DestructionSettings(deadmanDays: 30), markieren: [a.id])
        }
        #expect(report?.interrupted == true)
        #expect(report?.isComplete == false)
        #expect(v.vault.generation > generation)
        #expect(v.vault.destructibleEntries == [a.id])
        #expect(v.vault.destructionKeyID == v.vKeyID)
        #expect(v.state()?.vKeyID == v.vKeyID)
        #expect(!v.store.destructionKeyIsUnused(v.vKeyID, vaultID: vaultID, generation: generation))
        #expect(try await v.reveal(a.id) == EntrySecrets(a))
        try v.reopen()
        #expect(v.vault.destructibleEntries == [a.id])
    }

    @Test("Allgemein: nach dem Sperren schreibt kein laufender Vorgang mehr (Passwortwechsel)")
    func keinSchreibenNachSperre() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        let vorher = try f.fileBytes()
        let vault = f.vault
        // Lauf 1: altes Passwort prüfen, Lauf 2: neuer Schlüssel – währenddessen sperren.
        let observer = TestHooks.KDFObserver { n in if n == 2 { vault.lock() } }
        let fehler = TestHooks.$kdfObserver.withValue(observer) {
            dFehler { try vault.changeMasterPassword(current: KT.pw1, new: KT.pw2) }
        }
        #expect(observer.runs == 2)
        #expect(fehler == .io("vault.locked"))
        #expect(try f.fileBytes() == vorher)
        // Das alte Passwort öffnet weiter.
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)) != nil)
    }
}

@Suite("Datei-Befunde: Notfallweg ohne Tresordatei und für eine gewählte Sicherung (datei-2, datei-3)")
struct KernDateiNotfallTests {
    @Test("Tresordatei fehlt: Code passt zu den Sicherungen und stellt die neueste her")
    func tresorFehlt() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        f.vault.lock()
        FileIO.remove(f.store.vaultURL)
        #expect(!f.store.vaultExists)
        #expect(dFehler { _ = try f.store.checkRecoveryCode(f.code) } == .vaultMissing)
        #expect(try f.store.checkRecoveryCodeAgainstBackups(f.code) == .exact)
        let (wieder, info) = try f.store.recoverFromNewestReadableBackup(code: f.code, newMasterPassword: KT.pw2,
                                                                         kdf: KT.kdf)
        #expect(f.store.vaultExists)
        #expect(info.vaultID == f.vault.vaultID)
        #expect(wieder.entries.map(\.title) == ["A"])
        // Kopf ohne Datei: aus der neuesten lesbaren Sicherung (für die Wahl Code/Teile).
        #expect(try VaultStore.inspect(fileAt: info.url).recoveryScheme == .single)
    }

    @Test("Neuer Mac, Stufe 2: Sicherung vom Stick mit dem Notfallcode einspielen, neuer Tresor bleibt gesichert")
    func neuerMac() throws {
        let (a, _, _) = try KernStufen.make(.erhoeht)
        try a.vault.upsert(kernEntry("Alt"))
        let aID = a.vault.vaultID
        a.vault.lock()
        let stick = a.dir.sub("Stick")
        let kopie = stick.appendingPathComponent("Siegel-Sicherung-2026-10-17.siegel")
        try FileManager.default.copyItem(at: a.store.vaultURL, to: kopie)

        let neu = KernTempDir()
        let storeB = VaultStore(directory: neu.url.appendingPathComponent("Siegel", isDirectory: true),
                                rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        let (b, kitB) = try storeB.create(masterPassword: KT.pw3, kdf: KT.kdf)
        try b.upsert(kernEntry("Neu"))
        let bID = b.vaultID
        b.lock()

        // Bisher: Faktor fehlt, der automatische Weg kennt nur dasselbe Kit.
        #expect(dFehler { _ = try storeB.importBackup(from: kopie, masterPassword: KT.pw1) }
                == .factorMissing(.secureEnclave))
        let automatisch = dFehler { _ = try storeB.checkRecoveryCodeAgainstBackups(a.code) }
        if case .wrongRecoveryCode = automatisch {} else { Issue.record("Automatischer Weg kennt nur Kit B") }
        // Neu: gezielt für diese Datei.
        #expect(try storeB.checkRecoveryCode(a.code, againstFile: kopie) == .exact)
        let fremd = dFehler { _ = try storeB.checkRecoveryCode(kitB.code.formatted, againstFile: kopie) }
        if case .wrongRecoveryCode = fremd {} else { Issue.record("wrongRecoveryCode erwartet") }
        let fehlt = stick.appendingPathComponent("gibt-es-nicht.siegel")
        #expect(dFehler { _ = try storeB.checkRecoveryCode(a.code, againstFile: fehlt) } == .io("backup.missing"))
        #expect(dFehler {
            _ = try storeB.recoverBackup(from: fehlt, code: a.code, newMasterPassword: KT.pw4, kdf: KT.kdf)
        } == .io("backup.missing"))
        let falsch = dFehler {
            _ = try storeB.recoverBackup(from: kopie, code: kitB.code.formatted, newMasterPassword: KT.pw4, kdf: KT.kdf)
        }
        if case .wrongRecoveryCode = falsch {} else { Issue.record("wrongRecoveryCode erwartet") }

        let wieder = try storeB.recoverBackup(from: kopie, code: a.code, newMasterPassword: KT.pw4, kdf: KT.kdf)
        #expect(wieder.vaultID == aID)
        #expect(wieder.level == .standard)
        #expect(wieder.recoveryConfirmed)
        #expect(wieder.entries.map(\.title) == ["Alt"])
        // Der eben angelegte Tresor B bleibt als angeheftete Sicherung „vor-notfall“.
        #expect(storeB.backups().contains { $0.vaultID == bID && $0.reason == "notfall" })
        wieder.lock()
        #expect(KT.unlocked(try storeB.unlock(masterPassword: KT.pw4)) != nil)
        // Die Datei auf dem Stick bleibt unverändert.
        #expect(try Data(contentsOf: kopie) == Data(contentsOf: a.store.vaultURL))
    }

    @Test("Neuer Mac, Stufe 4: zwei Teile öffnen genau die gewählte Sicherung")
    func neuerMacTeile() throws {
        let (a, _, kit) = try KernStufen.make(.maximal)
        let teile = try #require(kit?.shares.map(\.formatted))
        try a.vault.upsert(kernEntry("Alt"))
        a.vault.lock()
        let kopie = a.dir.sub("Stick").appendingPathComponent("Siegel-Sicherung.siegel")
        try FileManager.default.copyItem(at: a.store.vaultURL, to: kopie)

        let neu = KernTempDir()
        let storeB = VaultStore(directory: neu.url.appendingPathComponent("Siegel", isDirectory: true),
                                rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        // Ohne Tresor (Einrichtung): direkt aus der Sicherung.
        #expect(try VaultStore.inspect(fileAt: kopie).recoveryScheme == .shamir2of3)
        #expect(try storeB.checkRecoveryShares([teile[2], teile[0]], againstFile: kopie) == [.exact, .exact])
        let wieder = try storeB.recoverBackup(from: kopie, shares: [teile[2], teile[0]], newMasterPassword: KT.pw4,
                                              kdf: KT.kdf)
        #expect(wieder.level == .standard)
        #expect(wieder.entries.map(\.title) == ["Alt"])
        #expect(storeB.vaultExists)
    }

    @Test("Abstufen 2 → 1: die angeheftete Stufe-2-Sicherung öffnet sich mit dem Notfallcode")
    func abgestufteSicherung() throws {
        let (a, faktoren, _) = try KernStufen.make(.erhoeht)
        try a.vault.upsert(kernEntry("Vorher"))
        try KernStufen.change(a.vault, to: .standard, faktoren: faktoren, current: [.secureEnclave])
        let alt = try #require(a.store.backups().filter { $0.reason == "stufenwechsel" }
            .max { $0.generation < $1.generation })
        #expect(dFehler { _ = try a.store.restoreBackup(alt, masterPassword: KT.pw1) } == .factorMissing(.secureEnclave))
        a.vault.lock()
        let wieder = try a.store.recoverBackup(from: alt.url, code: a.code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        #expect(wieder.entries.map(\.title) == ["Vorher"])
        #expect(wieder.level == .standard)
    }
}

@Suite("Datei-Befunde: Kopf bei beschädigtem Inhalt, Fehlversuche (datei-4, datei-5)")
struct KernDateiKopfTests {
    @Test("Gekipptes Byte im Inhalt (Stufe 4): ungeprüfter Kopf nennt die Teile, Teile stellen her")
    func kopfTrotzBeschaedigung() throws {
        let (f, _, kit) = try KernStufen.make(.maximal)
        let teile = try #require(kit?.shares.map(\.formatted))
        try f.vault.upsert(kernEntry("A"))
        f.vault.lock()
        var bytes = try f.fileBytes()
        bytes[bytes.count - 200] ^= 0x01
        try f.writeFile(bytes)
        #expect(KT.isCorrupt(dFehler { _ = try f.store.inspect() }))
        let kopf = try f.store.inspectHeaderUnverified()
        #expect(kopf.recoveryScheme == .shamir2of3)
        #expect(kopf.kitID == kit?.code.kitID)
        #expect(try f.store.checkRecoverySharesAgainstBackups([teile[0], teile[1]]) == [.exact, .exact])
        let (wieder, _) = try f.store.recoverFromNewestReadableBackup(shares: [teile[0], teile[1]],
                                                                      newMasterPassword: KT.pw2, kdf: KT.kdf)
        #expect(wieder.level == .standard)
        // Ohne Datei: vaultMissing, unlesbarer Kopf: corruptFile.
        FileIO.remove(f.store.vaultURL)
        #expect(dFehler { _ = try VaultStore.inspectHeaderUnverified(fileAt: f.store.vaultURL) } == .vaultMissing)
    }

    @Test("Tresor fehlt, Zähler an: Sicherungswege zählen, ab N/2 liefert der Kern die Warnung")
    func zaehlerOhneTresor() async throws {
        let v = try VTresor(.maximal)
        let a = try v.add("Bank", .maximal)
        try await v.einrichten(DestructionSettings(maxFailedAttempts: 10), markieren: [a.id])
        try v.vault.upsert(kernEntry("Später"))
        let factors = try v.factors()
        v.vault.lock()
        FileIO.remove(v.store.vaultURL)
        let sicherung = try #require(v.store.backups().first { $0.vaultID != nil })
        #expect(v.store.destructionStatus().shouldWarnAboutAttempts == false)
        for _ in 0..<5 {
            #expect(dFehler { _ = try v.store.restoreBackup(sicherung, masterPassword: KT.pw3, factors: factors) }
                    == .wrongPassword)
        }
        let status = v.store.destructionStatus()
        #expect(status.failedAttempts == 5)
        #expect(status.remainingAttempts == 5)
        #expect(status.shouldWarnAboutAttempts)
        #expect(v.eraser.destroyed.isEmpty)
    }
}
