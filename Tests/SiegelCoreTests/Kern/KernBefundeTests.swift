import Foundation
import Testing
@testable import SiegelCore

/// Regressionstests zu den Prüfbefunden vom 16.10.2026 (Nummern wie im Prüfbericht).
@Suite("Befunde 16.10.2026")
struct KernBefundeTests {
    // MARK: Hilfen

    /// Bestätigt das Kit aus `create` (zwei Gruppen).
    private func confirmSetupKit(_ f: KernVault) throws {
        let groups = f.pending.confirmationGroups.map { f.pending.code.groups[$0] }
        try f.vault.commitRecovery(f.pending, confirmation: groups)
    }

    /// Neues Kit vorbereiten und bestätigen; gibt den neuen Code zurück.
    private func newKit(_ vault: UnlockedVault, password: String = KT.pw1) throws -> PendingRecovery {
        let pending = try vault.prepareRecovery(masterPassword: password)
        try vault.commitRecovery(pending, confirmation: pending.confirmationGroups.map { pending.code.groups[$0] })
        return pending
    }

    private func flipPayloadByte(_ f: KernVault) throws {
        var b = try f.fileBytes()
        b[b.count - 100] ^= 0x01
        try f.writeFile(b)
    }

    private func quarantined(_ f: KernVault) -> [URL] {
        FileIO.listFiles(f.store.backupRoot).filter { $0.lastPathComponent.hasPrefix(BackupNaming.quarantinePrefix) }
    }

    // MARK: #2 Export ohne Nachbardatei

    @Test("#2 exportBackup legt keine Datei neben dem Ziel an (Sandbox gibt nur die gewählte Datei frei)")
    func exportOhneNachbardatei() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        let ziel = f.dir.sub("Ziel")
        let datei = ziel.appendingPathComponent("Siegel-Sicherung.siegel")
        // Wie die Powerbox-Freigabe: die gewählte Datei ist beschreibbar, der Ordner nicht.
        try FileIO.writeExclusive(datei, bytes: [1, 2, 3])
        #expect(chmod(ziel.path, 0o500) == 0)
        defer { _ = chmod(ziel.path, 0o700) }
        try f.store.exportBackup(to: datei)
        #expect(try FileIO.read(datei, maxSize: FileFormat.maxFileBytes) == f.fileBytes())
        #expect(FileIO.listFiles(ziel).map(\.lastPathComponent) == ["Siegel-Sicherung.siegel"])
        // Ohne Freigabe für die Datei selbst: klarer Fehler, nichts entsteht
        let fehlt = ziel.appendingPathComponent("neu.siegel")
        #expect(throws: SiegelError.io("export.write")) { try f.store.exportBackup(to: fehlt) }
        #expect(FileIO.listFiles(ziel).count == 1)
    }

    @Test("#2 exportBackup schreibt neu und prüft zurück (auch beim Ersetzen)")
    func exportErsetzt() throws {
        let f = try KernVault.make()
        let datei = f.dir.url.appendingPathComponent("Kopie.siegel")
        try f.store.exportBackup(to: datei)
        try f.vault.upsert(kernEntry("B"))
        try f.store.exportBackup(to: datei)
        #expect(try FileIO.read(datei, maxSize: FileFormat.maxFileBytes) == f.fileBytes())
        #expect(FileIO.listFiles(f.dir.url).filter { $0.lastPathComponent.hasSuffix(".tmp") }.isEmpty)
    }

    // MARK: #3 Wiederherstellen belebt kein ersetztes Kit still wieder

    @Test("#3 restoreBackup einer Sicherung von vor dem Kit-Wechsel → Kit gilt als unbestätigt")
    func restoreVorNeuemKit() throws {
        let f = try KernVault.make()
        try confirmSetupKit(f)
        try f.vault.upsert(kernEntry("A"))
        let kitA = f.vault.kitID
        let neu = try newKit(f.vault)
        #expect(f.vault.kitID == neu.code.kitID)
        #expect(f.vault.recoveryConfirmed)
        let vorKit = try #require(f.localBackups().first { $0.reason == BackupNaming.Reason.newKit.rawValue })
        f.vault.lock()
        let v = try f.store.restoreBackup(vorKit, masterPassword: KT.pw1)
        #expect(v.kitID == kitA)
        #expect(v.recoveryConfirmed == false)
        // Das alte Blatt öffnet den Tresor wieder, das neue nicht – darum zeigt die App „nicht bestätigt“.
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
    }

    @Test("#3 importBackup einer alten Kopie nach Kit-Wechsel → unbestätigt")
    func importVorNeuemKit() throws {
        let f = try KernVault.make()
        try confirmSetupKit(f)
        let kopie = f.dir.url.appendingPathComponent("alt.siegel")
        try f.store.exportBackup(to: kopie)
        _ = try newKit(f.vault)
        f.vault.lock()
        let v = try f.store.importBackup(from: kopie, masterPassword: KT.pw1)
        #expect(v.recoveryConfirmed == false)
    }

    @Test("#3 restoreNewestReadableBackup nach Kit-Wechsel und Beschädigung → unbestätigt")
    func neuesteLesbareNachKitWechsel() throws {
        let f = try KernVault.make()
        try confirmSetupKit(f)
        _ = try newKit(f.vault)
        f.vault.lock()
        try flipPayloadByte(f)
        let (v, info) = try f.store.restoreNewestReadableBackup(masterPassword: KT.pw1)
        #expect(info.reason == BackupNaming.Reason.newKit.rawValue)
        #expect(v.recoveryConfirmed == false)
    }

    @Test("#3 Wiederherstellung mit gleichem Kit lässt die Bestätigung stehen")
    func gleichesKitBleibtBestaetigt() throws {
        let f = try KernVault.make()
        try confirmSetupKit(f)
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        let alt = try #require(f.localBackups().first)
        f.vault.lock()
        let v = try f.store.restoreBackup(alt, masterPassword: KT.pw1)
        #expect(v.recoveryConfirmed)
        #expect(v.kitID == f.pending.code.kitID)
    }

    // MARK: #4 Notfallcode bei beschädigter Tresordatei

    @Test("#4 Inhalt gekippt: recover wirft corruptFile, der Sicherungsweg öffnet die neueste Sicherung")
    func notfallMitBeschaedigterDatei() throws {
        let f = try KernVault.make()
        try confirmSetupKit(f)
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        f.vault.lock()
        try flipPayloadByte(f)
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
        #expect(throws: SiegelError.corruptFile("file.checksum")) {
            try f.store.recover(code: f.code, newMasterPassword: KT.pw3, kdf: KT.kdf)
        }
        let (v, info) = try f.store.recoverFromNewestReadableBackup(code: f.code, newMasterPassword: KT.pw3, kdf: KT.kdf)
        #expect(info.generation == 3)
        #expect(v.entries.map(\.title) == ["A"])
        #expect(v.recoveryConfirmed)
        #expect(quarantined(f).count == 1)
        v.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw3)) != nil)
    }

    @Test("#4 Kopf gekippt (pkM): Code passt zu den Sicherungen, Wiederherstellung gelingt")
    func notfallMitBeschaedigtemKopf() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        f.vault.lock()
        var b = try f.fileBytes()
        b[200] ^= 0x01      // in recoveryPKM
        try f.writeFile(b)
        #expect(throws: (any Error).self) { _ = try f.store.checkRecoveryCode(f.code) }
        #expect(try f.store.checkRecoveryCodeAgainstBackups(f.code) == .exact)
        let (v, _) = try f.store.recoverFromNewestReadableBackup(code: f.code, newMasterPassword: KT.pw3, kdf: KT.kdf)
        #expect(v.entries.map(\.title) == ["A"])
        #expect(quarantined(f).count == 1)
    }

    @Test("#4 Gegenprobe: fremder Tresor und älteres Kit werden nie angenommen")
    func notfallGegenprobe() throws {
        let f = try KernVault.make()
        try confirmSetupKit(f)
        try f.vault.upsert(kernEntry("A"))
        let neu = try newKit(f.vault)
        try f.vault.upsert(kernEntry("B"))     // es gibt eine Sicherung mit dem neuen Kit
        f.vault.lock()
        try flipPayloadByte(f)
        // altes, bewusst ersetztes Kit
        #expect(throws: SiegelError.corruptFile("backup.noneReadable")) {
            _ = try f.store.recoverFromNewestReadableBackup(code: f.code, newMasterPassword: KT.pw3, kdf: KT.kdf)
        }
        #expect(throws: (any Error).self) { _ = try f.store.checkRecoveryCodeAgainstBackups(f.code) }
        // fremder Tresor
        let fremd = try KernVault.make()
        #expect(throws: SiegelError.corruptFile("backup.noneReadable")) {
            _ = try f.store.recoverFromNewestReadableBackup(code: fremd.code, newMasterPassword: KT.pw3, kdf: KT.kdf)
        }
        #expect(f.store.vaultExists)
        #expect(quarantined(f).isEmpty)
        // das aktuelle Kit öffnet die neueste Sicherung mit diesem Kit
        let (v, _) = try f.store.recoverFromNewestReadableBackup(code: neu.code.formatted, newMasterPassword: KT.pw3,
                                                                 kdf: KT.kdf)
        #expect(v.kitID == neu.code.kitID)
        #expect(v.entries.map(\.title) == ["A"])
    }

    @Test("#4 Regel und KDF-Grenzen gelten auch auf dem Sicherungsweg")
    func notfallSicherungswegRegeln() throws {
        let f = try KernVault.make()
        f.vault.lock()
        try flipPayloadByte(f)
        #expect(throws: SiegelError.passwordTooWeak(bits: MasterPasswordPolicy.check(KT.weak).bits)) {
            _ = try f.store.recoverFromNewestReadableBackup(code: f.code, newMasterPassword: KT.weak, kdf: KT.kdf)
        }
        #expect(throws: SiegelError.kdfParametersOutOfRange) {
            _ = try f.store.recoverFromNewestReadableBackup(code: f.code, newMasterPassword: KT.pw3, kdf: .standard)
        }
    }

    // MARK: #9 purgeBackups meldet, was übrig blieb; Temp-Reste

    @Test("#9 purgeBackups: zweiter Ort nicht lesbar → Bericht unvollständig, Kopie bleibt")
    func purgeZweiterOrtNichtErreichbar() throws {
        let f = try KernVault.make()
        let ext = f.dir.sub("USB")
        f.store.secondaryBackupDirectory = ext
        try f.vault.upsert(kernEntry("A"))
        #expect(FileIO.listFiles(ext).count == 1)
        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2)
        // Stick ausgesteckt: Ordner nicht mehr lesbar
        #expect(chmod(ext.path, 0o000) == 0)
        defer { _ = chmod(ext.path, 0o700) }
        let report = try f.vault.purgeBackups()
        #expect(report.secondaryUnreachable)
        #expect(report.isComplete == false)
        _ = chmod(ext.path, 0o700)
        #expect(FileIO.listFiles(ext).count == 1)
        // Nachholen, sobald der Ort wieder da ist: alte Kopie weg, frische Kopie mit dem neuen Passwort
        let nachher = f.store.purgeSecondaryBackups(vaultID: f.vault.vaultID, before: Clock.now().addingTimeInterval(1))
        #expect(nachher.isComplete)
        #expect(nachher.removed == 1)
        let externe = f.store.backups().filter(\.isExternal)
        #expect(externe.count == 1)
        f.vault.lock()
        #expect(throws: SiegelError.wrongPassword) {
            _ = try f.store.restoreBackup(try #require(externe.first), masterPassword: KT.pw1)
        }
    }

    @Test("#9 purgeBackups vollständig → isComplete; Ergebnis des zweiten Orts abrufbar")
    func purgeVollstaendig() throws {
        let f = try KernVault.make()
        let ext = f.dir.sub("USB")
        f.store.secondaryBackupDirectory = ext
        try f.vault.upsert(kernEntry("A"))
        guard case .written = f.store.lastSecondaryBackupResult else {
            Issue.record("erwartet .written")
            return
        }
        try f.vault.upsert(kernEntry("B"))
        #expect(f.store.lastSecondaryBackupResult == .notDue)
        let report = try f.vault.purgeBackups()
        #expect(report.isComplete)
        #expect(report.removed >= 3)
        f.store.secondaryBackupDirectory = f.dir.url.appendingPathComponent("fehlt")
        try f.vault.upsert(kernEntry("C"))
        #expect(f.store.lastSecondaryBackupResult == .unreachable)
    }

    @Test("#9 Temp-Reste eines abgebrochenen Speicherns werden aufgeräumt (nur ältere als 1 Minute)")
    func tempResteAufgeraeumt() throws {
        let f = try KernVault.make()
        let alt = f.store.directory.appendingPathComponent(".Tresor.siegel.0badf00d.tmp")
        let frisch = f.store.directory.appendingPathComponent(".Tresor.siegel.0000beef.tmp")
        try FileIO.writeExclusive(alt, bytes: try f.fileBytes())
        try FileIO.writeExclusive(frisch, bytes: [1])
        let vorZweiMinuten = Date().addingTimeInterval(-120)
        try FileManager.default.setAttributes([.modificationDate: vorZweiMinuten], ofItemAtPath: alt.path)
        let store = f.reopenStore()
        let v = try #require(KT.unlocked(try store.unlock(masterPassword: KT.pw1)))
        try v.upsert(kernEntry("A"))
        #expect(!FileIO.exists(alt))
        #expect(FileIO.exists(frisch))
    }

    // MARK: #16 bestehendes Kit später bestätigen

    @Test("#16 confirmExistingRecovery: ganzer Code bestätigt das Kit aus der Einrichtung")
    func bestehendesKitBestaetigen() throws {
        let f = try KernVault.make()
        #expect(f.vault.recoveryConfirmed == false)
        let fremd = try KernVault.make()
        #expect(throws: SiegelError.wrongRecoveryCode(codeKit: try codeKit(fremd.code, vault: f), vaultKit: f.vault.kitID)) {
            try f.vault.confirmExistingRecovery(code: fremd.code)
        }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try f.vault.confirmExistingRecovery(code: "ABC") }
        #expect(f.vault.recoveryConfirmed == false)
        let gen = f.vault.generation
        try f.vault.confirmExistingRecovery(code: f.code.lowercased())
        #expect(f.vault.recoveryConfirmed)
        #expect(f.vault.generation == gen + 1)
        #expect(f.vault.kitID == f.pending.code.kitID)
        // nochmals: nichts zu schreiben
        try f.vault.confirmExistingRecovery(code: f.code)
        #expect(f.vault.generation == gen + 1)
        f.vault.lock()
        let v = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)))
        #expect(v.recoveryConfirmed)
    }

    private func codeKit(_ code: String, vault f: KernVault) throws -> String {
        let r = try RecoveryCodeCodec.decode(code)
        return try RecoveryKEM.derivePublicKeys(r: r, vaultID: try f.parsedFile().header.vaultID).kitID
    }
}
