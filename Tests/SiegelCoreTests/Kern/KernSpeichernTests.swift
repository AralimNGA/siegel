import Foundation
import Testing
@testable import SiegelCore

@Suite("Speichern, Generation, Rollback")
struct KernSpeichernTests {
    @Test("Generation steigt bei jedem Schreibweg um genau 1")
    func generationJederWeg() throws {
        let f = try KernVault.make()
        var expected: UInt64 = 1
        func step(_ what: String, _ vault: UnlockedVault? = nil) throws {
            expected += 1
            let v = vault ?? f.vault
            #expect(v.generation == expected, "\(what)")
            #expect(try f.parsedFile().generation == expected, "\(what)")
            #expect(f.guardian.lastSeenGeneration(vaultID: v.vaultID) == expected, "\(what)")
        }
        #expect(f.vault.generation == 1)
        var e = kernEntry("A")
        try f.vault.upsert(e); try step("upsert")
        e.password = "Neu-1"
        try f.vault.upsert(e); try step("upsert Passwort")
        try f.vault.clearHistory(id: e.id); try step("clearHistory")
        try f.vault.delete(id: e.id); try step("delete")
        try f.vault.restore(id: e.id); try step("restore")
        try f.vault.delete(id: e.id); try step("delete 2")
        try f.vault.purgeDeleted(id: e.id); try step("purgeDeleted")
        _ = try f.vault.importEntries([kernEntry("Import", url: "import.example")]); try step("importEntries")
        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2); try step("changeMasterPassword")
        let groups = f.pending.confirmationGroups.map { f.pending.code.groups[$0] }
        try f.vault.commitRecovery(f.pending, confirmation: groups); try step("commitRecovery bestätigen")
        let pending = try f.vault.prepareRecovery(masterPassword: KT.pw2)
        try f.vault.commitRecovery(pending, confirmation: pending.confirmationGroups.map { pending.code.groups[$0] })
        try step("commitRecovery neues Kit")
        f.vault.lock()
        let rec = try f.store.recover(code: pending.code.formatted, newMasterPassword: KT.pw3, kdf: KT.kdf)
        try step("recover", rec)
        let oldBackup = try #require(f.localBackups().last)
        rec.lock()
        let restored = try f.store.restoreBackup(oldBackup, masterPassword: KT.pw1)
        try step("restoreBackup", restored)
        // Befund #3: Die alte Sicherung bringt das alte Kit mit; es gilt nicht still als bestätigt.
        #expect(restored.kitID == f.pending.code.kitID)
        #expect(restored.kitID != pending.code.kitID)
        #expect(restored.recoveryConfirmed == false)
        let export = f.dir.url.appendingPathComponent("export.siegel")
        try f.store.exportBackup(to: export)
        restored.lock()
        let imported = try f.store.importBackup(from: export, masterPassword: KT.pw1)
        try step("importBackup", imported)
        imported.lock()
        var b = try f.fileBytes()
        b[b.count / 2] ^= 1
        try f.writeFile(b)
        let (newest, _) = try f.store.restoreNewestReadableBackup(masterPassword: KT.pw1)
        try step("restoreNewestReadableBackup", newest)
        try newest.upsert(kernEntry("Danach")); try step("upsert nach Wiederherstellung", newest)
    }

    @Test("Rollback-Erkennung: ältere Datei als zuletzt gesehen")
    func rollback() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        let gen2 = try f.fileBytes()
        try f.vault.upsert(kernEntry("B"))
        #expect(f.vault.generation == 3)
        f.vault.lock()
        try f.writeFile(gen2)
        let outcome = try f.store.unlock(masterPassword: KT.pw1)
        guard case let .rollbackSuspected(v, seen, file) = outcome else {
            Issue.record("erwartet rollbackSuspected")
            return
        }
        #expect(seen == 3)
        #expect(file == 2)
        #expect(v.entries.map(\.title) == ["A"])
        // „Trotzdem öffnen“: nächstes Speichern schreibt über die gesehene Generation hinaus
        try v.upsert(kernEntry("C"))
        #expect(v.generation == 4)
        v.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)) != nil)
        // Ohne Erinnerung (frischer Guard) keine Warnung
        let fresh = f.reopenStore(guardian: InMemoryRollbackGuard())
        #expect(KT.unlocked(try fresh.unlock(masterPassword: KT.pw1)) != nil)
    }

    @Test("UserDefaultsRollbackGuard merkt nur steigende Generationen")
    func userDefaultsGuard() throws {
        let suite = "siegel-test-" + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let g = UserDefaultsRollbackGuard(defaults: defaults)
        let id = UUID()
        #expect(g.lastSeenGeneration(vaultID: id) == nil)
        g.record(vaultID: id, generation: 5)
        #expect(g.lastSeenGeneration(vaultID: id) == 5)
        g.record(vaultID: id, generation: 3)
        #expect(g.lastSeenGeneration(vaultID: id) == 5)
        g.record(vaultID: id, generation: UInt64.max - 1)
        #expect(g.lastSeenGeneration(vaultID: id) == UInt64.max - 1)
        #expect(UserDefaultsRollbackGuard(defaults: defaults).lastSeenGeneration(vaultID: id) == UInt64.max - 1)
        #expect(g.lastSeenGeneration(vaultID: UUID()) == nil)
    }

    @Test("vaultChangedOnDisk: zweite Sitzung überschreibt nichts, Eingabe bleibt im Speicher")
    func geaendertAufPlatte() throws {
        let f = try KernVault.make()
        let second = try #require(KT.unlocked(try f.reopenStore().unlock(masterPassword: KT.pw1)))
        try f.vault.upsert(kernEntry("Von Sitzung 1"))
        let onDisk = try f.fileBytes()
        #expect(throws: SiegelError.vaultChangedOnDisk) { try second.upsert(kernEntry("Von Sitzung 2")) }
        #expect(try f.fileBytes() == onDisk)
        #expect(second.entries.isEmpty)
        #expect(second.generation == 1)
        #expect(f.tempFiles().isEmpty)
    }

    @Test("Rücklese-Prüfung scheitert → alte Datei unverändert, Temp entfernt, keine Sicherung")
    func rueckleseFehler() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        let before = try f.fileBytes()
        let backupsBefore = f.backupFileNames()
        TestHooks.$corruptTempBeforeVerify.withValue(true) {
            #expect(throws: SiegelError.io("save.verify")) { try f.vault.upsert(kernEntry("B")) }
        }
        #expect(try f.fileBytes() == before)
        #expect(f.tempFiles().isEmpty)
        #expect(f.backupFileNames() == backupsBefore)
        #expect(f.vault.entries.map(\.title) == ["A"])
        #expect(f.vault.generation == 2)
        try f.vault.upsert(kernEntry("B"))
        #expect(f.vault.generation == 3)
    }

    @Test("Unter 64 MiB frei → notEnoughDiskSpace, nichts geschrieben")
    func platz() throws {
        let f = try KernVault.make()
        let before = try f.fileBytes()
        TestHooks.$freeSpaceOverride.withValue((64 << 20) - 1) {
            #expect(throws: SiegelError.notEnoughDiskSpace) { try f.vault.upsert(kernEntry("A")) }
        }
        #expect(try f.fileBytes() == before)
        #expect(f.tempFiles().isEmpty)
        let dir = KernTempDir()
        let store = VaultStore(directory: dir.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        TestHooks.$freeSpaceOverride.withValue(1 << 20) {
            #expect(throws: SiegelError.notEnoughDiskSpace) { try store.create(masterPassword: KT.pw1, kdf: KT.kdf) }
        }
        #expect(store.vaultExists == false)
        try TestHooks.$freeSpaceOverride.withValue(64 << 20) { try f.vault.upsert(kernEntry("A")) }
    }

    @Test("Fehlende Datei während der Sitzung wird beim Speichern neu geschrieben")
    func fehlendeDatei() throws {
        let f = try KernVault.make()
        FileIO.remove(f.store.vaultURL)
        try f.vault.upsert(kernEntry("A"))
        #expect(f.store.vaultExists)
        f.vault.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1))?.entries.map(\.title) == ["A"])
    }

    @Test("Ordner 0700, Dateien 0600, keine Temp-Reste")
    func rechte() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        func mode(_ u: URL) -> Int {
            ((try? FileManager.default.attributesOfItem(atPath: u.path)[.posixPermissions]) as? Int) ?? -1
        }
        #expect(mode(f.store.directory) == 0o700)
        #expect(mode(f.store.vaultURL) == 0o600)
        #expect(mode(f.store.backupRoot) == 0o700)
        #expect(mode(f.store.backupDirectory(for: f.vault.vaultID)) == 0o700)
        for b in f.localBackups() { #expect(mode(b.url) == 0o600) }
        #expect(f.tempFiles().isEmpty)
    }
}

@Suite("Sicherungen")
struct KernSicherungenTests {
    @Test("Namensschema und Sicherung pro Speichern")
    func schema() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        let list = f.localBackups()
        #expect(list.map(\.generation) == [2, 1])
        for b in list {
            let name = b.url.lastPathComponent
            let parsed = try #require(BackupNaming.parseLocal(name))
            #expect(parsed.generation == b.generation)
            #expect(parsed.reason == nil)
            #expect(b.vaultID == f.vault.vaultID)
            #expect(b.url.deletingLastPathComponent().lastPathComponent == f.vault.vaultID.uuidString)
            #expect(name.count == "20261016-120000-g1-abcd.siegel".count + String(b.generation).count - 1)
        }
        let fixed = Date(timeIntervalSince1970: 1_792_000_000)
        let n = BackupNaming.localName(date: fixed, generation: 42, reason: "neues-kit")
        let p = try #require(BackupNaming.parseLocal(n))
        #expect(p.date == fixed)
        #expect(p.generation == 42)
        #expect(p.reason == "neues-kit")
        #expect(n.hasPrefix(BackupNaming.timestamp(fixed) + "-g42-"))
        #expect(n.hasSuffix("-vor-neues-kit.siegel"))
        #expect(BackupNaming.parseLocal("Notizen.txt") == nil)
        #expect(BackupNaming.parseLocal("20261016-120000-gX-abcd.siegel") == nil)
    }

    @Test("Sicherungsnamen kollidieren nie (gleiche Generation, gleiche Sekunde, 300×)")
    func keineKollision() throws {
        let f = try KernVault.make()
        let fixed = Date(timeIntervalSince1970: 1_792_000_000)
        try TestHooks.$now.withValue(fixed) {
            for _ in 0..<300 { try f.store.backupNowForTesting(reason: nil) }
        }
        let names = f.backupFileNames()
        #expect(names.count == 300)
        for n in names {
            let p = try #require(BackupNaming.parseLocal(n))
            #expect(p.generation == 1)
            #expect(p.date == fixed)
        }
    }

    @Test("Ausdünnung: 48 h (max. 50), Tage, Wochen, Monate; angeheftete und älteste bleiben")
    func ausduennenRein() throws {
        let now = Date(timeIntervalSince1970: 1_792_000_000)
        var items: [BackupThinning.Item] = []
        var n = 0
        func add(_ age: TimeInterval, pinned: Bool = false) -> URL {
            n += 1
            let u = URL(fileURLWithPath: "/tmp/b\(n).siegel")
            items.append(BackupThinning.Item(url: u, date: now.addingTimeInterval(-age), pinned: pinned))
            return u
        }
        let h = 3600.0
        let d = 86_400.0
        var recent: [URL] = []
        for i in 0..<60 { recent.append(add(Double(i) * 0.5 * h + 60)) }   // 60 Stück in 30 h
        var daily: [[URL]] = []
        for day in 3...40 { daily.append((0..<3).map { add(Double(day) * d + Double($0) * h) }) }
        let pinnedOld = add(1000 * d, pinned: true)
        let pinnedNew = add(5 * d + 30, pinned: true)
        let veryOld = add(800 * d)
        let oldest = add(2000 * d)
        let midA = add(100 * d)
        let midB = add(100 * d + 600)
        let year = add(400 * d)

        let delete = Set(BackupThinning.selectForDeletion(items, now: now))
        #expect(!delete.contains(pinnedOld))
        #expect(!delete.contains(pinnedNew))
        #expect(!delete.contains(oldest))
        #expect(delete.contains(veryOld))           // älter als 24 Monate
        #expect(!delete.contains(year))             // Monatsrepräsentant
        #expect(!delete.contains(midA))             // neueste der Woche
        #expect(delete.contains(midB))
        #expect(recent.prefix(50).allSatisfy { !delete.contains($0) })
        // Tage 3…29: genau die neueste pro Tag bleibt (älter als 48 h)
        for (k, group) in daily.enumerated() where k + 3 <= 29 {
            #expect(!delete.contains(group[0]), "Tag \(k + 3)")
            #expect(delete.contains(group[2]), "Tag \(k + 3)")
        }
        // Nichts Angeheftetes, nie mehr als nötig
        let kept = items.filter { !delete.contains($0.url) }
        #expect(kept.count < items.count)
    }

    @Test("Ausdünnung im Ordner nach dem Speichern")
    func ausduennenOrdner() throws {
        let f = try KernVault.make()
        let dir = f.store.backupDirectory(for: f.vault.vaultID)
        try FileIO.ensureDirectory(dir)
        let bytes = try f.fileBytes()
        let now = Date()
        var names: [String: TimeInterval] = [:]
        for days in [1000.0, 900, 800, 3, 3.1, 3.2] {
            let name = BackupNaming.localName(date: now.addingTimeInterval(-days * 86_400), generation: 1, reason: nil)
            try FileIO.writeExclusive(dir.appendingPathComponent(name), bytes: bytes)
            names[name] = days
        }
        let pinned = BackupNaming.localName(date: now.addingTimeInterval(-700 * 86_400), generation: 1, reason: "import")
        try FileIO.writeExclusive(dir.appendingPathComponent(pinned), bytes: bytes)
        try FileIO.writeExclusive(dir.appendingPathComponent("fremd.txt"), bytes: [1, 2, 3])
        try f.vault.upsert(kernEntry("A"))
        let after = f.backupFileNames()
        #expect(after.contains(pinned))
        #expect(after.contains("fremd.txt"))
        let byAge = Dictionary(grouping: names.keys, by: { names[$0] ?? 0 })
        #expect(after.contains(byAge[1000]?.first ?? ""))   // älteste
        #expect(!after.contains(byAge[900]?.first ?? "x"))
        #expect(!after.contains(byAge[800]?.first ?? "x"))
        #expect(after.contains(byAge[3]?.first ?? ""))       // neueste des Tages
    }

    @Test("Wiederherstellung einer alten Generation löscht keine neueren Sicherungen")
    func wiederherstellungBehaeltNeuere() throws {
        let f = try KernVault.make()
        for i in 0..<5 { try f.vault.upsert(kernEntry("E\(i)")) }
        let namesBefore = f.backupFileNames()
        let gen2 = try #require(f.localBackups().first { $0.generation == 2 })
        f.vault.lock()
        let restored = try f.store.restoreBackup(gen2, masterPassword: KT.pw1)
        #expect(restored.entries.map(\.title) == ["E0"])
        #expect(restored.generation == 7)
        let namesAfter = f.backupFileNames()
        #expect(namesBefore.isSubset(of: namesAfter))
        let pinned = f.localBackups().filter { $0.reason == "wiederherstellung" }
        #expect(pinned.count == 1)
        #expect(pinned.first?.generation == 6)
        // DEK wurde rotiert: alter Sicherungs-DEK passt nicht zur neuen Datei
        #expect(try f.parsedFile().header.salt != (try VaultFile.parse(try FileIO.read(gen2.url, maxSize: FileFormat.maxFileBytes))).header.salt)
    }

    @Test("Beschädigt: neueste lesbare Sicherung, kaputte werden übersprungen, Datei wird gesichert")
    func beschaedigt() throws {
        for corruptHeader in [false, true] {
            let f = try KernVault.make()
            for i in 0..<3 { try f.vault.upsert(kernEntry("E\(i)")) }   // Sicherungen g1…g3, Datei g4
            let backups = f.localBackups()
            let newest = try #require(backups.first)
            #expect(newest.generation == 3)
            // neueste Sicherung beschädigen
            var nb = try FileIO.read(newest.url, maxSize: FileFormat.maxFileBytes)
            nb[nb.count / 2] ^= 1
            FileIO.remove(newest.url)
            try FileIO.writeExclusive(newest.url, bytes: nb)
            // Tresordatei beschädigen (Inhalt oder Kopf)
            var vb = try f.fileBytes()
            vb[corruptHeader ? 10 : vb.count / 2] ^= 1   // Byte 10 liegt in der vaultID
            try f.writeFile(vb)
            f.vault.lock()
            #expect(throws: SiegelError.corruptFile("file.checksum")) { try f.store.unlock(masterPassword: KT.pw1) }
            #expect(throws: SiegelError.wrongPassword) { try f.store.restoreNewestReadableBackup(masterPassword: KT.pw2) }
            let (v, used) = try f.store.restoreNewestReadableBackup(masterPassword: KT.pw1)
            #expect(used.generation == 2)
            #expect(v.entries.map(\.title) == ["E0"])   // Sicherung g2 = Stand nach E0
            #expect(v.generation == 5)
            // beschädigte Datei liegt als „beschaedigt-…“ in Sicherungen, kaputte Sicherung bleibt liegen
            let quarantined = FileIO.listFiles(f.store.backupRoot).filter {
                $0.lastPathComponent.hasPrefix(BackupNaming.quarantinePrefix)
            }
            #expect(quarantined.count == 1)
            #expect(try FileIO.read(quarantined[0], maxSize: FileFormat.maxFileBytes) == vb)
            #expect(FileIO.exists(newest.url))
            v.lock()
            #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)) != nil)
        }
    }

    @Test("quarantineCorruptVault verschiebt, löscht nie")
    func quarantaene() throws {
        let f = try KernVault.make()
        let bytes = try f.fileBytes()
        let moved = try f.store.quarantineCorruptVault()
        #expect(f.store.vaultExists == false)
        #expect(moved.deletingLastPathComponent().standardizedFileURL == f.store.backupRoot.standardizedFileURL)
        #expect(moved.lastPathComponent.hasPrefix("beschaedigt-"))
        #expect(try FileIO.read(moved, maxSize: FileFormat.maxFileBytes) == bytes)
        #expect(throws: SiegelError.vaultMissing) { try f.store.quarantineCorruptVault() }
        // „Tresor fehlt“: Sicherungen auflisten und wiederherstellen
        try f.writeFile(bytes)
        let second = try f.store.quarantineCorruptVault()
        #expect(second != moved)
        #expect(f.store.backups().isEmpty)   // beschaedigt-… zählt nicht als Sicherung
    }

    @Test("Tresor fehlt: Wiederherstellen aus der Liste")
    func tresorFehlt() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        f.vault.lock()
        FileIO.remove(f.store.vaultURL)
        let list = f.store.backups()
        #expect(list.count == 2)
        #expect(list.allSatisfy { $0.vaultID == f.vault.vaultID })
        let v = try f.store.restoreBackup(try #require(list.first), masterPassword: KT.pw1)
        #expect(v.entries.map(\.title) == ["A"])
        #expect(f.store.vaultExists)
    }

    @Test("Zweiter Sicherungsort: höchstens 1× pro Stunde, atomar, in backups() sichtbar")
    func zweiterOrt() throws {
        let f = try KernVault.make()
        let ext = f.dir.sub("USB")
        f.store.secondaryBackupDirectory = ext
        let t0 = Date(timeIntervalSince1970: 1_792_000_000)
        try TestHooks.$now.withValue(t0) { try f.vault.upsert(kernEntry("A")) }
        try TestHooks.$now.withValue(t0.addingTimeInterval(600)) { try f.vault.upsert(kernEntry("B")) }
        var files = FileIO.listFiles(ext)
        #expect(files.count == 1)
        let prefix = "Siegel-" + String(KT.hex(f.vault.vaultID.kernBytes).prefix(8)) + "-"
        #expect(files.first?.lastPathComponent.hasPrefix(prefix) == true)
        try TestHooks.$now.withValue(t0.addingTimeInterval(2 * 3600)) { try f.vault.upsert(kernEntry("C")) }
        files = FileIO.listFiles(ext)
        #expect(files.count == 2)
        #expect(files.allSatisfy { !$0.lastPathComponent.hasSuffix(".tmp") })
        let external = f.store.backups().filter(\.isExternal)
        #expect(external.count == 2)
        #expect(external.allSatisfy { $0.vaultID == f.vault.vaultID })
        #expect(external.map(\.generation) == [4, 2])
        // aus dem zweiten Ort wiederherstellen
        f.vault.lock()
        let v = try f.store.restoreBackup(try #require(external.last), masterPassword: KT.pw1)
        #expect(v.entries.map(\.title) == ["A"])
        // ohne zweiten Ort keine externen Einträge
        f.store.secondaryBackupDirectory = nil
        #expect(f.store.backups().allSatisfy { !$0.isExternal })
    }

    @Test("purgeBackups entfernt alle Sicherungen dieser vaultID und legt sofort eine neue an")
    func purge() throws {
        let f = try KernVault.make()
        let other = try KernVault.make()
        try other.vault.upsert(kernEntry("Fremd"))
        let ext = f.dir.sub("Extern")
        f.store.secondaryBackupDirectory = ext
        try f.vault.upsert(kernEntry("A"))
        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2)
        try f.vault.upsert(kernEntry("B"))
        #expect(f.localBackups().count == 3)
        #expect(f.localBackups().contains { $0.reason == "passwortwechsel" })
        // fremde vaultID im selben Ordner bleibt
        let foreignDir = f.store.backupDirectory(for: other.vault.vaultID)
        try FileIO.ensureDirectory(foreignDir)
        for b in other.localBackups() {
            try FileIO.writeExclusive(foreignDir.appendingPathComponent(b.url.lastPathComponent),
                                      bytes: try FileIO.read(b.url, maxSize: FileFormat.maxFileBytes))
        }
        let foreignCount = FileIO.listFiles(foreignDir).count
        try f.vault.purgeBackups()
        let left = f.localBackups()
        #expect(left.count == 1)
        #expect(left.first?.generation == f.vault.generation)
        #expect(left.first?.reason == nil)
        #expect(FileIO.listFiles(ext).count == 1)
        #expect(FileIO.listFiles(foreignDir).count == foreignCount)
        // die neue Sicherung öffnet mit dem neuen Passwort
        f.vault.lock()
        let v = try f.store.restoreBackup(try #require(left.first), masterPassword: KT.pw2)
        #expect(Set(v.entries.map(\.title)) == ["A", "B"])
    }

    @Test("exportBackup/importBackup: verschlüsselte Kopie, Einspielen rotiert den DEK")
    func exportImport() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        let target = f.dir.url.appendingPathComponent("Kopie.siegel")
        try f.store.exportBackup(to: target)
        #expect(try FileIO.read(target, maxSize: FileFormat.maxFileBytes) == f.fileBytes())
        try f.store.exportBackup(to: target)   // überschreiben erlaubt (Benutzer hat gewählt)
        let dir = KernTempDir()
        let other = VaultStore(directory: dir.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        #expect(throws: SiegelError.wrongPassword) { try other.importBackup(from: target, masterPassword: KT.pw2) }
        #expect(other.vaultExists == false)
        let v = try other.importBackup(from: target, masterPassword: KT.pw1)
        #expect(v.entries.map(\.title) == ["A"])
        #expect(v.vaultID == f.vault.vaultID)
        #expect(v.generation == 3)
        #expect(try !v.dekForTesting().constantTimeEquals(f.vault.dekForTesting()))
        // Notfallcode des Originals öffnet die eingespielte Kopie (gleiches Kit)
        #expect(try other.checkRecoveryCode(f.code) == .exact)
        // beschädigte Quelle wird abgelehnt
        var b = try FileIO.read(target, maxSize: FileFormat.maxFileBytes)
        b[100] ^= 1
        FileIO.remove(target)
        try FileIO.writeExclusive(target, bytes: b)
        #expect(throws: SiegelError.corruptFile("file.checksum")) { try other.importBackup(from: target, masterPassword: KT.pw1) }
        #expect(throws: SiegelError.io("backup.missing")) {
            try other.importBackup(from: dir.url.appendingPathComponent("gibtsnicht.siegel"), masterPassword: KT.pw1)
        }
    }

    @Test("Threadsicher: parallele Änderungen gehen nicht verloren")
    func parallel() throws {
        let f = try KernVault.make()
        let errors = KernErrorBox()
        let vault = f.vault
        DispatchQueue.concurrentPerform(iterations: 8) { t in
            for i in 0..<10 {
                do { try vault.upsert(kernEntry("T\(t)-\(i)")) } catch { errors.add() }
                _ = vault.entries.count
                _ = vault.masterPasswordReuse
            }
        }
        #expect(errors.count == 0)
        #expect(f.vault.entries.count == 80)
        #expect(f.vault.generation == 81)
        f.vault.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1))?.entries.count == 80)
    }
}

final class KernErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func add() { lock.withLock { n += 1 } }
    var count: Int { lock.withLock { n } }
}

@Suite("KEK-Wiederverwendung")
struct KernKEKWiederverwendungTests {
    @Test("restoreNewestReadableBackup: gleiches Salz + Parameter → nur ein Argon2 zum Öffnen")
    func wiederherstellen() throws {
        let f = try KernVault.make()
        for i in 0..<4 { try f.vault.upsert(kernEntry("E\(i)")) }   // Sicherungen g1…g4, alle mit gleichem Salz
        f.vault.lock()
        // alle bis auf die älteste Sicherung beschädigen, dazu die Tresordatei
        let backups = f.localBackups()
        #expect(backups.count == 4)
        for b in backups.dropLast() {
            var bytes = try FileIO.read(b.url, maxSize: FileFormat.maxFileBytes)
            let k = KT.headerLength(bytes) + VaultSlots.size + 60
            bytes[k] ^= 1   // Inhalt kaputt, Prüfsumme neu → erst nach Argon2 erkannt
            FileIO.remove(b.url)
            try FileIO.writeExclusive(b.url, bytes: KT.withFixedChecksum(bytes))
        }
        var vb = try f.fileBytes()
        vb[vb.count / 2] ^= 1
        try f.writeFile(vb)
        let counter = TestHooks.Counter()
        let (v, used) = try TestHooks.$kdfCounter.withValue(counter) {
            try f.store.restoreNewestReadableBackup(masterPassword: KT.pw1)
        }
        #expect(used.generation == 1)
        #expect(v.entries.isEmpty)
        // 1× zum Öffnen (für alle vier Sicherungen wiederverwendet) + 1× neues Salz beim Einsetzen
        #expect(counter.value == 2)
    }

    @Test("Entsperren bei beschädigtem Inhalt: einmal neu lesen, KEK wiederverwenden")
    func entsperrenNeuLesen() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A"))
        var bytes = try f.fileBytes()
        bytes[KT.headerLength(bytes) + VaultSlots.size + 60] ^= 1
        try f.writeFile(KT.withFixedChecksum(bytes))
        let counter = TestHooks.Counter()
        TestHooks.$kdfCounter.withValue(counter) {
            #expect(throws: SiegelError.corruptFile("payload.auth")) { try f.store.unlock(masterPassword: KT.pw1) }
        }
        #expect(counter.value == 1)
    }
}
