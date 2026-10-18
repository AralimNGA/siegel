import CryptoKit
import Foundation
import Synchronization

public enum UnlockOutcome: Sendable {
    case unlocked(UnlockedVault)
    case rollbackSuspected(UnlockedVault, seenGeneration: UInt64, fileGeneration: UInt64)
}

/// Tresordatei, Sicherungen und alle Wege, einen Tresor zu öffnen oder zu ersetzen (SPEC §4, §8).
public final class VaultStore: @unchecked Sendable {
    static let vaultFileName = "Tresor.siegel"
    static let backupFolderName = "Sicherungen"
    static let hardwareFolderName = "Hardware"
    static let hardwareKeyExtension = "siegelhw"
    static let minimumFreeSpace: UInt64 = 64 << 20
    static let externalInterval: TimeInterval = 3600

    let directory: URL
    let rollbackGuard: RollbackGuard
    let limits: KDFLimits
    /// Wartezeit vor dem einmaligen Neu-Lesen bei beschädigter Datei (SPEC §4 „Beschädigt“).
    let corruptRetryDelay: TimeInterval
    private let secondary = Mutex<URL?>(nil)
    private let secondaryResult = Mutex<SecondaryBackupResult?>(nil)
    /// Temp-Reste im Datenordner werden beim ersten Schreiben dieser Instanz aufgeräumt.
    private var tempsCleaned = false
    /// Serialisiert alle Schreibvorgänge dieses Stores (Schritte 0–7).
    private let writeLock = NSLock()
    /// Serialisiert Lesen-Ändern-Schreiben von `Hardware/zustand.json` und das Vernichten (§23).
    let destructionLock = NSLock()
    private let eraser = Mutex<any DestructionKeyEraser>(FileDestructionKeyEraser())

    /// Schicht, die den Vernichtungsschlüssel V vernichtet (§23.1). Die App setzt die Umsetzung aus SiegelHardware
    /// (`SecureEnclaveFactor.destroy(keyID:directory:)`); Standard ist die Datei-Variante des Kerns.
    /// Zusatz zu §23.3.
    public var destructionKeyEraser: any DestructionKeyEraser {
        get { eraser.withLock { $0 } }
        set { eraser.withLock { $0 = newValue } }
    }

    public convenience init(directory: URL, rollbackGuard: RollbackGuard) {
        self.init(directory: directory, rollbackGuard: rollbackGuard, limits: .production, corruptRetryDelay: 2)
    }

    init(directory: URL, rollbackGuard: RollbackGuard, limits: KDFLimits, corruptRetryDelay: TimeInterval) {
        self.directory = directory
        self.rollbackGuard = rollbackGuard
        self.limits = limits
        self.corruptRetryDelay = corruptRetryDelay
    }

    #if DEBUG
    /// Nur Tests: `testKDF` verschiebt den KDF-Bereich (8 KiB…1 MiB, t 1…3), siehe `KDFLimits.testing`.
    convenience init(directory: URL, rollbackGuard: RollbackGuard, testKDF: Bool, corruptRetryDelay: TimeInterval = 0) {
        self.init(directory: directory, rollbackGuard: rollbackGuard,
                  limits: testKDF ? .testing : .production, corruptRetryDelay: corruptRetryDelay)
    }
    #endif

    /// Nur im Sandbox-Container `com.aralim.siegel`, sonst `.io("sandbox.missing")`.
    public static func defaultDirectory() throws -> URL {
        guard ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] == "com.aralim.siegel",
              let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw SiegelError.io("sandbox.missing")
        }
        return base.appendingPathComponent("Siegel", isDirectory: true)
    }

    /// `volumeIsEncryptedKey` (FileVault); nil = unbekannt.
    public static func volumeIsEncrypted(_ url: URL) -> Bool? {
        (try? url.resourceValues(forKeys: [.volumeIsEncryptedKey]))?.volumeIsEncrypted
    }

    public var vaultURL: URL { directory.appendingPathComponent(Self.vaultFileName, isDirectory: false) }

    /// Vergleicht Master-Passwort und Wiederholung nach der RFC-8265-Abbildung (SPEC §1.1: Zs → U+0020, NFC).
    /// Zusatz zur Schnittstelle in §8, damit die Oberfläche genau gleich vergleicht wie der Kern.
    public static func passwordsMatch(_ a: String, _ b: String) -> Bool {
        Array(PasswordNormalizer.normalize(a).utf8) == Array(PasswordNormalizer.normalize(b).utf8)
    }

    public var vaultExists: Bool { FileIO.exists(vaultURL) }

    /// Zweiter Sicherungsort; die App löst das Bookmark auf und startet den Zugriff.
    public var secondaryBackupDirectory: URL? {
        get { secondary.withLock { $0 } }
        set { secondary.withLock { $0 = newValue } }
    }

    var backupRoot: URL { directory.appendingPathComponent(Self.backupFolderName, isDirectory: true) }

    /// Ablage der Secure-Enclave-Schlüssel (`<seKeyID>.siegelhw`, SPEC §14.1), nicht in der Tresordatei.
    public var hardwareDirectory: URL { directory.appendingPathComponent(Self.hardwareFolderName, isDirectory: true) }

    /// Entfernt die Ablage eines nicht mehr gebrauchten SE-Schlüssels (nach erfolgreichem Schreiben, §13).
    /// Bestes Bemühen: Fehlt sie, ist nichts zu tun. Gross-/Kleinschreibung der UUID egal.
    func removeHardwareKey(_ keyID: UUID) {
        let wanted = (keyID.uuidString + "." + Self.hardwareKeyExtension).lowercased()
        for f in FileIO.listFiles(hardwareDirectory) where f.lastPathComponent.lowercased() == wanted {
            FileIO.remove(f)
        }
    }

    func backupDirectory(for id: UUID) -> URL {
        backupRoot.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    // MARK: - Sicherungen

    /// Alle Sicherungen (lokal, alle vaultIDs, und am zweiten Ort), neueste zuerst.
    public func backups() -> [BackupInfo] {
        var out: [BackupInfo] = []
        for dir in FileIO.listDirectories(backupRoot) where UUID(uuidString: dir.lastPathComponent) != nil {
            for f in FileIO.listFiles(dir) {
                guard let name = BackupNaming.parseLocal(f.lastPathComponent) else { continue }
                let info = Self.readInfo(f)
                out.append(BackupInfo(url: f, date: name.date, generation: info?.generation ?? name.generation,
                                      vaultID: info?.vaultID, reason: name.reason, isExternal: false))
            }
        }
        if let ext = secondaryBackupDirectory {
            for f in FileIO.listFiles(ext) {
                guard let date = BackupNaming.parseAnyExternal(f.lastPathComponent) else { continue }
                let info = Self.readInfo(f)
                out.append(BackupInfo(url: f, date: date, generation: info?.generation ?? 0,
                                      vaultID: info?.vaultID, reason: nil, isExternal: true))
            }
        }
        return out.sorted { a, b in
            if a.date != b.date { return a.date > b.date }
            if a.generation != b.generation { return a.generation > b.generation }
            return a.url.lastPathComponent > b.url.lastPathComponent
        }
    }

    /// Ordner der lokalen Sicherungen (je vaultID ein Unterordner); die Oberfläche öffnet „Sicherung einspielen…“ dort,
    /// damit auch angeheftete Sicherungen erreichbar sind. Zusatz zu §8 (v4.4, Befund datei-3).
    public var backupsDirectory: URL { backupRoot }

    /// Angaben zu einer vom Nutzer gewählten Sicherungsdatei (Stand, vaultID, Änderungsdatum), ohne Schlüssel.
    /// Fehlt sie → `io("backup.missing")`; unlesbar → `corruptFile`. Zusatz zu §8 (v4.4, Befund datei-3).
    public static func backupInfo(fileAt url: URL) throws -> BackupInfo {
        let bytes: [UInt8]
        do {
            bytes = try FileIO.read(url, maxSize: FileFormat.maxFileBytes)
        } catch SiegelError.vaultMissing {
            throw SiegelError.io("backup.missing")
        }
        let file = try VaultFile.parse(bytes)
        let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        return BackupInfo(url: url, date: date ?? Clock.now(), generation: file.generation, vaultID: file.header.uuid,
                          reason: nil, isExternal: true)
    }

    private static func readInfo(_ url: URL) -> (vaultID: UUID, generation: UInt64)? {
        guard let bytes = try? FileIO.read(url, maxSize: FileFormat.maxFileBytes),
              let file = try? VaultFile.parse(bytes) else { return nil }
        return (file.header.uuid, file.generation)
    }

    /// Verschiebt die (beschädigte) Tresordatei nach `Sicherungen/beschaedigt-<Zeit>.siegel`, nie löschen.
    public func quarantineCorruptVault() throws -> URL {
        try writeLock.withLock {
            guard vaultExists else { throw SiegelError.vaultMissing }
            try FileIO.ensureDirectory(backupRoot)
            for attempt in 0..<32 {
                let name = BackupNaming.quarantineName(date: Clock.now(),
                                                       suffix: attempt == 0 ? nil : BackupNaming.randomHex4())
                let dst = backupRoot.appendingPathComponent(name, isDirectory: false)
                do {
                    try FileIO.renameExclusive(vaultURL, to: dst)
                    try? FileIO.fsyncDirectory(directory)
                    try? FileIO.fsyncDirectory(backupRoot)
                    return dst
                } catch is FileIO.Exists {
                    continue
                }
            }
            throw SiegelError.io("quarantine.name")
        }
    }

    /// Verschlüsselte Kopie der aktuellen Datei (nur unbeschädigt) an `url`, danach zurückgelesen und verglichen.
    ///
    /// Keine eigene Temp-Datei neben dem Ziel: In der App-Sandbox gibt das Sichern-Panel nur genau die gewählte
    /// Datei frei, eine Nachbardatei im Zielordner scheitert mit EPERM. `Data.write(.atomic)` weicht selbst auf
    /// einen erlaubten Weg aus. Das Original im Container bleibt unberührt; eine halb geschriebene Kopie fällt
    /// beim Zurücklesen auf (`io("export.verify")`).
    public func exportBackup(to url: URL) throws {
        let bytes = try FileIO.read(vaultURL, maxSize: FileFormat.maxFileBytes)
        _ = try VaultFile.parse(bytes)
        try Self.writeVerified(bytes, to: url)
    }

    /// Schreibt `bytes` an die vom Benutzer gewählte Datei (ersetzt sie) und prüft sie Byte für Byte.
    /// Zuerst atomar über Foundation; lehnt das Dateisystem bzw. die Sandbox die dafür nötige Temp-Datei ab,
    /// direkt in genau diese Datei (nie eine Nachbardatei anlegen).
    static func writeVerified(_ bytes: [UInt8], to url: URL) throws {
        do {
            try Data(bytes).write(to: url, options: [.atomic])
        } catch {
            try FileIO.writeInPlace(url, bytes: bytes)
        }
        _ = chmod(url.path, 0o600)
        let back: [UInt8]
        do {
            back = try FileIO.read(url, maxSize: FileFormat.maxFileBytes)
        } catch {
            throw SiegelError.io("export.verify")
        }
        guard back == bytes, (try? VaultFile.parse(back)) != nil else {
            throw SiegelError.io("export.verify")
        }
    }

    // MARK: - Interna: Speichern

    enum DiskExpectation {
        /// Neuer Tresor: es darf keine Datei geben.
        case absent
        /// Normales Speichern: Datei hat diese vaultID und Generation (fehlt sie, wird neu geschrieben).
        case generation(UUID, UInt64)
        /// Ersetzen: Datei ist bytegleich wie beobachtet (SHA-256; nil = fehlte).
        case observed([UInt8]?)
    }

    struct DiskState {
        let digest: [UInt8]
        let file: VaultFile?
        /// Datei einer neueren Formatversion (nie überschreiben).
        let newerVersion: UInt16?
    }

    func observeDisk() throws -> DiskState? {
        let bytes: [UInt8]
        do {
            bytes = try FileIO.read(vaultURL, maxSize: FileFormat.maxFileBytes)
        } catch SiegelError.vaultMissing {
            return nil
        } catch SiegelError.corruptFile {
            // zu gross zum Lesen
            return DiskState(digest: [], file: nil, newerVersion: nil)
        }
        let digest = Array(SHA256.hash(data: bytes))
        do {
            return DiskState(digest: digest, file: try VaultFile.parse(bytes), newerVersion: nil)
        } catch SiegelError.unsupportedVersion(let v) {
            return DiskState(digest: digest, file: nil, newerVersion: v)
        } catch {
            return DiskState(digest: digest, file: nil, newerVersion: nil)
        }
    }

    struct PersistResult {
        let generation: UInt64
        let content: VaultContent
    }

    func nextGeneration(vaultID: UUID, base: UInt64) throws -> UInt64 {
        let seen = rollbackGuard.lastSeenGeneration(vaultID: vaultID) ?? 0
        let (g, overflow) = max(base, seen).addingReportingOverflow(1)
        guard !overflow else { throw SiegelError.corruptFile("payload.generation") }
        return g
    }

    /// Inhalt vorbereiten, Datei bauen und nach SPEC §4 speichern.
    ///
    /// Selbstvernichtung (§23, v4.4): `duressBinding` = F aus den Faktoren dieses Kopfes (`DuressCrypto.binding`);
    /// Pflicht, sobald der Inhalt ein Vernichtungs-Passwort hat (sonst `crypto("duress.binding")`, vor dem Schreiben –
    /// der Umschlag liesse sich nicht nachführen). `newDEK`: die Datei bekommt einen neuen DEK (Zugangswechsel).
    func persist(header: VaultHeader, slots: VaultSlots, dek: SecureBytes, content: VaultContent,
                 baseGeneration: UInt64, expectation: DiskExpectation, reason: String?,
                 duressBinding: SecureBytes? = nil, newDEK: Bool = false) throws -> PersistResult {
        try limits.validate(header.kdf)
        // Geschrieben wird nur das aktuelle Format, und Stufe (Inhalt) und Faktoren (Kopf) passen immer zusammen.
        guard header.formatVersion == FileFormat.currentVersion else { throw SiegelError.crypto("format.version") }
        guard content.level.factors == header.factors else { throw SiegelError.crypto("level.mismatch") }
        guard content.destructionKeysAvoid(header: header) else { throw SiegelError.crypto("payload.destruction") }
        var content = content
        let now = Clock.now()
        content.prepareForSave(now: now)
        try content.prepareEntryData(now: now)
        if content.destruction?.duress != nil, duressBinding == nil { throw SiegelError.crypto("duress.binding") }
        let generation = try nextGeneration(vaultID: header.uuid, base: baseGeneration)
        let built = try VaultCrypto.buildFile(header: header, slots: slots, generation: generation, dek: dek,
                                              content: content)
        try commitWrite(bytes: built.bytes, header: header, slots: slots, generation: generation, dek: dek,
                        digest: built.digest, expectation: expectation, reason: reason)
        // Selbstvernichtung (§23): Umschlag des Vernichtungs-Passworts an diesen DEK (und F), Zustand nachführen.
        syncDestructionAfterWrite(content: content, header: header, dek: dek, binding: duressBinding, newDEK: newDEK)
        return PersistResult(generation: generation, content: content)
    }

    /// Speichern in genau dieser Reihenfolge (SPEC §4):
    /// (0) Platz (1) Generation auf der Platte (2) Temp + F_FULLFSYNC (3) Rücklese-Prüfung (4) clonefile-Sicherung
    /// (5) rename (6) fsync Ordner (7) ausdünnen. Scheitert 1–4: alte Datei unverändert, Temp entfernt.
    private func commitWrite(bytes: [UInt8], header: VaultHeader, slots: VaultSlots, generation: UInt64,
                             dek: SecureBytes, digest: [UInt8], expectation: DiskExpectation,
                             reason: String?) throws {
        try writeLock.withLock {
            try FileIO.ensureDirectory(directory)
            if !tempsCleaned {
                tempsCleaned = true
                Self.removeStaleTemps(in: FileIO.listFiles(directory), prefix: "." + Self.vaultFileName + ".",
                                      now: Clock.now())
            }
            // (0)
            if let free = FileIO.freeSpace(directory), free < Self.minimumFreeSpace {
                throw SiegelError.notEnoughDiskSpace
            }
            // (1)
            let existing = try observeDisk()
            switch expectation {
            case .absent:
                if existing != nil { throw SiegelError.vaultAlreadyExists }
            case let .generation(id, gen):
                if let e = existing {
                    guard let f = e.file, f.header.uuid == id, f.generation == gen else {
                        throw SiegelError.vaultChangedOnDisk
                    }
                }
            case let .observed(d):
                guard existing?.digest == d else { throw SiegelError.vaultChangedOnDisk }
                // Eine Datei mit höherer Formatversion wird nie überschrieben.
                if let v = existing?.newerVersion { throw SiegelError.unsupportedVersion(v) }
            }
            // Der letzte Stand im Format v1 wird vor dem ersten v2-Schreiben angeheftet gesichert (§13.2).
            let reason = existing?.file?.header.formatVersion == 1 ? BackupNaming.Reason.migrationV1.rawValue : reason
            // (2)
            let tmp = try writeTemp(bytes)
            do {
                #if DEBUG
                if TestHooks.corruptTempBeforeVerify { try Self.flipByteForTesting(tmp) }
                #endif
                // (3)
                try verifyTemp(tmp, header: header, slots: slots, generation: generation, dek: dek, digest: digest)
                // (4)
                if let e = existing { try backupCurrent(e, reason: reason) }
            } catch {
                FileIO.remove(tmp)
                throw error
            }
            // (5)
            do {
                try FileIO.rename(tmp, to: vaultURL)
            } catch {
                FileIO.remove(tmp)
                throw error
            }
            // (6) Die Datei ist ersetzt; ein Fehler hier darf den Erfolg nicht mehr umkehren.
            try? FileIO.fsyncDirectory(directory)
            rollbackGuard.record(vaultID: header.uuid, generation: generation)
            // (7)
            thinLocalBackups(vaultID: header.uuid)
            writeSecondaryBackup(vaultID: header.uuid, bytes: bytes, force: false)
        }
    }

    private func writeTemp(_ bytes: [UInt8]) throws -> URL {
        for _ in 0..<16 {
            let tmp = directory.appendingPathComponent("." + Self.vaultFileName + "." + hexString(randomBytes(4)) + ".tmp")
            do {
                try FileIO.writeExclusive(tmp, bytes: bytes)
                return tmp
            } catch is FileIO.Exists {
                continue
            }
        }
        throw SiegelError.io("file.create")
    }

    /// (3) Temp neu lesen, Prüfsumme, Kopf/Slots/Generation, mit dem DEK entschlüsseln, SHA-256 vergleichen.
    private func verifyTemp(_ tmp: URL, header: VaultHeader, slots: VaultSlots, generation: UInt64,
                            dek: SecureBytes, digest: [UInt8]) throws {
        do {
            let back = try FileIO.read(tmp, maxSize: FileFormat.maxFileBytes)
            let file = try VaultFile.parse(back)
            guard file.header == header, file.slots == slots, file.generation == generation else {
                throw SiegelError.io("save.verify")
            }
            let (_, backDigest) = try VaultCrypto.decryptPayload(file, dek: dek)
            guard backDigest == digest else { throw SiegelError.io("save.verify") }
        } catch {
            throw SiegelError.io("save.verify")
        }
    }

    /// (4) Bisherige Datei per clonefile sichern (nie überschreiben). Unlesbare Datei → „beschaedigt-…“.
    private func backupCurrent(_ e: DiskState, reason: String?) throws {
        if let f = e.file {
            let dir = backupDirectory(for: f.header.uuid)
            try FileIO.ensureDirectory(dir)
            for _ in 0..<32 {
                let name = BackupNaming.localName(date: Clock.now(), generation: f.generation, reason: reason)
                do {
                    try FileIO.clone(vaultURL, to: dir.appendingPathComponent(name, isDirectory: false))
                    try? FileIO.fsyncDirectory(dir)
                    return
                } catch is FileIO.Exists {
                    continue
                }
            }
            throw SiegelError.io("backup.name")
        }
        try FileIO.ensureDirectory(backupRoot)
        for attempt in 0..<32 {
            let name = BackupNaming.quarantineName(date: Clock.now(), suffix: attempt == 0 ? nil : BackupNaming.randomHex4())
            do {
                try FileIO.clone(vaultURL, to: backupRoot.appendingPathComponent(name, isDirectory: false))
                try? FileIO.fsyncDirectory(backupRoot)
                return
            } catch is FileIO.Exists {
                continue
            }
        }
        throw SiegelError.io("backup.name")
    }

    /// (7) Ausdünnen pro vaultID; nur Dateien nach dem Namensschema werden je angefasst.
    func thinLocalBackups(vaultID: UUID) {
        let dir = backupDirectory(for: vaultID)
        var items: [BackupThinning.Item] = []
        for f in FileIO.listFiles(dir) {
            guard let n = BackupNaming.parseLocal(f.lastPathComponent) else { continue }
            items.append(BackupThinning.Item(url: f, date: n.date, pinned: n.reason != nil))
        }
        for u in BackupThinning.selectForDeletion(items, now: Clock.now()) { FileIO.remove(u) }
    }

    /// Ergebnis des letzten Versuchs am zweiten Sicherungsort (nur dieser Prozess); nil = noch keiner.
    /// Die Oberfläche merkt sich damit die Zeit der letzten Sicherung dort und zeigt, wenn der Ort fehlt.
    /// Zusatz zur Schnittstelle in §8 (SPEC v3.1).
    public var lastSecondaryBackupResult: SecondaryBackupResult? {
        secondaryResult.withLock { $0 }
    }

    /// Zweiter Sicherungsort: höchstens 1× pro Stunde, atomar, gleiche Ausdünnung. Fehler brechen nichts ab,
    /// werden aber als Ergebnis gemeldet (`lastSecondaryBackupResult`).
    @discardableResult
    func writeSecondaryBackup(vaultID: UUID, bytes: [UInt8], force: Bool) -> SecondaryBackupResult {
        let result = writeSecondaryBackupUnrecorded(vaultID: vaultID, bytes: bytes, force: force)
        secondaryResult.withLock { $0 = result }
        return result
    }

    private func writeSecondaryBackupUnrecorded(vaultID: UUID, bytes: [UInt8], force: Bool) -> SecondaryBackupResult {
        guard let dir = secondaryBackupDirectory, let files = try? FileIO.listFilesChecked(dir) else {
            return .unreachable
        }
        let prefix = BackupNaming.externalPrefix(vaultID: vaultID)
        let now = Clock.now()
        Self.removeStaleTemps(in: files, prefix: "." + prefix, now: now)
        var items: [BackupThinning.Item] = []
        for f in files {
            guard let d = BackupNaming.parseExternal(f.lastPathComponent, prefix: prefix) else { continue }
            items.append(BackupThinning.Item(url: f, date: d, pinned: false))
        }
        if !force, let newest = items.map(\.date).max() {
            let age = now.timeIntervalSince(newest)
            if age >= 0, age < Self.externalInterval { return .notDue }
        }
        let name = BackupNaming.externalName(vaultID: vaultID, date: now)
        let dst = dir.appendingPathComponent(name, isDirectory: false)
        let tmp = dir.appendingPathComponent("." + name + "." + BackupNaming.randomHex4() + ".tmp", isDirectory: false)
        do {
            try FileIO.writeExclusive(tmp, bytes: bytes)
        } catch {
            return .failed
        }
        do {
            try FileIO.renameExclusive(tmp, to: dst)
        } catch is FileIO.Exists where force {
            // Gleiche Sekunde wie eine eben geschriebene Kopie derselben vaultID: durch den aktuellen Stand ersetzen.
            do {
                try FileIO.rename(tmp, to: dst)
            } catch {
                FileIO.remove(tmp)
                return .failed
            }
        } catch {
            FileIO.remove(tmp)
            return .failed
        }
        try? FileIO.fsyncDirectory(dir)
        if !items.contains(where: { $0.url.lastPathComponent == name }) {
            items.append(BackupThinning.Item(url: dst, date: now, pinned: false))
        }
        for u in BackupThinning.selectForDeletion(items, now: now) where u.lastPathComponent != name { FileIO.remove(u) }
        return .written(now)
    }

    /// Reste abgebrochener Schreibvorgänge (Absturz zwischen Temp-Datei und rename) entfernen. Nur ältere als
    /// eine Minute, damit ein gleichzeitiger Schreibvorgang nie getroffen wird. Sie sind verschlüsselt, öffnen
    /// sich aber mit dem damaligen Zugang (wichtig nach einem Passwortwechsel).
    static func removeStaleTemps(in files: [URL], prefix: String, now: Date) {
        for f in files {
            let name = f.lastPathComponent
            guard name.hasPrefix(prefix), name.hasSuffix(".tmp"), let age = FileIO.age(f, now: now), age > 60 else {
                continue
            }
            FileIO.remove(f)
        }
    }

    /// Alle Sicherungen dieser vaultID entfernen (auch angeheftete, auch am zweiten Ort) und sofort eine
    /// Sicherung des aktuellen Stands anlegen. Der Bericht nennt, was übrig blieb.
    func purgeBackups(vaultID: UUID, generation: UInt64) throws -> PurgeReport {
        try writeLock.withLock {
            guard let disk = try observeDisk(), let f = disk.file,
                  f.header.uuid == vaultID, f.generation == generation else {
                throw SiegelError.vaultChangedOnDisk
            }
            #if DEBUG
            if TestHooks.failPurgeBackups { throw SiegelError.io("test.purge") }
            #endif
            var report = PurgeReport()
            let now = Clock.now()
            Self.removeStaleTemps(in: FileIO.listFiles(directory), prefix: "." + Self.vaultFileName + ".", now: now)
            let dir = backupDirectory(for: vaultID)
            for u in FileIO.listFiles(dir) where u.pathExtension == BackupNaming.fileExtension {
                if FileIO.removeChecked(u) { report.removed += 1 } else { report.failed += 1 }
            }
            if let ext = secondaryBackupDirectory {
                let prefix = BackupNaming.externalPrefix(vaultID: vaultID)
                if let files = try? FileIO.listFilesChecked(ext) {
                    for u in files where BackupNaming.parseExternal(u.lastPathComponent, prefix: prefix) != nil {
                        if FileIO.removeChecked(u) { report.removed += 1 } else { report.failed += 1 }
                    }
                } else {
                    report.secondaryUnreachable = true
                }
            }
            try backupCurrent(disk, reason: nil)
            let bytes = try FileIO.read(vaultURL, maxSize: FileFormat.maxFileBytes)
            if !report.secondaryUnreachable, secondaryBackupDirectory != nil,
               case .failed = writeSecondaryBackup(vaultID: vaultID, bytes: bytes, force: true) {
                report.failed += 1
            }
            return report
        }
    }

    /// Holt das Entfernen am zweiten Ort nach, wenn er beim `purgeBackups` nicht erreichbar war: entfernt dort
    /// alle Sicherungen dieser vaultID, die vor `before` entstanden sind, und legt eine frische Kopie des
    /// aktuellen Stands an (wenn die Tresordatei zu dieser vaultID gehört). Braucht keinen entsperrten Tresor.
    /// Zusatz zur Schnittstelle in §8 (SPEC v3.1).
    public func purgeSecondaryBackups(vaultID: UUID, before: Date) -> PurgeReport {
        writeLock.withLock {
            var report = PurgeReport()
            guard let ext = secondaryBackupDirectory, let files = try? FileIO.listFilesChecked(ext) else {
                report.secondaryUnreachable = true
                return report
            }
            let prefix = BackupNaming.externalPrefix(vaultID: vaultID)
            Self.removeStaleTemps(in: files, prefix: "." + prefix, now: Clock.now())
            for u in files {
                guard let date = BackupNaming.parseExternal(u.lastPathComponent, prefix: prefix), date < before else {
                    continue
                }
                if FileIO.removeChecked(u) { report.removed += 1 } else { report.failed += 1 }
            }
            if let bytes = try? FileIO.read(vaultURL, maxSize: FileFormat.maxFileBytes),
               let file = try? VaultFile.parse(bytes), file.header.uuid == vaultID,
               case .failed = writeSecondaryBackup(vaultID: vaultID, bytes: bytes, force: true) {
                report.failed += 1
            }
            return report
        }
    }

    static func randomConfirmationGroups() -> [Int] {
        let a = Int(secureUniform(UInt32(RecoveryCodeCodec.groupCount)))
        var b = Int(secureUniform(UInt32(RecoveryCodeCodec.groupCount - 1)))
        if b >= a { b += 1 }
        return [min(a, b), max(a, b)]
    }

    #if DEBUG
    /// Nur Tests: aktuelle Datei sofort sichern (gleiche Generation beliebig oft, Namen dürfen nie kollidieren).
    func backupNowForTesting(reason: String?) throws {
        try writeLock.withLock {
            guard let disk = try observeDisk() else { throw SiegelError.vaultMissing }
            try backupCurrent(disk, reason: reason)
        }
    }

    static func flipByteForTesting(_ url: URL) throws {
        var bytes = try FileIO.read(url, maxSize: FileFormat.maxFileBytes)
        bytes[bytes.count / 2] ^= 0x01
        FileIO.remove(url)
        try FileIO.writeExclusive(url, bytes: bytes)
    }
    #endif
}
