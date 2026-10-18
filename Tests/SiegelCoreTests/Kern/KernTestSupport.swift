import Foundation
import Testing
@testable import SiegelCore

/// Gemeinsame Hilfen der Kern-Tests. Alle Tests arbeiten in eigenen Temp-Ordnern mit In-Memory-RollbackGuard.
enum KT {
    // Zufällig erzeugte, starke Passwörter (≥ 26 Zeichen aus 82) – bestehen auch die echte zxcvbn-Regel.
    static let pw1 = "u,F?CfDuMlYWuJASPVQ*6GUG@O"
    static let pw2 = "v,:f,uX&%!kQ>NiIti@!3c>w:~"
    static let pw3 = "t=5:U.+F3mYWO6#O8@s~@~4_q:"
    static let pw4 = "u_b,DV_>9Ml^Zx./m936@ziw:b"
    /// Offensichtlich schwach (für Policy-Tests).
    static let weak = "abc"

    /// Testschalter-Profile (8 KiB…1 MiB, t 1…3).
    static let kdf = KDFParameters(opsLimit: 1, memLimitBytes: 8 << 10)
    static let kdf2 = KDFParameters(opsLimit: 2, memLimitBytes: 16 << 10)

    static func hex(_ b: some Sequence<UInt8>) -> String { hexString(b) }

    static func bytes(fromHex s: String) -> [UInt8] {
        var out = [UInt8]()
        var it = s.makeIterator()
        while let a = it.next(), let b = it.next() {
            out.append(UInt8(String([a, b]), radix: 16) ?? 0)
        }
        return out
    }

    static func unlocked(_ outcome: UnlockOutcome) -> UnlockedVault? {
        if case let .unlocked(v) = outcome { return v }
        return nil
    }

    static func anyVault(_ outcome: UnlockOutcome) -> UnlockedVault {
        switch outcome {
        case let .unlocked(v): return v
        case let .rollbackSuspected(v, _, _): return v
        }
    }

    /// Länge des Kopfes einer (gültigen) Datei (v1: 1653, v2: 1709 + Credential-Länge).
    static func headerLength(_ bytes: [UInt8]) -> Int {
        (try? VaultFile.parse(bytes).header.bytes.count) ?? VaultHeader.v1Size
    }

    /// Prüfsumme neu berechnen (Angreifer-Variante; Label nach der Version im Kopf).
    static func withFixedChecksum(_ b: [UInt8]) -> [UInt8] {
        var x = Array(b.dropLast(FileFormat.checksumBytes))
        x += FileFormat.fileChecksum(x[...])
        return x
    }

    static func isCorrupt(_ e: SiegelError?) -> Bool {
        if case .corruptFile = e { return true }
        return false
    }
}

/// Temp-Ordner, der am Ende des Tests entfernt wird.
final class KernTempDir: @unchecked Sendable {
    let url: URL

    init() {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("siegel-kern-" + UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }

    func sub(_ name: String) -> URL {
        let u = url.appendingPathComponent(name, isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
}

/// Ein Test-Tresor (Testschalter-KDF) samt Ordner.
struct KernVault {
    let dir: KernTempDir
    let guardian: InMemoryRollbackGuard
    let store: VaultStore
    let vault: UnlockedVault
    let pending: PendingRecovery

    static func make(password: String = KT.pw1, kdf: KDFParameters = KT.kdf) throws -> KernVault {
        let dir = KernTempDir()
        let guardian = InMemoryRollbackGuard()
        let store = VaultStore(directory: dir.url.appendingPathComponent("Siegel", isDirectory: true),
                               rollbackGuard: guardian, testKDF: true)
        let (vault, pending) = try store.create(masterPassword: password, kdf: kdf)
        return KernVault(dir: dir, guardian: guardian, store: store, vault: vault, pending: pending)
    }

    /// Zweiter Store auf denselben Ordner (eigene Instanz).
    func reopenStore(guardian g: RollbackGuard? = nil) -> VaultStore {
        VaultStore(directory: store.directory, rollbackGuard: g ?? guardian, testKDF: true)
    }

    func fileBytes() throws -> [UInt8] {
        try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes)
    }

    func writeFile(_ bytes: [UInt8]) throws {
        FileIO.remove(store.vaultURL)
        try FileIO.writeExclusive(store.vaultURL, bytes: bytes)
    }

    func parsedFile() throws -> VaultFile { try VaultFile.parse(try fileBytes()) }

    var code: String { pending.code.formatted }

    func localBackups() -> [BackupInfo] {
        store.backups().filter { !$0.isExternal && $0.vaultID == vault.vaultID }
    }

    func backupFileNames() -> Set<String> {
        Set(FileIO.listFiles(store.backupDirectory(for: vault.vaultID)).map(\.lastPathComponent))
    }

    /// Temp-Dateien im Tresor-Ordner.
    func tempFiles() -> [URL] {
        FileIO.listFiles(store.directory).filter { $0.lastPathComponent.hasSuffix(".tmp") }
    }
}

func kernEntry(_ title: String, user: String = "anna", password: String = "Geheim-123", url: String = "https://example.ch",
           notes: String = "") -> VaultEntry {
    VaultEntry(title: title, username: user, password: password, url: url, notes: notes)
}
