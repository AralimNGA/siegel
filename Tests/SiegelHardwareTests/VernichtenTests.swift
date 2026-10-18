import CryptoKit
import Darwin
import Foundation
import SiegelCore
import Testing
@testable import SiegelHardware

/// SPEC v4.3 §23.1: Vernichtungs-Schlüssel und Krypto-Löschung. Alles gegen die Software-Schicht – kein Touch-ID-
/// Dialog, kein echter Secure-Enclave-Schlüssel.
@Suite("Vernichten und Backup-Ausschluss (§23.1)")
struct VernichtenTests {
    let backend = SoftwareSEBackend()
    var engine: SecureEnclaveEngine { SecureEnclaveEngine(backend: backend) }

    private func excluded(_ url: URL) -> Bool? {
        (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup
    }

    private func bytes(_ url: URL) throws -> [UInt8] { Array(try Data(contentsOf: url)) }

    @Test func alleSchluesseldateienSindVomBackupAusgenommen() throws {
        let dir = tempDirectory().appendingPathComponent("Hardware", isDirectory: true)
        let unlock = try engine.enroll(directory: dir)
        let entry = try engine.enrollEntryKey(directory: dir)
        for id in [unlock.keyID, entry.keyID] {
            #expect(excluded(HardwareKeyFile.fileURL(keyID: id, directory: dir)) == true)
        }
        // Auch direkt über das Dateiformat (jede Art), und keine Temp-Reste.
        let direkt = UUID()
        try HardwareKeyFile(kind: .entry, keyID: direkt, blob: Data(repeating: 7, count: 90),
                            point: P256.KeyAgreement.PrivateKey().publicKey.x963Representation).write(to: dir)
        #expect(excluded(HardwareKeyFile.fileURL(keyID: direkt, directory: dir)) == true)
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).count == 3)
    }

    @Test func vernichtenUeberschreibtVorDemLoeschen() throws {
        let dir = tempDirectory()
        let v = try engine.enrollEntryKey(directory: dir)
        let datei = HardwareKeyFile.fileURL(keyID: v.keyID, directory: dir)
        let vorher = try bytes(datei)
        // Zweiter Name auf dieselbe Datei (gleicher Inode): Er zeigt, was mit dem Inhalt geschah.
        let zeuge = dir.appendingPathComponent("zeuge.bin")
        #expect(link(datei.path, zeuge.path) == 0)
        let abfragen = backend.prompts.count

        try engine.destroy(keyID: v.keyID, directory: dir)

        #expect(!FileManager.default.fileExists(atPath: datei.path))
        let nachher = try bytes(zeuge)
        #expect(nachher.count == vorher.count)
        #expect(nachher != vorher)
        // Kein Rest des Formats: weder Magic noch Blob-Präfix der Software-Schicht.
        #expect(Array(nachher.prefix(8)) != HardwareKeyFile.magic)
        #expect(Data(nachher).range(of: Data(SoftwareSEBackend.blobPrefix)) == nil)
        #expect(throws: SiegelError.self) {
            try HardwareKeyFile.decode(nachher, expectedKeyID: v.keyID, expectedKind: .entry)
        }
        // Danach ist der Schlüssel unbrauchbar – ohne Touch-ID-Abfrage.
        let k = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try engine.sharedSecret(keyID: v.keyID, ephemeralPublicKey: k, directory: dir, reason: "x")
        }
        #expect(backend.prompts.count == abfragen)
    }

    @Test func vernichtenTrifftNurDiesenSchluessel() throws {
        let dir = tempDirectory()
        let v = try engine.enrollEntryKey(directory: dir)
        let entsperren = try engine.enroll(directory: dir)
        try engine.destroy(keyID: v.keyID, directory: dir)
        let wieder = try engine.secret(keyID: entsperren.keyID, directory: dir, reason: "Siegel entsperren")
        #expect(wieder.testBytes == entsperren.secret.testBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path)
                == [HardwareKeyFile.fileURL(keyID: entsperren.keyID, directory: dir).lastPathComponent])
    }

    @Test func vernichtenOhneDateiIstKeinFehlerUndWiederholbar() throws {
        let dir = tempDirectory()
        try engine.destroy(keyID: UUID(), directory: dir)
        let v = try engine.enrollEntryKey(directory: dir)
        try engine.destroy(keyID: v.keyID, directory: dir)
        try engine.destroy(keyID: v.keyID, directory: dir)
        // Öffentliche Schnittstelle: kein Dialog, kein Gerät nötig.
        try SecureEnclaveFactor.destroy(keyID: UUID(), directory: tempDirectory())
        #expect(backend.prompts.count == 1)
    }

    @Test func vernichtenFolgtKeinemSymlink() throws {
        let dir = tempDirectory()
        let id = UUID()
        let fremd = tempDirectory().appendingPathComponent("fremde-datei.bin")
        let inhalt = Data((0..<300).map { UInt8($0 & 0xff) })
        try inhalt.write(to: fremd)
        try FileManager.default.createSymbolicLink(at: HardwareKeyFile.fileURL(keyID: id, directory: dir),
                                                   withDestinationURL: fremd)
        try engine.destroy(keyID: id, directory: dir)
        // Der Link ist weg, das Ziel unberührt.
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
        #expect(try Data(contentsOf: fremd) == inhalt)
    }

    @Test func ueberschreibenErfasstDieGanzeDatei() throws {
        // Grösser als ein Block (4096), damit auch die Blockgrenzen geprüft sind.
        let datei = tempDirectory().appendingPathComponent("gross.bin")
        try Data(repeating: 0, count: 10_000).write(to: datei)
        let fd = open(datei.path, O_WRONLY | O_CLOEXEC)
        #expect(fd >= 0)
        #expect(HardwareKeyFile.overwriteWithRandom(fd))
        close(fd)
        let nachher = try bytes(datei)
        #expect(nachher.count == 10_000)
        // Zufall: etwa 1/256 Nullen; je Block deutlich weniger als die Hälfte.
        for start in stride(from: 0, to: 10_000, by: 4096) {
            let block = nachher[start..<min(start + 4096, 10_000)]
            #expect(block.filter { $0 == 0 }.count < block.count / 8)
        }
        // Kein reguläres Ziel (Ordner) → nichts geschrieben, false.
        let ordner = open(tempDirectory().path, O_RDONLY | O_CLOEXEC)
        #expect(!HardwareKeyFile.overwriteWithRandom(ordner))
        close(ordner)
    }

    @Test func loeschenGescheitertWirdGemeldet() throws {
        let dir = tempDirectory()
        let v = try engine.enrollEntryKey(directory: dir)
        // Ordner ohne Schreibrecht: Löschen scheitert → io("hw.destroy"), Inhalt ist trotzdem überschrieben.
        #expect(chmod(dir.path, 0o500) == 0)
        defer { _ = chmod(dir.path, 0o700) }
        let datei = HardwareKeyFile.fileURL(keyID: v.keyID, directory: dir)
        let vorher = try bytes(datei)
        #expect(throws: SiegelError.io("hw.destroy")) { try engine.destroy(keyID: v.keyID, directory: dir) }
        let nachher = try bytes(datei)
        #expect(nachher.count == vorher.count && nachher != vorher)
    }
}
