import CryptoKit
import Darwin
import Foundation
import SiegelCore

/// Ablage eines Secure-Enclave-Schlüssels ausserhalb der Tresordatei (SPEC §14.1):
/// `<Ordner>/<keyID>.siegelhw`, Rechte 0600, Ordner 0700, vom Backup ausgenommen (v4.3, §23.1).
///
/// Format (Little-Endian, feste Reihenfolge, strenger Parser – jede Abweichung ist ein Fehler):
///
/// | Feld | Grösse |
/// |---|---|
/// | magic `"SIEGELHW"` | 8 |
/// | version `u16` = 1 | 2 |
/// | kind `u8` (1 = Entsperren, 2 = Einträge) | 1 |
/// | keyID (bindet die Datei an ihren Namen) | 16 |
/// | blobLength `u16` (1…4096) | 2 |
/// | seBlob (`dataRepresentation`, vom Secure Enclave verpackt) | blobLength |
/// | point (x963, 65 B): kind 1 = P (öffentlicher Software-Schlüssel), kind 2 = öffentlicher SE-Schlüssel | 65 |
/// | Prüfsumme `SHA3-256("Siegel v2 hw file check" ‖ alle Bytes davor)` | 32 |
///
/// SPEC nennt `{version, seBlob, P}`; magic, kind, keyID und Prüfsumme sind Ergänzungen gegen Verwechseln
/// (Eintrags- statt Entsperr-Schlüssel, umbenannte Datei) und Bitfäule.
struct HardwareKeyFile: Equatable, Sendable {
    enum Kind: UInt8, Sendable {
        case unlock = 1
        case entry = 2
    }

    static let magic: [UInt8] = Array("SIEGELHW".utf8)
    static let version: UInt16 = 1
    static let maxBlobLength = 4096
    static let pointLength = 65
    static let checksumLength = 32
    static let maxFileLength = 8 + 2 + 1 + 16 + 2 + maxBlobLength + pointLength + checksumLength
    static let fileExtension = "siegelhw"
    static let checksumLabel: [UInt8] = Array("Siegel v2 hw file check".utf8)

    let kind: Kind
    let keyID: UUID
    let blob: Data
    let point: Data

    static func fileURL(keyID: UUID, directory: URL) -> URL {
        directory.appendingPathComponent("\(keyID.uuidString).\(fileExtension)", isDirectory: false)
    }

    // MARK: Kodieren / strenges Lesen

    func encoded() throws -> [UInt8] {
        guard (1...Self.maxBlobLength).contains(blob.count) else { throw SiegelError.crypto("hw.blob") }
        guard point.count == Self.pointLength else { throw SiegelError.crypto("hw.point") }
        var out: [UInt8] = []
        out.reserveCapacity(Self.maxFileLength)
        out += Self.magic
        out.appendLE16(Self.version)
        out.append(kind.rawValue)
        out += keyID.hwBytes
        out.appendLE16(UInt16(blob.count))
        out += blob
        out += point
        out += Self.checksum(out)
        return out
    }

    /// Strenger Parser. Fehler sind feste Codes `corruptFile("hw.…")`; die öffentliche API macht daraus
    /// `factorUnavailable(.secureEnclave)`.
    static func decode(_ bytes: [UInt8], expectedKeyID: UUID, expectedKind: Kind) throws -> HardwareKeyFile {
        let fixed = 8 + 2 + 1 + 16 + 2
        guard bytes.count >= fixed + 1 + pointLength + checksumLength, bytes.count <= maxFileLength else {
            throw SiegelError.corruptFile("hw.length")
        }
        let body = Array(bytes[0..<(bytes.count - checksumLength)])
        let stored = Array(bytes[(bytes.count - checksumLength)...])
        guard constantTimeEqual(checksum(body), stored) else { throw SiegelError.corruptFile("hw.checksum") }
        guard Array(bytes[0..<8]) == magic else { throw SiegelError.corruptFile("hw.magic") }
        guard bytes.readLE16(at: 8) == version else { throw SiegelError.corruptFile("hw.version") }
        guard let kind = Kind(rawValue: bytes[10]) else { throw SiegelError.corruptFile("hw.kind") }
        guard kind == expectedKind else { throw SiegelError.corruptFile("hw.kind") }
        let id = UUID(hwBytes: Array(bytes[11..<27]))
        guard id == expectedKeyID else { throw SiegelError.corruptFile("hw.keyid") }
        let blobLength = Int(bytes.readLE16(at: 27))
        guard (1...maxBlobLength).contains(blobLength) else { throw SiegelError.corruptFile("hw.blob") }
        guard bytes.count == fixed + blobLength + pointLength + checksumLength else {
            throw SiegelError.corruptFile("hw.length")
        }
        let blob = Data(bytes[fixed..<(fixed + blobLength)])
        let point = Data(bytes[(fixed + blobLength)..<(fixed + blobLength + pointLength)])
        guard point.first == 0x04, (try? P256.KeyAgreement.PublicKey(x963Representation: point)) != nil else {
            throw SiegelError.corruptFile("hw.point")
        }
        return HardwareKeyFile(kind: kind, keyID: id, blob: blob, point: point)
    }

    static func checksum(_ body: [UInt8]) -> [UInt8] {
        var h = SHA3_256()
        h.update(data: checksumLabel)
        h.update(data: body)
        return Array(h.finalize())
    }

    // MARK: Dateisystem

    /// Schreibt atomar und ohne zu überschreiben: Temp-Datei (O_EXCL, 0600) + F_FULLFSYNC, `renamex_np`
    /// mit RENAME_EXCL, fsync auf den Ordner. Scheitert ein Schritt, bleibt nichts liegen.
    /// v4.3 (§23.1): Jede Schlüsseldatei ist vom Backup ausgenommen (`isExcludedFromBackup`, keine Time-Machine-
    /// Kopie). Das Attribut wird gesetzt, bevor Daten in der Datei stehen; scheitert es, bleibt nichts liegen.
    func write(to directory: URL) throws {
        let bytes = try encoded()
        try Self.ensureDirectory(directory)
        let target = Self.fileURL(keyID: keyID, directory: directory)
        let temp = directory.appendingPathComponent(".\(keyID.uuidString).\(UUID().uuidString).tmp", isDirectory: false)
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SiegelError.io("hw.write") }
        guard Self.excludeFromBackup(temp) else {
            close(fd)
            _ = unlink(temp.path)
            throw SiegelError.io("hw.write")
        }
        var ok = bytes.withUnsafeBytes { buf -> Bool in
            var offset = 0
            while offset < buf.count {
                guard let p = buf.baseAddress else { return false }
                let n = Darwin.write(fd, p + offset, buf.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                offset += n
            }
            return true
        }
        if ok, fcntl(fd, F_FULLFSYNC) != 0 { ok = fsync(fd) == 0 }
        if close(fd) != 0 { ok = false }
        guard ok, renamex_np(temp.path, target.path, UInt32(RENAME_EXCL)) == 0 else {
            _ = unlink(temp.path)
            throw SiegelError.io("hw.write")
        }
        Self.syncDirectory(directory)
    }

    /// Liest und prüft die Datei. Fehlt sie oder ist sie ungültig → `factorUnavailable(.secureEnclave)`.
    static func read(keyID: UUID, kind: Kind, directory: URL) throws -> HardwareKeyFile {
        let url = fileURL(keyID: keyID, directory: directory)
        guard let bytes = readSmallFile(url) else { throw SiegelError.factorUnavailable(.secureEnclave) }
        do {
            return try decode(bytes, expectedKeyID: keyID, expectedKind: kind)
        } catch {
            throw SiegelError.factorUnavailable(.secureEnclave)
        }
    }

    /// Entfernt die Schlüsseldatei. Fehlt sie schon, ist das kein Fehler.
    static func remove(keyID: UUID, directory: URL) throws {
        let url = fileURL(keyID: keyID, directory: directory)
        if unlink(url.path) != 0, errno != ENOENT { throw SiegelError.io("hw.remove") }
        syncDirectory(directory)
    }

    /// Vernichtet die Schlüsseldatei (§23.1, Krypto-Löschung): Inhalt an Ort und Stelle mit Zufallsbytes
    /// überschreiben, `F_FULLFSYNC` (sonst `fsync`), löschen, Ordner `fsync`. Fehlt die Datei, ist das kein Fehler.
    ///
    /// - Ein Symlink wird nie durchschritten (`O_NOFOLLOW`): nur der Link selbst wird gelöscht.
    /// - Nur reguläre Dateien werden überschrieben; die Länge bleibt gleich (kein Kürzen vor dem Überschreiben).
    /// - Lässt sich nur das Überschreiben nicht durchführen, wird trotzdem gelöscht (das Wichtigste ist, dass der
    ///   Name verschwindet); gemeldet wird nur ein Löschen, das scheitert → `io("hw.destroy")`.
    /// - Ehrlich (SICHERHEIT.md): Auf einer SSD und unter APFS (Kopie beim Schreiben, lokale Schnappschüsse) kann der
    ///   alte Inhalt physisch liegen bleiben. Er ist nur mit der Secure Enclave dieses Macs und dem Finger nutzbar.
    static func destroy(keyID: UUID, directory: URL) throws {
        let url = fileURL(keyID: keyID, directory: directory)
        let fd = open(url.path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd >= 0 {
            _ = overwriteWithRandom(fd)
            close(fd)
        }
        if unlink(url.path) != 0, errno != ENOENT { throw SiegelError.io("hw.destroy") }
        syncDirectory(directory)
    }

    /// Überschreibt eine reguläre Datei ganz mit Zufallsbytes (in Blöcken, ab Offset 0) und erzwingt das Schreiben
    /// auf den Datenträger. false = nicht regulär, nicht lesbar oder Schreiben gescheitert.
    static func overwriteWithRandom(_ fd: Int32) -> Bool {
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return false }
        let total = Int(st.st_size)
        var block = [UInt8](repeating: 0, count: 4096)
        var offset = 0
        var ok = true
        while offset < total, ok {
            let n = min(block.count, total - offset)
            ok = block.withUnsafeMutableBytes { buf -> Bool in
                guard let base = buf.baseAddress else { return false }
                arc4random_buf(base, n)
                var written = 0
                while written < n {
                    let w = pwrite(fd, base + written, n - written, off_t(offset + written))
                    if w < 0 {
                        if errno == EINTR { continue }
                        return false
                    }
                    if w == 0 { return false }
                    written += w
                }
                return true
            }
            offset += n
        }
        if fcntl(fd, F_FULLFSYNC) != 0, fsync(fd) != 0 { ok = false }
        return ok
    }

    /// `isExcludedFromBackup = true` (keine Time-Machine-Kopie, §23.1). false = Attribut nicht gesetzt.
    static func excludeFromBackup(_ url: URL) -> Bool {
        var u = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        do {
            try u.setResourceValues(values)
        } catch {
            return false
        }
        return (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup == true
    }

    /// Nur reguläre Dateien (kein Symlink), höchstens `maxFileLength` Byte.
    private static func readSmallFile(_ url: URL) -> [UInt8]? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG,
              st.st_size > 0, st.st_size <= off_t(maxFileLength) else { return nil }
        var out = [UInt8](repeating: 0, count: Int(st.st_size))
        var offset = 0
        let ok = out.withUnsafeMutableBytes { buf -> Bool in
            while offset < buf.count {
                guard let p = buf.baseAddress else { return false }
                let n = Darwin.read(fd, p + offset, buf.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                if n == 0 { return false }
                offset += n
            }
            return true
        }
        return ok ? out : nil
    }

    private static func ensureDirectory(_ directory: URL) throws {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDir) {
            guard isDir.boolValue else { throw SiegelError.io("hw.directory") }
            return
        }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            throw SiegelError.io("hw.directory")
        }
    }

    private static func syncDirectory(_ directory: URL) {
        let fd = open(directory.path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { return }
        _ = fsync(fd)
        close(fd)
    }
}

extension UUID {
    var hwBytes: [UInt8] {
        withUnsafeBytes(of: uuid) { Array($0) }
    }

    init(hwBytes bytes: [UInt8]) {
        var u: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &u) { dst in
            for i in 0..<min(16, bytes.count) { dst[i] = bytes[i] }
        }
        self.init(uuid: u)
    }
}
