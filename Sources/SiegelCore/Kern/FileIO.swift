import Darwin
import Foundation

/// POSIX-Dateioperationen für das sichere Speichern (SPEC §4). Fehler nur als feste Codes.
enum FileIO {
    struct Exists: Error {}

    /// Legt Ordner (rekursiv) mit 0700 an; ein bestehender Zielordner wird auf 0700 gesetzt.
    static func ensureDirectory(_ url: URL) throws {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) {
            guard isDir.boolValue else { throw SiegelError.io("dir.notDirectory") }
            _ = chmod(url.path, 0o700)
            return
        }
        let parent = url.deletingLastPathComponent()
        if parent.path != url.path, !FileManager.default.fileExists(atPath: parent.path) {
            try ensureDirectory(parent)
        }
        if mkdir(url.path, 0o700) != 0, errno != EEXIST { throw SiegelError.io("dir.create") }
        _ = chmod(url.path, 0o700)
    }

    static func exists(_ url: URL) -> Bool {
        var st = stat()
        return lstat(url.path, &st) == 0
    }

    /// Liest eine ganze Datei (höchstens `maxSize` Byte, sonst `corruptFile("file.length")`).
    static func read(_ url: URL, maxSize: Int) throws -> [UInt8] {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else {
            if errno == ENOENT { throw SiegelError.vaultMissing }
            throw SiegelError.io("file.read")
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw SiegelError.io("file.read") }
        guard (st.st_mode & S_IFMT) == S_IFREG else { throw SiegelError.io("file.read") }
        let size = Int(st.st_size)
        guard size <= maxSize else { throw SiegelError.corruptFile("file.length") }
        var out = [UInt8](repeating: 0, count: size)
        var done = 0
        try out.withUnsafeMutableBytes { buf in
            while done < size {
                guard let p = buf.baseAddress else { throw SiegelError.io("file.read") }
                let n = Darwin.read(fd, p + done, size - done)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw SiegelError.io("file.read")
                }
                if n == 0 { break }
                done += n
            }
        }
        // Datei während des Lesens gekürzt/verlängert → so viel wie gelesen
        if done != size { out.removeLast(size - done) }
        var extra: UInt8 = 0
        if Darwin.read(fd, &extra, 1) > 0 { throw SiegelError.io("file.changedWhileReading") }
        return out
    }

    /// Liest höchstens `count` Byte vom Dateianfang (Kopf).
    static func readPrefix(_ url: URL, count: Int) throws -> [UInt8] {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else {
            if errno == ENOENT { throw SiegelError.vaultMissing }
            throw SiegelError.io("file.read")
        }
        defer { close(fd) }
        var out = [UInt8](repeating: 0, count: count)
        var done = 0
        try out.withUnsafeMutableBytes { buf in
            while done < count {
                guard let p = buf.baseAddress else { throw SiegelError.io("file.read") }
                let n = Darwin.read(fd, p + done, count - done)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw SiegelError.io("file.read")
                }
                if n == 0 { break }
                done += n
            }
        }
        if done != count { out.removeLast(count - done) }
        return out
    }

    /// Schreibt eine neue Datei exklusiv (O_CREAT|O_EXCL, 0600) und synchronisiert per F_FULLFSYNC.
    static func writeExclusive(_ url: URL, bytes: UnsafeRawBufferPointer) throws {
        let fd = open(url.path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            if errno == EEXIST { throw Exists() }
            throw SiegelError.io("file.create")
        }
        var ok = false
        defer {
            close(fd)
            if !ok { unlink(url.path) }
        }
        var done = 0
        while done < bytes.count {
            guard let p = bytes.baseAddress else { throw SiegelError.io("file.write") }
            let n = Darwin.write(fd, p + done, bytes.count - done)
            if n < 0 {
                if errno == EINTR { continue }
                throw SiegelError.io("file.write")
            }
            done += n
        }
        if fcntl(fd, F_FULLFSYNC) != 0 {
            guard fsync(fd) == 0 else { throw SiegelError.io("file.sync") }
        }
        ok = true
    }

    static func writeExclusive(_ url: URL, bytes: [UInt8]) throws {
        try bytes.withUnsafeBytes { try writeExclusive(url, bytes: $0) }
    }

    /// Schreibt genau diese Datei (anlegen oder kürzen, 0600) ohne Nachbardatei und synchronisiert per
    /// F_FULLFSYNC. Für vom Benutzer gewählte Ziele, deren Ordner die Sandbox nicht freigibt. Nicht atomar:
    /// Der Aufrufer liest zurück und vergleicht.
    static func writeInPlace(_ url: URL, bytes: [UInt8]) throws {
        let fd = open(url.path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw SiegelError.io("export.write") }
        defer { close(fd) }
        var done = 0
        try bytes.withUnsafeBytes { buf in
            while done < buf.count {
                guard let p = buf.baseAddress else { throw SiegelError.io("export.write") }
                let n = Darwin.write(fd, p + done, buf.count - done)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw SiegelError.io("export.write")
                }
                done += n
            }
        }
        if fcntl(fd, F_FULLFSYNC) != 0 {
            guard fsync(fd) == 0 else { throw SiegelError.io("export.write") }
        }
    }

    /// APFS-Klon; scheitert bei vorhandenem Ziel (`Exists`), nie überschreiben. Ohne Klon-Unterstützung Kopie.
    static func clone(_ src: URL, to dst: URL) throws {
        if clonefile(src.path, dst.path, UInt32(CLONE_NOFOLLOW)) == 0 { return }
        let err = errno
        if err == EEXIST { throw Exists() }
        guard err == ENOTSUP || err == EXDEV else { throw SiegelError.io("backup.clone") }
        let bytes = try read(src, maxSize: FileFormat.maxFileBytes)
        try writeExclusive(dst, bytes: bytes)
    }

    /// rename(2) (ersetzt das Ziel atomar).
    static func rename(_ src: URL, to dst: URL) throws {
        guard Darwin.rename(src.path, dst.path) == 0 else { throw SiegelError.io("file.rename") }
    }

    /// Umbenennen ohne Überschreiben (`RENAME_EXCL`). Dateisysteme ohne `RENAME_EXCL` (exFAT/FAT auf
    /// USB-Sticks, SMB): vorher prüfen, dann rename(2).
    static func renameExclusive(_ src: URL, to dst: URL) throws {
        if renamex_np(src.path, dst.path, UInt32(RENAME_EXCL)) == 0 { return }
        let err = errno
        if err == EEXIST { throw Exists() }
        guard err == ENOTSUP || err == EINVAL else { throw SiegelError.io("file.rename") }
        if exists(dst) { throw Exists() }
        try rename(src, to: dst)
    }

    static func fsyncDirectory(_ url: URL) throws {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw SiegelError.io("dir.sync") }
        defer { close(fd) }
        if fcntl(fd, F_FULLFSYNC) != 0 {
            guard fsync(fd) == 0 else { throw SiegelError.io("dir.sync") }
        }
    }

    /// Freier Platz in Byte (statfs).
    static func freeSpace(_ url: URL) -> UInt64? {
        #if DEBUG
        if let o = TestHooks.freeSpaceOverride { return o }
        #endif
        var st = statfs()
        guard statfs(url.path, &st) == 0 else { return nil }
        return UInt64(st.f_bavail) * UInt64(st.f_bsize)
    }

    static func remove(_ url: URL) {
        _ = unlink(url.path)
    }

    /// Entfernt eine Datei; true, wenn sie danach nicht mehr da ist (fehlte sie schon, zählt das als Erfolg).
    @discardableResult
    static func removeChecked(_ url: URL) -> Bool {
        if unlink(url.path) == 0 { return true }
        return errno == ENOENT
    }

    /// Dateien (keine Ordner) eines Ordners, ohne Symlinks zu folgen. Fehlt der Ordner oder ist er nicht
    /// lesbar, leer.
    static func listFiles(_ dir: URL) -> [URL] {
        (try? listFilesChecked(dir)) ?? []
    }

    /// Wie `listFiles`, wirft aber, wenn der Ordner nicht gelesen werden kann (z. B. Stick ausgesteckt).
    static func listFilesChecked(_ dir: URL) throws -> [URL] {
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        } catch {
            throw SiegelError.io("dir.read")
        }
        return names.sorted().compactMap { name in
            let u = dir.appendingPathComponent(name, isDirectory: false)
            var st = stat()
            guard lstat(u.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
            return u
        }
    }

    /// Alter einer Datei in Sekunden (Änderungszeit); nil, wenn nicht lesbar.
    static func age(_ url: URL, now: Date) -> TimeInterval? {
        var st = stat()
        guard lstat(url.path, &st) == 0 else { return nil }
        let mtime = Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9
        return now.timeIntervalSince1970 - mtime
    }

    static func listDirectories(_ dir: URL) -> [URL] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else { return [] }
        return names.sorted().compactMap { name in
            let u = dir.appendingPathComponent(name, isDirectory: true)
            var st = stat()
            guard lstat(u.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return nil }
            return u
        }
    }

    static func setExcludedFromBackup(_ url: URL) throws {
        var u = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        do {
            try u.setResourceValues(values)
        } catch {
            throw SiegelError.io("export.excludeFromBackup")
        }
    }
}
