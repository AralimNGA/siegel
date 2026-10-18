import AppKit
import Darwin

/// Nur eine laufende Instanz (SPEC §4): `flock(LOCK_EX|LOCK_NB)` auf `Application Support/Siegel/.lock`
/// für die ganze Laufzeit des Prozesses. Der Dateideskriptor bleibt bewusst offen; das System gibt die
/// Sperre beim Prozessende frei (auch nach einem Absturz).
@MainActor
public enum SingleInstance {
    public enum Result: Sendable, Equatable {
        case acquired
        case alreadyRunning
        case failed
    }

    private static var descriptor: Int32 = -1

    public static func acquire(directory: URL) -> Result {
        if descriptor >= 0 { return .acquired }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            return .failed
        }
        let path = directory.appendingPathComponent(".lock").path
        let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return .failed }
        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            let fehler = errno
            close(fd)
            return fehler == EWOULDBLOCK ? .alreadyRunning : .failed
        }
        descriptor = fd
        return .acquired
    }

    /// Bringt die bereits laufende Instanz nach vorne (falls auffindbar).
    public static func activateOtherInstance() {
        guard let id = Bundle.main.bundleIdentifier else { return }
        let eigene = ProcessInfo.processInfo.processIdentifier
        for app in NSRunningApplication.runningApplications(withBundleIdentifier: id)
        where app.processIdentifier != eigene {
            app.activate()
        }
    }
}
