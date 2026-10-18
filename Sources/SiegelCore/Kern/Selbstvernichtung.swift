import Darwin
import Foundation

// Selbstvernichtung (SPEC §23): öffentliche Typen der Schnittstelle (§23.3) und die austauschbare Schicht, die den
// Vernichtungs-SE-Schlüssel V vernichtet. Ablauf, Zustand und Kryptografie stehen in VaultStore+Vernichtung.swift,
// DestructionState.swift, UnlockedVault+Vernichtung.swift und EntrySealing.swift (vernichtbare Variante).

/// Was die Vernichtung ausgelöst hat.
public enum DestructionTrigger: String, Codable, Sendable {
    case deadman, failedAttempts, duressPassword
}

/// Einstellungen der Selbstvernichtung. Massgeblich ist der verschlüsselte Inhalt; eine Kopie liegt im Container
/// (`Hardware/zustand.json`) für die Prüfungen im gesperrten Zustand.
public struct DestructionSettings: Codable, Sendable, Equatable {
    /// Totmann-Schalter: Frist in Tagen seit dem letzten echten Entsperren; nil = aus; sonst 7…365.
    public var deadmanDays: Int?
    /// Fehlversuch-Zähler: falsche Entsperrversuche in Folge; nil = aus; sonst 10…100.
    public var maxFailedAttempts: Int?
    /// Vernichtungs-Passwort eingerichtet.
    public var duressEnabled: Bool

    public init(deadmanDays: Int? = nil, maxFailedAttempts: Int? = nil, duressEnabled: Bool = false) {
        self.deadmanDays = deadmanDays
        self.maxFailedAttempts = maxFailedAttempts
        self.duressEnabled = duressEnabled
    }

    /// Alles aus.
    public static let off = DestructionSettings()
    /// Erlaubte Frist des Totmann-Schalters (Tage).
    public static let deadmanDaysRange = 7...365
    /// Erlaubte Grenze des Fehlversuch-Zählers.
    public static let maxFailedAttemptsRange = 10...100

    /// Mindestens ein Auslöser ist eingeschaltet.
    public var anyTriggerEnabled: Bool { deadmanDays != nil || maxFailedAttempts != nil || duressEnabled }

    /// Bereiche prüfen (§23.2). Ausserhalb → `io("destruction.deadmanDays")` bzw. `io("destruction.maxFailedAttempts")`.
    func validate() throws {
        if let d = deadmanDays, !Self.deadmanDaysRange.contains(d) { throw SiegelError.io("destruction.deadmanDays") }
        if let n = maxFailedAttempts, !Self.maxFailedAttemptsRange.contains(n) {
            throw SiegelError.io("destruction.maxFailedAttempts")
        }
    }

    enum CodingKeys: String, CodingKey { case deadmanDays, maxFailedAttempts, duressEnabled }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        deadmanDays = try c.decodeIfPresent(Int.self, forKey: .deadmanDays)
        maxFailedAttempts = try c.decodeIfPresent(Int.self, forKey: .maxFailedAttempts)
        duressEnabled = try c.decode(Bool.self, forKey: .duressEnabled)
    }

    /// null explizit (wie der übrige Inhalt).
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        if let d = deadmanDays { try c.encode(d, forKey: .deadmanDays) } else { try c.encodeNil(forKey: .deadmanDays) }
        if let n = maxFailedAttempts {
            try c.encode(n, forKey: .maxFailedAttempts)
        } else {
            try c.encodeNil(forKey: .maxFailedAttempts)
        }
        try c.encode(duressEnabled, forKey: .duressEnabled)
    }
}

/// Zustand der Selbstvernichtung, auch im gesperrten Zustand lesbar (aus `Hardware/zustand.json`, nicht geheim).
/// `destroyed` aus §23.3 ist als zwei optionale Felder umgesetzt (`destroyedTrigger`, `destroyedAt`).
///
/// Wichtig für die Oberfläche: `destroyedTrigger`/`destroyedAt` gehören nur in die Meldung nach einem **echten**
/// Entsperren (dort besser `UnlockedVault.destructionStatus`, das in einer Vernichtungs-Sitzung nichts verrät).
/// Der Sperrbildschirm nutzt nur `deadline` und `failedAttempts`.
public struct DestructionStatus: Sendable, Equatable {
    public let settings: DestructionSettings
    public let lastGenuineUnlock: Date?
    public let failedAttempts: Int
    /// Ende der Totmann-Frist (letzte echte Entsperrung + Frist); nil, wenn der Totmann-Schalter aus ist.
    public let deadline: Date?
    public let destroyedTrigger: DestructionTrigger?
    public let destroyedAt: Date?
    /// Ist ein Vernichtungsschlüssel V eingerichtet (oder schon vernichtet)? Dann gibt es markierte Einträge bzw. gab
    /// es sie, und der Notfallweg lässt sie weg – auch ganz ohne Auslöser (v4.4, Befund ablaeufe-5). Auch gesperrt
    /// bekannt (`zustand.json` nennt V ohnehin), in einer Vernichtungs-Sitzung gleich wie in der echten.
    public let keyConfigured: Bool

    public init(settings: DestructionSettings, lastGenuineUnlock: Date?, failedAttempts: Int, deadline: Date?,
                destroyedTrigger: DestructionTrigger?, destroyedAt: Date?, keyConfigured: Bool = false) {
        self.settings = settings
        self.lastGenuineUnlock = lastGenuineUnlock
        self.failedAttempts = failedAttempts
        self.deadline = deadline
        self.destroyedTrigger = destroyedTrigger
        self.destroyedAt = destroyedAt
        self.keyConfigured = keyConfigured
    }

    /// Nichts eingerichtet, nichts vernichtet.
    public static let off = DestructionStatus(settings: .off, lastGenuineUnlock: nil, failedAttempts: 0, deadline: nil,
                                              destroyedTrigger: nil, destroyedAt: nil)

    /// Verbleibende Fehlversuche bis zur Vernichtung (nil, wenn der Zähler aus ist). Die Oberfläche warnt ab der
    /// Hälfte („Noch x Versuche bis zur Vernichtung“, §23.2).
    public var remainingAttempts: Int? {
        settings.maxFailedAttempts.map { max(0, $0 - failedAttempts) }
    }

    /// true, sobald die Hälfte der erlaubten Fehlversuche erreicht ist (§23.2).
    public var shouldWarnAboutAttempts: Bool {
        guard let n = settings.maxFailedAttempts else { return false }
        return failedAttempts * 2 >= n
    }

    /// true, wenn höchstens noch 25 % der Totmann-Frist bleiben (Hinweis „Frist endet am …“, §23.2).
    public func deadlineIsNear(now: Date) -> Bool {
        guard let deadline, let last = lastGenuineUnlock else { return false }
        let total = deadline.timeIntervalSince(last)
        guard total > 0 else { return false }
        return deadline.timeIntervalSince(now) <= total / 4
    }
}

/// Vernichtet den Vernichtungs-SE-Schlüssel V (§23.1): Blob-Datei mit Zufallsbytes überschreiben, `F_FULLFSYNC`,
/// löschen, Ordner `fsync`. Fehlt die Datei schon, ist das kein Fehler. Die echte Umsetzung liefert SiegelHardware
/// (`SecureEnclaveFactor.destroy(keyID:directory:)`); die Oberfläche setzt sie mit
/// `store.destructionKeyEraser = …`. Ohne das nimmt der Kern `FileDestructionKeyEraser` (gleiches Vorgehen, eigener
/// Code). Der Kern ruft nur `destroy` auf und braucht dafür keinen Schlüssel (geht im gesperrten Zustand).
public protocol DestructionKeyEraser: Sendable {
    func destroy(keyID: UUID, directory: URL) throws
}

/// Variante mit Closure (z. B. `ClosureDestructionKeyEraser { try SecureEnclaveFactor.destroy(keyID: $0, directory: $1) }`).
public struct ClosureDestructionKeyEraser: DestructionKeyEraser {
    private let body: @Sendable (UUID, URL) throws -> Void

    public init(_ body: @escaping @Sendable (UUID, URL) throws -> Void) {
        self.body = body
    }

    public func destroy(keyID: UUID, directory: URL) throws {
        try body(keyID, directory)
    }
}

/// Rückfall des Kerns: `<directory>/<keyID>.siegelhw` überschreiben (Zufallsbytes gleicher Länge, `F_FULLFSYNC`),
/// löschen, Ordner `fsync`. Gross-/Kleinschreibung des Namens egal. Fehler: `io("hw.destroy")`.
public struct FileDestructionKeyEraser: DestructionKeyEraser {
    public init() {}

    public func destroy(keyID: UUID, directory: URL) throws {
        let wanted = (keyID.uuidString + "." + VaultStore.hardwareKeyExtension).lowercased()
        var failed = false
        for f in FileIO.listFiles(directory) where f.lastPathComponent.lowercased() == wanted {
            if !Self.overwriteAndRemove(f) { failed = true }
        }
        try? FileIO.fsyncDirectory(directory)
        if failed { throw SiegelError.io("hw.destroy") }
    }

    /// true = Datei ist danach weg (vorher überschrieben, soweit möglich).
    static func overwriteAndRemove(_ url: URL) -> Bool {
        let fd = open(url.path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)
        if fd >= 0 {
            var st = stat()
            if fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size > 0 {
                let noise = randomBytes(Int(st.st_size))
                var done = 0
                noise.withUnsafeBytes { buf in
                    while done < buf.count, let p = buf.baseAddress {
                        let n = pwrite(fd, p + done, buf.count - done, off_t(done))
                        if n < 0 {
                            if errno == EINTR { continue }
                            break
                        }
                        done += n
                    }
                }
                if fcntl(fd, F_FULLFSYNC) != 0 { _ = fsync(fd) }
            }
            close(fd)
        }
        if unlink(url.path) == 0 { return true }
        return errno == ENOENT
    }
}
