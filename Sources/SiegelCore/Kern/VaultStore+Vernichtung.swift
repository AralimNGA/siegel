import Foundation

// Selbstvernichtung im Store (SPEC §23): Zustand im gesperrten Zustand, Totmann-Schalter, Fehlversuch-Zähler,
// Vernichten über die austauschbare Schicht, Entsperren mit Vernichtungs-Passwort (beide Argon2 parallel).
//
// Was wann geschrieben wird (alles im Hardware-Ordner, nie in der Tresordatei):
// - Echtes Entsperren: `zustand.json` (Fehlversuche 0, letzte echte Entsperrung, Einstellungen aus dem Inhalt) und
//   die Datei des Vernichtungs-Passworts frisch gekapselt (an DEK und Faktoren gebunden, v4.4). Steht nach einer
//   Vernichtungs-Sitzung `rekeyPending` an, zuerst DEK-Rotation mit Speichern (`VaultStore.unlock`).
// - Vernichtungs-Passwort: V überschreiben + löschen, dann `zustand.json` (Fehlversuche 0, `destroyed`,
//   `rekeyPending`); die letzte echte Entsperrung bleibt (Totmann-Schalter nicht verlängert). Die Tresordatei bleibt
//   unverändert.
// - Falsches Passwort (Zähler an): `zustand.json` (Fehlversuche + 1), bei N zusätzlich V vernichten.
// - Jedes Speichern mit eingerichteter Selbstvernichtung: Datei des Vernichtungs-Passworts neu (frische Kapselung
//   an den DEK) und `zustand.json`, falls sich Einstellungen geändert haben – in echter und Vernichtungs-Sitzung gleich.
// Ohne eingerichtete Selbstvernichtung entsteht keine dieser Dateien.

extension VaultStore {
    static let duressExtension = hardwareKeyExtension

    // MARK: - Öffentlich (§23.3)

    /// Zustand im gesperrten Zustand (aus `Hardware/zustand.json`, ohne Geheimnis). Fehlt die Datei oder gehört sie
    /// zu einem anderen Tresor: alles aus.
    public func destructionStatus() -> DestructionStatus {
        destructionLock.withLock { currentState()?.status ?? .off }
    }

    /// Darf die Oberfläche einen eben angelegten Vernichtungsschlüssel V nach einem gescheiterten
    /// `configureDestruction` wieder vernichten? Nur wenn sicher nichts ihn nennt: `zustand.json` nennt ihn weder als
    /// V noch als vernichtet, und die Tresordatei ist noch genau der Stand `generation` dieses Tresors (sonst könnte
    /// sie Einträge enthalten, die an V versiegelt sind). Im Zweifel false: Eine verwaiste V-Datei ist harmlos, ein
    /// fehlendes V mit Einträgen daran ist Datenverlust. Zusatz zu §23.3 (v4.4, Befund datei-1).
    public func destructionKeyIsUnused(_ keyID: UUID, vaultID: UUID, generation: UInt64) -> Bool {
        let named = destructionLock.withLock { () -> Bool in
            guard let st = DestructionState.read(in: hardwareDirectory) else {
                // Unlesbarer Zustand zählt als „nennt ihn vielleicht“.
                return FileIO.exists(DestructionState.url(in: hardwareDirectory))
            }
            return st.vKeyID == keyID || st.destroyed?.keyID == keyID
        }
        guard !named, let disk = try? observeDisk(), let file = disk.file else { return false }
        return file.header.uuid == vaultID && file.generation == generation
    }

    /// Totmann-Schalter (§23.2 Nr. 1): ist die Frist seit der letzten echten Entsperrung abgelaufen, wird V vernichtet
    /// (true = gerade vernichtet). Läuft die Uhr rückwärts (`now` mehr als einen Tag vor der letzten echten
    /// Entsperrung), wird nicht vernichtet und nichts geschrieben. Ist schon vernichtet, wird nur das Löschen von V
    /// wiederholt, falls die Datei noch da ist (false). Geht auch gesperrt, braucht keinen Schlüssel. Fehler beim
    /// Vermerken → `io("destruction.write")` (V ist dann trotzdem schon vernichtet).
    public func checkDeadman(now: Date) throws -> Bool {
        try destructionLock.withLock {
            guard var st = currentState() else { return false }
            if let d = st.destroyed {
                if hardwareKeyExists(d.keyID) { eraseDestructionKey(d.keyID) }
                return false
            }
            guard let days = st.settings.deadmanDays, let last = st.lastGenuineUnlock, st.vKeyID != nil else {
                return false
            }
            let now = Clock.canonical(now)
            // Unbrauchbare Uhr (±∞, NaN) wie eine rückwärts laufende: nichts (Fuzz-Befund vernichtung-3; sonst wäre V
            // bei +∞ gelöscht, der Vermerk aber nicht schreibbar).
            guard now.timeIntervalSince1970.isFinite else { return false }
            // Uhr rückwärts (§23.2). Äquivalent zur Frist-Prüfung darunter, solange die Frist mindestens einen Tag ist
            // (gelesen werden nur 7…365): steht als Regel hier, wirkt aber erst, wenn der Bereich je kleiner würde.
            // Wirksam gegen eine zurückgestellte Uhr ist `max(alt, jetzt)` in `recordGenuineUnlock` (Mutationsproben
            // zielen besser dorthin).
            if now < last.addingTimeInterval(-Self.clockTolerance) { return false }
            guard now >= last.addingTimeInterval(TimeInterval(days) * 86_400) else { return false }
            try destroyLocked(&st, trigger: .deadman, at: now)
            return true
        }
    }

    /// Toleranz der Uhr (§23.2: „jetzt < letztes Entsperren − 1 Tag“ gilt als rückwärts).
    static let clockTolerance: TimeInterval = 86_400

    // MARK: - Zustand lesen

    /// Zustand, sofern er zu dieser Tresordatei gehört (bei unlesbarem Kopf gilt er trotzdem). Unter `destructionLock`.
    /// Nennt er den Entsperr-SE-Schlüssel des Kopfes (als V, als vernichtet oder als Ablage), gilt er nicht: Das kommt
    /// im Betrieb nie vor (`configureDestruction` lehnt es ab), und Vernichten hiesse dann Aussperren (Fuzz-Befund
    /// vernichtung-1). Fehlt die Tresordatei oder ist ihr Kopf unlesbar, gilt dasselbe für die Entsperr-SE-Schlüssel
    /// der eigenen Sicherungen dieses Tresors (mit einer davon geht es weiter; Fuzz-Befund vernichtung-6).
    func currentState() -> DestructionState? {
        guard let st = DestructionState.read(in: hardwareDirectory) else { return nil }
        guard let header = currentHeader() else {
            return backupUnlockKeyIDs(vaultID: st.vaultID).contains(where: st.names) ? nil : st
        }
        if header.uuid != st.vaultID { return nil }
        if let se = header.factorFields.seKeyID, st.names(se) { return nil }
        return st
    }

    /// Entsperr-SE-Schlüssel aus den Köpfen der lokalen Sicherungen dieses Tresors und der beiseitegelegten
    /// beschädigten Tresordateien (nur Kopf, ohne Prüfsumme; Kennungen sind nicht geheim).
    func backupUnlockKeyIDs(vaultID: UUID) -> Set<UUID> {
        var out = Set<UUID>()
        for f in FileIO.listFiles(backupDirectory(for: vaultID)) + FileIO.listFiles(backupRoot)
        where f.pathExtension == BackupNaming.fileExtension {
            if let h = Self.readHeader(f), h.uuid == vaultID, let se = h.factorFields.seKeyID { out.insert(se) }
        }
        return out
    }

    func currentHeader() -> VaultHeader? {
        guard let prefix = try? FileIO.readPrefix(vaultURL, count: VaultHeader.maxSize) else { return nil }
        return try? VaultFile.parseHeaderOnly(prefix)
    }

    func hardwareKeyURL(_ id: UUID) -> URL {
        hardwareDirectory.appendingPathComponent(id.uuidString + "." + Self.hardwareKeyExtension, isDirectory: false)
    }

    /// Liegt `<id>.siegelhw` im Hardware-Ordner (Gross-/Kleinschreibung egal)?
    func hardwareKeyExists(_ id: UUID) -> Bool {
        let wanted = (id.uuidString + "." + Self.hardwareKeyExtension).lowercased()
        return FileIO.listFiles(hardwareDirectory).contains { $0.lastPathComponent.lowercased() == wanted }
    }

    // MARK: - Vernichten

    /// V vernichten und vermerken (nur unter `destructionLock`). Schon vernichtet oder kein V → nichts.
    func destroyLocked(_ st: inout DestructionState, trigger: DestructionTrigger, at: Date) throws {
        guard st.destroyed == nil, let v = st.vKeyID else { return }
        eraseDestructionKey(v)
        st.destroyed = DestructionState.Destroyed(keyID: v, trigger: trigger, at: Clock.canonical(at))
        try DestructionState.write(st, in: hardwareDirectory)
    }

    /// Über die austauschbare Schicht; liegt die Datei danach noch da (Schicht gescheitert oder untätig), selbst
    /// überschreiben und löschen. Fehler brechen nichts ab (die nächste Prüfung versucht es erneut).
    func eraseDestructionKey(_ id: UUID) {
        try? destructionKeyEraser.destroy(keyID: id, directory: hardwareDirectory)
        if hardwareKeyExists(id) { try? FileDestructionKeyEraser().destroy(keyID: id, directory: hardwareDirectory) }
    }

    // MARK: - Fehlversuche und Entsperrungen

    /// Ein falsches Passwort (nur `wrongPassword`, §23.2 Nr. 2). Zähler aus oder schon vernichtet → nichts.
    func recordFailedAttempt() {
        destructionLock.withLock {
            guard var st = currentState(), let n = st.settings.maxFailedAttempts, st.destroyed == nil else { return }
            st.failedAttempts = min(st.failedAttempts + 1, DestructionState.maxCounter)
            if st.failedAttempts >= n, st.vKeyID != nil {
                try? destroyLocked(&st, trigger: .failedAttempts, at: Clock.now())
                return
            }
            try? DestructionState.write(st, in: hardwareDirectory)
        }
    }

    /// Echtes Entsperren (oder Einsetzen einer Sicherung mit ihrem Master-Passwort): Zähler auf 0, letzte echte
    /// Entsperrung nachführen (nie rückwärts: läuft die Uhr rückwärts, bleibt der alte Wert – die Frist wird so
    /// weder verlängert noch später fälschlich überschritten), Einstellungen aus dem Inhalt, Datei des
    /// Vernichtungs-Passworts frisch kapseln (`binding` = F aus den Faktoren dieses Entsperrens). Immer neu statt nur
    /// bei Abweichung: So werden auch Ablagen aus v4.3 (noch nicht an die Faktoren gebunden) ersetzt.
    func recordGenuineUnlock(content: VaultContent, header: VaultHeader, dek: SecureBytes, binding: SecureBytes?) {
        destructionLock.withLock {
            let existing = DestructionState.read(in: hardwareDirectory)
            guard content.destruction != nil || existing != nil else { return }
            var st = existing.flatMap { $0.vaultID == header.uuid ? $0 : nil } ?? DestructionState(vaultID: header.uuid)
            apply(content, to: &st)
            st.failedAttempts = 0
            if content.destruction != nil {
                let now = Clock.now()
                st.lastGenuineUnlock = max(st.lastGenuineUnlock ?? now, now)
            }
            if let d = content.destruction?.duress, let binding {
                try? writeDuressFile(d, dek: dek, binding: binding, vaultID: header.vaultID)
            }
            removeStaleDuressFile(old: existing?.duressFileID, keep: st.duressFileID, content: content, header: header)
            store(st, previous: existing)
        }
    }

    /// Vernichtungs-Passwort erkannt (§23.2 Nr. 3): zuerst V vernichten (synchron), Zähler auf 0 wie bei einem
    /// echten Entsperren, die letzte echte Entsperrung bleibt. Die Sitzung arbeitet mit dem echten DEK: Das nächste
    /// echte Entsperren erneuert ihn (`rekeyPending`, v4.4).
    /// Gelesen wird wie bei allen Prüfungen im gesperrten Zustand über `currentState()`: Wird zustand.json zwischen
    /// Probe und Vermerk gegen einen Zustand getauscht, der den Entsperr-SE-Schlüssel nennt oder zu einem anderen
    /// Tresor gehört, gilt er nicht, und es wird nichts vermerkt und nichts gelöscht (Fuzz-Befund vernichtung-4).
    func recordDuressUnlock(at now: Date) {
        destructionLock.withLock {
            guard var st = currentState() else { return }
            st.failedAttempts = 0
            st.rekeyPending = true
            if let d = st.destroyed {
                if hardwareKeyExists(d.keyID) { eraseDestructionKey(d.keyID) }
                try? DestructionState.write(st, in: hardwareDirectory)
            } else if st.vKeyID != nil {
                try? destroyLocked(&st, trigger: .duressPassword, at: now)
            } else {
                try? DestructionState.write(st, in: hardwareDirectory)
            }
        }
    }

    /// Nach jedem erfolgreichen Schreiben (aus `persist`): Umschlag des Vernichtungs-Passworts an den DEK dieser Datei
    /// (gebunden an F), Kopie der Einstellungen nachführen, veraltete Dateien des Vernichtungs-Passworts entfernen.
    /// `newDEK`: die Datei trägt einen neuen DEK (Zugangswechsel) – eine ausstehende Rotation (`rekeyPending`) ist damit
    /// erledigt. Bestes Bemühen: Die Tresordatei ist schon geschrieben; das nächste echte Entsperren repariert.
    func syncDestructionAfterWrite(content: VaultContent, header: VaultHeader, dek: SecureBytes, binding: SecureBytes?,
                                   newDEK: Bool) {
        destructionLock.withLock {
            let existing = DestructionState.read(in: hardwareDirectory)
            guard content.destruction != nil || existing != nil else { return }
            var st = existing.flatMap { $0.vaultID == header.uuid ? $0 : nil } ?? DestructionState(vaultID: header.uuid)
            apply(content, to: &st)
            if newDEK { st.rekeyPending = false }
            if st.settings.anyTriggerEnabled, st.lastGenuineUnlock == nil { st.lastGenuineUnlock = Clock.now() }
            if let d = content.destruction?.duress, let binding {
                try? writeDuressFile(d, dek: dek, binding: binding, vaultID: header.vaultID)
            }
            removeStaleDuressFile(old: existing?.duressFileID, keep: st.duressFileID, content: content, header: header)
            store(st, previous: existing)
        }
    }

    /// Einstellungen, V und Ablage aus dem (massgeblichen) Inhalt; ein Vermerk gilt nur, solange der Inhalt genau
    /// dieses V nennt; ohne Zähler kein Zählerstand.
    private func apply(_ content: VaultContent, to st: inout DestructionState) {
        let cfg = content.destruction
        st.settings = cfg?.settings ?? .off
        st.vKeyID = cfg?.vKey?.keyID
        st.duressFileID = cfg?.duress?.fileID
        if let d = st.destroyed, d.keyID != st.vKeyID { st.destroyed = nil }
        if st.settings.maxFailedAttempts == nil { st.failedAttempts = 0 }
        if cfg == nil { st.lastGenuineUnlock = nil }
    }

    /// Schreiben, wenn sich etwas geändert hat; nichts mehr zu merken → Datei entfernen.
    private func store(_ st: DestructionState, previous: DestructionState?) {
        if st.isEmpty {
            if previous != nil || FileIO.exists(DestructionState.url(in: hardwareDirectory)) {
                DestructionState.remove(in: hardwareDirectory)
            }
            return
        }
        guard st != previous else { return }
        try? DestructionState.write(st, in: hardwareDirectory)
    }

    // MARK: - Datei des Vernichtungs-Passworts

    /// Ablage frisch kapseln. Ersetzt wird nur eine Datei mit der Form einer Ablage (auch eine beschädigte oder fremde
    /// heilt so); liegt unter diesem Namen eine andere Datei – ein SE-Schlüssel, V –, bleibt sie unberührt und es kommt
    /// `io("destruction.write")`. Tiefenverteidigung (Fuzz-Befund vernichtung-8): Der Inhalt prüft seine Kennungen
    /// paarweise, kennt aber nicht jede Datei im Hardware-Ordner (z. B. ein früheres V).
    func writeDuressFile(_ d: DestructionConfig.Duress, dek: SecureBytes, binding: SecureBytes,
                         vaultID: [UInt8]) throws {
        let url = hardwareKeyURL(d.fileID)
        if FileIO.exists(url) {
            guard let alt = try? FileIO.read(url, maxSize: DuressFile.fileLength), DuressFile.hasShape(alt) else {
                throw SiegelError.io("destruction.write")
            }
        }
        let file = try DuressCrypto.seal(dek: dek, duress: d, binding: binding, vaultID: vaultID)
        do {
            try FileIO.ensureDirectory(hardwareDirectory)
        } catch {
            throw SiegelError.io("destruction.write")
        }
        try DestructionState.writeAtomically(try file.encoded(), to: url, directory: hardwareDirectory)
    }

    func readDuressFile(_ id: UUID) -> DuressFile? {
        guard let bytes = try? FileIO.read(hardwareKeyURL(id), maxSize: DuressFile.fileLength) else { return nil }
        return try? DuressFile.decode(bytes, expectedID: id)
    }

    /// Ablage eines ersetzten oder entfernten Vernichtungs-Passworts löschen. `old` stammt aus `zustand.json` (nicht
    /// authentisiert): nie eine Datei, die der Tresor noch braucht – Entsperr-SE-Schlüssel, Eintrags-SE-Schlüssel, V
    /// (Fuzz-Befund vernichtung-2: sonst löschte ein echtes Entsperren still V oder den Eintrags-Schlüssel) – und nur
    /// eine Datei, die wirklich eine Ablage mit dieser Kennung ist (Fuzz-Befund vernichtung-7: der Notfallweg löschte
    /// sonst den Entsperr-SE-Schlüssel, den ältere Sicherungen noch brauchen; der neue Kopf kennt ihn nicht mehr).
    private func removeStaleDuressFile(old: UUID?, keep: UUID?, content: VaultContent, header: VaultHeader) {
        guard let old, old != keep else { return }
        let inUse = [header.factorFields.seKeyID, content.entryFactors.deviceKeyID,
                     content.destruction?.vKey?.keyID].compactMap { $0 }
        guard !inUse.contains(old), readDuressFile(old) != nil else { return }
        _ = FileDestructionKeyEraser.overwriteAndRemove(hardwareKeyURL(old))
        try? FileIO.fsyncDirectory(hardwareDirectory)
    }

    // MARK: - Entsperren mit Vernichtungs-Passwort

    /// Was das Entsperren über das Vernichtungs-Passwort wissen muss. `file` fehlt, wenn der Zustand es eingeschaltet
    /// nennt, die Datei aber fehlt oder beschädigt ist: dann läuft das zweite Argon2 mit einem Wegwerf-Salz (gleiche
    /// Dauer), erkennen kann es nichts.
    struct DuressProbe {
        let file: DuressFile?
        let salt: [UInt8]
    }

    /// Steht nach einer Vernichtungs-Sitzung die DEK-Rotation noch aus (v4.4)? Nur für diesen Tresor.
    func rekeyPending() -> Bool {
        destructionLock.withLock { currentState()?.rekeyPending ?? false }
    }

    /// nil = Vernichtungs-Passwort nicht eingeschaltet (dann nur ein Argon2 wie bisher).
    func duressProbe() -> DuressProbe? {
        destructionLock.withLock {
            guard let st = currentState(), st.settings.duressEnabled, let id = st.duressFileID else { return nil }
            let file = readDuressFile(id)
            return DuressProbe(file: file, salt: file?.salt ?? randomBytes(DuressCrypto.saltBytes))
        }
    }

    /// Argon2 für das Master-Passwort (über den Cache) und für das Vernichtungs-Passwort **gleichzeitig** (§23.2:
    /// gleiche Dauer). Scheitert einer (meist zu wenig Arbeitsspeicher für beide), einmal nacheinander.
    func bothArgon(header: VaultHeader, password: SecureBytes, cache: KEKCache, duressSalt: [UInt8],
                   duressCache: SecretCache) throws -> (p: SecureBytes, d: SecureBytes) {
        let limits = self.limits
        let kdf = header.kdf
        let cached = duressCache.value
        let (ra, rb) = ParallelKDF.run({ try cache.argon(header: header, password: password, limits: limits) },
                                       { try cached ?? DuressCrypto.derive(password: password, salt: duressSalt,
                                                                           kdf: kdf, limits: limits) })
        let p = try ra.get(or: { try cache.argon(header: header, password: password, limits: limits) })
        let d = try rb.get(or: { try DuressCrypto.derive(password: password, salt: duressSalt, kdf: kdf, limits: limits) })
        duressCache.value = d
        return (p, d)
    }
}

/// Merkt sich ein Geheimnis für die Dauer eines Aufrufs (z. B. d über den einmaligen Neu-Lese-Versuch).
final class SecretCache: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: SecureBytes?

    var value: SecureBytes? {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }
}

/// Zwei Argon2-Läufe gleichzeitig: `a` auf diesem Thread, `b` auf einem eigenen. Testschalter (TaskLocal) gelten
/// auch auf dem zweiten Thread.
enum ParallelKDF {
    private final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<SecureBytes, SiegelError> = .failure(.kdfFailed)
        func set(_ r: Result<SecureBytes, SiegelError>) { lock.withLock { result = r } }
        var value: Result<SecureBytes, SiegelError> { lock.withLock { result } }
    }

    static func run(_ a: () throws -> SecureBytes,
                    _ b: @escaping @Sendable () throws -> SecureBytes)
        -> (Result<SecureBytes, SiegelError>, Result<SecureBytes, SiegelError>) {
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        #if DEBUG
        let hooks = TestHooks.Snapshot.current()
        let job: @Sendable () -> Void = {
            hooks.apply { box.set(Self.capture(b)) }
            done.signal()
        }
        #else
        let job: @Sendable () -> Void = {
            box.set(Self.capture(b))
            done.signal()
        }
        #endif
        let thread = Thread(block: job)
        thread.qualityOfService = .userInitiated
        thread.start()
        let ra = capture(a)
        done.wait()
        return (ra, box.value)
    }

    private static func capture(_ body: () throws -> SecureBytes) -> Result<SecureBytes, SiegelError> {
        do {
            return .success(try body())
        } catch let e as SiegelError {
            return .failure(e)
        } catch {
            return .failure(.kdfFailed)
        }
    }
}

extension Result where Success == SecureBytes, Failure == SiegelError {
    /// Erfolg, sonst `retry()` (nur bei `kdfFailed`; andere Fehler wie zu grosse Parameter gelten sofort).
    func get(or retry: () throws -> SecureBytes) throws -> SecureBytes {
        switch self {
        case let .success(v): return v
        case .failure(.kdfFailed): return try retry()
        case let .failure(e): throw e
        }
    }
}
