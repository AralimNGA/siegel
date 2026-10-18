import Foundation

// Notfallweg (SPEC §1.3, §1.5, §4, §15): Code bzw. zwei Teile prüfen (mit Fehlerkorrektur), wiederherstellen,
// auch aus Sicherungen, wenn die Tresordatei beschädigt ist. Jede Wiederherstellung setzt Stufe 1 (§16.1).

extension VaultStore {
    // MARK: - Eingabe-Hilfen für die Oberfläche

    /// Hat die Eingabe die volle Form eines Notfallcodes (55 Zeichen aus dem Alphabet, höchstens 4 "?")? Meldet der
    /// Kern danach `invalidRecoveryCodeFormat`, liegt es nur an den Füllbits (letztes Zeichen ist immer 0, 8, G
    /// oder R) bzw. an zu vielen Fehlern – nicht an der Länge (Befund #42).
    public static func recoveryCodeInputIsComplete(_ input: String) -> Bool {
        (try? RecoveryCodeCodec.parseSymbols(input, allowUnknown: true)) != nil
    }

    /// Wie `recoveryCodeInputIsComplete`, für einen Teil (56 Zeichen).
    public static func recoveryShareInputIsComplete(_ input: String) -> Bool {
        (try? RecoveryCodeCodec.parseSymbols(input, allowUnknown: true, count: Shamir.symbolCount)) != nil
    }

    /// Nummer des Teils (1…3), wenn die Eingabe ein exakt gültiger Teil ist (Prüfsumme stimmt); sonst nil.
    /// Damit kann die Oberfläche „Teil 2 erkannt“ zeigen und zweimal denselben Teil abfangen.
    public static func recoveryShareIndex(_ input: String) -> Int? {
        Shamir.index(of: input)
    }

    // MARK: - Notfallcode prüfen

    /// Prüft einen eingegebenen Code gegen den Kopf (inkl. Fehlerkorrektur). Für einen Treffer liest er nur den
    /// Kopf; ohne Treffer prüft er die Datei-Prüfsumme, bevor er `wrongRecoveryCode` bzw. `recoveryCodeChecksum`
    /// meldet (Befund #22: sonst nennt die Meldung bei Bitfäule im Kopf eine erfundene Kit-Kennung).
    public func checkRecoveryCode(_ input: String) throws -> RecoveryCodeMatch {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let symbols = try RecoveryCodeCodec.parseSymbols(input, allowUnknown: true)
        let header = try readCurrentHeader()
        return try withChecksumOnMiss { try Self.matchRecoveryCode(symbols: symbols, header: header) }
    }

    /// Zwei Teile (Shamir 2 aus 3) gegen den Kopf prüfen, mit Korrektur pro Teil („?“, 1–2 Fehler, vertauschte
    /// Nachbarn): erst Teil-Prüfsumme, dann zusammen mit dem anderen Teil der pk-Vergleich. Genau 2 Eingaben.
    /// Ergebnis in derselben Reihenfolge wie die Eingaben. Fehler wie bei `checkRecoveryCode`; zweimal derselbe
    /// Teil → `invalidRecoveryCodeFormat`.
    public func checkRecoveryShares(_ inputs: [String]) throws -> [RecoveryCodeMatch] {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let symbols = try Self.parseShareInputs(inputs)
        let header = try readCurrentHeader()
        return try withChecksumOnMiss { try Self.matchRecoveryShares(symbols, header: header) }
    }

    private func readCurrentHeader() throws -> VaultHeader {
        let prefix = try FileIO.readPrefix(vaultURL, count: VaultHeader.maxSize)
        return try VaultFile.parseHeaderOnly(prefix)
    }

    /// Kein Treffer (falsches Kit oder Prüfsumme): erst Bitfäule der ganzen Datei ausschliessen (`corruptFile`).
    private func withChecksumOnMiss<T>(_ url: URL? = nil, _ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch let e as SiegelError {
            switch e {
            case .wrongRecoveryCode, .recoveryCodeChecksum:
                let all = try FileIO.read(url ?? vaultURL, maxSize: FileFormat.maxFileBytes)
                try VaultFile.verifyChecksum(all)
                throw e
            default:
                throw e
            }
        }
    }

    // MARK: - Notfallweg für eine bestimmte Datei (v4.4, Befund datei-3)

    /// Wie `checkRecoveryCode`, gegen den Kopf einer bestimmten Datei (vom Nutzer gewählte Sicherung, z. B. vom
    /// USB-Stick auf einem neuen Mac). Fehlt die Datei → `io("backup.missing")`. Zusatz zu §8/§22.
    public func checkRecoveryCode(_ input: String, againstFile url: URL) throws -> RecoveryCodeMatch {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let symbols = try RecoveryCodeCodec.parseSymbols(input, allowUnknown: true)
        let header = try Self.readBackupHeader(url)
        return try Self.mappingMissing {
            try withChecksumOnMiss(url) { try Self.matchRecoveryCode(symbols: symbols, header: header) }
        }
    }

    /// Wie `checkRecoveryShares`, gegen den Kopf einer bestimmten Datei. Zusatz zu §8/§22.
    public func checkRecoveryShares(_ inputs: [String], againstFile url: URL) throws -> [RecoveryCodeMatch] {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let symbols = try Self.parseShareInputs(inputs)
        let header = try Self.readBackupHeader(url)
        return try Self.mappingMissing {
            try withChecksumOnMiss(url) { try Self.matchRecoveryShares(symbols, header: header) }
        }
    }

    /// Notfallweg für genau diese Datei: öffnet sie mit dem Notfallcode (gemessen an ihrem eigenen Kopf), egal zu
    /// welchem Tresor sie gehört, und setzt sie mit neuem Master-Passwort, neuem DEK, neuem Salz und Stufe 1 als
    /// Tresor ein (§16.1). Eine bisherige Tresordatei (etwa ein eben angelegter leerer Tresor) bleibt als angeheftete
    /// Sicherung „vor-notfall“ erhalten. Gedacht für den Fall, dass die Faktoren der Datei fehlen: neuer Mac
    /// (Touch-ID-Schlüssel gilt nur auf dem alten), Sicherungen nach dem Abstufen, Karte oder Schlüssel verloren.
    /// Anders als der automatische Weg (`recoverFromNewestReadableBackup`, nur dasselbe Kit) wählt hier der Nutzer
    /// die Datei ausdrücklich. Fehlt die Datei → `io("backup.missing")`; passt der Code nicht → `wrongRecoveryCode`.
    /// Zusatz zu §8/§22 (v4.4).
    public func recoverBackup(from url: URL, code: String, newMasterPassword: String,
                              kdf: KDFParameters = .standard) throws -> UnlockedVault {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try checkNewPassword(newMasterPassword, kdf: kdf)
        let r = try RecoveryCodeCodec.decode(code)
        return try recoverBackup(from: url, r: r, newMasterPassword: newMasterPassword, kdf: kdf)
    }

    /// Wie `recoverBackup(from:code:…)`, mit zwei der drei Teile. Zusatz zu §22 (v4.4).
    public func recoverBackup(from url: URL, shares: [String], newMasterPassword: String,
                              kdf: KDFParameters = .standard) throws -> UnlockedVault {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try checkNewPassword(newMasterPassword, kdf: kdf)
        let r = try Self.combineShares(shares)
        return try recoverBackup(from: url, r: r, newMasterPassword: newMasterPassword, kdf: kdf)
    }

    private func recoverBackup(from url: URL, r: SecureBytes, newMasterPassword: String,
                               kdf: KDFParameters) throws -> UnlockedVault {
        let bytes = try Self.mappingMissing { try FileIO.read(url, maxSize: FileFormat.maxFileBytes) }
        let file = try VaultFile.parse(bytes)
        guard RecoveryKEM.matches(r: r, vaultID: file.header.vaultID, expected: file.header.pk) else {
            let codeKit = try RecoveryKEM.derivePublicKeys(r: r, vaultID: file.header.vaultID).kitID
            throw SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: file.header.pk.kitID)
        }
        let opened = try Self.unsealed(try VaultCrypto.openWithRecovery(file, r: r), r: r)
        let pw = try PasswordNormalizer.secureBytes(newMasterPassword)
        guard try !MasterTag.isUsedByEntries(pw, entries: opened.content.entries) else {
            throw SiegelError.masterPasswordReused
        }
        return try install(opened, password: pw, factors: FactorSecrets(), kdf: kdf, confirmRecovery: true,
                           recoveryReset: true, reason: .recovery)
    }

    /// Kopf einer gewählten Datei (ohne Prüfsumme; die Prüfung folgt bei einem Fehlschlag bzw. beim Öffnen).
    private static func readBackupHeader(_ url: URL) throws -> VaultHeader {
        try mappingMissing { try VaultFile.parseHeaderOnly(try FileIO.readPrefix(url, count: VaultHeader.maxSize)) }
    }

    /// Eine fehlende Sicherungsdatei ist kein fehlender Tresor (`vaultMissing` führte die Oberfläche zu „Tresor fehlt“).
    private static func mappingMissing<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch SiegelError.vaultMissing {
            throw SiegelError.io("backup.missing")
        }
    }

    static func matchRecoveryCode(symbols input: [UInt8], header: VaultHeader) throws -> RecoveryCodeMatch {
        var symbols = input
        defer { for i in symbols.indices { symbols[i] = 0 } }
        let vaultID = header.vaultID
        let pk = header.pk
        let hasUnknown = symbols.contains(RecoveryCodeCodec.unknownSymbol)
        var paddingOK = false
        var checksumOK = false
        var exactR: SecureBytes?
        if !hasUnknown {
            let packed = try SecureBytes.scratch(count: RecoveryCodeCodec.packedBytes)
            packed.withUnsafeMutableBytes { out in
                symbols.withUnsafeBytes { RecoveryCodeCodec.pack($0, into: out) }
                let v = RecoveryCodeCodec.packedIsValid(UnsafeRawBufferPointer(out))
                paddingOK = v.paddingOK
                checksumOK = v.checksumOK
            }
            if paddingOK, checksumOK {
                let r = try packed.slice(0..<RecoveryKEM.rBytes)
                if RecoveryKEM.matches(r: r, vaultID: vaultID, expected: pk) { return .exact }
                exactR = r
            }
        }
        let hit = RecoveryCodeCorrection.search(symbols) { r in
            guard let rb = try? SecureBytes(copying: r) else { return false }
            return RecoveryKEM.matches(r: rb, vaultID: vaultID, expected: pk)
        }
        if let hit {
            return .corrected(formatted: RecoveryCodeCodec.formatSymbols(hit.symbols, groupSize: RecoveryCodeCodec.groupSize),
                              changedPositions: hit.changed.sorted())
        }
        if hasUnknown { throw SiegelError.recoveryCodeChecksum }
        guard paddingOK else { throw SiegelError.invalidRecoveryCodeFormat }
        guard checksumOK, let r = exactR else { throw SiegelError.recoveryCodeChecksum }
        let codeKit = try RecoveryKEM.derivePublicKeys(r: r, vaultID: vaultID).kitID
        throw SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: pk.kitID)
    }

    static func parseShareInputs(_ inputs: [String]) throws -> [[UInt8]] {
        guard inputs.count == 2 else { throw SiegelError.invalidRecoveryCodeFormat }
        return try inputs.map { try RecoveryCodeCodec.parseSymbols($0, allowUnknown: true, count: Shamir.symbolCount) }
    }

    static func matchRecoveryShares(_ inputs: [[UInt8]], header: VaultHeader) throws -> [RecoveryCodeMatch] {
        let vaultID = header.vaultID
        let pk = header.pk
        if let (a, b) = Shamir.searchPair(inputs[0], inputs[1], isMatch: {
            RecoveryKEM.matches(r: $0, vaultID: vaultID, expected: pk)
        }) {
            return [shareMatch(a), shareMatch(b)]
        }
        // Kein Treffer: möglichst genauer Grund.
        if inputs.contains(where: { $0.contains(RecoveryCodeCodec.unknownSymbol) }) {
            throw SiegelError.recoveryCodeChecksum
        }
        let exactA = Shamir.candidates(inputs[0], tier: 0)
        let exactB = Shamir.candidates(inputs[1], tier: 0)
        guard let a = exactA.first, let b = exactB.first else { throw SiegelError.recoveryCodeChecksum }
        guard a.x != b.x else { throw SiegelError.invalidRecoveryCodeFormat }
        let r = try Shamir.combine(x1: a.x, y1: try a.y(), x2: b.x, y2: try b.y())
        let codeKit = try RecoveryKEM.derivePublicKeys(r: r, vaultID: vaultID).kitID
        throw SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: pk.kitID)
    }

    private static func shareMatch(_ c: Shamir.Candidate) -> RecoveryCodeMatch {
        guard !c.changed.isEmpty else { return .exact }
        return .corrected(formatted: RecoveryCodeCodec.formatSymbols(c.symbols, groupSize: Shamir.groupSize),
                          changedPositions: c.changed.sorted())
    }

    /// Zwei exakte Teile → R. Gleiche Nummer oder nicht genau zwei → `invalidRecoveryCodeFormat`.
    static func combineShares(_ shares: [String]) throws -> SecureBytes {
        guard shares.count == 2 else { throw SiegelError.invalidRecoveryCodeFormat }
        let a = try Shamir.decode(shares[0])
        let b = try Shamir.decode(shares[1])
        guard a.x != b.x else { throw SiegelError.invalidRecoveryCodeFormat }
        return try Shamir.combine(x1: a.x, y1: a.y, x2: b.x, y2: b.y)
    }

    // MARK: - Wiederherstellen

    /// Wiederherstellung über den Notfallcode: neuer DEK, neues Master-Passwort, Stufe 1 (keine Faktoren),
    /// angeheftete Sicherung „vor-notfall“. Versiegelte Einträge werden über ihre Notfall-Umschläge entsiegelt und
    /// stehen danach auf Schutz 1 (§16.1).
    public func recover(code: String, newMasterPassword: String, kdf: KDFParameters = .standard) throws -> UnlockedVault {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try checkNewPassword(newMasterPassword, kdf: kdf)
        let r = try RecoveryCodeCodec.decode(code)
        return try recover(r: r, newMasterPassword: newMasterPassword, kdf: kdf)
    }

    /// Wiederherstellung mit zwei der drei Teile (Stufen 4/5). Sonst wie `recover(code:…)`.
    public func recover(shares: [String], newMasterPassword: String,
                        kdf: KDFParameters = .standard) throws -> UnlockedVault {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try checkNewPassword(newMasterPassword, kdf: kdf)
        let r = try Self.combineShares(shares)
        return try recover(r: r, newMasterPassword: newMasterPassword, kdf: kdf)
    }

    private func checkNewPassword(_ password: String, kdf: KDFParameters) throws {
        let policy = MasterPasswordPolicy.check(PasswordNormalizer.normalize(password))
        guard policy.ok else { throw SiegelError.passwordTooWeak(bits: policy.bits) }
        try limits.validate(kdf)
    }

    private func recover(r: SecureBytes, newMasterPassword: String, kdf: KDFParameters) throws -> UnlockedVault {
        let bytes = try FileIO.read(vaultURL, maxSize: FileFormat.maxFileBytes)
        let file = try VaultFile.parse(bytes)
        let opened = try Self.unsealed(try VaultCrypto.openWithRecovery(file, r: r), r: r)
        let pw = try PasswordNormalizer.secureBytes(newMasterPassword)
        guard try !MasterTag.isUsedByEntries(pw, entries: opened.content.entries) else {
            throw SiegelError.masterPasswordReused
        }
        var content = opened.content
        if content.recoveryConfirmedAt == nil { content.recoveryConfirmedAt = Clock.now() }
        try content.resetAfterRecovery()
        let (header, slots, dek) = try rekey(vaultID: file.header.vaultID, kdf: kdf, fields: .none,
                                             scheme: file.header.recoveryScheme, pk: file.header.pk, password: pw,
                                             factors: FactorSecrets())
        let result = try persist(header: header, slots: slots, dek: dek, content: content,
                                 baseGeneration: file.generation,
                                 expectation: .generation(file.header.uuid, file.generation),
                                 reason: BackupNaming.Reason.recovery.rawValue, newDEK: true)
        return try UnlockedVault(store: self, header: header, slots: slots, dek: dek, content: result.content,
                                 generation: result.generation, password: pw)
    }

    /// Alles entsiegeln, bevor die Wiederherstellung Stufe und Schutz zurücksetzt (§16.1).
    static func unsealed(_ opened: OpenedVault, r: SecureBytes) throws -> OpenedVault {
        var content = opened.content
        try content.unsealAll(r: r, header: opened.file.header)
        return OpenedVault(file: opened.file, dek: opened.dek, content: content, migrationKEK: opened.migrationKEK)
    }

    // MARK: - Notfallweg, wenn die Tresordatei beschädigt ist

    /// Sicherungen, die der Notfallweg verwenden darf (neueste zuerst). Grundsatz: nur Sicherungen mit derselben
    /// vaultID **und demselben Kit** wie die aktuelle Datei – ein bewusst ersetztes, älteres Kit öffnet so nie
    /// wieder einen Stand (SPEC §1.3). Ist die Datei beschädigt, gilt ihr Kopf nur, wenn ihn eine Sicherung
    /// bestätigt (gleiche vaultID und Kit-Kennung: ein zufällig gekipptes Bit erzeugt nie genau ein anderes
    /// gültiges Kit). Sonst stufenweise: gleiche vaultID, und erst wenn auch die unlesbar ist, alle. Entscheidend
    /// für das Öffnen bleibt immer der eigene Kopf jeder Sicherung.
    private func recoveryBackupCandidates() -> [BackupInfo] {
        let all = backups().filter { $0.vaultID != nil }
        var current: VaultHeader?
        var intact = false
        if let bytes = try? FileIO.read(vaultURL, maxSize: FileFormat.maxFileBytes),
           let file = try? VaultFile.parse(bytes) {
            current = file.header
            intact = true
        } else if let prefix = try? FileIO.readPrefix(vaultURL, count: VaultHeader.maxSize) {
            current = try? VaultFile.parseHeaderOnly(prefix)
        }
        guard let current else { return all }
        let sameKit = all.filter { b in
            guard b.vaultID == current.uuid, let h = Self.readHeader(b.url) else { return false }
            return h.pk.kitID == current.pk.kitID
        }
        if intact || !sameKit.isEmpty { return sameKit }
        let sameVault = all.filter { $0.vaultID == current.uuid }
        return sameVault.isEmpty ? all : sameVault
    }

    static func readHeader(_ url: URL) -> VaultHeader? {
        guard let bytes = try? FileIO.readPrefix(url, count: VaultHeader.maxSize) else { return nil }
        return try? VaultFile.parseHeaderOnly(bytes)
    }

    /// Gleiche Auswahl wie `recoverFromNewestReadableBackup`; pro (vaultID, Kit) nur einmal. Kein Treffer →
    /// derselbe Fehler wie die Prüfung gegen die Datei (bzw. `corruptFile("backup.noneReadable")`).
    private func matchAgainstBackups<T>(_ match: (VaultHeader) throws -> T) throws -> T {
        var seen = Set<String>()
        var lastError: SiegelError?
        for backup in recoveryBackupCandidates() {
            guard let header = Self.readHeader(backup.url) else { continue }
            let key = header.uuid.uuidString + header.pk.kitID
            guard seen.insert(key).inserted else { continue }
            do {
                return try match(header)
            } catch let error as SiegelError {
                lastError = error
            }
        }
        throw lastError ?? SiegelError.corruptFile("backup.noneReadable")
    }

    /// Prüft einen Code gegen die Sicherungen (inkl. Korrektur), für den Notfallweg bei beschädigter
    /// Tresordatei. Zusatz zur Schnittstelle in §8 (SPEC v3.1).
    public func checkRecoveryCodeAgainstBackups(_ input: String) throws -> RecoveryCodeMatch {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let symbols = try RecoveryCodeCodec.parseSymbols(input, allowUnknown: true)
        return try matchAgainstBackups { try Self.matchRecoveryCode(symbols: symbols, header: $0) }
    }

    /// Wie `checkRecoveryCodeAgainstBackups`, für zwei Teile. Zusatz zu §22 (Notfallweg der Stufen 4/5).
    public func checkRecoverySharesAgainstBackups(_ inputs: [String]) throws -> [RecoveryCodeMatch] {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let symbols = try Self.parseShareInputs(inputs)
        return try matchAgainstBackups { try Self.matchRecoveryShares(symbols, header: $0) }
    }

    /// Notfallweg bei beschädigter Tresordatei: öffnet die neueste lesbare Sicherung, die dieser Code öffnet
    /// (gemessen am eigenen Kopf der Sicherung), und setzt sie mit neuem Master-Passwort, neuem DEK, neuem Salz und
    /// Stufe 1 als Tresor ein. Die beschädigte Datei wird als `beschaedigt-…` abgelegt, nie gelöscht. `recover`
    /// selbst wirft bei einem gekippten Byte weiterhin `corruptFile` (SPEC §10); dieser Weg ist bewusst
    /// getrennt, weil er auf einen älteren Stand zurückgeht. Zusatz zur Schnittstelle in §8 (SPEC v3.1).
    public func recoverFromNewestReadableBackup(code: String, newMasterPassword: String,
                                                kdf: KDFParameters = .standard) throws -> (UnlockedVault, BackupInfo) {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try checkNewPassword(newMasterPassword, kdf: kdf)
        let r = try RecoveryCodeCodec.decode(code)
        return try recoverFromBackups(r: r, newMasterPassword: newMasterPassword, kdf: kdf)
    }

    /// Wie `recoverFromNewestReadableBackup(code:…)`, mit zwei Teilen. Zusatz zu §22.
    public func recoverFromNewestReadableBackup(shares: [String], newMasterPassword: String,
                                                kdf: KDFParameters = .standard) throws -> (UnlockedVault, BackupInfo) {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try checkNewPassword(newMasterPassword, kdf: kdf)
        let r = try Self.combineShares(shares)
        return try recoverFromBackups(r: r, newMasterPassword: newMasterPassword, kdf: kdf)
    }

    private func recoverFromBackups(r: SecureBytes, newMasterPassword: String,
                                    kdf: KDFParameters) throws -> (UnlockedVault, BackupInfo) {
        let pw = try PasswordNormalizer.secureBytes(newMasterPassword)
        for backup in recoveryBackupCandidates() {
            guard let bytes = try? FileIO.read(backup.url, maxSize: FileFormat.maxFileBytes),
                  let file = try? VaultFile.parse(bytes),
                  RecoveryKEM.matches(r: r, vaultID: file.header.vaultID, expected: file.header.pk) else { continue }
            let opened: OpenedVault
            do {
                opened = try Self.unsealed(try VaultCrypto.openWithRecovery(file, r: r), r: r)
            } catch SiegelError.corruptFile {
                continue
            }
            guard try !MasterTag.isUsedByEntries(pw, entries: opened.content.entries) else {
                throw SiegelError.masterPasswordReused
            }
            let vault = try install(opened, password: pw, factors: FactorSecrets(), kdf: kdf, confirmRecovery: true,
                                    recoveryReset: true, reason: .recovery)
            return (vault, backup)
        }
        throw SiegelError.corruptFile("backup.noneReadable")
    }
}
