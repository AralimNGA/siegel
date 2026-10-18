import Foundation

// Anlegen, Kopf-Auskunft, Entsperren (mit Faktoren), Wiederherstellen/Einspielen von Sicherungen (SPEC §4, §13, §22).

extension VaultStore {
    // MARK: - Anlegen

    /// Neuer Tresor in Stufe 1 (Format v2, keine Faktoren, ein Notfallcode). Höhere Stufen danach über
    /// `UnlockedVault.changeSecurityLevel`.
    public func create(masterPassword: String, kdf: KDFParameters = .standard) throws -> (UnlockedVault, PendingRecovery) {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let policy = MasterPasswordPolicy.check(PasswordNormalizer.normalize(masterPassword))
        guard policy.ok else { throw SiegelError.passwordTooWeak(bits: policy.bits) }
        try limits.validate(kdf)
        guard !vaultExists else { throw SiegelError.vaultAlreadyExists }

        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        let vaultID = VaultHeader.bytes(of: UUID())
        let r = try SecureBytes.random(count: RecoveryKEM.rBytes)
        let pk = try RecoveryKEM.derivePublicKeys(r: r, vaultID: vaultID)
        let (header, slots, dek) = try rekey(vaultID: vaultID, kdf: kdf, fields: .none, scheme: .single, pk: pk,
                                             password: pw, factors: FactorSecrets())
        let result = try persist(header: header, slots: slots, dek: dek, content: .empty(now: Clock.now()),
                                 baseGeneration: 0, expectation: .absent, reason: nil, newDEK: true)
        let vault = try UnlockedVault(store: self, header: header, slots: slots, dek: dek, content: result.content,
                                      generation: result.generation, password: pw)
        let code = RecoveryCode(formatted: try RecoveryCodeCodec.format(r: r), kitID: pk.kitID)
        return (vault, PendingRecovery(code: code, confirmationGroups: Self.randomConfirmationGroups()))
    }

    // MARK: - Kopf-Auskunft (§13.3)

    /// Liest nur KOPF + Prüfsumme (kein Argon2): welche Faktoren, welches Notfallschema, welches Kit.
    /// Fehlende Datei → `vaultMissing`; Bitfäule → `corruptFile`; neuere Version → `unsupportedVersion`.
    public static func inspect(fileAt url: URL) throws -> VaultHeaderInfo {
        let bytes = try FileIO.read(url, maxSize: FileFormat.maxFileBytes)
        try VaultFile.verifyChecksum(bytes)
        return try VaultFile.parseHeaderOnly(Array(bytes.dropLast(FileFormat.checksumBytes))).info
    }

    public func inspect() throws -> VaultHeaderInfo {
        try Self.inspect(fileAt: vaultURL)
    }

    /// Wie `inspect(fileAt:)`, aber **ohne** Prüfsumme: liest nur den Kopf (Format, Faktoren, Notfallschema, Kit).
    /// Ausdrücklich ungeprüft – nur für die Wahl der Eingabe im Notfallweg (ein Code oder zwei Teile), wenn ein
    /// gekipptes Byte im Inhalt `inspect` scheitern lässt; über den Zugang entscheidet weiterhin der eigene Kopf jeder
    /// geöffneten Datei. Fehlende Datei → `vaultMissing`; unlesbarer Kopf → `corruptFile`. Zusatz zu §13.3 (v4.4,
    /// Befund datei-4).
    public static func inspectHeaderUnverified(fileAt url: URL) throws -> VaultHeaderInfo {
        try VaultFile.parseHeaderOnly(try FileIO.readPrefix(url, count: VaultHeader.maxSize)).info
    }

    public func inspectHeaderUnverified() throws -> VaultHeaderInfo {
        try Self.inspectHeaderUnverified(fileAt: vaultURL)
    }

    // MARK: - Entsperren

    /// Ohne Faktoren (Stufe 1 bzw. Format v1). Verlangt die Datei Faktoren → `factorMissing`.
    public func unlock(masterPassword: String) throws -> UnlockOutcome {
        try unlock(masterPassword: masterPassword, factors: FactorSecrets())
    }

    /// Entsperren mit den rohen Faktor-Werten, die `inspect()` verlangt (§13.1). Fehlt einer → `factorMissing`
    /// (vor Argon2); falsche Karte → `wrongCard`; falsches Passwort oder falscher Faktor → `wrongPassword`.
    ///
    /// Selbstvernichtung (§23): zuerst der Totmann-Schalter. Ist das Vernichtungs-Passwort eingeschaltet, laufen
    /// **immer beide** Argon2 gleichzeitig (gleiche Dauer). Passt das Master-Passwort → normal (Zähler 0, Frist neu).
    /// Passt das Vernichtungs-Passwort → zuerst V vernichten (synchron), dann mit dem DEK aus dessen Umschlag öffnen
    /// (der Umschlag braucht auch die Faktoren, v4.4): eine Vernichtungs-Sitzung (`isDuressSession`), nach aussen wie
    /// `.unlocked`. Nur `wrongPassword` zählt als Fehlversuch; bei N wird vernichtet und trotzdem `wrongPassword`
    /// gemeldet. Das erste echte Entsperren nach einer Vernichtungs-Sitzung erneuert DEK und Salz und schreibt sofort
    /// (sie arbeitete mit dem echten DEK; v4.4).
    public func unlock(masterPassword: String, factors: FactorSecrets) throws -> UnlockOutcome {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        _ = try? checkDeadman(now: Clock.now())
        let probe = duressProbe()
        let cache = KEKCache()
        let duressCache = SecretCache()
        let attempt: UnlockAttempt
        do {
            do {
                attempt = try openForUnlock(password: pw, factors: factors, cache: cache, probe: probe,
                                            duressCache: duressCache)
            } catch let error as SiegelError where Self.isRetryable(error) {
                // Beschädigt: kurz warten und genau einmal neu lesen (gleiches Salz → Argon2 wiederverwenden).
                if corruptRetryDelay > 0 { Thread.sleep(forTimeInterval: corruptRetryDelay) }
                attempt = try openForUnlock(password: pw, factors: factors, cache: cache, probe: probe,
                                            duressCache: duressCache)
            }
        } catch SiegelError.wrongPassword {
            recordFailedAttempt()
            throw SiegelError.wrongPassword
        }
        switch attempt {
        case let .genuine(opened):
            let header = opened.file.header
            // Nach einer Vernichtungs-Sitzung: DEK erneuern (nicht bei Rollback-Verdacht – dort entscheidet der Nutzer;
            // scheitert das Schreiben, öffnet der Tresor wie bisher und das nächste echte Entsperren versucht es neu).
            if header.formatVersion >= 2, rekeyPending(), rollbackSeen(opened.file) == nil,
               let fresh = try? rekeyAfterDuress(opened, password: pw, factors: factors, rawPassword: masterPassword) {
                return .unlocked(fresh)
            }
            let vault = try UnlockedVault(store: self, header: header, slots: opened.file.slots,
                                          dek: opened.dek, content: opened.content, generation: opened.file.generation,
                                          password: pw, rawPassword: masterPassword, factors: factors,
                                          migrationKEK: opened.migrationKEK)
            recordGenuineUnlock(content: opened.content, header: header, dek: opened.dek,
                                binding: try? DuressCrypto.binding(header: header, factors: factors))
            return outcome(vault, file: opened.file)
        case let .duress(file, dek):
            #if DEBUG
            TestHooks.afterDuressArgon?.run()
            #endif
            recordDuressUnlock(at: Clock.now())
            // Veralteter Umschlag (Schreiben nach einem Speichern gescheitert) oder falscher Faktor: vernichtet ist
            // trotzdem.
            guard let dek, let (content, _) = try? VaultCrypto.decryptPayload(file, dek: dek) else {
                throw SiegelError.wrongPassword
            }
            let vault = try UnlockedVault(store: self, header: file.header, slots: file.slots, dek: dek,
                                          content: content, generation: file.generation, password: pw,
                                          rawPassword: masterPassword, factors: factors, duress: true)
            return outcome(vault, file: file)
        }
    }

    /// Rollback-Stolperdraht wie bisher (auch in einer Vernichtungs-Sitzung gleich).
    private func outcome(_ vault: UnlockedVault, file: VaultFile) -> UnlockOutcome {
        if let seen = rollbackSeen(file) {
            return .rollbackSuspected(vault, seenGeneration: seen, fileGeneration: file.generation)
        }
        rollbackGuard.record(vaultID: file.header.uuid, generation: file.generation)
        return .unlocked(vault)
    }

    /// Höhere schon gesehene Generation (Rollback-Verdacht), sonst nil.
    private func rollbackSeen(_ file: VaultFile) -> UInt64? {
        guard let seen = rollbackGuard.lastSeenGeneration(vaultID: file.header.uuid), seen > file.generation else {
            return nil
        }
        return seen
    }

    /// Erstes echtes Entsperren nach einer Vernichtungs-Sitzung (§23.2 Nr. 3, v4.4): Die Sitzung arbeitete mit dem
    /// echten DEK. Darum wie bei einem Zugangswechsel (§1.2) neuer DEK und neues Salz (gleiche Stufe, gleiche Faktoren,
    /// gleiches Kit), sofort geschrieben; der Umschlag des Vernichtungs-Passworts folgt dem neuen DEK. Ein Argon2 mehr.
    private func rekeyAfterDuress(_ opened: OpenedVault, password: SecureBytes, factors: FactorSecrets,
                                  rawPassword: String) throws -> UnlockedVault {
        let source = opened.file.header
        let (header, slots, dek) = try rekey(vaultID: source.vaultID, kdf: source.kdf, fields: source.factorFields,
                                             scheme: source.recoveryScheme, pk: source.pk, password: password,
                                             factors: factors)
        let binding = try DuressCrypto.binding(header: header, factors: factors)
        let result = try persist(header: header, slots: slots, dek: dek, content: opened.content,
                                 baseGeneration: opened.file.generation,
                                 expectation: .generation(source.uuid, opened.file.generation), reason: nil,
                                 duressBinding: binding, newDEK: true)
        let vault = try UnlockedVault(store: self, header: header, slots: slots, dek: dek, content: result.content,
                                      generation: result.generation, password: password, rawPassword: rawPassword,
                                      factors: factors)
        recordGenuineUnlock(content: result.content, header: header, dek: dek, binding: binding)
        return vault
    }

    static func isRetryable(_ e: SiegelError) -> Bool {
        switch e {
        case .corruptFile, .kdfParametersOutOfRange, .unsupportedVersion: return true
        default: return false
        }
    }

    enum UnlockAttempt {
        case genuine(OpenedVault)
        /// Vernichtungs-Passwort erkannt; DEK aus dem Umschlag (nil = Umschlag passt nicht mehr).
        case duress(VaultFile, SecureBytes?)
    }

    private func openForUnlock(password: SecureBytes, factors: FactorSecrets, cache: KEKCache, probe: DuressProbe?,
                               duressCache: SecretCache) throws -> UnlockAttempt {
        let bytes = try FileIO.read(vaultURL, maxSize: FileFormat.maxFileBytes)
        let file = try VaultFile.parse(bytes)
        guard let probe else {
            return .genuine(try VaultCrypto.openWithPassword(file, password: password, factors: factors, limits: limits,
                                                             cache: cache))
        }
        // Gleiche Reihenfolge wie der Passwortweg: Faktoren/Karte vor jeder Rechnung, dann beide Argon2 zugleich.
        try FactorKDF.precheck(file.header, factors)
        let (p, d) = try bothArgon(header: file.header, password: password, cache: cache, duressSalt: probe.salt,
                                   duressCache: duressCache)
        let kek = try FactorKDF.kek(p: p, header: file.header, factors: factors)
        let master = AEAD.unwrap(kek: kek, blob: file.slots.pwSlot, ad: VaultSlots.pwAD(file.header))
        // Der Umschlag des Vernichtungs-Passworts ist an die Faktoren gebunden (F, v4.4); erkannt wird nur über d.
        let binding = try? DuressCrypto.binding(header: file.header, factors: factors)
        let duress = probe.file.map { DuressCrypto.open($0, d: d, binding: binding, vaultID: file.header.vaultID) }
        if let dek = master {
            let (content, _) = try VaultCrypto.decryptPayload(file, dek: dek)
            var opened = OpenedVault(file: file, dek: dek, content: content)
            if file.header.formatVersion == 1 {
                opened.migrationKEK = try FactorKDF.kek(p: p, factorKeys: [], salt: file.header.salt, mask: 0)
            }
            return .genuine(opened)
        }
        if let duress, duress.recognized { return .duress(file, duress.dek) }
        throw SiegelError.wrongPassword
    }

    // MARK: - Sicherungen einsetzen

    public func restoreBackup(_ backup: BackupInfo, masterPassword: String) throws -> UnlockedVault {
        try restoreBackup(backup, masterPassword: masterPassword, factors: FactorSecrets())
    }

    /// Sicherung als Tresor einsetzen: mit den Faktoren, die **ihr** Kopf verlangt; DEK und Salz werden erneuert.
    public func restoreBackup(_ backup: BackupInfo, masterPassword: String, factors: FactorSecrets) throws -> UnlockedVault {
        dispatchPrecondition(condition: .notOnQueue(.main))
        return try openAndInstall(from: backup.url, masterPassword: masterPassword, factors: factors)
    }

    public func importBackup(from url: URL, masterPassword: String) throws -> UnlockedVault {
        try importBackup(from: url, masterPassword: masterPassword, factors: FactorSecrets())
    }

    public func importBackup(from url: URL, masterPassword: String, factors: FactorSecrets) throws -> UnlockedVault {
        dispatchPrecondition(condition: .notOnQueue(.main))
        return try openAndInstall(from: url, masterPassword: masterPassword, factors: factors)
    }

    /// Sicherungswege zählen falsche Passwörter wie das Entsperren (§23.2 Nr. 2), sonst liesse sich der Zähler über
    /// sie umgehen; ein Erfolg gilt als echtes Entsperren.
    private func openAndInstall(from url: URL, masterPassword: String, factors: FactorSecrets) throws -> UnlockedVault {
        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        _ = try? checkDeadman(now: Clock.now())
        let bytes: [UInt8]
        do {
            bytes = try FileIO.read(url, maxSize: FileFormat.maxFileBytes)
        } catch SiegelError.vaultMissing {
            throw SiegelError.io("backup.missing")
        }
        let file = try VaultFile.parse(bytes)
        let opened: OpenedVault
        do {
            opened = try VaultCrypto.openWithPassword(file, password: pw, factors: factors, limits: limits)
        } catch SiegelError.wrongPassword {
            recordFailedAttempt()
            throw SiegelError.wrongPassword
        }
        return try install(opened, password: pw, factors: factors, rawPassword: masterPassword)
    }

    public func restoreNewestReadableBackup(masterPassword: String) throws -> (UnlockedVault, BackupInfo) {
        try restoreNewestReadableBackup(masterPassword: masterPassword, factors: FactorSecrets())
    }

    /// Neueste lesbare Sicherung öffnen (absteigend; gleiches Salz + Parameter → Argon2 wiederverwenden).
    /// Verlangt die neueste noch nicht ausgeschlossene Sicherung einen Faktor, der fehlt (`factorMissing`) oder nicht
    /// passt (`wrongCard`), endet die Suche dort: sonst würde still ein älterer Stand mit tieferer Stufe eingesetzt
    /// (Datenverlust und Herabstufung). Ohne den Faktor bleibt der Notfallweg. Falsches Passwort → ältere Sicherungen
    /// probieren (früheres Passwort); ohne Treffer `wrongPassword`, sonst `corruptFile("backup.noneReadable")`.
    public func restoreNewestReadableBackup(masterPassword: String,
                                            factors: FactorSecrets) throws -> (UnlockedVault, BackupInfo) {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        _ = try? checkDeadman(now: Clock.now())
        let currentID = (try? FileIO.readPrefix(vaultURL, count: VaultHeader.maxSize))
            .flatMap { try? VaultFile.parseHeaderOnly($0) }?.uuid
        var candidates = backups()
        if let currentID, candidates.contains(where: { $0.vaultID == currentID }) {
            candidates = candidates.filter { $0.vaultID == currentID }
        }
        let cache = KEKCache()
        var sawWrongPassword = false
        for backup in candidates {
            guard let bytes = try? FileIO.read(backup.url, maxSize: FileFormat.maxFileBytes),
                  let file = try? VaultFile.parse(bytes) else { continue }
            let opened: OpenedVault
            do {
                opened = try VaultCrypto.openWithPassword(file, password: pw, factors: factors, limits: limits,
                                                          cache: cache)
            } catch SiegelError.wrongPassword {
                sawWrongPassword = true
                continue
            } catch let error as SiegelError {
                switch error {
                case .factorMissing, .wrongCard, .kdfFailed: throw error
                default: continue
                }
            } catch {
                continue
            }
            return (try install(opened, password: pw, factors: factors, rawPassword: masterPassword), backup)
        }
        if sawWrongPassword {
            recordFailedAttempt()
            throw SiegelError.wrongPassword
        }
        throw SiegelError.corruptFile("backup.noneReadable")
    }

    // MARK: - Interna: neuer Zugang

    /// Neuer Kopf v2 (neues Salz), Argon2, Faktoren, neuer DEK und beide Slots. Fehlende Faktoren und eine falsche
    /// Karte fallen vor Argon2 auf.
    func rekey(vaultID: [UInt8], kdf: KDFParameters, fields: HeaderFactorFields, scheme: RecoveryScheme,
               pk: RecoveryPublicKeys, password: SecureBytes,
               factors: FactorSecrets) throws -> (VaultHeader, VaultSlots, SecureBytes) {
        try limits.validate(kdf)
        let header = try VaultHeader(vaultID: vaultID, kdf: kdf, salt: randomBytes(KDF.saltBytes), factors: fields,
                                     recoveryScheme: scheme, pk: pk)
        try FactorKDF.precheck(header, factors)
        let p = try KDF.deriveKEK(password: password, salt: header.salt, params: kdf, limits: limits)
        let kek = try FactorKDF.kek(p: p, header: header, factors: factors)
        let dek = try SecureBytes.random(count: AEAD.keyBytes)
        let slots = try VaultCrypto.makeSlots(header: header, kekPw: kek, dek: dek)
        return (header, slots, dek)
    }

    /// Geöffneten Tresor als aktuellen einsetzen (Wiederherstellung/Einspielen): DEK-Rotation, neues Salz,
    /// bisherige Datei als „vor-wiederherstellung“ bzw. beschädigt sichern. Faktoren und Stufe der Sicherung bleiben
    /// (dieselben Faktor-Werte, mit denen sie geöffnet wurde); `recoveryReset` (Notfallweg) setzt Stufe 1.
    ///
    /// Notfallkit: Die Sicherung bringt ihr eigenes Kit (pk im Kopf) mit. Ist nicht belegt, dass es dasselbe Kit
    /// wie in der bisherigen Datei ist (gleiche vaultID und Kit-Kennung), gilt es als unbestätigt
    /// (`recoveryConfirmedAt = nil`): Das gedruckte Blatt passt dann womöglich nicht mehr, und ein bewusst
    /// ersetztes altes Kit darf nicht still wieder gelten (SPEC §1.3, §1.5). Fehlt die Datei oder ist sie
    /// beschädigt, ist das Kit unbekannt → ebenfalls unbestätigt (sichere Richtung).
    func install(_ opened: OpenedVault, password: SecureBytes, factors: FactorSecrets, kdf: KDFParameters? = nil,
                 confirmRecovery: Bool = false, recoveryReset: Bool = false,
                 reason: BackupNaming.Reason = .restore, rawPassword: String? = nil) throws -> UnlockedVault {
        let disk = try observeDisk()
        if let v = disk?.newerVersion { throw SiegelError.unsupportedVersion(v) }
        let source = opened.file.header
        var base = opened.file.generation
        if let f = disk?.file, f.header.uuid == source.uuid { base = max(base, f.generation) }
        var content = opened.content
        let sameKit = disk?.file.map { $0.header.uuid == source.uuid && $0.header.pk.kitID == source.pk.kitID } ?? false
        if confirmRecovery {
            // Notfallweg: Der eingegebene Code hat genau dieses Kit geöffnet – damit ist es bestätigt.
            if content.recoveryConfirmedAt == nil { content.recoveryConfirmedAt = Clock.now() }
        } else if !sameKit {
            content.recoveryConfirmedAt = nil
        }
        if recoveryReset { try content.resetAfterRecovery() }
        let used = recoveryReset ? FactorSecrets() : factors
        let (header, slots, dek) = try rekey(vaultID: source.vaultID, kdf: kdf ?? source.kdf,
                                             fields: recoveryReset ? .none : source.factorFields,
                                             scheme: source.recoveryScheme, pk: source.pk, password: password,
                                             factors: used)
        let binding = try DuressCrypto.binding(header: header, factors: used)
        let result = try persist(header: header, slots: slots, dek: dek, content: content,
                                 baseGeneration: base, expectation: .observed(disk?.digest),
                                 reason: reason.rawValue, duressBinding: binding, newDEK: true)
        let vault = try UnlockedVault(store: self, header: header, slots: slots, dek: dek, content: result.content,
                                      generation: result.generation, password: password, rawPassword: rawPassword,
                                      factors: used)
        // Mit dem Master-Passwort der Sicherung geöffnet (bzw. Notfallweg): gilt als echtes Entsperren (§23).
        recordGenuineUnlock(content: result.content, header: header, dek: dek, binding: binding)
        return vault
    }
}
