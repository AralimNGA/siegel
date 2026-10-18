import Clibsodium
import Foundation

// Eintrags-Schutz (SPEC §16), Offline-Sicherheitsbericht (§17), Exporte (§8, §19) und die async-Varianten der
// Zugangswechsel, die versiegelte Einträge mitnehmen müssen (neues Kit).

extension UnlockedVault {
    // MARK: - Aufdecken (§16)

    /// Geheimteile eines Eintrags. Schutz 1: direkt, Provider wird nicht gebraucht. Schutz ≥ 2: Provider Pflicht
    /// (sonst `factorMissing` mit der ersten verlangten Art); gerufen werden nur die Methoden der Maske, jede genau
    /// einmal (frische Freigabe pro Aufdecken). K und alle Zwischenwerte liegen nur in `SecureBytes` und werden mit
    /// dem Ende des Aufrufs freigegeben; nichts wird zwischengespeichert. Falsche Karte → `wrongCard`; ein anderer
    /// falscher Faktor → `wrongPassword` („Passwort oder ein Faktor stimmt nicht“). Wird der Tresor während der
    /// Freigabe gesperrt → `io("vault.locked")`. Liste und Suche brauchen das nicht (offene Felder).
    ///
    /// Vernichtbare Einträge (§23.1) werden über V freigegeben (`secureEnclaveSharedSecret(keyID: V, …)`, dazu Karte
    /// bzw. Sicherheitsschlüssel); sind sie vernichtet → `factorUnavailable(.secureEnclave)` ohne Provider-Aufruf.
    /// In einer Vernichtungs-Sitzung gibt es sie nicht (`io("entry.notFound")`).
    @concurrent
    public func revealSecrets(id: UUID, factors: EntryFactorProvider?) async throws -> EntrySecrets {
        let s = try snapshot()
        guard let i = visibleIndex(s.content, id) else { throw SiegelError.io("entry.notFound") }
        let e = s.content.entries[i]
        guard e.secretsSealed else {
            return EntrySecrets(password: e.password, notes: e.notes, totp: e.totp, history: e.history)
        }
        if s.content.destructible[id] != nil {
            return try await revealDestructible(e, state: s, provider: factors)
        }
        let mask = e.protection.factors
        guard let sealed = s.content.sealed[id] else { throw SiegelError.corruptFile("entry.sealed") }
        try EntrySealing.requireEnrolled(mask, s.content.entryFactors)
        try EntrySealing.requireUsableHere(sealed.blob.factors)
        guard let provider = factors else { throw SiegelError.factorMissing(mask.kinds.first ?? .secureEnclave) }
        let keys = try s.content.sealingKeys(vaultID: s.header.vaultID)
        let released = try await EntrySealing.release(sealed.blob.factors, id: id, mask: mask, keys: keys.factors,
                                                      vaultID: keys.vaultID,
                                                      provider: LockCheckedEntryFactors(provider, vault: self))
        guard !isLocked else { throw SiegelError.io("vault.locked") }
        guard let padded = try EntrySealing.open(sealed.blob, id: id, s: UInt8(e.protection.rawValue), mask: mask,
                                                 adLabel: EntrySealing.entryAD, base: keys.base, vaultID: keys.vaultID,
                                                 released: released) else {
            throw SiegelError.wrongPassword
        }
        return try EntrySealing.decodeSecrets(padded)
    }

    /// Vernichtbaren Eintrag über V (+ Karte, + Sicherheitsschlüssel) öffnen.
    func revealDestructible(_ e: VaultEntry, state s: State,
                                    provider: EntryFactorProvider?) async throws -> EntrySecrets {
        guard let blob = s.content.destructible[e.id], let v = s.content.destruction?.vKey else {
            throw SiegelError.corruptFile("entry.sealed")
        }
        guard !destructionKeyDestroyed(s.content) else { throw SiegelError.factorUnavailable(.secureEnclave) }
        let mask = e.protection.factors
        let part = EntrySealing.SEPart.destruction(keyID: v.keyID, publicKey: v.publicKey)
        try EntrySealing.requireEnrolled(part.required(mask), s.content.entryFactors)
        try EntrySealing.requireUsableHere(blob.factors)
        guard let provider else { throw SiegelError.factorMissing(.secureEnclave) }
        let keys = try s.content.sealingKeys(vaultID: s.header.vaultID)
        let released = try await EntrySealing.release(blob.factors, id: e.id, mask: mask, keys: keys.factors,
                                                      vaultID: keys.vaultID,
                                                      provider: LockCheckedEntryFactors(provider, vault: self), se: part)
        guard !isLocked else { throw SiegelError.io("vault.locked") }
        guard let padded = try EntrySealing.open(blob, id: e.id, s: UInt8(e.protection.rawValue), mask: mask,
                                                 adLabel: EntrySealing.destructibleAD, base: keys.base,
                                                 vaultID: keys.vaultID, released: released,
                                                 keyInfo: EntrySealing.destructibleKeyInfo) else {
            throw SiegelError.wrongPassword
        }
        return try EntrySealing.decodeSecrets(padded)
    }

    /// Schutz setzen und Geheimteile schreiben (§16, §22) – der einzige Weg, die Geheimteile eines versiegelten
    /// Eintrags zu ändern. `secrets` sind die vorher aufgedeckten (ggf. bearbeiteten) Geheimteile und ersetzen die
    /// bisherigen ganz; der Verlauf wird nach §3 gekürzt und enthält nie das aktuelle Passwort
    /// (`EntrySecrets.replacingPassword(with:)` schiebt ein altes Passwort hinein). Schutz ≥ 2 verlangt die
    /// eingerichteten Faktoren (`factorMissing`, nichts geschrieben) und versiegelt sofort neu; Schutz 1 speichert
    /// offen. Setzt `modified`.
    ///
    /// Vernichtbare Einträge (§23.1) bleiben vernichtbar und werden wieder an V versiegelt; Schutz unter 4 →
    /// `notAllowedAtLevel` (erst über `configureDestruction` die Markierung entfernen). Vernichtete Einträge lassen
    /// sich nur noch entfernen (`io("entry.destroyed")`).
    public func setProtection(_ protection: EntryProtection, id: UUID, secrets: EntrySecrets) throws {
        var probe = VaultEntry(password: secrets.password, notes: secrets.notes, totp: secrets.totp)
        probe.history = secrets.history
        try VaultContent.validate(probe)
        try mutate { content, now, header in
            guard let i = visibleIndex(content, id) else {
                throw SiegelError.io("entry.notFound")
            }
            let destructible = content.destructible[id] != nil
            if destructible {
                guard !destructionKeyDestroyed(content) else { throw SiegelError.io("entry.destroyed") }
                guard protection >= .maximal else { throw SiegelError.notAllowedAtLevel }
                try EntrySealing.requireEnrolled(protection.factors.subtracting(.secureEnclave), content.entryFactors)
            } else {
                try EntrySealing.requireEnrolled(protection.factors, content.entryFactors)
            }
            var e = content.entries[i]
            e.password = secrets.password
            e.notes = secrets.notes
            e.totp = secrets.totp
            e.history = VaultContent.applyHistoryRule(secrets.history.filter { $0.password != secrets.password }, now: now)
            e.secretsSealed = false
            e.protection = protection
            e.modified = now
            content.entries[i] = e
            content.sealed[id] = nil
            content.destructible[id] = nil
            if destructible {
                try content.sealDestructible(at: i, vaultID: header.vaultID, now: now)
            } else if protection > .normal {
                try content.seal(at: i, vaultID: header.vaultID, kit: header.pk, now: now)
            }
            return true
        }
    }

    // MARK: - Offline-Sicherheitsbericht (§17)

    /// Schwach (zxcvbn-Stufe unter „fair“, < 36 Bit), wiederverwendet (gleicher reuseTag, Gruppen ab 2), alt (letzte
    /// Passwortänderung vor über 365 Tagen), gleich wie das Master-Passwort. Ohne Netzwerk, kein Abgleich mit
    /// Leak-Datenbanken (bewusst). Funktioniert auch für versiegelte Einträge (Metadaten, keine Geheimteile).
    /// Gezählt werden nicht gelöschte Einträge mit Passwort (`total`); Reihenfolge wie in der Liste.
    public func securityReport() -> SecurityReport {
        guard let s = try? snapshot() else {
            return SecurityReport(weak: [], reused: [], old: [], sameAsMaster: [], total: 0)
        }
        let now = Clock.now()
        let reuseKey = try? s.content.reuseKey()
        var weak: [UUID] = []
        var old: [UUID] = []
        var byTag: [[UInt8]: [UUID]] = [:]
        var tagOrder: [[UInt8]] = []
        var total = 0
        for e in s.content.entries where e.deletedAt == nil && !hiddenEntries.contains(e.id) {
            let m: EntryMeta?
            if e.secretsSealed {
                m = s.content.meta[e.id]
            } else if let reuseKey {
                m = EntrySealing.meta(password: e.password, previous: s.content.meta[e.id], reuseKey: reuseKey,
                                      fallbackChanged: VaultContent.estimatedPasswordChange(e), now: now)
            } else {
                m = nil
            }
            guard let m, let tag = m.tag else { continue }
            total += 1
            if let st = m.strength, st < PasswordStrength.Level.fair.rawValue { weak.append(e.id) }
            if let changed = m.changed, now.timeIntervalSince(changed) > Self.oldPasswordAge { old.append(e.id) }
            if byTag[tag] == nil { tagOrder.append(tag) }
            byTag[tag, default: []].append(e.id)
        }
        let reused = tagOrder.compactMap { byTag[$0] }.filter { $0.count > 1 }
        let same = s.content.entries.filter {
            $0.deletedAt == nil && s.reuse.contains($0.id) && !hiddenEntries.contains($0.id)
        }.map(\.id)
        return SecurityReport(weak: weak, reused: reused, old: old, sameAsMaster: same, total: total)
    }

    static let oldPasswordAge: TimeInterval = 365 * 86_400

    // MARK: - Freigaben für Zugangswechsel und Exporte

    /// Anker der Gruppen über den Provider freigeben (eine Freigabe pro Gruppe, in Maskenreihenfolge). Nach einem
    /// Sperren unterwegs (z. B. während des Argon2 eines Exports) fragt er keinen Faktor mehr ab (Befund ablaeufe-4).
    func releaseGroups(_ groups: [RecoveryGroup], state s: State,
                       provider: EntryFactorProvider) async throws -> [UUID: SecureBytes] {
        guard !isLocked else { throw SiegelError.io("vault.locked") }
        let keys = try s.content.sealingKeys(vaultID: s.header.vaultID)
        let checked = LockCheckedEntryFactors(provider, vault: self)
        var out: [UUID: SecureBytes] = [:]
        for g in groups {
            out[g.id] = try await EntrySealing.releaseAnchor(g, keys: keys, provider: checked)
        }
        return out
    }

    /// Wie `commitRecovery(_:confirmation:)`. Ist es ein neues Kit und gibt es versiegelte Einträge, werden deren
    /// Notfall-Gruppen an das neue Kit gekapselt: dafür je Gruppe eine Freigabe über `entryFactors` (Schutz 2/3: ein
    /// Touch ID; Schutz 4: Touch ID + Karte; Schutz 5: zusätzlich der Sicherheitsschlüssel). Ohne Provider →
    /// `factorMissing`, nichts geschrieben. Zusatz zu §22.
    @concurrent
    public func commitRecovery(_ pending: PendingRecovery, confirmation: [String],
                               entryFactors: EntryFactorProvider?) async throws {
        try Self.checkConfirmation(pending, confirmation)
        let r = try Self.secret(of: pending)
        let s = try snapshot()
        var released: [UUID: SecureBytes] = [:]
        if let p = s.pending, p.r.constantTimeEquals(r), p.header.pk != s.header.pk {
            let needed = s.content.neededRecoveryGroups
            if let first = needed.first {
                guard let provider = entryFactors else {
                    throw SiegelError.factorMissing(first.mask.kinds.first ?? .secureEnclave)
                }
                released = try await releaseGroups(needed, state: s, provider: provider)
            }
        }
        try commitRecovery(pending, confirmation: confirmation, releasedGroups: released)
    }

    /// Wie `changeSecurityLevel(…)`. Bringt der Wechsel ein neues Kit und gibt es versiegelte Einträge, prüft er zuerst
    /// Passwort und Faktoren (Argon2) und holt dann je Notfall-Gruppe eine Freigabe über `entryFactors`. Ohne Provider
    /// → `factorMissing`. Zusatz zu §22.
    @concurrent
    public func changeSecurityLevel(to level: SecurityLevel, masterPassword: String, currentFactors: FactorSecrets,
                                    newFactors: NewFactorMaterial, recovery: PendingRecovery?,
                                    recoveryConfirmation: [String], entryFactors: EntryFactorProvider?) async throws {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let s = try snapshot()
        var released: [UUID: SecureBytes] = [:]
        var verified: [UInt8]?
        let needed = s.content.neededRecoveryGroups
        if let recovery, let first = needed.first {
            try Self.validate(newFactors)
            try Self.checkConfirmation(recovery, recoveryConfirmation)
            guard let provider = entryFactors else {
                throw SiegelError.factorMissing(first.mask.kinds.first ?? .secureEnclave)
            }
            // Erst Passwort und Faktoren (kein Touch ID für ein falsches Passwort), dann die Freigaben.
            try verifyAccess(try PasswordNormalizer.secureBytes(masterPassword), currentFactors, s)
            verified = s.header.salt
            released = try await releaseGroups(needed, state: s, provider: provider)
        }
        try changeSecurityLevel(to: level, masterPassword: masterPassword, currentFactors: currentFactors,
                                newFactors: newFactors, recovery: recovery, recoveryConfirmation: recoveryConfirmation,
                                releasedGroups: released, verifiedSalt: verified)
    }

    // MARK: - Exporte (§8 CSV-Hygiene, §16, §19)

    struct ExportPlan {
        /// Nicht gelöscht und Schutz < 4 (Schutz 4/5 nie in Exporten).
        let entries: [VaultEntry]
        /// Notfall-Gruppen der versiegelten Einträge darunter (Schutz 2/3), über ihren Anker freizugeben.
        let needed: [RecoveryGroup]
    }

    func exportPlan(_ s: State, allowed: Bool) throws -> ExportPlan {
        guard allowed else { throw SiegelError.notAllowedAtLevel }
        let list = s.content.entries.filter { $0.deletedAt == nil && $0.protection.exportAllowed }
        var masks = Set<UInt8>()
        for e in list where e.secretsSealed { masks.insert(e.protection.factors.rawValue) }
        let needed = s.content.recoveryGroups.filter { masks.contains($0.mask.rawValue) }
        guard needed.count == masks.count else { throw SiegelError.corruptFile("entry.sealed") }
        return ExportPlan(entries: list, needed: needed)
    }

    /// Einträge mit Geheimteilen (versiegelte über die freigegebenen Gruppen).
    func exportItems(_ s: State, plan: ExportPlan,
                     released: [UUID: SecureBytes]) throws -> [(VaultEntry, EntrySecrets)] {
        let opened = try s.content.secretsViaGroups(for: plan.entries, released: released, vaultID: s.header.vaultID)
        return try plan.entries.map { e in
            if e.secretsSealed {
                guard let x = opened[e.id] else { throw SiegelError.corruptFile("entry.sealed") }
                return (VaultContent.unsealed(e, with: x), x)
            }
            return (e, EntrySecrets(password: e.password, notes: e.notes, totp: e.totp, history: e.history))
        }
    }

    public func exportCSV(toParent directory: URL, masterPassword: String) throws -> URL {
        try exportCSV(toParent: directory, masterPassword: masterPassword, factors: FactorSecrets())
    }

    /// Prüft Master-Passwort und Faktoren, lehnt iCloud Drive ab und schreibt `Siegel-Export-<JJJJ-MM-TT>.noindex/`
    /// (0700) mit `Siegel-Export.csv` (0600), beide vom Backup ausgenommen. Stufen 4/5 → `notAllowedAtLevel` (vor
    /// Argon2). Einträge mit Schutz 4/5 fehlen immer. Gibt es versiegelte Einträge mit Schutz 2/3, braucht der Export
    /// deren Freigabe: async-Variante mit `entryFactors`; hier → `factorMissing` (vor Argon2).
    public func exportCSV(toParent directory: URL, masterPassword: String, factors: FactorSecrets) throws -> URL {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let s = try snapshot()
        let plan = try exportPlan(s, allowed: s.content.level.policy.allowCSVExport)
        if let g = plan.needed.first { throw SiegelError.factorMissing(g.mask.kinds.first ?? .secureEnclave) }
        try verifyAccess(try PasswordNormalizer.secureBytes(masterPassword), factors, s)
        try CSVExportLocation.check(directory)
        return try writeCSV(try exportItems(s, plan: plan, released: [:]), directory: directory)
    }

    /// Wie `exportCSV(toParent:masterPassword:factors:)`; versiegelte Einträge mit Schutz 2/3 kommen über eine
    /// Freigabe ihrer Notfall-Gruppe dazu (ein Touch ID für alle, nach der Passwortprüfung). Zusatz zu §22.
    @concurrent
    public func exportCSV(toParent directory: URL, masterPassword: String, factors: FactorSecrets,
                          entryFactors: EntryFactorProvider?) async throws -> URL {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let s = try snapshot()
        let plan = try exportPlan(s, allowed: s.content.level.policy.allowCSVExport)
        if let g = plan.needed.first, entryFactors == nil {
            throw SiegelError.factorMissing(g.mask.kinds.first ?? .secureEnclave)
        }
        try verifyAccess(try PasswordNormalizer.secureBytes(masterPassword), factors, s)
        try CSVExportLocation.check(directory)
        var released: [UUID: SecureBytes] = [:]
        if let provider = entryFactors, !plan.needed.isEmpty {
            released = try await releaseGroups(plan.needed, state: s, provider: provider)
        }
        guard !isLocked else { throw SiegelError.io("vault.locked") }
        return try writeCSV(try exportItems(s, plan: plan, released: released), directory: directory)
    }

    private func writeCSV(_ items: [(VaultEntry, EntrySecrets)], directory: URL) throws -> URL {
        var data = CSVExport.export(items.map(\.0))
        return try Self.writeExport(&data, directory: directory, fileName: "Siegel-Export.csv")
    }

    /// KeePass-Export KDBX 4.1 (§19): nur Stufen 1–3 (sonst `notAllowedAtLevel`, vor Argon2), eigenes Export-Passwort
    /// nach `MasterPasswordPolicy` (`passwordTooWeak`), nicht gleich dem Master-Passwort (`masterPasswordReused`),
    /// Master-Passwort + Faktoren geprüft, Datei-Hygiene wie CSV (`Siegel-Export.kdbx`). Schutz 4/5 fehlt immer;
    /// versiegelte Einträge mit Schutz 2/3 → async-Variante, hier `factorMissing`.
    public func exportKeePass(toParent directory: URL, masterPassword: String, factors: FactorSecrets,
                              exportPassword: String) throws -> URL {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let s = try snapshot()
        let plan = try exportPlan(s, allowed: s.content.level.policy.allowKeePassExport)
        try Self.checkExportPassword(exportPassword, masterPassword: masterPassword)
        if let g = plan.needed.first { throw SiegelError.factorMissing(g.mask.kinds.first ?? .secureEnclave) }
        try verifyAccess(try PasswordNormalizer.secureBytes(masterPassword), factors, s)
        try CSVExportLocation.check(directory)
        return try writeKeePass(try exportItems(s, plan: plan, released: [:]), directory: directory,
                                password: exportPassword)
    }

    /// Wie `exportKeePass(…)`, mit Freigabe der versiegelten Einträge (Schutz 2/3). Zusatz zu §22.
    @concurrent
    public func exportKeePass(toParent directory: URL, masterPassword: String, factors: FactorSecrets,
                              exportPassword: String, entryFactors: EntryFactorProvider?) async throws -> URL {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let s = try snapshot()
        let plan = try exportPlan(s, allowed: s.content.level.policy.allowKeePassExport)
        try Self.checkExportPassword(exportPassword, masterPassword: masterPassword)
        if let g = plan.needed.first, entryFactors == nil {
            throw SiegelError.factorMissing(g.mask.kinds.first ?? .secureEnclave)
        }
        try verifyAccess(try PasswordNormalizer.secureBytes(masterPassword), factors, s)
        try CSVExportLocation.check(directory)
        var released: [UUID: SecureBytes] = [:]
        if let provider = entryFactors, !plan.needed.isEmpty {
            released = try await releaseGroups(plan.needed, state: s, provider: provider)
        }
        guard !isLocked else { throw SiegelError.io("vault.locked") }
        return try writeKeePass(try exportItems(s, plan: plan, released: released), directory: directory,
                                password: exportPassword)
    }

    static func checkExportPassword(_ exportPassword: String, masterPassword: String) throws {
        let policy = MasterPasswordPolicy.check(PasswordNormalizer.normalize(exportPassword))
        guard policy.ok else { throw SiegelError.passwordTooWeak(bits: policy.bits) }
        guard !VaultStore.passwordsMatch(exportPassword, masterPassword) else { throw SiegelError.masterPasswordReused }
    }

    private func writeKeePass(_ items: [(VaultEntry, EntrySecrets)], directory: URL, password: String) throws -> URL {
        var data: Data
        #if DEBUG
        if let hook = TestHooks.keePassExporter {
            data = try hook.export(items, password)
            return try Self.writeExport(&data, directory: directory, fileName: "Siegel-Export.kdbx")
        }
        #endif
        do {
            data = try KeePassExport.kdbx(items, password: password)
        } catch let e as SiegelError {
            throw e
        } catch {
            throw SiegelError.io("export.kdbx")
        }
        return try Self.writeExport(&data, directory: directory, fileName: "Siegel-Export.kdbx")
    }

    /// Schreibt in einen neuen `.noindex`-Ordner (0700) eine Datei (0600), beide vom Backup ausgenommen; scheitert
    /// etwas, bleibt nichts liegen. Die Daten werden danach genullt (best effort).
    static func writeExport(_ data: inout Data, directory: URL, fileName: String) throws -> URL {
        _ = Sodium.ready
        defer { data.withUnsafeMutableBytes { if let p = $0.baseAddress { sodium_memzero(p, $0.count) } } }
        let folder = try CSVExportLocation.makeFolder(in: directory, now: Date())
        let file = folder.appendingPathComponent(fileName, isDirectory: false)
        do {
            try data.withUnsafeBytes { try FileIO.writeExclusive(file, bytes: $0) }
            _ = chmod(file.path, 0o600)
            try FileIO.setExcludedFromBackup(folder)
            try FileIO.setExcludedFromBackup(file)
        } catch {
            FileIO.remove(file)
            _ = rmdir(folder.path)
            throw (error as? SiegelError) ?? SiegelError.io("export.write")
        }
        return file
    }
}

/// Prüft vor jeder Freigabe, ob der Tresor inzwischen gesperrt ist (Befund ablaeufe-4): Der Kern ruft die Faktoren
/// nacheinander ab (Touch ID → Karte → Schlüssel); wird dazwischen gesperrt, öffnet keine weitere Abfrage mehr ein
/// Kamera- oder Schlüssel-Sheet bzw. einen Touch-ID-Dialog über dem Sperrbildschirm → `io("vault.locked")`.
struct LockCheckedEntryFactors: EntryFactorProvider {
    private let base: EntryFactorProvider
    private let vault: UnlockedVault

    init(_ base: EntryFactorProvider, vault: UnlockedVault) {
        self.base = base
        self.vault = vault
    }

    private func requireOpen() throws {
        guard !vault.isLocked else { throw SiegelError.io("vault.locked") }
    }

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        try requireOpen()
        return try await base.secureEnclaveSharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey)
    }

    func cardSecret() async throws -> FactorSecret {
        try requireOpen()
        return try await base.cardSecret()
    }

    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
        try requireOpen()
        return try await base.securityKeyOutput(credentialID: credentialID, salt: salt)
    }
}

extension EntrySecrets {
    /// Neues Passwort; das bisherige wandert in den Verlauf (wie `upsert` bei offenen Einträgen). Zum Bearbeiten
    /// versiegelter Einträge vor `setProtection`. Zusatz zu §22.
    public func replacingPassword(with newPassword: String) -> EntrySecrets {
        guard newPassword != password else { return self }
        var out = self
        if !password.isEmpty { out.history.append(PasswordHistoryItem(password: password, changed: Clock.now())) }
        out.history.removeAll { $0.password == newPassword }
        out.password = newPassword
        return out
    }
}
