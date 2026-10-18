import Foundation

// Selbstvernichtung im entsperrten Tresor (SPEC §23.3): Einstellungen, Markierung vernichtbarer Einträge,
// Vernichtungs-Passwort, vernichtete Einträge entfernen, Vernichtungs-Sitzung.

extension UnlockedVault {
    // MARK: - Lesen

    /// Vernichtete Einträge (nur in einer echten Sitzung gefüllt): die vernichtbaren Einträge, deren V vernichtet ist.
    /// Sie stehen weiter in `entries` (die Oberfläche markiert sie), lassen sich nicht mehr aufdecken
    /// (`factorUnavailable(.secureEnclave)`) und nur noch mit `removeDestroyedEntries()` entfernen.
    public var destroyedEntries: [UUID] {
        guard !isDuressSession, let s = try? snapshot(), destructionKeyDestroyed(s.content) else { return [] }
        return s.content.entries.filter { s.content.destructible[$0.id] != nil }.map(\.id)
    }

    /// Einstellungen der Selbstvernichtung aus dem verschlüsselten Inhalt (massgeblich). Zusatz zu §23.3.
    public var destructionSettings: DestructionSettings {
        (try? snapshot())?.content.destruction?.settings ?? .off
    }

    /// Als vernichtbar markierte Einträge (in einer Vernichtungs-Sitzung leer). Zusatz zu §23.3.
    public var destructibleEntries: Set<UUID> {
        guard let s = try? snapshot() else { return [] }
        return s.content.destructibleIDs.subtracting(hiddenEntries)
    }

    /// Kennung des eingerichteten Vernichtungsschlüssels V (nil = keiner oder schon vernichtet; in einer
    /// Vernichtungs-Sitzung der bisherige, damit nichts auffällt). Die Oberfläche braucht ein neues V (`vKey`), wenn
    /// das nil ist. Zusatz zu §23.3.
    public var destructionKeyID: UUID? {
        guard let s = try? snapshot(), let v = s.content.destruction?.vKey,
              isDuressSession || !destructionKeyDestroyed(s.content) else {
            return nil
        }
        return v.keyID
    }

    /// Wie `VaultStore.destructionStatus()`, aber passend zur Sitzung: Einstellungen aus dem Inhalt, und in einer
    /// Vernichtungs-Sitzung ohne Vermerk der Vernichtung (nichts deutet darauf hin). Zusatz zu §23.3.
    public var destructionStatus: DestructionStatus {
        let st = store.destructionStatus()
        let settings = destructionSettings
        let deadline = settings.deadmanDays.flatMap { days in
            st.lastGenuineUnlock.map { Clock.canonical($0.addingTimeInterval(TimeInterval(days) * 86_400)) }
        }
        return DestructionStatus(settings: settings, lastGenuineUnlock: st.lastGenuineUnlock,
                                 failedAttempts: st.failedAttempts, deadline: deadline,
                                 destroyedTrigger: isDuressSession ? nil : st.destroyedTrigger,
                                 destroyedAt: isDuressSession ? nil : st.destroyedAt,
                                 keyConfigured: st.keyConfigured || destructionKeyID != nil)
    }

    // MARK: - Einrichten (§23.3)

    /// Selbstvernichtung einstellen (nur Stufe 4/5). Braucht Master-Passwort und alle Faktoren der Stufe.
    ///
    /// - `s`: Totmann-Frist (7…365 Tage), Fehlversuch-Grenze (10…100), Vernichtungs-Passwort an/aus. Ausserhalb der
    ///   Bereiche → `io("destruction.deadmanDays")` bzw. `io("destruction.maxFailedAttempts")`.
    /// - `duressPassword`: neues Vernichtungs-Passwort (nur mit `s.duressEnabled`; nil = bisheriges behalten).
    ///   `MasterPasswordPolicy` (`passwordTooWeak`), ungleich dem Master-Passwort (`masterPasswordReused`). Fehlt es
    ///   beim ersten Einschalten oder wird es bei ausgeschaltetem Vernichtungs-Passwort mitgegeben →
    ///   `io("destruction.duressPassword")`.
    /// - `destructible`: die **ganze** neue Auswahl vernichtbarer Einträge (Schutz 4/5, sonst `notAllowedAtLevel`;
    ///   unbekannt → `io("entry.notFound")`). Markieren und Entmarkieren versiegelt neu und braucht die
    ///   Geheimteile: das geht nur mit der async-Variante (`entryFactors:`); hier → `factorMissing(.secureEnclave)`.
    /// - `vKey`: neuer Vernichtungsschlüssel V (öffentlicher Teil, vom Hardware-Modul; nil = bisheriger). Ohne V und
    ///   mit eingeschalteter Selbstvernichtung → `factorMissing(.secureEnclave)`.
    ///
    /// Stufe 1–3 → `notAllowedAtLevel` (ausser alles aus). Nach einer Vernichtung zuerst `removeDestroyedEntries()`
    /// (`io("destruction.destroyed")`). In einer Vernichtungs-Sitzung gilt das Passwort als falsch (`wrongPassword`,
    /// nach gleich langer Rechnung). Werden Einträge neu markiert, entfernt der Kern danach alle älteren Sicherungen
    /// (sie enthielten die Einträge noch mit Notfallweg); der Bericht kommt zurück (nil = nichts entfernt).
    @discardableResult
    public func configureDestruction(_ s: DestructionSettings, duressPassword: String?, destructible: Set<UUID>,
                                     masterPassword: String, factors: FactorSecrets,
                                     vKey: EntryKeyEnrollment?) throws -> PurgeReport? {
        try configureDestruction(s, duressPassword: duressPassword, destructible: destructible,
                                 masterPassword: masterPassword, factors: factors, vKey: vKey, opened: [:],
                                 verifiedSalt: nil)
    }

    /// Wie `configureDestruction(…)`; Einträge, die neu versiegelt werden müssen, werden vorher über `entryFactors`
    /// geöffnet: neu markierte über die Notfall-Gruppe ihrer Maske (eine Freigabe je Gruppe), entmarkierte einzeln
    /// über V (Touch ID je Eintrag; Karte und Sicherheitsschlüssel werden während des Aufrufs nur einmal geholt).
    /// Passwort und Faktoren werden zuerst geprüft (kein Touch ID für ein falsches Passwort). Zusatz zu §23.3.
    @concurrent @discardableResult
    public func configureDestruction(_ s: DestructionSettings, duressPassword: String?, destructible: Set<UUID>,
                                     masterPassword: String, factors: FactorSecrets, vKey: EntryKeyEnrollment?,
                                     entryFactors: EntryFactorProvider?) async throws -> PurgeReport? {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let request = try DestructionRequest(settings: s, duressPassword: duressPassword, destructible: destructible,
                                             masterPassword: masterPassword, vKey: vKey)
        let st = try snapshot()
        var opened: [UUID: OpenedEntry] = [:]
        var verified: [UInt8]?
        if !isDuressSession {
            let plan = try destructionPlan(request, state: st)
            let sealedNeeds = plan.reseal.filter { id in st.content.entries.contains { $0.id == id && $0.secretsSealed } }
            if !sealedNeeds.isEmpty {
                guard let entryFactors else { throw SiegelError.factorMissing(.secureEnclave) }
                try verifyAccess(try PasswordNormalizer.secureBytes(masterPassword), factors, st)
                verified = st.header.salt
                opened = try await openForResealing(sealedNeeds, state: st, provider: CachingEntryFactors(entryFactors))
                guard !isLocked else { throw SiegelError.io("vault.locked") }
            }
        }
        return try configureDestruction(s, duressPassword: duressPassword, destructible: destructible,
                                        masterPassword: masterPassword, factors: factors, vKey: vKey, opened: opened,
                                        verifiedSalt: verified)
    }

    /// Geheimteile eines Eintrags, geöffnet aus genau diesem Siegel (ändert sich der Eintrag inzwischen, gilt das
    /// Geöffnete nicht mehr).
    struct OpenedEntry {
        let secrets: EntrySecrets
        let sealed: SealedSecrets?
        let destructible: SealedBlob?
    }

    /// Kern: `opened` = Geheimteile der neu zu versiegelnden (versiegelten) Einträge; `verifiedSalt` = Zugang für
    /// genau diesen Kopf schon geprüft. Wurde ein Eintrag seit dem Öffnen geändert → `io("entry.stale")`.
    func configureDestruction(_ s: DestructionSettings, duressPassword: String?, destructible: Set<UUID>,
                              masterPassword: String, factors: FactorSecrets, vKey: EntryKeyEnrollment?,
                              opened: [UUID: OpenedEntry], verifiedSalt: [UInt8]?) throws -> PurgeReport? {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let request = try DestructionRequest(settings: s, duressPassword: duressPassword, destructible: destructible,
                                             masterPassword: masterPassword, vKey: vKey)
        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        return try writeLock.withLock { () -> PurgeReport? in
            let st = try snapshot()
            if isDuressSession {
                // Gleich lange Rechnung wie eine echte Prüfung; das Vernichtungs-Passwort ist kein Master-Passwort.
                _ = try? verifyAccess(pw, factors, st)
                throw SiegelError.wrongPassword
            }
            let plan = try destructionPlan(request, state: st)
            if verifiedSalt != st.header.salt { try verifyAccess(pw, factors, st) }

            var content = st.content
            var config: DestructionConfig?
            if plan.active {
                var duress: DestructionConfig.Duress?
                if s.duressEnabled {
                    if let dpw = duressPassword {
                        duress = try makeDuress(dpw, vaultID: st.header.vaultID, kdf: st.header.kdf)
                    } else {
                        duress = st.content.destruction?.duress
                    }
                }
                config = DestructionConfig(settings: s, vKey: plan.vKey, duress: duress)
            }
            content.destruction = config
            let now = Clock.now()
            for i in content.entries.indices where plan.reseal.contains(content.entries[i].id) {
                let e = content.entries[i]
                if e.secretsSealed {
                    guard let o = opened[e.id] else { throw SiegelError.factorMissing(.secureEnclave) }
                    guard o.sealed == content.sealed[e.id], o.destructible == content.destructible[e.id] else {
                        throw SiegelError.io("entry.stale")
                    }
                    content.replaceSecrets(at: i, with: o.secrets)
                } else {
                    content.replaceSecrets(at: i, with: EntrySecrets(password: e.password, notes: e.notes,
                                                                     totp: e.totp, history: e.history))
                }
                if destructible.contains(e.id) {
                    try content.sealDestructible(at: i, vaultID: st.header.vaultID, now: now)
                } else {
                    try content.seal(at: i, vaultID: st.header.vaultID, kit: st.header.pk, now: now)
                }
            }
            if content.destruction?.isEmpty == true { content.destruction = nil }
            // Inzwischen gesperrt (z. B. App-Wechsel während des Argon2 für das Vernichtungs-Passwort)? Dann nichts
            // schreiben: Ein Fehler darf nur kommen, solange die Datei unverändert ist (Befund datei-1). `save` und
            // `rekeyAndSave` prüfen das unmittelbar vor dem Schreiben nochmals.
            try requireUnlocked()
            let generation: UInt64
            if let old = st.content.destruction?.duress, old.fileID != content.destruction?.duress?.fileID {
                // Vernichtungs-Passwort ersetzt oder entfernt: Sein Umschlag war ein Schlüssel-Slot für den DEK, also
                // ein Zugangswechsel (§1.2, v4.4) – neuer DEK, sonst öffnete eine Kopie der alten Ablage mit dem alten
                // Vernichtungs-Passwort (und den Faktoren) auch jede spätere Tresordatei.
                generation = try rekeyAndSave(st, content: content, password: pw, factors: factors)
            } else {
                generation = try save(st, content: content, reason: nil)
            }

            // Ab hier ist die Datei geschrieben: nichts wirft mehr (Befund datei-1). Sonst hielte die Oberfläche den
            // Vorgang für gescheitert und vernichtete das neue V, an dem die eben markierten Einträge hängen.
            // Erst nach erfolgreichem Schreiben: ersetztes bzw. nicht mehr gebrauchtes V vernichten.
            if let old = st.content.destruction?.vKey, old.keyID != plan.vKey?.keyID {
                store.eraseDestructionKey(old.keyID)
            }
            if let v = plan.vKey { try? FileIO.setExcludedFromBackup(store.hardwareKeyURL(v.keyID)) }
            guard plan.newlyMarked else { return nil }
            // Ältere Sicherungen enthielten die neu markierten Einträge noch mit Notfall-Umschlag (§23.1). Scheitert das
            // Entfernen, steht es im Bericht (`interrupted`); die Oberfläche meldet dann, dass sie noch da sein können.
            do {
                return try store.purgeBackups(vaultID: st.header.uuid, generation: generation)
            } catch {
                var report = PurgeReport()
                report.interrupted = true
                return report
            }
        }
    }

    /// Vernichtete Einträge endgültig entfernen (nach der Meldung „n Einträge wurden vernichtet“). Danach ist die
    /// Selbstvernichtung aus (V ist verbraucht; neu einrichten mit neuem V). Nichts vernichtet → nichts. In einer
    /// Vernichtungs-Sitzung ohne Wirkung.
    public func removeDestroyedEntries() throws {
        guard !isDuressSession else { return }
        try writeLock.withLock {
            let s = try snapshot()
            guard destructionKeyDestroyed(s.content) else { return }
            var content = s.content
            content.dropDestructibleEntries()
            try save(s, content: content, reason: nil)
        }
    }

    // MARK: - Interna

    /// Speichern mit neuem DEK und neuem Salz (gleiche Stufe, Faktoren, Kit und KDF). Nur unter `writeLock`, nach
    /// geprüftem Zugang (`pw`, `factors` = alle Faktoren der Stufe). Ein Argon2. Gesperrt → `io("vault.locked")`,
    /// ohne zu schreiben; liefert die geschriebene Generation und wirft nach dem Schreiben nicht mehr.
    @discardableResult
    func rekeyAndSave(_ s: State, content: VaultContent, password pw: SecureBytes,
                      factors: FactorSecrets) throws -> UInt64 {
        let (header, slots, dek) = try store.rekey(vaultID: s.header.vaultID, kdf: s.header.kdf,
                                                   fields: s.header.factorFields, scheme: s.header.recoveryScheme,
                                                   pk: s.header.pk, password: pw, factors: factors)
        let tagKey = try MasterTag.key(dek: dek)
        let tag = try MasterTag.tag(key: tagKey, password: pw)
        try requireUnlocked()
        let result = try store.persist(header: header, slots: slots, dek: dek, content: content,
                                       baseGeneration: s.generation,
                                       expectation: .generation(s.header.uuid, s.generation), reason: nil,
                                       duressBinding: s.duressBinding, newDEK: true)
        let reuse = Self.reuseSet(result.content, tagKey: tagKey, masterTag: tag, masterReuseTags: s.masterReuseTags)
        commit { st in
            st.header = header
            st.slots = slots
            st.dek = dek
            st.content = result.content
            st.generation = result.generation
            st.tagKey = tagKey
            st.masterTag = tag
            st.reuse = reuse
            st.pending = nil
            st.migrationKEK = nil
        }
        return result.generation
    }

    /// Ist das V dieses Inhalts im Zustand als vernichtet vermerkt?
    func destructionKeyDestroyed(_ content: VaultContent) -> Bool {
        guard let v = content.destruction?.vKey else { return false }
        return store.destroyedKeyID() == v.keyID
    }

    /// Ist `pw` das Vernichtungs-Passwort? (ein Argon2 mit dSalt, Vergleich des Prüfwerts)
    func isDuressPassword(_ pw: SecureBytes, _ d: DestructionConfig.Duress, vaultID: [UInt8],
                          kdf: KDFParameters) throws -> Bool {
        let dd = try DuressCrypto.derive(password: pw, salt: d.salt, kdf: kdf, limits: store.limits)
        return constantTimeEqual(try DuressCrypto.check(d: dd, vaultID: vaultID), d.check)
    }

    /// Neues Vernichtungs-Passwort: dSalt, Argon2 mit den Parametern des Kopfes, Schlüsselpaar und Prüfwert.
    private func makeDuress(_ password: String, vaultID: [UInt8], kdf: KDFParameters) throws -> DestructionConfig.Duress {
        let dpw = try PasswordNormalizer.secureBytes(password)
        let salt = randomBytes(DuressCrypto.saltBytes)
        let d = try DuressCrypto.derive(password: dpw, salt: salt, kdf: kdf, limits: store.limits)
        return DestructionConfig.Duress(fileID: UUID(), salt: salt, check: try DuressCrypto.check(d: d, vaultID: vaultID),
                                        pk: try DuressCrypto.publicKeys(d: d, vaultID: vaultID))
    }

    /// Geprüfte Eingaben (ohne Zustand).
    struct DestructionRequest {
        let settings: DestructionSettings
        let destructible: Set<UUID>
        let vKey: DestructionConfig.VKey?
        /// Bringt die Anfrage ein neues Vernichtungs-Passwort mit (das Passwort selbst wird hier nicht gehalten)?
        let hasNewDuressPassword: Bool

        init(settings: DestructionSettings, duressPassword: String?, destructible: Set<UUID>, masterPassword: String,
             vKey: EntryKeyEnrollment?) throws {
            try settings.validate()
            if let dpw = duressPassword {
                guard settings.duressEnabled else { throw SiegelError.io("destruction.duressPassword") }
                let policy = MasterPasswordPolicy.check(PasswordNormalizer.normalize(dpw))
                guard policy.ok else { throw SiegelError.passwordTooWeak(bits: policy.bits) }
                guard !VaultStore.passwordsMatch(dpw, masterPassword) else { throw SiegelError.masterPasswordReused }
            }
            if let vKey {
                guard !VaultHeader.bytes(of: vKey.keyID).allSatisfy({ $0 == 0 }) else {
                    throw SiegelError.crypto("factor.keyID")
                }
                let k = try UnlockedVault.entryKey(vKey)
                self.vKey = DestructionConfig.VKey(keyID: k.keyID, publicKey: k.publicKey)
            } else {
                self.vKey = nil
            }
            self.settings = settings
            self.destructible = destructible
            self.hasNewDuressPassword = duressPassword != nil
        }
    }

    struct DestructionPlan {
        /// Selbstvernichtung danach eingeschaltet (ein Auslöser oder vernichtbare Einträge).
        let active: Bool
        let vKey: DestructionConfig.VKey?
        /// Einträge, die neu versiegelt werden (markieren, entmarkieren).
        let reseal: Set<UUID>
        let newlyMarked: Bool
    }

    /// Regeln vor jeder Rechnung (§23): Stufe, Schutz, V, Vernichtungs-Passwort, nichts Vernichtetes offen.
    func destructionPlan(_ r: DestructionRequest, state st: State) throws -> DestructionPlan {
        let content = st.content
        let destroyed = destructionKeyDestroyed(content)
        if destroyed { throw SiegelError.io("destruction.destroyed") }
        let active = r.settings.anyTriggerEnabled || !r.destructible.isEmpty
        if active, content.level < .maximal { throw SiegelError.notAllowedAtLevel }
        for id in r.destructible {
            guard let i = visibleIndex(content, id) else { throw SiegelError.io("entry.notFound") }
            let p = content.entries[i].protection
            guard p >= .maximal else { throw SiegelError.notAllowedAtLevel }
            try EntrySealing.requireEnrolled(p.factors.subtracting(.secureEnclave), content.entryFactors)
        }
        let current = content.destructibleIDs
        let old = content.destruction?.vKey
        let v = active ? (r.vKey ?? old) : nil
        if active, v == nil { throw SiegelError.factorMissing(.secureEnclave) }
        if let nv = v {
            let taken = [content.entryFactors.deviceKeyID, st.header.factorFields.seKeyID].compactMap { $0 }
            guard !taken.contains(nv.keyID) else { throw SiegelError.crypto("factor.keyID") }
        }
        // Ein anderes V geht nur, solange keine vernichtbaren Einträge an das bisherige gebunden bleiben.
        if let nv = v, let ov = old, nv != ov, !current.intersection(r.destructible).isEmpty {
            throw SiegelError.notAllowedAtLevel
        }
        if r.settings.duressEnabled, content.destruction?.duress == nil, !r.hasNewDuressPassword {
            throw SiegelError.io("destruction.duressPassword")
        }
        let toMark = r.destructible.subtracting(current)
        let toUnmark = current.subtracting(r.destructible)
        return DestructionPlan(active: active, vKey: v, reseal: toMark.union(toUnmark), newlyMarked: !toMark.isEmpty)
    }

    /// Geheimteile der neu zu versiegelnden Einträge: neu markierte über ihre Notfall-Gruppe (eine Freigabe je
    /// Gruppe), entmarkierte über V (je Eintrag).
    private func openForResealing(_ ids: Set<UUID>, state st: State,
                                  provider: EntryFactorProvider) async throws -> [UUID: OpenedEntry] {
        var out: [UUID: OpenedEntry] = [:]
        let list = st.content.entries.filter { ids.contains($0.id) && $0.secretsSealed }
        let viaGroups = list.filter { st.content.sealed[$0.id] != nil }
        if !viaGroups.isEmpty {
            let masks = Set(viaGroups.map { $0.protection.factors.rawValue })
            let groups = st.content.recoveryGroups.filter { masks.contains($0.mask.rawValue) }
                .sorted { $0.mask.rawValue < $1.mask.rawValue }
            guard groups.count == masks.count else { throw SiegelError.corruptFile("entry.sealed") }
            let released = try await releaseGroups(groups, state: st, provider: provider)
            let opened = try st.content.secretsViaGroups(for: viaGroups, released: released, vaultID: st.header.vaultID)
            for (id, secrets) in opened {
                out[id] = OpenedEntry(secrets: secrets, sealed: st.content.sealed[id], destructible: nil)
            }
        }
        for e in list where st.content.destructible[e.id] != nil {
            out[e.id] = OpenedEntry(secrets: try await revealDestructible(e, state: st, provider: provider), sealed: nil,
                                    destructible: st.content.destructible[e.id])
        }
        return out
    }
}

extension VaultStore {
    /// Kennung des als vernichtet vermerkten V (aus dem Zustand dieses Tresors), sonst nil.
    func destroyedKeyID() -> UUID? {
        destructionLock.withLock { currentState()?.destroyed?.keyID }
    }
}

/// Hält Karte und Sicherheitsschlüssel für die Dauer eines Aufrufs (Markieren/Entmarkieren vieler Einträge);
/// Touch ID wird für jeden Eintrag neu verlangt.
final class CachingEntryFactors: EntryFactorProvider, @unchecked Sendable {
    private let base: EntryFactorProvider
    private let lock = NSLock()
    private var card: FactorSecret?
    private var keyOutputs: [Data: FactorSecret] = [:]

    init(_ base: EntryFactorProvider) { self.base = base }

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        try await base.secureEnclaveSharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey)
    }

    func cardSecret() async throws -> FactorSecret {
        if let q = lock.withLock({ card }) { return q }
        let q = try await base.cardSecret()
        lock.withLock { card = q }
        return q
    }

    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
        let key = credentialID + salt
        if let y = lock.withLock({ keyOutputs[key] }) { return y }
        let y = try await base.securityKeyOutput(credentialID: credentialID, salt: salt)
        lock.withLock { keyOutputs[key] = y }
        return y
    }
}
