import Foundation

// Notfallkit im entsperrten Tresor (SPEC §1.5, §15): vorbereiten, bestätigen, bestehendes Kit bestätigen,
// Sicherungen entfernen.

extension UnlockedVault {
    /// Neues Kit mit dem Schema der Stufe, ohne Faktoren (Stufe 1 bzw. Format v1).
    public func prepareRecovery(masterPassword: String) throws -> PendingRecovery {
        try prepareRecovery(masterPassword: masterPassword, factors: FactorSecrets(), scheme: level.recoveryScheme)
    }

    /// Bereitet ein neues Notfallkit vor (nichts geschrieben, alter Code bleibt gültig). `.single`: ein Code mit zwei
    /// Bestätigungsgruppen; `.shamir2of3`: drei Teile mit je einer Bestätigungsgruppe (`code.formatted` bleibt dann
    /// leer, damit nie ein ganzer Code entsteht). Zwei Argon2-Läufe: Prüfung von Passwort + Faktoren und KEK_pw mit
    /// neuem Salz für das spätere Schreiben. Ein Kit mit anderem Schema als die Stufe lässt sich nur über
    /// `changeSecurityLevel` schreiben.
    public func prepareRecovery(masterPassword: String, factors: FactorSecrets,
                                scheme: RecoveryScheme) throws -> PendingRecovery {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        return try writeLock.withLock {
            let s = try snapshot()
            try verifyAccess(pw, factors, s)
            let r = try SecureBytes.random(count: RecoveryKEM.rBytes)
            let pk = try RecoveryKEM.derivePublicKeys(r: r, vaultID: s.header.vaultID)
            let header = try s.header.rebuilt(salt: randomBytes(KDF.saltBytes), recoveryScheme: scheme, pk: pk)
            let p = try KDF.deriveKEK(password: pw, salt: header.salt, params: header.kdf, limits: store.limits)
            let kek = try FactorKDF.kek(p: p, header: header, factors: factors)
            let dek = try SecureBytes.random(count: AEAD.keyBytes)
            let tagKey = try MasterTag.key(dek: dek)
            let tag = try MasterTag.tag(key: tagKey, password: pw)
            try setPending(PendingKit(r: r, scheme: scheme, header: header, kekPw: kek, dek: dek, tagKey: tagKey,
                                      masterTag: tag, basedOnSalt: s.header.salt))
            switch scheme {
            case .single:
                let code = RecoveryCode(formatted: try RecoveryCodeCodec.format(r: r), kitID: pk.kitID)
                return PendingRecovery(code: code, confirmationGroups: VaultStore.randomConfirmationGroups())
            case .shamir2of3:
                let ys = try Shamir.split(r)
                let shares = try ys.enumerated().map { i, y in
                    RecoveryShare(index: i + 1, formatted: try Shamir.format(x: UInt8(i + 1), y: y), kitID: pk.kitID)
                }
                let groups = (0..<Shamir.shareCount).map { _ in Int(secureUniform(UInt32(Shamir.fullGroups))) }
                return PendingRecovery(code: RecoveryCode(formatted: "", kitID: pk.kitID), confirmationGroups: [],
                                       scheme: .shamir2of3, shares: shares, shareConfirmationGroups: groups)
            }
        }
    }

    /// Bestätigt ein Kit: `.single` mit den zwei verlangten Gruppen, `.shamir2of3` mit drei (je Teil eine, in der
    /// Reihenfolge von `shares`). Neues Kit → DEK-Rotation, angeheftete Sicherung „vor-neues-kit“, alter Code ungültig.
    /// Bereits gültiges Kit (aus `create`) → nur `recoveryConfirmedAt` setzen.
    /// Falsche Gruppen → `recoveryConfirmationMismatch`, nichts geschrieben.
    /// Mit versiegelten Einträgen braucht ein neues Kit die async-Variante (`entryFactors:`), hier → `factorMissing`.
    public func commitRecovery(_ pending: PendingRecovery, confirmation: [String]) throws {
        try commitRecovery(pending, confirmation: confirmation, releasedGroups: [:])
    }

    /// Kern von `commitRecovery`: `releasedGroups` = ERS je Notfall-Gruppe für das neue Kit.
    func commitRecovery(_ pending: PendingRecovery, confirmation: [String],
                        releasedGroups: [UUID: SecureBytes]) throws {
        try Self.checkConfirmation(pending, confirmation)
        let r = try Self.secret(of: pending)
        try writeLock.withLock {
            let s = try snapshot()
            if let p = s.pending, p.r.constantTimeEquals(r) {
                guard p.basedOnSalt == s.header.salt else { throw SiegelError.crypto("recovery.pendingStale") }
                guard p.scheme == s.content.level.recoveryScheme else { throw SiegelError.notAllowedAtLevel }
                var content = s.content
                content.recoveryConfirmedAt = Clock.now()
                try content.rewrapRecoveryGroups(released: releasedGroups, kit: p.header.pk, vaultID: s.header.vaultID)
                let slots = try VaultCrypto.makeSlots(header: p.header, kekPw: p.kekPw, dek: p.dek)
                // Gleiche Faktoren (der Kopf wurde nur mit neuem Salz und Kit neu gebaut) → F bleibt.
                try requireUnlocked()
                let result = try store.persist(header: p.header, slots: slots, dek: p.dek, content: content,
                                               baseGeneration: s.generation,
                                               expectation: .generation(s.header.uuid, s.generation),
                                               reason: BackupNaming.Reason.newKit.rawValue,
                                               duressBinding: s.duressBinding, newDEK: true)
                let reuse = Self.reuseSet(result.content, tagKey: p.tagKey, masterTag: p.masterTag,
                                          masterReuseTags: s.masterReuseTags)
                commit { st in
                    st.header = p.header
                    st.slots = slots
                    st.dek = p.dek
                    st.content = result.content
                    st.generation = result.generation
                    st.tagKey = p.tagKey
                    st.masterTag = p.masterTag
                    st.reuse = reuse
                    st.pending = nil
                    st.migrationKEK = nil
                }
            } else if RecoveryKEM.matches(r: r, vaultID: s.header.vaultID, expected: s.header.pk) {
                var content = s.content
                content.recoveryConfirmedAt = Clock.now()
                try save(s, content: content, reason: nil)
            } else {
                throw SiegelError.crypto("recovery.pendingStale")
            }
        }
    }

    /// Prüft die eingetippten Bestätigungsgruppen (Gross/Klein, Leerraum, O/I/L egal).
    static func checkConfirmation(_ pending: PendingRecovery, _ confirmation: [String]) throws {
        func same(_ typed: String, _ group: String) -> Bool { RecoveryCodeCodec.normalizedGroup(typed) == group }
        switch pending.scheme {
        case .single:
            let groups = pending.code.groups
            guard pending.confirmationGroups.count == 2, confirmation.count == 2,
                  groups.count == RecoveryCodeCodec.groupCount else {
                throw SiegelError.recoveryConfirmationMismatch
            }
            for (k, idx) in pending.confirmationGroups.enumerated() {
                guard idx >= 0, idx < groups.count, same(confirmation[k], groups[idx]) else {
                    throw SiegelError.recoveryConfirmationMismatch
                }
            }
        case .shamir2of3:
            guard pending.shares.count == Shamir.shareCount, pending.shareConfirmationGroups.count == Shamir.shareCount,
                  confirmation.count == Shamir.shareCount else {
                throw SiegelError.recoveryConfirmationMismatch
            }
            for (k, idx) in pending.shareConfirmationGroups.enumerated() {
                let groups = pending.shares[k].groups
                guard idx >= 0, idx < Shamir.fullGroups, idx < groups.count, same(confirmation[k], groups[idx]) else {
                    throw SiegelError.recoveryConfirmationMismatch
                }
            }
        }
    }

    /// R eines vorbereiteten Kits: aus dem Code bzw. aus den Teilen (alle drei müssen dasselbe R ergeben).
    static func secret(of pending: PendingRecovery) throws -> SecureBytes {
        switch pending.scheme {
        case .single:
            return try RecoveryCodeCodec.decode(pending.code.formatted)
        case .shamir2of3:
            guard pending.shares.count == Shamir.shareCount else { throw SiegelError.recoveryConfirmationMismatch }
            let f = pending.shares.map(\.formatted)
            let r = try VaultStore.combineShares([f[0], f[1]])
            let check = try VaultStore.combineShares([f[1], f[2]])
            guard r.constantTimeEquals(check) else { throw SiegelError.recoveryConfirmationMismatch }
            return r
        }
    }

    /// Löscht alle Sicherungen dieser vaultID (auch angeheftete) und legt sofort eine des aktuellen Stands an.
    /// Der Bericht nennt, was sich nicht entfernen liess (z. B. zweiter Ort nicht erreichbar).
    @discardableResult
    public func purgeBackups() throws -> PurgeReport {
        try writeLock.withLock {
            let s = try snapshot()
            return try store.purgeBackups(vaultID: s.header.uuid, generation: s.generation)
        }
    }

    /// Bestätigt das bestehende Notfallkit mit dem **ganzen** Code (z. B. nach „Später bestätigen“ oder nach
    /// einer Wiederherstellung): passt er exakt zu den öffentlichen Schlüsseln im Kopf, wird
    /// `recoveryConfirmedAt` gesetzt; sonst `wrongRecoveryCode` (bzw. Format-/Prüfsummenfehler).
    /// Zwei Gruppen genügen hier nicht: Der Code ist nirgends gespeichert, prüfen lässt sich nur der ganze.
    /// Zusatz zur Schnittstelle in §8 (SPEC v3.1).
    public func confirmExistingRecovery(code: String) throws {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try confirmExisting(r: try RecoveryCodeCodec.decode(code))
    }

    /// Wie `confirmExistingRecovery(code:)`, mit zwei ganzen Teilen (Stufen 4/5). Zusatz zu §22.
    public func confirmExistingRecovery(shares: [String]) throws {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try confirmExisting(r: try VaultStore.combineShares(shares))
    }

    private func confirmExisting(r: SecureBytes) throws {
        try writeLock.withLock {
            let s = try snapshot()
            guard RecoveryKEM.matches(r: r, vaultID: s.header.vaultID, expected: s.header.pk) else {
                let codeKit = try RecoveryKEM.derivePublicKeys(r: r, vaultID: s.header.vaultID).kitID
                throw SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: s.header.pk.kitID)
            }
            guard s.content.recoveryConfirmedAt == nil else { return }
            var content = s.content
            content.recoveryConfirmedAt = Clock.now()
            try save(s, content: content, reason: nil)
        }
    }
}
