import Foundation

// Eintrags-Schutz im Inhalt (SPEC §16, §17): versiegeln, Notfall-Gruppen pflegen, mit dem Notfallcode alles
// entsiegeln, Metadaten für den Bericht, Konsistenzregeln.

extension VaultContent {
    // MARK: - Schlüssel

    /// Grundschlüssel sicherstellen (ältere Inhalte haben keinen; er entsteht beim ersten Speichern).
    @discardableResult
    mutating func ensureEntryKey() throws -> SecureBytes {
        if let k = entryKey { return k.key }
        let k = try EntryBaseKey.generate()
        entryKey = k
        return k.key
    }

    func sealingKeys(vaultID: [UInt8]) throws -> EntrySealing.Keys {
        guard let k = entryKey else { throw SiegelError.crypto("entry.baseKey") }
        return EntrySealing.Keys(vaultID: vaultID, base: k.key, factors: entryFactors)
    }

    func reuseKey() throws -> SecureBytes {
        guard let k = entryKey else { throw SiegelError.crypto("entry.baseKey") }
        return try EntrySealing.reuseKey(k.key)
    }

    /// reuseTags des Master-Passworts (§17, v4.4); leer ohne Grundschlüssel. Zuerst der Tag der nach §1.1
    /// normalisierten Bytes (gleiche Abbildung wie für Eintragspasswörter); enthält die rohe Eingabe ein Zs-Zeichen
    /// ausser U+0020, dazu der Tag nach der Formel bis v4.3 (nur NFC): Versiegelte Einträge aus dieser Zeit tragen ihn
    /// noch, bis sie neu versiegelt werden, und werden so erkannt, wenn das Master-Passwort genau so getippt ist.
    func masterReuseTags(_ password: SecureBytes, raw: String?) -> [[UInt8]] {
        guard let rk = try? reuseKey() else { return [] }
        var out: [[UInt8]] = []
        if let t = password.withUnsafeBytes({ EntrySealing.reuseTag(key: rk, bytes: $0) }) { out.append(t) }
        if let raw, let legacy = EntrySealing.legacyReuseTag(key: rk, password: raw) { out.append(legacy) }
        return out
    }

    /// Faktorarten, an denen versiegelte Einträge hängen (diese Eintrags-Faktoren dürfen nicht ersetzt werden).
    /// Vernichtbare Einträge hängen statt am Eintrags-SE-Schlüssel am Vernichtungsschlüssel V (§23.1).
    var sealedKinds: FactorSet {
        var s: FactorSet = []
        for e in entries where e.secretsSealed {
            let mask = e.protection.factors
            s.formUnion(destructible[e.id] != nil ? mask.subtracting(.secureEnclave) : mask)
        }
        return s
    }

    /// Gruppen, die versiegelte Einträge brauchen (in Maskenreihenfolge). Vernichtbare haben keinen Notfall-Umschlag.
    var neededRecoveryGroups: [RecoveryGroup] {
        var used = Set<UInt8>()
        for e in entries where e.secretsSealed && destructible[e.id] == nil { used.insert(e.protection.factors.rawValue) }
        return recoveryGroups.filter { used.contains($0.mask.rawValue) }.sorted { $0.mask.rawValue < $1.mask.rawValue }
    }

    // MARK: - Versiegeln

    /// Geheimteile von `entries[i]` (Klartext) mit dessen Schutz versiegeln: Metadaten (§17) aus dem Klartext,
    /// Blob, Notfall-Umschlag an die Gruppe der Maske (neu, falls es noch keine gibt). Danach sind die Felder leer und
    /// `secretsSealed` gesetzt. Braucht nur öffentliche Schlüssel und den Grundschlüssel.
    mutating func seal(at i: Int, vaultID: [UInt8], kit: RecoveryPublicKeys, now: Date) throws {
        let e = entries[i]
        let p = e.protection
        guard p > .normal, !e.secretsSealed else { throw SiegelError.crypto("entry.sealedState") }
        let mask = p.factors
        try EntrySealing.requireEnrolled(mask, entryFactors)
        try ensureEntryKey()
        let keys = try sealingKeys(vaultID: vaultID)
        meta[e.id] = EntrySealing.meta(password: e.password, previous: meta[e.id],
                                       reuseKey: try EntrySealing.reuseKey(keys.base),
                                       fallbackChanged: Self.estimatedPasswordChange(e), now: now)
        let plaintext = try EntrySealing.encodeSecrets(EntrySecrets(password: e.password, notes: e.notes, totp: e.totp,
                                                                    history: e.history))
        let s = UInt8(p.rawValue)
        let (blob, k) = try EntrySealing.seal(plaintext, id: e.id, s: s, mask: mask, adLabel: EntrySealing.entryAD,
                                              keys: keys)
        let group = try recoveryGroup(for: mask, keys: keys, kit: kit)
        let recovery = try EntrySealing.recoveryWrap(k: k, id: e.id, s: s, mask: mask, group: group.pk, vaultID: vaultID)
        sealed[e.id] = SealedSecrets(blob: blob, recovery: recovery)
        entries[i].password = ""
        entries[i].notes = ""
        entries[i].totp = ""
        entries[i].history = []
        entries[i].secretsSealed = true
    }

    private mutating func recoveryGroup(for mask: FactorSet, keys: EntrySealing.Keys,
                                        kit: RecoveryPublicKeys) throws -> RecoveryGroup {
        if let g = recoveryGroups.first(where: { $0.mask == mask }) { return g }
        let g = try EntrySealing.makeGroup(mask: mask, keys: keys, kit: kit)
        recoveryGroups.append(g)
        return g
    }

    /// Letzte Passwortänderung, wenn es keine Metadaten gibt: jüngster Verlaufseintrag (da wurde das jetzige Passwort
    /// gesetzt), sonst das Anlegen.
    static func estimatedPasswordChange(_ e: VaultEntry) -> Date {
        e.history.map(\.changed).max() ?? e.created
    }

    /// Entry mit aufgedeckten Geheimteilen (Schutz bleibt, `secretsSealed` aus).
    static func unsealed(_ e: VaultEntry, with s: EntrySecrets) -> VaultEntry {
        var out = e
        out.password = s.password
        out.notes = s.notes
        out.totp = s.totp
        out.history = s.history
        out.secretsSealed = false
        return out
    }

    // MARK: - Notfall: alles entsiegeln

    /// Mit R (Notfallcode) alle versiegelten Einträge entsiegeln: Kit → Gruppen → Umschläge → Blobs. Danach gibt es
    /// keine versiegelten Teile und keine Gruppen mehr (Schutz und Stufe setzt `resetAfterRecovery`). Nach bestandener
    /// Kit-Prüfung ist jedes Scheitern `corruptFile` (wie §1.3).
    ///
    /// Vernichtbare Einträge (§23.1) haben keinen Notfallweg: Sie fallen hier ganz weg (mit Metadaten), die
    /// Selbstvernichtung ist danach aus. Sonst wäre die Vernichtung über den Notfallcode umgehbar.
    mutating func unsealAll(r: SecureBytes, header: VaultHeader) throws {
        dropDestructibleEntries()
        let needed = neededRecoveryGroups
        if !needed.isEmpty {
            guard let kitKeys = EntrySealing.kitPrivateKeys(r: r, header: header) else {
                throw SiegelError.corruptFile("entry.recovery")
            }
            var groupKeys: [UInt8: HybridPrivateKeys] = [:]
            for g in needed { groupKeys[g.mask.rawValue] = try EntrySealing.openGroup(g, kit: kitKeys, vaultID: header.vaultID) }
            for i in entries.indices where entries[i].secretsSealed {
                let e = entries[i]
                guard let x = sealed[e.id], let gk = groupKeys[e.protection.factors.rawValue] else {
                    throw SiegelError.corruptFile("entry.recovery")
                }
                entries[i] = Self.unsealed(e, with: try Self.openViaGroup(x, entry: e, group: gk, vaultID: header.vaultID))
            }
        }
        guard !entries.contains(where: \.secretsSealed) else { throw SiegelError.corruptFile("entry.recovery") }
        sealed = [:]
        recoveryGroups = []
    }

    /// Vernichtbare Einträge samt Metadaten entfernen und die Selbstvernichtung ausschalten (Notfallweg).
    mutating func dropDestructibleEntries() {
        let doomed = Set(destructible.keys)
        if !doomed.isEmpty {
            entries.removeAll { doomed.contains($0.id) }
            for id in doomed { meta[id] = nil }
        }
        destructible = [:]
        destruction = nil
    }

    /// Geheimteile über den Notfall-Umschlag (Gruppen-Schlüssel statt Faktoren).
    static func openViaGroup(_ x: SealedSecrets, entry e: VaultEntry, group: HybridPrivateKeys,
                             vaultID: [UInt8]) throws -> EntrySecrets {
        let s = UInt8(e.protection.rawValue)
        let mask = e.protection.factors
        let k = try EntrySealing.openRecoveryWrap(x.recovery, id: e.id, s: s, mask: mask, group: group, vaultID: vaultID)
        guard let padded = AEAD.open(key: k, nonce: x.blob.nonce, ciphertext: x.blob.ciphertext,
                                     ad: EntrySealing.ad(EntrySealing.entryAD, vaultID: vaultID,
                                                         id: EntrySealing.idBytes(e.id), s: s, mask: mask)) else {
            throw SiegelError.corruptFile("entry.recovery")
        }
        return try EntrySealing.decodeSecrets(padded)
    }

    /// Geheimteile versiegelter Einträge über freigegebene Gruppen (ERS je Gruppen-ID), z. B. für den Export.
    func secretsViaGroups(for list: [VaultEntry], released: [UUID: SecureBytes],
                          vaultID: [UInt8]) throws -> [UUID: EntrySecrets] {
        var keysByMask: [UInt8: HybridPrivateKeys] = [:]
        var out: [UUID: EntrySecrets] = [:]
        for e in list where e.secretsSealed {
            let mask = e.protection.factors
            guard let x = sealed[e.id], let g = recoveryGroups.first(where: { $0.mask == mask }) else {
                throw SiegelError.corruptFile("entry.sealed")
            }
            let gk: HybridPrivateKeys
            if let known = keysByMask[mask.rawValue] {
                gk = known
            } else {
                guard let ers = released[g.id] else { throw SiegelError.factorMissing(mask.kinds.first ?? .secureEnclave) }
                guard let k = EntrySealing.groupPrivateKeys(ers: ers, vaultID: vaultID, expected: g.pk) else {
                    throw SiegelError.corruptFile("entry.anchor")
                }
                keysByMask[mask.rawValue] = k
                gk = k
            }
            out[e.id] = try Self.openViaGroup(x, entry: e, group: gk, vaultID: vaultID)
        }
        return out
    }

    /// Neues Kit: alle gebrauchten Gruppen an die neuen öffentlichen Schlüssel kapseln (ERS je Gruppe aus der
    /// Freigabe der Anker). Fehlt eine Freigabe → `factorMissing` (erste Faktorart der Gruppe). Ungebrauchte Gruppen
    /// fallen weg.
    mutating func rewrapRecoveryGroups(released: [UUID: SecureBytes], kit: RecoveryPublicKeys,
                                       vaultID: [UInt8]) throws {
        pruneRecoveryGroups()
        for i in recoveryGroups.indices {
            let g = recoveryGroups[i]
            guard let ers = released[g.id] else { throw SiegelError.factorMissing(g.mask.kinds.first ?? .secureEnclave) }
            guard EntrySealing.groupPrivateKeys(ers: ers, vaultID: vaultID, expected: g.pk) != nil else {
                throw SiegelError.corruptFile("entry.anchor")
            }
            recoveryGroups[i].kit = try EntrySealing.wrapToKit(ers: ers, groupID: g.id, mask: g.mask, kit: kit,
                                                               vaultID: vaultID)
        }
    }

    mutating func pruneRecoveryGroups() {
        let needed = Set(neededRecoveryGroups.map(\.id))
        recoveryGroups.removeAll { !needed.contains($0.id) }
    }

    /// Kommt das (normalisierte) Passwort als aktuelles Passwort eines versiegelten Eintrags vor (über reuseTag)?
    /// `raw` = Eingabe vor der Abbildung (für Tags nach der Formel bis v4.3, siehe `masterReuseTags`).
    func isUsedBySealedEntries(_ password: SecureBytes, raw: String?) -> Bool {
        let tags = masterReuseTags(password, raw: raw)
        guard !tags.isEmpty else { return false }
        return entries.contains { e in
            guard e.secretsSealed, let tag = meta[e.id]?.tag else { return false }
            return tags.contains { constantTimeEqual(tag, $0) }
        }
    }

    // MARK: - Speichern

    /// Vor jedem Speichern (nach `prepareForSave`): Grundschlüssel sicherstellen, verwaiste Teile und ungebrauchte
    /// Gruppen entfernen, Metadaten offener Einträge nachführen (versiegelte bekommen sie beim Versiegeln).
    mutating func prepareEntryData(now: Date) throws {
        try ensureEntryKey()
        let ids = Set(entries.map(\.id))
        sealed = sealed.filter { ids.contains($0.key) }
        destructible = destructible.filter { ids.contains($0.key) }
        meta = meta.filter { ids.contains($0.key) }
        if destruction?.isEmpty == true { destruction = nil }
        pruneRecoveryGroups()
        let rk = try reuseKey()
        for e in entries where !e.secretsSealed {
            meta[e.id] = EntrySealing.meta(password: e.password, previous: meta[e.id], reuseKey: rk,
                                           fallbackChanged: Self.estimatedPasswordChange(e), now: now)
        }
    }

    // MARK: - Konsistenz

    /// Regeln des Eintrags-Schutzes. Beim Lesen → `corruptFile`, beim Schreiben → `crypto` (Programmfehler).
    /// Schutz 1 ⇔ offen; Schutz ≥ 2 ⇔ versiegelt mit genau den Faktor-Teilen der Maske, leeren Klartextfeldern,
    /// Metadaten, eingerichteten Faktoren und einer Gruppe für die Maske.
    func checkSealing(_ fail: (String) -> SiegelError) throws {
        var masks = Set<UInt8>()
        var groupIDs = Set<UUID>()
        for g in recoveryGroups {
            guard EntrySealing.validMasks.contains(g.mask), masks.insert(g.mask.rawValue).inserted,
                  groupIDs.insert(g.id).inserted,
                  g.pk.pkM.count == RecoveryPublicKeys.pkMBytes, g.pk.pkX.count == RecoveryPublicKeys.pkXBytes,
                  g.kit.isWellFormed, g.anchor.isWellFormed, g.anchor.factors.mask == g.mask,
                  deviceArtMatches(g.anchor.factors, destructible: false),
                  entryFactors.enrolled.isSuperset(of: g.mask), entryKey != nil else {
                throw fail("payload.recoveryGroup")
            }
        }
        for m in meta.values {
            if let t = m.tag, t.count != EntrySealing.reuseTagBytes { throw fail("payload.meta") }
            if let s = m.strength, !(0...4).contains(s) { throw fail("payload.meta") }
        }
        try checkDestruction(fail)
        var ids = Set<UUID>()
        var sealedIDs = Set<UUID>()
        var destructibleIDs = Set<UUID>()
        for e in entries {
            if !sealed.isEmpty || !destructible.isEmpty, !ids.insert(e.id).inserted { throw fail("payload.duplicateID") }
            if e.protection == .normal {
                guard sealed[e.id] == nil, destructible[e.id] == nil, !e.secretsSealed else {
                    throw fail("entry.sealedState")
                }
                continue
            }
            let mask = e.protection.factors
            guard e.secretsSealed, e.password.isEmpty, e.notes.isEmpty, e.totp.isEmpty, e.history.isEmpty,
                  meta[e.id] != nil, entryKey != nil else {
                throw fail("entry.sealedState")
            }
            if let b = destructible[e.id] {
                // Vernichtbar (§23.1): nur Schutz 4/5, nur Stufe 4/5, an V versiegelt, kein Notfall-Umschlag.
                guard sealed[e.id] == nil, e.protection >= .maximal, level >= .maximal, b.isWellFormed,
                      b.factors.mask == mask, destruction?.vKey != nil, deviceArtMatches(b.factors, destructible: true),
                      entryFactors.enrolled.isSuperset(of: mask.subtracting(.secureEnclave)) else {
                    throw fail("entry.sealedState")
                }
                destructibleIDs.insert(e.id)
                continue
            }
            guard let x = sealed[e.id], x.blob.isWellFormed, x.recovery.isWellFormed, x.blob.factors.mask == mask,
                  deviceArtMatches(x.blob.factors, destructible: false),
                  entryFactors.enrolled.isSuperset(of: mask), masks.contains(mask.rawValue) else {
                throw fail("entry.sealedState")
            }
            sealedIDs.insert(e.id)
        }
        guard sealedIDs.count == sealed.count, destructibleIDs.count == destructible.count else {
            throw fail("entry.sealedState")
        }
    }

    /// Die Art des Gerätefaktors eines Siegels passt zum eingerichteten Schlüssel (v4.6): Mac-Art ⇔ `"se"`,
    /// Windows Hello ⇔ `"hello"` (vernichtbar: nach der Art von V). Ohne Gerätefaktor in der Maske immer.
    func deviceArtMatches(_ f: SealedFactors, destructible: Bool) -> Bool {
        guard f.mask.contains(.secureEnclave) else { return true }
        let hello = destructible ? destruction?.vKey?.isWindowsHello == true : entryFactors.windowsHello != nil
        return hello ? f.hello != nil : f.seEphemeral != nil
    }

    /// Regeln der Selbstvernichtung im Inhalt (§23): Bereiche, `duressEnabled ⇔ duress`, eingeschaltet nur in Stufe
    /// 4/5 und nur mit V; V, Ablage-Kennung und Eintrags-SE-Schlüssel paarweise verschieden (den Entsperr-SE-Schlüssel
    /// des Kopfes prüft `destructionKeysAvoid(header:)`).
    /// Weder V noch die Ablage des Vernichtungs-Passworts heissen wie der Entsperr-SE-Schlüssel des Kopfes (Lesen:
    /// `VaultCrypto.decryptPayload`, Schreiben: `VaultStore.persist`). Tiefenverteidigung, v4.4.
    func destructionKeysAvoid(header: VaultHeader) -> Bool {
        guard let d = destruction, let se = header.factorFields.seKeyID else { return true }
        return d.vKey?.keyID != se && d.duress?.fileID != se
    }

    func checkDestruction(_ fail: (String) -> SiegelError) throws {
        guard let d = destruction else { return }
        guard (try? d.settings.validate()) != nil, d.settings.duressEnabled == (d.duress != nil), !d.isEmpty else {
            throw fail("payload.destruction")
        }
        if let v = d.vKey {
            guard v.isWellFormed, v.keyID != entryFactors.deviceKeyID else { throw fail("payload.destruction") }
        }
        if let x = d.duress {
            // Die Ablage-Kennung ist ein Dateiname im Hardware-Ordner: nie V oder der Eintrags-SE-Schlüssel (sonst
            // überschriebe das Kapseln beim Speichern bzw. echten Entsperren diese Schlüssel; v4.4, Tiefenverteidigung).
            guard x.salt.count == DuressCrypto.saltBytes, x.check.count == DuressCrypto.checkBytes,
                  x.pk.pkM.count == RecoveryPublicKeys.pkMBytes, x.pk.pkX.count == RecoveryPublicKeys.pkXBytes,
                  x.fileID != d.vKey?.keyID, x.fileID != entryFactors.deviceKeyID else {
                throw fail("payload.destruction")
            }
        }
        if d.settings.anyTriggerEnabled || !destructible.isEmpty {
            guard level >= .maximal, d.vKey != nil else { throw fail("payload.destruction") }
        }
    }
}
