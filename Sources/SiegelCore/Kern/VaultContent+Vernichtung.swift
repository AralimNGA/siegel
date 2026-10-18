import Foundation

// Selbstvernichtung im Inhalt (SPEC §23.1): vernichtbar versiegeln, Geheimteile wieder offenlegen (für das
// Neu-Versiegeln beim Markieren/Entmarkieren).

extension VaultContent {
    /// Kennungen der vernichtbaren Einträge (auch gelöschte).
    var destructibleIDs: Set<UUID> { Set(destructible.keys) }

    /// Geheimteile von `entries[i]` (Klartext, Schutz 4/5) vernichtbar versiegeln: an V statt an den
    /// Eintrags-SE-Schlüssel, **ohne** Notfall-Umschlag (§23.1). Metadaten (§17) wie beim normalen Versiegeln.
    /// Stufe < 4 oder Schutz < 4 → `notAllowedAtLevel`; kein V → `factorMissing(.secureEnclave)`.
    mutating func sealDestructible(at i: Int, vaultID: [UInt8], now: Date) throws {
        let e = entries[i]
        let p = e.protection
        guard !e.secretsSealed else { throw SiegelError.crypto("entry.sealedState") }
        guard p >= .maximal, level >= .maximal else { throw SiegelError.notAllowedAtLevel }
        guard let v = destruction?.vKey else { throw SiegelError.factorMissing(.secureEnclave) }
        // V der Windows-Hello-Art (v4.6): Versiegeln braucht dort eine Signatur – auf dem Mac ein anderes Gerät.
        guard !v.isWindowsHello else { throw SiegelError.factorUnavailable(.secureEnclave) }
        let mask = p.factors
        try EntrySealing.requireEnrolled(mask.subtracting(.secureEnclave), entryFactors)
        try ensureEntryKey()
        let keys = try sealingKeys(vaultID: vaultID)
        meta[e.id] = EntrySealing.meta(password: e.password, previous: meta[e.id],
                                       reuseKey: try EntrySealing.reuseKey(keys.base),
                                       fallbackChanged: Self.estimatedPasswordChange(e), now: now)
        let plaintext = try EntrySealing.encodeSecrets(EntrySecrets(password: e.password, notes: e.notes, totp: e.totp,
                                                                    history: e.history))
        let blob = try EntrySealing.sealDestructible(plaintext, id: e.id, s: UInt8(p.rawValue), mask: mask,
                                                     vKeyID: v.keyID, vPublicKey: v.publicKey, keys: keys)
        sealed[e.id] = nil
        destructible[e.id] = blob
        entries[i].password = ""
        entries[i].notes = ""
        entries[i].totp = ""
        entries[i].history = []
        entries[i].secretsSealed = true
    }

    /// Geheimteile in `entries[i]` einsetzen (offen, beide Siegel entfernt); danach neu versiegeln.
    mutating func replaceSecrets(at i: Int, with s: EntrySecrets) {
        let id = entries[i].id
        entries[i] = Self.unsealed(entries[i], with: s)
        sealed[id] = nil
        destructible[id] = nil
    }
}
