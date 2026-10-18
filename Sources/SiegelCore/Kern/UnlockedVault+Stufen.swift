import CryptoKit
import Foundation

// Sicherheitsstufen und Faktoren (SPEC §13, §14, §16, §22).

extension UnlockedVault {
    /// Faktoren für Einträge einrichten (öffentliche Teile in den verschlüsselten Inhalt; §16): Eintrags-SE-Schlüssel
    /// (`entryKey`), Karte (`card`), Sicherheitsschlüssel (`securityKey`). `material.secureEnclave` (Entsperr-Schlüssel)
    /// gehört zur Tresor-Stufe und wird hier nicht verwendet. Braucht Master-Passwort und alle Faktoren der Stufe.
    /// Kein Zugangswechsel: DEK und Salz bleiben. Eine andere Karte als die zum Öffnen → `wrongCard`; ein anderer
    /// Sicherheitsschlüssel als der zum Öffnen → `notAllowedAtLevel` (erst die Stufe wechseln).
    public func enrollFactors(_ material: NewFactorMaterial, masterPassword: String,
                              currentFactors: FactorSecrets) throws {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        try Self.validate(material)
        try writeLock.withLock {
            let s = try snapshot()
            try verifyAccess(pw, currentFactors, s)
            let vaultID = s.header.vaultID
            var keys = s.content.entryFactors
            if let ek = material.entryKey {
                // Ein Mac-Schlüssel ersetzt einen unter Windows eingerichteten Gerätefaktor (nie beide, v4.6).
                keys.secureEnclave = try Self.entryKey(ek)
                keys.windowsHello = nil
            }
            if let card = material.card {
                let tag = CardCode.tagBytes(q: card.q, vaultID: vaultID)
                if let opening = s.header.factorFields.cardTag, opening != tag { throw SiegelError.wrongCard }
                keys.card = try Self.cardKey(card.q, vaultID: vaultID)
            }
            if let k = material.securityKey {
                if let cred = s.header.factorFields.fidoCredentialID {
                    guard Array(k.credentialID) == cred, Array(k.salt) == s.header.factorFields.fidoSalt,
                          let current = currentFactors.securityKey, current.constantTimeEquals(k.output) else {
                        throw SiegelError.notAllowedAtLevel
                    }
                }
                keys.securityKey = try Self.securityKey(k, vaultID: vaultID)
            }
            guard keys != s.content.entryFactors else { return }
            try Self.checkReplacement(old: s.content.entryFactors, new: keys, content: s.content)
            var content = s.content
            content.entryFactors = keys
            try save(s, content: content, reason: nil)
        }
    }

    /// Stufe wechseln (auf- und abwärts, §13). Braucht das Master-Passwort und **alle Faktoren der aktuellen Stufe**
    /// (`currentFactors`), erneuert DEK und KDF-Salz und schreibt sofort (angeheftete Sicherung „vor-stufenwechsel“).
    ///
    /// Faktoren der Zielstufe: neu aus `newFactors` oder die bisherigen. Bisherige ohne neues Material müssen in
    /// `currentFactors` stecken: der Entsperr-SE-Schlüssel (nur wenn schon im Kopf), die Karte (geprüft über die
    /// Kennung im Kopf bzw. Inhalt → `wrongCard`), der Sicherheitsschlüssel (im Kopf, oder für Einträge
    /// eingerichtet: geprüft über den Prüfwert → `wrongPassword`). Fehlt etwas → `factorMissing`. Eine Karte bzw. ein
    /// Sicherheitsschlüssel zum Öffnen wird zugleich für Einträge eingerichtet.
    ///
    /// Notfallkit: Verlangt die Zielstufe ein anderes Schema (ein Code ↔ 2 aus 3), ist ein neues Kit Pflicht
    /// (`recovery` aus `prepareRecovery(…scheme: ziel.recoveryScheme)` + `recoveryConfirmation`), sonst
    /// `notAllowedAtLevel`. Bei gleichem Schema ist es freiwillig. Falsche Bestätigung → `recoveryConfirmationMismatch`.
    ///
    /// KDF: das Profil der Zielstufe (Standard für 1–2, Stark für 3–5). Abwärts wird der nicht mehr gebrauchte
    /// Entsperr-SE-Schlüssel (`Hardware/<seKeyID>.siegelhw`) erst nach erfolgreichem Schreiben entfernt.
    ///
    /// Eintrags-Schutz (§16): Ein Eintrags-Faktor, an dem versiegelte Einträge hängen, lässt sich nicht ersetzen
    /// (`notAllowedAtLevel`). Bringt der Wechsel ein neues Kit und gibt es versiegelte Einträge, müssen deren
    /// Notfall-Gruppen neu an das Kit gekapselt werden: das geht nur mit der async-Variante
    /// (`entryFactors:`, eine Freigabe pro Gruppe); hier → `factorMissing`.
    public func changeSecurityLevel(to level: SecurityLevel, masterPassword: String, currentFactors: FactorSecrets,
                                    newFactors: NewFactorMaterial, recovery: PendingRecovery?,
                                    recoveryConfirmation: [String]) throws {
        try changeSecurityLevel(to: level, masterPassword: masterPassword, currentFactors: currentFactors,
                                newFactors: newFactors, recovery: recovery, recoveryConfirmation: recoveryConfirmation,
                                releasedGroups: [:], verifiedSalt: nil)
    }

    /// Kern des Stufenwechsels. `releasedGroups`: ERS je Gruppe (aus `releaseAnchor`) für ein neues Kit;
    /// `verifiedSalt`: Zugang wurde für genau diesen Kopf schon geprüft (async-Variante, kein zweites Argon2).
    func changeSecurityLevel(to level: SecurityLevel, masterPassword: String, currentFactors: FactorSecrets,
                             newFactors: NewFactorMaterial, recovery: PendingRecovery?,
                             recoveryConfirmation: [String], releasedGroups: [UUID: SecureBytes],
                             verifiedSalt: [UInt8]?) throws {
        dispatchPrecondition(condition: .notOnQueue(.main))
        try Self.validate(newFactors)
        var kitR: SecureBytes?
        if let recovery {
            try Self.checkConfirmation(recovery, recoveryConfirmation)
            guard recovery.scheme == level.recoveryScheme else { throw SiegelError.notAllowedAtLevel }
            kitR = try Self.secret(of: recovery)
        }
        let pw = try PasswordNormalizer.secureBytes(masterPassword)
        try writeLock.withLock {
            let s = try snapshot()
            if kitR == nil, s.header.recoveryScheme != level.recoveryScheme { throw SiegelError.notAllowedAtLevel }
            let kdf = store.limits.profile(for: level)
            try store.limits.validate(kdf)
            try Self.checkDestructionAllows(level: level, kdf: kdf, state: s)
            if verifiedSalt != s.header.salt { try verifyAccess(pw, currentFactors, s) }

            let plan = try Self.planFactors(for: level, state: s, current: currentFactors, new: newFactors)
            try Self.checkReplacement(old: s.content.entryFactors, new: plan.entryKeys, content: s.content)

            // Notfallkit: neues (vorbereitet und bestätigt) oder das bisherige.
            var pk = s.header.pk
            var scheme = s.header.recoveryScheme
            var content = s.content
            if let r = kitR {
                guard let p = s.pending, p.r.constantTimeEquals(r) else {
                    throw SiegelError.crypto("recovery.pendingStale")
                }
                pk = p.header.pk
                scheme = p.scheme
                content.recoveryConfirmedAt = Clock.now()
            }
            content.level = level
            content.entryFactors = plan.entryKeys
            if pk != s.header.pk {
                try content.rewrapRecoveryGroups(released: releasedGroups, kit: pk, vaultID: s.header.vaultID)
            }

            let (header, slots, dek) = try store.rekey(vaultID: s.header.vaultID, kdf: kdf, fields: plan.fields,
                                                       scheme: scheme, pk: pk, password: pw, factors: plan.secrets)
            // F folgt den Faktoren der Zielstufe (v4.4).
            let binding = try DuressCrypto.binding(header: header, factors: plan.secrets)
            try requireUnlocked()
            let result = try store.persist(header: header, slots: slots, dek: dek, content: content,
                                           baseGeneration: s.generation,
                                           expectation: .generation(s.header.uuid, s.generation),
                                           reason: BackupNaming.Reason.levelChange.rawValue,
                                           duressBinding: binding, newDEK: true)
            let tagKey = try MasterTag.key(dek: dek)
            let tag = try MasterTag.tag(key: tagKey, password: pw)
            let reuse = Self.reuseSet(result.content, tagKey: tagKey, masterTag: tag,
                                      masterReuseTags: s.masterReuseTags)
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
                st.duressBinding = binding
            }
            // Erst nach erfolgreichem Schreiben: nicht mehr gebrauchten Entsperr-SE-Schlüssel entfernen.
            if let old = s.header.factorFields.seKeyID, old != plan.fields.seKeyID { store.removeHardwareKey(old) }
        }
    }

    /// Selbstvernichtung (§23): eingeschaltet nur in Stufe 4/5; mit Vernichtungs-Passwort kein anderes KDF-Profil
    /// (beide Argon2 brauchen dieselben Parameter). Sonst `notAllowedAtLevel` – erst die Selbstvernichtung ausschalten.
    static func checkDestructionAllows(level: SecurityLevel, kdf: KDFParameters, state s: State) throws {
        guard let d = s.content.destruction else { return }
        if level < .maximal, d.settings.anyTriggerEnabled || !s.content.destructible.isEmpty || d.vKey != nil {
            throw SiegelError.notAllowedAtLevel
        }
        if d.duress != nil, kdf != s.header.kdf { throw SiegelError.notAllowedAtLevel }
    }

    /// Eintrags-Faktoren, an denen versiegelte Einträge hängen, dürfen nicht durch andere ersetzt werden (die Einträge
    /// wären sonst nur noch über den Notfallcode lesbar): erst deren Schutz senken → sonst `notAllowedAtLevel`.
    static func checkReplacement(old: EntryFactorKeys, new: EntryFactorKeys, content: VaultContent) throws {
        let used = content.sealedKinds
        if used.contains(.secureEnclave), old.secureEnclave != new.secureEnclave || old.windowsHello != new.windowsHello {
            throw SiegelError.notAllowedAtLevel
        }
        if used.contains(.card), old.card != new.card { throw SiegelError.notAllowedAtLevel }
        if used.contains(.securityKey), old.securityKey != new.securityKey { throw SiegelError.notAllowedAtLevel }
    }

    struct FactorPlan {
        var fields = HeaderFactorFields.none
        var secrets = FactorSecrets()
        var entryKeys: EntryFactorKeys
    }

    /// Kopf-Felder, Faktor-Werte und Eintrags-Schlüssel für die Zielstufe zusammenstellen (rechnet nur HKDF/SHA3).
    static func planFactors(for level: SecurityLevel, state s: State, current: FactorSecrets,
                            new: NewFactorMaterial) throws -> FactorPlan {
        let vaultID = s.header.vaultID
        let head = s.header.factorFields
        var plan = FactorPlan(entryKeys: s.content.entryFactors)

        if let ek = new.entryKey {
            plan.entryKeys.secureEnclave = try entryKey(ek)
            plan.entryKeys.windowsHello = nil
        }
        if let card = new.card { plan.entryKeys.card = try cardKey(card.q, vaultID: vaultID) }
        if let k = new.securityKey { plan.entryKeys.securityKey = try securityKey(k, vaultID: vaultID) }

        if level.factors.contains(.secureEnclave) {
            if let se = new.secureEnclave {
                plan.fields.seKeyID = se.keyID
                plan.secrets.secureEnclave = se.secret
            } else if let id = head.seKeyID, let secret = current.secureEnclave {
                plan.fields.seKeyID = id
                plan.secrets.secureEnclave = secret
            } else {
                throw SiegelError.factorMissing(.secureEnclave)
            }
        }

        if level.factors.contains(.card) {
            let q: FactorSecret
            if let card = new.card {
                q = card.q
            } else {
                guard let known = head.cardTag ?? s.content.entryFactors.card?.tag, let scanned = current.card else {
                    throw SiegelError.factorMissing(.card)
                }
                guard CardCode.tagBytes(q: scanned, vaultID: vaultID) == known else { throw SiegelError.wrongCard }
                q = scanned
            }
            plan.fields.cardTag = CardCode.tagBytes(q: q, vaultID: vaultID)
            plan.secrets.card = q
            if plan.entryKeys.card == nil { plan.entryKeys.card = try cardKey(q, vaultID: vaultID) }
        }

        if level.factors.contains(.securityKey) {
            if let k = new.securityKey {
                plan.fields.fidoCredentialID = Array(k.credentialID)
                plan.fields.fidoSalt = Array(k.salt)
                plan.secrets.securityKey = k.output
            } else if let cred = head.fidoCredentialID, let salt = head.fidoSalt, let out = current.securityKey {
                // Schon im Kopf: beim Prüfen des Zugangs bestätigt.
                plan.fields.fidoCredentialID = cred
                plan.fields.fidoSalt = salt
                plan.secrets.securityKey = out
            } else if let enrolled = s.content.entryFactors.securityKey, let out = current.securityKey {
                // Nur für Einträge eingerichtet: Ausgabe zum Entsperr-Salz über den Prüfwert bestätigen.
                let check = try FactorKDF.fidoCheck(out, vaultID: vaultID)
                guard constantTimeEqual(check, enrolled.check) else { throw SiegelError.wrongPassword }
                plan.fields.fidoCredentialID = enrolled.credentialID
                plan.fields.fidoSalt = enrolled.salt
                plan.secrets.securityKey = out
            } else {
                throw SiegelError.factorMissing(.securityKey)
            }
        }
        return plan
    }

    // MARK: - Faktor-Material prüfen und umsetzen

    /// Längen und Werte des neuen Materials (vom Hardware-Modul), bevor irgendetwas gerechnet wird.
    static func validate(_ m: NewFactorMaterial) throws {
        if let se = m.secureEnclave, VaultHeader.bytes(of: se.keyID).allSatisfy({ $0 == 0 }) {
            throw SiegelError.crypto("factor.keyID")
        }
        if let ek = m.entryKey {
            guard !VaultHeader.bytes(of: ek.keyID).allSatisfy({ $0 == 0 }) else { throw SiegelError.crypto("factor.keyID") }
            _ = try entryKey(ek)
        }
        if let k = m.securityKey {
            let zero = { (d: Data) in d.allSatisfy { $0 == 0 } }
            guard k.credentialID.count >= VaultHeader.minFidoCredential,
                  k.credentialID.count <= VaultHeader.maxFidoCredential,
                  k.salt.count == VaultHeader.fidoSaltBytes, k.entrySalt.count == VaultHeader.fidoSaltBytes,
                  !zero(k.salt), !zero(k.entrySalt), k.salt != k.entrySalt else {
                throw SiegelError.crypto("factor.securityKey")
            }
        }
    }

    /// Öffentlicher Eintrags-SE-Schlüssel: P-256, x963 (65 B), gültiger Punkt.
    static func entryKey(_ ek: EntryKeyEnrollment) throws -> EntryFactorKeys.SecureEnclaveKey {
        guard ek.publicKey.count == 65, (try? P256.KeyAgreement.PublicKey(x963Representation: ek.publicKey)) != nil else {
            throw SiegelError.crypto("factor.publicKey")
        }
        return .init(keyID: ek.keyID, publicKey: Array(ek.publicKey))
    }

    static func cardKey(_ q: FactorSecret, vaultID: [UInt8]) throws -> EntryFactorKeys.CardKey {
        .init(tag: CardCode.tagBytes(q: q, vaultID: vaultID),
              pk: try EntryKeyDerivation.cardPublicKeys(q: q, vaultID: vaultID))
    }

    static func securityKey(_ k: SecurityKeyEnrollment, vaultID: [UInt8]) throws -> EntryFactorKeys.SecurityKey {
        .init(credentialID: Array(k.credentialID), salt: Array(k.salt),
              check: try FactorKDF.fidoCheck(k.output, vaultID: vaultID), entrySalt: Array(k.entrySalt),
              pk: try EntryKeyDerivation.fidoPublicKeys(entryOutput: k.entryOutput, vaultID: vaultID))
    }
}

/// Vergleich gleich langer Bytefolgen ohne frühen Abbruch.
func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var d: UInt8 = 0
    for i in a.indices { d |= a[i] ^ b[i] }
    return d == 0
}
