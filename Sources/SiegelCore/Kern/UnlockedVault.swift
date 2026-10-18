import Clibsodium
import Foundation

/// Ein entsperrter Tresor. Threadsicher: ein kurzer Zustands-Lock für Lesen/Übernehmen und ein Schreib-Lock,
/// der Änderungen serialisiert. Mutationen sind transaktional: Kopie ändern → speichern → erst dann übernehmen.
public final class UnlockedVault: @unchecked Sendable {
    /// Vorbereitetes neues Notfallkit (`prepareRecovery`); erst `commitRecovery` (bzw. `changeSecurityLevel`)
    /// schreibt es.
    struct PendingKit {
        let r: SecureBytes
        let scheme: RecoveryScheme
        /// Neuer Kopf: Faktoren wie bei der Vorbereitung, neues Salz, neues Kit.
        let header: VaultHeader
        let kekPw: SecureBytes
        let dek: SecureBytes
        let tagKey: SecureBytes
        let masterTag: SecureBytes
        /// Salz des Kopfes, auf dem die Vorbereitung beruht (Passwortwechsel dazwischen → ungültig).
        let basedOnSalt: [UInt8]
    }

    struct State {
        var header: VaultHeader
        var slots: VaultSlots
        var dek: SecureBytes
        var content: VaultContent
        var generation: UInt64
        var tagKey: SecureBytes
        var masterTag: SecureBytes
        /// reuseTags des Master-Passworts (§17, Grundschlüssel statt DEK): erkennen es auch in versiegelten Einträgen
        /// (v4.4: normalisiert wie §1.1, dazu bei Zs-Zeichen der Tag nach der Formel bis v4.3).
        var masterReuseTags: [[UInt8]]
        var reuse: Set<UUID>
        var pending: PendingKit?
        /// Nur bei einer v1-Datei: KEK_pw für den Kopf v2 mit demselben Salz (Migration beim ersten Speichern).
        var migrationKEK: SecureBytes?
        /// F (§23.2 Nr. 3, v4.4): aus den Faktoren dieser Sitzung, damit jedes Speichern den Umschlag des
        /// Vernichtungs-Passworts an DEK **und** Faktoren neu kapseln kann. nil ohne Faktoren (Stufe 1, v1).
        var duressBinding: SecureBytes?
    }

    /// Nicht geheime Kennwerte, die auch nach `lock()` lesbar bleiben.
    struct Meta {
        var generation: UInt64
        var kdf: KDFParameters
        var kitID: String
        var level: SecurityLevel
        var headerInfo: VaultHeaderInfo
        var enrolled: FactorSet

        init(_ s: State) {
            generation = s.generation
            kdf = s.header.kdf
            kitID = s.header.pk.kitID
            level = s.content.level
            headerInfo = s.header.info
            enrolled = s.content.entryFactors.enrolled
        }
    }

    let store: VaultStore
    private let id: UUID
    let stateLock = NSLock()
    let writeLock = NSLock()
    private var state: State?
    private(set) var meta: Meta
    /// Mit dem Vernichtungs-Passwort geöffnet (§23.2 Nr. 3). Nach aussen wie eine normale Sitzung.
    public let isDuressSession: Bool
    /// In einer Vernichtungs-Sitzung unsichtbar: die (eben vernichteten) vernichtbaren Einträge. Sie bleiben
    /// unverändert im Inhalt und werden bei jedem Speichern mitgeschrieben. In echten Sitzungen leer.
    let hiddenEntries: Set<UUID>

    /// `rawPassword`: die Eingabe vor der §1.1-Abbildung (nur für den Tag nach der Formel bis v4.3, nicht gehalten);
    /// `factors`: die Faktoren, mit denen geöffnet wurde (für F; fehlt einer, gibt es kein F und ein Speichern mit
    /// Vernichtungs-Passwort scheitert vor dem Schreiben).
    init(store: VaultStore, header: VaultHeader, slots: VaultSlots, dek: SecureBytes, content: VaultContent,
         generation: UInt64, password: SecureBytes, rawPassword: String? = nil, factors: FactorSecrets = FactorSecrets(),
         migrationKEK: SecureBytes? = nil, duress: Bool = false) throws {
        var content = content
        // Ältere Inhalte (v1, Stufe A) haben noch keinen Grundschlüssel; er wird mit dem nächsten Speichern geschrieben.
        try content.ensureEntryKey()
        let tagKey = try MasterTag.key(dek: dek)
        let tag = try MasterTag.tag(key: tagKey, password: password)
        let masterReuseTags = content.masterReuseTags(password, raw: rawPassword)
        self.store = store
        self.id = header.uuid
        self.isDuressSession = duress
        self.hiddenEntries = duress ? content.destructibleIDs : []
        let s = State(header: header, slots: slots, dek: dek, content: content, generation: generation,
                      tagKey: tagKey, masterTag: tag, masterReuseTags: masterReuseTags,
                      reuse: Self.reuseSet(content, tagKey: tagKey, masterTag: tag, masterReuseTags: masterReuseTags),
                      pending: nil, migrationKEK: header.formatVersion == 1 ? migrationKEK : nil,
                      duressBinding: try? DuressCrypto.binding(header: header, factors: factors))
        self.state = s
        self.meta = Meta(s)
    }

    // MARK: - Lesen

    public var vaultID: UUID { id }
    public var generation: UInt64 { stateLock.withLock { meta.generation } }
    public var kdf: KDFParameters { stateLock.withLock { meta.kdf } }
    public var kitID: String { stateLock.withLock { meta.kitID } }
    public var isLocked: Bool { stateLock.withLock { state == nil } }

    /// Tresor-Stufe (§13); bleibt nach `lock()` lesbar.
    public var level: SecurityLevel { stateLock.withLock { meta.level } }
    /// Regeln der Stufe, die die Oberfläche durchsetzt.
    public var policy: LevelPolicy { level.policy }
    /// Kopf im Speicher (wie `VaultStore.inspect()`, aber der beim Entsperren authentifizierte).
    public var headerInfo: VaultHeaderInfo { stateLock.withLock { meta.headerInfo } }
    /// Für Einträge eingerichtete Faktoren (§16): Eintrags-SE-Schlüssel, Karte, Sicherheitsschlüssel.
    public var enrolledFactors: FactorSet { stateLock.withLock { meta.enrolled } }

    /// Wurde der Eintrags-Gerätefaktor unter Windows eingerichtet (Windows Hello, v4.6)? Dann ist er auf diesem Mac ein
    /// anderes Gerät: Einträge, die ihn verlangen, öffnet hier nur der Notfallweg (`revealSecrets` →
    /// `factorUnavailable(.secureEnclave)` ohne Provider-Aufruf). Zusatz zu §22.
    public var entryDeviceIsWindowsHello: Bool {
        stateLock.withLock { state?.content.entryFactors.windowsHello != nil }
    }

    /// Credential und Entsperr-Salz des eingerichteten Sicherheitsschlüssels (aus dem Kopf, sonst aus dem Inhalt),
    /// damit die Oberfläche dessen Ausgabe holen kann, bevor sie ihn in die Tresor-Stufe aufnimmt. Zusatz zu §22.
    public var securityKeyCredential: (credentialID: Data, salt: Data)? {
        stateLock.withLock {
            guard let s = state else { return nil }
            if let cred = s.header.factorFields.fidoCredentialID, let salt = s.header.factorFields.fidoSalt {
                return (Data(cred), Data(salt))
            }
            return s.content.entryFactors.securityKey.map { (Data($0.credentialID), Data($0.salt)) }
        }
    }

    public var recoveryConfirmed: Bool {
        stateLock.withLock { state?.content.recoveryConfirmedAt != nil }
    }

    /// Ohne gelöschte Einträge (in einer Vernichtungs-Sitzung ohne die vernichteten).
    public var entries: [VaultEntry] {
        stateLock.withLock { state?.content.entries.filter { $0.deletedAt == nil && !hiddenEntries.contains($0.id) } ?? [] }
    }

    /// „Zuletzt gelöscht“.
    public var deletedEntries: [VaultEntry] {
        stateLock.withLock { state?.content.entries.filter { $0.deletedAt != nil && !hiddenEntries.contains($0.id) } ?? [] }
    }

    /// Letzte Änderung eines Eintrags (bearbeitet oder gelöscht); nil ohne Einträge.
    public var lastModified: Date? {
        stateLock.withLock {
            state?.content.entries.filter { !hiddenEntries.contains($0.id) }
                .map { e in max(e.modified, e.deletedAt ?? .distantPast) }.max()
        }
    }

    /// Einträge, deren Passwort oder Verlaufswert dem Master-Passwort entspricht.
    public var masterPasswordReuse: Set<UUID> {
        stateLock.withLock { (state?.reuse ?? []).subtracting(hiddenEntries) }
    }

    /// Index eines Eintrags, den diese Sitzung sehen darf (in einer Vernichtungs-Sitzung nie ein vernichteter).
    func visibleIndex(_ content: VaultContent, _ id: UUID) -> Int? {
        guard !hiddenEntries.contains(id) else { return nil }
        return content.entries.firstIndex { $0.id == id }
    }

    // MARK: - Einträge

    /// Transaktional; setzt `modified`, pflegt den Verlauf (altes Passwort wandert hinein).
    ///
    /// Eintrags-Schutz (§16): Neue Einträge bekommen mindestens `policy.defaultEntryProtection` (Stufen 4/5: Schutz 2).
    /// Schutz ≥ 2 wird sofort versiegelt (nur öffentliche Schlüssel nötig); fehlt ein eingerichteter Faktor →
    /// `factorMissing`. Bei einem versiegelten Eintrag ändert `upsert` nur die offenen Felder (Titel, Benutzer, URL):
    /// `secretsSealed` muss gesetzt und die Geheimteile leer sein, der Schutz gleich bleiben – Geheimteile und Schutz
    /// ändert nur `setProtection` (sonst `io("entry.sealedSecrets")` bzw. `io("entry.protection")`). Ein offener
    /// Eintrag darf über `upsert` höher geschützt werden, nie tiefer.
    public func upsert(_ entry: VaultEntry) throws {
        try VaultContent.validate(entry)
        try mutate { content, now, header in
            // Vernichtungs-Sitzung: ein unsichtbarer Eintrag lässt sich weder ändern noch neu anlegen.
            guard !hiddenEntries.contains(entry.id) else { throw SiegelError.io("entry.stale") }
            if let i = content.entries.firstIndex(where: { $0.id == entry.id }) {
                let old = content.entries[i]
                if old.secretsSealed {
                    guard entry.protection == old.protection else { throw SiegelError.io("entry.protection") }
                    guard entry.secretsSealed, Self.secretsAreEmpty(entry) else {
                        throw SiegelError.io("entry.sealedSecrets")
                    }
                    var updated = entry
                    updated.created = old.created
                    updated.deletedAt = old.deletedAt
                    updated.modified = now
                    content.entries[i] = updated
                    return true
                }
                // Veraltete Kopie (z. B. von vor einer Wiederherstellung): nie leere Geheimteile übernehmen.
                guard !entry.secretsSealed else { throw SiegelError.io("entry.stale") }
                guard entry.protection >= old.protection else { throw SiegelError.io("entry.protection") }
                var updated = entry
                updated.created = old.created
                updated.deletedAt = old.deletedAt
                var history = old.history
                if old.password != entry.password, !old.password.isEmpty {
                    history.append(PasswordHistoryItem(password: old.password, changed: now))
                }
                // Das aktuelle Passwort ist kein „früheres“.
                history.removeAll { $0.password == entry.password }
                updated.history = VaultContent.applyHistoryRule(history, now: now)
                updated.modified = now
                content.entries[i] = updated
                if updated.protection > .normal {
                    try content.seal(at: i, vaultID: header.vaultID, kit: header.pk, now: now)
                }
            } else {
                guard !entry.secretsSealed else { throw SiegelError.io("entry.stale") }
                var created = entry
                created.created = Clock.canonical(entry.created)
                created.modified = now
                created.deletedAt = nil
                created.protection = max(entry.protection, content.level.policy.defaultEntryProtection)
                created.history = VaultContent.applyHistoryRule(
                    entry.history.filter { $0.password != entry.password }, now: now)
                content.entries.append(created)
                if created.protection > .normal {
                    try content.seal(at: content.entries.count - 1, vaultID: header.vaultID, kit: header.pk, now: now)
                }
            }
            return true
        }
    }

    static func secretsAreEmpty(_ e: VaultEntry) -> Bool {
        e.password.isEmpty && e.notes.isEmpty && e.totp.isEmpty && e.history.isEmpty
    }

    /// Setzt `deletedAt` (→ „Zuletzt gelöscht“, 30 Tage).
    public func delete(id: UUID) throws {
        try mutate { content, now, _ in
            guard let i = visibleIndex(content, id) else {
                throw SiegelError.io("entry.notFound")
            }
            guard content.entries[i].deletedAt == nil else { return false }
            content.entries[i].deletedAt = now
            return true
        }
    }

    public func restore(id: UUID) throws {
        try mutate { content, _, _ in
            guard let i = visibleIndex(content, id) else {
                throw SiegelError.io("entry.notFound")
            }
            guard content.entries[i].deletedAt != nil else { return false }
            content.entries[i].deletedAt = nil
            return true
        }
    }

    /// Endgültig entfernen (nur Einträge in „Zuletzt gelöscht“).
    public func purgeDeleted(id: UUID) throws {
        try mutate { content, _, _ in
            guard let i = visibleIndex(content, id) else {
                throw SiegelError.io("entry.notFound")
            }
            guard content.entries[i].deletedAt != nil else { throw SiegelError.io("entry.notDeleted") }
            content.entries.remove(at: i)
            return true
        }
    }

    /// Verlauf leeren. Bei versiegelten Einträgen ist der Verlauf ein Geheimteil → `io("entry.sealedSecrets")`
    /// (über `setProtection` mit leerem Verlauf).
    public func clearHistory(id: UUID) throws {
        try mutate { content, _, _ in
            guard let i = visibleIndex(content, id) else {
                throw SiegelError.io("entry.notFound")
            }
            guard !content.entries[i].secretsSealed else { throw SiegelError.io("entry.sealedSecrets") }
            guard !content.entries[i].history.isEmpty else { return false }
            content.entries[i].history = []
            return true
        }
    }

    /// Nur anhängen. Dubletten (Host + Benutzer + Passwort) werden übersprungen; gleicher Host + Benutzer mit
    /// anderem Passwort → neuer Eintrag mit Titelzusatz „(Import)“. Bestand wird nie geändert. Vorher
    /// angeheftete Sicherung „vor-import“. Der Bericht füllt `added` (inkl. Konflikte), `skippedDuplicates`
    /// und `conflicts`; die übrigen Zähler stammen aus `CSVImport.parse`.
    /// Versiegelte Bestandseinträge vergleicht der Kern über ihren reuseTag (§17). Neue Einträge bekommen
    /// mindestens den Standard-Schutz der Stufe und werden dann versiegelt (fehlender Faktor → `factorMissing`,
    /// vor dem Schreiben). Die letzte Passwortänderung importierter Einträge ist ihr `modified`.
    public func importEntries(_ entries: [VaultEntry]) throws -> ImportReport {
        for e in entries {
            try VaultContent.validate(e)
            guard !e.secretsSealed else { throw SiegelError.io("entry.stale") }
        }
        var report = ImportReport()
        try mutate(reason: .importCSV) { content, now, header in
            report = ImportReport()
            let minimum = content.level.policy.defaultEntryProtection
            for e in entries { try EntrySealing.requireEnrolled(max(e.protection, minimum).factors, content.entryFactors) }
            try content.ensureEntryKey()
            let reuseKey = try content.reuseKey()
            var known: [String: Set<String>] = [:]
            var knownTags: [String: Set<[UInt8]>] = [:]
            var ids = Set<UUID>()
            for e in content.entries {
                ids.insert(e.id)
                guard e.deletedAt == nil, !hiddenEntries.contains(e.id) else { continue }
                if e.secretsSealed {
                    knownTags[Self.duplicateKey(e), default: []].insert(content.meta[e.id]?.tag ?? [])
                } else {
                    known[Self.duplicateKey(e), default: []].insert(e.password)
                }
            }
            for e in entries {
                let key = Self.duplicateKey(e)
                var new = e
                if known[key] != nil || knownTags[key] != nil {
                    let tag = EntrySealing.reuseTag(key: reuseKey, password: e.password) ?? []
                    // Versiegelte Einträge können noch einen Tag nach der Formel bis v4.3 tragen (nur NFC).
                    let legacy = EntrySealing.legacyReuseTag(key: reuseKey, password: e.password)
                    if known[key]?.contains(e.password) == true || knownTags[key]?.contains(tag) == true
                        || legacy.map({ knownTags[key]?.contains($0) == true }) == true {
                        report.skippedDuplicates += 1
                        continue
                    }
                    new.title = Self.importTitle(e.title)
                    report.conflicts += 1
                }
                if ids.contains(new.id) { new.id = UUID() }
                ids.insert(new.id)
                new.deletedAt = nil
                new.created = Clock.canonical(new.created)
                new.modified = Clock.canonical(new.modified)
                new.protection = max(e.protection, minimum)
                new.history = VaultContent.applyHistoryRule(new.history.filter { $0.password != new.password }, now: now)
                content.meta[new.id] = EntrySealing.meta(password: new.password, previous: nil, reuseKey: reuseKey,
                                                         fallbackChanged: new.modified, now: now)
                content.entries.append(new)
                if new.protection > .normal {
                    try content.seal(at: content.entries.count - 1, vaultID: header.vaultID, kit: header.pk, now: now)
                }
                known[key, default: []].insert(e.password)
                report.added += 1
            }
            return report.added > 0
        }
        return report
    }

    /// Host (klein, IDNA) + Benutzer, getrennt durch ein Nullzeichen.
    static func duplicateKey(_ e: VaultEntry) -> String {
        hostKey(e.url) + "\u{0}" + e.username
    }

    static func hostKey(_ url: String) -> String {
        let t = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return "" }
        let withScheme = t.contains("://") ? t : "https://" + t
        if let h = URL(string: withScheme)?.host(percentEncoded: false), !h.isEmpty {
            var host = h.lowercased()
            if host.hasSuffix(".") { host.removeLast() }
            return host
        }
        return t.lowercased()
    }

    static func importTitle(_ title: String) -> String {
        let suffix = title.isEmpty ? "(Import)" : " (Import)"
        var base = title
        while (base + suffix).utf8.count > VaultContent.maxTitle, !base.isEmpty { base.removeLast() }
        return base + suffix
    }

    // MARK: - Master-Passwort und Notfallkit

    /// Argon2-Prüfung des Master-Passworts (nicht auf dem Main-Thread), ohne Faktoren.
    public func verify(masterPassword: String) -> Bool {
        verify(masterPassword: masterPassword, factors: FactorSecrets())
    }

    /// Argon2-Prüfung von Master-Passwort und Faktoren der Stufe. Fehlt ein Faktor oder stimmt etwas nicht → false.
    public func verify(masterPassword: String, factors: FactorSecrets) -> Bool {
        dispatchPrecondition(condition: .notOnQueue(.main))
        guard let pw = try? PasswordNormalizer.secureBytes(masterPassword), let s = try? snapshot() else { return false }
        return (try? verifyAccess(pw, factors, s)) != nil
    }

    public func changeMasterPassword(current: String, new: String, kdf: KDFParameters? = nil) throws {
        try changeMasterPassword(current: current, new: new, factors: FactorSecrets(), kdf: kdf)
    }

    /// Neues Passwort (und optional KDF-Profil): neuer DEK, neues Salz, recSlot neu gekapselt (Code bleibt gültig),
    /// Faktoren der Stufe bleiben, angeheftete Sicherung „vor-passwortwechsel“. Ein reiner Profilwechsel ruft das
    /// mit `new == current` auf: Das ist kein *neues* Passwort, darum greift die Wiederverwendungs-Sperre (§1.6)
    /// dann nicht. Ein Profil schwächer als das der Stufe (Stufen 3–5: Stark) → `notAllowedAtLevel`.
    public func changeMasterPassword(current: String, new: String, factors: FactorSecrets,
                                     kdf: KDFParameters? = nil) throws {
        dispatchPrecondition(condition: .notOnQueue(.main))
        let policy = MasterPasswordPolicy.check(PasswordNormalizer.normalize(new))
        guard policy.ok else { throw SiegelError.passwordTooWeak(bits: policy.bits) }
        let unchanged = VaultStore.passwordsMatch(current, new)
        let newPW = try PasswordNormalizer.secureBytes(new)
        let currentPW = try PasswordNormalizer.secureBytes(current)
        try writeLock.withLock {
            let s = try snapshot()
            let params = kdf ?? s.header.kdf
            try store.limits.validate(params)
            if kdf != nil, store.limits.isWeaker(params, thanLevel: s.content.level) {
                throw SiegelError.notAllowedAtLevel
            }
            // Vernichtungs-Passwort (§23.2): gleiche Argon2-Parameter wie der Kopf, also kein Profilwechsel.
            if s.content.destruction?.duress != nil, params != s.header.kdf { throw SiegelError.notAllowedAtLevel }
            if !unchanged, try MasterTag.isUsedByEntries(newPW, entries: s.content.entries)
                || s.content.isUsedBySealedEntries(newPW, raw: new) {
                throw SiegelError.masterPasswordReused
            }
            try verifyAccess(currentPW, factors, s)
            // Das neue Master-Passwort darf nicht das Vernichtungs-Passwort sein (sonst öffnete es immer echt).
            if let d = s.content.destruction?.duress,
               try isDuressPassword(newPW, d, vaultID: s.header.vaultID, kdf: s.header.kdf) {
                throw SiegelError.masterPasswordReused
            }
            let (header, slots, dek) = try store.rekey(vaultID: s.header.vaultID, kdf: params,
                                                       fields: s.header.factorFields,
                                                       scheme: s.header.recoveryScheme, pk: s.header.pk,
                                                       password: newPW, factors: factors)
            // Gleiche Faktoren wie beim Entsperren (eben geprüft) → F bleibt.
            try requireUnlocked()
            let result = try store.persist(header: header, slots: slots, dek: dek, content: s.content,
                                           baseGeneration: s.generation,
                                           expectation: .generation(s.header.uuid, s.generation),
                                           reason: BackupNaming.Reason.passwordChange.rawValue,
                                           duressBinding: s.duressBinding, newDEK: true)
            let tagKey = try MasterTag.key(dek: dek)
            let tag = try MasterTag.tag(key: tagKey, password: newPW)
            let masterReuseTags = result.content.masterReuseTags(newPW, raw: new)
            let reuse = Self.reuseSet(result.content, tagKey: tagKey, masterTag: tag, masterReuseTags: masterReuseTags)
            commit { st in
                st.header = header
                st.slots = slots
                st.dek = dek
                st.content = result.content
                st.generation = result.generation
                st.tagKey = tagKey
                st.masterTag = tag
                st.masterReuseTags = masterReuseTags
                st.reuse = reuse
                st.pending = nil
                st.migrationKEK = nil
            }
        }
    }

    /// DEK und Inhalt verwerfen; danach unbrauchbar. Laufende Speichervorgänge halten ihre eigene Referenz
    /// bis zum Ende (Millisekunden), danach wird auch dort genullt.
    public func lock() {
        stateLock.withLock { state = nil }
    }

    // MARK: - Interna

    func snapshot() throws -> State {
        try stateLock.withLock {
            guard let s = state else { throw SiegelError.io("vault.locked") }
            return s
        }
    }

    /// Vor jedem Schreiben (unter `writeLock`): Nach dem Sperren schreibt der Tresor nichts mehr – auch kein
    /// Vorgang, der vorher begonnen hat und inzwischen lange rechnete (Argon2, Freigaben). Sonst stünde auf der Platte
    /// ein Stand, den die Sitzung nicht mehr übernimmt und von dem die Oberfläche nichts weiss (Befund datei-1).
    func requireUnlocked() throws {
        guard !isLocked else { throw SiegelError.io("vault.locked") }
    }

    func commit(_ update: (inout State) -> Void) {
        stateLock.withLock {
            guard var s = state else { return }
            update(&s)
            state = s
            meta = Meta(s)
        }
    }

    /// Vorbereitetes Kit merken (nur solange entsperrt).
    func setPending(_ pending: PendingKit) throws {
        try stateLock.withLock {
            guard state != nil else { throw SiegelError.io("vault.locked") }
            state?.pending = pending
        }
    }

    /// Kopie ändern → speichern → übernehmen. `change` liefert false, wenn nichts zu speichern ist. Der Kopf ist der
    /// beim Entsperren authentifizierte (vaultID und Kit zum Versiegeln).
    func mutate(reason: BackupNaming.Reason? = nil,
                _ change: (inout VaultContent, Date, VaultHeader) throws -> Bool) throws {
        try writeLock.withLock {
            let s = try snapshot()
            var content = s.content
            guard try change(&content, Clock.now(), s.header) else { return }
            try save(s, content: content, reason: reason?.rawValue)
        }
    }

    /// Einträge, deren Passwort (oder Verlaufswert) dem Master-Passwort entspricht: offene über den Master-Tag
    /// (§1.6), versiegelte über ihren reuseTag (§17, nur das aktuelle Passwort; jeder der Master-Tags zählt).
    static func reuseSet(_ content: VaultContent, tagKey: SecureBytes, masterTag: SecureBytes,
                         masterReuseTags: [[UInt8]]) -> Set<UUID> {
        var out = MasterTag.reuse(entries: content.entries, key: tagKey, masterTag: masterTag)
        for e in content.entries where e.secretsSealed {
            if let t = content.meta[e.id]?.tag, masterReuseTags.contains(where: { constantTimeEqual(t, $0) }) {
                out.insert(e.id)
            }
        }
        return out
    }

    /// Normales Speichern mit gleichem DEK und gleichen Slots. Nur unter `writeLock` aufrufen.
    /// Ist die Datei noch Format v1, wird sie dabei zu v2 (gleiches Salz, gleicher DEK, Slots neu mit den v2-Labels;
    /// vorher angeheftete Sicherung „vor-migration-v1“, siehe `VaultStore.commitWrite`). Gesperrt → `io("vault.locked")`,
    /// ohne zu schreiben. Liefert die geschriebene Generation; nach dem Schreiben wirft es nicht mehr.
    @discardableResult
    func save(_ s: State, content: VaultContent, reason: String?) throws -> UInt64 {
        var header = s.header
        var slots = s.slots
        if s.header.formatVersion == 1 {
            guard let kek = s.migrationKEK else { throw SiegelError.crypto("migration.kek") }
            header = try VaultHeader(vaultID: s.header.vaultID, kdf: s.header.kdf, salt: s.header.salt, factors: .none,
                                     recoveryScheme: .single, pk: s.header.pk)
            slots = try VaultCrypto.makeSlots(header: header, kekPw: kek, dek: s.dek)
        }
        try requireUnlocked()
        let result = try store.persist(header: header, slots: slots, dek: s.dek, content: content,
                                       baseGeneration: s.generation,
                                       expectation: .generation(s.header.uuid, s.generation), reason: reason,
                                       duressBinding: s.duressBinding)
        let reuse = Self.reuseSet(result.content, tagKey: s.tagKey, masterTag: s.masterTag,
                                  masterReuseTags: s.masterReuseTags)
        commit { st in
            st.header = header
            st.slots = slots
            st.content = result.content
            st.generation = result.generation
            st.reuse = reuse
            st.migrationKEK = nil
        }
        return result.generation
    }

    /// Master-Passwort und Faktoren gegen den Kopf im Speicher: Faktoren vorhanden/Karte (`factorMissing`,
    /// `wrongCard`), Argon2 mit Salz/Parametern des Kopfes, pwSlot öffnen, DEK vergleichen (`wrongPassword`).
    func verifyAccess(_ pw: SecureBytes, _ factors: FactorSecrets, _ s: State) throws {
        let (kek, _) = try FactorKDF.deriveKEK(header: s.header, password: pw, factors: factors, limits: store.limits,
                                               cache: nil)
        guard let dek = AEAD.unwrap(kek: kek, blob: s.slots.pwSlot, ad: VaultSlots.pwAD(s.header)),
              dek.constantTimeEquals(s.dek) else {
            throw SiegelError.wrongPassword
        }
    }

    #if DEBUG
    /// Nur Tests: Kopie des aktuellen DEK.
    func dekForTesting() throws -> SecureBytes {
        let s = try snapshot()
        return try s.dek.withUnsafeBytes { try SecureBytes(copying: $0) }
    }

    /// Nur Tests: alle Einträge inkl. gelöschter.
    var allEntriesForTesting: [VaultEntry] { stateLock.withLock { state?.content.entries ?? [] } }
    var headerForTesting: VaultHeader? { stateLock.withLock { state?.header } }
    var contentForTesting: VaultContent? { stateLock.withLock { state?.content } }
    var recoveryConfirmedAtForTesting: Date? { stateLock.withLock { state?.content.recoveryConfirmedAt } }
    #endif
}

extension UnlockedVault: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "UnlockedVault(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: KeyValuePairs<String, Any>(), displayStyle: .class) }
}

/// Ziel-Prüfung und Ordner für den CSV-Export (SPEC §8 „CSV-Export-Hygiene“).
enum CSVExportLocation {
    static func check(_ directory: URL) throws {
        let dir = directory.standardizedFileURL.resolvingSymlinksInPath()
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else {
            throw SiegelError.io("export.directory")
        }
        if let v = try? dir.resourceValues(forKeys: [.isUbiquitousItemKey]), v.isUbiquitousItem == true {
            throw SiegelError.exportLocationRejected("icloud")
        }
        let path = dir.path
        if path.contains("/Library/Mobile Documents/") || path.hasSuffix("/Library/Mobile Documents") {
            throw SiegelError.exportLocationRejected("icloud")
        }
    }

    /// `Siegel-Export-<JJJJ-MM-TT>.noindex` (0700); besteht er schon, mit Zähler.
    static func makeFolder(in directory: URL, now: Date) throws -> URL {
        let c = Calendar(identifier: .gregorian).dateComponents([.year, .month, .day], from: now)
        func pad(_ v: Int?, _ w: Int) -> String {
            let s = String(v ?? 0)
            return String(repeating: "0", count: max(0, w - s.count)) + s
        }
        let day = pad(c.year, 4) + "-" + pad(c.month, 2) + "-" + pad(c.day, 2)
        for n in 1...100 {
            let name = "Siegel-Export-" + day + (n == 1 ? "" : "-" + String(n)) + ".noindex"
            let url = directory.appendingPathComponent(name, isDirectory: true)
            if mkdir(url.path, 0o700) == 0 {
                _ = chmod(url.path, 0o700)
                return url
            }
            guard errno == EEXIST else { throw SiegelError.io("export.folder") }
        }
        throw SiegelError.io("export.folder")
    }
}
