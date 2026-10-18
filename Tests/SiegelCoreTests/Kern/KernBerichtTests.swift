import Foundation
import Testing
@testable import SiegelCore

/// Offline-Sicherheitsbericht (SPEC §17) und Inhalts-JSON des Eintrags-Schutzes.
@Suite("Offline-Sicherheitsbericht (§17)")
struct KernBerichtTests {
    /// Zufälliges starkes Passwort (20 Zeichen).
    private func stark() -> String { "Zq7!" + hexString(randomBytes(8)) + "#Wm" }

    @Test("Schwach, wiederverwendet, alt, gleich wie Master – auch versiegelt, gleich nach dem Neu-Öffnen")
    func bericht() async throws {
        let t = try SchutzTresor.make()
        let vor400Tagen = Clock.canonical(Date().addingTimeInterval(-400 * 86_400))
        let alt = schutzEntry("Alt", protection: .normal, password: stark())
        try TestHooks.$now.withValue(vor400Tagen) {
            var e = alt
            e.history = []
            e.created = vor400Tagen
            try t.vault.upsert(e)
        }
        let schwach = schutzEntry("Schwach", protection: .normal, password: "passwort1")
        let gleich = stark()
        let a = schutzEntry("A", protection: .normal, password: gleich)
        let b = schutzEntry("B", protection: .hoch, password: gleich)
        let m1 = schutzEntry("M1", protection: .normal, password: KT.pw1)
        let m2 = schutzEntry("M2", protection: .maximal, password: KT.pw1)
        let leer = VaultEntry(title: "Leer", username: "x")
        let weg = schutzEntry("Weg", protection: .fingerabdruck, password: "passwort1")
        for e in [schwach, a, b, m1, m2, leer, weg] { try t.vault.upsert(e) }
        try t.vault.delete(id: weg.id)

        let r = t.vault.securityReport()
        #expect(r.total == 6)
        #expect(r.weak == [schwach.id])
        #expect(r.reused == [[a.id, b.id], [m1.id, m2.id]])
        #expect(r.old == [alt.id])
        #expect(r.sameAsMaster == [m1.id, m2.id])
        #expect(t.vault.masterPasswordReuse == [m1.id, m2.id])

        // Nach dem Neu-Öffnen dasselbe (Metadaten persistiert, ohne Geheimteile zu öffnen)
        let v = try t.reopen()
        #expect(v.securityReport() == r)
        #expect(v.masterPasswordReuse == [m1.id, m2.id])

        // Passwortwechsel: nicht mehr alt; versiegelter Eintrag über setProtection: nicht mehr wiederverwendet
        var neu = try #require(v.entries.first { $0.id == alt.id })
        neu.password = stark()
        try v.upsert(neu)
        let sb = try await v.revealSecrets(id: b.id, factors: t.p).replacingPassword(with: stark())
        try v.setProtection(.hoch, id: b.id, secrets: sb)
        let r2 = v.securityReport()
        #expect(r2.old.isEmpty)
        #expect(r2.reused == [[m1.id, m2.id]])
        // Neues Master-Passwort: M1/M2 haben das alte
        try v.changeMasterPassword(current: KT.pw1, new: KT.pw2, factors: FactorSecrets())
        #expect(v.securityReport().sameAsMaster.isEmpty)
        #expect(v.masterPasswordReuse.isEmpty)
        // Gleiches Passwort ohne Änderung lässt das Datum stehen
        let changedBefore = try #require(v.contentForTesting?.meta[m2.id]?.changed)
        var umbenannt = try #require(v.entries.first { $0.id == m2.id })
        umbenannt.title = "M2 neu"
        try v.upsert(umbenannt)
        #expect(v.contentForTesting?.meta[m2.id]?.changed == changedBefore)
    }

    @Test("Metadaten: reuseTag 16 Byte mit dem Grundschlüssel, stabil über DEK-Rotation; Inhalt ohne Metadaten wird ergänzt")
    func metadaten() throws {
        let t = try SchutzTresor.make()
        let e = schutzEntry("E", protection: .fingerabdruck)
        try t.vault.upsert(e)
        try t.vault.upsert(schutzEntry("O", protection: .normal, password: e.password))
        let c1 = try #require(t.vault.contentForTesting)
        let tag = try #require(c1.meta[e.id]?.tag)
        #expect(tag.count == 16)
        #expect(c1.meta.values.allSatisfy { $0.tag == tag && $0.strength != nil && $0.changed != nil })
        try t.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2, factors: FactorSecrets())
        let c2 = try #require(t.vault.contentForTesting)
        #expect(c2.entryKey == c1.entryKey)
        #expect(c2.meta[e.id]?.tag == tag)
        #expect(t.vault.securityReport().reused.count == 1)

        // v1-Inhalt (ohne Grundschlüssel und Metadaten): Bericht sofort, Speichern schreibt sie
        let dir = KernTempDir()
        let store = VaultStore(directory: dir.sub("Siegel"), rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        try KernMigrationTests.writeV1(to: store, entries: [kernEntry("A", password: "x"), kernEntry("B", password: "x")])
        let v = try #require(KT.unlocked(try store.unlock(masterPassword: KT.pw1)))
        let r = v.securityReport()
        #expect(r.total == 2 && r.weak.count == 2 && r.reused.count == 1)
        try v.upsert(kernEntry("C", password: "Zq7!" + hexString(randomBytes(8))))
        let c = try #require(v.contentForTesting)
        #expect(c.meta.count == 3 && c.entryKey != nil)
    }

    @Test("Inhalts-JSON: entryKey, recoveryGroups, sealed und meta; Rundlauf; strenge Regeln beim Lesen und Schreiben")
    func inhaltJSON() throws {
        let t = try SchutzTresor.make()
        let offen = schutzEntry("Offen", protection: .normal)
        let zu = schutzEntry("Zu", protection: .maximal)
        try t.vault.upsert(offen)
        try t.vault.upsert(zu)
        let json = try t.jsonOnDisk()
        #expect(json.hasPrefix("{\"entries\":[{\"created\":"))
        #expect(json.contains("\"entryKey\":\""))
        #expect(json.contains("\"recoveryGroups\":[{\"anchor\":{\"card\":{\"ctM\":\""))
        #expect(json.contains("\"sealed\":null"))
        #expect(json.contains("\"sealed\":{\"blob\":{\"card\":{\"ctM\":\""))
        #expect(json.contains("\"fido\":null"))
        #expect(json.contains("\"meta\":{\"changed\":"))

        let content = try #require(t.vault.contentForTesting)
        let (padded, _) = try PayloadCodec.encode(content)
        #expect(try PayloadCodec.decode(padded).content == content)

        let io = try #require(content.entries.firstIndex { $0.id == offen.id })
        let iz = try #require(content.entries.firstIndex { $0.id == zu.id })
        let x = try #require(content.sealed[zu.id])
        func rejected(_ change: (inout VaultContent) -> Void) -> Bool {
            var c = content
            change(&c)
            return (try? c.checkSealing { SiegelError.corruptFile($0) }) == nil
        }
        #expect(!rejected { _ in })
        #expect(rejected { $0.entries[io].protection = .hoch })
        #expect(rejected { $0.sealed[offen.id] = x })
        #expect(rejected { $0.entries[iz].password = "x" })
        #expect(rejected { $0.entries[iz].history = [PasswordHistoryItem(password: "x", changed: Date())] })
        #expect(rejected { $0.entries[iz].protection = .festung })
        #expect(rejected { $0.sealed[zu.id]?.blob.factors.fido = x.blob.factors.card })
        #expect(rejected { $0.sealed[zu.id]?.blob.nonce.removeLast() })
        #expect(rejected { $0.sealed[zu.id]?.recovery.wrapped.removeLast() })
        #expect(rejected { $0.sealed[zu.id]?.blob.factors.seEphemeral = [UInt8](repeating: 4, count: 64) })
        #expect(rejected { $0.recoveryGroups = [] })
        #expect(rejected { $0.recoveryGroups.append($0.recoveryGroups[0]) })
        #expect(rejected { $0.recoveryGroups[0].mask = [.card] })
        #expect(rejected { $0.meta[zu.id] = nil })
        #expect(rejected { $0.meta[offen.id]?.tag = [1, 2, 3] })
        #expect(rejected { $0.entryKey = nil })
        #expect(rejected { $0.entryFactors.card = nil })
        #expect(rejected { $0.entries.append($0.entries[iz]) })

        // Schreiben verweigert inkonsistente Inhalte (Programmfehler fallen beim Schreiben auf)
        var bad = content
        bad.entries[io].protection = .hoch
        #expect(throws: SiegelError.crypto("entry.sealedState")) { try PayloadCodec.encode(bad) }

        // Lesen: manipuliertes JSON (Schutz 4 → 1 bei versiegeltem Eintrag) → corruptFile
        let manipulated = json.replacingOccurrences(of: "\"protection\":4", with: "\"protection\":1")
        #expect(manipulated != json)
        #expect(throws: SiegelError.corruptFile("entry.sealedState")) {
            try PayloadCodec.decode(try Self.padded(manipulated))
        }
    }

    /// ISO/IEC 7816-4-Polsterung wie `sodium_pad` (0x80, dann Nullen bis zum Vielfachen von 16 KiB).
    static func padded(_ json: String) throws -> SecureBytes {
        var bytes = Array(json.utf8)
        let size = (bytes.count / PayloadCodec.blockSize + 1) * PayloadCodec.blockSize
        bytes.append(0x80)
        bytes += [UInt8](repeating: 0, count: size - bytes.count)
        return try SecureBytes.copy(bytes)
    }
}

/// Exporte mit Eintrags-Schutz (SPEC §8 Hygiene, §16 Schutz 4/5 nie, §19 KeePass).
@Suite("Exporte mit Eintrags-Schutz")
struct KernSchutzExportTests {
    private final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var value: ([(VaultEntry, EntrySecrets)], String)?
        func set(_ v: ([(VaultEntry, EntrySecrets)], String)) { lock.withLock { value = v } }
        var get: ([(VaultEntry, EntrySecrets)], String)? { lock.withLock { value } }
    }

    private func mode(_ u: URL) -> Int {
        ((try? FileManager.default.attributesOfItem(atPath: u.path)[.posixPermissions]) as? Int) ?? -1
    }

    private func isEmptyDir(_ u: URL) -> Bool {
        ((try? FileManager.default.contentsOfDirectory(atPath: u.path)) ?? ["x"]).isEmpty
    }

    private func vaultMitAllenStufen() throws -> (SchutzTresor, [EntryProtection: VaultEntry]) {
        let t = try SchutzTresor.make()
        var list: [EntryProtection: VaultEntry] = [:]
        for p in EntryProtection.allCases {
            let e = schutzEntry("E\(p.rawValue)", protection: p)
            try t.vault.upsert(e)
            list[p] = e
        }
        return (t, list)
    }

    @Test("CSV: Schutz 4/5 fehlen; Schutz 2/3 mit einer Freigabe nach der Passwortprüfung; sync → factorMissing vor Argon2")
    func csv() async throws {
        let (t, list) = try vaultMitAllenStufen()
        let dir = t.f.dir.sub("Export")
        let counter = TestHooks.Counter()
        TestHooks.$kdfCounter.withValue(counter) {
            #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
                try t.vault.exportCSV(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets())
            }
        }
        #expect(counter.value == 0)
        await #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
            try await t.vault.exportCSV(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets(), entryFactors: nil)
        }
        await #expect(throws: SiegelError.wrongPassword) {
            try await t.vault.exportCSV(toParent: dir, masterPassword: KT.pw2, factors: FactorSecrets(), entryFactors: t.p)
        }
        #expect(t.p.counts == [0, 0, 0])
        #expect(isEmptyDir(dir))

        let url = try await t.vault.exportCSV(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets(),
                                              entryFactors: t.p)
        #expect(t.p.counts == [1, 0, 0])
        let text = String(decoding: try Data(contentsOf: url), as: UTF8.self)
        for (p, e) in list {
            #expect(text.contains(e.password) == (p < .maximal))
            #expect(text.contains(e.title) == (p < .maximal))
        }
        #expect(mode(url) == 0o600 && mode(url.deletingLastPathComponent()) == 0o700)
        #expect(url.deletingLastPathComponent().lastPathComponent.hasSuffix(".noindex"))

        // Nur offene und Schutz-4-Einträge: die sync-Variante genügt
        let t2 = try SchutzTresor.make()
        let offen = schutzEntry("Offen", protection: .normal)
        let vier = schutzEntry("Vier", protection: .maximal)
        try t2.vault.upsert(offen)
        try t2.vault.upsert(vier)
        let url2 = try t2.vault.exportCSV(toParent: t2.f.dir.sub("Export"), masterPassword: KT.pw1)
        let text2 = String(decoding: try Data(contentsOf: url2), as: UTF8.self)
        #expect(text2.contains(offen.password) && !text2.contains(vier.password) && !text2.contains("Vier"))
        #expect(t2.p.counts == [0, 0, 0])
    }

    @Test("KeePass: nur Stufen 1–3, eigenes starkes Export-Passwort, Schutz 4/5 fehlen, Datei-Hygiene")
    func keepass() async throws {
        let (t, list) = try vaultMitAllenStufen()
        let dir = t.f.dir.sub("Export")
        let counter = TestHooks.Counter()
        try TestHooks.$kdfCounter.withValue(counter) {
            do {
                _ = try t.vault.exportKeePass(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets(),
                                              exportPassword: "kurz")
                Issue.record("schwaches Export-Passwort angenommen")
            } catch SiegelError.passwordTooWeak {}
            #expect(throws: SiegelError.masterPasswordReused) {
                try t.vault.exportKeePass(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets(),
                                          exportPassword: KT.pw1)
            }
            #expect(throws: SiegelError.factorMissing(.secureEnclave)) {
                try t.vault.exportKeePass(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets(),
                                          exportPassword: KT.pw4)
            }
        }
        #expect(counter.value == 0)
        await #expect(throws: SiegelError.wrongPassword) {
            try await t.vault.exportKeePass(toParent: dir, masterPassword: KT.pw2, factors: FactorSecrets(),
                                            exportPassword: KT.pw4, entryFactors: t.p)
        }
        #expect(t.p.counts == [0, 0, 0])

        // Mit Test-Exporter: welche Einträge mit welchen Geheimteilen
        let box = Box()
        let hook = TestHooks.KeePassHook { items, password in
            box.set((items, password))
            return Data("KDBX-TEST".utf8)
        }
        let url = try await TestHooks.$keePassExporter.withValue(hook) {
            try await t.vault.exportKeePass(toParent: dir, masterPassword: KT.pw1, factors: FactorSecrets(),
                                            exportPassword: KT.pw4, entryFactors: t.p)
        }
        #expect(t.p.counts == [1, 0, 0])
        let (items, password) = try #require(box.get)
        #expect(password == KT.pw4)
        #expect(Set(items.map(\.0.id)) == Set([EntryProtection.normal, .fingerabdruck, .hoch].compactMap { list[$0]?.id }))
        for (entry, secrets) in items {
            let o = try #require(list.values.first { $0.id == entry.id })
            #expect(secrets == EntrySecrets(o))
            #expect(entry.title == o.title && entry.url == o.url && entry.username == o.username)
        }
        #expect(url.lastPathComponent == "Siegel-Export.kdbx")
        #expect(try Data(contentsOf: url) == Data("KDBX-TEST".utf8))
        #expect(mode(url) == 0o600 && mode(url.deletingLastPathComponent()) == 0o700)
        #expect(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
        #expect(try url.deletingLastPathComponent().resourceValues(forKeys: [.isExcludedFromBackupKey])
            .isExcludedFromBackup == true)

        // Echter Exporter (heute ein Platzhalter): Erfolg → Datei da; Fehler → es bleibt nichts liegen
        let dir2 = t.f.dir.sub("Export2")
        do {
            let real = try await t.vault.exportKeePass(toParent: dir2, masterPassword: KT.pw1, factors: FactorSecrets(),
                                                       exportPassword: KT.pw4, entryFactors: t.p)
            #expect(FileManager.default.fileExists(atPath: real.path))
        } catch is SiegelError {
            #expect(isEmptyDir(dir2))
        }

        // Stufe 4: notAllowedAtLevel vor Argon2
        let t4 = try SchutzTresor.make(.maximal)
        let c4 = TestHooks.Counter()
        TestHooks.$kdfCounter.withValue(c4) {
            #expect(throws: SiegelError.notAllowedAtLevel) {
                try t4.vault.exportKeePass(toParent: dir, masterPassword: KT.pw1, factors: try t4.k.secrets([.secureEnclave, .card]),
                                           exportPassword: KT.pw4)
            }
        }
        await #expect(throws: SiegelError.notAllowedAtLevel) {
            try await t4.vault.exportCSV(toParent: dir, masterPassword: KT.pw1,
                                         factors: try t4.k.secrets([.secureEnclave, .card]), entryFactors: t4.p)
        }
        #expect(c4.value == 0)
    }
}
