import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Interop in der Gegenrichtung (`windows/SPEC-WINDOWS.md` W7, SPEC §12 v4.6): Der Swift-Kern öffnet die vom C#-Kern
/// geschriebenen, eingefrorenen Dateien in `windows/tests/Fixtures/` (Werte in deren `README.md`) mit Passwort, festen
/// Software-Faktoren und Shamir-Teilen und vergleicht den Inhalt. Nur lesend: jeder Test arbeitet auf einer Kopie.
///
/// Windows-Hello-Art (W4.1): Einträge, deren Gerätefaktor unter Windows eingerichtet wurde, sind hier ein **anderes
/// Gerät** – `factorUnavailable(.secureEnclave)` ohne Provider-Aufruf; der Notfallweg öffnet alles, und Weiterschreiben
/// auf dem Mac lässt die Siegel der Hello-Art unverändert (C# deckt sie danach wieder auf, `CsHelloTests`).
@Suite("Interop: Dateien des C#-Kerns", .serialized)
struct CSharpFixtureTests {
    static let fixtures = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("windows/tests/Fixtures")
    static let referenz = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("referenz")
    /// KDF-Profil aller C#-Fixtures (256 MiB, t = 3).
    static let kdf = KDFParameters(opsLimit: 3, memLimitBytes: 256 << 20)

    static func f(_ b: UInt8) throws -> FactorSecret { try FactorSecret(copying: [UInt8](repeating: b, count: 32)) }

    /// Kopie einer Fixture als `Tresor.siegel` in einem frischen Store (echte KDF-Grenzen).
    static func store(_ name: String) throws -> (KernTempDir, VaultStore) {
        let dir = KernTempDir()
        let siegelDir = dir.sub("Siegel")
        try FileManager.default.copyItem(at: fixtures.appendingPathComponent(name),
                                         to: siegelDir.appendingPathComponent(VaultStore.vaultFileName))
        return (dir, VaultStore(directory: siegelDir, rollbackGuard: InMemoryRollbackGuard()))
    }

    static func sha256(_ url: URL) throws -> String {
        KT.hex(SHA256.hash(data: try Data(contentsOf: url)))
    }

    struct Erwartet {
        let title, username, password, url, notes, totp: String
        let history: [String]
        let protection: EntryProtection
        var deleted = false
    }

    /// Einträge von `cs_v2_beispiel.siegel` und `cs_v2_hello.siegel` (README, `CsBeispiel.Eintraege`).
    static let eintraege: [Erwartet] = [
        Erwartet(title: "Bibliothek Bern", username: "leserin.muster", password: "Buecher-Regal-42!",
                 url: "https://bibliothek.example.ch", notes: "Ausweisnummer steht auf der Karte.", totp: "", history: [],
                 protection: .normal),
        Erwartet(title: "Velo-Club", username: "velofahrer", password: "Kette+Sattel-77", url: "velo.example.ch", notes: "",
                 totp: "otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club",
                 history: ["Rad&Weg-2026"], protection: .fingerabdruck),
        Erwartet(title: "Krankenkasse", username: "versicherte.4711", password: "Praemie-2027!",
                 url: "https://kasse.example.ch", notes: "Versichertennummer 756.0000.0000.00", totp: "", history: [],
                 protection: .hoch),
        Erwartet(title: "Bank Thun", username: "kunde-0815", password: "Konto#Sicher-4", url: "https://bank.example.ch",
                 notes: "PIN-Brief im Ordner «Bank», Karte gültig bis 12/29",
                 totp: "otpauth://totp/Bank:kunde-0815?secret=KRSXG5CTMVRXEZLU&issuer=Bank",
                 history: ["Alt-Konto-3", "Alt-Konto-2"], protection: .maximal),
        Erwartet(title: "Krypto-Wallet", username: "", password: "Seed+Phrase-55", url: "",
                 notes: "Zeilen\nmit Umlauten: äöü, Zeichen: «» – Ende", totp: "", history: [], protection: .festung),
        Erwartet(title: "Alter Shop", username: "kaeufer", password: "Warenkorb-99", url: "https://shop.example.ch",
                 notes: "Konto gekündigt", totp: "", history: [], protection: .hoch, deleted: true),
    ]

    static func check(_ e: Erwartet, _ s: EntrySecrets) {
        #expect(s.password == e.password, "\(e.title): Passwort")
        #expect(s.notes == e.notes, "\(e.title): Notiz")
        #expect(s.totp == e.totp, "\(e.title): TOTP")
        #expect(s.history.map(\.password) == e.history, "\(e.title): Verlauf")
    }

    /// Software-Gegenseite der Eintrags-Faktoren von `cs_v2_beispiel.siegel` (Mac-Art, README): P-256-Skalar 88…,
    /// Karte q = 22…, Sicherheitsschlüssel 77….
    final class Beispiel: EntryFactorProvider, @unchecked Sendable {
        let key: P256.KeyAgreement.PrivateKey
        private let lock = NSLock()
        private var n = [0, 0, 0]
        var counts: [Int] { lock.withLock { n } }
        init() throws { key = try P256.KeyAgreement.PrivateKey(rawRepresentation: [UInt8](repeating: 0x88, count: 32)) }
        func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
            lock.withLock { n[0] += 1 }
            #expect(keyID == UUID(uuidString: "66666666-7777-4888-8999-AAAAAAAAAAAA"))
            let shared = try key.sharedSecretFromKeyAgreement(
                with: try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey))
            return try shared.withUnsafeBytes { try FactorSecret(copying: Array($0)) }
        }
        func cardSecret() async throws -> FactorSecret {
            lock.withLock { n[1] += 1 }
            return try CSharpFixtureTests.f(0x22)
        }
        func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
            lock.withLock { n[2] += 1 }
            #expect(credentialID == Data(repeating: 0x44, count: 64) && salt == Data(repeating: 0x66, count: 32))
            return try CSharpFixtureTests.f(0x77)
        }
    }

    // MARK: - cs_v2_stufe_a.siegel (Stufe A des C#-Kerns)

    @Test("cs_v2_stufe_a.siegel: Inhalt wie erwartet_v2_beispiel.json, Weiterschreiben, zwei Teile")
    func stufeA() throws {
        let (dir, store) = try Self.store("cs_v2_stufe_a.siegel")
        #expect(try Self.sha256(Self.fixtures.appendingPathComponent("cs_v2_stufe_a.siegel"))
            == "3c12350ee73bf1ffdbc2a8d3f5a28d70782c47ec9a1a3a35913bc60b4bb7bc76")
        let info = try store.inspect()
        #expect(info.kitID == "8K09-66VB" && info.factors == .all && info.recoveryScheme == .shamir2of3)
        #expect(info.vaultID == UUID(uuidString: "30BA11CE-0480-4A1B-B5B6-FD82D6B4F8D3"))
        let factors = FactorSecrets(secureEnclave: try Self.f(0x11), card: try Self.f(0x22), securityKey: try Self.f(0x33))
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: "Wq7!vTz#2pLm9@Xc4$Rb8&Hn6*Kd",
                                                              factors: factors)))
        #expect(vault.level == .festung && vault.enrolledFactors == .all && vault.recoveryConfirmed)
        #expect(!vault.entryDeviceIsWindowsHello)
        // Inhalt = dieselben drei Einträge wie die Mac-Beispieldatei v2 (referenz/erwartet_v2_beispiel.json).
        let json = try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: Self.referenz.appendingPathComponent("erwartet_v2_beispiel.json"))) as? [String: Any])
        let soll = try #require(json["eintraege"] as? [[String: Any]])
        #expect(vault.entries.count == soll.count)
        for (ist, s) in zip(vault.entries, soll) {
            #expect(ist.title == s["title"] as? String)
            #expect(!ist.secretsSealed)
            for (feld, wert) in [("username", ist.username), ("password", ist.password), ("url", ist.url),
                                 ("totp", ist.totp), ("notes", ist.notes)] {
                if let erwartet = s[feld] as? String { #expect(wert == erwartet, "\(ist.title): \(feld)") }
            }
            #expect(ist.history.map(\.password) == (s["verlauf"] as? [String] ?? []))
            for stueck in s["notesEnthaelt"] as? [String] ?? [] { #expect(ist.notes.contains(stueck)) }
        }
        // Der Swift-Kern schreibt die C#-Datei weiter (Stufe 5: neuer Eintrag mit Schutz 2, Mac-Art).
        try vault.upsert(kernEntry("Von Swift"))
        #expect(vault.entries.first { $0.title == "Von Swift" }?.secretsSealed == true)
        vault.lock()
        let shares = ["05JNX-WRBPA-XC60H-CBAAX-TXKNT-0AZF4-Q7Z9C-4AP52-V5D7A-RRDAZ-G9XRT-E",
                      "09X66-X43YV-P0EME-S5C5Z-6VSF6-5CQBN-RH41R-1EGCG-6JZ50-6SE01-749ZW-A",
                      "0E382-2FVSB-FB4R4-A0J4E-K48SD-TA0P7-A3KXM-D1FVQ-DZHBM-CY6RK-EZPKX-R"]
        #expect(try store.checkRecoveryShares([shares[0], shares[2]]) == [.exact, .exact])
        let rec = try store.recover(shares: [shares[1], shares[2]], newMasterPassword: KT.pw2, kdf: Self.kdf)
        #expect(rec.entries.count == 4 && rec.level == .standard)
        #expect(rec.entries.first { $0.title == "Von Swift" }?.password == "Geheim-123")
        _ = dir
    }

    // MARK: - cs_v2_beispiel.siegel (Stufe B, Mac-Art)

    @Test("cs_v2_beispiel.siegel: Stufe 4, Schutz 1–5 aufdecken, Papierkorb, Notfallweg mit jedem Paar Teile")
    func beispiel() async throws {
        #expect(try Self.sha256(Self.fixtures.appendingPathComponent("cs_v2_beispiel.siegel"))
            == "3d3a1655d7365ec4b6c7c020e23b8f1cc97d6ae765003e65cd1046f1d00e52f2")
        let shares = ["06YGZ-YXAW9-Z5KD3-YN8VT-1A3ZH-0D8ZG-THQ01-PRE3N-R2TWJ-9RN8C-EDHF3-4",
                      "0BZ59-XFH33-V4CE1-C8VDW-J9CWA-3HZ9M-GEQ8P-W2PCX-QFH0F-JZMTG-MSVJH-4",
                      "0CV98-1HH9T-7BNDF-BXDVE-WQHM3-2TDVQ-9V9MV-N73Y5-J8KB8-SNBA0-X5FVF-V"]
        let password = "Fj8#qW2!xN5@tR9$kP3&vL6*hZ4m"
        let erzeugt = Date(timeIntervalSince1970: 1_792_317_600)
        do {
            let (dir, store) = try Self.store("cs_v2_beispiel.siegel")
            let info = try store.inspect()
            #expect(info.kitID == "XNXZ-QZ73" && info.factors == [.secureEnclave, .card] && info.recoveryScheme == .shamir2of3)
            #expect(info.vaultID == UUID(uuidString: "0BEDA2B0-B055-4D1F-ADBD-E35461ED501A"))
            #expect(info.seKeyID == UUID(uuidString: "11111111-2222-4333-8444-555555555555"))
            let vault = try #require(KT.unlocked(try store.unlock(
                masterPassword: password, factors: FactorSecrets(secureEnclave: try Self.f(0x11), card: try Self.f(0x22)))))
            #expect(vault.level == .maximal && vault.enrolledFactors == .all && vault.recoveryConfirmed)
            #expect(vault.generation == 10 && !vault.entryDeviceIsWindowsHello)
            #expect(vault.entries.map(\.title) == Self.eintraege.filter { !$0.deleted }.map(\.title))
            #expect(vault.deletedEntries.map(\.title) == ["Alter Shop"])
            let p = try Beispiel()
            for e in Self.eintraege {
                let stored = try #require((e.deleted ? vault.deletedEntries : vault.entries).first { $0.title == e.title })
                #expect(stored.username == e.username && stored.url == e.url && stored.protection == e.protection)
                #expect(stored.secretsSealed == (e.protection > .normal) && stored.created == erzeugt)
                if e.deleted {
                    #expect(stored.deletedAt == erzeugt)
                    try vault.restore(id: stored.id)
                }
                let before = p.counts
                Self.check(e, try await vault.revealSecrets(id: stored.id, factors: e.protection == .normal ? nil : p))
                let m = e.protection.factors
                #expect(p.counts == [before[0] + (m.contains(.secureEnclave) ? 1 : 0),
                                     before[1] + (m.contains(.card) ? 1 : 0),
                                     before[2] + (m.contains(.securityKey) ? 1 : 0)])
            }
            vault.lock()
            _ = dir
        }
        for (i, j) in [(0, 1), (1, 2), (2, 0)] {
            let (dir, store) = try Self.store("cs_v2_beispiel.siegel")
            #expect(try store.checkRecoveryShares([shares[i], shares[j]]) == [.exact, .exact])
            if i == 1 {
                let rec = try store.recover(shares: [shares[i], shares[j]], newMasterPassword: KT.pw2, kdf: Self.kdf)
                #expect(rec.level == .standard)
                for e in Self.eintraege {
                    let got = try #require((e.deleted ? rec.deletedEntries : rec.entries).first { $0.title == e.title })
                    #expect(!got.secretsSealed)
                    Self.check(e, EntrySecrets(password: got.password, notes: got.notes, totp: got.totp, history: got.history))
                }
            }
            _ = dir
        }
    }

    // MARK: - Windows-Hello-Art (cs_v2_hello.siegel, cs_inhalt_hello.json, swift_hello_aus_cs.siegel)

    static let helloPassword = "Rk5$wT9!bN2#qX7@mH4&zP8*vC3j"
    static let helloShares = ["06VAM-QNR4Y-C2AZ7-M7Z0C-QJGYH-VAAPK-JG3WC-9T66T-TVRRH-5AH9Y-S6YFG-M",
                              "08RJR-NEEEG-H8EF7-DDX6F-9CDK7-3WAGS-7M4WY-E28NJ-RTZ5F-WV6W9-0RVZF-R",
                              "0D6AF-98N8P-YH1X8-KBZ0Y-3611M-CATK2-V1RRG-3RD33-7XSEQ-MC2E0-8D618-5"]
    static let helloKeyID = UUID(uuidString: "B6666666-7777-4888-8999-AAAAAAAAAAAA")

    static func helloFactors() throws -> FactorSecrets {
        FactorSecrets(secureEnclave: try f(0x11), card: try f(0x22))
    }

    /// Zählt jeden Aufruf; beim „anderen Gerät“ darf keiner kommen.
    final class Zaehler: EntryFactorProvider, @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        var calls: Int { lock.withLock { n } }
        func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
            lock.withLock { n += 1 }
            return try CSharpFixtureTests.f(0x01)
        }
        func cardSecret() async throws -> FactorSecret {
            lock.withLock { n += 1 }
            return try CSharpFixtureTests.f(0x22)
        }
        func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
            lock.withLock { n += 1 }
            return try CSharpFixtureTests.f(0x77)
        }
    }

    static func isFactorUnavailableSE(_ e: Error) -> Bool {
        if case .factorUnavailable(.secureEnclave) = e as? SiegelError { return true }
        return false
    }

    /// Die Änderungen, die der Mac an einem Hello-Tresor machen darf (ohne Gerätefaktor): ein offenes Passwort ändern,
    /// einen versiegelten Eintrag umbenennen. Genau so entstand `swift_hello_aus_cs.siegel`.
    static func macAenderungen(_ vault: UnlockedVault) throws {
        var bib = try #require(vault.entries.first { $0.title == "Bibliothek Bern" })
        bib.password = "Mac-Eintrag-61!"
        try vault.upsert(bib)
        var velo = try #require(vault.entries.first { $0.title == "Velo-Club" })
        #expect(velo.secretsSealed)
        velo.title = "Velo-Club Bern"
        try vault.upsert(velo)
    }

    @Test("cs_v2_hello.siegel: Windows-Hello-Einträge sind ein anderes Gerät, Notfallweg öffnet alles")
    func hello() async throws {
        #expect(try Self.sha256(Self.fixtures.appendingPathComponent("cs_v2_hello.siegel"))
            == "8c209465cc1a124fe9695db28718bbb7b9074ff9d70a4839cafc31030d322400")
        let erzeugt = Date(timeIntervalSince1970: 1_792_321_200)
        let (dir, store) = try Self.store("cs_v2_hello.siegel")
        let info = try store.inspect()
        #expect(info.kitID == "Q19F-W07N" && info.factors == [.secureEnclave, .card] && info.recoveryScheme == .shamir2of3)
        #expect(info.vaultID == UUID(uuidString: "15467C6E-D6A8-456B-A31E-F62AFE0C10C5"))
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: Self.helloPassword,
                                                              factors: try Self.helloFactors())))
        #expect(vault.level == .maximal && vault.enrolledFactors == .all && vault.entryDeviceIsWindowsHello)
        let original = try #require(vault.contentForTesting)
        #expect(original.entryFactors.windowsHello?.keyID == Self.helloKeyID && original.entryFactors.secureEnclave == nil)
        #expect(original.sealed.values.allSatisfy { $0.blob.factors.hello != nil && $0.blob.factors.seEphemeral == nil })
        #expect(original.sealed.count == 5 && original.recoveryGroups.count == 3)
        let zaehler = Zaehler()
        for e in Self.eintraege {
            let stored = try #require((e.deleted ? vault.deletedEntries : vault.entries).first { $0.title == e.title })
            #expect(stored.username == e.username && stored.url == e.url && stored.protection == e.protection)
            #expect(stored.created == erzeugt)
            if e.protection == .normal {
                Self.check(e, try await vault.revealSecrets(id: stored.id, factors: nil))
                continue
            }
            // Anderes Gerät: mit und ohne Provider, ohne dass er gefragt wird (auch nicht nach Karte oder Schlüssel).
            for provider in [zaehler as EntryFactorProvider?, nil] {
                await #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
                    _ = try await vault.revealSecrets(id: stored.id, factors: provider)
                }
            }
        }
        #expect(zaehler.calls == 0)
        // Neu versiegeln geht auf dem Mac nicht (Stufe 4: Schutz ≥ 2) – nichts wird geschrieben.
        let generation = vault.generation
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) { try vault.upsert(kernEntry("Neu am Mac")) }
        let velo = try #require(vault.entries.first { $0.title == "Velo-Club" })
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try vault.setProtection(.fingerabdruck, id: velo.id, secrets: EntrySecrets(password: "x"))
        }
        #expect(vault.generation == generation)
        // Erlaubt: offene Felder ändern. Die Siegel der Hello-Art bleiben dabei unverändert.
        try Self.macAenderungen(vault)
        vault.lock()
        let again = try #require(KT.unlocked(try store.unlock(masterPassword: Self.helloPassword,
                                                             factors: try Self.helloFactors())))
        let after = try #require(again.contentForTesting)
        #expect(after.entryFactors == original.entryFactors)
        #expect(after.sealed == original.sealed && after.recoveryGroups == original.recoveryGroups)
        #expect(again.entries.first { $0.title == "Velo-Club Bern" }?.secretsSealed == true)
        #expect(again.entries.first { $0.title == "Bibliothek Bern" }?.password == "Mac-Eintrag-61!")
        again.lock()
        // Notfallweg: jeder Eintrag lesbar, danach Stufe 1 ohne Windows-Hello-Schlüssel.
        #expect(try store.checkRecoveryShares([Self.helloShares[2], Self.helloShares[0]]) == [.exact, .exact])
        let rec = try store.recover(shares: [Self.helloShares[2], Self.helloShares[0]], newMasterPassword: KT.pw2,
                                    kdf: Self.kdf)
        #expect(rec.level == .standard && !rec.entryDeviceIsWindowsHello)
        for e in Self.eintraege where e.title != "Bibliothek Bern" {
            let title = e.title == "Velo-Club" ? "Velo-Club Bern" : e.title
            let got = try #require((e.deleted ? rec.deletedEntries : rec.entries).first { $0.title == title })
            #expect(!got.secretsSealed && got.protection == .normal)
            Self.check(e, EntrySecrets(password: got.password, notes: got.notes, totp: got.totp, history: got.history))
        }
        _ = dir
    }

    @Test("cs_inhalt_hello.json: V der Hello-Art und vernichtbarer Eintrag, Swift kodiert bytegleich neu")
    func helloInhalt() throws {
        let url = Self.fixtures.appendingPathComponent("cs_inhalt_hello.json")
        #expect(try Self.sha256(url) == "70699a8d67b8c9a1f521ac47dfb6e5e2aeb0e2103eb4f8c01e197cc3cf554acf")
        let json = try String(contentsOf: url, encoding: .utf8)
        let (content, _) = try PayloadCodec.decode(try KernBerichtTests.padded(json))
        #expect(content.level == .maximal && content.entryFactors.windowsHello != nil)
        let v = try #require(content.destruction?.vKey)
        #expect(v.isWindowsHello && v.publicKey.isEmpty && v.keyID == UUID(uuidString: "C7777777-8888-4999-8AAA-BBBBBBBBBBBB"))
        #expect(content.destruction?.duress != nil && content.destruction?.settings.deadmanDays == 30)
        #expect(content.destructible.count == 1 && content.destructible.values.allSatisfy { $0.factors.hello != nil })
        #expect(content.deviceArtMatches(try #require(content.destructible.values.first).factors, destructible: true))
        let (again, _) = try PayloadCodec.encode(content)
        #expect(PayloadCodec.jsonStringForTesting(again) == json)
        // Mischformen sind beschädigt (wie im C#-Kern): beide Arten, unbekannte Version, V ohne öffentlichen Teil.
        for (alt, neu) in [("\"version\":1}", "\"version\":2}"), ("\"windowsHello\":1}", "\"windowsHello\":2}"),
                           ("\"windowsHello\":1}", "\"windowsHello\":0}")] {
            let manipuliert = json.replacingOccurrences(of: alt, with: neu)
            #expect(manipuliert != json)
            #expect(throws: SiegelError.self) { try PayloadCodec.decode(try KernBerichtTests.padded(manipuliert)) }
        }
    }

    @Test("swift_hello_aus_cs.siegel: vom Swift-Kern weitergeschrieben, gleiche Siegel wie die C#-Datei")
    func helloSwiftDatei() throws {
        #expect(try Self.sha256(Self.fixtures.appendingPathComponent("swift_hello_aus_cs.siegel"))
            == Self.swiftHelloSHA256)
        let (dir, store) = try Self.store("swift_hello_aus_cs.siegel")
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: Self.helloPassword,
                                                              factors: try Self.helloFactors())))
        #expect(vault.entryDeviceIsWindowsHello && vault.entries.contains { $0.title == "Velo-Club Bern" })
        vault.lock()
        _ = dir
    }

    /// SHA-256 von `swift_hello_aus_cs.siegel` (README).
    static let swiftHelloSHA256 = "c91351a4947d9700958cae2f80934bfd71be4efb3c785891076c8e6922b1152d"

    /// Erzeugt `swift_hello_aus_cs.siegel` – nur von Hand:
    /// `SIEGEL_SWIFT_HELLO_ZIEL=/pfad/swift_hello_aus_cs.siegel swift test --filter CSharpFixtureTests`.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SIEGEL_SWIFT_HELLO_ZIEL"] != nil))
    func erzeugeSwiftHelloDatei() throws {
        guard let ziel = ProcessInfo.processInfo.environment["SIEGEL_SWIFT_HELLO_ZIEL"] else { return }
        try TestHooks.$now.withValue(Date(timeIntervalSince1970: 1_792_324_800)) {
            let (dir, store) = try Self.store("cs_v2_hello.siegel")
            let vault = try #require(KT.unlocked(try store.unlock(masterPassword: Self.helloPassword,
                                                                  factors: try Self.helloFactors())))
            try Self.macAenderungen(vault)
            vault.lock()
            let target = URL(fileURLWithPath: ziel)
            try? FileManager.default.removeItem(at: target)
            try FileManager.default.copyItem(at: store.vaultURL, to: target)
            _ = dir
        }
    }
}
