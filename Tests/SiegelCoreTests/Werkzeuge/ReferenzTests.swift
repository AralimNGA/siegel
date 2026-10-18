import Foundation
import Testing
@testable import SiegelCore

// Gegenprobe Swift ↔ Python (SPEC §21): Die unabhängige Python-Referenz (`referenz/siegel_referenz.py`, nur aus
// SPEC.md geschrieben) und der Swift-Kern müssen dieselbe Beispieldatei gleich lesen; KeePass-Exporte aus Swift
// muss Python öffnen. Läuft nur, wenn Python 3.12 (python.org) und libsodium (Homebrew) an den Standardorten
// liegen – sonst übersprungen (z. B. in der CI). Argon2 mit 256 MiB → `.serialized`.

enum ReferenzUmgebung {
    static let python = ProcessInfo.processInfo.environment["SIEGEL_PYTHON"]
        ?? "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
    static let libsodium = ProcessInfo.processInfo.environment["SIEGEL_LIBSODIUM"]
        ?? "/opt/homebrew/opt/libsodium/lib/libsodium.dylib"
    /// Paketordner (Tests/SiegelCoreTests/Werkzeuge/<diese Datei> → vier Ebenen hoch).
    static let paket = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    static let skript = paket.appendingPathComponent("referenz/siegel_referenz.py")
    static let fixtures = paket.appendingPathComponent("Tests/SiegelCoreTests/Fixtures")

    static var verfuegbar: Bool {
        FileManager.default.isExecutableFile(atPath: python) && FileManager.default.fileExists(atPath: libsodium)
            && FileManager.default.fileExists(atPath: skript.path)
    }

    struct Fehlschlag: Error, CustomStringConvertible {
        let description: String
    }

    /// Startet die Referenz; Passwort über stdin. Ergebnis: JSON-Objekt oder Fehlertext (stderr).
    static func lauf(_ art: String, _ datei: URL, passwort: String, argumente: [String] = []) throws -> [String: Any] {
        let prozess = Process()
        prozess.executableURL = URL(fileURLWithPath: python)
        prozess.arguments = ["-I", skript.path, art, datei.path] + argumente
        var umgebung = ["SIEGEL_LIBSODIUM": libsodium]
        umgebung["PATH"] = "/usr/bin:/bin"
        prozess.environment = umgebung
        let eingabe = Pipe(), ausgabe = Pipe(), fehler = Pipe()
        prozess.standardInput = eingabe
        prozess.standardOutput = ausgabe
        prozess.standardError = fehler
        try prozess.run()
        eingabe.fileHandleForWriting.write(Data(passwort.utf8))
        try eingabe.fileHandleForWriting.close()
        let daten = ausgabe.fileHandleForReading.readDataToEndOfFile()
        let meldung = String(decoding: fehler.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        prozess.waitUntilExit()
        guard prozess.terminationStatus == 0 else {
            throw Fehlschlag(description: meldung.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        guard let objekt = try JSONSerialization.jsonObject(with: daten) as? [String: Any] else {
            throw Fehlschlag(description: "kein JSON")
        }
        return objekt
    }

    /// Wert einer Tabellenzeile `| Name | `Wert` … |` im Abschnitt zur Datei.
    static func readmeWert(_ name: String, abschnitt datei: String) throws -> String {
        let text = try String(contentsOf: fixtures.appendingPathComponent("README.md"), encoding: .utf8)
        let teile = text.components(separatedBy: "\n## ")
        guard let teil = teile.first(where: { $0.split(separator: "\n").first?.contains(datei) == true }) else {
            throw Fehlschlag(description: "Abschnitt fehlt")
        }
        for zeile in teil.split(separator: "\n") where zeile.hasPrefix("| " + name + " |") {
            let spalten = zeile.split(separator: "`")
            if spalten.count >= 2 { return String(spalten[1]) }
        }
        throw Fehlschlag(description: "Zeile fehlt")
    }
}

@Suite("Referenz: Swift ↔ Python", .serialized, .enabled(if: ReferenzUmgebung.verfuegbar))
struct ReferenzTests {

    @Test("v1-Beispieldatei: Swift-Kern und Python-Referenz lesen denselben Inhalt")
    func v1Beispiel() throws {
        let passwort = try ReferenzUmgebung.readmeWert("Master-Passwort", abschnitt: "v1_beispiel.siegel")
        let fixture = ReferenzUmgebung.fixtures.appendingPathComponent("v1_beispiel.siegel")

        // Python
        let python = try ReferenzUmgebung.lauf("siegel", fixture, passwort: passwort)
        let inhalt = try #require(python["inhalt"] as? [String: Any])
        let pyEintraege = try #require(inhalt["entries"] as? [[String: Any]])

        // Swift (Kern, öffentliche Schnittstelle) in einem Temp-Ordner
        let ordner = FileManager.default.temporaryDirectory.appendingPathComponent("referenz-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: ordner, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: ordner) }
        let store = VaultStore(directory: ordner, rollbackGuard: InMemoryRollbackGuard())
        try FileManager.default.copyItem(at: fixture, to: store.vaultURL)
        let vault: UnlockedVault
        switch try store.unlock(masterPassword: passwort) {
        case .unlocked(let v): vault = v
        case .rollbackSuspected(let v, _, _): vault = v
        }
        defer { vault.lock() }

        #expect(python["vaultID"] as? String == vault.vaultID.uuidString)
        #expect(python["kitID"] as? String == vault.kitID)
        #expect((python["generation"] as? NSNumber)?.uint64Value == vault.generation)
        let kdf = try #require(python["kdf"] as? [String: Any])
        #expect((kdf["opsLimit"] as? NSNumber)?.uint32Value == vault.kdf.opsLimit)
        #expect((kdf["memLimitBytes"] as? NSNumber)?.uint64Value == vault.kdf.memLimitBytes)
        #expect((inhalt["recoveryConfirmedAt"] is NSNull) == !vault.recoveryConfirmed)

        let swiftEintraege = vault.entries
        #expect(pyEintraege.count == swiftEintraege.count)
        for py in pyEintraege {
            let id = try #require((py["id"] as? String).flatMap(UUID.init(uuidString:)))
            let sw = try #require(swiftEintraege.first { $0.id == id })
            #expect(py["title"] as? String == sw.title)
            #expect(py["username"] as? String == sw.username)
            #expect(py["password"] as? String == sw.password)
            #expect(py["url"] as? String == sw.url)
            #expect(py["notes"] as? String == sw.notes)
            let verlauf = (py["history"] as? [[String: Any]] ?? []).compactMap { $0["password"] as? String }
            #expect(verlauf == sw.history.map(\.password))
            #expect((py["created"] as? NSNumber)?.doubleValue == sw.created.timeIntervalSince1970)
        }
    }

    @Test("v2-Beispieldatei (Stufe 5): Swift-Kern und Python-Referenz lesen mit denselben Faktoren denselben Inhalt")
    func v2Beispiel() throws {
        let passwort = try ReferenzUmgebung.readmeWert("Master-Passwort", abschnitt: "v2_beispiel.siegel")
        let fixture = ReferenzUmgebung.fixtures.appendingPathComponent("v2_beispiel.siegel")
        let se = try ReferenzUmgebung.readmeWert("Faktor Secure Enclave (Hex)", abschnitt: "v2_beispiel.siegel")
        let karte = try ReferenzUmgebung.readmeWert("Faktor Karte (Hex)", abschnitt: "v2_beispiel.siegel")
        let fido = try ReferenzUmgebung.readmeWert("Faktor FIDO2 (Hex)", abschnitt: "v2_beispiel.siegel")

        // Python
        let python = try ReferenzUmgebung.lauf("siegel", fixture, passwort: passwort,
                                               argumente: ["--se", se, "--karte", karte, "--fido", fido])
        let inhalt = try #require(python["inhalt"] as? [String: Any])
        let pyEintraege = try #require(inhalt["entries"] as? [[String: Any]])

        // Swift (Kern, öffentliche Schnittstelle)
        func faktor(_ hex: String) throws -> FactorSecret {
            var bytes: [UInt8] = []
            var rest = Substring(hex)
            while rest.count >= 2 {
                bytes.append(try #require(UInt8(rest.prefix(2), radix: 16)))
                rest = rest.dropFirst(2)
            }
            return try FactorSecret(copying: bytes)
        }
        let faktoren = FactorSecrets(secureEnclave: try faktor(se), card: try faktor(karte),
                                     securityKey: try faktor(fido))
        let ordner = FileManager.default.temporaryDirectory.appendingPathComponent("referenz-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: ordner, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: ordner) }
        let store = VaultStore(directory: ordner, rollbackGuard: InMemoryRollbackGuard())
        try FileManager.default.copyItem(at: fixture, to: store.vaultURL)
        let kopf = try store.inspect()
        let vault: UnlockedVault
        switch try store.unlock(masterPassword: passwort, factors: faktoren) {
        case .unlocked(let v): vault = v
        case .rollbackSuspected(let v, _, _): vault = v
        }
        defer { vault.lock() }

        #expect(python["formatVersion"] as? Int == Int(kopf.formatVersion))
        #expect(python["factorMask"] as? Int == Int(kopf.factors.rawValue))
        #expect(python["recoveryScheme"] as? Int == Int(kopf.recoveryScheme.rawValue))
        #expect(python["seKeyID"] as? String == kopf.seKeyID?.uuidString)
        #expect(python["vaultID"] as? String == vault.vaultID.uuidString)
        #expect(python["kitID"] as? String == vault.kitID)
        #expect(python["kitID"] as? String == kopf.kitID)
        #expect((python["generation"] as? NSNumber)?.uint64Value == vault.generation)
        #expect((inhalt["level"] as? NSNumber)?.intValue == vault.level.rawValue)

        let swiftEintraege = vault.entries
        #expect(pyEintraege.count == swiftEintraege.count)
        for py in pyEintraege {
            let id = try #require((py["id"] as? String).flatMap(UUID.init(uuidString:)))
            let sw = try #require(swiftEintraege.first { $0.id == id })
            #expect(py["title"] as? String == sw.title)
            #expect(py["username"] as? String == sw.username)
            #expect(py["password"] as? String == sw.password)
            #expect(py["url"] as? String == sw.url)
            #expect(py["notes"] as? String == sw.notes)
            #expect(py["totp"] as? String == sw.totp)
            #expect((py["protection"] as? NSNumber)?.intValue == sw.protection.rawValue)
            let verlauf = (py["history"] as? [[String: Any]] ?? []).compactMap { $0["password"] as? String }
            #expect(verlauf == sw.history.map(\.password))
        }
    }

    @Test("Python lehnt die Beispieldatei mit falschem Passwort und mit gekipptem Byte ab")
    func ablehnung() throws {
        let passwort = try ReferenzUmgebung.readmeWert("Master-Passwort", abschnitt: "v1_beispiel.siegel")
        let fixture = ReferenzUmgebung.fixtures.appendingPathComponent("v1_beispiel.siegel")
        #expect(throws: (any Error).self) { try ReferenzUmgebung.lauf("siegel", fixture, passwort: passwort + "!") }
        var daten = try Data(contentsOf: fixture)
        daten[5000] ^= 0x10
        let kopie = FileManager.default.temporaryDirectory.appendingPathComponent("gekippt-\(UUID().uuidString).siegel")
        try daten.write(to: kopie)
        defer { try? FileManager.default.removeItem(at: kopie) }
        do {
            _ = try ReferenzUmgebung.lauf("siegel", kopie, passwort: passwort)
            Issue.record("gekippte Datei wurde geöffnet")
        } catch let fehler as ReferenzUmgebung.Fehlschlag {
            #expect(fehler.description.contains("file.checksum"))
        }
    }

    @Test("KeePass-Export aus Swift: Python liest alle Felder byte-genau (Testschalter-KDF)")
    func kdbxSchnell() throws {
        let items = kdbxBeispielEintraege()
        try pruefeKDBX(try KeePassExport.kdbx(items, password: kdbxPasswort, kdf: kdbxTestKDF), items, speicher: 64 << 10)
    }

    @Test("KeePass-Export mit den echten Parametern (Argon2id 256 MiB, t = 3) ist mit libsodium lesbar")
    func kdbxEcht() throws {
        let items = Array(kdbxBeispielEintraege().prefix(2))
        try pruefeKDBX(try KeePassExport.kdbx(items, password: kdbxPasswort), items, speicher: 256 << 20)
    }

    @Test("Frischer KeePass-Export über den Tresor (UnlockedVault.exportKeePass, echte Parameter): Python liest ihn")
    func kdbxUeberTresor() throws {
        let t = try KernVault.make()
        defer { t.vault.lock() }
        var mitTOTP = kernEntry("Velo-Club", user: "velofahrer", password: "Kette+Sattel-77", url: "velo.example.ch",
                                notes: "Zeile 1\nZeile 2 – «äöü»")
        mitTOTP.totp = "otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club"
        try t.vault.upsert(kernEntry("Bibliothek", password: "Buecher <&> \"Regal\" '42'"))
        try t.vault.upsert(mitTOTP)
        let geloescht = kernEntry("Gelöscht", password: "weg-damit-1")
        try t.vault.upsert(geloescht)
        try t.vault.delete(id: geloescht.id)

        let ziel = t.dir.sub("export")
        let datei = try t.vault.exportKeePass(toParent: ziel, masterPassword: KT.pw1, factors: FactorSecrets(),
                                              exportPassword: KT.pw2)
        #expect(datei.lastPathComponent == "Siegel-Export.kdbx")
        #expect(datei.deletingLastPathComponent().pathExtension == "noindex")
        let python = try ReferenzUmgebung.lauf("kdbx", datei, passwort: KT.pw2)
        let kdf = try #require(python["kdf"] as? [String: Any])
        #expect((kdf["M"] as? NSNumber)?.uint64Value == 256 << 20)
        let gruppe = try #require(python["gruppe"] as? [String: Any])
        let eintraege = try #require(gruppe["eintraege"] as? [[String: Any]])
        let swift = t.vault.entries
        #expect(eintraege.count == swift.count)
        for py in eintraege {
            let werte = try #require(py["werte"] as? [String: String])
            let id = try #require((py["uuid"] as? String).flatMap(UUID.init(uuidString:)))
            let sw = try #require(swift.first { $0.id == id })
            #expect(werte["Title"] == sw.title)
            #expect(werte["UserName"] ?? "" == sw.username)
            #expect(werte["Password"] ?? "" == sw.password)
            #expect(werte["URL"] ?? "" == sw.url)
            #expect(werte["Notes"] ?? "" == sw.notes)
            #expect(werte["otp"] == KeePassExport.otpValue(sw.totp, title: sw.title).nilWennLeer)
        }
    }

    private func pruefeKDBX(_ data: Data, _ items: [(VaultEntry, EntrySecrets)], speicher: UInt64) throws {
        let datei = FileManager.default.temporaryDirectory.appendingPathComponent("export-\(UUID().uuidString).kdbx")
        try data.write(to: datei)
        defer { try? FileManager.default.removeItem(at: datei) }
        let python = try ReferenzUmgebung.lauf("kdbx", datei, passwort: kdbxPasswort)
        #expect(python["version"] as? String == "4.1")
        #expect(python["generator"] as? String == "Siegel")
        let kdf = try #require(python["kdf"] as? [String: Any])
        #expect((kdf["M"] as? NSNumber)?.uint64Value == speicher)
        #expect((kdf["P"] as? NSNumber)?.intValue == 1)
        #expect((kdf["salzLaenge"] as? NSNumber)?.intValue == 16)
        let gruppe = try #require(python["gruppe"] as? [String: Any])
        #expect(gruppe["name"] as? String == "Siegel")
        let eintraege = try #require(gruppe["eintraege"] as? [[String: Any]])
        #expect(eintraege.count == items.count)
        for (py, (entry, secrets)) in zip(eintraege, items) {
            let werte = try #require(py["werte"] as? [String: String])
            #expect(py["uuid"] as? String == entry.id.uuidString)
            #expect(Array((werte["Title"] ?? "-").utf8) == Array(entry.title.utf8))
            #expect(Array((werte["UserName"] ?? "-").utf8) == Array(entry.username.utf8))
            #expect(Array((werte["Password"] ?? "-").utf8) == Array(secrets.password.utf8))
            #expect(Array((werte["URL"] ?? "-").utf8) == Array(entry.url.utf8))
            #expect(Array((werte["Notes"] ?? "-").utf8) == Array(secrets.notes.utf8))
            #expect(werte["otp"] == KeePassExport.otpValue(secrets.totp, title: entry.title).nilWennLeer)
            let geschuetzt = py["geschuetzt"] as? [String] ?? []
            #expect(geschuetzt.contains("Password"))
            #expect((py["erstellt"] as? NSNumber)?.int64Value == Int64(floor(entry.created.timeIntervalSince1970)))
            #expect((py["geaendert"] as? NSNumber)?.int64Value == Int64(floor(entry.modified.timeIntervalSince1970)))
            #expect((py["verlauf"] as? NSNumber)?.intValue == 0)
        }
        // Falsches Passwort scheitert in Python am Kopf-HMAC
        do {
            _ = try ReferenzUmgebung.lauf("kdbx", datei, passwort: kdbxPasswort + "x")
            Issue.record("falsches Passwort wurde angenommen")
        } catch let fehler as ReferenzUmgebung.Fehlschlag {
            #expect(fehler.description.contains("kdbx.passwortOderKopf"))
        }
    }
}

private extension String {
    var nilWennLeer: String? { isEmpty ? nil : self }
}
