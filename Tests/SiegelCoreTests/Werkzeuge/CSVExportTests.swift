import Foundation
import Testing
@testable import SiegelCore

// Tests für CSVExport (SPEC §7.9, §8): Kopf, alle Felder zitiert, CRLF, ohne BOM, ohne Gelöschte und Verlauf,
// Rundlauf Export → Import über das Chrome-Format. Alle Daten sind erfunden.

@Suite("CSV-Export")
struct CSVExportTests {

    @Test("Kopfzeile, alle Felder zitiert, CRLF, UTF-8 ohne BOM")
    func format() {
        var entry = VaultEntry(title: "Bank, Privat", username: "anna", password: "a\"b",
                               url: "https://bank.example", notes: "Zeile 1\nZeile 2")
        entry.history = [PasswordHistoryItem(password: "altes-geheimnis", changed: Date())]
        let data = CSVExport.export([entry])
        let expected = "\"name\",\"url\",\"username\",\"password\",\"note\"\r\n"
            + "\"Bank, Privat\",\"https://bank.example\",\"anna\",\"a\"\"b\",\"Zeile 1\nZeile 2\"\r\n"
        #expect(Array(data) == Array(expected.utf8))
        #expect(data.first == 0x22)                                   // kein BOM
        #expect(String(data: data, encoding: .utf8)?.contains("altes-geheimnis") == false)   // kein Verlauf
    }

    @Test("2FA-Geheimnis (totp) wird nicht exportiert, auch nicht in den Notizen")
    func ohneTOTP() throws {
        let entry = VaultEntry(title: "GitHub", username: "anna", password: "pw", url: "https://github.com",
                               notes: "Notiz", totp: "otpauth://totp/GitHub:anna?secret=JBSWY3DPEHPK3PXP")
        let text = try #require(String(data: CSVExport.export([entry]), encoding: .utf8))
        #expect(!text.contains("JBSWY3DPEHPK3PXP"))
        #expect(!text.contains("otpauth"))
        #expect(text == "\"name\",\"url\",\"username\",\"password\",\"note\"\r\n"
            + "\"GitHub\",\"https://github.com\",\"anna\",\"pw\",\"Notiz\"\r\n")
    }

    @Test("Leere Liste → nur Kopfzeile")
    func leer() {
        #expect(Array(CSVExport.export([])) == Array("\"name\",\"url\",\"username\",\"password\",\"note\"\r\n".utf8))
    }

    @Test("Gelöschte Einträge werden nicht exportiert")
    func geloescht() throws {
        let kept = VaultEntry(title: "Bleibt", username: "u", password: "p1", url: "https://a.example")
        var deleted = VaultEntry(title: "Weg", username: "u", password: "geloescht-pw", url: "https://b.example")
        deleted.deletedAt = Date()
        let data = CSVExport.export([kept, deleted])
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(!text.contains("Weg"))
        #expect(!text.contains("geloescht-pw"))
        #expect(text.contains("Bleibt"))
    }

    @Test("Jedes Feld zitiert, Leerfelder als \"\"; Datei endet mit CRLF")
    func jedesFeldZitiert() throws {
        let data = CSVExport.export([VaultEntry(title: "T"), VaultEntry(title: "=1+2", password: "@x")])
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.hasSuffix("\r\n"))
        let lines = text.components(separatedBy: "\r\n").dropLast()
        #expect(lines.count == 3)
        #expect(lines[1] == "\"T\",\"\",\"\",\"\",\"\"")
        #expect(lines[2] == "\"=1+2\",\"\",\"\",\"@x\",\"\"")     // roh, kein Formel-Präfix
    }

    @Test("Rundlauf Export → Import (Chrome) ist byte-genau")
    func rundlauf() throws {
        let entries = [
            VaultEntry(title: "SBB", username: "anna@example.ch", password: "zug,fahrt\"2026",
                       url: "https://www.sbb.ch/de", notes: "Halbtax\r\nGA nein"),
            VaultEntry(title: "Bank, \"Privat\"", username: "4711", password: "=SUMME(A1)+'1",
                       url: "https://bank.example/login?x=1,2", notes: "PIN: im Safe\n\nZweite Zeile"),
            VaultEntry(title: "Unicode Zürich", username: "jürg", password: "🔑Äöü e\u{0301} \u{00A0}",
                       url: "https://bücher.de", notes: ""),
            VaultEntry(title: "Steuerzeichen im Passwort", username: "u", password: "\u{0}\t\r\n\u{202E}x",
                       url: "https://c.example", notes: "Tab\tim Text"),
            VaultEntry(title: "Leeres Passwort", username: "nur-name", password: "", url: "", notes: "n"),
        ]
        let data = CSVExport.export(entries)
        let result = try CSVImport.parse(data)
        #expect(result.format == .chrome)
        #expect(result.entries.count == entries.count)
        for (original, imported) in zip(entries, result.entries) {
            #expect(Array(imported.title.utf8) == Array(original.title.utf8))
            #expect(Array(imported.username.utf8) == Array(original.username.utf8))
            #expect(Array(imported.password.utf8) == Array(original.password.utf8))
            #expect(Array(imported.url.utf8) == Array(original.url.utf8))
            #expect(Array(imported.notes.utf8) == Array(original.notes.utf8))
        }
        #expect(result.report.passwordsWithControlCharacters == 1)
        #expect(result.report.movedToNotes == 0)
        #expect(result.report.withOTPSecret == 0)
    }
}
