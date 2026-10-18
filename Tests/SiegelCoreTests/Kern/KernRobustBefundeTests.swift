import Foundation
import Testing
@testable import SiegelCore

// Regressionstests zu den Robustheits-Befunden der Windows-Prüfung (SPEC v4.8, `windows/SPEC-WINDOWS.md` W12 W1.3), soweit
// sie den Swift-Kern betreffen oder seine Werte festhalten, die der C#-Kern nachbildet
// (`windows/tests/Siegel.Core.Tests/Tresor/RobustBefundeWindowsTests.cs`, gleiche Werte):
// robust-2  hostKey bei Hosts, die IDNA ablehnt (Swift wirft nie; C# warf UriFormatException)
// robust-7  Spaltennamen über 256 Byte ohne Rolle (beide Kerne); Foundation-Grenzen des CSV-Titels aus der URL
// robust-8  doppelte Eintrags-Kennungen immer beschädigt (beide Kerne)

private let doppelteID = "06caf7c7-5bfa-4c75-abec-76e7488cc7a2"

private func eintrag(_ meta: String) -> String {
    "{\"created\":1,\"history\":[],\"modified\":1,\"notes\":\"\",\"password\":\"p\",\"title\":\"t\",\"url\":\"\","
        + "\"username\":\"\",\"id\":\"\(doppelteID)\"\(meta)}"
}

private func inhalt(_ eintraege: [String]) -> String {
    "{\"v\":2,\"entries\":[\(eintraege.joined(separator: ","))],\"factors\":{},\"level\":1,\"savedAt\":1}"
}

private func csv(_ text: String) throws -> CSVImportResult { try CSVImport.parse(Data(text.utf8)) }

private let chrome = "name,url,username,password"

@Suite("Robustheits-Befunde der Windows-Prüfung (v4.8)")
struct KernRobustBefundeTests {

    @Test("robust-8: jede doppelte Eintrags-Kennung ist beschädigt, auch ohne Schutzdaten")
    func doppelteKennung() throws {
        let eins = try PayloadCodec.decode(try KernBerichtTests.padded(inhalt([eintrag("")]))).content
        #expect(eins.entries.count == 1)
        for paar in [[eintrag(""), eintrag("")], [eintrag(",\"meta\":null"), eintrag(",\"meta\":null")],
                     [eintrag(""), eintrag(",\"meta\":null")]] {
            #expect(throws: SiegelError.corruptFile("payload.duplicateID")) {
                try PayloadCodec.decode(try KernBerichtTests.padded(inhalt(paar)))
            }
        }
    }

    @Test("robust-8: gelesen heisst wieder lesbar – ein Inhalt mit doppelter Kennung kommt gar nicht erst herein")
    func gelesenHeisstWiederLesbar() throws {
        // Vorher: Decode nahm zwei Einträge mit gleicher Kennung ohne meta an; Encode schrieb dann meta für beide, und
        // das erneute Lesen ergab payload.duplicateID (Speichern scheiterte immer an save.verify).
        var c = try PayloadCodec.decode(try KernBerichtTests.padded(inhalt([eintrag("")]))).content
        c.entries.append(c.entries[0])
        c.meta[c.entries[0].id] = nil
        let json = try #require(PayloadCodec.jsonStringForTesting(try PayloadCodec.encode(c).padded))
        #expect(throws: SiegelError.corruptFile("payload.duplicateID")) {
            try PayloadCodec.decode(try KernBerichtTests.padded(json))
        }
    }

    @Test("robust-7: Spaltennamen über 256 Byte haben keine Rolle und werden nicht verglichen")
    func kopfzeilenGrenze() throws {
        let x256 = String(repeating: "x", count: 256)
        #expect(throws: SiegelError.csvInvalid(line: 1, reason: "csv.header.duplicate")) {
            try csv("\(chrome),\(x256),\(x256.uppercased())\n")
        }
        let x257 = String(repeating: "x", count: 257)
        var r = try csv("\(chrome),\(x257),\(x257)\nA,https://a.ch,u,p,1,2\n")
        #expect(r.entries.count == 1)
        #expect(r.entries.first?.notes == "\(x257): 1\n\(x257): 2")
        // gemessen ohne Leerraum am Rand
        r = try csv("name,url" + String(repeating: " ", count: 300) + ",username,password\nA,https://a.ch,u,p\n")
        #expect(r.entries.first?.url == "https://a.ch")
        #expect(throws: SiegelError.csvInvalid(line: 1, reason: "csv.header.unknown")) {
            try csv("name" + String(repeating: "x", count: 253) + ",url,username,password\n")
        }
        // Grenze in Byte vor dem Vergleich: kanonisch gleiche Namen mit 255 und 256 Byte sind doppelt, mit 257 nicht
        let nfc = String(repeating: "\u{E9}", count: 127) + "x"
        let zerlegt1 = "e\u{301}" + String(repeating: "\u{E9}", count: 126) + "x"
        let zerlegt2 = "e\u{301}e\u{301}" + String(repeating: "\u{E9}", count: 125) + "x"
        let laengen: [Int] = [nfc.utf8.count, zerlegt1.utf8.count, zerlegt2.utf8.count]
        #expect(laengen == [255, 256, 257])
        #expect(throws: SiegelError.csvInvalid(line: 1, reason: "csv.header.duplicate")) {
            try csv("\(chrome),\(nfc),\(zerlegt1)\n")
        }
        r = try csv("\(chrome),\(nfc),\(zerlegt2)\nA,https://a.ch,u,p,1,2\n")
        #expect(r.entries.first?.notes == "\(nfc): 1\n\(zerlegt2): 2")
    }

    @Test("robust-7: lange Folgen von Kombinationszeichen in Kopfzeile und URL bleiben schnell, Fehlercode wie C#")
    func langeKombinationsfolgen() throws {
        let lang = "e" + String(repeating: "\u{301}\u{316}", count: 150_000)
        let start = ContinuousClock.now
        let r = try csv("\(chrome),\(lang),\(lang)\nBank,https://bank.ch,anna,pw,,\n")
        #expect(r.format == .chrome)
        #expect(r.entries.first?.notes == "")
        let url = "https://" + lang + ".ch/"
        #expect(CSVText.titleFromURL(url) == url)
        #expect(throws: SiegelError.csvInvalid(line: 2, reason: "csv.field.title")) {
            try csv("\(chrome)\n,\(url),anna,pw\n")
        }
        #expect(ContinuousClock.now - start < .seconds(5))
    }

    @Test("robust-7: Foundation-Grenzen des Titels aus der URL (der C#-Kern bildet sie nach)")
    func titelGrenzenFoundation() {
        let shy = "\u{AD}"
        #expect(CSVText.titleFromURL("https://a" + String(repeating: shy, count: 1022) + ".ch/x") == "a.ch")
        let zuLang = "https://a" + String(repeating: shy, count: 1023) + ".ch/x"
        #expect(CSVText.titleFromURL(zuLang) == zuLang)
        #expect(CSVText.titleFromURL("https://" + String(repeating: "a", count: 2048) + "/x") == String(repeating: "a", count: 2048))
        let asciiZuLang = "https://" + String(repeating: "a", count: 2049) + "/x"
        #expect(CSVText.titleFromURL(asciiZuLang) == asciiZuLang)
        #expect(CSVText.titleFromURL("https://" + String(repeating: "%61", count: 2049) + "/x") == String(repeating: "a", count: 2049))
        let e57 = String(repeating: "\u{E9}", count: 57)
        #expect(CSVText.titleFromURL("https://" + e57 + ".ch/") == e57 + ".ch")
        let e58 = "https://" + String(repeating: "\u{E9}", count: 58) + ".ch/"
        #expect(CSVText.titleFromURL(e58) == e58)
    }

    @Test("robust-2: hostKey bei Hosts, die IDNA ablehnt, und weitere Werte (der C#-Kern bildet sie nach)")
    func hostKeyWerte() {
        for url in ["https://bank.\u{FFFD}.ch", "https://bank.\u{E000}.ch", "https://\u{378}.ch"] {
            #expect(UnlockedVault.hostKey(url) == url)
        }
        #expect(UnlockedVault.hostKey("  HTTPS://Bank.\u{FFFD}.CH \n") == "https://bank.\u{FFFD}.ch")
        // "://" als Character-Folge: U+200D gehört zum zweiten "/", also wird "https://" vorangestellt
        #expect("https://\u{200D}.ch".contains("://") == false)
        #expect(UnlockedVault.hostKey("https://\u{200D}.ch") == "https")
        #expect(UnlockedVault.hostKey("https://bank..ch/login") == "bank..ch")
        #expect(UnlockedVault.hostKey("https://[::1]:80/") == "::1")
        #expect(UnlockedVault.hostKey("https://ex%41mple.com/") == "example.com")
        #expect(UnlockedVault.hostKey("https://B\u{DC}cher.de") == "xn--bcher-kva.de")
        #expect(UnlockedVault.hostKey("https://\u{130}stanbul.com") == "xn--istanbul-o0e.com")
        #expect(UnlockedVault.hostKey("\u{130}STANBUL") == "xn--istanbul-o0e")
        #expect(UnlockedVault.hostKey("https://x\u{AD}.ch") == "x.ch")
    }
}
