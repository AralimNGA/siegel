import Foundation
import Testing
@testable import SiegelCore

// Tests für CSVImport (SPEC §8 „CSV-Details“, §10): alle vier Formate mit realistischen Beispieldateien,
// RFC 4180, BOM, Grenzen, Steuerzeichen, Notizen-Übernahme, 2FA nach `totp` (SPEC §18), OTP-Zählung,
// Spaltengrenze (Befund #45). Alle Daten sind erfunden.

private func csv(_ text: String) -> Data { Data(text.utf8) }

private func parse(_ text: String) throws -> CSVImportResult { try CSVImport.parse(csv(text)) }

private func invalid(_ line: Int, _ reason: String) -> SiegelError {
    .csvInvalid(line: line, reason: reason)
}

private let chromeHeader = "name,url,username,password,note\n"

@Suite("CSV-Import: Formate")
struct CSVFormatTests {

    @Test("Apple Passwörter: Abbildung, OTPAuth nach totp, Zählung")
    func apple() throws {
        let file = """
        Title,URL,Username,Password,Notes,OTPAuth\r
        example.com (anna@example.com),https://example.com/,anna@example.com,"Pa,ss""wort","Notiz, mit Komma",\r
        GitHub,https://github.com/login,anna-dev,gh-Geheim-42,"Zeile 1
        Zeile 2",otpauth://totp/GitHub:anna-dev?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\r

        """
        let result = try parse(file)
        #expect(result.format == .applePasswords)
        #expect(result.entries.count == 2)
        let first = result.entries[0]
        #expect(first.title == "example.com (anna@example.com)")
        #expect(first.url == "https://example.com/")
        #expect(first.username == "anna@example.com")
        #expect(first.password == "Pa,ss\"wort")
        #expect(first.notes == "Notiz, mit Komma")
        let second = result.entries[1]
        #expect(second.title == "GitHub")
        #expect(second.notes == "Zeile 1\nZeile 2")
        #expect(second.totp == "otpauth://totp/GitHub:anna-dev?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
        #expect(first.totp == "")
        #expect(result.report.withOTPSecret == 1)
        #expect(result.report.movedToNotes == 0)
        #expect(result.report.added == 2)
        #expect(Set(result.entries.map(\.id)).count == 2)
    }

    @Test("Chrome: Abbildung, Titel aus Host, note")
    func chrome() throws {
        let file = """
        name,url,username,password,note
        accounts.google.com,https://accounts.google.com/signin/v2,anna.muster@gmail.com,G00gle!Pass,
        www.sbb.ch,https://www.sbb.ch/de/login,anna,"zug,fahrt""2026",Halbtax bis 12/2027
        ,https://www.digitec.ch/login,anna@example.ch,dg-pass,

        """
        let result = try parse(file)
        #expect(result.format == .chrome)
        #expect(result.entries.map(\.title) == ["accounts.google.com", "www.sbb.ch", "digitec.ch"])
        #expect(result.entries[1].password == "zug,fahrt\"2026")
        #expect(result.entries[1].notes == "Halbtax bis 12/2027")
        #expect(result.entries[0].notes == "")
        #expect(result.report.withOTPSecret == 0)
        #expect(result.report.movedToNotes == 0)
    }

    @Test("Firefox: Zeitstempel in ms, Titel aus Host, übrige Spalten in Notizen")
    func firefox() throws {
        let file = """
        "url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\r
        "https://www.mozilla.org","anna","fx-Pass-1","","https://www.mozilla.org","{0e5a3b8c-4f2d-4a7e-9c11-2b7d3f6e8a90}","1700000000000","1700000500000","1700000300000"\r
        "https://auth.example.net","bob@example.net","x""y,z","Example Realm","","{11111111-2222-3333-4444-555555555555}","1690000000123","","1690000000123"\r

        """
        let result = try parse(file)
        #expect(result.format == .firefox)
        #expect(result.entries.count == 2)
        let first = result.entries[0]
        #expect(first.title == "mozilla.org")
        #expect(first.url == "https://www.mozilla.org")
        #expect(first.created == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(first.modified == Date(timeIntervalSince1970: 1_700_000_300))
        #expect(first.notes == """
            formActionOrigin: https://www.mozilla.org
            guid: {0e5a3b8c-4f2d-4a7e-9c11-2b7d3f6e8a90}
            timeLastUsed: 1700000500000
            """)
        let second = result.entries[1]
        #expect(second.title == "auth.example.net")
        #expect(second.password == "x\"y,z")
        #expect(second.created == Date(timeIntervalSince1970: 1_690_000_000.123))
        #expect(second.notes == "httpRealm: Example Realm\nguid: {11111111-2222-3333-4444-555555555555}")
        #expect(result.report.movedToNotes == 2)
    }

    @Test("Firefox: unlesbarer Zeitstempel → Importzeit, Rohwert in Notizen; modified ≥ created")
    func firefoxZeitstempel() throws {
        let before = Date()
        let file = """
        url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
        https://a.example,anna,pw,,,,abc,,
        https://b.example,bob,pw,,,,1700000000000,,1600000000000
        https://c.example,carl,pw,,,,,,

        """
        let result = try parse(file)
        let after = Date()
        #expect(result.entries[0].notes == "timeCreated: abc")
        #expect(result.entries[0].created >= before && result.entries[0].created <= after)
        #expect(result.entries[1].created == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(result.entries[1].modified == result.entries[1].created)
        #expect(result.entries[2].notes == "")
        #expect(result.entries[2].created >= before && result.entries[2].created <= after)
    }

    @Test("Bitwarden: login mit TOTP, eigene Felder, type=note")
    func bitwarden() throws {
        let file = """
        folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
        Social,1,login,Mastodon,,,0,https://mastodon.social,anna,md-Pass-9,JBSWY3DPEHPK3PXP
        ,,login,Bank,PIN-Brief im Ordner,"Kundennummer: 12345
        Frage: Haustier",,https://bank.example.ch,4711,bk-Pass,
        ,,note,WLAN Zuhause,"SSID: Muster
        Schlüssel: geheim",,0,,,,
        ,,,,,,0,,,,

        """
        let result = try parse(file)
        #expect(result.format == .bitwarden)
        #expect(result.entries.count == 3)   // letzte Zeile hat keinen Inhalt
        let mastodon = result.entries[0]
        #expect(mastodon.title == "Mastodon")
        #expect(mastodon.url == "https://mastodon.social")
        #expect(mastodon.username == "anna")
        #expect(mastodon.password == "md-Pass-9")
        #expect(mastodon.notes == "folder: Social\nfavorite: 1\nreprompt: 0")
        #expect(mastodon.totp == "JBSWY3DPEHPK3PXP")
        let bank = result.entries[1]
        #expect(bank.notes == "PIN-Brief im Ordner\n\nfields: Kundennummer: 12345\nFrage: Haustier")
        let note = result.entries[2]
        #expect(note.title == "WLAN Zuhause")
        #expect(note.url == "" && note.username == "" && note.password == "")
        #expect(note.notes == "SSID: Muster\nSchlüssel: geheim\n\nreprompt: 0")
        #expect(result.report.withOTPSecret == 1)
        #expect(result.report.movedToNotes == 3)
    }

    @Test("Bitwarden: type=note mit Login-Werten → Werte in Notizen; fremder Typ vermerkt")
    func bitwardenNotizMitWerten() throws {
        let file = """
        folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
        ,,note,Notiz,Text,,,https://x.example,user,pw,
        ,,card,Karte,,,,,,kartenpw,

        """
        let result = try parse(file)
        #expect(result.entries[0].password == "")
        #expect(result.entries[0].notes == "Text\n\nlogin_uri: https://x.example\nlogin_username: user\nlogin_password: pw")
        #expect(result.entries[1].password == "kartenpw")
        #expect(result.entries[1].notes == "type: card")
    }

    @Test("Kopfzeile: Gross/Klein und Leerraum egal, Reihenfolge egal")
    func kopfzeileTolerant() throws {
        let apple = try parse(" TITLE , url,UserName,PASSWORD,notes,otpauth\nT,https://t.example,u,p,n,\n")
        #expect(apple.format == .applePasswords)
        #expect(apple.entries[0].title == "T" && apple.entries[0].notes == "n")

        let chrome = try parse("PASSWORD,Note,Name,URL,Username\npw,nn,Titel,https://c.example,user\n")
        #expect(chrome.format == .chrome)
        #expect(chrome.entries[0].password == "pw")
        #expect(chrome.entries[0].title == "Titel")
        #expect(chrome.entries[0].notes == "nn")

        let bitwarden = try parse("Folder,Favorite,Type,Name,Notes,Fields,Reprompt,Login_URI,Login_Username,Login_Password,Login_TOTP\n,,login,B,,,,https://b.example,u,p,\n")
        #expect(bitwarden.format == .bitwarden)

        let firefox = try parse("URL,USERNAME,PASSWORD,GUID\nhttps://f.example,u,p,{1}\n")
        #expect(firefox.format == .firefox)
        #expect(firefox.entries[0].notes == "GUID: {1}")
    }

    @Test("Nicht abgebildete Spalten → „Spalte: Wert“ in Notizen, leere Spaltennamen nummeriert")
    func zusatzspalten() throws {
        let file = "name,url,username,password,note,Kategorie,,Leer\n"
            + "Shop,https://shop.example,anna,pw,Kundin seit 2019,Einkauf,ohne Namen,\n"
            + "Zweiter,https://z.example,bob,pw2,,,,\n"
        let result = try parse(file)
        #expect(result.entries[0].notes == "Kundin seit 2019\n\nKategorie: Einkauf\nSpalte 7: ohne Namen")
        #expect(result.entries[1].notes == "")
        #expect(result.report.movedToNotes == 1)
    }

    @Test("Unbekannte oder doppelte Kopfzeile")
    func kopfzeileFehler() {
        #expect(throws: invalid(1, "csv.header.unknown")) { try parse("foo,bar\n1,2\n") }
        #expect(throws: invalid(1, "csv.header.unknown")) { try parse("url,username,password\nx,y,z\n") }
        #expect(throws: invalid(1, "csv.header.duplicate")) { try parse("name,url,username,password,NAME\n") }
        #expect(throws: invalid(2, "csv.header.unknown")) { try parse("\nfoo,bar\n") }
    }

    @Test("Nur Kopfzeile → leeres Ergebnis mit erkanntem Format")
    func nurKopfzeile() throws {
        let result = try parse("name,url,username,password,note\r\n")
        #expect(result.format == .chrome)
        #expect(result.entries.isEmpty)
        #expect(result.report == ImportReport())
    }
}

@Suite("CSV-Import: 2FA nach totp (SPEC §18)")
struct CSVTOTPTests {

    @Test("Gültige Werte → totp (Rand-Leerraum entfernt); ungültige bleiben in den Notizen")
    func zuordnung() throws {
        let file = "Title,URL,Username,Password,Notes,OTPAuth\n"
            + "A,https://a.example,u,p,,\"  otpauth://totp/A:u?secret=JBSWY3DPEHPK3PXP&period=60 \"\n"
            + "B,https://b.example,u,p,Alt,otpauth://hotp/B:u?secret=JBSWY3DPEHPK3PXP&counter=3\n"
            + "C,https://c.example,u,p,,steam://ABCDEFGH\n"
            + "D,https://d.example,u,p,,otpauth://totp/D?secret=JBSWY3DP\n"
            + "E,https://e.example,u,p,,\n"
        let result = try parse(file)
        #expect(result.entries.map(\.totp) == ["otpauth://totp/A:u?secret=JBSWY3DPEHPK3PXP&period=60", "", "", "", ""])
        #expect(try TOTP.parse(result.entries[0].totp).period == 60)
        #expect(result.entries[0].notes == "")
        #expect(result.entries[1].notes == "Alt\n\nOTPAuth: otpauth://hotp/B:u?secret=JBSWY3DPEHPK3PXP&counter=3")
        #expect(result.entries[2].notes == "OTPAuth: steam://ABCDEFGH")
        #expect(result.entries[3].notes == "OTPAuth: otpauth://totp/D?secret=JBSWY3DP")     // Geheimnis zu kurz
        #expect(result.entries[4].notes == "")
        #expect(result.report.withOTPSecret == 1)
        #expect(result.report.movedToNotes == 3)
    }

    @Test("Bitwarden: login_totp als Base32 oder URI; type=note behält den Wert in den Notizen")
    func bitwarden() throws {
        let file = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            + ",,login,Roh,,,,https://r.example,u,p,jbsw y3dp ehpk 3pxp\n"
            + ",,login,URI,,,,https://u.example,u,p,otpauth://totp/U?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8\n"
            + ",,note,Notiz,Text,,,,,,JBSWY3DPEHPK3PXP\n"
        let result = try parse(file)
        #expect(result.entries[0].totp == "jbsw y3dp ehpk 3pxp")
        #expect(try TOTP.parse(result.entries[0].totp) == TOTP.parse("JBSWY3DPEHPK3PXP"))
        #expect(try TOTP.parse(result.entries[1].totp).digits == 8)
        #expect(result.entries[2].totp == "")
        #expect(result.entries[2].notes == "Text\n\nlogin_totp: JBSWY3DPEHPK3PXP")
        #expect(result.report.withOTPSecret == 2)
        #expect(result.report.movedToNotes == 1)
    }

    @Test("Datensatz nur mit 2FA-Wert wird nicht übersprungen (gültig und ungültig)")
    func nurZweiFaktor() throws {
        let file = "Title,URL,Username,Password,Notes,OTPAuth\n"
            + ",,,,,JBSWY3DPEHPK3PXP\n"
            + ",,,,,kein-geheimnis\n"
        let result = try parse(file)
        #expect(result.entries.count == 2)
        #expect(result.entries[0].totp == "JBSWY3DPEHPK3PXP")
        #expect(result.entries[1].notes == "OTPAuth: kein-geheimnis")
    }
}

@Suite("CSV-Import: Spaltengrenze (Befund #45)")
struct CSVSpaltenTests {

    @Test("Kopfzeile mit Millionen Kommas: csv.header.unknown in Zeile 1, schnell und ohne Riesenspeicher")
    func breiteKopfzeile() {
        var data = Data("name,url,username,password,note".utf8)
        data.append(Data(repeating: 0x2C, count: 16 * 1024 * 1024 - data.count))
        let start = ContinuousClock.now
        #expect(throws: invalid(1, "csv.header.unknown")) { try CSVImport.parse(data) }
        #expect(ContinuousClock.now - start < .seconds(1))
    }

    @Test("Datenzeile mit 1 Mio. Kommas: csv.fieldCount mit der Zeile des Datensatzes")
    func breiteDatenzeile() {
        var data = Data((chromeHeader + "A,https://a.example,u,p,\n").utf8)
        data.append(Data(repeating: 0x2C, count: 1_000_000))
        data.append(Data("\n".utf8))
        let start = ContinuousClock.now
        #expect(throws: invalid(3, "csv.fieldCount")) { try CSVImport.parse(data) }
        #expect(ContinuousClock.now - start < .seconds(1))
    }

    @Test("256 Felder in der Kopfzeile sind erlaubt, 257 nicht")
    func grenze256() throws {
        let extra = (6...256).map { "x\($0)" }
        let header = (["name", "url", "username", "password", "note"] + extra).joined(separator: ",")
        #expect(header.split(separator: ",").count == 256)
        let row = (["T", "https://t.example", "u", "p", ""] + extra.map { _ in "" }).joined(separator: ",")
        let ok = try parse(header + "\n" + row + "\n")
        #expect(ok.entries.count == 1)
        #expect(throws: invalid(1, "csv.header.unknown")) { try parse(header + ",x257\n" + row + ",\n") }
        // Zitierte Felder zählen genauso (auch das letzte Feld vor dem Dateiende)
        #expect(throws: invalid(2, "csv.fieldCount")) { try parse(chromeHeader + "\"A\",\"b\",\"c\",\"d\",\"e\",\"f\"") }
    }
}

@Suite("CSV-Import: RFC 4180")
struct CSVRFCTests {

    @Test("Zeilenenden CRLF, LF, CR und gemischt; ohne abschliessenden Umbruch; Leerzeilen")
    func zeilenenden() throws {
        let variants = [
            "name,url,username,password,note\r\nA,https://a.ch,u1,p1,\r\nB,https://b.ch,u2,p2,n\r\n",
            "name,url,username,password,note\nA,https://a.ch,u1,p1,\nB,https://b.ch,u2,p2,n\n",
            "name,url,username,password,note\rA,https://a.ch,u1,p1,\rB,https://b.ch,u2,p2,n\r",
            "name,url,username,password,note\r\nA,https://a.ch,u1,p1,\nB,https://b.ch,u2,p2,n",
            "name,url,username,password,note\n\nA,https://a.ch,u1,p1,\r\n\r\nB,https://b.ch,u2,p2,n\n\n\n",
        ]
        for text in variants {
            let result = try parse(text)
            #expect(result.entries.map(\.title) == ["A", "B"])
            #expect(result.entries.map(\.password) == ["p1", "p2"])
            #expect(result.entries.map(\.notes) == ["", "n"])
        }
    }

    @Test("Zitierte Felder: Kommas, doppelte Anführungszeichen, Umbrüche, leere Felder")
    func zitiert() throws {
        let file = chromeHeader
            + "\"a,b\",\"https://x.example/?q=1,2\",\"\",\"\"\"\",\"\"\"start und ende\"\"\"\n"
            + "\"Mehr\nzeilig\",https://y.example,\"u\",\"p\r\nw\",\"Notiz\r\nmit CRLF\"\n"
            + "Leer,https://z.example,,,\n"
        let result = try parse(file)
        #expect(result.entries.count == 3)
        #expect(result.entries[0].title == "a,b")
        #expect(result.entries[0].url == "https://x.example/?q=1,2")
        #expect(result.entries[0].username == "")
        #expect(result.entries[0].password == "\"")
        #expect(result.entries[0].notes == "\"start und ende\"")
        #expect(result.entries[1].title == "Mehrzeilig")                      // LF aus Titel entfernt
        #expect(Array(result.entries[1].password.utf8) == Array("p\r\nw".utf8))  // byte-genau
        #expect(Array(result.entries[1].notes.utf8) == Array("Notiz\r\nmit CRLF".utf8))
        #expect(result.entries[2].password == "" && result.entries[2].username == "")
        #expect(result.report.passwordsWithControlCharacters == 1)
    }

    @Test("Leerzeichen bleiben erhalten (kein Trimmen der Werte)")
    func keinTrimmen() throws {
        let result = try parse(chromeHeader + " Titel ,https://x.example, anna ,  pw  , n \n")
        #expect(result.entries[0].title == " Titel ")
        #expect(result.entries[0].username == " anna ")
        #expect(result.entries[0].password == "  pw  ")
        #expect(result.entries[0].notes == " n ")
    }

    @Test("BOM wird entfernt")
    func bom() throws {
        var data = Data([0xEF, 0xBB, 0xBF])
        data.append(csv("name,url,username,password,note\r\nA,https://a.example,u,p,\r\n"))
        let result = try CSVImport.parse(data)
        #expect(result.format == .chrome)
        #expect(result.entries.count == 1)
        #expect(throws: invalid(0, "csv.empty")) { try CSVImport.parse(Data([0xEF, 0xBB, 0xBF])) }
    }

    @Test("Anführungszeichen-Fehler mit Zeilennummer")
    func anfuehrungszeichenFehler() {
        // " mitten im nicht zitierten Feld
        #expect(throws: invalid(3, "csv.quote")) {
            try parse(chromeHeader + "A,https://a.example,u,p,\nB,https://b.example,u,p\"w,\n")
        }
        // Zeichen nach dem schliessenden "
        #expect(throws: invalid(2, "csv.quote")) { try parse(chromeHeader + "\"A\"x,https://a.example,u,p,\n") }
        // Leerzeichen vor dem öffnenden " (nicht RFC 4180)
        #expect(throws: invalid(2, "csv.quote")) { try parse(chromeHeader + "A, \"https://a.example\",u,p,\n") }
        // Zeilennummer zählt Umbrüche in zitierten Feldern mit
        #expect(throws: invalid(5, "csv.quote")) {
            try parse(chromeHeader + "A,https://a.example,u,p,\"Zeile 1\nZeile 2\nZeile 3\"\nB,x\"y,u,p,\n")
        }
        // offenes " bis Dateiende: Zeile, in der der Datensatz beginnt
        #expect(throws: invalid(3, "csv.unterminatedQuote")) {
            try parse(chromeHeader + "A,https://a.example,u,p,\nB,https://b.example,u,\"offen\nbis zum Ende,\n")
        }
    }

    @Test("Feldanzahl muss zur Kopfzeile passen")
    func feldanzahl() {
        #expect(throws: invalid(2, "csv.fieldCount")) { try parse(chromeHeader + "A,https://a.example,u,p\n") }
        #expect(throws: invalid(2, "csv.fieldCount")) { try parse(chromeHeader + "A,https://a.example,u,p,n,zuviel\n") }
        #expect(throws: invalid(4, "csv.fieldCount")) {
            try parse(chromeHeader + "A,https://a.example,u,p,\"zwei\nZeilen\"\nB,https://b.example\n")
        }
    }

    @Test("Leere Datei, nur Leerzeilen")
    func leer() {
        #expect(throws: invalid(0, "csv.empty")) { try CSVImport.parse(Data()) }
        #expect(throws: invalid(0, "csv.empty")) { try parse("\r\n\n\r\n") }
    }

    @Test("Ungültiges UTF-8 und UTF-16 werden abgelehnt")
    func kodierung() {
        var bad = csv(chromeHeader + "A,https://a.example,u,")
        bad.append(contentsOf: [0xC3, 0x28])
        bad.append(csv(",\n"))
        #expect(throws: invalid(2, "csv.encoding")) { try CSVImport.parse(bad) }

        var utf16 = Data([0xFF, 0xFE])
        utf16.append("name,url,username,password,note\n".data(using: .utf16LittleEndian) ?? Data())
        #expect(throws: invalid(1, "csv.encoding")) { try CSVImport.parse(utf16) }
    }

    @Test("Kein Teilimport: Fehler in der letzten Zeile verwirft alles")
    func keinTeilimport() {
        var file = chromeHeader
        for i in 0..<100 { file += "T\(i),https://t\(i).example,u,p,\n" }
        file += "kaputt\",x,u,p,\n"
        #expect(throws: invalid(102, "csv.quote")) { try parse(file) }
    }

    @Test("Ganz leere Datensätze und Zeilen nur aus Leerraum werden übersprungen")
    func leereDatensaetze() throws {
        let result = try parse(chromeHeader + ",,,,\r\nA,,,,\r\n,,,,\r\n  \t\r\n")
        #expect(result.entries.count == 1)
        #expect(result.entries[0].title == "A")
    }
}

@Suite("CSV-Import: Grenzen und Hygiene")
struct CSVLimitTests {

    @Test("Datei grösser als 16 MiB")
    func dateigroesse() {
        #expect(throws: invalid(0, "csv.fileTooLarge")) {
            try CSVImport.parse(Data(count: 16 * 1024 * 1024 + 1))
        }
    }

    @Test("Höchstens 20 000 Datensätze (Leerzeilen zählen nicht)")
    func zeilenzahl() throws {
        var file = chromeHeader
        file.reserveCapacity(700_000)
        for i in 0..<20_000 { file += "T\(i),https://x.example,u,p,\n" }
        file += "\n\n"
        let ok = try parse(file)
        #expect(ok.entries.count == 20_000)

        file += "Zuviel,https://x.example,u,p,\n"
        // Kopfzeile = 1, 20 000 Datensätze = Zeilen 2…20001, zwei Leerzeilen, dann Zeile 20004.
        #expect(throws: invalid(20_004, "csv.tooManyRows")) { try parse(file) }
    }

    @Test("Feldgrenzen §3: Titel/Benutzer/URL 2 KiB, Passwort 4 KiB, Notizen 256 KiB (UTF-8-Bytes)")
    func feldgrenzen() throws {
        let twoKiB = String(repeating: "ä", count: 1024)          // genau 2048 Bytes
        let fourKiB = String(repeating: "x", count: 4096)
        let notesMax = String(repeating: "n", count: 256 * 1024)

        let ok = try parse(chromeHeader + "\(twoKiB),https://a.example/\(String(repeating: "p", count: 2048 - 18)),\(twoKiB),\(fourKiB),\(notesMax)\n")
        #expect(ok.entries[0].title.utf8.count == 2048)
        #expect(ok.entries[0].url.utf8.count == 2048)
        #expect(ok.entries[0].password.utf8.count == 4096)
        #expect(ok.entries[0].notes.utf8.count == 262_144)

        #expect(throws: invalid(2, "csv.field.title")) { try parse(chromeHeader + "\(twoKiB)a,https://a.example,u,p,\n") }
        #expect(throws: invalid(2, "csv.field.username")) { try parse(chromeHeader + "T,https://a.example,\(twoKiB)a,p,\n") }
        #expect(throws: invalid(2, "csv.field.url")) {
            try parse(chromeHeader + "T,https://a.example/\(String(repeating: "p", count: 2048)),u,p,\n")
        }
        #expect(throws: invalid(2, "csv.field.password")) { try parse(chromeHeader + "T,https://a.example,u,\(fourKiB)x,\n") }
        #expect(throws: invalid(2, "csv.field.notes")) { try parse(chromeHeader + "T,https://a.example,u,p,\(notesMax)n\n") }

        // Notizen-Grenze gilt nach dem Anhängen der Zusatzspalten (hier ein ungültiger OTPAuth-Wert ohne secret,
        // der deshalb in den Notizen bleibt).
        let appleHeader = "Title,URL,Username,Password,Notes,OTPAuth\n"
        #expect(throws: invalid(2, "csv.field.notes")) {
            try parse(appleHeader + "T,https://a.example,u,p,\(String(repeating: "n", count: 262_140)),otpauth://totp/x\n")
        }
        // Titel-Grenze gilt nach dem Entfernen von Steuerzeichen.
        let withTabs = String(repeating: "a", count: 2048) + "\t\t\t"
        #expect(try parse(chromeHeader + "\"\(withTabs)\",https://a.example,u,p,\n").entries[0].title.utf8.count == 2048)
    }

    @Test("Steuer- und Bidi-Zeichen aus Titel/Benutzer/URL entfernt, Passwort byte-genau und gezählt")
    func steuerzeichen() throws {
        var allControls = ""
        for v in 0x00...0x1F { allControls.unicodeScalars.append(Unicode.Scalar(UInt8(v))) }
        allControls += "\u{7F}\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}"
        let quotedControls = allControls.replacingOccurrences(of: "\"", with: "\"\"")

        let file = chromeHeader
            + "\"Bank\u{202E}exe.pdf\u{7}\",\"https://bank.example/\u{2066}x\u{2069}\u{7F}\",\"\tanna\u{200F}\",\"pw\twith\u{202E}bidi\",\"Notiz\tmit Tab\"\n"
            + "\"X\(quotedControls)Y\",https://b.example,\"\(quotedControls)u\",'=SUMME(1),\n"
            + "Nul,https://c.example,u,\"\u{0}nul\",\n"
            + "Normal,https://d.example,u,e\u{0301}\u{00A0}x,\n"
        let result = try parse(file)
        let bank = result.entries[0]
        #expect(bank.title == "Bankexe.pdf")
        #expect(bank.url == "https://bank.example/x")
        #expect(bank.username == "anna")
        #expect(Array(bank.password.utf8) == Array("pw\twith\u{202E}bidi".utf8))
        #expect(bank.notes == "Notiz\tmit Tab")                 // Notizen unverändert
        #expect(result.entries[1].title == "XY")
        #expect(result.entries[1].username == "u")
        #expect(result.entries[1].password == "'=SUMME(1)")
        #expect(Array(result.entries[2].password.utf8) == [0x00, 0x6E, 0x75, 0x6C])
        // Byte-genau auch bei kanonisch gleichwertigen Formen (kein NFC, NBSP bleibt).
        #expect(Array(result.entries[3].password.utf8) == Array("e\u{0301}\u{00A0}x".utf8))
        #expect(result.report.passwordsWithControlCharacters == 2)
        #expect(result.report.apostrophePrefixed == 1)
    }

    @Test("Titel aus dem Host der URL")
    func titelAusHost() throws {
        #expect(CSVText.titleFromURL("https://www.example.com/login") == "example.com")
        #expect(CSVText.titleFromURL("example.com/path") == "example.com")
        #expect(CSVText.titleFromURL("https://user:pw@Sub.Example.COM:8443/") == "sub.example.com")
        #expect(CSVText.titleFromURL("https://bücher.de/x") == "bücher.de")
        #expect(CSVText.titleFromURL("https://\u{0430}pple.com/").hasPrefix("xn--"))   // kyrillisches a
        #expect(CSVText.titleFromURL("android://abc==@com.example.app/") == "com.example.app")
        #expect(CSVText.titleFromURL("kein url") == "kein url")

        let result = try parse(chromeHeader + ",https://www.galaxus.ch/de,anna,p,\n,,bob,p,\n")
        #expect(result.entries[0].title == "galaxus.ch")
        #expect(result.entries[1].title == "")
    }

    @Test("reason-Codes sind feste, dokumentierte Codes")
    func reasonCodes() {
        #expect(Set(CSVImport.reasonCodes).count == CSVImport.reasonCodes.count)
        #expect(CSVImport.reasonCodes.allSatisfy { $0.hasPrefix("csv.") && $0.utf8.allSatisfy { $0 < 0x80 } })
    }
}
