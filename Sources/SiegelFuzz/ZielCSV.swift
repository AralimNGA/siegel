#if DEBUG
import Foundation
@testable import SiegelCore

/// Ziel „csv“: CSV-Import (SPEC §8 „CSV-Details“, §18) und Rundlauf Export → Import.
///
/// Rahmung: Byte 0 = Art (0 Import einer mutierten Datei, 1 Rundlauf mit Einträgen aus dem Zufall der Eingabe),
/// danach die CSV-Bytes bzw. die Zufallsbytes für die Einträge.
/// Invarianten: kein Absturz/Hänger; Fehler nur `csvInvalid` mit festem Code und plausibler Zeile; Ergebnis hält
/// alle Grenzen ein (Feldlängen, keine Steuer-/Richtungszeichen in Titel/Benutzer/URL, created ≤ modified,
/// Bericht passt); Rundlauf: was exportiert wurde, kommt beim Import Feld für Feld gleich zurück.
final class ZielCSV: FuzzZiel {
    let name = "csv"
    let zeitlimit = 10.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 5)
    var zusatz: [String: Int] = [:]

    private static let saat: [String] = [
        "\u{FEFF}Title,URL,Username,Password,Notes,OTPAuth\r\nBank,https://bank.example.ch,anna,\"Ge\"\"heim,1\",\"Zeile 1\r\nZeile 2\",otpauth://totp/Bank:anna?secret=JBSWY3DPEHPK3PXP&issuer=Bank\r\n",
        "name,url,username,password,note\nVelo,velo.example.ch,velo,Kette+Sattel,\nLeer,,,,\n,,,,\n",
        "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\r\nhttps://a.example,u,p,,https://a.example,{x},1700000000000,1700000000000,1700000000001\r\n",
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nArbeit,1,login,Mail,n,,0,https://mail.example,anna,pw,JBSWY3DPEHPK3PXP\n,,note,Notiz,Text,,0,,,,\n,,card,Karte,,,0,,,,\n",
        "Title,URL,Username,Password\n\"\u{202E}evil\",https://\u{0430}pple.com,\u{0007}x,'=cmd\n",
    ]

    func vorbereiten(_ u: Umgebung) throws {
        for s in Self.saat { korpus.saatAufnehmen([0] + Array(s.utf8)) }
        korpus.saatAufnehmen([1] + Array(repeating: 7, count: 64))
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    private static let bausteine: [String] = [",", "\"", "\"\"", "\r\n", "\n", "\r", "\u{FEFF}", "\u{0000}", "\t", " ",
                                              "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP", "steam://x", "253402300799999",
                                              "253402300800000", "-1", "type", "note", "login", "name", "url", "username",
                                              "password", "title", "notes", "otpauth", "login_totp", "timeCreated",
                                              String(repeating: "x", count: 2049), String(repeating: "é", count: 2100),
                                              String(repeating: ",", count: 300), "\u{202E}", "\u{2066}", "'", "=", "+"]

    func naechste(_ z: inout Zufall) -> [UInt8] {
        if z.chance(0.15) { return [1] + z.bytes(z.int(16...256)) }
        var basis = korpus.waehle(&z)
        basis[0] = 0
        var b = Array(basis.dropFirst())
        for _ in 0..<z.int(1...3) {
            if z.chance(0.5) {
                b = Mutator.bytes(b, &z, maxLaenge: 1 << 20)
            } else {
                let stueck = Array(z.pick(Self.bausteine).utf8)
                let at = z.int(b.count + 1)
                if z.chance(0.3), !b.isEmpty {
                    let n = min(b.count - min(at, b.count), z.int(1...8))
                    b.replaceSubrange(min(at, b.count)..<(min(at, b.count) + n), with: stueck)
                } else {
                    b.insert(contentsOf: stueck, at: at)
                }
            }
        }
        if z.chance(0.03) {
            // viele Zeilen (Zeilengrenze 20 000)
            let zeile = Array("a,b,c,d\n".utf8)
            b = Array("name,url,username,password\n".utf8) + Array([[UInt8]](repeating: zeile, count: z.pick([19_999, 20_000, 20_001])).joined())
        }
        return [0] + b
    }

    // MARK: Prüfen

    private static func zeilenzahl(_ b: [UInt8]) -> Int { b.reduce(1) { $0 + (($1 == 0x0A || $1 == 0x0D) ? 1 : 0) } }

    private func pruefeErgebnis(_ r: CSVImportResult) throws {
        guard r.report.added == r.entries.count, r.report.withOTPSecret <= r.entries.count,
              r.report.movedToNotes <= r.entries.count else { throw Fund("csv", "Bericht passt nicht zu den Einträgen") }
        for e in r.entries {
            guard e.title.utf8.count <= 2048, e.username.utf8.count <= 2048, e.url.utf8.count <= 2048,
                  e.password.utf8.count <= 4096, e.notes.utf8.count <= 256 * 1024 else {
                throw Fund("csv", "Feldgrenze verletzt")
            }
            for t in [e.title, e.username, e.url] where CSVText.containsControlOrBidi(t) {
                throw Fund("csv", "Steuer-/Richtungszeichen in Titel/Benutzer/URL")
            }
            guard e.created <= e.modified else { throw Fund("csv", "created > modified") }
            if !e.totp.isEmpty, (try? TOTP.parse(e.totp)) == nil { throw Fund("csv", "ungültiges 2FA-Geheimnis übernommen") }
            guard !(e.title.isEmpty && e.username.isEmpty && e.url.isEmpty && e.password.isEmpty && e.notes.isEmpty
                    && e.totp.isEmpty) else { throw Fund("csv", "leerer Eintrag übernommen") }
            do { try VaultContent.validate(e) } catch { throw Fund("csv", "Eintrag verletzt die Feldgrenzen des Kerns") }
        }
    }

    /// Einträge aus Zufallsbytes: Felder mit Kommas, Anführungszeichen, Umbrüchen, Unicode.
    private func eintraege(_ bytes: [UInt8]) -> [VaultEntry] {
        var z = Zufall(saat: bytes.reduce(UInt64(0xC5)) { ($0 &* 31) &+ UInt64($1) })
        let teile = ["a", "Z", ",", "\"", "\r\n", "\n", "\r", " ", "é", "😀", "\u{0}", "\t", "'", "=1+2", "ß", "\u{202E}"]
        func feld(_ max: Int, sauber: Bool) -> String {
            var s = ""
            for _ in 0..<z.int(0...max) {
                var t = z.pick(teile)
                if sauber, t.unicodeScalars.contains(where: CSVText.isControlOrBidi) { t = "x" }
                s += t
            }
            return s
        }
        return (0..<z.int(1...8)).map { _ in
            var e = VaultEntry(title: "T" + feld(12, sauber: true), username: feld(8, sauber: true),
                               password: feld(16, sauber: false), url: feld(8, sauber: true), notes: feld(24, sauber: false))
            if z.chance(0.1) { e.deletedAt = Date(timeIntervalSince1970: 1_800_000_000) }
            return e
        }
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard let art = e.first else { return "leer" }
        let b = Array(e.dropFirst())
        if art == 1 {
            let liste = eintraege(b)
            let daten = CSVExport.export(liste)
            let r: CSVImportResult
            do { r = try CSVImport.parse(daten) } catch {
                throw Fund("rundlauf", "Export lässt sich nicht importieren: " + fehlerCode(error))
            }
            let erwartet = liste.filter { $0.deletedAt == nil }
            guard r.format == .chrome, r.entries.count == erwartet.count else {
                throw Fund("rundlauf", "Anzahl/Format nach Export → Import")
            }
            for (x, y) in zip(erwartet, r.entries) {
                guard x.title == y.title, x.url == y.url, x.username == y.username, x.password == y.password,
                      x.notes == y.notes else { throw Fund("rundlauf", "Feld ändert sich bei Export → Import") }
            }
            return "rundlauf:ok"
        }
        do {
            let r = try CSVImport.parse(Data(b))
            try pruefeErgebnis(r)
            return "ok:" + r.format.rawValue
        } catch let x as SiegelError {
            guard case let .csvInvalid(zeile, grund) = x else { throw Fund("fehlertyp", "CSV: " + fehlerCode(x)) }
            guard CSVImport.reasonCodes.contains(grund) else { throw Fund("fehlertyp", "unbekannter reason-Code") }
            guard zeile >= 0, zeile <= Self.zeilenzahl(b) else { throw Fund("csv", "Zeilennummer ausserhalb der Datei") }
            return "csvInvalid(" + grund + ")"
        }
    }
}
#endif
