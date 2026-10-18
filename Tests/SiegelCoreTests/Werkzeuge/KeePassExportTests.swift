import Foundation
import Testing
@testable import SiegelCore

// Tests für den KeePass-Export KDBX 4.1 (SPEC §19). Geöffnet wird mit dem unabhängigen Test-Leser `KDBXLeser`;
// zusätzlich liest `ReferenzTests` dieselben Dateien mit der Python-Referenz. Die meisten Tests nutzen den
// DEBUG-Testschalter (Argon2id t = 1, 64 KiB); ein Test in einer `.serialized`-Suite nutzt die echten 256 MiB.

let kdbxTestKDF = KeePassExport.KDF(opsLimit: 1, memLimitBytes: 64 << 10)
/// 20 Zufallszeichen: erfüllt die Master-Passwort-Regel (die auch für das Export-Passwort gilt).
let kdbxPasswort = "kV7#pQ2$mZ9!xR4@tL8&"

private func date(_ t: TimeInterval) -> Date { Date(timeIntervalSince1970: t) }

/// Erfundene Einträge mit allem, was im XML schwierig ist.
func kdbxBeispielEintraege() -> [(VaultEntry, EntrySecrets)] {
    func eintrag(_ title: String, _ user: String, _ password: String, _ url: String, _ notes: String,
                 _ totp: String = "", created: TimeInterval = 1_700_000_000.7, modified: TimeInterval = 1_760_000_000) -> (VaultEntry, EntrySecrets) {
        var e = VaultEntry(title: title, username: user, password: password, url: url, notes: notes, totp: totp)
        e.created = date(created)
        e.modified = date(modified)
        return (e, EntrySecrets(password: password, notes: notes, totp: totp))
    }
    return [
        eintrag("Bank <Privat> & Co", "anna\"o'neil", "Pa$$w0rd <&> \"'", "https://bank.example.ch/login?a=1&b=2",
                "Zeile 1\r\nZeile 2\nZeile 3\r", "otpauth://totp/Bank:anna?secret=JBSWY3DPEHPK3PXP&issuer=Bank"),
        eintrag("Zürich Velo 🚲", "jürg", "🔑Äöü e\u{0301} \u{00A0}", "https://bücher.de", "«Guillemets» — ‹›",
                "jbsw y3dp ehpk 3pxp"),
        eintrag("Steuer\u{7}zeichen", "u\u{1F}", "\u{0}\t\r\n\u{202E}x", "", "Nul\u{0}im Text\u{FFFF}"),
        eintrag("", "", "", "", ""),
        eintrag("   ", "", "  ", "", "\t", "kein-geheimnis"),
        eintrag("]]> <![CDATA[ x ]]>", "&amp;", "&#13;", "<!-- -->", "<?xml?>"),
    ]
}

@Suite("KeePass-Export: Rundlauf")
struct KeePassRundlaufTests {

    @Test("Alle Felder kommen byte-genau zurück; Password und otp geschützt")
    func rundlauf() throws {
        let items = kdbxBeispielEintraege()
        let datei = try KDBXLeser.lesen(try KeePassExport.kdbx(items, password: kdbxPasswort, kdf: kdbxTestKDF),
                                        passwort: kdbxPasswort)
        #expect(datei.version == 0x0004_0001)
        #expect(datei.gruppe == "Siegel")
        #expect(datei.eintraege.count == items.count)
        for ((entry, secrets), gelesen) in zip(items, datei.eintraege) {
            #expect(gelesen.uuid == Data(KeePassExport.uuidBytes(entry.id)))
            #expect(Array((gelesen.werte["Title"] ?? "-").utf8) == Array(entry.title.utf8))
            #expect(Array((gelesen.werte["UserName"] ?? "-").utf8) == Array(entry.username.utf8))
            #expect(Array((gelesen.werte["Password"] ?? "-").utf8) == Array(secrets.password.utf8))
            #expect(Array((gelesen.werte["URL"] ?? "-").utf8) == Array(entry.url.utf8))
            #expect(Array((gelesen.werte["Notes"] ?? "-").utf8) == Array(secrets.notes.utf8))
            #expect(gelesen.geschuetzt.contains("Password"))
            #expect(gelesen.erstellt == Date(timeIntervalSince1970: floor(entry.created.timeIntervalSince1970)))
            #expect(gelesen.geaendert == entry.modified)
        }
        let e = datei.eintraege
        // otp: URI unverändert, Base32 zur URI ergänzt, Ungültiges roh, leer → kein Feld
        #expect(e[0].werte["otp"] == "otpauth://totp/Bank:anna?secret=JBSWY3DPEHPK3PXP&issuer=Bank")
        #expect(e[1].werte["otp"] == "otpauth://totp/Z%C3%BCrich%20Velo%20%F0%9F%9A%B2?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1")
        #expect(try TOTP.parse(e[1].werte["otp"] ?? "") == TOTP.parse("JBSWY3DPEHPK3PXP").withLabel(issuer: "", account: "Zürich Velo 🚲"))
        #expect(e[4].werte["otp"] == "kein-geheimnis")
        #expect(e[2].werte["otp"] == nil && e[3].werte["otp"] == nil)
        #expect(e[0].geschuetzt.contains("otp"))
        // Unerlaubte XML-Zeichen und reiner Leerraum werden geschützt geschrieben, sonst nicht
        #expect(e[2].geschuetzt == ["Password", "Title", "UserName", "Notes"])
        #expect(e[4].geschuetzt == ["Password", "Title", "Notes", "otp"])
        #expect(e[0].geschuetzt == ["Password", "otp"])
        // Klartext steht nur für ungeschützte Werte im XML
        #expect(!datei.xml.contains("Pa$$w0rd"))
        #expect(!datei.xml.contains("JBSWY3DPEHPK3PXP"))
        #expect(datei.xml.contains("Bank &lt;Privat&gt; &amp; Co"))
        #expect(datei.xml.contains("Zeile 1&#13;\nZeile 2"))
    }

    @Test("Kopf: ChaCha20, keine Kompression, Argon2id p = 1, Salz 16 B, Version 0x13, innerer Strom ChaCha20")
    func kopf() throws {
        let data = try KeePassExport.kdbx(kdbxBeispielEintraege(), password: kdbxPasswort, kdf: kdbxTestKDF)
        #expect(Array(data.prefix(12)) == [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x01, 0x00, 0x04, 0x00])
        let datei = try KDBXLeser.lesen(data, passwort: kdbxPasswort)
        #expect(datei.kopfFelder[2] == KDBXLeser.chacha20)
        #expect(datei.kopfFelder[3] == Data([0, 0, 0, 0]))
        #expect(datei.kopfFelder[4]?.count == 32)
        #expect(datei.kopfFelder[7]?.count == 12)
        #expect(datei.kopfFelder[0] == Data([0x0D, 0x0A, 0x0D, 0x0A]))
        #expect(Set(datei.kopfFelder.keys) == [0, 2, 3, 4, 7, 11])
        #expect(datei.kdf["$UUID"] == KDBXLeser.argon2id)
        #expect(datei.kdf["S"]?.count == 16)
        #expect(datei.kdf["P"] == Data([1, 0, 0, 0]))
        #expect(datei.kdf["V"] == Data([0x13, 0, 0, 0]))
        #expect(datei.kdf["M"] == Data(KeePassExport.le(UInt64(64 << 10))))
        #expect(datei.kdf["I"] == Data(KeePassExport.le(UInt64(1))))
        #expect(datei.kdfTypen == ["$UUID": 0x42, "S": 0x42, "P": 0x04, "M": 0x05, "I": 0x05, "V": 0x04])
        #expect(datei.innererStromID == 3)
        #expect(datei.bloecke == 2)                  // ein Datenblock und der leere Abschluss
        #expect(datei.xml.hasPrefix("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile>"))
    }

    @Test("Zwei Exporte desselben Inhalts unterscheiden sich vollständig (Seed, IV, Salz, Strom zufällig)")
    func zufall() throws {
        let items = kdbxBeispielEintraege()
        let a = try KeePassExport.kdbx(items, password: kdbxPasswort, kdf: kdbxTestKDF)
        let b = try KeePassExport.kdbx(items, password: kdbxPasswort, kdf: kdbxTestKDF)
        #expect(a != b)
        #expect(a.count == b.count)
        let a1 = try KDBXLeser.lesen(a, passwort: kdbxPasswort)
        let b1 = try KDBXLeser.lesen(b, passwort: kdbxPasswort)
        #expect(a1.kopfFelder[4] != b1.kopfFelder[4] && a1.kopfFelder[7] != b1.kopfFelder[7] && a1.kdf["S"] != b1.kdf["S"])
        #expect(a1.eintraege == b1.eintraege)
    }

    @Test("Mehrere Blöcke zu 1 MiB bei grossem Inhalt")
    func mehrereBloecke() throws {
        let notiz = String(repeating: "Notiz mit viel Text. ", count: 12_000)        // ≈ 252 KB je Eintrag
        let items = (0..<6).map { i -> (VaultEntry, EntrySecrets) in
            let e = VaultEntry(title: "Eintrag \(i)", username: "u\(i)", password: "pw-\(i)", url: "", notes: notiz)
            return (e, EntrySecrets(password: "pw-\(i)", notes: notiz))
        }
        let datei = try KDBXLeser.lesen(try KeePassExport.kdbx(items, password: kdbxPasswort, kdf: kdbxTestKDF),
                                        passwort: kdbxPasswort)
        #expect(datei.bloecke == 3)                 // 1 MiB + Rest + Abschluss
        #expect(datei.eintraege.map { $0.werte["Notes"] } == Array(repeating: notiz, count: 6))
        #expect(datei.eintraege.map { $0.werte["Password"] } == (0..<6).map { "pw-\($0)" })
    }

    @Test("Leere Liste ergibt eine gültige Datei ohne Einträge")
    func leer() throws {
        let datei = try KDBXLeser.lesen(try KeePassExport.kdbx([], password: kdbxPasswort, kdf: kdbxTestKDF),
                                        passwort: kdbxPasswort)
        #expect(datei.eintraege.isEmpty)
        #expect(datei.gruppe == "Siegel")
    }
}

@Suite("KeePass-Export: Auswahl, Passwort, Manipulation")
struct KeePassRegelnTests {

    @Test("Gelöschte Einträge, Schutz 4/5 und Verlauf werden nicht exportiert")
    func auswahl() throws {
        var geloescht = VaultEntry(title: "Gelöscht", password: "weg")
        geloescht.deletedAt = Date()
        let maximal = VaultEntry(title: "Maximal", password: "nie-exportieren", protection: .maximal)
        let festung = VaultEntry(title: "Festung", password: "nie-exportieren-2", protection: .festung)
        let hoch = VaultEntry(title: "Hoch", password: "hoch-pw", protection: .hoch)
        var mitVerlauf = VaultEntry(title: "Verlauf", password: "neu")
        mitVerlauf.history = [PasswordHistoryItem(password: "altes-geheimnis", changed: Date())]
        let items: [(VaultEntry, EntrySecrets)] = [
            (geloescht, EntrySecrets(password: "weg")), (maximal, EntrySecrets(password: "nie-exportieren")),
            (festung, EntrySecrets(password: "nie-exportieren-2")), (hoch, EntrySecrets(password: "hoch-pw")),
            (mitVerlauf, EntrySecrets(password: "neu", history: mitVerlauf.history)),
        ]
        let datei = try KDBXLeser.lesen(try KeePassExport.kdbx(items, password: kdbxPasswort, kdf: kdbxTestKDF),
                                        passwort: kdbxPasswort)
        #expect(datei.eintraege.map { $0.werte["Title"] } == ["Hoch", "Verlauf"])
        #expect(datei.eintraege.map { $0.werte["Password"] } == ["hoch-pw", "neu"])
        #expect(!datei.xml.contains("<History>") && datei.xml.contains("<History/>"))
    }

    @Test("Versiegelte Einträge: Geheimteile aus EntrySecrets; offene Einträge füllen leere Felder selbst")
    func geheimteile() throws {
        let offen = VaultEntry(title: "Offen", password: "aus-dem-eintrag", notes: "Notiz", totp: "JBSWY3DPEHPK3PXP")
        let datei = try KDBXLeser.lesen(try KeePassExport.kdbx([(offen, EntrySecrets())], password: kdbxPasswort,
                                                               kdf: kdbxTestKDF), passwort: kdbxPasswort)
        #expect(datei.eintraege[0].werte["Password"] == "aus-dem-eintrag")
        #expect(datei.eintraege[0].werte["Notes"] == "Notiz")
        #expect(datei.eintraege[0].werte["otp"]?.hasPrefix("otpauth://totp/Offen?secret=JBSWY3DPEHPK3PXP") == true)
        // Versiegelt: der Eintrag selbst ist leer, nur EntrySecrets zählt.
        let json = Data(#"{"id":"6A0B7C1E-3F4D-4E2A-9B8C-1D2E3F405162","title":"Zu","username":"","password":"","url":"","notes":"","created":0,"modified":0,"history":[],"totp":"","protection":2,"secretsSealed":true}"#.utf8)
        let versiegelt = try JSONDecoder().decode(VaultEntry.self, from: json)
        #expect(versiegelt.secretsSealed)
        let zweite = try KDBXLeser.lesen(try KeePassExport.kdbx([(versiegelt, EntrySecrets(password: "aufgedeckt"))],
                                                                password: kdbxPasswort, kdf: kdbxTestKDF),
                                         passwort: kdbxPasswort)
        #expect(zweite.eintraege[0].werte["Password"] == "aufgedeckt")
    }

    @Test("Export-Passwort muss die Master-Passwort-Regel erfüllen")
    func schwachesPasswort() {
        for schwach in ["", "kurz", "Passwort1234!", "aaaaaaaaaaaaaaaaaaaa"] {
            let error = #expect(throws: SiegelError.self) {
                try KeePassExport.kdbx([], password: schwach, kdf: kdbxTestKDF)
            }
            guard case .passwordTooWeak = error else {
                Issue.record("passwordTooWeak erwartet")
                continue
            }
        }
    }

    @Test("Falsches Passwort scheitert am Kopf-HMAC")
    func falschesPasswort() throws {
        let data = try KeePassExport.kdbx(kdbxBeispielEintraege(), password: kdbxPasswort, kdf: kdbxTestKDF)
        #expect(throws: KDBXLeser.Fehler.kopfHMAC) { try KDBXLeser.lesen(data, passwort: kdbxPasswort + "x") }
        #expect(throws: KDBXLeser.Fehler.kopfHMAC) { try KDBXLeser.lesen(data, passwort: "kV7#pQ2$mZ9!xR4@tL8") }
    }

    @Test("Jedes gekippte Byte wird erkannt (Kopf-Hash, Kopf-HMAC, Block-HMAC), Kürzen und Verlängern auch")
    func manipulation() throws {
        let data = try KeePassExport.kdbx([kdbxBeispielEintraege()[0]], password: kdbxPasswort, kdf: kdbxTestKDF)
        var bytes = Array(data)
        // Jede 7. Stelle plus alle Stellen der ersten 300 Byte (Kopf und Kopf-Prüfwerte) kippen
        let stellen = Set(Array(0..<min(300, bytes.count)) + Array(stride(from: 0, to: bytes.count, by: 7)))
        for stelle in stellen.sorted() {
            bytes[stelle] ^= 0x01
            #expect(throws: (any Error).self, "Stelle \(stelle)") { try KDBXLeser.lesen(Data(bytes), passwort: kdbxPasswort) }
            bytes[stelle] ^= 0x01
        }
        #expect(throws: KDBXLeser.Fehler.kurz) { try KDBXLeser.lesen(data.dropLast(), passwort: kdbxPasswort) }
        #expect(throws: KDBXLeser.Fehler.restbytes) { try KDBXLeser.lesen(data + Data([0]), passwort: kdbxPasswort) }
        #expect(try KDBXLeser.lesen(Data(bytes), passwort: kdbxPasswort).eintraege.count == 1)
    }

    @Test("Zeiten: Base64 von Int64 Sekunden seit 0001-01-01")
    func zeiten() {
        #expect(KeePassExport.timeText(Date(timeIntervalSince1970: 0)) == Data(KeePassExport.le(UInt64(62_135_596_800))).base64EncodedString())
        #expect(KDBXLeser.zeit(KeePassExport.timeText(Date(timeIntervalSince1970: 1_234_567_890.9)))
                == Date(timeIntervalSince1970: 1_234_567_890))
        #expect(KDBXLeser.zeit(KeePassExport.timeText(Date(timeIntervalSince1970: -1e12))) == Date(timeIntervalSince1970: -62_000_000_000))
        #expect(KeePassExport.timeText(Date(timeIntervalSince1970: .nan)) == KeePassExport.timeText(Date(timeIntervalSince1970: 0)))
    }
}

@Suite("KeePass-Export: echte Argon2-Parameter (256 MiB)", .serialized)
struct KeePassEchteParameterTests {

    @Test("kdbx() nutzt Argon2id t = 3, m = 256 MiB, p = 1, und die Datei lässt sich öffnen")
    func echteParameter() throws {
        let data = try KeePassExport.kdbx(kdbxBeispielEintraege(), password: kdbxPasswort)
        let datei = try KDBXLeser.lesen(data, passwort: kdbxPasswort)
        #expect(datei.kdf["M"] == Data(KeePassExport.le(UInt64(256 << 20))))
        #expect(datei.kdf["I"] == Data(KeePassExport.le(UInt64(3))))
        #expect(datei.kdf["P"] == Data([1, 0, 0, 0]))
        #expect(datei.eintraege.count == kdbxBeispielEintraege().count)
    }
}
