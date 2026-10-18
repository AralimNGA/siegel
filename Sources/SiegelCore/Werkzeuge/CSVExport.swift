import Foundation

/// CSV-Export im Chrome-Format (SPEC §7.9, §8): Kopf `name,url,username,password,note`, **alle** Felder
/// (auch der Kopf) in Anführungszeichen, `"` verdoppelt, Datensätze mit CRLF (auch nach dem letzten),
/// UTF-8 ohne BOM. Gelöschte Einträge (`deletedAt` gesetzt) und der Passwort-Verlauf werden nicht exportiert.
/// Werte bleiben roh (kein Formel-Präfix `'`, siehe SPEC §12 „Verworfen“).
///
/// **2FA-Geheimnisse (`totp`, SPEC §18) werden nicht exportiert**: Das Chrome-Format hat keine Spalte dafür, und
/// ein Anhängen an die Notizen würde beim erneuten Import Passwort und zweiten Faktor still in dasselbe Feld
/// mischen. Wer die 2FA-Geheimnisse mitnehmen will, nimmt den KeePass-Export (Feld `otp`, §19). Die Oberfläche
/// nennt das in der Export-Warnung.
///
/// Die Ausgabe wird in einem Zug in einen Puffer exakt passender Grösse geschrieben, damit beim Wachsen keine
/// Klartext-Kopien in freigegebenem Speicher liegen bleiben (best effort; Dateischreiben und Aufräumen macht
/// `UnlockedVault.exportCSV`).
public enum CSVExport {
    static let header = ["name", "url", "username", "password", "note"]

    public static func export(_ entries: [VaultEntry]) -> Data {
        let rows: [[String]] = [header] + entries.lazy
            .filter { $0.deletedAt == nil }
            .map { [$0.title, $0.url, $0.username, $0.password, $0.notes] }

        // Exakte Grösse: je Feld 2 Anführungszeichen + Bytes + verdoppelte ", dazu Kommas und CRLF.
        var size = 0
        for row in rows {
            for value in row {
                size += 2 + value.utf8.count + value.utf8.lazy.filter { $0 == 0x22 }.count
            }
            size += max(row.count - 1, 0) + 2
        }

        var data = Data(count: size)
        data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            var offset = 0
            func put(_ byte: UInt8) {
                if offset < raw.count { raw[offset] = byte }
                offset += 1
            }
            for row in rows {
                for (column, value) in row.enumerated() {
                    if column > 0 { put(0x2C) }
                    put(0x22)
                    for byte in value.utf8 {
                        put(byte)
                        if byte == 0x22 { put(0x22) }
                    }
                    put(0x22)
                }
                put(0x0D)
                put(0x0A)
            }
        }
        return data
    }
}
