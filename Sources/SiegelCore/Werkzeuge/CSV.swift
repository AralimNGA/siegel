import Foundation

/// CSV-Import (SPEC §8 „CSV-Details“): Apple Passwörter, Chrome, Firefox, Bitwarden.
///
/// Ablauf: Grösse prüfen → BOM entfernen → RFC 4180 lesen (`CSVReader`) → Format an der Kopfzeile erkennen
/// (Spaltennamen ohne Leerraum am Rand, Gross/Klein egal, Reihenfolge egal) → Datensätze abbilden → Grenzen
/// prüfen. Jeder Fehler bricht den ganzen Import ab (kein Teilimport).
///
/// Erkennung (in dieser Reihenfolge, erste passende gewinnt; Pflichtspalten):
/// - Bitwarden: `type`, `name`, `login_uri`, `login_username`, `login_password`
/// - Apple:     `title`, `url`, `username`, `password`
/// - Chrome:    `name`, `url`, `username`, `password`
/// - Firefox:   `url`, `username`, `password` und mindestens eine von `guid`, `httprealm`,
///              `formactionorigin`, `timecreated`, `timelastused`, `timepasswordchanged`
///
/// Abbildung:
/// - Apple:     Title→Titel, URL, Username, Password, Notes→Notizen, OTPAuth→`totp`
/// - Chrome:    name→Titel, url, username, password, note→Notizen
/// - Firefox:   url, username, password, timeCreated→created, timePasswordChanged→modified (Millisekunden)
/// - Bitwarden: name→Titel, notes→Notizen, login_uri→URL, login_username, login_password,
///              login_totp→`totp`, type (`login`; `note` → nur Titel und Notizen)
/// - 2FA (SPEC §18, v4): Der Wert der 2FA-Spalte kommt nach `VaultEntry.totp` (Leerraum am Rand entfernt), wenn
///   `TOTP.parse` ihn annimmt (`otpauth://totp/…` oder Base32). Sonst (z. B. `steam://…`, `otpauth://hotp/…`,
///   Tippfehler) bleibt er wie bisher als Zeile „Spalte: Wert“ in den Notizen – nichts geht verloren.
/// - Jede andere nicht leere Spalte kommt als Zeile „Spalte: Wert“ (Spaltenname wie in der Kopfzeile) in die
///   Notizen. Reihenfolge: bisherige Notizen, Leerzeile, Zusatzzeilen in Spaltenreihenfolge. Leere
///   Spaltennamen heissen „Spalte n“ (1-basiert).
/// - Bitwarden `type=note`: Werte in URL/Benutzer/Passwort/2FA (normal leer) landen ebenfalls als
///   Zusatzzeilen in den Notizen (auch ein gültiges 2FA-Geheimnis, weil Notizen kein Login sind); ein anderer
///   Typ als `login`/`note` wird als Zeile `type: …` vermerkt.
/// - Firefox-Zeitstempel: leer → Importzeitpunkt; nicht lesbar (keine ganze Zahl 0…253402300799999) →
///   Importzeitpunkt und der Rohwert kommt als Zusatzzeile in die Notizen. `modified` ≥ `created`.
/// - Titel leer → Host der URL (ohne `www.`, klein; ohne Schema mit `https://` versucht; Hosts ausserhalb
///   ASCII/Latein als Punycode gegen Verwechslung); kein Host → URL selbst.
/// - Aus Titel, Benutzer, URL werden U+0000–001F, U+007F, U+200E/200F, U+202A–202E, U+2066–2069 entfernt.
///   Passwörter bleiben byte-genau; der Bericht zählt Passwörter mit diesen Zeichen und mit führendem `'`.
/// - Datensätze ohne Titel, Benutzer, URL, Passwort, Notizen und 2FA (z. B. `,,,,` oder nur Metadaten wie
///   `reprompt`/`guid`) werden übersprungen; sie enthalten keine Zugangsdaten.
///
/// Bericht (vorläufig): `added` = Anzahl Einträge, `withOTPSecret` = Einträge, deren 2FA-Geheimnis nach
/// `totp` übernommen wurde, `movedToNotes` = Einträge, bei denen mindestens eine Spalte in die Notizen kam
/// (dazu zählt auch ein 2FA-Wert, den `TOTP.parse` nicht annimmt), `passwordsWithControlCharacters`,
/// `apostrophePrefixed`. Dubletten/Konflikte zählt erst `importEntries`.
///
/// Fehler `SiegelError.csvInvalid(line:reason:)`. `line` = physische Zeile (1-basiert), in der der
/// Datensatz beginnt; bei `csv.quote` die Zeile des Zeichens; 0 = ganze Datei. Feste reason-Codes:
/// - `csv.fileTooLarge`       Datei > 16 MiB (line 0)
/// - `csv.empty`              keine Kopfzeile (leer, nur BOM oder nur Leerzeilen; line 0)
/// - `csv.encoding`           kein gültiges UTF-8
/// - `csv.quote`              `"` in nicht zitiertem Feld oder Zeichen nach schliessendem `"`
/// - `csv.unterminatedQuote`  zitiertes Feld bis Dateiende nicht geschlossen
/// - `csv.header.unknown`     Kopfzeile passt zu keinem Format oder hat mehr als 256 Felder
/// - `csv.header.duplicate`   Spaltenname doppelt (Spaltennamen über 256 Byte UTF-8 haben keine Rolle und zählen nicht,
///                            v4.8)
/// - `csv.fieldCount`         Datensatz hat nicht gleich viele Felder wie die Kopfzeile (zu viele: Abbruch schon
///                            beim Lesen, Zeile = Beginn des Datensatzes)
/// - `csv.tooManyRows`        mehr als 20 000 Datensätze (ohne Kopfzeile, ohne Leerzeilen)
/// - `csv.field.title`, `csv.field.username`, `csv.field.url` (> 2 KiB UTF-8),
///   `csv.field.password` (> 4 KiB), `csv.field.notes` (> 256 KiB, nach dem Anhängen der Zusatzzeilen)
public enum CSVImport {
    static let maximumFileBytes = 16 * 1024 * 1024
    static let maximumRows = 20_000
    static let maximumTitleBytes = 2 * 1024
    static let maximumUsernameBytes = 2 * 1024
    static let maximumURLBytes = 2 * 1024
    static let maximumPasswordBytes = 4 * 1024
    static let maximumNotesBytes = 256 * 1024
    /// Längere Spaltennamen (UTF-8, ohne Leerraum am Rand) haben keine Rolle (v4.8, Befund robust-7): sie werden weder
    /// klein geschrieben noch verglichen und kommen nur als „Spalte: Wert“ in die Notizen. Das kanonische Vergleichen
    /// (`Set<String>`) langer Folgen von Kombinationszeichen wäre quadratisch.
    static let maximumHeaderLabelBytes = 256

    /// Vollständige Liste der reason-Codes (intern; für Tests und als Referenz für die Oberfläche).
    static let reasonCodes: [String] = [
        "csv.fileTooLarge", "csv.empty", "csv.encoding", "csv.quote", "csv.unterminatedQuote",
        "csv.header.unknown", "csv.header.duplicate", "csv.fieldCount", "csv.tooManyRows",
        "csv.field.title", "csv.field.username", "csv.field.url", "csv.field.password", "csv.field.notes",
    ]

    public static func parse(_ data: Data) throws -> CSVImportResult {
        guard data.count <= maximumFileBytes else {
            throw SiegelError.csvInvalid(line: 0, reason: "csv.fileTooLarge")
        }
        let now = Date()
        return try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) throws(SiegelError) -> CSVImportResult in
            let hasBOM = raw.count >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF
            var reader = CSVReader(bytes: raw, startIndex: hasBOM ? 3 : 0)
            defer { reader.wipe() }

            guard let header = try reader.next() else {
                throw .csvInvalid(line: 0, reason: "csv.empty")
            }
            let layout = try Layout(header: header)
            // Befund #45: Datensätze nur so breit wie die Kopfzeile lesen (Abbruch während des Lesens).
            reader.maxFields = layout.columns.count
            reader.tooManyFieldsReason = "csv.fieldCount"

            var entries: [VaultEntry] = []
            var report = ImportReport()
            var rows = 0
            while let record = try reader.next() {
                rows += 1
                if rows > maximumRows {
                    throw .csvInvalid(line: record.line, reason: "csv.tooManyRows")
                }
                guard record.fields.count == layout.columns.count else {
                    throw .csvInvalid(line: record.line, reason: "csv.fieldCount")
                }
                guard let mapped = try layout.map(record, now: now) else { continue }
                entries.append(mapped.entry)
                if mapped.hasOTP { report.withOTPSecret += 1 }
                if mapped.movedToNotes { report.movedToNotes += 1 }
                if CSVText.containsControlOrBidi(mapped.entry.password) { report.passwordsWithControlCharacters += 1 }
                if mapped.entry.password.unicodeScalars.first == "'" { report.apostrophePrefixed += 1 }
            }
            report.added = entries.count
            return CSVImportResult(format: layout.format, entries: entries, report: report)
        }
    }
}

// MARK: - Kopfzeile und Abbildung

extension CSVImport {
    enum Role: Equatable {
        case title, url, username, password, notes, otp, created, modified, type
        case extra
    }

    struct Column {
        /// Spaltenname wie in der Kopfzeile (ohne Leerraum am Rand), für „Spalte: Wert“.
        let label: String
        let role: Role
    }

    struct Mapped {
        let entry: VaultEntry
        let hasOTP: Bool
        let movedToNotes: Bool
    }

    struct Layout {
        let format: CSVImportResult.Format
        let columns: [Column]

        init(header: CSVReader.Record) throws(SiegelError) {
            var labels: [String] = []
            var normalized: [String] = []
            var seen = Set<String>()
            for (offset, raw) in header.fields.enumerated() {
                let label = raw.trimmingCharacters(in: .whitespaces)
                if label.utf8.count > CSVImport.maximumHeaderLabelBytes {
                    // Zusatzspalte ohne Rolle (leerer Schlüssel passt zu keiner Rolle und zählt nicht als Doppel)
                    labels.append(label)
                    normalized.append("")
                    continue
                }
                let key = label.lowercased()
                if !key.isEmpty {
                    guard seen.insert(key).inserted else {
                        throw .csvInvalid(line: header.line, reason: "csv.header.duplicate")
                    }
                }
                labels.append(key.isEmpty ? "Spalte \(offset + 1)" : label)
                normalized.append(key)
            }

            guard let (format, roles) = Self.detect(seen) else {
                throw .csvInvalid(line: header.line, reason: "csv.header.unknown")
            }
            self.format = format
            var columns: [Column] = []
            for (label, key) in zip(labels, normalized) {
                var role = Role.extra
                for (name, mappedRole) in roles where name == key {
                    role = mappedRole
                }
                columns.append(Column(label: label, role: role))
            }
            self.columns = columns
        }

        /// Format und Rollen-Tabelle (normalisierter Spaltenname → Rolle) als Liste, ohne Dictionary-Literal-Fallen.
        static func detect(_ names: Set<String>) -> (CSVImportResult.Format, [(String, Role)])? {
            if names.isSuperset(of: ["type", "name", "login_uri", "login_username", "login_password"]) {
                return (.bitwarden, [("name", .title), ("notes", .notes), ("login_uri", .url),
                                     ("login_username", .username), ("login_password", .password),
                                     ("login_totp", .otp), ("type", .type)])
            }
            if names.isSuperset(of: ["title", "url", "username", "password"]) {
                return (.applePasswords, [("title", .title), ("url", .url), ("username", .username),
                                          ("password", .password), ("notes", .notes), ("otpauth", .otp)])
            }
            if names.isSuperset(of: ["name", "url", "username", "password"]) {
                return (.chrome, [("name", .title), ("url", .url), ("username", .username),
                                  ("password", .password), ("note", .notes)])
            }
            let firefoxMarkers: Set<String> = ["guid", "httprealm", "formactionorigin",
                                               "timecreated", "timelastused", "timepasswordchanged"]
            if names.isSuperset(of: ["url", "username", "password"]), !names.isDisjoint(with: firefoxMarkers) {
                return (.firefox, [("url", .url), ("username", .username), ("password", .password),
                                   ("timecreated", .created), ("timepasswordchanged", .modified)])
            }
            return nil
        }

        /// Bildet einen Datensatz ab; nil = Datensatz ganz leer (überspringen).
        func map(_ record: CSVReader.Record, now: Date) throws(SiegelError) -> Mapped? {
            let line = record.line

            // Bitwarden: Typ vorab bestimmen.
            var isNote = false
            for (column, value) in zip(columns, record.fields) where column.role == .type {
                isNote = value.trimmingCharacters(in: .whitespaces).lowercased() == "note"
            }

            var title = "", url = "", username = "", password = "", notes = "", totp = ""
            var created: Date?
            var modified: Date?
            var extraLines: [String] = []
            var hasOTP = false
            var hadOTPValue = false
            var movedToNotes = false

            func addExtra(_ label: String, _ value: String) {
                extraLines.append(label + ": " + value)
            }

            for (column, value) in zip(columns, record.fields) {
                switch column.role {
                case .title:
                    title = value
                case .notes:
                    notes = value
                case .url, .username, .password:
                    if isNote {
                        if !value.isEmpty { addExtra(column.label, value); movedToNotes = true }
                    } else if column.role == .url {
                        url = value
                    } else if column.role == .username {
                        username = value
                    } else {
                        password = value
                    }
                case .otp:
                    guard !value.isEmpty else { break }
                    hadOTPValue = true
                    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !isNote, (try? TOTP.parseTyped(trimmed)) != nil {
                        totp = trimmed
                        hasOTP = true
                    } else {
                        addExtra(column.label, value); movedToNotes = true
                    }
                case .created, .modified:
                    let trimmed = value.trimmingCharacters(in: .whitespaces)
                    guard !trimmed.isEmpty else { break }
                    if let date = CSVText.dateFromMilliseconds(trimmed) {
                        if column.role == .created { created = date } else { modified = date }
                    } else {
                        addExtra(column.label, value); movedToNotes = true
                    }
                case .type:
                    let kind = value.trimmingCharacters(in: .whitespaces).lowercased()
                    if !kind.isEmpty, kind != "login", kind != "note" {
                        addExtra(column.label, value); movedToNotes = true
                    }
                case .extra:
                    if !value.isEmpty { addExtra(column.label, value); movedToNotes = true }
                }
            }

            title = CSVText.strippingControlAndBidi(title)
            username = CSVText.strippingControlAndBidi(username)
            url = CSVText.strippingControlAndBidi(url)

            // Ohne Inhalt (nur Metadaten wie reprompt/guid oder ganz leer) → überspringen.
            if title.isEmpty, username.isEmpty, url.isEmpty, password.isEmpty, notes.isEmpty, !hadOTPValue {
                return nil
            }
            if !extraLines.isEmpty {
                let extra = extraLines.joined(separator: "\n")
                notes = notes.isEmpty ? extra : notes + "\n\n" + extra
            }
            if title.isEmpty, !url.isEmpty {
                title = CSVText.strippingControlAndBidi(CSVText.titleFromURL(url))
            }

            guard title.utf8.count <= CSVImport.maximumTitleBytes else {
                throw .csvInvalid(line: line, reason: "csv.field.title")
            }
            guard username.utf8.count <= CSVImport.maximumUsernameBytes else {
                throw .csvInvalid(line: line, reason: "csv.field.username")
            }
            guard url.utf8.count <= CSVImport.maximumURLBytes else {
                throw .csvInvalid(line: line, reason: "csv.field.url")
            }
            guard password.utf8.count <= CSVImport.maximumPasswordBytes else {
                throw .csvInvalid(line: line, reason: "csv.field.password")
            }
            guard notes.utf8.count <= CSVImport.maximumNotesBytes else {
                throw .csvInvalid(line: line, reason: "csv.field.notes")
            }

            var entry = VaultEntry(title: title, username: username, password: password, url: url, notes: notes,
                                   totp: totp)
            let createdDate = created ?? modified ?? now
            var modifiedDate = modified ?? created ?? now
            if modifiedDate < createdDate { modifiedDate = createdDate }
            entry.created = createdDate
            entry.modified = modifiedDate
            return Mapped(entry: entry, hasOTP: hasOTP, movedToNotes: movedToNotes)
        }
    }
}

// MARK: - Text-Hilfen

enum CSVText {
    /// Steuer- und Bidi-Zeichen nach SPEC §8: U+0000–001F, U+007F, U+200E/200F, U+202A–202E, U+2066–2069.
    static func isControlOrBidi(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x0000...0x001F, 0x007F, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
            return true
        default:
            return false
        }
    }

    static func containsControlOrBidi(_ text: String) -> Bool {
        text.unicodeScalars.contains(where: isControlOrBidi)
    }

    static func strippingControlAndBidi(_ text: String) -> String {
        guard containsControlOrBidi(text) else { return text }
        var scalars = String.UnicodeScalarView()
        for scalar in text.unicodeScalars where !isControlOrBidi(scalar) {
            scalars.append(scalar)
        }
        return String(scalars)
    }

    /// Firefox: Millisekunden seit 1970 als ganze Zahl 0…253402300799999 (bis Ende Jahr 9999).
    static func dateFromMilliseconds(_ text: String) -> Date? {
        guard !text.isEmpty, text.utf8.count <= 15, text.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              let ms = Int64(text), ms <= 253_402_300_799_999 else { return nil }
        return Date(timeIntervalSince1970: Double(ms) / 1000)
    }

    /// Titel aus der URL: Host ohne `www.`, klein. Ohne Schema wird `https://` versucht.
    /// Hosts mit Zeichen ausserhalb ASCII/Latein werden als Punycode gezeigt (Schutz vor Verwechslung).
    /// Kein Host → die URL selbst.
    static func titleFromURL(_ url: String) -> String {
        let trimmed = url.trimmingCharacters(in: .whitespaces)
        var host = hostOf(trimmed)
        if host == nil, !trimmed.contains("://") { host = hostOf("https://" + trimmed) }
        guard var name = host, !name.isEmpty else { return url }
        name = name.lowercased()
        if name.hasPrefix("www."), name.count > 4 { name.removeFirst(4) }
        return name
    }

    private static func hostOf(_ string: String) -> String? {
        guard let components = URLComponents(string: string), let unicodeHost = components.host,
              !unicodeHost.isEmpty else { return nil }
        if unicodeHost.unicodeScalars.allSatisfy(isLatinOrASCII) { return unicodeHost }
        // Gemischte/fremde Schriftsysteme: Punycode-Form (URL.host liefert IDNA-kodiert).
        return URL(string: string)?.host(percentEncoded: false) ?? unicodeHost
    }

    private static func isLatinOrASCII(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x0000...0x007F: return true
        case 0x00C0...0x00D6, 0x00D8...0x00F6, 0x00F8...0x024F: return true   // Latin-1 Buchstaben, Latin Extended-A/B
        default: return false
        }
    }
}
