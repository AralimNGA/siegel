import Clibsodium
import Foundation

/// Strenger RFC-4180-Leser auf Byte-Ebene (SPEC §8 „CSV-Details“).
///
/// - Trenner `,`; Datensätze enden mit CRLF, LF oder einzelnem CR. Die letzte Zeile darf ohne Umbruch enden;
///   eine abschliessende Leerzeile erzeugt keinen Datensatz.
/// - Felder in `"…"` dürfen Kommas, CR und LF enthalten; `""` steht für ein `"`.
/// - Streng: `"` mitten in einem nicht zitierten Feld oder ein Zeichen nach dem schliessenden `"` (ausser
///   Trenner/Umbruch) → `csv.quote`; offenes `"` am Dateiende → `csv.unterminatedQuote`.
/// - Leerzeilen (Datensatz aus genau einem Feld, das leer ist oder nur Leerzeichen/Tabs enthält) werden übersprungen.
/// - Feldinhalte bleiben byte-genau (kein Trimmen, keine Umbruch-Normalisierung) und müssen gültiges UTF-8
///   sein (`csv.encoding`).
/// - Zeilennummern sind physische Zeilen der Datei (1-basiert, Umbrüche in zitierten Feldern zählen mit).
/// - Höchstens `maxFields` Felder je Datensatz, geprüft **während** des Lesens (Befund #45: sonst belegt eine
///   16-MiB-Zeile aus Kommas rund 2 GB Arbeitsspeicher). Mehr → `csvInvalid(line: Beginn, reason:
///   tooManyFieldsReason)`, der Rest der Zeile wird nicht mehr gelesen.
///
/// Die Bytes `"`, `,`, CR und LF kommen in UTF-8 nie innerhalb eines Mehrbyte-Zeichens vor, darum ist das
/// Zerlegen auf Byte-Ebene korrekt.
struct CSVReader {
    struct Record {
        /// Physische Zeile, in der der Datensatz beginnt.
        let line: Int
        let fields: [String]
    }

    /// Obergrenze der Felder je Datensatz. Kein bekanntes Format hat mehr als 11 Spalten; 256 lässt Platz für
    /// unbekannte Zusatzspalten. `CSVImport.parse` setzt nach der Kopfzeile die Spaltenzahl der Kopfzeile.
    var maxFields = 256
    /// reason-Code beim Überschreiten (Kopfzeile: `csv.header.unknown`, Datensätze: `csv.fieldCount`).
    var tooManyFieldsReason = "csv.header.unknown"

    private let bytes: UnsafeRawBufferPointer
    private var index: Int
    private var line = 1
    private var field: [UInt8] = []

    private static let quote: UInt8 = 0x22
    private static let comma: UInt8 = 0x2C
    private static let cr: UInt8 = 0x0D
    private static let lf: UInt8 = 0x0A

    init(bytes: UnsafeRawBufferPointer, startIndex: Int) {
        self.bytes = bytes
        self.index = startIndex
        field.reserveCapacity(4096)
    }

    /// Best effort: Arbeitspuffer nullen (kann nach einem Fehler noch Feldinhalte enthalten).
    mutating func wipe() {
        field.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
        field.removeAll(keepingCapacity: true)
    }

    private enum State { case fieldStart, unquoted, quoted, quoteInQuoted }

    /// Nächster nicht leerer Datensatz oder nil am Dateiende.
    mutating func next() throws(SiegelError) -> Record? {
        while true {
            guard let record = try readRecord() else { return nil }
            // Leerzeile (auch nur Leerzeichen/Tabs)
            if record.fields.count == 1, record.fields[0].utf8.allSatisfy({ $0 == 0x20 || $0 == 0x09 }) { continue }
            return record
        }
    }

    private mutating func readRecord() throws(SiegelError) -> Record? {
        let count = bytes.count
        guard index < count else { return nil }
        let recordLine = line
        var fields: [String] = []
        var state = State.fieldStart

        while index < count {
            let byte = bytes[index]
            index += 1
            switch state {
            case .fieldStart:
                if byte == Self.quote {
                    state = .quoted
                } else if byte == Self.comma {
                    try append(try takeField(recordLine), to: &fields, recordLine)
                } else if byte == Self.cr || byte == Self.lf {
                    try append(try takeField(recordLine), to: &fields, recordLine)
                    consumeLineBreak(after: byte)
                    return Record(line: recordLine, fields: fields)
                } else {
                    field.append(byte)
                    state = .unquoted
                }
            case .unquoted:
                if byte == Self.comma {
                    try append(try takeField(recordLine), to: &fields, recordLine)
                    state = .fieldStart
                } else if byte == Self.cr || byte == Self.lf {
                    try append(try takeField(recordLine), to: &fields, recordLine)
                    consumeLineBreak(after: byte)
                    return Record(line: recordLine, fields: fields)
                } else if byte == Self.quote {
                    throw .csvInvalid(line: line, reason: "csv.quote")
                } else {
                    field.append(byte)
                }
            case .quoted:
                if byte == Self.quote {
                    state = .quoteInQuoted
                } else {
                    field.append(byte)
                    if byte == Self.lf {
                        line += 1
                    } else if byte == Self.cr {
                        if index < count, bytes[index] == Self.lf {
                            field.append(Self.lf)
                            index += 1
                        }
                        line += 1
                    }
                }
            case .quoteInQuoted:
                if byte == Self.quote {
                    field.append(Self.quote)
                    state = .quoted
                } else if byte == Self.comma {
                    try append(try takeField(recordLine), to: &fields, recordLine)
                    state = .fieldStart
                } else if byte == Self.cr || byte == Self.lf {
                    try append(try takeField(recordLine), to: &fields, recordLine)
                    consumeLineBreak(after: byte)
                    return Record(line: recordLine, fields: fields)
                } else {
                    throw .csvInvalid(line: line, reason: "csv.quote")
                }
            }
        }

        // Dateiende ohne abschliessenden Umbruch.
        switch state {
        case .quoted:
            throw .csvInvalid(line: recordLine, reason: "csv.unterminatedQuote")
        case .fieldStart, .unquoted, .quoteInQuoted:
            try append(try takeField(recordLine), to: &fields, recordLine)
            return Record(line: recordLine, fields: fields)
        }
    }

    private func append(_ value: String, to fields: inout [String], _ recordLine: Int) throws(SiegelError) {
        guard fields.count < maxFields else {
            throw .csvInvalid(line: recordLine, reason: tooManyFieldsReason)
        }
        fields.append(value)
    }

    /// CRLF als ein Umbruch; einzelnes CR oder LF ebenso.
    private mutating func consumeLineBreak(after byte: UInt8) {
        if byte == Self.cr, index < bytes.count, bytes[index] == Self.lf { index += 1 }
        line += 1
    }

    private mutating func takeField(_ recordLine: Int) throws(SiegelError) -> String {
        defer {
            field.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
            field.removeAll(keepingCapacity: true)
        }
        guard let value = String(validating: field, as: UTF8.self) else {
            throw .csvInvalid(line: recordLine, reason: "csv.encoding")
        }
        return value
    }
}
