import Clibsodium
import CryptoKit
import Foundation

/// 2FA-Codes nach RFC 6238 (TOTP) auf Basis von RFC 4226 (HOTP), SPEC §18.
///
/// Eingabe (`VaultEntry.totp`): eine `otpauth://totp/…`-URI oder ein reines Base32-Geheimnis (RFC 4648).
/// Base32 ist tolerant: Leerraum wird ignoriert, Kleinbuchstaben sind erlaubt, das Padding `=` darf fehlen
/// (wenn vorhanden, muss es vollständig und am Ende stehen). Überzählige Bits am Ende werden ignoriert, wie es
/// Authenticator-Apps tun.
///
/// URI-Parser (streng, mit Grenzen):
/// - Schema `otpauth` und Typ `totp` (Gross/Klein egal); `hotp` und andere Typen → `totp.type`.
/// - Label (Prozent-kodiert) = `Aussteller:Konto` oder nur `Konto`; Parameter `secret` (Pflicht), `issuer`,
///   `algorithm` (`SHA1`, `SHA256`, `SHA512`), `digits` (genau 6 oder 8), `period` (15–120 s, Standard 30).
///   Unbekannte Parameter (z. B. `image`) werden ignoriert, bekannte doppelt → `totp.duplicate`.
/// - Ein `#`, ein Parameter ohne `=`, eine ungültige Prozent-Kodierung oder ungültiges UTF-8 → `totp.uri`.
/// - Aus Aussteller und Konto werden Steuer- und Richtungszeichen entfernt (wie beim CSV-Import).
///
/// Grenzen: Eingabe ≤ 2048 UTF-8-Bytes, höchstens 32 Parameter, Geheimnis 10–128 Byte (80–1024 Bit),
/// Aussteller und Konto je ≤ 256 UTF-8-Bytes.
///
/// Fehler: `SiegelError.totpInvalid(code)` mit festen Codes (Liste `reasonCodes`):
/// `totp.empty`, `totp.tooLong`, `totp.uri`, `totp.type`, `totp.secret.missing`, `totp.base32`,
/// `totp.secret.length`, `totp.algorithm`, `totp.digits`, `totp.period`, `totp.duplicate`, `totp.label`.
///
/// Das Geheimnis liegt dekodiert nur in `SecureBytes` (sodium_malloc, beim Freigeben genullt). Die Quelle
/// selbst ist ein Swift-`String` im Eintrag und lässt sich wie alle Eintragsfelder nicht zuverlässig nullen.
public enum TOTP {
    public struct Parameters: Sendable, Equatable {
        public enum Algorithm: String, Sendable, CaseIterable {
            case sha1, sha256, sha512

            /// Schreibweise in otpauth-URIs.
            public var uriName: String {
                switch self {
                case .sha1: "SHA1"
                case .sha256: "SHA256"
                case .sha512: "SHA512"
                }
            }
        }

        /// Dekodiertes Geheimnis (10–128 Byte).
        let key: SecureBytes
        public let algorithm: Algorithm
        /// 6 oder 8.
        public let digits: Int
        /// Sekunden, 15–120.
        public let period: Int
        /// Aussteller (z. B. „GitHub“), leer wenn unbekannt.
        public let issuer: String
        /// Konto (z. B. „anna@example.ch“), leer wenn unbekannt.
        public let account: String

        /// Prüft alle Grenzen (Geheimnis 10–128 Byte, Ziffern 6/8, Periode 15–120, Texte ≤ 256 Byte) und
        /// kopiert das Geheimnis in `SecureBytes`. Verstoss → `SiegelError.totpInvalid(code)`.
        public init(secret: some ContiguousBytes, algorithm: Algorithm = .sha1, digits: Int = 6, period: Int = 30,
                    issuer: String = "", account: String = "") throws {
            let key = try secret.withUnsafeBytes { raw -> SecureBytes in
                guard raw.count >= TOTP.minimumSecretBytes, raw.count <= TOTP.maximumSecretBytes else {
                    throw SiegelError.totpInvalid("totp.secret.length")
                }
                return try SecureBytes(copying: raw)
            }
            try self.init(key: key, algorithm: algorithm, digits: digits, period: period,
                          issuer: issuer, account: account)
        }

        init(key: SecureBytes, algorithm: Algorithm, digits: Int, period: Int, issuer: String,
             account: String) throws(SiegelError) {
            guard key.count >= TOTP.minimumSecretBytes, key.count <= TOTP.maximumSecretBytes else {
                throw .totpInvalid("totp.secret.length")
            }
            guard TOTP.allowedDigits.contains(digits) else { throw .totpInvalid("totp.digits") }
            guard TOTP.allowedPeriods.contains(period) else { throw .totpInvalid("totp.period") }
            let cleanIssuer = CSVText.strippingControlAndBidi(issuer)
            let cleanAccount = CSVText.strippingControlAndBidi(account)
            guard cleanIssuer.utf8.count <= TOTP.maximumLabelPartBytes,
                  cleanAccount.utf8.count <= TOTP.maximumLabelPartBytes else {
                throw .totpInvalid("totp.label")
            }
            self.key = key
            self.algorithm = algorithm
            self.digits = digits
            self.period = period
            self.issuer = cleanIssuer
            self.account = cleanAccount
        }

        /// Länge des Geheimnisses in Byte (zum Anzeigen der Stärke, ohne das Geheimnis herauszugeben).
        public var secretByteCount: Int { key.count }

        public static func == (a: Parameters, b: Parameters) -> Bool {
            a.algorithm == b.algorithm && a.digits == b.digits && a.period == b.period
                && a.issuer == b.issuer && a.account == b.account && a.key.constantTimeEquals(b.key)
        }
    }

    // MARK: - Grenzen und Codes

    static let maximumInputBytes = 2048
    static let maximumParameters = 32
    static let minimumSecretBytes = 10
    static let maximumSecretBytes = 128
    static let maximumLabelPartBytes = 256
    static let allowedDigits: Set<Int> = [6, 8]
    static let allowedPeriods = 15...120

    /// Alle reason-Codes von `totpInvalid` (intern; Referenz für Tests und Oberfläche).
    static let reasonCodes: [String] = [
        "totp.empty", "totp.tooLong", "totp.uri", "totp.type", "totp.secret.missing", "totp.base32",
        "totp.secret.length", "totp.algorithm", "totp.digits", "totp.period", "totp.duplicate", "totp.label",
    ]

    // MARK: - Öffentliche Schnittstelle

    /// `otpauth://totp/…`-URI oder reines Base32-Geheimnis → Parameter. Leerraum am Rand wird ignoriert.
    public static func parse(_ uriOrSecret: String) throws -> Parameters {
        try parseTyped(uriOrSecret)
    }

    /// Code zum Zeitpunkt `date` und verbleibende Sekunden der laufenden Periode (1…period).
    /// Zeiten vor 1970 gelten als 1970 (Zähler 0).
    public static func code(_ p: Parameters, at date: Date) -> (code: String, remaining: Int) {
        let raw = date.timeIntervalSince1970
        let seconds: Int64 = raw.isFinite ? Int64(max(0, min(floor(raw), 9.0e15))) : 0
        let period = Int64(p.period)
        let counter = UInt64(seconds / period)
        let remaining = Int(period - seconds % period)
        return (hotp(key: p.key, counter: counter, digits: p.digits, algorithm: p.algorithm), remaining)
    }

    // MARK: - HOTP (RFC 4226)

    /// HOTP-Wert: HMAC über den Zähler (8 Byte, Big-Endian), dynamische Kürzung, `digits` Stellen mit Nullen.
    static func hotp(key: SecureBytes, counter: UInt64, digits: Int, algorithm: Parameters.Algorithm) -> String {
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let symmetric = key.withUnsafeBytes { SymmetricKey(data: $0) }
        let mac: [UInt8]
        switch algorithm {
        case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetric))
        case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetric))
        case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetric))
        }
        guard let last = mac.last else { return String(repeating: "0", count: digits) }
        let offset = Int(last & 0x0f)
        let binary = (UInt32(mac[offset] & 0x7f) << 24) | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus &*= 10 }
        let value = String(binary % modulus)
        return String(repeating: "0", count: max(0, digits - value.count)) + value
    }

    // MARK: - Parser

    static func parseTyped(_ input: String) throws(SiegelError) -> Parameters {
        var bytes = Array(input.utf8)
        defer { wipe(&bytes) }
        guard bytes.count <= maximumInputBytes else { throw .totpInvalid("totp.tooLong") }
        var start = 0
        var end = bytes.count
        while start < end, isWhitespace(bytes[start]) { start += 1 }
        while end > start, isWhitespace(bytes[end - 1]) { end -= 1 }
        guard start < end else { throw .totpInvalid("totp.empty") }
        let trimmed = bytes[start..<end]

        let prefix = Array("otpauth://".utf8)
        if trimmed.count >= prefix.count,
           zip(trimmed.prefix(prefix.count), prefix).allSatisfy({ lowerASCII($0) == $1 }) {
            return try parseURI(trimmed.dropFirst(prefix.count))
        }
        // Andere URI-Schemata (z. B. otpauth-migration://) sind kein Geheimnis.
        if containsSubsequence(trimmed, Array("://".utf8)) { throw .totpInvalid("totp.uri") }
        let key = try decodeBase32(trimmed)
        return try Parameters(key: key, algorithm: .sha1, digits: 6, period: 30, issuer: "", account: "")
    }

    /// Rest nach `otpauth://`: `typ/label?parameter`. Arbeitet auf dem Puffer des Aufrufers (der ihn nullt).
    private static func parseURI(_ rest: ArraySlice<UInt8>) throws(SiegelError) -> Parameters {
        guard !rest.contains(UInt8(ascii: "#")) else { throw .totpInvalid("totp.uri") }

        // Typ
        var index = rest.startIndex
        while index < rest.endIndex, rest[index] != UInt8(ascii: "/"), rest[index] != UInt8(ascii: "?") { index += 1 }
        let type = rest[rest.startIndex..<index].map(lowerASCII)
        guard type == Array("totp".utf8) else { throw .totpInvalid("totp.type") }

        // Label
        var labelRange = index..<index
        if index < rest.endIndex, rest[index] == UInt8(ascii: "/") {
            index += 1
            let labelStart = index
            while index < rest.endIndex, rest[index] != UInt8(ascii: "?") { index += 1 }
            labelRange = labelStart..<index
        }
        let label = try decodeText(rest[labelRange])

        // Parameter (das Geheimnis wird nur als Bereich gemerkt und erst unten in SecureBytes dekodiert)
        var secretRange: Range<Int>?
        var issuerParameter: String?
        var algorithm: Parameters.Algorithm?
        var digits: Int?
        var period: Int?
        if index < rest.endIndex, rest[index] == UInt8(ascii: "?") {
            let query = rest[(index + 1)...]
            let items = query.split(separator: UInt8(ascii: "&"), omittingEmptySubsequences: true)
            guard items.count <= maximumParameters else { throw .totpInvalid("totp.uri") }
            for item in items {
                guard let equals = item.firstIndex(of: UInt8(ascii: "=")) else { throw .totpInvalid("totp.uri") }
                let name = try percentDecode(item[item.startIndex..<equals]).map(lowerASCII)
                let value = item[(equals + 1)...]
                switch name {
                case Array("secret".utf8):
                    guard secretRange == nil else { throw .totpInvalid("totp.duplicate") }
                    secretRange = value.startIndex..<value.endIndex
                case Array("issuer".utf8):
                    guard issuerParameter == nil else { throw .totpInvalid("totp.duplicate") }
                    issuerParameter = try decodeText(value)
                case Array("algorithm".utf8):
                    guard algorithm == nil else { throw .totpInvalid("totp.duplicate") }
                    switch try decodeText(value).uppercased() {
                    case "SHA1": algorithm = .sha1
                    case "SHA256": algorithm = .sha256
                    case "SHA512": algorithm = .sha512
                    default: throw .totpInvalid("totp.algorithm")
                    }
                case Array("digits".utf8):
                    guard digits == nil else { throw .totpInvalid("totp.duplicate") }
                    digits = try smallNumber(try percentDecode(value), code: "totp.digits")
                case Array("period".utf8):
                    guard period == nil else { throw .totpInvalid("totp.duplicate") }
                    period = try smallNumber(try percentDecode(value), code: "totp.period")
                default:
                    continue        // image, color, lock … werden ignoriert
                }
            }
        }

        guard let secretRange, !secretRange.isEmpty else { throw .totpInvalid("totp.secret.missing") }
        let key = try decodePercentEncodedBase32(rest[secretRange])

        // Label: "Aussteller:Konto" oder nur "Konto" (Leerzeichen um das Konto sind erlaubt).
        var issuer = issuerParameter ?? ""
        var account = label
        if let colon = label.firstIndex(of: ":") {
            let labelIssuer = String(label[label.startIndex..<colon])
            account = String(label[label.index(after: colon)...])
            if issuerParameter == nil { issuer = labelIssuer }
        }
        account = account.trimmingCharacters(in: .whitespaces)
        issuer = issuer.trimmingCharacters(in: .whitespaces)

        return try Parameters(key: key, algorithm: algorithm ?? .sha1, digits: digits ?? 6, period: period ?? 30,
                              issuer: issuer, account: account)
    }

    /// Prozent-kodiertes Base32: zuerst in eine genullte Rechenfläche dekodieren, dann Base32.
    private static func decodePercentEncodedBase32(_ raw: ArraySlice<UInt8>) throws(SiegelError) -> SecureBytes {
        do {
            let scratch = try SecureBytes.scratch(count: raw.count)
            let length = try scratch.withUnsafeMutableBytes { out -> Int in
                var written = 0
                try percentDecode(raw) { out[written] = $0; written += 1 }
                return written
            }
            return try scratch.withUnsafeBytes { try decodeBase32($0[0..<length]) }
        } catch let error as SiegelError {
            throw error
        } catch {
            throw .crypto("memory.alloc")
        }
    }

    /// Dezimalzahl aus 1–3 ASCII-Ziffern.
    private static func smallNumber(_ bytes: [UInt8], code: String) throws(SiegelError) -> Int {
        guard (1...3).contains(bytes.count), bytes.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else {
            throw .totpInvalid(code)
        }
        return bytes.reduce(0) { $0 * 10 + Int($1 - 0x30) }
    }

    /// Prozent-dekodiert und als UTF-8 gelesen (Label, Aussteller, Algorithmus).
    private static func decodeText(_ bytes: ArraySlice<UInt8>) throws(SiegelError) -> String {
        let decoded = try percentDecode(bytes)
        guard let text = String(validating: decoded, as: UTF8.self) else { throw .totpInvalid("totp.uri") }
        return text
    }

    /// `%XX` → Byte. `+` bleibt `+` (otpauth kodiert Leerzeichen als `%20`).
    static func percentDecode(_ bytes: ArraySlice<UInt8>) throws(SiegelError) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        try percentDecode(bytes) { out.append($0) }
        return out
    }

    private static func percentDecode(_ bytes: ArraySlice<UInt8>, _ emit: (UInt8) -> Void) throws(SiegelError) {
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let byte = bytes[index]
            if byte == UInt8(ascii: "%") {
                guard index + 2 < bytes.endIndex, let high = hexValue(bytes[index + 1]),
                      let low = hexValue(bytes[index + 2]) else {
                    throw .totpInvalid("totp.uri")
                }
                emit(high << 4 | low)
                index += 3
            } else {
                emit(byte)
                index += 1
            }
        }
    }

    /// RFC 4648 Base32, tolerant (Leerraum, Kleinbuchstaben, fehlendes Padding). Ergebnis in `SecureBytes`.
    static func decodeBase32<C: Collection<UInt8>>(_ input: C) throws(SiegelError) -> SecureBytes {
        var values: [UInt8] = []
        values.reserveCapacity(input.count)
        defer { wipe(&values) }
        var padding = 0
        for byte in input {
            if isWhitespace(byte) { continue }
            if byte == UInt8(ascii: "=") {
                padding += 1
                continue
            }
            guard padding == 0 else { throw .totpInvalid("totp.base32") }   // Zeichen nach dem Padding
            let upper = (byte >= 0x61 && byte <= 0x7A) ? byte - 0x20 : byte
            switch upper {
            case 0x41...0x5A: values.append(upper - 0x41)          // A–Z → 0–25
            case 0x32...0x37: values.append(upper - 0x32 + 26)     // 2–7 → 26–31
            default: throw .totpInvalid("totp.base32")
            }
        }
        // Gültige Restlängen eines Achterblocks und das dazu passende Padding
        let expectedPadding: Int
        switch values.count % 8 {
        case 0: expectedPadding = 0
        case 2: expectedPadding = 6
        case 4: expectedPadding = 4
        case 5: expectedPadding = 3
        case 7: expectedPadding = 1
        default: throw .totpInvalid("totp.base32")
        }
        guard padding == 0 || padding == expectedPadding else { throw .totpInvalid("totp.base32") }
        let byteCount = values.count * 5 / 8
        guard byteCount >= minimumSecretBytes, byteCount <= maximumSecretBytes else {
            throw .totpInvalid("totp.secret.length")
        }
        do {
            return try SecureBytes(count: byteCount) { out in
                var buffer: UInt64 = 0
                var bits = 0
                var written = 0
                for value in values {
                    buffer = (buffer << 5) | UInt64(value)
                    bits += 5
                    if bits >= 8, written < byteCount {
                        bits -= 8
                        out[written] = UInt8(truncatingIfNeeded: buffer >> UInt64(bits))
                        written += 1
                    }
                }
                buffer = 0
            }
        } catch {
            throw .crypto("memory.alloc")
        }
    }

    // MARK: - Hilfen

    private static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private static func lowerASCII(_ byte: UInt8) -> UInt8 {
        (byte >= 0x41 && byte <= 0x5A) ? byte + 0x20 : byte
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x41...0x46: byte - 0x41 + 10
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }

    private static func containsSubsequence(_ haystack: ArraySlice<UInt8>, _ needle: [UInt8]) -> Bool {
        guard needle.count <= haystack.count else { return false }
        var index = haystack.startIndex
        while index + needle.count <= haystack.endIndex {
            if haystack[index..<(index + needle.count)].elementsEqual(needle) { return true }
            index += 1
        }
        return false
    }

    /// Best effort: Arbeitspuffer nullen.
    static func wipe(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
        bytes.removeAll()
    }
}

// MARK: - Geschwärzte Beschreibung (SPEC §5)

extension TOTP.Parameters: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "TOTP.Parameters(\(algorithm.uriName), \(digits), \(period)s, redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["algorithm": algorithm, "digits": digits, "period": period], displayStyle: .struct)
    }
}
