import Clibsodium
import Foundation

/// KeePass-Export im Format KDBX 4.1 (SPEC §19), lesbar mit KeePassXC, KeePass 2 und `referenz/siegel_referenz.py`.
///
/// Aufbau der Datei (alle Zahlen Little-Endian):
/// 1. **Äusserer Kopf**: Signaturen `0x9AA2D903`, `0xB54BFB67`, Version 4.1 (`0x00040001`), dann Felder
///    `id (1 B) ‖ Länge (4 B) ‖ Daten`: CipherID (2) = ChaCha20 `D6038A2B-8B6F-4CB5-A524-339A31DBB59A`,
///    CompressionFlags (3) = 0 (keine Kompression), MasterSeed (4, 32 B), EncryptionIV (7, 12 B),
///    KdfParameters (11, VariantDictionary: `$UUID` = Argon2id `9E298B19-56DB-4773-B23D-FC3EC6F0A1E6`,
///    `S` Salz 16 B, `P` = 1, `M` = 256 MiB, `I` = 3, `V` = 0x13), EndOfHeader (0, `\r\n\r\n`).
/// 2. `SHA-256(Kopf)` und `HMAC-SHA-256(Kopf)` mit dem Block-Schlüssel für Index 2^64−1.
/// 3. **HMAC-Blockstrom**: Blöcke `HMAC (32 B) ‖ Länge (4 B) ‖ Daten` zu höchstens 1 MiB, zum Schluss ein leerer
///    Block. `HMAC = HMAC-SHA-256(SHA-512(Index ‖ HMAC-Basis), Index ‖ Länge ‖ Daten)`.
/// 4. Der Strom ist mit ChaCha20 (RFC 7539, Zähler ab 0, libsodium `crypto_stream_chacha20_ietf_xor`)
///    verschlüsselt und enthält den **inneren Kopf** (InnerRandomStreamID (1) = 3 ChaCha20,
///    InnerRandomStreamKey (2, 64 B), Ende (0)) und danach das **KeePass-XML** (UTF-8, ohne BOM).
///
/// Schlüssel: `Zusammengesetzt = SHA-256(SHA-256(Passwort-UTF-8))` (nur Passwort, wie KeePass: die Bytes werden
/// unverändert genommen, ohne die Siegel-Abbildung aus §1.1, damit dieselben Tasten in KeePass dieselben Bytes
/// ergeben); `Transformiert = Argon2id(Zusammengesetzt, S, t = 3, m = 256 MiB, p = 1)` über libsodium
/// `crypto_pwhash`; `Inhaltsschlüssel = SHA-256(MasterSeed ‖ Transformiert)`;
/// `HMAC-Basis = SHA-512(MasterSeed ‖ Transformiert ‖ 0x01)`.
///
/// Libsodium kennt nur 16 Byte Salz (KeePass erzeugt 32). KeePass 2 erlaubt ab 8 Byte, KeePassXC 8–32 Byte
/// (`KDF_MIN_SEED_SIZE`/`KDF_MAX_SEED_SIZE` in `src/crypto/kdf/Kdf.h`, nachgesehen am 17.10.2026).
///
/// XML: Gruppe „Siegel“ mit je einem Eintrag `Title`, `UserName`, `Password`, `URL`, `Notes` und – falls vorhanden –
/// `otp` (otpauth-URI wie bei KeePassXC; ein reines Base32-Geheimnis wird zu `otpauth://totp/<Titel>?secret=…`
/// ergänzt), dazu `Times` (Erstellt/Geändert als Base64 eines Int64 Sekunden seit 0001-01-01). `Password` und `otp`
/// sind geschützt (`Protected="True"`: XOR mit dem inneren ChaCha20-Strom, Schlüssel und Nonce aus
/// `SHA-512(InnerRandomStreamKey)[0..<32]` bzw. `[32..<44]`, fortlaufend in Dokumentreihenfolge, dann Base64).
/// Andere Werte mit Zeichen, die XML 1.0 verbietet (U+0000–0008, 000B, 000C, 000E–001F, FFFE, FFFF), werden
/// ebenfalls geschützt geschrieben, damit sie byte-genau ankommen, ebenso Werte nur aus Leerraum (KeePass liest XML
/// mit `IgnoreWhitespace`); ein Wagenrücklauf wird als `&#13;` geschrieben (XML-Parser machen sonst aus CR LF ein LF).
///
/// Nicht exportiert: gelöschte Einträge, Einträge mit Schutz 4/5 (`EntryProtection.exportAllowed`, §16), der
/// Passwort-Verlauf (wie beim CSV-Export). Geheimteile kommen aus `EntrySecrets`; bei nicht versiegelten Einträgen
/// füllt der Eintrag selbst leere Felder. Das Export-Passwort muss die Master-Passwort-Regel erfüllen
/// (`passwordTooWeak`). Klartext entsteht nur in `SecureBytes`; die Ausgabe ist verschlüsselt.
public enum KeePassExport {
    /// Argon2id-Parameter des Exports (SPEC §19: p = 1, m = 256 MiB, t = 3).
    struct KDF: Equatable, Sendable {
        let opsLimit: UInt64
        let memLimitBytes: UInt64
        static let export = KDF(opsLimit: 3, memLimitBytes: 256 << 20)
    }

    public static func kdbx(_ items: [(VaultEntry, EntrySecrets)], password: String) throws -> Data {
        try build(items, password: password, kdf: .export, now: Date())
    }

    #if DEBUG
    /// Testschalter (nur DEBUG, nur `@testable`): kleinere Argon2-Parameter für schnelle Tests.
    static func kdbx(_ items: [(VaultEntry, EntrySecrets)], password: String, kdf: KDF, now: Date = Date()) throws -> Data {
        try build(items, password: password, kdf: kdf, now: now)
    }
    #endif

    // MARK: - Konstanten

    static let signature1: UInt32 = 0x9AA2_D903
    static let signature2: UInt32 = 0xB54B_FB67
    static let version: UInt32 = 0x0004_0001              // 4.1
    static let cipherChaCha20: [UInt8] = [0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5,
                                          0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A]
    static let kdfArgon2id: [UInt8] = [0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73,
                                       0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6]
    static let innerStreamChaCha20: UInt32 = 3
    static let blockSize = 1 << 20
    /// Sekunden von 0001-01-01T00:00:00Z bis 1970-01-01T00:00:00Z.
    static let secondsTo1970: Int64 = 62_135_596_800

    enum HeaderField: UInt8 {
        case end = 0, cipherID = 2, compressionFlags = 3, masterSeed = 4, encryptionIV = 7, kdfParameters = 11
    }

    enum InnerField: UInt8 {
        case end = 0, randomStreamID = 1, randomStreamKey = 2
    }

    // MARK: - Aufbau

    private static func build(_ items: [(VaultEntry, EntrySecrets)], password: String, kdf: KDF,
                              now: Date) throws -> Data {
        dispatchPrecondition(condition: .notOnQueue(.main))
        _ = Sodium.ready
        let policy = MasterPasswordPolicy.check(password)
        guard policy.ok else { throw SiegelError.passwordTooWeak(bits: policy.bits) }

        let masterSeed = randomBytes(32)
        let encryptionIV = randomBytes(12)
        let kdfSalt = randomBytes(crypto_pwhash_argon2id_saltbytes())
        let innerKey = try SecureBytes.random(count: 64)

        // Schlüssel
        let composite = try passwordCompositeKey(password)
        let transformed = try argon2id(composite, salt: kdfSalt, kdf: kdf)
        let encryptionKey = try Hash.sha256([.public(masterSeed), .secret(transformed)])
        let hmacBase = try Hash.sha512([.public(masterSeed), .secret(transformed), .public([0x01])])

        // Äusserer Kopf
        var header: [UInt8] = []
        header += le(signature1)
        header += le(signature2)
        header += le(version)
        header += field(HeaderField.cipherID.rawValue, cipherChaCha20)
        header += field(HeaderField.compressionFlags.rawValue, le(UInt32(0)))
        header += field(HeaderField.masterSeed.rawValue, masterSeed)
        header += field(HeaderField.encryptionIV.rawValue, encryptionIV)
        header += field(HeaderField.kdfParameters.rawValue, kdfParameters(salt: kdfSalt, kdf: kdf))
        header += field(HeaderField.end.rawValue, [0x0D, 0x0A, 0x0D, 0x0A])

        var output: [UInt8] = header
        output += try Hash.sha256([.public(header)]).withUnsafeBytes { Array($0) }
        output += try hmac(blockIndex: UInt64.max, hmacBase: hmacBase, message: header)

        // Klartext (innerer Kopf + XML) direkt in einen SecureBytes-Puffer passender Grösse schreiben, dann in
        // diesem Puffer verschlüsseln: zwei Durchgänge (zählen, schreiben), damit nie eine Klartext-Kopie in
        // gewachsenem und wieder freigegebenem Speicher liegen bleibt.
        let entries = items.filter { $0.0.deletedAt == nil && $0.0.protection.exportAllowed }
        let groupID = randomBytes(16)
        var counter = ByteSink(buffer: nil)
        var countingStream = try InnerStream(key: innerKey, writing: false)
        writePayload(into: &counter, innerKey: innerKey, entries: entries, groupID: groupID, now: now,
                     stream: &countingStream)
        let payloadLength = counter.count

        let payload = try SecureBytes.scratch(count: payloadLength)
        try payload.withUnsafeMutableBytes { buffer in
            var sink = ByteSink(buffer: buffer)
            var stream = try InnerStream(key: innerKey, writing: true)
            writePayload(into: &sink, innerKey: innerKey, entries: entries, groupID: groupID, now: now, stream: &stream)
            guard sink.count == payloadLength else { throw SiegelError.crypto("kdbx.length") }
            // Äussere Verschlüsselung ChaCha20 (Zähler 0), an Ort und Stelle
            let rc = encryptionKey.withUnsafeBytes { key -> Int32 in
                encryptionIV.withUnsafeBytes { iv -> Int32 in
                    guard let data = buffer.u8, let n = iv.u8, let k = key.u8 else { return -1 }
                    return crypto_stream_chacha20_ietf_xor(data, data, UInt64(buffer.count), n, k)
                }
            }
            guard rc == 0 else { throw SiegelError.crypto("kdbx.encrypt") }
        }

        // HMAC-Blockstrom über den Geheimtext
        try payload.withUnsafeBytes { cipher in
            var index: UInt64 = 0
            var offset = 0
            repeat {
                let length = min(blockSize, cipher.count - offset)
                let block = Array(cipher[offset..<(offset + length)])
                var message: [UInt8] = []
                message.reserveCapacity(12 + length)
                message += le(index)
                message += le(UInt32(length))
                message += block
                output += try hmac(blockIndex: index, hmacBase: hmacBase, message: message)
                output += le(UInt32(length))
                output += block
                offset += length
                index += 1
            } while offset < cipher.count
            // Abschluss: leerer Block
            var final: [UInt8] = []
            final += le(index)
            final += le(UInt32(0))
            output += try hmac(blockIndex: index, hmacBase: hmacBase, message: final)
            output += le(UInt32(0))
        }
        return Data(output)
    }

    /// VariantDictionary (Version 0x0100) mit den Argon2id-Parametern.
    static func kdfParameters(salt: [UInt8], kdf: KDF) -> [UInt8] {
        var d: [UInt8] = [0x00, 0x01]
        func item(_ type: UInt8, _ key: String, _ value: [UInt8]) {
            d.append(type)
            d += le(UInt32(key.utf8.count))
            d += Array(key.utf8)
            d += le(UInt32(value.count))
            d += value
        }
        item(0x42, "$UUID", kdfArgon2id)
        item(0x42, "S", salt)
        item(0x04, "P", le(UInt32(1)))
        item(0x05, "M", le(kdf.memLimitBytes))
        item(0x05, "I", le(kdf.opsLimit))
        item(0x04, "V", le(UInt32(0x13)))
        d.append(0x00)
        return d
    }

    // MARK: - Schlüssel

    /// SHA-256(SHA-256(UTF-8 des Passworts)), Passwort-Bytes nur in SecureBytes.
    private static func passwordCompositeKey(_ password: String) throws -> SecureBytes {
        var copy = password
        let bytes = try copy.withUTF8 { try SecureBytes(copying: UnsafeRawBufferPointer($0)) }
        let first = try Hash.sha256([.secret(bytes)])
        return try Hash.sha256([.secret(first)])
    }

    private static func argon2id(_ composite: SecureBytes, salt: [UInt8], kdf: KDF) throws -> SecureBytes {
        guard salt.count == crypto_pwhash_argon2id_saltbytes() else { throw SiegelError.crypto("kdbx.salt") }
        return try SecureBytes(count: 32) { out in
            let rc: Int32 = composite.withUnsafeBytes { pw in
                salt.withUnsafeBytes { s in
                    guard let o = out.u8, let sp = s.u8, let pp = pw.baseAddress else { return -1 }
                    return crypto_pwhash(o, 32, pp.assumingMemoryBound(to: CChar.self), UInt64(pw.count), sp,
                                         kdf.opsLimit, Int(kdf.memLimitBytes), crypto_pwhash_alg_argon2id13())
                }
            }
            guard rc == 0 else { throw SiegelError.kdfFailed }
        }
    }

    /// HMAC-SHA-256 mit dem Block-Schlüssel `SHA-512(Index ‖ HMAC-Basis)`.
    private static func hmac(blockIndex: UInt64, hmacBase: SecureBytes, message: [UInt8]) throws -> [UInt8] {
        let blockKey = try Hash.sha512([.public(le(blockIndex)), .secret(hmacBase)])
        var state = crypto_auth_hmacsha256_state()
        defer { withUnsafeMutableBytes(of: &state) { sodium_memzero($0.baseAddress, $0.count) } }
        var mac = [UInt8](repeating: 0, count: 32)
        let rc = blockKey.withUnsafeBytes { key -> Int32 in
            guard let k = key.u8, crypto_auth_hmacsha256_init(&state, k, key.count) == 0 else { return -1 }
            let updated = message.withUnsafeBytes { m -> Int32 in
                guard let p = m.u8, m.count > 0 else { return 0 }
                return crypto_auth_hmacsha256_update(&state, p, UInt64(m.count))
            }
            guard updated == 0 else { return -1 }
            return mac.withUnsafeMutableBytes { out -> Int32 in
                guard let o = out.u8 else { return -1 }
                return crypto_auth_hmacsha256_final(&state, o)
            }
        }
        guard rc == 0 else { throw SiegelError.crypto("kdbx.hmac") }
        return mac
    }

    // MARK: - Klartext (innerer Kopf + XML)

    private static func writePayload(into sink: inout ByteSink, innerKey: SecureBytes, entries: [(VaultEntry, EntrySecrets)],
                                     groupID: [UInt8], now: Date, stream: inout InnerStream) {
        // Innerer Kopf
        sink.append(InnerField.randomStreamID.rawValue)
        sink.append(le(UInt32(4)))
        sink.append(le(innerStreamChaCha20))
        sink.append(InnerField.randomStreamKey.rawValue)
        sink.append(le(UInt32(64)))
        innerKey.withUnsafeBytes { sink.append($0) }
        sink.append(InnerField.end.rawValue)
        sink.append(le(UInt32(0)))

        // XML
        var xml = XMLWriter(sink: sink, stream: stream)
        defer {
            sink = xml.sink
            stream = xml.stream
        }
        let time = timeText(now)
        let zeroUUID = base64([UInt8](repeating: 0, count: 16))
        xml.raw("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile>\n<Meta>\n")
        xml.element("Generator", "Siegel")
        xml.element("DatabaseName", "Siegel")
        xml.element("DatabaseNameChanged", time)
        xml.element("DatabaseDescription", "Export aus Siegel")
        xml.element("DatabaseDescriptionChanged", time)
        xml.element("DefaultUserName", "")
        xml.element("DefaultUserNameChanged", time)
        xml.element("MaintenanceHistoryDays", "365")
        xml.element("Color", "")
        xml.element("MasterKeyChanged", time)
        xml.element("MasterKeyChangeRec", "-1")
        xml.element("MasterKeyChangeForce", "-1")
        xml.raw("<MemoryProtection>\n")
        xml.element("ProtectTitle", "False")
        xml.element("ProtectUserName", "False")
        xml.element("ProtectPassword", "True")
        xml.element("ProtectURL", "False")
        xml.element("ProtectNotes", "False")
        xml.raw("</MemoryProtection>\n")
        xml.element("RecycleBinEnabled", "False")
        xml.element("RecycleBinUUID", zeroUUID)
        xml.element("RecycleBinChanged", time)
        xml.element("EntryTemplatesGroup", zeroUUID)
        xml.element("EntryTemplatesGroupChanged", time)
        xml.element("HistoryMaxItems", "10")
        xml.element("HistoryMaxSize", "6291456")
        xml.element("LastSelectedGroup", zeroUUID)
        xml.element("LastTopVisibleGroup", zeroUUID)
        xml.element("SettingsChanged", time)
        xml.raw("<CustomData/>\n</Meta>\n<Root>\n<Group>\n")
        xml.element("UUID", base64(groupID))
        xml.element("Name", "Siegel")
        xml.element("Notes", "")
        xml.element("IconID", "48")
        xml.times(created: time, modified: time)
        xml.element("IsExpanded", "True")
        xml.element("DefaultAutoTypeSequence", "")
        xml.element("EnableAutoType", "null")
        xml.element("EnableSearching", "null")
        xml.element("LastTopVisibleEntry", zeroUUID)
        for (entry, given) in entries {
            let secrets = effectiveSecrets(entry, given)
            xml.raw("<Entry>\n")
            xml.element("UUID", base64(uuidBytes(entry.id)))
            xml.element("IconID", "0")
            xml.element("ForegroundColor", "")
            xml.element("BackgroundColor", "")
            xml.element("OverrideURL", "")
            xml.element("Tags", "")
            xml.times(created: timeText(entry.created), modified: timeText(entry.modified))
            // Reihenfolge wie KeePass (ordinal sortiert); Password und otp geschützt.
            xml.string("Notes", secrets.notes, protected: false)
            xml.string("Password", secrets.password, protected: true)
            xml.string("Title", entry.title, protected: false)
            xml.string("URL", entry.url, protected: false)
            xml.string("UserName", entry.username, protected: false)
            let otp = otpValue(secrets.totp, title: entry.title)
            if !otp.isEmpty { xml.string("otp", otp, protected: true) }
            xml.raw("<AutoType>\n")
            xml.element("Enabled", "True")
            xml.element("DataTransferObfuscation", "0")
            xml.raw("</AutoType>\n<History/>\n</Entry>\n")
        }
        xml.raw("</Group>\n<DeletedObjects/>\n</Root>\n</KeePassFile>\n")
    }

    /// Geheimteile eines Eintrags: aus `EntrySecrets`; bei nicht versiegelten Einträgen ergänzt ein leeres Feld
    /// aus dem Eintrag selbst (dort stehen die Werte dann im Klartext, beide Quellen sind gleich).
    static func effectiveSecrets(_ entry: VaultEntry, _ given: EntrySecrets) -> EntrySecrets {
        guard !entry.secretsSealed else { return given }
        var result = given
        if result.password.isEmpty { result.password = entry.password }
        if result.notes.isEmpty { result.notes = entry.notes }
        if result.totp.isEmpty { result.totp = entry.totp }
        return result
    }

    /// `otp`-Feld: otpauth-URI unverändert (ohne Rand-Leerraum); reines Base32 → `otpauth://totp/<Titel>?secret=…`
    /// mit den Standardwerten; was `TOTP.parse` nicht annimmt, bleibt roh (nichts geht verloren).
    static func otpValue(_ stored: String, title: String) -> String {
        let trimmed = stored.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, (try? TOTP.parseTyped(trimmed)) != nil else { return trimmed }
        if trimmed.lowercased().hasPrefix("otpauth://") { return trimmed }
        var secret = ""
        for scalar in trimmed.unicodeScalars where scalar != "=" && !scalar.properties.isWhitespace {
            secret.unicodeScalars.append(scalar)
        }
        let label = (title.isEmpty ? "Siegel" : title)
            .addingPercentEncoding(withAllowedCharacters: otpLabelAllowed) ?? "Siegel"
        return "otpauth://totp/" + label + "?secret=" + secret.uppercased() + "&period=30&digits=6&algorithm=SHA1"
    }

    private static let otpLabelAllowed = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~@")

    /// Base64 eines Int64 (Sekunden seit 0001-01-01, Little-Endian) wie KDBX 4.
    static func timeText(_ date: Date) -> String {
        let raw = date.timeIntervalSince1970
        let seconds = raw.isFinite ? Int64(max(-6.2e10, min(floor(raw), 2.5e11))) : 0
        return base64(le(UInt64(bitPattern: max(0, seconds + secondsTo1970))))
    }

    static func uuidBytes(_ id: UUID) -> [UInt8] {
        withUnsafeBytes(of: id.uuid) { Array($0) }
    }

    static func base64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
    }

    // MARK: - Hilfstypen

    /// Zählt Bytes (Puffer nil) oder schreibt sie in einen Puffer fester Grösse.
    struct ByteSink {
        private(set) var count = 0
        let buffer: UnsafeMutableRawBufferPointer?

        init(buffer: UnsafeMutableRawBufferPointer?) {
            self.buffer = buffer
        }

        mutating func append(_ byte: UInt8) {
            if let buffer, count < buffer.count { buffer[count] = byte }
            count += 1
        }

        mutating func append(_ bytes: [UInt8]) {
            for byte in bytes { append(byte) }
        }

        mutating func append(_ bytes: UnsafeRawBufferPointer) {
            for byte in bytes { append(byte) }
        }

        mutating func append(_ text: String) {
            for byte in text.utf8 { append(byte) }
        }
    }

    /// Innerer Zufallsstrom (ChaCha20, RFC 7539): Schlüssel und Nonce aus SHA-512(InnerRandomStreamKey).
    /// Liefert Schlüsselstrom-Bytes fortlaufend in 64-Byte-Blöcken. Beim Zählen (`writing == false`) nur die Anzahl.
    struct InnerStream {
        private let keyAndNonce: SecureBytes          // SHA-512: [0..<32] Schlüssel, [32..<44] Nonce
        private let block: SecureBytes                // aktueller Schlüsselstrom-Block
        private var used = 64
        private var blockCounter: UInt32 = 0
        private let writing: Bool

        init(key: SecureBytes, writing: Bool) throws {
            keyAndNonce = try Hash.sha512([.secret(key)])
            block = try SecureBytes.scratch(count: 64)
            self.writing = writing
        }

        mutating func next() -> UInt8 {
            guard writing else { return 0 }
            if used == 64 {
                let counter = blockCounter
                keyAndNonce.withUnsafeBytes { kn in
                    block.withUnsafeMutableBytes { out in
                        sodium_memzero(out.baseAddress, out.count)
                        if let o = out.u8, let k = kn.u8 {
                            _ = crypto_stream_chacha20_ietf_xor_ic(o, o, 64, k + 32, counter, k)
                        }
                    }
                }
                blockCounter &+= 1
                used = 0
            }
            let byte = block.withUnsafeBytes { $0[used] }
            used += 1
            return byte
        }
    }

    /// Schreibt das KeePass-XML in eine `ByteSink`; geschützte Werte laufen durch den inneren Strom.
    struct XMLWriter {
        var sink: ByteSink
        var stream: InnerStream

        mutating func raw(_ text: String) { sink.append(text) }

        mutating func element(_ name: String, _ value: String) {
            if value.isEmpty {
                sink.append("<" + name + "/>\n")
            } else {
                sink.append("<" + name + ">")
                escaped(value)
                sink.append("</" + name + ">\n")
            }
        }

        mutating func times(created: String, modified: String) {
            raw("<Times>\n")
            element("CreationTime", created)
            element("LastModificationTime", modified)
            element("LastAccessTime", modified)
            element("ExpiryTime", created)
            element("Expires", "False")
            element("UsageCount", "0")
            element("LocationChanged", modified)
            raw("</Times>\n")
        }

        mutating func string(_ key: String, _ value: String, protected: Bool) {
            sink.append("<String><Key>" + key + "</Key>")
            if protected || XMLWriter.needsProtection(value) {
                sink.append("<Value Protected=\"True\">")
                protectedBase64(value)
                sink.append("</Value></String>\n")
            } else {
                sink.append("<Value>")
                escaped(value)
                sink.append("</Value></String>\n")
            }
        }

        /// Zeichen, die XML 1.0 nicht erlaubt (auch nicht als Zeichenreferenz), oder ein Wert nur aus Leerraum
        /// (KeePass liest XML mit `IgnoreWhitespace` und machte daraus einen leeren Wert).
        static func needsProtection(_ value: String) -> Bool {
            if !value.isEmpty, value.utf8.allSatisfy({ $0 == 0x20 || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D }) {
                return true
            }
            return value.unicodeScalars.contains { scalar in
                switch scalar.value {
                case 0x09, 0x0A, 0x0D: false
                case 0x00...0x1F, 0xFFFE, 0xFFFF: true
                default: false
                }
            }
        }

        private mutating func escaped(_ value: String) {
            for byte in value.utf8 {
                switch byte {
                case UInt8(ascii: "&"): sink.append("&amp;")
                case UInt8(ascii: "<"): sink.append("&lt;")
                case UInt8(ascii: ">"): sink.append("&gt;")
                case 0x0D: sink.append("&#13;")
                default: sink.append(byte)
                }
            }
        }

        /// UTF-8 ⊕ Schlüsselstrom, Base64, ohne Zwischenkopie des Klartexts.
        private mutating func protectedBase64(_ value: String) {
            let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
            var group: UInt32 = 0
            var filled = 0
            for byte in value.utf8 {
                group = (group << 8) | UInt32(byte ^ stream.next())
                filled += 1
                if filled == 3 {
                    for shift in [18, 12, 6, 0] { sink.append(alphabet[Int((group >> UInt32(shift)) & 0x3F)]) }
                    group = 0
                    filled = 0
                }
            }
            if filled == 1 {
                group <<= 16
                sink.append(alphabet[Int((group >> 18) & 0x3F)])
                sink.append(alphabet[Int((group >> 12) & 0x3F)])
                sink.append([UInt8(ascii: "="), UInt8(ascii: "=")])
            } else if filled == 2 {
                group <<= 8
                sink.append(alphabet[Int((group >> 18) & 0x3F)])
                sink.append(alphabet[Int((group >> 12) & 0x3F)])
                sink.append(alphabet[Int((group >> 6) & 0x3F)])
                sink.append(UInt8(ascii: "="))
            }
            group = 0
        }
    }

    /// SHA-256/SHA-512 über libsodium; Eingaben öffentlich ([UInt8]) oder geheim (SecureBytes), Ausgabe in SecureBytes.
    enum Hash {
        enum Part {
            case `public`([UInt8])
            case secret(SecureBytes)

            func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
                switch self {
                case .public(let bytes): try bytes.withUnsafeBytes(body)
                case .secret(let secure): try secure.withUnsafeBytes(body)
                }
            }
        }

        static func sha256(_ parts: [Part]) throws -> SecureBytes {
            var state = crypto_hash_sha256_state()
            defer { withUnsafeMutableBytes(of: &state) { sodium_memzero($0.baseAddress, $0.count) } }
            _ = crypto_hash_sha256_init(&state)
            for part in parts {
                part.withBytes { b in if let p = b.u8, b.count > 0 { _ = crypto_hash_sha256_update(&state, p, UInt64(b.count)) } }
            }
            return try SecureBytes(count: 32) { out in
                guard let o = out.u8, crypto_hash_sha256_final(&state, o) == 0 else { throw SiegelError.crypto("kdbx.hash") }
            }
        }

        static func sha512(_ parts: [Part]) throws -> SecureBytes {
            var state = crypto_hash_sha512_state()
            defer { withUnsafeMutableBytes(of: &state) { sodium_memzero($0.baseAddress, $0.count) } }
            _ = crypto_hash_sha512_init(&state)
            for part in parts {
                part.withBytes { b in if let p = b.u8, b.count > 0 { _ = crypto_hash_sha512_update(&state, p, UInt64(b.count)) } }
            }
            return try SecureBytes(count: 64) { out in
                guard let o = out.u8, crypto_hash_sha512_final(&state, o) == 0 else { throw SiegelError.crypto("kdbx.hash") }
            }
        }
    }

    // MARK: - Little-Endian

    static func le<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
        withUnsafeBytes(of: value.littleEndian) { Array($0) }
    }

    /// KDBX-4-Kopffeld: id (1 B) ‖ Länge (4 B) ‖ Daten.
    static func field(_ id: UInt8, _ data: [UInt8]) -> [UInt8] {
        [id] + le(UInt32(data.count)) + data
    }
}
