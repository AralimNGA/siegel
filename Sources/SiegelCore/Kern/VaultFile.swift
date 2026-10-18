import CryptoKit
import Foundation

// Dateiformat `.siegel` (SPEC §2, §13.2): Little-Endian, strenger Parser.
//   KOPF (v1: 1653 B; v2: 1709 B + Länge der FIDO-Credential-ID) ‖ SLOTS (1744) ‖
//   INHALT (generation u64 ‖ nonce 24 ‖ ctLen u32 ‖ ct‖tag) ‖ PRÜFSUMME (32)
// Die Prüfsumme (letzte 32 Byte = SHA3-256("Siegel v<n> file check" ‖ alles davor)) wird vor allem anderen
// geprüft. Das Label hängt an der Version in Byte 6–7; künftige Versionen behalten dieses Muster, damit eine
// neuere Datei als `unsupportedVersion` erkannt wird und ein gekipptes Versionsbyte als `corruptFile`.

enum FileFormat {
    static let magic = Array("SIEGEL".utf8)
    /// Geschrieben wird immer die neueste Version; gelesen werden 1 und 2.
    static let currentVersion: UInt16 = 2
    static let kdfAlgArgon2id13: UInt8 = 1
    static let checksumBytes = 32
    static let minCiphertext = 16_400
    static let maxCiphertext = 64 << 20
    static let payloadPrefixBytes = 8 + 24 + 4
    static let minFileBytes = VaultHeader.v1Size + VaultSlots.size + payloadPrefixBytes + minCiphertext + checksumBytes
    static let maxFileBytes = VaultHeader.maxSize + VaultSlots.size + payloadPrefixBytes + maxCiphertext + checksumBytes

    /// Labels einer Formatversion (SPEC §13.2). Die Labels des Notfallcodes (Prüfsumme, Kit-Kennung, HKDF für R)
    /// gehören zum gedruckten Kit und bleiben in allen Versionen "Siegel v1 …" (siehe RecoveryCodeCodec).
    struct Labels: Equatable, Sendable {
        let pwSlot: [UInt8]
        let recSlot: [UInt8]
        let payload: [UInt8]
        let hybridKEM: [UInt8]

        init(version: UInt16) {
            let v = "Siegel v" + String(version) + " "
            pwSlot = Array((v + "slot pw").utf8)
            recSlot = Array((v + "slot rec").utf8)
            payload = Array((v + "payload").utf8)
            hybridKEM = Array((v + "hybrid KEM").utf8)
        }
    }

    static func checksumLabel(version: UInt16) -> [UInt8] {
        Array(("Siegel v" + String(version) + " file check").utf8)
    }

    /// Version laut Byte 6–7 (ungeprüft; nur für die Wahl des Prüfsummen-Labels).
    static func statedVersion(_ bytes: ArraySlice<UInt8>) -> UInt16 {
        let s = bytes.startIndex
        guard bytes.count >= 8 else { return 0 }
        return UInt16(bytes[s + 6]) | (UInt16(bytes[s + 7]) << 8)
    }

    static func fileChecksum(_ body: ArraySlice<UInt8>, version: UInt16) -> [UInt8] {
        var h = SHA3_256()
        h.update(data: checksumLabel(version: version))
        body.withUnsafeBytes { h.update(bufferPointer: $0) }
        return Array(h.finalize())
    }

    /// Prüfsumme mit dem Label der Version, die im Kopf steht.
    static func fileChecksum(_ body: ArraySlice<UInt8>) -> [UInt8] {
        fileChecksum(body, version: statedVersion(body))
    }
}

// MARK: - Little-Endian-Helfer

extension Array where Element == UInt8 {
    mutating func appendLE<T: FixedWidthInteger>(_ v: T) {
        Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) }
    }
}

struct ByteReader {
    let bytes: [UInt8]
    private(set) var offset: Int
    let end: Int

    init(_ bytes: [UInt8], from: Int = 0, to: Int? = nil) {
        self.bytes = bytes
        self.offset = from
        self.end = to ?? bytes.count
    }

    var remaining: Int { end - offset }

    mutating func take(_ n: Int, code: String) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw SiegelError.corruptFile(code) }
        defer { offset += n }
        return Array(bytes[offset..<(offset + n)])
    }

    mutating func readLE<T: FixedWidthInteger>(_: T.Type, code: String) throws -> T {
        let size = MemoryLayout<T>.size
        guard remaining >= size else { throw SiegelError.corruptFile(code) }
        var v: T = 0
        for i in 0..<size { v |= T(bytes[offset + i]) << T(8 * i) }
        offset += size
        return v
    }
}

// MARK: - Faktor-Felder des Kopfes (v2)

/// Nicht geheime Faktor-Angaben im KOPF v2 (SPEC §13.2). Ein Feld ist genau dann gesetzt, wenn das Bit der Maske
/// gesetzt ist; ungesetzte Felder werden als Nullbytes geschrieben.
struct HeaderFactorFields: Equatable, Sendable {
    var seKeyID: UUID?
    var cardTag: [UInt8]?
    var fidoCredentialID: [UInt8]?
    var fidoSalt: [UInt8]?

    static let none = HeaderFactorFields(seKeyID: nil, cardTag: nil, fidoCredentialID: nil, fidoSalt: nil)

    var mask: FactorSet {
        var m: FactorSet = []
        if seKeyID != nil { m.insert(.secureEnclave) }
        if cardTag != nil { m.insert(.card) }
        if fidoCredentialID != nil { m.insert(.securityKey) }
        return m
    }

    /// Längen und Konsistenz; Verstoss → `code` (beim Lesen `corruptFile`, beim Schreiben `crypto`).
    func validate(_ fail: (String) -> SiegelError) throws {
        if let id = seKeyID, VaultHeader.bytes(of: id).allSatisfy({ $0 == 0 }) { throw fail("header.seKeyID") }
        if let t = cardTag, t.count != VaultHeader.cardTagBytes { throw fail("header.cardTag") }
        switch (fidoCredentialID, fidoSalt) {
        case (nil, nil):
            break
        case let (cred?, salt?):
            guard cred.count >= VaultHeader.minFidoCredential, cred.count <= VaultHeader.maxFidoCredential else {
                throw fail("header.fidoCredential")
            }
            guard salt.count == VaultHeader.fidoSaltBytes, !salt.allSatisfy({ $0 == 0 }) else {
                throw fail("header.fidoSalt")
            }
        default:
            throw fail("header.fidoSalt")
        }
    }
}

// MARK: - KOPF

struct VaultHeader: Equatable, Sendable {
    static let v1Size = 1653
    /// v2 ohne Credential-ID: 6+2+16+1+4+8+16+1+1+16+4+2+32+1568+32
    static let v2FixedSize = 1709
    static let seKeyIDBytes = 16
    static let cardTagBytes = 4
    static let fidoSaltBytes = 32
    static let minFidoCredential = 16
    static let maxFidoCredential = 1024
    static let maxSize = v2FixedSize + maxFidoCredential
    /// Bit 0 = Secure Enclave, Bit 1 = Karte, Bit 2 = FIDO2.
    static let knownMaskBits: UInt8 = 0x07

    let formatVersion: UInt16
    let vaultID: [UInt8]
    let kdf: KDFParameters
    let salt: [UInt8]
    /// v1: immer leer.
    let factorFields: HeaderFactorFields
    /// v1: immer `.single`.
    let recoveryScheme: RecoveryScheme
    let pk: RecoveryPublicKeys
    /// Serialisierte Bytes (Teil der AD).
    let bytes: [UInt8]

    var uuid: UUID { VaultHeader.uuid(vaultID) }
    var factors: FactorSet { factorFields.mask }
    var labels: FileFormat.Labels { FileFormat.Labels(version: formatVersion) }

    /// Kopf v1 (nur noch zum Lesen alter Dateien und für Tests).
    init(v1 vaultID: [UInt8], kdf: KDFParameters, salt: [UInt8], pk: RecoveryPublicKeys) {
        precondition(vaultID.count == 16 && salt.count == KDF.saltBytes, "header.fields")
        precondition(pk.pkM.count == RecoveryPublicKeys.pkMBytes && pk.pkX.count == RecoveryPublicKeys.pkXBytes,
                     "header.pk")
        self.formatVersion = 1
        self.vaultID = vaultID
        self.kdf = kdf
        self.salt = salt
        self.factorFields = .none
        self.recoveryScheme = .single
        self.pk = pk
        var b = [UInt8]()
        b.reserveCapacity(VaultHeader.v1Size)
        b.append(contentsOf: FileFormat.magic)
        b.appendLE(UInt16(1))
        b.append(contentsOf: vaultID)
        b.append(FileFormat.kdfAlgArgon2id13)
        b.appendLE(kdf.opsLimit)
        b.appendLE(kdf.memLimitBytes)
        b.append(contentsOf: salt)
        b.append(contentsOf: pk.pkM)
        b.append(contentsOf: pk.pkX)
        self.bytes = b
    }

    /// Kopf v2. Faktor-Felder werden geprüft (falsche Längen → `crypto(...)`).
    init(vaultID: [UInt8], kdf: KDFParameters, salt: [UInt8], factors fields: HeaderFactorFields,
         recoveryScheme: RecoveryScheme, pk: RecoveryPublicKeys) throws {
        try fields.validate { SiegelError.crypto($0) }
        precondition(vaultID.count == 16 && salt.count == KDF.saltBytes, "header.fields")
        precondition(pk.pkM.count == RecoveryPublicKeys.pkMBytes && pk.pkX.count == RecoveryPublicKeys.pkXBytes,
                     "header.pk")
        self.formatVersion = 2
        self.vaultID = vaultID
        self.kdf = kdf
        self.salt = salt
        self.factorFields = fields
        self.recoveryScheme = recoveryScheme
        self.pk = pk
        self.bytes = VaultHeader.encodeV2(vaultID: vaultID, kdf: kdf, salt: salt, fields: fields,
                                          scheme: recoveryScheme, pk: pk)
    }

    private static func encodeV2(vaultID: [UInt8], kdf: KDFParameters, salt: [UInt8], fields: HeaderFactorFields,
                                 scheme: RecoveryScheme, pk: RecoveryPublicKeys) -> [UInt8] {
        let cred = fields.fidoCredentialID ?? []
        var b = [UInt8]()
        b.reserveCapacity(v2FixedSize + cred.count)
        b.append(contentsOf: FileFormat.magic)
        b.appendLE(UInt16(2))
        b.append(contentsOf: vaultID)
        b.append(FileFormat.kdfAlgArgon2id13)
        b.appendLE(kdf.opsLimit)
        b.appendLE(kdf.memLimitBytes)
        b.append(contentsOf: salt)
        b.append(fields.mask.rawValue)
        b.append(scheme.rawValue)
        b.append(contentsOf: fields.seKeyID.map { VaultHeader.bytes(of: $0) } ?? [UInt8](repeating: 0, count: seKeyIDBytes))
        b.append(contentsOf: fields.cardTag ?? [UInt8](repeating: 0, count: cardTagBytes))
        b.appendLE(UInt16(cred.count))
        b.append(contentsOf: cred)
        b.append(contentsOf: fields.fidoSalt ?? [UInt8](repeating: 0, count: fidoSaltBytes))
        b.append(contentsOf: pk.pkM)
        b.append(contentsOf: pk.pkX)
        return b
    }

    /// Derselbe Kopf mit neuem Salz/KDF/Kit/Faktoren (immer v2).
    func rebuilt(kdf: KDFParameters? = nil, salt: [UInt8], factors: HeaderFactorFields? = nil,
                 recoveryScheme: RecoveryScheme? = nil, pk: RecoveryPublicKeys? = nil) throws -> VaultHeader {
        try VaultHeader(vaultID: vaultID, kdf: kdf ?? self.kdf, salt: salt, factors: factors ?? factorFields,
                        recoveryScheme: recoveryScheme ?? self.recoveryScheme, pk: pk ?? self.pk)
    }

    /// Liest den KOPF ab `reader` (Version 1 oder 2, streng). Rundlauf muss bytegenau sein.
    static func parse(_ reader: inout ByteReader) throws -> VaultHeader {
        let start = reader.offset
        guard reader.remaining >= v1Size else { throw SiegelError.corruptFile("header.length") }
        let magic = try reader.take(6, code: "header.length")
        guard magic == FileFormat.magic else { throw SiegelError.corruptFile("header.magic") }
        let version = try reader.readLE(UInt16.self, code: "header.length")
        guard version != 0 else { throw SiegelError.corruptFile("header.version") }
        guard version <= FileFormat.currentVersion else { throw SiegelError.unsupportedVersion(version) }
        let vaultID = try reader.take(16, code: "header.length")
        let alg = try reader.take(1, code: "header.length")[0]
        guard alg == FileFormat.kdfAlgArgon2id13 else { throw SiegelError.corruptFile("header.kdfAlg") }
        let ops = try reader.readLE(UInt32.self, code: "header.length")
        let mem = try reader.readLE(UInt64.self, code: "header.length")
        let kdf = KDFParameters(opsLimit: ops, memLimitBytes: mem)
        let salt = try reader.take(KDF.saltBytes, code: "header.length")
        let header: VaultHeader
        if version == 1 {
            let pkM = try reader.take(RecoveryPublicKeys.pkMBytes, code: "header.length")
            let pkX = try reader.take(RecoveryPublicKeys.pkXBytes, code: "header.length")
            header = VaultHeader(v1: vaultID, kdf: kdf, salt: salt, pk: RecoveryPublicKeys(pkM: pkM, pkX: pkX))
        } else {
            let mask = try reader.take(1, code: "header.length")[0]
            guard mask & ~knownMaskBits == 0 else { throw SiegelError.corruptFile("header.factorMask") }
            let schemeRaw = try reader.take(1, code: "header.length")[0]
            guard let scheme = RecoveryScheme(rawValue: schemeRaw) else {
                throw SiegelError.corruptFile("header.recoveryScheme")
            }
            let factors = FactorSet(rawValue: mask)
            let seRaw = try reader.take(seKeyIDBytes, code: "header.length")
            let tag = try reader.take(cardTagBytes, code: "header.length")
            let credLen = Int(try reader.readLE(UInt16.self, code: "header.length"))
            if factors.contains(.securityKey) {
                guard credLen >= minFidoCredential, credLen <= maxFidoCredential else {
                    throw SiegelError.corruptFile("header.fidoCredential")
                }
            } else {
                guard credLen == 0 else { throw SiegelError.corruptFile("header.fidoCredential") }
            }
            let cred = try reader.take(credLen, code: "header.length")
            let fidoSalt = try reader.take(fidoSaltBytes, code: "header.length")
            let pkM = try reader.take(RecoveryPublicKeys.pkMBytes, code: "header.length")
            let pkX = try reader.take(RecoveryPublicKeys.pkXBytes, code: "header.length")
            // Konsistenz Maske ↔ Nullfelder
            func zero(_ b: [UInt8]) -> Bool { b.allSatisfy { $0 == 0 } }
            var fields = HeaderFactorFields.none
            if factors.contains(.secureEnclave) {
                fields.seKeyID = VaultHeader.uuid(seRaw)
            } else if !zero(seRaw) {
                throw SiegelError.corruptFile("header.seKeyID")
            }
            if factors.contains(.card) {
                fields.cardTag = tag
            } else if !zero(tag) {
                throw SiegelError.corruptFile("header.cardTag")
            }
            if factors.contains(.securityKey) {
                fields.fidoCredentialID = cred
                fields.fidoSalt = fidoSalt
            } else if !zero(fidoSalt) {
                throw SiegelError.corruptFile("header.fidoSalt")
            }
            try fields.validate { SiegelError.corruptFile($0) }
            do {
                header = try VaultHeader(vaultID: vaultID, kdf: kdf, salt: salt, factors: fields,
                                         recoveryScheme: scheme, pk: RecoveryPublicKeys(pkM: pkM, pkX: pkX))
            } catch {
                throw SiegelError.corruptFile("header.encoding")
            }
        }
        guard Array(reader.bytes[start..<reader.offset]) == header.bytes else {
            throw SiegelError.corruptFile("header.encoding")
        }
        return header
    }

    /// Kopf-Auskunft ohne Geheimnis (SPEC §13.3).
    var info: VaultHeaderInfo {
        VaultHeaderInfo(formatVersion: formatVersion, vaultID: uuid, factors: factors, recoveryScheme: recoveryScheme,
                        seKeyID: factorFields.seKeyID, cardTag: factorFields.cardTag.map { Data($0) },
                        fidoCredentialID: factorFields.fidoCredentialID.map { Data($0) },
                        fidoSalt: factorFields.fidoSalt.map { Data($0) }, kdf: kdf, kitID: pk.kitID)
    }

    static func uuid(_ b: [UInt8]) -> UUID {
        UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }

    static func bytes(of id: UUID) -> [UInt8] {
        withUnsafeBytes(of: id.uuid) { Array($0) }
    }
}

// MARK: - SLOTS

struct VaultSlots: Equatable, Sendable {
    static let size = 1744

    let pwSlot: [UInt8]
    let ctM: [UInt8]
    let ctX: [UInt8]
    let recSlot: [UInt8]

    var bytes: [UInt8] { pwSlot + ctM + ctX + recSlot }

    init(pwSlot: [UInt8], ctM: [UInt8], ctX: [UInt8], recSlot: [UInt8]) {
        precondition(pwSlot.count == AEAD.wrappedBytes && recSlot.count == AEAD.wrappedBytes, "slots.wrap")
        precondition(ctM.count == RecoveryKEM.ctMBytes && ctX.count == RecoveryKEM.ctXBytes, "slots.ct")
        self.pwSlot = pwSlot
        self.ctM = ctM
        self.ctX = ctX
        self.recSlot = recSlot
    }

    static func parse(_ reader: inout ByteReader) throws -> VaultSlots {
        guard reader.remaining >= size else { throw SiegelError.corruptFile("slots.length") }
        return VaultSlots(pwSlot: try reader.take(AEAD.wrappedBytes, code: "slots.length"),
                          ctM: try reader.take(RecoveryKEM.ctMBytes, code: "slots.length"),
                          ctX: try reader.take(RecoveryKEM.ctXBytes, code: "slots.length"),
                          recSlot: try reader.take(AEAD.wrappedBytes, code: "slots.length"))
    }

    /// AD = Label ‖ KOPF (Label je nach Formatversion).
    static func pwAD(_ header: VaultHeader) -> [UInt8] { header.labels.pwSlot + header.bytes }
    static func recAD(_ header: VaultHeader) -> [UInt8] { header.labels.recSlot + header.bytes }
}

// MARK: - Ganze Datei

struct VaultFile: Sendable {
    let header: VaultHeader
    let slots: VaultSlots
    let generation: UInt64
    let nonce: [UInt8]
    let ciphertext: [UInt8]

    /// AD des Inhalts: "Siegel v<n> payload" ‖ KOPF ‖ SLOTS ‖ generation
    static func payloadAD(header: VaultHeader, slots: VaultSlots, generation: UInt64) -> [UInt8] {
        var ad = header.labels.payload + header.bytes + slots.bytes
        ad.appendLE(generation)
        return ad
    }

    var payloadAD: [UInt8] { VaultFile.payloadAD(header: header, slots: slots, generation: generation) }

    /// Serialisiert inkl. Prüfsumme (Label der Kopf-Version).
    func serialize() -> [UInt8] {
        var b = header.bytes
        b.reserveCapacity(header.bytes.count + VaultSlots.size + FileFormat.payloadPrefixBytes + ciphertext.count
                          + FileFormat.checksumBytes)
        b.append(contentsOf: slots.bytes)
        b.appendLE(generation)
        b.append(contentsOf: nonce)
        b.appendLE(UInt32(ciphertext.count))
        b.append(contentsOf: ciphertext)
        b.append(contentsOf: FileFormat.fileChecksum(b[...], version: header.formatVersion))
        return b
    }

    /// Prüfsumme (vor allem anderen), dann Kopf, Slots, Inhalt. Restbytes → Fehler.
    static func parse(_ bytes: [UInt8]) throws -> VaultFile {
        try verifyChecksum(bytes)
        let bodyEnd = bytes.count - FileFormat.checksumBytes
        var r = ByteReader(bytes, from: 0, to: bodyEnd)
        let header = try VaultHeader.parse(&r)
        let slots = try VaultSlots.parse(&r)
        let generation = try r.readLE(UInt64.self, code: "payload.length")
        let nonce = try r.take(AEAD.nonceBytes, code: "payload.length")
        let ctLen = Int(try r.readLE(UInt32.self, code: "payload.length"))
        guard ctLen >= FileFormat.minCiphertext, ctLen <= FileFormat.maxCiphertext,
              (ctLen - AEAD.tagBytes) % PayloadCodec.blockSize == 0 else {
            throw SiegelError.corruptFile("payload.length")
        }
        guard r.remaining == ctLen else { throw SiegelError.corruptFile("file.length") }
        let ct = try r.take(ctLen, code: "payload.length")
        return VaultFile(header: header, slots: slots, generation: generation, nonce: nonce, ciphertext: ct)
    }

    /// Nur Länge und Prüfsumme (Bitfäule-Erkennung). Label nach der Version in Byte 6–7: ein gekipptes
    /// Versionsbyte fällt hier auf, eine echte neuere Datei (eigenes Label) besteht und meldet danach ihre Version.
    static func verifyChecksum(_ bytes: [UInt8]) throws {
        guard bytes.count >= FileFormat.checksumBytes + VaultHeader.v1Size else {
            throw SiegelError.corruptFile("file.length")
        }
        guard bytes.count <= FileFormat.maxFileBytes else { throw SiegelError.corruptFile("file.length") }
        let bodyEnd = bytes.count - FileFormat.checksumBytes
        let expected = FileFormat.fileChecksum(bytes[0..<bodyEnd])
        guard Array(bytes[bodyEnd...]) == expected else { throw SiegelError.corruptFile("file.checksum") }
    }

    /// Nur den Kopf lesen (Anfang der Datei, ohne Prüfsumme).
    static func parseHeaderOnly(_ bytes: [UInt8]) throws -> VaultHeader {
        var r = ByteReader(bytes)
        return try VaultHeader.parse(&r)
    }
}
