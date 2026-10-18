import CryptoKit
import Darwin
import Foundation

// Selbstvernichtung (SPEC §23): Einstellungen im verschlüsselten Inhalt, Vernichtungs-Passwort (Kryptografie und
// Ablage im Container) und der nicht geheime Zustand `Hardware/zustand.json`.

// MARK: - Im verschlüsselten Inhalt (massgeblich)

/// Selbstvernichtung im verschlüsselten Inhalt: Einstellungen, öffentlicher Teil von V, öffentlicher Teil des
/// Vernichtungs-Passworts. Invariante: `settings.duressEnabled ⇔ duress != nil`.
struct DestructionConfig: Sendable, Equatable {
    /// Vernichtungs-SE-Schlüssel V (§23.1): Kennung (Dateiname im Hardware-Ordner) und öffentlicher Schlüssel (x963).
    /// Ein unter Windows eingerichtetes V (Windows Hello, v4.6) hat keinen öffentlichen Teil (`publicKey` leer) und
    /// `windowsHello` = Version; auf dem Mac ist es ein anderes Gerät (nicht nutzbar, aber unverändert weiterzuschreiben).
    struct VKey: Sendable, Equatable {
        var keyID: UUID
        var publicKey: [UInt8]
        var windowsHello: Int? = nil

        var isWindowsHello: Bool { windowsHello != nil }

        var isWellFormed: Bool {
            if let v = windowsHello { return v == EntryFactorKeys.WindowsHelloKey.version && publicKey.isEmpty }
            return publicKey.count == 65 && publicKey.first == 0x04
        }
    }

    /// Vernichtungs-Passwort (§23.2 Nr. 3): Ablage-Kennung, dSalt, Prüfwert und öffentlicher Hybrid-Schlüssel aus d.
    /// Damit kapselt der Kern den DEK bei jedem Speichern neu, ohne das Passwort zu kennen.
    struct Duress: Sendable, Equatable {
        var fileID: UUID
        var salt: [UInt8]
        var check: [UInt8]
        var pk: RecoveryPublicKeys
    }

    var settings: DestructionSettings
    var vKey: VKey?
    var duress: Duress?

    /// Nichts eingerichtet (dann steht `destruction` gar nicht im Inhalt).
    var isEmpty: Bool { !settings.anyTriggerEnabled && vKey == nil && duress == nil }
}

// MARK: - Vernichtungs-Passwort: Kryptografie

/// d = Argon2id(Vernichtungs-Passwort, dSalt, gleiche Parameter wie der Kopf); daraus per HKDF ein Hybrid-Schlüsselpaar
/// (ML-KEM-1024 + X25519, wie die Karte §16.1) und ein Prüfwert. Der DEK ist an den öffentlichen Schlüssel gekapselt
/// **und an die Faktoren der Stufe gebunden** (v4.4):
///   pk     = Hybrid(HKDF(d, salt = vaultID, info = "Siegel v2 duress ML-KEM-1024 seed" / "Siegel v2 duress X25519"))
///   check  = HKDF-SHA512(d, salt = vaultID, info = "Siegel v2 duress check", 16)
///   F      = HKDF-SHA512(e ‖ c ‖ [y] (Faktor-Schlüssel wie §13.1), salt = vaultID,
///                        info = "Siegel v2 duress factors" ‖ factorMask, 32)
///   kek    = HKDF-SHA512(Kombinierer §1.3 (Label "Siegel v2 duress", Zusatzfeld fileID) ‖ F, salt = fileID,
///                        info = "Siegel v2 duress kek", 32)
///   wrap   = XChaCha20-Poly1305(kek, DEK, AD = "Siegel v2 duress" ‖ vaultID ‖ fileID ‖ dSalt)
/// Ohne Karte, Sicherheitsschlüssel und Secure Enclave liefern Container und Vernichtungs-Passwort also keinen DEK.
/// Der Prüfwert hängt nur an d: Er erkennt das Vernichtungs-Passwort auch bei falschen Faktoren oder veraltetem
/// Umschlag (dann wird trotzdem vernichtet). Wer `zustand.json` und die Datei hat, kann damit Vermutungen prüfen –
/// mit derselben Argon2-Arbeit wie beim Master-Passwort.
enum DuressCrypto {
    static let saltBytes = 16
    static let checkBytes = 16
    static let label = Array("Siegel v2 duress".utf8)
    static let seedInfo = Array("Siegel v2 duress ML-KEM-1024 seed".utf8)
    static let x25519Info = Array("Siegel v2 duress X25519".utf8)
    static let checkInfo = Array("Siegel v2 duress check".utf8)
    static let bindingInfo = Array("Siegel v2 duress factors".utf8)
    static let kekInfo = Array("Siegel v2 duress kek".utf8)

    /// F aus den Faktoren, die der Kopf verlangt (dieselben Faktor-Schlüssel e/c/y wie KEK_pw, domänengetrennt).
    /// nil ohne Faktoren (Format v1, Stufe 1) – dort gibt es kein Vernichtungs-Passwort. Fehlt ein verlangter Faktor →
    /// `factorMissing`.
    static func binding(header: VaultHeader, factors: FactorSecrets) throws -> SecureBytes? {
        guard header.formatVersion >= 2, !header.factors.kinds.isEmpty else { return nil }
        var keys: [SecureBytes] = []
        for kind in header.factors.kinds {
            guard let raw = factors.secret(kind) else { throw SiegelError.factorMissing(kind) }
            keys.append(try FactorKDF.factorKey(raw, kind: kind, vaultID: header.vaultID))
        }
        let ikm = try FactorKDF.concatenate(keys)
        return try ikm.withUnsafeBytes {
            try FactorKDF.hkdf($0, salt: header.vaultID, info: bindingInfo + [header.factors.rawValue], count: 32)
        }
    }

    /// kek = HKDF-SHA512(Kombinierer-Ausgabe ‖ F, salt = fileID, info = "Siegel v2 duress kek", 32).
    static func boundKEK(_ combined: SecureBytes, binding: SecureBytes, fileID: UUID) throws -> SecureBytes {
        let ikm = try FactorKDF.concatenate([combined, binding])
        return try ikm.withUnsafeBytes {
            try FactorKDF.hkdf($0, salt: VaultHeader.bytes(of: fileID), info: kekInfo, count: 32)
        }
    }

    /// d (32 B). Gleiche Fehler wie beim Master-Passwort (`kdfFailed`, `kdfParametersOutOfRange`).
    static func derive(password: SecureBytes, salt: [UInt8], kdf: KDFParameters, limits: KDFLimits) throws -> SecureBytes {
        guard salt.count == saltBytes else { throw SiegelError.crypto("duress.salt") }
        return try KDF.deriveKEK(password: password, salt: salt, params: kdf, limits: limits)
    }

    static func publicKeys(d: SecureBytes, vaultID: [UInt8]) throws -> RecoveryPublicKeys {
        try RecoveryKEM.derivePublicKeys(ikm: d, vaultID: vaultID, seedInfo: seedInfo, x25519Info: x25519Info)
    }

    static func check(d: SecureBytes, vaultID: [UInt8]) throws -> [UInt8] {
        let c = try d.withUnsafeBytes { try FactorKDF.hkdf($0, salt: vaultID, info: checkInfo, count: checkBytes) }
        return c.withUnsafeBytes { Array($0) }
    }

    static func wrapAD(vaultID: [UInt8], fileID: UUID, salt: [UInt8]) -> [UInt8] {
        label + vaultID + VaultHeader.bytes(of: fileID) + salt
    }

    /// Neuer Umschlag des DEK (frische Kapselung, an F gebunden) als Datei-Inhalt.
    static func seal(dek: SecureBytes, duress: DestructionConfig.Duress, binding: SecureBytes,
                     vaultID: [UInt8]) throws -> DuressFile {
        let enc = try RecoveryKEM.encapsulate(to: duress.pk, label: label, context: VaultHeader.bytes(of: duress.fileID))
        let kek = try boundKEK(enc.kek, binding: binding, fileID: duress.fileID)
        let wrapped = try AEAD.wrap(kek: kek, secret: dek,
                                    ad: wrapAD(vaultID: vaultID, fileID: duress.fileID, salt: duress.salt))
        return DuressFile(fileID: duress.fileID, salt: duress.salt, check: duress.check,
                          capsule: HybridCapsule(enc), wrapped: wrapped)
    }

    /// Ergebnis mit d: erkannt (Prüfwert passt, hängt nur an d) und – wenn der Umschlag zu Passwort **und** Faktoren
    /// (F) passt – der DEK. Ohne F (nil) höchstens „erkannt“.
    static func open(_ file: DuressFile, d: SecureBytes, binding: SecureBytes?,
                     vaultID: [UInt8]) -> (recognized: Bool, dek: SecureBytes?) {
        guard let c = try? check(d: d, vaultID: vaultID), constantTimeEqual(c, file.check) else { return (false, nil) }
        guard let binding,
              let pk = try? publicKeys(d: d, vaultID: vaultID),
              let keys = RecoveryKEM.privateKeys(ikm: d, vaultID: vaultID, seedInfo: seedInfo, x25519Info: x25519Info,
                                                 expected: pk),
              let combined = try? RecoveryKEM.decapsulate(keys, ctM: file.capsule.ctM, ctX: file.capsule.ctX,
                                                          label: label, context: VaultHeader.bytes(of: file.fileID)),
              let kek = try? boundKEK(combined, binding: binding, fileID: file.fileID),
              let dek = AEAD.unwrap(kek: kek, blob: file.wrapped,
                                    ad: wrapAD(vaultID: vaultID, fileID: file.fileID, salt: file.salt)) else {
            return (true, nil)
        }
        return (true, dek)
    }
}

// MARK: - Vernichtungs-Passwort: Ablage im Container

/// `Hardware/<fileID>.siegelhw` (§23.2 Nr. 3: im Container, nicht in der Tresordatei, gleiche Form wie die
/// SE-Schlüsseldateien des Hardware-Moduls): magic `"SIEGELHW"` ‖ version u16 = 1 ‖ kind u8 = 2 ‖ fileID (16) ‖
/// blobLength u16 ‖ blob ‖ point (P-256 x963, 65) ‖ SHA3-256("Siegel v2 hw file check" ‖ alles davor) (32).
/// `blob` = dSalt (16) ‖ check (16) ‖ ctM (1568) ‖ ctX (32) ‖ wrap (72) ‖ Zufallsbytes bis `blobLength`; `point` ist ein
/// zufälliger gültiger P-256-Punkt. Die Datei ist immer genau `fileLength` (2048) Byte gross.
struct DuressFile: Equatable, Sendable {
    static let magic = Array("SIEGELHW".utf8)
    static let version: UInt16 = 1
    static let kind: UInt8 = 2
    static let blobLength = 1922
    static let pointLength = 65
    static let checksumLength = 32
    static let fixedLength = 8 + 2 + 1 + 16 + 2
    static let fileLength = fixedLength + blobLength + pointLength + checksumLength
    static let payloadLength = DuressCrypto.saltBytes + DuressCrypto.checkBytes + RecoveryKEM.ctMBytes
        + RecoveryKEM.ctXBytes + AEAD.wrappedBytes
    static let checksumLabel = Array("Siegel v2 hw file check".utf8)

    let fileID: UUID
    let salt: [UInt8]
    let check: [UInt8]
    let capsule: HybridCapsule
    let wrapped: [UInt8]

    func encoded() throws -> [UInt8] {
        guard salt.count == DuressCrypto.saltBytes, check.count == DuressCrypto.checkBytes, capsule.isWellFormed,
              wrapped.count == AEAD.wrappedBytes else { throw SiegelError.crypto("duress.file") }
        var out: [UInt8] = []
        out.reserveCapacity(Self.fileLength)
        out += Self.magic
        out.appendLE(Self.version)
        out.append(Self.kind)
        out += VaultHeader.bytes(of: fileID)
        out.appendLE(UInt16(Self.blobLength))
        out += salt + check + capsule.ctM + capsule.ctX + wrapped
        out += randomBytes(Self.blobLength - Self.payloadLength)
        out += Array(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        out += Self.checksum(out)
        return out
    }

    /// Strenger Parser; jede Abweichung → `corruptFile("duress.…")`.
    static func decode(_ bytes: [UInt8], expectedID: UUID) throws -> DuressFile {
        guard bytes.count == fileLength else { throw SiegelError.corruptFile("duress.length") }
        let body = Array(bytes[0..<(fileLength - checksumLength)])
        guard constantTimeEqual(checksum(body), Array(bytes[(fileLength - checksumLength)...])) else {
            throw SiegelError.corruptFile("duress.checksum")
        }
        var r = ByteReader(body)
        guard try r.take(8, code: "duress.magic") == magic,
              try r.readLE(UInt16.self, code: "duress.version") == version,
              try r.take(1, code: "duress.kind") == [kind] else { throw SiegelError.corruptFile("duress.magic") }
        let id = VaultHeader.uuid(try r.take(16, code: "duress.id"))
        guard id == expectedID else { throw SiegelError.corruptFile("duress.id") }
        guard try r.readLE(UInt16.self, code: "duress.blob") == UInt16(blobLength) else {
            throw SiegelError.corruptFile("duress.blob")
        }
        let salt = try r.take(DuressCrypto.saltBytes, code: "duress.blob")
        let check = try r.take(DuressCrypto.checkBytes, code: "duress.blob")
        let ctM = try r.take(RecoveryKEM.ctMBytes, code: "duress.blob")
        let ctX = try r.take(RecoveryKEM.ctXBytes, code: "duress.blob")
        let wrapped = try r.take(AEAD.wrappedBytes, code: "duress.blob")
        _ = try r.take(blobLength - payloadLength, code: "duress.blob")
        let point = try r.take(pointLength, code: "duress.point")
        guard point.first == 0x04, (try? P256.KeyAgreement.PublicKey(x963Representation: point)) != nil,
              r.remaining == 0 else { throw SiegelError.corruptFile("duress.point") }
        return DuressFile(fileID: id, salt: salt, check: check, capsule: HybridCapsule(ctM: ctM, ctX: ctX),
                          wrapped: wrapped)
    }

    static func checksum(_ body: [UInt8]) -> [UInt8] {
        var h = SHA3_256()
        h.update(data: checksumLabel)
        h.update(data: body)
        return Array(h.finalize())
    }

    /// Hat die Datei die Form einer Ablage (Länge, magic, Version, kind, Bloblänge)? Prüfsumme, Kennung und Inhalt
    /// zählen nicht: auch eine beschädigte oder fremde Ablage darf ersetzt werden, ein SE-Schlüssel (andere Länge bzw.
    /// Bloblänge) nie.
    static func hasShape(_ bytes: [UInt8]) -> Bool {
        bytes.count == fileLength && Array(bytes[0..<8]) == magic && bytes[8] == UInt8(version & 0xFF)
            && bytes[9] == UInt8(version >> 8) && bytes[10] == kind
            && bytes[27] == UInt8(blobLength & 0xFF) && bytes[28] == UInt8(blobLength >> 8)
    }
}

// MARK: - Zustand im Container (nicht geheim)

/// `Hardware/zustand.json` (§23.3): Kopie der Einstellungen, letzte echte Entsperrung, Fehlversuche, Vernichtung.
/// Massgeblich für die Einstellungen ist der verschlüsselte Inhalt; die Kopie dient den Prüfungen im gesperrten
/// Zustand und wird bei jedem Speichern und jedem echten Entsperren aus dem Inhalt nachgeführt.
///
/// `{"destroyed": null|{"at","keyID","trigger"}, "duressFileID": …|null, "failedAttempts": n,
///   "lastGenuineUnlock": …|null, ["rekeyPending": true,] "settings": {…}, "v": 1, "vaultID": "…", "vKeyID": …|null}`
/// `rekeyPending` (v4.4) steht nur da, solange nach einer Vernichtungs-Sitzung der DEK noch nicht erneuert ist.
struct DestructionState: Equatable, Sendable {
    struct Destroyed: Equatable, Sendable, Codable {
        var keyID: UUID
        var trigger: DestructionTrigger
        var at: Date
    }

    static let version = 1
    static let fileName = "zustand.json"
    static let maxFileBytes = 16 << 10
    /// Obergrenze des Zählers in der Datei (mehr ist sinnlos und gilt als beschädigt).
    static let maxCounter = 1_000_000

    var vaultID: UUID
    var settings: DestructionSettings
    var vKeyID: UUID?
    var duressFileID: UUID?
    var lastGenuineUnlock: Date?
    var failedAttempts: Int
    var destroyed: Destroyed?
    /// Seit der letzten Vernichtungs-Sitzung (sie arbeitete mit dem echten DEK) noch keine DEK-Rotation (v4.4).
    var rekeyPending: Bool

    init(vaultID: UUID) {
        self.vaultID = vaultID
        settings = .off
        vKeyID = nil
        duressFileID = nil
        lastGenuineUnlock = nil
        failedAttempts = 0
        destroyed = nil
        rekeyPending = false
    }

    /// Nichts mehr zu merken (dann wird die Datei entfernt).
    var isEmpty: Bool {
        !settings.anyTriggerEnabled && vKeyID == nil && duressFileID == nil && destroyed == nil && !rekeyPending
    }

    /// Nennt der Zustand diese Kennung (als V, als vernichtet oder als Ablage des Vernichtungs-Passworts)?
    func names(_ id: UUID) -> Bool {
        vKeyID == id || destroyed?.keyID == id || duressFileID == id
    }

    var deadline: Date? {
        guard let days = settings.deadmanDays, let last = lastGenuineUnlock else { return nil }
        return Clock.canonical(last.addingTimeInterval(TimeInterval(days) * 86_400))
    }

    var status: DestructionStatus {
        DestructionStatus(settings: settings, lastGenuineUnlock: lastGenuineUnlock, failedAttempts: failedAttempts,
                          deadline: deadline, destroyedTrigger: destroyed?.trigger, destroyedAt: destroyed?.at,
                          keyConfigured: vKeyID != nil || destroyed != nil)
    }

    // MARK: JSON

    private struct DTO: Codable {
        var v: Int
        var vaultID: UUID
        var settings: DestructionSettings
        var vKeyID: UUID?
        var duressFileID: UUID?
        var lastGenuineUnlock: Date?
        var failedAttempts: Int
        var destroyed: Destroyed?
        var rekeyPending: Bool

        enum CodingKeys: String, CodingKey {
            case v, vaultID, settings, vKeyID, duressFileID, lastGenuineUnlock, failedAttempts, destroyed, rekeyPending
        }

        init(_ s: DestructionState) {
            v = DestructionState.version
            vaultID = s.vaultID
            settings = s.settings
            vKeyID = s.vKeyID
            duressFileID = s.duressFileID
            lastGenuineUnlock = s.lastGenuineUnlock
            failedAttempts = s.failedAttempts
            destroyed = s.destroyed
            rekeyPending = s.rekeyPending
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            v = try c.decode(Int.self, forKey: .v)
            vaultID = try c.decode(UUID.self, forKey: .vaultID)
            settings = try c.decode(DestructionSettings.self, forKey: .settings)
            vKeyID = try c.decodeIfPresent(UUID.self, forKey: .vKeyID)
            duressFileID = try c.decodeIfPresent(UUID.self, forKey: .duressFileID)
            lastGenuineUnlock = try c.decodeIfPresent(Date.self, forKey: .lastGenuineUnlock)
            failedAttempts = try c.decode(Int.self, forKey: .failedAttempts)
            destroyed = try c.decodeIfPresent(Destroyed.self, forKey: .destroyed)
            // Fehlt in Dateien bis v4.3 und solange nichts aussteht (geschrieben wird es nur als `true`).
            rekeyPending = try c.decodeIfPresent(Bool.self, forKey: .rekeyPending) ?? false
        }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(v, forKey: .v)
            try c.encode(vaultID, forKey: .vaultID)
            try c.encode(settings, forKey: .settings)
            if let x = vKeyID { try c.encode(x, forKey: .vKeyID) } else { try c.encodeNil(forKey: .vKeyID) }
            if let x = duressFileID {
                try c.encode(x, forKey: .duressFileID)
            } else {
                try c.encodeNil(forKey: .duressFileID)
            }
            if let x = lastGenuineUnlock {
                try c.encode(x, forKey: .lastGenuineUnlock)
            } else {
                try c.encodeNil(forKey: .lastGenuineUnlock)
            }
            try c.encode(failedAttempts, forKey: .failedAttempts)
            if let x = destroyed { try c.encode(x, forKey: .destroyed) } else { try c.encodeNil(forKey: .destroyed) }
            if rekeyPending { try c.encode(true, forKey: .rekeyPending) }
        }
    }

    func encoded() throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        do {
            return Array(try encoder.encode(DTO(self)))
        } catch {
            throw SiegelError.io("destruction.encode")
        }
    }

    /// Strenger Leser: unbekannte Version, Bereiche oder Werte → `corruptFile("destruction.state")`.
    static func decode(_ bytes: [UInt8]) throws -> DestructionState {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let dto: DTO
        do {
            dto = try decoder.decode(DTO.self, from: Data(bytes))
        } catch {
            throw SiegelError.corruptFile("destruction.state")
        }
        guard dto.v == version, (0...maxCounter).contains(dto.failedAttempts),
              (try? dto.settings.validate()) != nil,
              dto.settings.duressEnabled == (dto.duressFileID != nil) else {
            throw SiegelError.corruptFile("destruction.state")
        }
        var s = DestructionState(vaultID: dto.vaultID)
        s.settings = dto.settings
        s.vKeyID = dto.vKeyID
        s.duressFileID = dto.duressFileID
        s.lastGenuineUnlock = dto.lastGenuineUnlock.map(Clock.canonical)
        s.failedAttempts = dto.failedAttempts
        s.destroyed = dto.destroyed.map { Destroyed(keyID: $0.keyID, trigger: $0.trigger, at: Clock.canonical($0.at)) }
        s.rekeyPending = dto.rekeyPending
        return s
    }

    // MARK: Datei

    static func url(in hardware: URL) -> URL { hardware.appendingPathComponent(fileName, isDirectory: false) }

    /// nil = fehlt oder unlesbar (dann gilt „nichts eingerichtet“; ein echtes Entsperren schreibt sie neu).
    static func read(in hardware: URL) -> DestructionState? {
        guard let bytes = try? FileIO.read(url(in: hardware), maxSize: maxFileBytes) else { return nil }
        return try? decode(bytes)
    }

    /// Atomar ersetzen (Temp + F_FULLFSYNC + rename + Ordner fsync), 0600, vom Backup ausgenommen (best effort).
    /// Jeder Schreibfehler → `io("destruction.write")` (Fuzz-Befund vernichtung-5: ein nicht beschreibbarer
    /// Hardware-Ordner lieferte `io("file.create")`).
    static func write(_ state: DestructionState, in hardware: URL) throws {
        do {
            try FileIO.ensureDirectory(hardware)
        } catch {
            throw SiegelError.io("destruction.write")
        }
        try writeAtomically(try state.encoded(), to: url(in: hardware), directory: hardware)
    }

    static func remove(in hardware: URL) {
        if FileIO.removeChecked(url(in: hardware)) { try? FileIO.fsyncDirectory(hardware) }
    }

    /// Gemeinsamer Weg für zustand.json und die Datei des Vernichtungs-Passworts. Fehler: `io("destruction.write")`.
    static func writeAtomically(_ bytes: [UInt8], to target: URL, directory: URL) throws {
        var tmp: URL?
        for _ in 0..<16 {
            let candidate = directory.appendingPathComponent("." + target.lastPathComponent + "."
                                                                + hexString(randomBytes(4)) + ".tmp")
            do {
                try FileIO.writeExclusive(candidate, bytes: bytes)
                tmp = candidate
                break
            } catch is FileIO.Exists {
                continue
            } catch {
                throw SiegelError.io("destruction.write")
            }
        }
        guard let tmp else { throw SiegelError.io("destruction.write") }
        do {
            try FileIO.rename(tmp, to: target)
        } catch {
            FileIO.remove(tmp)
            throw SiegelError.io("destruction.write")
        }
        try? FileIO.fsyncDirectory(directory)
        try? FileIO.setExcludedFromBackup(target)
    }
}
