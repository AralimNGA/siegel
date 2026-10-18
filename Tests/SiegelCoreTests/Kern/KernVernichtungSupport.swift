import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Software-Ersatz für den Vernichtungsschlüssel V (nur Tests): der private P-256-Schlüssel liegt roh (32 B) in
/// `Hardware/<vKeyID>.siegelhw` – genau die Datei, die das Vernichten überschreibt und löscht. Fehlt sie, ist V weg
/// (`factorUnavailable(.secureEnclave)` wie beim echten Secure Enclave ohne Blob).
final class VernichtungsProvider: EntryFactorProvider, @unchecked Sendable {
    let schutz: SchutzProvider
    let hardware: URL
    let vKeyID: UUID
    private let lock = NSLock()
    private var vCalls = 0

    init(_ schutz: SchutzProvider, hardware: URL, vKeyID: UUID) {
        self.schutz = schutz
        self.hardware = hardware
        self.vKeyID = vKeyID
    }

    var vCount: Int { lock.withLock { vCalls } }

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        guard keyID == vKeyID else {
            return try await schutz.secureEnclaveSharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey)
        }
        lock.withLock { vCalls += 1 }
        let url = hardware.appendingPathComponent(vKeyID.uuidString + ".siegelhw")
        guard let raw = try? Data(contentsOf: url), raw.count == 32,
              let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw) else {
            throw SiegelError.factorUnavailable(.secureEnclave)
        }
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        let shared = try key.sharedSecretFromKeyAgreement(with: pub)
        return try shared.withUnsafeBytes { try FactorSecret(copying: Array($0)) }
    }

    func cardSecret() async throws -> FactorSecret { try await schutz.cardSecret() }

    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
        try await schutz.securityKeyOutput(credentialID: credentialID, salt: salt)
    }
}

/// Zählt die Aufrufe der austauschbaren Vernichtungs-Schicht und vernichtet wie der Kern (Datei-Variante).
final class ZaehlEraser: DestructionKeyEraser, @unchecked Sendable {
    private let lock = NSLock()
    private var ids: [UUID] = []
    /// true = tut nichts (Schicht kaputt): dann muss der Rückfall des Kerns greifen.
    let untaetig: Bool

    init(untaetig: Bool = false) { self.untaetig = untaetig }

    var destroyed: [UUID] { lock.withLock { ids } }

    func destroy(keyID: UUID, directory: URL) throws {
        lock.withLock { ids.append(keyID) }
        if untaetig { throw SiegelError.io("test.eraser") }
        try FileDestructionKeyEraser().destroy(keyID: keyID, directory: directory)
    }
}

/// Testtresor der Stufe 4 oder 5 mit allen Eintrags-Faktoren und einem Software-V.
final class VTresor: @unchecked Sendable {
    static let duressPW = "w=8:Q.+F3mYWO6#O8@s~@~4_q:"
    static let duressPW2 = "x_b,DV_>9Ml^Zx./m936@ziw:b"

    let t: SchutzTresor
    let vKeyID = UUID()
    let vKey = P256.KeyAgreement.PrivateKey()
    let eraser = ZaehlEraser()
    let provider: VernichtungsProvider
    var vault: UnlockedVault

    var store: VaultStore { t.store }
    var level: SecurityLevel { vault.level }
    var hardware: URL { store.hardwareDirectory }
    var vURL: URL { hardware.appendingPathComponent(vKeyID.uuidString + ".siegelhw") }
    var stateURL: URL { hardware.appendingPathComponent("zustand.json") }

    init(_ level: SecurityLevel = .maximal) throws {
        t = try SchutzTresor.make(level, enroll: .all)
        vault = t.vault
        provider = VernichtungsProvider(t.p, hardware: t.store.hardwareDirectory, vKeyID: vKeyID)
        t.store.destructionKeyEraser = eraser
        try FileManager.default.createDirectory(at: t.store.hardwareDirectory, withIntermediateDirectories: true)
        try vKey.rawRepresentation.write(to: vURL)
    }

    var vEnrollment: EntryKeyEnrollment {
        EntryKeyEnrollment(keyID: vKeyID, publicKey: vKey.publicKey.x963Representation)
    }

    func factors() throws -> FactorSecrets { try t.k.secrets(vault.level.factors) }

    /// Eintrag anlegen und seine Kennung liefern.
    @discardableResult
    func add(_ title: String, _ protection: EntryProtection) throws -> VaultEntry {
        let e = schutzEntry(title, protection: protection)
        try vault.upsert(e)
        return e
    }

    @discardableResult
    func einrichten(_ s: DestructionSettings, duress: String? = nil, markieren: Set<UUID>,
                    vKey: Bool = true, password: String = KT.pw1) async throws -> PurgeReport? {
        try await vault.configureDestruction(s, duressPassword: duress, destructible: markieren, masterPassword: password,
                                             factors: try factors(), vKey: vKey ? vEnrollment : nil,
                                             entryFactors: provider)
    }

    /// Sperren und neu entsperren (Faktoren der Stufe).
    func reopen(_ password: String = KT.pw1) throws {
        let f = try factors()
        vault.lock()
        vault = KT.anyVault(try store.unlock(masterPassword: password, factors: f))
    }

    /// Nur entsperren versuchen (Tresor bleibt danach gesperrt, falls es klappt, wird es zurückgegeben).
    func tryUnlock(_ password: String) throws -> UnlockedVault {
        KT.anyVault(try store.unlock(masterPassword: password, factors: try t.k.secrets(level.factors)))
    }

    func reveal(_ id: UUID, in v: UnlockedVault? = nil) async throws -> EntrySecrets {
        try await (v ?? vault).revealSecrets(id: id, factors: provider)
    }

    func state() -> DestructionState? { DestructionState.read(in: hardware) }

    func hardwareNames() -> Set<String> {
        Set(FileIO.listFiles(hardware).map(\.lastPathComponent))
    }

    /// Kann der aktuelle Umschlag des Vernichtungs-Passworts den DEK des offenen Tresors liefern (mit den Faktoren
    /// der Stufe, v4.4)?
    func duressEnvelopeOpens(_ password: String = VTresor.duressPW, in v: UnlockedVault? = nil) throws -> Bool {
        let v = v ?? vault
        guard let c = v.contentForTesting, let d = c.destruction?.duress, let h = v.headerForTesting,
              let file = store.readDuressFile(d.fileID) else { return false }
        let dd = try DuressCrypto.derive(password: try PasswordNormalizer.secureBytes(password), salt: d.salt,
                                         kdf: h.kdf, limits: store.limits)
        let binding = try DuressCrypto.binding(header: h, factors: try t.k.secrets(h.factors))
        let r = DuressCrypto.open(file, d: dd, binding: binding, vaultID: h.vaultID)
        guard r.recognized, let dek = r.dek else { return false }
        return dek.constantTimeEquals(try v.dekForTesting())
    }

    /// Angreifer-Sicht (v4.4): nur Dateien – eine Kopie der Ablage, eine Tresordatei – und das Vernichtungs-Passwort,
    /// dazu wahlweise Faktoren. Liefert (erkannt, DEK öffnet `vaultFile`).
    func offlineDuress(_ ablage: [UInt8], fileID: UUID, password: String = VTresor.duressPW, vaultFile: [UInt8],
                       factors: FactorSecrets?) throws -> (recognized: Bool, content: VaultContent?) {
        let f = try DuressFile.decode(ablage, expectedID: fileID)
        let file = try VaultFile.parse(vaultFile)
        let d = try DuressCrypto.derive(password: try PasswordNormalizer.secureBytes(password), salt: f.salt,
                                        kdf: file.header.kdf, limits: store.limits)
        let binding = try factors.flatMap { try DuressCrypto.binding(header: file.header, factors: $0) }
        let r = DuressCrypto.open(f, d: d, binding: binding, vaultID: file.header.vaultID)
        return (r.recognized, r.dek.flatMap { try? VaultCrypto.decryptPayload(file, dek: $0).content })
    }
}

extension KernVault {
    /// Inhalt einer Datei mit dem Master-Passwort öffnen (Sicherungen prüfen).
    func openFile(_ url: URL, password: String = KT.pw1, factors: FactorSecrets) throws -> VaultContent {
        let file = try VaultFile.parse(try FileIO.read(url, maxSize: FileFormat.maxFileBytes))
        return try VaultCrypto.openWithPassword(file, password: try PasswordNormalizer.secureBytes(password),
                                                factors: factors, limits: store.limits).content
    }
}
