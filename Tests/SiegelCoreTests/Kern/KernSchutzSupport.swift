import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// Test-Provider für den Eintrags-Schutz: Software-P256 statt Secure Enclave, feste q und y2 (aus `KernFaktoren`).
/// Zählt jeden Aufruf; Fehlverhalten lässt sich pro Faktor einstellen.
final class SchutzProvider: EntryFactorProvider, @unchecked Sendable {
    enum Verhalten: Sendable { case richtig, falsch, abbruch, fremderFehler, nichtVerfuegbar }

    let faktoren: KernFaktoren
    let entryKeyID = UUID()
    let seKey = P256.KeyAgreement.PrivateKey()
    private let lock = NSLock()
    private var calls: [FactorKind: Int] = [:]
    private var verhalten: [FactorKind: Verhalten] = [:]
    /// Wird vor der Antwort aufgerufen (z. B. Tresor sperren).
    private var beforeAnswer: (@Sendable () -> Void)?

    init(_ faktoren: KernFaktoren) { self.faktoren = faktoren }

    var entryKey: EntryKeyEnrollment {
        EntryKeyEnrollment(keyID: entryKeyID, publicKey: seKey.publicKey.x963Representation)
    }

    func set(_ kind: FactorKind, _ v: Verhalten) { lock.withLock { verhalten[kind] = v } }
    func onAnswer(_ body: (@Sendable () -> Void)?) { lock.withLock { beforeAnswer = body } }
    func count(_ kind: FactorKind) -> Int { lock.withLock { calls[kind] ?? 0 } }
    var counts: [Int] { [count(.secureEnclave), count(.card), count(.securityKey)] }
    func reset() { lock.withLock { calls = [:] } }

    private func enter(_ kind: FactorKind) throws -> Verhalten {
        let (v, hook) = lock.withLock { () -> (Verhalten, (@Sendable () -> Void)?) in
            calls[kind, default: 0] += 1
            return (verhalten[kind] ?? .richtig, beforeAnswer)
        }
        hook?()
        switch v {
        case .abbruch: throw CancellationError()
        case .fremderFehler: throw NSError(domain: "Test", code: 7)
        case .nichtVerfuegbar: throw SiegelError.factorUnavailable(kind)
        case .richtig, .falsch: return v
        }
    }

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        let v = try enter(.secureEnclave)
        guard keyID == entryKeyID else { throw SiegelError.factorUnavailable(.secureEnclave) }
        let key = v == .falsch ? P256.KeyAgreement.PrivateKey() : seKey
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        let shared = try key.sharedSecretFromKeyAgreement(with: pub)
        return try shared.withUnsafeBytes { try FactorSecret(copying: Array($0)) }
    }

    func cardSecret() async throws -> FactorSecret {
        let v = try enter(.card)
        return v == .falsch ? CardCode.generate() : faktoren.q
    }

    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
        let v = try enter(.securityKey)
        guard credentialID == Data(faktoren.credentialID), salt == Data(faktoren.entrySalt) else {
            throw SiegelError.factorUnavailable(.securityKey)
        }
        return try FactorSecret(copying: v == .falsch ? randomBytes(32) : faktoren.entryOutput)
    }
}

/// Ein Testtresor mit Eintrags-Faktoren, deren Gegenseite `SchutzProvider` kennt.
struct SchutzTresor {
    let f: KernVault
    let k: KernFaktoren
    let p: SchutzProvider
    /// Gültiges Kit (bei Stufen mit Schema-Wechsel das neue, sonst das aus `create`).
    let kit: PendingRecovery?

    var vault: UnlockedVault { f.vault }
    var store: VaultStore { f.store }

    /// Stufe `level`, Eintrags-SE-Schlüssel des Providers, dazu Karte und Sicherheitsschlüssel für Einträge
    /// (sofern `enroll` sie enthält und die Stufe sie nicht ohnehin einrichtet).
    static func make(_ level: SecurityLevel = .standard, enroll: FactorSet = .all) throws -> SchutzTresor {
        let f = try KernVault.make()
        let k = try KernFaktoren()
        let p = SchutzProvider(k)
        var material = try k.material(for: level, entryKey: false)
        if enroll.contains(.secureEnclave) { material.entryKey = p.entryKey }
        var kit: PendingRecovery? = f.pending
        if level != .standard {
            kit = try KernStufen.change(f.vault, to: level, faktoren: k, current: [], newMaterial: material) ?? f.pending
        }
        var extra = NewFactorMaterial()
        if level == .standard, enroll.contains(.secureEnclave) { extra.entryKey = p.entryKey }
        if enroll.contains(.card), !level.factors.contains(.card) { extra.card = k.card }
        if enroll.contains(.securityKey), !level.factors.contains(.securityKey) { extra.securityKey = try k.securityKey }
        if extra.entryKey != nil || extra.card != nil || extra.securityKey != nil {
            try f.vault.enrollFactors(extra, masterPassword: KT.pw1, currentFactors: try k.secrets(level.factors))
        }
        return SchutzTresor(f: f, k: k, p: p, kit: kit)
    }

    /// Öffnet erneut (Faktoren der Stufe).
    func reopen(password: String = KT.pw1) throws -> UnlockedVault {
        let level = vault.level
        vault.lock()
        return KT.anyVault(try store.unlock(masterPassword: password, factors: try k.secrets(level.factors)))
    }

    /// Klartext-JSON des Inhalts auf der Platte (mit dem DEK des offenen Tresors).
    func jsonOnDisk(_ v: UnlockedVault? = nil) throws -> String {
        let file = try f.parsedFile()
        let dek = try (v ?? vault).dekForTesting()
        let padded = try #require(AEAD.open(key: dek, nonce: file.nonce, ciphertext: file.ciphertext, ad: file.payloadAD))
        return try #require(PayloadCodec.jsonStringForTesting(padded))
    }
}

/// Eintrag mit allen Geheimteilen.
func schutzEntry(_ title: String, protection: EntryProtection, password: String? = nil) -> VaultEntry {
    var e = VaultEntry(title: title, username: title.lowercased() + "@example.ch",
                       password: password ?? "PW-" + title + "-" + hexString(randomBytes(6)),
                       url: "https://" + title.lowercased() + ".example.ch",
                       notes: "Notiz zu " + title, totp: "otpauth://totp/" + title + "?secret=JBSWY3DPEHPK3PXP",
                       protection: protection)
    e.history = [PasswordHistoryItem(password: "Alt-" + title, changed: Date(timeIntervalSince1970: 1_790_000_000))]
    return e
}

extension EntrySecrets {
    init(_ e: VaultEntry) {
        self.init(password: e.password, notes: e.notes, totp: e.totp, history: e.history)
    }
}
