import CryptoKit
import Foundation
import SiegelCore
@testable import SiegelHardware

/// Software-Ersatz für den Secure Enclave (nur Tests): gleiche Rechnung (P-256-ECDH), aber ohne Touch-ID-Dialog.
/// Zählt jede „Touch-ID-Abfrage“ und kann Fehler wie Abbruch oder geänderte Biometrie nachstellen.
final class SoftwareSEBackend: SecureEnclaveBackend, @unchecked Sendable {
    static let blobPrefix = Array("SW-SE1".utf8)

    private let lock = NSLock()
    private var _prompts: [String] = []
    private var _created = 0
    /// Fehler bei der nächsten und allen weiteren Abfragen (nil = keiner).
    var failure: NSError? {
        get { lock.withLock { _failure } }
        set { lock.withLock { _failure = newValue } }
    }
    private var _failure: NSError?
    /// Liefert bei der Prüfung ein falsches Ergebnis (Einrichten muss abbrechen).
    var tamper: Bool {
        get { lock.withLock { _tamper } }
        set { lock.withLock { _tamper = newValue } }
    }
    private var _tamper = false
    var available = true
    /// Zustand von Touch ID für `biometryState` (Sperre, Sensor nicht erreichbar, …), ohne Dialog.
    var biometry: BiometryState {
        get { lock.withLock { _biometry } }
        set { lock.withLock { _biometry = newValue } }
    }
    private var _biometry: BiometryState = .ready
    /// Wie oft `biometryState` gefragt wurde.
    var stateQueries: Int { lock.withLock { _stateQueries } }
    private var _stateQueries = 0

    var prompts: [String] { lock.withLock { _prompts } }
    var created: Int { lock.withLock { _created } }

    var isAvailable: Bool { available }

    var biometryState: BiometryState {
        lock.withLock {
            _stateQueries += 1
            return _biometry
        }
    }

    func createKey() throws -> SEKeyMaterial {
        let key = P256.KeyAgreement.PrivateKey()
        lock.withLock { _created += 1 }
        return SEKeyMaterial(blob: Data(Self.blobPrefix + Array(key.rawRepresentation)),
                             publicKey: key.publicKey.x963Representation)
    }

    func sharedSecret(blob: Data, peer: P256.KeyAgreement.PublicKey, reason: String) throws -> FactorSecret {
        let (failure, tamper) = lock.withLock { () -> (NSError?, Bool) in
            _prompts.append(reason)
            return (_failure, _tamper)
        }
        if let failure { throw failure }
        guard blob.count == Self.blobPrefix.count + 32, Array(blob.prefix(Self.blobPrefix.count)) == Self.blobPrefix else {
            throw NSError(domain: "CryptoTokenKit", code: -6)   // objectNotFound
        }
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: blob.dropFirst(Self.blobPrefix.count))
        var bytes = try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Array($0) }
        if tamper { bytes[0] ^= 0x01 }
        return try FactorSecret(copying: bytes)
    }
}
