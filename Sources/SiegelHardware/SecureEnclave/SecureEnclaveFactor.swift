import CryptoKit
import Dispatch
import Foundation
import SiegelCore

/// Secure-Enclave-Faktor mit Touch ID (SPEC §14.1, §16.1).
///
/// Alle Aufrufe ausser `isAvailable`, `remove` und `destroy` können einen Touch-ID-Dialog zeigen und blockieren bis zur
/// Antwort: nie auf dem Main-Thread aufrufen (`Task.detached`). Liefert immer rohe 32 Byte (ECDH); die HKDFs
/// rechnet der Kern.
public enum SecureEnclaveFactor {
    /// Text im Touch-ID-Dialog beim Einrichten des Entsperr-Schlüssels.
    public static let enrollReason = "Touch ID für Siegel einrichten"
    /// Text im Touch-ID-Dialog beim Einrichten des Schlüssels für geschützte Einträge.
    public static let entryEnrollReason = "Touch ID für geschützte Einträge einrichten"
    /// Ersatz, falls die Oberfläche einen leeren Grund übergibt (LocalAuthentication verlangt einen Text).
    public static let defaultReason = "Siegel entsperren"

    /// Secure Enclave vorhanden und Touch ID eingerichtet (zeigt keinen Dialog). Bei vorübergehender
    /// Touch-ID-Sperre (zu viele Fehlversuche) oder unerreichbarem Sensor ebenfalls false. Die Abfragen unten melden
    /// diese Zustände als `factorTemporarilyUnavailable(.secureEnclave, "se.lockout"/"se.notReachable")` (v4.4).
    public static var isAvailable: Bool { SystemSecureEnclaveBackend().isAvailable }

    /// Erzeugt den Entsperr-Schlüssel, prüft ihn **einmal mit Touch ID** und legt `<keyID>.siegelhw` ab.
    public static func enroll(directory: URL) throws -> SEEnrollment {
        dispatchPrecondition(condition: .notOnQueue(.main))
        return try engine.enroll(directory: directory)
    }

    /// Erzeugt den Schlüssel für geschützte Einträge (§16.1), ebenfalls einmal mit Touch ID geprüft.
    public static func enrollEntryKey(directory: URL) throws -> EntryKeyEnrollment {
        dispatchPrecondition(condition: .notOnQueue(.main))
        return try engine.enrollEntryKey(directory: directory)
    }

    /// ECDH_SE für das Entsperren (Touch ID).
    public static func secret(keyID: UUID, directory: URL, reason: String) throws -> FactorSecret {
        dispatchPrecondition(condition: .notOnQueue(.main))
        return try engine.secret(keyID: keyID, directory: directory, reason: reason)
    }

    /// ECDH(Eintrags-SE-Schlüssel, ephemerer Schlüssel des Kerns) für das Aufdecken eines Eintrags (Touch ID).
    /// `ephemeralPublicKey` ist x963 (65 B); ungültig → `crypto("se.publickey")` ohne Dialog.
    public static func sharedSecret(keyID: UUID, ephemeralPublicKey: Data, directory: URL,
                                    reason: String) throws -> FactorSecret {
        dispatchPrecondition(condition: .notOnQueue(.main))
        return try engine.sharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey,
                                       directory: directory, reason: reason)
    }

    /// Entfernt die Schlüsseldatei (danach ist der Schlüssel unbrauchbar). Fehlt sie, ist das kein Fehler.
    public static func remove(keyID: UUID, directory: URL) throws {
        try engine.remove(keyID: keyID, directory: directory)
    }

    /// Vernichtet die Schlüsseldatei (SPEC v4.3 §23.1, z. B. den Vernichtungs-Schlüssel V): mit Zufallsbytes
    /// überschreiben, `F_FULLFSYNC`, löschen, Ordner `fsync`. Zeigt keinen Dialog, braucht keinen Finger und darf
    /// überall laufen (auch gesperrt, auch auf dem Main-Thread – es sind wenige KiB). Fehlt die Datei, ist das kein
    /// Fehler; scheitert das Löschen → `io("hw.destroy")`.
    public static func destroy(keyID: UUID, directory: URL) throws {
        try engine.destroy(keyID: keyID, directory: directory)
    }

    static var engine: SecureEnclaveEngine { SecureEnclaveEngine(backend: SystemSecureEnclaveBackend()) }
}

/// Ablauflogik unabhängig von der Hardware (Tests setzen eine Software-Schicht ein).
struct SecureEnclaveEngine: Sendable {
    let backend: any SecureEnclaveBackend

    func enroll(directory: URL) throws -> SEEnrollment {
        let material = try mapped { try backend.createKey() }
        let sePublic = try Self.publicKey(material.publicKey, code: "se.key")
        // Software-Schlüssel d nur in diesem Block; danach verworfen (CryptoKit nullt seinen Speicher).
        let (expected, p) = try { () throws -> (FactorSecret, P256.KeyAgreement.PublicKey) in
            let d = P256.KeyAgreement.PrivateKey()
            let shared = try d.sharedSecretFromKeyAgreement(with: sePublic)
            return (try FactorSecret(copying: shared), d.publicKey)
        }()
        let check = try touchID { try backend.sharedSecret(blob: material.blob, peer: p, reason: SecureEnclaveFactor.enrollReason) }
        guard constantTimeEqual(expected, check) else { throw SiegelError.crypto("se.verify") }
        let keyID = UUID()
        try HardwareKeyFile(kind: .unlock, keyID: keyID, blob: material.blob, point: p.x963Representation)
            .write(to: directory)
        return SEEnrollment(keyID: keyID, secret: expected)
    }

    func enrollEntryKey(directory: URL) throws -> EntryKeyEnrollment {
        let material = try mapped { try backend.createKey() }
        let sePublic = try Self.publicKey(material.publicKey, code: "se.key")
        // Prüfung nach dem Muster von §14.1: ephemerer Software-Schlüssel k gegen den SE-Schlüssel.
        let (expected, k) = try { () throws -> (FactorSecret, P256.KeyAgreement.PublicKey) in
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: sePublic)
            return (try FactorSecret(copying: shared), ephemeral.publicKey)
        }()
        let check = try touchID {
            try backend.sharedSecret(blob: material.blob, peer: k, reason: SecureEnclaveFactor.entryEnrollReason)
        }
        guard constantTimeEqual(expected, check) else { throw SiegelError.crypto("se.verify") }
        let keyID = UUID()
        let publicX963 = sePublic.x963Representation
        try HardwareKeyFile(kind: .entry, keyID: keyID, blob: material.blob, point: publicX963).write(to: directory)
        return EntryKeyEnrollment(keyID: keyID, publicKey: publicX963)
    }

    func secret(keyID: UUID, directory: URL, reason: String) throws -> FactorSecret {
        let file = try HardwareKeyFile.read(keyID: keyID, kind: .unlock, directory: directory)
        let p = try Self.publicKey(file.point, code: "se.key")
        return try touchID { try backend.sharedSecret(blob: file.blob, peer: p, reason: Self.reasonText(reason)) }
    }

    func sharedSecret(keyID: UUID, ephemeralPublicKey: Data, directory: URL, reason: String) throws -> FactorSecret {
        let peer = try Self.publicKey(ephemeralPublicKey, code: "se.publickey")
        let file = try HardwareKeyFile.read(keyID: keyID, kind: .entry, directory: directory)
        return try touchID { try backend.sharedSecret(blob: file.blob, peer: peer, reason: Self.reasonText(reason)) }
    }

    func remove(keyID: UUID, directory: URL) throws {
        try HardwareKeyFile.remove(keyID: keyID, directory: directory)
    }

    func destroy(keyID: UUID, directory: URL) throws {
        try HardwareKeyFile.destroy(keyID: keyID, directory: directory)
    }

    /// Nur unkomprimierte P-256-Punkte (x963, 65 B), die auf der Kurve liegen.
    static func publicKey(_ x963: Data, code: String) throws -> P256.KeyAgreement.PublicKey {
        guard x963.count == 65, x963.first == 0x04,
              let key = try? P256.KeyAgreement.PublicKey(x963Representation: x963) else {
            throw SiegelError.crypto(code)
        }
        return key
    }

    static func reasonText(_ reason: String) -> String {
        reason.isEmpty ? SecureEnclaveFactor.defaultReason : reason
    }

    private func mapped<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch {
            throw SecureEnclaveErrors.classify(error)
        }
    }

    /// Wie `mapped`, für Aufrufe mit Touch ID: Ein nicht erkannter Fehler gilt nur dann als abgelehnter Schlüssel,
    /// wenn Touch ID jetzt bereit ist; bei Sperre oder unerreichbarem Sensor ist er vorübergehend (v4.4, §14.1).
    /// Fehlt die Schlüsseldatei, wird gar nicht erst gefragt (`HardwareKeyFile.read` → `factorUnavailable`).
    private func touchID<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch {
            throw SecureEnclaveErrors.classifyTouchID(error) { backend.biometryState }
        }
    }
}
