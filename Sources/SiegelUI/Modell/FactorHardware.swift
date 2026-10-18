import AppKit
import AVFoundation
import QuartzCore
import SiegelCore
import SiegelHardware

/// Zugriff der Oberfläche auf die Faktor-Hardware (SPEC §14). Die App nutzt `SystemFactorHardware`, die genau
/// die öffentliche Schnittstelle von SiegelHardware (§22) aufruft. SiegelSnapshots setzt eine eigene Umsetzung
/// ein (kein Touch-ID-Dialog, keine Kamera, kein USB). Blockierende Aufrufe (Touch ID, Berührung, Registrieren)
/// ruft die Oberfläche nie auf dem Main-Thread auf.
public protocol FactorHardware: Sendable {
    var secureEnclaveAvailable: Bool { get }
    /// Entsperr-Schlüssel in der Secure Enclave anlegen (prüft einmal mit Touch ID).
    func enrollSecureEnclave(directory: URL) throws -> SEEnrollment
    /// Eintrags-Schlüssel in der Secure Enclave anlegen (§16.1).
    func enrollEntryKey(directory: URL) throws -> EntryKeyEnrollment
    /// ECDH_SE mit Touch ID (Entsperren, Stufenregel „Touch ID vor dem Aufdecken“).
    func secureEnclaveSecret(keyID: UUID, directory: URL, reason: String) throws -> FactorSecret
    /// Eintrags-Schlüssel mit Touch ID (Aufdecken eines geschützten Eintrags).
    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data, directory: URL,
                                   reason: String) throws -> FactorSecret
    func removeSecureEnclaveKey(keyID: UUID, directory: URL) throws
    /// Schlüsseldatei vernichten: überschreiben, F_FULLFSYNC, löschen (SPEC v4.3 §23.1). Ohne Dialog.
    func destroySecureEnclaveKey(keyID: UUID, directory: URL) throws
    /// QR-Bild der Schlüsselkarte (nil = nicht verfügbar).
    func cardImage(payload: String, pixels: Int) -> CGImage?
    @MainActor func cameraAuthorization() -> AVAuthorizationStatus
    @MainActor func requestCameraAccess() async -> Bool
    @MainActor func makeScanner(onPayload: @escaping @MainActor (String) -> Void) -> any CardScanning
    func securityKeys() -> [SecurityKeyChoice]
    /// Einmal registrieren (Berührung, 30 s Frist) und beide hmac-secret-Ausgaben holen. `cancellation` setzt die
    /// Oberfläche bei „Abbrechen“ und beim Sperren: Der Vorgang endet dann sofort (CTAPHID_CANCEL, Verbindung zu)
    /// mit `factorCancelled` (v4.4, Befund hardware-4).
    func registerSecurityKey(_ key: SecurityKeyChoice, cancellation: SecurityKeyCancellation) throws -> SecurityKeyEnrollment
    func securityKeySecret(_ key: SecurityKeyChoice, credentialID: Data, salt: Data,
                           cancellation: SecurityKeyCancellation) throws -> FactorSecret
}

/// Kamera-Scanner der Schlüsselkarte (nur im Speicher; stoppt nach einer Erkennung).
@MainActor
public protocol CardScanning: AnyObject {
    func start() throws
    func stop()
    /// Kamerabild; nil = keine echte Kamera (die Oberfläche zeigt dann einen Platzhalter).
    var previewLayer: CALayer? { get }
}

/// Ein angeschlossener Sicherheitsschlüssel, wie die Oberfläche ihn zeigt.
public struct SecurityKeyChoice: Sendable, Hashable, Identifiable {
    public let name: String
    let device: SecurityKeyDevice?

    /// Für Attrappen (Snapshots): ohne echtes Gerät.
    public init(name: String) {
        self.name = name
        self.device = nil
    }

    init(device: SecurityKeyDevice) {
        self.name = device.name
        self.device = device
    }

    public var id: SecurityKeyChoice { self }
}

/// Die echte Hardware über SiegelHardware (§22).
public struct SystemFactorHardware: FactorHardware {
    public init() {}

    public var secureEnclaveAvailable: Bool { SecureEnclaveFactor.isAvailable }

    public func enrollSecureEnclave(directory: URL) throws -> SEEnrollment {
        try SecureEnclaveFactor.enroll(directory: directory)
    }

    public func enrollEntryKey(directory: URL) throws -> EntryKeyEnrollment {
        try SecureEnclaveFactor.enrollEntryKey(directory: directory)
    }

    public func secureEnclaveSecret(keyID: UUID, directory: URL, reason: String) throws -> FactorSecret {
        try SecureEnclaveFactor.secret(keyID: keyID, directory: directory, reason: reason)
    }

    public func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data, directory: URL,
                                          reason: String) throws -> FactorSecret {
        try SecureEnclaveFactor.sharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey,
                                             directory: directory, reason: reason)
    }

    public func removeSecureEnclaveKey(keyID: UUID, directory: URL) throws {
        try SecureEnclaveFactor.remove(keyID: keyID, directory: directory)
    }

    public func destroySecureEnclaveKey(keyID: UUID, directory: URL) throws {
        try SecureEnclaveFactor.destroy(keyID: keyID, directory: directory)
    }

    public func cardImage(payload: String, pixels: Int) -> CGImage? {
        CardImage.qr(payload: payload, pixels: pixels)
    }

    @MainActor
    public func cameraAuthorization() -> AVAuthorizationStatus {
        QRScanner.authorization()
    }

    @MainActor
    public func requestCameraAccess() async -> Bool {
        await QRScanner.requestAccess()
    }

    @MainActor
    public func makeScanner(onPayload: @escaping @MainActor (String) -> Void) -> any CardScanning {
        SystemCardScanner(scanner: QRScanner(onPayload: onPayload))
    }

    public func securityKeys() -> [SecurityKeyChoice] {
        SecurityKeyFactor.connectedDevices().map(SecurityKeyChoice.init(device:))
    }

    public func registerSecurityKey(_ key: SecurityKeyChoice,
                                    cancellation: SecurityKeyCancellation) throws -> SecurityKeyEnrollment {
        guard let device = key.device else { throw SiegelError.factorUnavailable(.securityKey) }
        return try SecurityKeyFactor.register(on: device, cancellation: cancellation)
    }

    public func securityKeySecret(_ key: SecurityKeyChoice, credentialID: Data, salt: Data,
                                  cancellation: SecurityKeyCancellation) throws -> FactorSecret {
        guard let device = key.device else { throw SiegelError.factorUnavailable(.securityKey) }
        return try SecurityKeyFactor.secret(on: device, credentialID: credentialID, salt: salt,
                                            cancellation: cancellation)
    }
}

@MainActor
final class SystemCardScanner: CardScanning {
    private let scanner: QRScanner

    init(scanner: QRScanner) {
        self.scanner = scanner
    }

    func start() throws { try scanner.start() }
    func stop() { scanner.stop() }
    var previewLayer: CALayer? { scanner.previewLayer }
}

/// Anzeige der Faktoren in der Oberfläche (kurz, lang, Symbol). „Touch ID“ statt „Fingerabdruck“, weil der
/// Mac den Sensor so nennt.
public enum FactorUI {
    public static func name(_ kind: FactorKind) -> String {
        switch kind {
        case .secureEnclave: "Touch ID"
        case .card: "Karte"
        case .securityKey: "Schlüssel"
        }
    }

    public static func longName(_ kind: FactorKind) -> String {
        switch kind {
        case .secureEnclave: "Touch ID"
        case .card: "QR-Schlüsselkarte"
        case .securityKey: "Sicherheitsschlüssel"
        }
    }

    /// Master-Passwort (nicht „key“: das wäre vom Sicherheitsschlüssel kaum zu unterscheiden).
    public static let passwordSymbol = "ellipsis.rectangle"

    public static func symbol(_ kind: FactorKind) -> String {
        switch kind {
        case .secureEnclave: "touchid"
        case .card: "qrcode"
        case .securityKey: "key.horizontal"
        }
    }

    /// „Touch ID, Karte und Schlüssel“
    public static func list(_ set: FactorSet, long: Bool = false) -> String {
        let namen = set.kinds.map { long ? longName($0) : name($0) }
        switch namen.count {
        case 0: return ""
        case 1: return namen[0]
        default: return namen.dropLast().joined(separator: ", ") + " und " + (namen.last ?? "")
        }
    }
}
