import Dispatch
import Foundation
import SiegelCore
import Synchronization

/// Abbruch eines laufenden Schlüssel-Vorgangs (v4.4, Befund hardware-4). Die Oberfläche setzt ihn bei „Abbrechen“ und
/// beim Sperren. Der Vorgang prüft ihn mindestens alle 100 ms, beendet eine offene Anfrage mit CTAPHID_CANCEL
/// (CTAP 2.1 §11.2.9.1.5), schliesst die HID-Verbindung und meldet `factorCancelled`. Einmal gesetzt, bleibt er
/// gesetzt (pro Versuch ein neues Token).
public final class SecurityKeyCancellation: Sendable {
    private let flag = Atomic<Bool>(false)

    public init() {}

    public func cancel() { flag.store(true, ordering: .releasing) }

    public var isCancelled: Bool { flag.load(ordering: .acquiring) }
}

/// Ein angeschlossener FIDO2-Sicherheitsschlüssel.
public struct SecurityKeyDevice: Sendable, Hashable {
    /// Hersteller/Produkt, z. B. „YubiKey OTP+FIDO+CCID“.
    public let name: String
    /// IORegistry-Kennung (0 = unbekannt, dann wird über den Namen gesucht).
    let registryID: UInt64

    public init(name: String) {
        self.name = name
        self.registryID = 0
    }

    init(name: String, registryID: UInt64) {
        self.name = name
        self.registryID = registryID
    }
}

/// Sicherheitsschlüssel über FIDO2 hmac-secret (SPEC §14.3), eigene CTAP2-Umsetzung über USB-HID.
///
/// **Mit echter Hardware ungetestet**: Alle Abläufe sind gegen einen virtuellen Authenticator nach CTAP 2.1
/// getestet (auch kaputte Antworten), aber noch nie gegen ein Gerät. Erst nach einem Test mit Gerät in
/// PRUEFLISTE.md auf `true` setzen. Die Aufrufe blockieren bis zur Berührung (Frist 30 s): nie auf dem Main-Thread.
public enum SecurityKeyFactor {
    /// Ehrliche Kennzeichnung (SPEC §13): false, bis ein Test mit echtem Gerät abgehakt ist.
    public static let testedWithHardware = false
    /// Hinweis für die Oberfläche, solange `testedWithHardware == false`.
    public static let hardwareNotice = "Mit echter Hardware ungetestet"

    public static func connectedDevices() -> [SecurityKeyDevice] {
        HIDDeviceTransport.enumerate()
    }

    /// Registriert einmal (Berührung 1) und holt beide Ausgaben – Entsperr- und Eintrags-Salz in einer Anfrage
    /// (Berührung 2). Salze: je 32 B zufällig.
    /// Fehler: nicht berührt/abgelehnt/abgebrochen (`cancellation`) → `factorCancelled`; Gerät belegt →
    /// `factorTemporarilyUnavailable(.securityKey, "fido.busy")`; Gerät fehlt, kann kein hmac-secret ohne UV oder
    /// verlangt eine PIN → `factorUnavailable(.securityKey)`.
    public static func register(on device: SecurityKeyDevice,
                                cancellation: SecurityKeyCancellation? = nil) throws -> SecurityKeyEnrollment {
        dispatchPrecondition(condition: .notOnQueue(.main))
        return try withTransport(device, cancellation) { transport throws(FIDOError) in
            try FIDO2Flows(transport: transport, cancellation: cancellation).register()
        }
    }

    /// Eine hmac-secret-Ausgabe (32 B, roh) für `salt` (Berührung). Ein anderer oder zurückgesetzter Schlüssel
    /// kennt die credentialID nicht → `wrongSecurityKey` (v4.4); Fehler sonst wie `register`.
    public static func secret(on device: SecurityKeyDevice, credentialID: Data, salt: Data,
                              cancellation: SecurityKeyCancellation? = nil) throws -> FactorSecret {
        dispatchPrecondition(condition: .notOnQueue(.main))
        do {
            try FIDO2Flows.validate(credentialID: credentialID, salt: salt)
        } catch {
            throw error.siegelError
        }
        return try withTransport(device, cancellation) { transport throws(FIDOError) in
            try FIDO2Flows(transport: transport, cancellation: cancellation).secret(credentialID: credentialID, salt: salt)
        }
    }

    /// Öffnet die HID-Verbindung nur für die Dauer von `body` (auch nach einem Abbruch sofort zu).
    private static func withTransport<T>(_ device: SecurityKeyDevice, _ cancellation: SecurityKeyCancellation?,
                                         _ body: (any CTAPHIDTransport) throws(FIDOError) -> T) throws -> T {
        guard cancellation?.isCancelled != true else { throw SiegelError.factorCancelled }
        let transport: HIDDeviceTransport
        do {
            transport = try HIDDeviceTransport.open(device)
        } catch {
            throw error.siegelError
        }
        defer { transport.close() }
        do {
            return try body(transport)
        } catch {
            throw error.siegelError
        }
    }
}
