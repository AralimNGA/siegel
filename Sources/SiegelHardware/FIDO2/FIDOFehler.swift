import SiegelCore

/// Interne Fehler des FIDO2-Teils (feste Codes, nie Inhalte). Nach aussen gehen nur `SiegelError`-Fälle.
package enum FIDOError: Error, Equatable, Sendable {
    /// Gerät fehlt, wurde abgezogen, oder Lesen/Schreiben scheiterte.
    case transport
    /// Keine Antwort innert Frist (ohne Benutzeraktion).
    case timeout
    /// Nicht berührt innert Frist (30 s).
    case userTimeout
    /// CTAPHID-Rahmung verletzt.
    case hid(String)
    /// CTAPHID_ERROR vom Gerät.
    case hidError(UInt8)
    /// CBOR ungültig.
    case cbor(CBORError)
    /// CTAP2-Statuscode ≠ 0.
    case ctap(UInt8)
    /// Antwort formal gültig, aber inhaltlich falsch.
    case response(String)
    /// Gerät kann das Verlangte nicht (kein CTAP2, kein hmac-secret, verlangt UV/PIN).
    case unsupported(String)
    /// Ungültige Eingabe des Aufrufers.
    case input(String)
    /// Von der Oberfläche abgebrochen (`SecurityKeyCancellation`, v4.4); eine offene Anfrage wurde mit
    /// CTAPHID_CANCEL beendet.
    case cancelled

    /// Abbildung auf die Fehler der Schnittstelle (SPEC §22, v4.4).
    package var siegelError: SiegelError {
        switch self {
        case .userTimeout, .cancelled:
            return .factorCancelled
        case .ctap(let status) where CTAPStatus.cancelled.contains(status):
            return .factorCancelled
        case .ctap(let status) where status == CTAPStatus.noCredentials:
            // Die credentialID ist an das Gerät gebunden, das sie registriert hat: anderer Schlüssel steckt, oder
            // dieser wurde zurückgesetzt (Befund hardware-3).
            return .wrongSecurityKey
        case .hidError(let code) where code == CTAPHID.ErrorCode.channelBusy:
            // Ein anderer Vorgang (anderes Programm, Browser) hält den Schlüssel über die ganze Frist (hardware-4).
            return .factorTemporarilyUnavailable(.securityKey, Self.busyCode)
        case .input:
            return .crypto("fido.input")
        default:
            return .factorUnavailable(.securityKey)
        }
    }

    /// Fester Code von `factorTemporarilyUnavailable(.securityKey, …)`.
    package static let busyCode = "fido.busy"

    /// Alle Fehler, die die FIDO2-Abläufe nach aussen geben können (Fuzzer, Tests).
    package static func isAllowedOutward(_ error: SiegelError) -> Bool {
        switch error {
        case .factorUnavailable(.securityKey), .factorCancelled, .wrongSecurityKey, .crypto("fido.input"):
            return true
        case let .factorTemporarilyUnavailable(kind, code):
            return kind == .securityKey && code == busyCode
        default:
            return false
        }
    }
}

/// CTAP2-Statuscodes (CTAP 2.1 §8.2), soweit gebraucht.
package enum CTAPStatus {
    package static let ok: UInt8 = 0x00
    package static let invalidCommand: UInt8 = 0x01
    package static let invalidParameter: UInt8 = 0x02
    package static let invalidLength: UInt8 = 0x03
    package static let cborUnexpectedType: UInt8 = 0x11
    package static let invalidCBOR: UInt8 = 0x12
    package static let missingParameter: UInt8 = 0x14
    package static let unsupportedAlgorithm: UInt8 = 0x26
    package static let operationDenied: UInt8 = 0x27
    package static let unsupportedOption: UInt8 = 0x2B
    package static let invalidOption: UInt8 = 0x2C
    package static let keepaliveCancel: UInt8 = 0x2D
    package static let noCredentials: UInt8 = 0x2E
    package static let userActionTimeout: UInt8 = 0x2F
    package static let pinInvalid: UInt8 = 0x31
    package static let pinBlocked: UInt8 = 0x32
    package static let pinAuthInvalid: UInt8 = 0x33
    package static let pinNotSet: UInt8 = 0x35
    package static let puatRequired: UInt8 = 0x36
    package static let invalidSubcommand: UInt8 = 0x3E
    package static let uvBlocked: UInt8 = 0x3C
    package static let uvInvalid: UInt8 = 0x3F

    /// Nutzer hat abgelehnt, nicht berührt oder der Vorgang wurde abgebrochen.
    package static let cancelled: Set<UInt8> = [operationDenied, keepaliveCancel, userActionTimeout]
}
