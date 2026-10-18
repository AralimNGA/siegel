import CryptoKit
import Foundation
import LocalAuthentication
import Security
import SiegelCore

/// Frisch erzeugter Secure-Enclave-Schlüssel: Blob (vom Secure Enclave verpackt) und öffentlicher Schlüssel (x963).
struct SEKeyMaterial: Sendable {
    let blob: Data
    let publicKey: Data
}

/// Austauschbare Schicht für die eigentlichen Secure-Enclave-Operationen. Die App nutzt
/// `SystemSecureEnclaveBackend`; Tests ersetzen sie durch eine Software-Variante, damit `swift test` nie einen
/// Touch-ID-Dialog auslöst.
protocol SecureEnclaveBackend: Sendable {
    var isAvailable: Bool { get }
    /// Zustand von Touch ID jetzt, ohne Dialog (`canEvaluatePolicy`). Unterscheidet nach einem Fehler, ob Touch ID nur
    /// vorübergehend nicht geht (Sperre, Sensor nicht erreichbar) oder der Schlüssel wirklich abgelehnt wurde.
    var biometryState: BiometryState { get }
    /// Erzeugt einen neuen Schlüssel (`.privateKeyUsage`, `.biometryCurrentSet`). Kein Dialog.
    func createKey() throws -> SEKeyMaterial
    /// Rohes ECDH (32 B) zwischen dem Blob-Schlüssel und `peer`. Verlangt Touch ID, blockiert bis zur Antwort.
    func sharedSecret(blob: Data, peer: P256.KeyAgreement.PublicKey, reason: String) throws -> FactorSecret
}

/// Echte Umsetzung mit CryptoKit (SPEC §14.1). Ohne Schlüsselbund: Der Blob liegt in der eigenen Datei.
struct SystemSecureEnclaveBackend: SecureEnclaveBackend {
    var isAvailable: Bool {
        guard SecureEnclave.isAvailable else { return false }
        let context = LAContext()
        defer { context.invalidate() }
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    var biometryState: BiometryState {
        guard SecureEnclave.isAvailable else { return .unavailable }
        let context = LAContext()
        defer { context.invalidate() }
        var error: NSError?
        guard !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return .ready }
        guard let error else { return .unavailable }
        return BiometryState(laError: error)
    }

    func createKey() throws -> SEKeyMaterial {
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           [.privateKeyUsage, .biometryCurrentSet], &cfError) else {
            cfError?.release()
            throw SiegelError.factorUnavailable(.secureEnclave)
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        return SEKeyMaterial(blob: key.dataRepresentation, publicKey: key.publicKey.x963Representation)
    }

    func sharedSecret(blob: Data, peer: P256.KeyAgreement.PublicKey, reason: String) throws -> FactorSecret {
        // Frischer Kontext pro Abfrage, keine Wiederverwendung einer früheren Touch-ID-Freigabe.
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        defer { context.invalidate() }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        return try FactorSecret(copying: shared)
    }
}

/// Zustand von Touch ID ohne Dialog (aus `LAContext.canEvaluatePolicy`).
enum BiometryState: Sendable, Equatable {
    case ready
    /// Nach zu vielen Fehlversuchen gesperrt; das Mac-Passwort gibt Touch ID wieder frei (`biometryLockout`).
    case lockedOut
    /// Sensor gerade nicht erreichbar: Deckel zu, Tastatur mit Touch ID nicht verbunden oder nicht gekoppelt
    /// (`biometryNotAvailable`, `biometryDisconnected`, `biometryNotPaired`).
    case notReachable
    /// Keine Fingerabdrücke eingerichtet (`biometryNotEnrolled`): Ein Schlüssel mit `.biometryCurrentSet` ist damit
    /// ungültig geworden.
    case notEnrolled
    /// Kein Secure Enclave oder ein anderer Grund.
    case unavailable

    init(laError error: NSError) {
        guard error.domain == LAErrorDomain else {
            self = .unavailable
            return
        }
        switch error.code {
        case LAError.Code.biometryLockout.rawValue:
            self = .lockedOut
        case LAError.Code.biometryNotAvailable.rawValue, LAError.Code.biometryDisconnected.rawValue,
             LAError.Code.biometryNotPaired.rawValue:
            self = .notReachable
        case LAError.Code.biometryNotEnrolled.rawValue:
            self = .notEnrolled
        default:
            self = .unavailable
        }
    }

    /// Fester Fehler für einen vorübergehenden Zustand (SPEC v4.4, §14.1); nil = nicht vorübergehend.
    var temporaryError: SiegelError? {
        switch self {
        case .lockedOut: .factorTemporarilyUnavailable(.secureEnclave, SecureEnclaveErrors.lockoutCode)
        case .notReachable: .factorTemporarilyUnavailable(.secureEnclave, SecureEnclaveErrors.notReachableCode)
        case .ready, .notEnrolled, .unavailable: nil
        }
    }
}

/// Bildet Fehler aus CryptoKit, Security, CryptoTokenKit und LocalAuthentication auf `SiegelError` ab:
/// Abbruch durch Nutzer oder System, Fingerabdruck nicht erkannt → `factorCancelled` (erneut versuchen);
/// Touch ID gesperrt (zu viele Fehlversuche) oder nicht erreichbar (Deckel zu, Tastatur fehlt) →
/// `factorTemporarilyUnavailable(.secureEnclave, …)` (erneut versuchen, kein Notfallweg, v4.4);
/// alles andere (Biometrie geändert, nicht eingerichtet, Blob ungültig) → `factorUnavailable(.secureEnclave)`.
enum SecureEnclaveErrors {
    /// Domäne von CryptoTokenKit (`TKErrorDomain`), als Text, damit das Modul CryptoTokenKit nicht nötig ist.
    static let tokenKitDomain = "CryptoTokenKit"
    static let tokenKitCanceledByUser = -4
    /// Feste Codes von `factorTemporarilyUnavailable(.secureEnclave, …)`.
    static let lockoutCode = "se.lockout"
    static let notReachableCode = "se.notReachable"

    static func classify(_ error: Error) -> SiegelError {
        if let siegel = error as? SiegelError { return siegel }
        var current: NSError? = error as NSError
        var depth = 0
        while let e = current, depth < 8 {
            if isCancel(e) { return .factorCancelled }
            if e.domain == LAErrorDomain, let temporary = BiometryState(laError: e).temporaryError { return temporary }
            current = e.userInfo[NSUnderlyingErrorKey] as? NSError
            depth += 1
        }
        return .factorUnavailable(.secureEnclave)
    }

    /// Nach einer Touch-ID-Abfrage: Ist der Fehler nicht als Abbruch oder vorübergehend erkannt, entscheidet der
    /// Zustand von Touch ID jetzt (ohne Dialog). Nur wenn Touch ID bereit ist (oder keine Finger mehr eingerichtet
    /// sind), gilt der Schlüssel als abgelehnt – sonst würde eine Sperre oder ein zugeklappter Deckel zum Notfallweg
    /// führen (Befund hardware-1). CryptoKit/CryptoTokenKit verpacken den LAError nicht immer erkennbar.
    static func classifyTouchID(_ error: Error, state: () -> BiometryState) -> SiegelError {
        let classified = classify(error)
        guard classified == .factorUnavailable(.secureEnclave), !(error is SiegelError) else { return classified }
        return state().temporaryError ?? classified
    }

    static func isCancel(_ e: NSError) -> Bool {
        switch e.domain {
        case LAErrorDomain:
            let cancelCodes: [LAError.Code] = [.userCancel, .appCancel, .systemCancel, .userFallback,
                                               .authenticationFailed, .notInteractive]
            return cancelCodes.contains { $0.rawValue == e.code }
        case NSOSStatusErrorDomain:
            return e.code == Int(errSecUserCanceled)
        case tokenKitDomain:
            return e.code == tokenKitCanceledByUser
        default:
            return false
        }
    }
}
