import CryptoKit
import Foundation
import LocalAuthentication
import Security
import SiegelCore
import Testing
@testable import SiegelHardware

/// Secure-Enclave-Logik gegen die Software-Schicht: nie ein Touch-ID-Dialog in `swift test`.
@Suite("Secure Enclave (Software-Schicht)")
struct SecureEnclaveTests {
    let backend = SoftwareSEBackend()
    var engine: SecureEnclaveEngine { SecureEnclaveEngine(backend: backend) }

    @Test func einrichtenPrueftEinmalUndLegtDateiAb() throws {
        let dir = tempDirectory().appendingPathComponent("Hardware", isDirectory: true)
        let enrollment = try engine.enroll(directory: dir)
        #expect(backend.prompts == [SecureEnclaveFactor.enrollReason])
        let file = HardwareKeyFile.fileURL(keyID: enrollment.keyID, directory: dir)
        #expect(file.lastPathComponent == "\(enrollment.keyID.uuidString).siegelhw")
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        let dirAttrs = try FileManager.default.attributesOfItem(atPath: dir.path)
        #expect((dirAttrs[.posixPermissions] as? NSNumber)?.intValue == 0o700)
        // Keine Temp-Reste.
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == [file.lastPathComponent])

        let again = try engine.secret(keyID: enrollment.keyID, directory: dir, reason: "Siegel entsperren")
        #expect(again.testBytes == enrollment.secret.testBytes)
        #expect(enrollment.secret.testBytes.count == 32)
        #expect(backend.prompts.last == "Siegel entsperren")
    }

    @Test func jedeAbfrageIstEineEigeneFreigabe() throws {
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        for _ in 0..<3 { _ = try engine.secret(keyID: e.keyID, directory: dir, reason: "Siegel entsperren") }
        #expect(backend.prompts.count == 4)
    }

    @Test func leererGrundWirdErsetzt() throws {
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        _ = try engine.secret(keyID: e.keyID, directory: dir, reason: "")
        #expect(backend.prompts.last == SecureEnclaveFactor.defaultReason)
    }

    @Test func falschePruefungBrichtAbOhneDatei() throws {
        let dir = tempDirectory()
        backend.tamper = true
        #expect(throws: SiegelError.crypto("se.verify")) { try engine.enroll(directory: dir) }
        #expect(throws: SiegelError.crypto("se.verify")) { try engine.enrollEntryKey(directory: dir) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
    }

    @Test func abbruchBeimEinrichtenSchreibtNichts() throws {
        let dir = tempDirectory()
        backend.failure = NSError(domain: LAErrorDomain, code: LAError.Code.userCancel.rawValue)
        #expect(throws: SiegelError.factorCancelled) { try engine.enroll(directory: dir) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
    }

    @Test func fehlenderBlobIstNichtVerfuegbar() throws {
        let dir = tempDirectory()
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try engine.secret(keyID: UUID(), directory: dir, reason: "x")
        }
        #expect(backend.prompts.isEmpty)
    }

    static let gesperrt = SiegelError.factorTemporarilyUnavailable(.secureEnclave, "se.lockout")
    static let unerreichbar = SiegelError.factorTemporarilyUnavailable(.secureEnclave, "se.notReachable")
    static let nichtNutzbar = SiegelError.factorUnavailable(.secureEnclave)

    @Test(arguments: [
        (LAErrorDomain, LAError.Code.userCancel.rawValue, SiegelError.factorCancelled),
        (LAErrorDomain, LAError.Code.appCancel.rawValue, .factorCancelled),
        (LAErrorDomain, LAError.Code.systemCancel.rawValue, .factorCancelled),
        (LAErrorDomain, LAError.Code.userFallback.rawValue, .factorCancelled),
        (LAErrorDomain, LAError.Code.authenticationFailed.rawValue, .factorCancelled),
        // Befund hardware-1: Sperre und unerreichbarer Sensor sind vorübergehend (kein Notfallweg).
        (LAErrorDomain, LAError.Code.biometryLockout.rawValue, gesperrt),
        (LAErrorDomain, -8, gesperrt),
        (LAErrorDomain, LAError.Code.biometryNotAvailable.rawValue, unerreichbar),
        (LAErrorDomain, -6, unerreichbar),
        (LAErrorDomain, LAError.Code.biometryDisconnected.rawValue, unerreichbar),
        (LAErrorDomain, LAError.Code.biometryNotPaired.rawValue, unerreichbar),
        // Keine Finger mehr eingerichtet: Der Schlüssel mit .biometryCurrentSet ist ungültig.
        (LAErrorDomain, LAError.Code.biometryNotEnrolled.rawValue, nichtNutzbar),
        (LAErrorDomain, LAError.Code.invalidContext.rawValue, nichtNutzbar),
        (NSOSStatusErrorDomain, Int(errSecUserCanceled), .factorCancelled),
        (NSOSStatusErrorDomain, Int(errSecAuthFailed), nichtNutzbar),
        (NSOSStatusErrorDomain, Int(errSecItemNotFound), nichtNutzbar),
        ("CryptoTokenKit", -4, .factorCancelled),
        ("CryptoTokenKit", -6, nichtNutzbar),
        ("CryptoTokenKit", -5, nichtNutzbar),
    ])
    func fehlerAbbildung(domain: String, code: Int, expected: SiegelError) throws {
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        backend.failure = NSError(domain: domain, code: code)
        #expect(throws: expected) { try engine.secret(keyID: e.keyID, directory: dir, reason: "x") }
        // Auch beim Eintrags-Schlüssel und beim Einrichten gleich.
        let entry = try { () throws -> EntryKeyEnrollment in
            backend.failure = nil
            defer { backend.failure = NSError(domain: domain, code: code) }
            return try engine.enrollEntryKey(directory: dir)
        }()
        let k = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(throws: expected) {
            try engine.sharedSecret(keyID: entry.keyID, ephemeralPublicKey: k, directory: dir, reason: "x")
        }
        #expect(throws: expected) { try engine.enroll(directory: tempDirectory()) }
    }

    @Test func verschachtelteSperreWirdErkannt() {
        let inner = NSError(domain: LAErrorDomain, code: LAError.Code.biometryLockout.rawValue)
        let outer = NSError(domain: "CryptoTokenKit", code: -9, userInfo: [NSUnderlyingErrorKey: inner])
        #expect(SecureEnclaveErrors.classify(outer) == Self.gesperrt)
        let deckel = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed),
                             userInfo: [NSUnderlyingErrorKey: NSError(domain: LAErrorDomain, code: -6)])
        #expect(SecureEnclaveErrors.classify(deckel) == Self.unerreichbar)
    }

    /// Befund hardware-1: Verpackt das System den Grund nicht erkennbar, entscheidet der Zustand von Touch ID
    /// (ohne Dialog). „Schlüssel abgelehnt“ (Notfallweg) nur, wenn Touch ID bereit ist.
    @Test(arguments: [
        (BiometryState.lockedOut, gesperrt),
        (.notReachable, unerreichbar),
        (.ready, nichtNutzbar),
        (.notEnrolled, nichtNutzbar),
        (.unavailable, nichtNutzbar),
    ])
    func unbekannterFehlerNachZustand(state: BiometryState, expected: SiegelError) throws {
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        backend.failure = NSError(domain: "CryptoTokenKit", code: -9)
        backend.biometry = state
        #expect(throws: expected) { try engine.secret(keyID: e.keyID, directory: dir, reason: "x") }
        #expect(backend.stateQueries == 1)
    }

    @Test func zustandNurNachUnbekanntemFehlerGefragt() throws {
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        backend.biometry = .lockedOut
        _ = try engine.secret(keyID: e.keyID, directory: dir, reason: "x")
        backend.failure = NSError(domain: LAErrorDomain, code: LAError.Code.userCancel.rawValue)
        #expect(throws: SiegelError.factorCancelled) { try engine.secret(keyID: e.keyID, directory: dir, reason: "x") }
        #expect(backend.stateQueries == 0)
    }

    @Test func fehlendeSchluesseldateiBleibtEndgueltigAuchBeiSperre() throws {
        // Ohne Datei ist der Schlüssel wirklich weg: Notfallweg, auch wenn Touch ID gerade gesperrt ist.
        let dir = tempDirectory()
        backend.biometry = .lockedOut
        #expect(throws: Self.nichtNutzbar) { try engine.secret(keyID: UUID(), directory: dir, reason: "x") }
        #expect(backend.prompts.isEmpty)
        #expect(backend.stateQueries == 0)
    }

    @Test(arguments: [
        (LAError.Code.biometryLockout.rawValue, BiometryState.lockedOut),
        (LAError.Code.biometryNotAvailable.rawValue, .notReachable),
        (LAError.Code.biometryDisconnected.rawValue, .notReachable),
        (LAError.Code.biometryNotPaired.rawValue, .notReachable),
        (LAError.Code.biometryNotEnrolled.rawValue, .notEnrolled),
        (LAError.Code.passcodeNotSet.rawValue, .unavailable),
        (LAError.Code.userCancel.rawValue, .unavailable),
    ])
    func zustandAusLAError(code: Int, expected: BiometryState) {
        #expect(BiometryState(laError: NSError(domain: LAErrorDomain, code: code)) == expected)
        #expect(BiometryState(laError: NSError(domain: "andere", code: code)) == .unavailable)
    }

    @Test func verschachtelterAbbruchWirdErkannt() {
        let inner = NSError(domain: LAErrorDomain, code: LAError.Code.userCancel.rawValue)
        let outer = NSError(domain: "CryptoTokenKit", code: -9, userInfo: [NSUnderlyingErrorKey: inner])
        #expect(SecureEnclaveErrors.classify(outer) == .factorCancelled)
        #expect(SecureEnclaveErrors.classify(CryptoKitError.incorrectKeySize) == .factorUnavailable(.secureEnclave))
        #expect(SecureEnclaveErrors.classify(SiegelError.crypto("x")) == .crypto("x"))
    }

    @Test func geaenderteBiometrieMachtDenSchluesselUnbrauchbar() throws {
        // Der echte Secure Enclave lehnt einen Schlüssel mit .biometryCurrentSet nach einer Änderung ab;
        // nachgestellt durch einen nicht mehr ladbaren Blob.
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        let url = HardwareKeyFile.fileURL(keyID: e.keyID, directory: dir)
        let file = try HardwareKeyFile.decode(Array(try Data(contentsOf: url)), expectedKeyID: e.keyID, expectedKind: .unlock)
        try FileManager.default.removeItem(at: url)
        try HardwareKeyFile(kind: .unlock, keyID: e.keyID, blob: Data(repeating: 7, count: 40), point: file.point).write(to: dir)
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try engine.secret(keyID: e.keyID, directory: dir, reason: "x")
        }
    }

    // MARK: Eintrags-Schlüssel (§16.1)

    @Test func eintragsSchluesselWieImKern() throws {
        let dir = tempDirectory()
        let entry = try engine.enrollEntryKey(directory: dir)
        #expect(entry.publicKey.count == 65)
        #expect(entry.publicKey.first == 0x04)
        #expect(backend.prompts == [SecureEnclaveFactor.entryEnrollReason])

        // Der Kern versiegelt mit einem ephemeren Schlüssel k gegen den öffentlichen Eintrags-Schlüssel …
        let k = P256.KeyAgreement.PrivateKey()
        let sealSide = try k.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: entry.publicKey))
        // … und beim Aufdecken liefert SiegelHardware dasselbe ECDH.
        let open = try engine.sharedSecret(keyID: entry.keyID, ephemeralPublicKey: k.publicKey.x963Representation,
                                           directory: dir, reason: "Eintrag aufdecken")
        #expect(open.testBytes == sealSide.withUnsafeBytes { Array($0) })
        #expect(backend.prompts.last == "Eintrag aufdecken")
    }

    @Test func eintragsUndEntsperrSchluesselSindGetrennt() throws {
        let dir = tempDirectory()
        let unlock = try engine.enroll(directory: dir)
        let entry = try engine.enrollEntryKey(directory: dir)
        let k = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try engine.sharedSecret(keyID: unlock.keyID, ephemeralPublicKey: k, directory: dir, reason: "x")
        }
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try engine.secret(keyID: entry.keyID, directory: dir, reason: "x")
        }
    }

    @Test func ungueltigerEphemererSchluesselOhneDialog() throws {
        let dir = tempDirectory()
        let entry = try engine.enrollEntryKey(directory: dir)
        let before = backend.prompts.count
        let valid = P256.KeyAgreement.PrivateKey().publicKey
        var offCurve = Array(valid.x963Representation)
        offCurve[64] ^= 0x01
        let candidates: [Data] = [
            Data(),
            Data(repeating: 0, count: 65),
            Data(offCurve),
            valid.compressedRepresentation,
            valid.rawRepresentation,
            Data(Array(valid.x963Representation) + [0]),
        ]
        for c in candidates {
            #expect(throws: SiegelError.crypto("se.publickey")) {
                try engine.sharedSecret(keyID: entry.keyID, ephemeralPublicKey: c, directory: dir, reason: "x")
            }
        }
        #expect(backend.prompts.count == before)
    }

    @Test func entfernenMachtUnbrauchbarUndIstWiederholbar() throws {
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        try engine.remove(keyID: e.keyID, directory: dir)
        try engine.remove(keyID: e.keyID, directory: dir)
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try engine.secret(keyID: e.keyID, directory: dir, reason: "x")
        }
    }

    @Test func geschwaerzteAusgabe() throws {
        let dir = tempDirectory()
        let e = try engine.enroll(directory: dir)
        let hexSecret = hexString(e.secret.testBytes)
        var dumped = ""
        dump(e, to: &dumped)
        #expect(!String(describing: e).contains(hexSecret))
        #expect(!dumped.contains(hexSecret))
        #expect(String(describing: e.secret) == "FactorSecret(redacted)")
    }
}

/// Echter Secure Enclave – nur manuell (`SIEGEL_HW_MANUELL=1 swift test --filter Manuell`).
/// Erlaubt sind nur `isAvailable` und das Erzeugen eines Schlüssels ohne Nutzung (kein Dialog).
@Suite("Manuell: echter Secure Enclave", .enabled(if: ProcessInfo.processInfo.environment["SIEGEL_HW_MANUELL"] == "1"))
struct ManuellSecureEnclaveTests {
    @Test func verfuegbarUndSchluesselErzeugenOhneNutzung() throws {
        #expect(SecureEnclave.isAvailable)
        let material = try SystemSecureEnclaveBackend().createKey()
        #expect(material.publicKey.count == 65)
        #expect(!material.blob.isEmpty)
        #expect(material.blob.count <= HardwareKeyFile.maxBlobLength)
        // Datei-Format mit echtem Blob (ohne Touch ID).
        let dir = tempDirectory()
        let id = UUID()
        try HardwareKeyFile(kind: .entry, keyID: id, blob: material.blob, point: material.publicKey).write(to: dir)
        let back = try HardwareKeyFile.read(keyID: id, kind: .entry, directory: dir)
        #expect(back.blob == material.blob)
        _ = SystemSecureEnclaveBackend().isAvailable
    }
}
