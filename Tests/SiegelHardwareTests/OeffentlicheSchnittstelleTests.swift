import Foundation
import SiegelCore
import Testing
@testable import SiegelHardware

/// Öffentliche Schnittstelle nach SPEC §22, soweit ohne Hardware und ohne Dialog prüfbar.
@Suite("Öffentliche Schnittstelle")
struct OeffentlicheSchnittstelleTests {
    @Test func sicherheitsschluesselEhrlichGekennzeichnet() {
        #expect(SecurityKeyFactor.testedWithHardware == false)
        #expect(SecurityKeyFactor.hardwareNotice == "Mit echter Hardware ungetestet")
    }

    @Test func ohneGeraetNichtVerfuegbar() throws {
        // Auf dem Testrechner steckt kein Sicherheitsschlüssel; die Aufzählung darf nichts kaputt machen.
        let devices = SecurityKeyFactor.connectedDevices()
        #expect(devices.allSatisfy { !$0.name.isEmpty })
        #expect(throws: SiegelError.factorUnavailable(.securityKey)) {
            try SecurityKeyFactor.register(on: SecurityKeyDevice(name: "Kein Gerät \(UUID().uuidString)"))
        }
        #expect(throws: SiegelError.factorUnavailable(.securityKey)) {
            try SecurityKeyFactor.secret(on: SecurityKeyDevice(name: "Kein Gerät \(UUID().uuidString)"),
                                         credentialID: Data(count: 32), salt: Data(count: 32))
        }
    }

    @Test func geraeteGleichheit() {
        #expect(SecurityKeyDevice(name: "A") == SecurityKeyDevice(name: "A"))
        #expect(SecurityKeyDevice(name: "A", registryID: 1) != SecurityKeyDevice(name: "A", registryID: 2))
    }

    @Test func secureEnclaveEntfernenOhneDatei() throws {
        try SecureEnclaveFactor.remove(keyID: UUID(), directory: tempDirectory())
    }

    @Test func secureEnclaveFehlenderSchluesselOhneDialog() {
        // Fehlt die Datei, wird der Secure Enclave gar nicht erst gefragt.
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try SecureEnclaveFactor.secret(keyID: UUID(), directory: tempDirectory(), reason: "Test")
        }
        #expect(throws: SiegelError.crypto("se.publickey")) {
            try SecureEnclaveFactor.sharedSecret(keyID: UUID(), ephemeralPublicKey: Data(count: 65),
                                                 directory: tempDirectory(), reason: "Test")
        }
    }
}
