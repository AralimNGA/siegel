import CryptoKit
import Foundation
import SiegelCore
import Testing
@testable import SiegelHardware

/// Der ganze FIDO2-Ablauf (CTAPHID → CTAP2 → hmac-secret) gegen den virtuellen Authenticator.
@Suite("Sicherheitsschlüssel (FIDO2 hmac-secret)")
struct SecurityKeyFlowTests {
    func flows(_ auth: VirtualAuthenticator) -> FIDO2Flows {
        FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .test)
    }

    @Test(arguments: [[2, 1], [1], [2], nil] as [[Int]?])
    func registrierenUndWiederAbrufen(protocols: [Int]?) throws {
        var config = VirtualAuthenticator.Configuration()
        config.pinProtocols = protocols
        let auth = VirtualAuthenticator(config)
        let enrollment = try flows(auth).register()

        #expect(enrollment.credentialID.count == 64)
        #expect(enrollment.salt.count == 32)
        #expect(enrollment.entrySalt.count == 32)
        #expect(enrollment.salt != enrollment.entrySalt)
        #expect(enrollment.output.testBytes != enrollment.entryOutput.testBytes)
        #expect(auth.touches == 2)                          // registrieren + eine Assertion
        #expect(auth.saltCounts == [2])                     // beide Salze in einer Anfrage
        let expectedProtocol = (protocols ?? [1]).contains(2) ? 2 : 1
        #expect(auth.pinProtocolsUsed == [expectedProtocol])
        #expect(auth.lastAssertionHadProtocolKey == (expectedProtocol == 2))
        #expect(auth.lastMakeCredentialOptions == .map([CBORPair(.text("rk"), .bool(false))]))

        let unlock = try flows(auth).secret(credentialID: enrollment.credentialID, salt: enrollment.salt)
        let entry = try flows(auth).secret(credentialID: enrollment.credentialID, salt: enrollment.entrySalt)
        #expect(unlock.testBytes == enrollment.output.testBytes)
        #expect(entry.testBytes == enrollment.entryOutput.testBytes)
        #expect(auth.saltCounts == [2, 1, 1])
        #expect(auth.touches == 4)
    }

    @Test func zweiRegistrierungenSindUnabhaengig() throws {
        let auth = VirtualAuthenticator()
        let a = try flows(auth).register()
        let b = try flows(auth).register()
        #expect(a.credentialID != b.credentialID)
        #expect(a.output.testBytes != b.output.testBytes)
        let crossed = try flows(auth).secret(credentialID: a.credentialID, salt: b.salt)
        #expect(crossed.testBytes != b.output.testBytes)
    }

    @Test func anderesGeraetKenntDenSchluesselNicht() throws {
        let auth = VirtualAuthenticator()
        let e = try flows(auth).register()
        let other = VirtualAuthenticator()
        #expect(throws: FIDOError.ctap(CTAPStatus.noCredentials)) {
            try flows(other).secret(credentialID: e.credentialID, salt: e.salt)
        }
        // Befund hardware-3: eigene Meldung „nicht der Schlüssel dieses Tresors“ statt „verlangt eine PIN-Prüfung“.
        #expect(FIDOError.ctap(CTAPStatus.noCredentials).siegelError == .wrongSecurityKey)
        // Gleich nach einem Zurücksetzen des Schlüssels (alle Registrierungen weg).
        auth.forgetCredentials()
        #expect(throws: FIDOError.ctap(CTAPStatus.noCredentials)) {
            try flows(auth).secret(credentialID: e.credentialID, salt: e.salt)
        }
    }

    @Test func abbildungDerNeuenFaelle() {
        #expect(FIDOError.hidError(CTAPHID.ErrorCode.channelBusy).siegelError
                == .factorTemporarilyUnavailable(.securityKey, "fido.busy"))
        #expect(FIDOError.hidError(CTAPHID.ErrorCode.invalidChannel).siegelError == .factorUnavailable(.securityKey))
        #expect(FIDOError.cancelled.siegelError == .factorCancelled)
        // PIN/UV verlangt bleibt „nicht nutzbar“ (dort passt der PIN-Satz der Oberfläche).
        #expect(FIDOError.ctap(CTAPStatus.pinNotSet).siegelError == .factorUnavailable(.securityKey))
        #expect(FIDOError.unsupported("uv").siegelError == .factorUnavailable(.securityKey))
        for e: SiegelError in [.wrongSecurityKey, .factorCancelled, .factorUnavailable(.securityKey),
                               .factorTemporarilyUnavailable(.securityKey, "fido.busy"), .crypto("fido.input")] {
            #expect(FIDOError.isAllowedOutward(e))
        }
        #expect(!FIDOError.isAllowedOutward(.factorUnavailable(.secureEnclave)))
        #expect(!FIDOError.isAllowedOutward(.factorTemporarilyUnavailable(.securityKey, "x")))
    }

    // MARK: Abbrechen (Befund hardware-4)

    /// Fristen wie `.test`, aber mit langer Berührungsfrist: Ein Abbruch muss weit vor ihr greifen.
    static var langeFrist: CTAPHIDTimeouts {
        var t = CTAPHIDTimeouts.test
        t.userPresence = .seconds(20)
        t.cancelPoll = .milliseconds(10)
        return t
    }

    /// Setzt das Token, sobald das Gerät auf die Berührung wartet (erstes KEEPALIVE).
    func cancelWhenWaitingForTouch(_ auth: VirtualAuthenticator, _ token: SecurityKeyCancellation) {
        auth.packetMutator = { packets in
            if packets.contains(where: { $0.count == CTAPHID.reportSize && $0[4] == CTAPHID.Command.keepalive }) {
                token.cancel()
            }
        }
    }

    @Test func abbrechenBeendetDieOffeneAnfrage() throws {
        let auth = VirtualAuthenticator()
        let e = try flows(auth).register()
        auth.config.presence = .timeout          // blinkt, bis CTAPHID_CANCEL kommt
        let token = SecurityKeyCancellation()
        cancelWhenWaitingForTouch(auth, token)
        let transport = VirtualHIDTransport(auth)
        let clock = ContinuousClock()
        let start = clock.now
        #expect(throws: FIDOError.cancelled) {
            try FIDO2Flows(transport: transport, timeouts: Self.langeFrist, cancellation: token)
                .secret(credentialID: e.credentialID, salt: e.salt)
        }
        #expect(start.duration(to: clock.now) < .seconds(3))
        #expect(auth.cancels == 1)                                   // Gerät vom Warten befreit
        #expect(transport.sentCommands.last == CTAPHID.Command.cancel)
        #expect(token.isCancelled)
    }

    @Test func abbrechenBeimRegistrieren() throws {
        var config = VirtualAuthenticator.Configuration()
        config.presence = .timeout
        let auth = VirtualAuthenticator(config)
        let token = SecurityKeyCancellation()
        cancelWhenWaitingForTouch(auth, token)
        let transport = VirtualHIDTransport(auth)
        #expect(throws: FIDOError.cancelled) {
            try FIDO2Flows(transport: transport, timeouts: Self.langeFrist, cancellation: token).register()
        }
        #expect(auth.cancels == 1)
        #expect(auth.credentialCount == 0)
    }

    @Test func schonAbgebrochenFragtDasGeraetNicht() throws {
        let auth = VirtualAuthenticator()
        let e = try flows(auth).register()
        let token = SecurityKeyCancellation()
        token.cancel()
        let transport = VirtualHIDTransport(auth)
        let commands = auth.ctapCommands.count
        #expect(throws: FIDOError.cancelled) {
            try FIDO2Flows(transport: transport, timeouts: .test, cancellation: token)
                .secret(credentialID: e.credentialID, salt: e.salt)
        }
        #expect(transport.sentCommands.isEmpty)
        #expect(auth.ctapCommands.count == commands)
        // Öffentliche API: ohne das Gerät zu öffnen.
        #expect(throws: SiegelError.factorCancelled) {
            try SecurityKeyFactor.secret(on: SecurityKeyDevice(name: "Kein Gerät \(UUID().uuidString)"),
                                         credentialID: Data(count: 32), salt: Data(count: 32), cancellation: token)
        }
        #expect(throws: SiegelError.factorCancelled) {
            try SecurityKeyFactor.register(on: SecurityKeyDevice(name: "Kein Gerät \(UUID().uuidString)"),
                                           cancellation: token)
        }
    }

    @Test func abbrechenWaehrendBelegt() throws {
        // Ein anderer Vorgang hält den Schlüssel (ERR_CHANNEL_BUSY): Auch das Warten zwischen den Versuchen bricht ab.
        let auth = VirtualAuthenticator()
        let token = SecurityKeyCancellation()
        var busy = 0
        auth.packetMutator = { packets in
            guard let first = packets.first, first[4] == CTAPHID.Command.cbor else { return }
            busy += 1
            if busy == 3 { token.cancel() }
            packets = (try? CTAPHID.fragment(cid: first.readBE32(at: 0), command: CTAPHID.Command.error,
                                             payload: [CTAPHID.ErrorCode.channelBusy])) ?? []
        }
        var t = Self.langeFrist
        t.command = .seconds(20)
        t.busyRetry = .milliseconds(50)
        let clock = ContinuousClock()
        let start = clock.now
        #expect(throws: FIDOError.cancelled) {
            try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: t, cancellation: token).register()
        }
        #expect(start.duration(to: clock.now) < .seconds(3))
        #expect(auth.cancels == 0)
    }

    @Test func dauerndBelegtIstVoruebergehend() {
        let auth = VirtualAuthenticator()
        auth.packetMutator = { packets in
            guard let first = packets.first, first[4] == CTAPHID.Command.cbor else { return }
            packets = (try? CTAPHID.fragment(cid: first.readBE32(at: 0), command: CTAPHID.Command.error,
                                             payload: [CTAPHID.ErrorCode.channelBusy])) ?? []
        }
        #expect(throws: FIDOError.hidError(CTAPHID.ErrorCode.channelBusy)) { try flows(auth).register() }
        #expect(FIDOError.hidError(CTAPHID.ErrorCode.channelBusy).siegelError
                == .factorTemporarilyUnavailable(.securityKey, "fido.busy"))
    }

    @Test func belegtBisZurBeruehrungsfristIstBelegt() {
        // Belegt bis zum Ende der 30-s-Frist: „belegt“ (nicht „nicht berührt“), und kein CTAPHID_CANCEL für eine
        // Anfrage, die das Gerät nie angenommen hat.
        let auth = VirtualAuthenticator()
        auth.packetMutator = { [unowned auth] packets in
            guard let first = packets.first, auth.ctapCommands.last == CTAPCommand.makeCredential else { return }
            packets = (try? CTAPHID.fragment(cid: first.readBE32(at: 0), command: CTAPHID.Command.error,
                                             payload: [CTAPHID.ErrorCode.channelBusy])) ?? []
        }
        let transport = VirtualHIDTransport(auth)
        #expect(throws: FIDOError.hidError(CTAPHID.ErrorCode.channelBusy)) {
            try FIDO2Flows(transport: transport, timeouts: .test).register()
        }
        #expect(!transport.sentCommands.contains(CTAPHID.Command.cancel))
    }

    @Test func ohneAbbruchUnveraendert() throws {
        // Ein nie gesetztes Token ändert nichts am Ablauf.
        let auth = VirtualAuthenticator()
        let token = SecurityKeyCancellation()
        let e = try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .test, cancellation: token).register()
        let out = try FIDO2Flows(transport: VirtualHIDTransport(auth), timeouts: .test, cancellation: token)
            .secret(credentialID: e.credentialID, salt: e.salt)
        #expect(out.testBytes == e.output.testBytes)
        #expect(!token.isCancelled)
        #expect(auth.cancels == 0)
    }

    @Test func eingabenWerdenVorDemGeraetGeprueft() throws {
        let auth = VirtualAuthenticator()
        let id = Data(repeating: 1, count: 32)
        #expect(throws: FIDOError.input("salt")) { try flows(auth).secret(credentialID: id, salt: Data(count: 31)) }
        #expect(throws: FIDOError.input("credential")) { try flows(auth).secret(credentialID: Data(count: 15), salt: Data(count: 32)) }
        #expect(throws: FIDOError.input("credential")) { try flows(auth).secret(credentialID: Data(count: 1025), salt: Data(count: 32)) }
        #expect(auth.ctapCommands.isEmpty)
        #expect(FIDOError.input("salt").siegelError == .crypto("fido.input"))
        // Öffentliche API: gleiche Prüfung, ohne Gerät.
        #expect(throws: SiegelError.crypto("fido.input")) {
            try SecurityKeyFactor.secret(on: SecurityKeyDevice(name: "gibt es nicht"), credentialID: id, salt: Data(count: 3))
        }
    }

    // MARK: Gerätefähigkeiten (vor jeder Berührung geprüft)

    @Test func ohneHmacSecret() {
        var config = VirtualAuthenticator.Configuration()
        config.extensions = []
        let auth = VirtualAuthenticator(config)
        #expect(throws: FIDOError.unsupported("hmac-secret")) { try flows(auth).register() }
        #expect(auth.touches == 0)
    }

    @Test func nurU2F() {
        var config = VirtualAuthenticator.Configuration()
        config.versions = ["U2F_V2"]
        let auth = VirtualAuthenticator(config)
        #expect(throws: FIDOError.unsupported("ctap2")) { try flows(auth).register() }
    }

    @Test func immerUVVerlangt() throws {
        let auth = VirtualAuthenticator()
        let e = try flows(auth).register()
        auth.config.alwaysUv = true
        #expect(throws: FIDOError.unsupported("uv")) { try flows(auth).register() }
        #expect(throws: FIDOError.unsupported("uv")) { try flows(auth).secret(credentialID: e.credentialID, salt: e.salt) }
        #expect(auth.touches == 2)
    }

    @Test func gesetztePIN() throws {
        // CTAP 2.1 mit makeCredUvNotRqd: Registrieren ohne PIN erlaubt.
        var config = VirtualAuthenticator.Configuration()
        config.clientPin = true
        let auth = VirtualAuthenticator(config)
        let e = try flows(auth).register()
        // CTAP 2.0 ohne makeCredUvNotRqd: Registrieren verlangt PIN → nicht nutzbar (vor der Berührung).
        auth.config.makeCredUvNotRqd = nil
        let touches = auth.touches
        #expect(throws: FIDOError.unsupported("pin")) { try flows(auth).register() }
        #expect(auth.touches == touches)
        // hmac-secret ohne UV geht mit gesetzter PIN weiterhin.
        let out = try flows(auth).secret(credentialID: e.credentialID, salt: e.salt)
        #expect(out.testBytes == e.output.testBytes)
    }

    @Test func eingebauteUV() throws {
        // CTAP 2.1 mit eingerichtetem Fingerabdruck am Schlüssel, ohne makeCredUvNotRqd: nicht nutzbar, ohne Berührung.
        var config = VirtualAuthenticator.Configuration()
        config.builtInUV = true
        config.makeCredUvNotRqd = nil
        let auth = VirtualAuthenticator(config)
        #expect(throws: FIDOError.unsupported("uv")) { try flows(auth).register() }
        #expect(auth.touches == 0)
        // Mit makeCredUvNotRqd geht es (hmac-secret ohne UV).
        auth.config.makeCredUvNotRqd = true
        let e = try flows(auth).register()
        #expect(try flows(auth).secret(credentialID: e.credentialID, salt: e.salt).testBytes == e.output.testBytes)
        // CTAP 2.0 mit uv: true verlangt bei makeCredential keine UV.
        var old = VirtualAuthenticator.Configuration()
        old.versions = ["FIDO_2_0"]
        old.builtInUV = true
        old.makeCredUvNotRqd = nil
        _ = try flows(VirtualAuthenticator(old)).register()
    }

    @Test func geraetVerlangtPINTrotzAngabe() {
        // Gerät behauptet makeCredUvNotRqd, verlangt aber doch eine PIN.
        var config = VirtualAuthenticator.Configuration()
        config.makeCredUvNotRqd = true
        config.clientPin = true
        let auth = VirtualAuthenticator(config)
        auth.responseMutator = { cmd, bytes in if cmd == CTAPCommand.makeCredential { bytes = [CTAPStatus.puatRequired] } }
        #expect(throws: FIDOError.ctap(CTAPStatus.puatRequired)) { try flows(auth).register() }
        #expect(FIDOError.ctap(CTAPStatus.puatRequired).siegelError == .factorUnavailable(.securityKey))
    }

    @Test func uvFlagInDerAntwortWirdAbgelehnt() throws {
        let auth = VirtualAuthenticator()
        let e = try flows(auth).register()
        auth.config.setUVFlag = true
        #expect(throws: FIDOError.unsupported("uv")) { try flows(auth).secret(credentialID: e.credentialID, salt: e.salt) }
    }

    @Test func gleicheAusgabenFuerBeideSalzeAbgelehnt() {
        var config = VirtualAuthenticator.Configuration()
        config.sameOutputForAllSalts = true
        #expect(throws: FIDOError.response("output.same")) { try flows(VirtualAuthenticator(config)).register() }
    }

    @Test func zuKleineNachrichtengroesse() {
        var config = VirtualAuthenticator.Configuration()
        config.maxMsgSize = 64
        #expect(throws: FIDOError.unsupported("msgsize")) { try flows(VirtualAuthenticator(config)).register() }
    }

    @Test func zuKurzeOderZuLangeCredentialID() {
        for length in [8, 1025] {
            var config = VirtualAuthenticator.Configuration()
            config.credentialIDLength = length
            #expect(throws: FIDOError.self) { try flows(VirtualAuthenticator(config)).register() }
        }
    }

    // MARK: Nutzer

    @Test func abgelehnt() {
        var config = VirtualAuthenticator.Configuration()
        config.presence = .deny
        let auth = VirtualAuthenticator(config)
        #expect(throws: FIDOError.ctap(CTAPStatus.operationDenied)) { try flows(auth).register() }
        #expect(FIDOError.ctap(CTAPStatus.operationDenied).siegelError == .factorCancelled)
    }

    @Test func nichtBeruehrtInnertFrist() {
        var config = VirtualAuthenticator.Configuration()
        config.presence = .timeout
        let auth = VirtualAuthenticator(config)
        let transport = VirtualHIDTransport(auth)
        #expect(throws: FIDOError.userTimeout) { try FIDO2Flows(transport: transport, timeouts: .test).register() }
        #expect(auth.cancels == 1)
        #expect(transport.sentCommands.contains(CTAPHID.Command.cancel))
        #expect(FIDOError.userTimeout.siegelError == .factorCancelled)
    }

    @Test func geraetAntwortetGarNicht() {
        var config = VirtualAuthenticator.Configuration()
        config.presence = .silent
        #expect(throws: FIDOError.userTimeout) { try flows(VirtualAuthenticator(config)).register() }
        let auth = VirtualAuthenticator()
        auth.packetMutator = { $0 = [] }
        #expect(throws: FIDOError.timeout) { try flows(auth).register() }
        #expect(FIDOError.timeout.siegelError == .factorUnavailable(.securityKey))
    }

    @Test func geraetAbgezogen() {
        let auth = VirtualAuthenticator()
        let transport = VirtualHIDTransport(auth)
        transport.failSend = true
        #expect(throws: FIDOError.transport) { try FIDO2Flows(transport: transport, timeouts: .test).register() }
        #expect(FIDOError.transport.siegelError == .factorUnavailable(.securityKey))
    }

    // MARK: Kaputte Antworten

    /// Ersetzt eine CTAP2-Antwort durch neu kodiertes CBOR nach einer Änderung.
    func rewrite(_ auth: VirtualAuthenticator, command: UInt8, _ change: @escaping (CBOR) -> CBOR) {
        auth.responseMutator = { cmd, bytes in
            guard cmd == command, bytes.first == 0, let value = try? CBORDecoder.decode(Array(bytes.dropFirst())),
                  let encoded = try? CBOREncoder.encode(change(value)) else { return }
            bytes = [0] + encoded
        }
    }

    func replacing(_ value: CBOR, key: Int64, with new: CBOR?) -> CBOR {
        var pairs = (value.mapValue ?? []).filter { $0.key != .int(key) }
        if let new { pairs.append(CBORPair(.int(key), new)) }
        return .map(pairs)
    }

    func authData(_ value: CBOR) -> [UInt8] { value[int: 2]?.bytesValue ?? [] }

    @Test func kaputteAssertionen() throws {
        let auth = VirtualAuthenticator()
        let e = try flows(auth).register()
        func expectFailure(_ change: @escaping (CBOR) -> CBOR) {
            rewrite(auth, command: CTAPCommand.getAssertion, change)
            #expect(throws: FIDOError.self) { try flows(auth).secret(credentialID: e.credentialID, salt: e.salt) }
        }
        // rpIdHash falsch
        expectFailure { v in var a = self.authData(v); a[0] ^= 1; return self.replacing(v, key: 2, with: .bytes(a)) }
        // UP fehlt
        expectFailure { v in var a = self.authData(v); a[32] &= ~AuthenticatorData.flagUP; return self.replacing(v, key: 2, with: .bytes(a)) }
        // ED gesetzt, aber Erweiterungen abgeschnitten
        expectFailure { v in self.replacing(v, key: 2, with: .bytes(Array(self.authData(v).prefix(37)))) }
        // Restbytes nach den Erweiterungen
        expectFailure { v in self.replacing(v, key: 2, with: .bytes(self.authData(v) + [0])) }
        // AT in einer Assertion
        expectFailure { v in var a = self.authData(v); a[32] |= AuthenticatorData.flagAT; return self.replacing(v, key: 2, with: .bytes(a)) }
        // fremde credentialID
        expectFailure { v in self.replacing(v, key: 1, with: .map([CBORPair(.text("id"), .bytes([1, 2, 3]))])) }
        // falscher Typ
        expectFailure { v in
            self.replacing(v, key: 1, with: .map([CBORPair(.text("id"), .bytes(Array(e.credentialID))),
                                                   CBORPair(.text("type"), .text("password"))]))
        }
        // Signatur fehlt
        expectFailure { v in self.replacing(v, key: 3, with: nil) }
        // authData fehlt / falscher Typ
        expectFailure { v in self.replacing(v, key: 2, with: nil) }
        expectFailure { v in self.replacing(v, key: 2, with: .text("x")) }
        // hmac-secret-Ausgabe zu kurz / falscher Typ
        expectFailure { v in
            let a = self.authData(v)
            let ext = try? CBORDecoder.decodePrefix(a, at: 37)
            guard let out = ext?.0[text: "hmac-secret"]?.bytesValue else { return v }
            let shorter: CBOR = .map([CBORPair(.text("hmac-secret"), .bytes(Array(out.dropLast(16))))])
            return self.replacing(v, key: 2, with: .bytes(Array(a.prefix(37)) + ((try? CBOREncoder.encode(shorter)) ?? [])))
        }
        expectFailure { v in
            let a = self.authData(v)
            let ext: CBOR = .map([CBORPair(.text("hmac-secret"), .bool(true))])
            return self.replacing(v, key: 2, with: .bytes(Array(a.prefix(37)) + ((try? CBOREncoder.encode(ext)) ?? [])))
        }
        // Antwort leer
        auth.responseMutator = { cmd, bytes in if cmd == CTAPCommand.getAssertion { bytes = [0] } }
        #expect(throws: FIDOError.response("assert.empty")) { try flows(auth).secret(credentialID: e.credentialID, salt: e.salt) }
        // Status ohne Daten, aber nicht 0
        auth.responseMutator = { cmd, bytes in if cmd == CTAPCommand.getAssertion { bytes = [0x7F] } }
        #expect(throws: FIDOError.ctap(0x7F)) { try flows(auth).secret(credentialID: e.credentialID, salt: e.salt) }
        // Nicht-kanonisches CBOR (Schlüssel vertauscht)
        auth.responseMutator = { cmd, bytes in
            if cmd == CTAPCommand.getAssertion { bytes = [0] + hex("a2 02 40 01 40") }
        }
        #expect(throws: FIDOError.cbor(.unorderedKeys)) { try flows(auth).secret(credentialID: e.credentialID, salt: e.salt) }
        // Restbytes hinter dem CBOR
        auth.responseMutator = { cmd, bytes in if cmd == CTAPCommand.getAssertion { bytes += [0] } }
        #expect(throws: FIDOError.cbor(.trailingBytes)) { try flows(auth).secret(credentialID: e.credentialID, salt: e.salt) }
    }

    @Test func kaputteRegistrierungen() throws {
        let auth = VirtualAuthenticator()
        func expectFailure(_ change: @escaping (CBOR) -> CBOR) {
            rewrite(auth, command: CTAPCommand.makeCredential, change)
            #expect(throws: FIDOError.self) { try flows(auth).register() }
        }
        expectFailure { v in var a = self.authData(v); a[5] ^= 1; return self.replacing(v, key: 2, with: .bytes(a)) }
        expectFailure { v in var a = self.authData(v); a[32] &= ~AuthenticatorData.flagAT; return self.replacing(v, key: 2, with: .bytes(a)) }
        expectFailure { v in var a = self.authData(v); a[32] &= ~AuthenticatorData.flagED; return self.replacing(v, key: 2, with: .bytes(a)) }
        expectFailure { v in var a = self.authData(v); a[53] = 0xFF; a[54] = 0xFF; return self.replacing(v, key: 2, with: .bytes(a)) }
        expectFailure { v in self.replacing(v, key: 1, with: nil) }
        expectFailure { v in self.replacing(v, key: 3, with: .array([])) }
        expectFailure { v in
            // hmac-secret: false in den Erweiterungen
            let a = self.authData(v)
            guard let ext = try? CBOREncoder.encode(.map([CBORPair(.text("hmac-secret"), .bool(true))])),
                  let neu = try? CBOREncoder.encode(.map([CBORPair(.text("hmac-secret"), .bool(false))])) else { return v }
            return self.replacing(v, key: 2, with: .bytes(Array(a.dropLast(ext.count)) + neu))
        }
        #expect(auth.credentialCount > 0)
    }

    @Test func kaputteGeraeteinfoUndSchluesselvereinbarung() {
        let auth = VirtualAuthenticator()
        func expectFailure(_ command: UInt8, _ change: @escaping (CBOR) -> CBOR) {
            rewrite(auth, command: command, change)
            #expect(throws: FIDOError.self) { try flows(auth).register() }
        }
        expectFailure(CTAPCommand.getInfo) { v in self.replacing(v, key: 1, with: nil) }
        expectFailure(CTAPCommand.getInfo) { v in self.replacing(v, key: 1, with: .array([.unsigned(1)])) }
        expectFailure(CTAPCommand.getInfo) { v in self.replacing(v, key: 3, with: .bytes([1, 2])) }
        expectFailure(CTAPCommand.getInfo) { v in self.replacing(v, key: 4, with: .map([CBORPair(.text("rk"), .unsigned(1))])) }
        expectFailure(CTAPCommand.getInfo) { v in self.replacing(v, key: 6, with: .array([.text("2")])) }
        expectFailure(CTAPCommand.getInfo) { v in self.replacing(v, key: 6, with: .array([.unsigned(3)])) }
        expectFailure(CTAPCommand.getInfo) { v in self.replacing(v, key: 5, with: .text("viel")) }
        expectFailure(CTAPCommand.clientPIN) { v in .map([]) }
        expectFailure(CTAPCommand.clientPIN) { v in
            .map([CBORPair(.int(1), .map([CBORPair(.int(1), .int(2)), CBORPair(.int(-1), .int(1)),
                                          CBORPair(.int(-2), .bytes([UInt8](repeating: 0, count: 32))),
                                          CBORPair(.int(-3), .bytes([UInt8](repeating: 0, count: 32)))]))])
        }
    }

    @Test func authenticatorDatenStrikt() throws {
        #expect(throws: FIDOError.response("authdata.length")) { try AuthenticatorData.parse([UInt8](repeating: 0, count: 36)) }
        let plain = try AuthenticatorData.parse([UInt8](repeating: 0, count: 32) + [0x01, 0, 0, 0, 7])
        #expect(plain.signCount == 7)
        #expect(plain.extensions == nil)
        #expect(throws: FIDOError.response("authdata.trailing")) {
            try AuthenticatorData.parse([UInt8](repeating: 0, count: 32) + [0x01, 0, 0, 0, 7, 0])
        }
        #expect(throws: FIDOError.cbor(.truncated)) {
            try AuthenticatorData.parse([UInt8](repeating: 0, count: 32) + [0x81, 0, 0, 0, 7])
        }
        #expect(throws: FIDOError.response("authdata.extensions")) {
            try AuthenticatorData.parse([UInt8](repeating: 0, count: 32) + [0x81, 0, 0, 0, 7, 0x80])
        }
        #expect(throws: FIDOError.response("authdata.length")) {
            try AuthenticatorData.parse([UInt8](repeating: 0, count: 4097))
        }
    }
}
