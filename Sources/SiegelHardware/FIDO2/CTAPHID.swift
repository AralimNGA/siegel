import Foundation

/// Transport für CTAPHID-Berichte (je 64 Byte). Die App nutzt `HIDDeviceTransport` (IOHIDManager), Tests einen
/// virtuellen Authenticator.
package protocol CTAPHIDTransport: AnyObject, Sendable {
    /// Schreibt genau einen Ausgabebericht (64 Byte).
    func send(report: [UInt8]) throws
    /// Nächster Eingabebericht oder nil, wenn bis `timeout` nichts kam.
    func receive(timeout: Duration) throws -> [UInt8]?
    func close()
}

/// CTAPHID-Rahmung (CTAP 2.1 §11.2): Init-Paket `CID ‖ CMD ‖ BCNTH ‖ BCNTL ‖ 57 Daten`,
/// Folgepaket `CID ‖ SEQ ‖ 59 Daten`, höchstens 7609 Byte Nutzlast.
package enum CTAPHID {
    package static let reportSize = 64
    package static let initDataSize = 57
    package static let contDataSize = 59
    package static let maxPayload = initDataSize + 128 * contDataSize
    package static let broadcastCID: UInt32 = 0xFFFF_FFFF

    package enum Command {
        package static let ping: UInt8 = 0x81
        package static let msg: UInt8 = 0x83
        package static let initialize: UInt8 = 0x86
        package static let wink: UInt8 = 0x88
        package static let cbor: UInt8 = 0x90
        package static let cancel: UInt8 = 0x91
        package static let keepalive: UInt8 = 0xBB
        package static let error: UInt8 = 0xBF
    }

    package enum Capability {
        package static let wink: UInt8 = 0x01
        package static let cbor: UInt8 = 0x04
        package static let nmsg: UInt8 = 0x08
    }

    package enum ErrorCode {
        package static let invalidCommand: UInt8 = 0x01
        package static let invalidParameter: UInt8 = 0x02
        package static let invalidLength: UInt8 = 0x03
        package static let invalidSequence: UInt8 = 0x04
        package static let messageTimeout: UInt8 = 0x05
        package static let channelBusy: UInt8 = 0x06
        package static let lockRequired: UInt8 = 0x0A
        package static let invalidChannel: UInt8 = 0x0B
        package static let other: UInt8 = 0x7F
    }

    package struct Message: Equatable, Sendable {
        package let cid: UInt32
        package let command: UInt8
        package let payload: [UInt8]
    }

    /// Zerlegt eine Nachricht in 64-Byte-Pakete (aufgefüllt mit Nullen).
    package static func fragment(cid: UInt32, command: UInt8, payload: [UInt8]) throws(FIDOError) -> [[UInt8]] {
        guard command & 0x80 != 0 else { throw .hid("hid.command") }
        guard payload.count <= maxPayload else { throw .hid("hid.length") }
        var packets: [[UInt8]] = []
        var first: [UInt8] = []
        first.reserveCapacity(reportSize)
        first.appendBE32(cid)
        first.append(command)
        first.appendBE16(UInt16(payload.count))
        let head = min(payload.count, initDataSize)
        first += payload[0..<head]
        first += [UInt8](repeating: 0, count: reportSize - first.count)
        packets.append(first)
        var offset = head
        var seq: UInt8 = 0
        while offset < payload.count {
            let n = min(payload.count - offset, contDataSize)
            var p: [UInt8] = []
            p.reserveCapacity(reportSize)
            p.appendBE32(cid)
            p.append(seq)
            p += payload[offset..<(offset + n)]
            p += [UInt8](repeating: 0, count: reportSize - p.count)
            packets.append(p)
            offset += n
            seq += 1
        }
        return packets
    }

    /// Setzt Antworten eines Kanals strikt zusammen. Pakete anderer Kanäle werden übergangen; falsche Länge,
    /// falsche Folgenummer, Folgepaket ohne Anfang oder neuer Anfang mitten in einer Nachricht sind Fehler.
    package struct Reassembler: Sendable {
        package let cid: UInt32
        private var command: UInt8 = 0
        private var expected = 0
        private var buffer: [UInt8] = []
        private var nextSeq: UInt8 = 0
        private var active = false

        package init(cid: UInt32) { self.cid = cid }

        package mutating func feed(_ report: [UInt8]) throws(FIDOError) -> Message? {
            guard report.count == reportSize else { throw .hid("hid.report") }
            guard report.readBE32(at: 0) == cid else { return nil }
            let type = report[4]
            if type & 0x80 != 0 {
                guard !active else { throw .hid("hid.interrupted") }
                let length = Int(report.readBE16(at: 5))
                guard length <= maxPayload else { throw .hid("hid.length") }
                let n = min(length, initDataSize)
                if length <= initDataSize {
                    return Message(cid: cid, command: type, payload: Array(report[7..<(7 + n)]))
                }
                command = type
                expected = length
                buffer = Array(report[7..<(7 + n)])
                buffer.reserveCapacity(length)
                nextSeq = 0
                active = true
                return nil
            }
            guard active else { throw .hid("hid.continuation") }
            guard type == nextSeq else { throw .hid("hid.sequence") }
            let n = min(expected - buffer.count, contDataSize)
            buffer += report[5..<(5 + n)]
            nextSeq += 1
            guard buffer.count == expected else { return nil }
            active = false
            defer { buffer = [] }
            return Message(cid: cid, command: command, payload: buffer)
        }
    }
}

/// Zeitlimits einer CTAPHID-Sitzung.
package struct CTAPHIDTimeouts: Sendable {
    package var initialize: Duration = .seconds(3)
    package var command: Duration = .seconds(5)
    /// Frist für Berührung (SPEC §22: 30 s).
    package var userPresence: Duration = .seconds(30)
    package var cancelDrain: Duration = .milliseconds(500)
    package var busyRetry: Duration = .milliseconds(100)
    /// Höchstens so lange wartet ein Empfang, bevor der Abbruch erneut geprüft wird (v4.4, Befund hardware-4).
    package var cancelPoll: Duration = .milliseconds(100)
    package init() {}
    package static let standard = CTAPHIDTimeouts()
}

/// Ein CTAPHID-Kanal: INIT-Handshake, Senden, strikte Antwort mit KEEPALIVE/ERROR und Fristen.
///
/// Abbruch (v4.4): Ist `cancellation` gesetzt, wartet jeder Empfang höchstens `cancelPoll` am Stück und prüft
/// dazwischen das Token. Ist es gesetzt, wird eine offene Anfrage mit CTAPHID_CANCEL beendet (CTAP 2.1
/// §11.2.9.1.5) und `cancelled` gemeldet – der Schlüssel hört auf zu blinken und ist sofort wieder frei.
final class CTAPHIDChannel {
    let transport: any CTAPHIDTransport
    let timeouts: CTAPHIDTimeouts
    let cancellation: SecurityKeyCancellation?
    private(set) var cid: UInt32 = CTAPHID.broadcastCID
    private(set) var capabilities: UInt8 = 0
    private let clock = ContinuousClock()

    init(transport: any CTAPHIDTransport, timeouts: CTAPHIDTimeouts,
         cancellation: SecurityKeyCancellation? = nil) throws(FIDOError) {
        self.transport = transport
        self.timeouts = timeouts
        self.cancellation = cancellation
        try initialize()
    }

    private var isCancelled: Bool { cancellation?.isCancelled == true }

    private func initialize() throws(FIDOError) {
        let nonce: [UInt8]
        do { nonce = try SecureRandom.bytes(8) } catch { throw .transport }
        try send(cid: CTAPHID.broadcastCID, command: CTAPHID.Command.initialize, payload: nonce)
        let deadline = clock.now.advanced(by: timeouts.initialize)
        var reassembler = CTAPHID.Reassembler(cid: CTAPHID.broadcastCID)
        while true {
            guard let message = try next(&reassembler, deadline: deadline) else { throw .timeout }
            switch message.command {
            case CTAPHID.Command.initialize:
                guard message.payload.count == 17 else { throw .hid("hid.init.length") }
                // Antworten auf fremde INIT-Anfragen (andere Programme) haben eine andere Nonce: übergehen.
                guard Array(message.payload[0..<8]) == nonce else { continue }
                let newCID = message.payload.readBE32(at: 8)
                guard newCID != 0, newCID != CTAPHID.broadcastCID else { throw .hid("hid.init.cid") }
                guard message.payload[12] == 2 else { throw .unsupported("hid.version") }
                capabilities = message.payload[16]
                guard capabilities & CTAPHID.Capability.cbor != 0 else { throw .unsupported("ctap2") }
                cid = newCID
                return
            case CTAPHID.Command.error:
                guard message.payload.count == 1 else { throw .hid("hid.error.length") }
                throw .hidError(message.payload[0])
            case CTAPHID.Command.keepalive:
                continue
            default:
                throw .hid("hid.unexpected")
            }
        }
    }

    /// CTAPHID_CBOR: liefert (Statusbyte, CBOR-Daten). Mit `userPresence` gilt die 30-s-Frist; danach wird die
    /// Anfrage abgebrochen (CTAPHID_CANCEL) und `userTimeout` gemeldet.
    func cbor(_ request: [UInt8], userPresence: Bool) throws(FIDOError) -> (status: UInt8, body: [UInt8]) {
        let response = try transact(command: CTAPHID.Command.cbor, payload: request, userPresence: userPresence)
        guard let status = response.first else { throw .hid("hid.cbor.empty") }
        return (status, Array(response.dropFirst()))
    }

    func transact(command: UInt8, payload: [UInt8], userPresence: Bool) throws(FIDOError) -> [UInt8] {
        let deadline = clock.now.advanced(by: userPresence ? timeouts.userPresence : timeouts.command)
        // Letzte Antwort war ERR_CHANNEL_BUSY (und seither kein KEEPALIVE): Läuft die Frist ab, ist der Schlüssel
        // belegt – nicht „antwortet nicht“ und nicht „nicht berührt“ (v4.4, unabhängig vom Zeitpunkt des Ablaufs).
        var lastWasBusy = false
        while true {
            guard !isCancelled else { throw .cancelled }
            try send(cid: cid, command: command, payload: payload)
            var reassembler = CTAPHID.Reassembler(cid: cid)
            var busy = false
            receiving: while true {
                let received: CTAPHID.Message?
                do throws(FIDOError) {
                    received = try next(&reassembler, deadline: deadline)
                } catch {
                    // Abgebrochen, während die Anfrage offen ist: das Gerät davon befreien.
                    if error == .cancelled { cancel() }
                    throw error
                }
                guard let message = received else {
                    if lastWasBusy { throw .hidError(CTAPHID.ErrorCode.channelBusy) }
                    if userPresence {
                        cancel()
                        throw .userTimeout
                    }
                    throw .timeout
                }
                switch message.command {
                case CTAPHID.Command.keepalive:
                    // 1 = verarbeitet, 2 = wartet auf Berührung. Die Frist läuft weiter.
                    guard message.payload.count == 1, message.payload[0] == 1 || message.payload[0] == 2 else {
                        throw .hid("hid.keepalive")
                    }
                    lastWasBusy = false
                case CTAPHID.Command.error:
                    guard message.payload.count == 1 else { throw .hid("hid.error.length") }
                    if message.payload[0] == CTAPHID.ErrorCode.channelBusy {
                        busy = true
                        lastWasBusy = true
                        break receiving
                    }
                    throw .hidError(message.payload[0])
                case command:
                    return message.payload
                default:
                    throw .hid("hid.unexpected")
                }
            }
            // Kanal belegt (z. B. ein Browser nutzt den Schlüssel): kurz warten, erneut senden, innerhalb der Frist.
            // Hier ist keine eigene Anfrage offen; ein Abbruch braucht darum kein CTAPHID_CANCEL.
            if busy {
                guard clock.now.advanced(by: timeouts.busyRetry) < deadline else { throw .hidError(CTAPHID.ErrorCode.channelBusy) }
                try pause(timeouts.busyRetry)
            }
        }
    }

    /// CTAPHID_CANCEL senden und die Restantwort kurz abwarten (wird verworfen).
    func cancel() {
        guard let packets = try? CTAPHID.fragment(cid: cid, command: CTAPHID.Command.cancel, payload: []) else { return }
        for p in packets { try? transport.send(report: p) }
        let deadline = clock.now.advanced(by: timeouts.cancelDrain)
        var reassembler = CTAPHID.Reassembler(cid: cid)
        while true {
            let left = clock.now.duration(to: deadline)
            guard left > .zero, let report = try? transport.receive(timeout: left) else { return }
            do {
                if let message = try reassembler.feed(report),
                   message.command == CTAPHID.Command.cbor || message.command == CTAPHID.Command.error {
                    return
                }
            } catch {
                reassembler = CTAPHID.Reassembler(cid: cid)
            }
        }
    }

    private func send(cid: UInt32, command: UInt8, payload: [UInt8]) throws(FIDOError) {
        for packet in try CTAPHID.fragment(cid: cid, command: command, payload: payload) {
            do { try transport.send(report: packet) } catch { throw .transport }
        }
    }

    /// Wartet `duration` in Scheiben von höchstens `cancelPoll` und prüft dazwischen den Abbruch.
    private func pause(_ duration: Duration) throws(FIDOError) {
        let end = clock.now.advanced(by: duration)
        while true {
            guard !isCancelled else { throw .cancelled }
            let left = clock.now.duration(to: end)
            guard left > .zero else { return }
            Thread.sleep(forTimeInterval: Self.seconds(min(left, timeouts.cancelPoll)))
        }
    }

    /// Liest Berichte bis zu einer vollständigen Nachricht dieses Kanals oder bis zur Frist (nil). Mit Abbruch-Token
    /// wartet ein Empfang höchstens `cancelPoll` am Stück; ist das Token gesetzt → `cancelled`.
    private func next(_ reassembler: inout CTAPHID.Reassembler, deadline: ContinuousClock.Instant) throws(FIDOError) -> CTAPHID.Message? {
        while true {
            guard !isCancelled else { throw .cancelled }
            let left = clock.now.duration(to: deadline)
            guard left > .zero else { return nil }
            let slice = cancellation == nil ? left : min(left, timeouts.cancelPoll)
            let report: [UInt8]?
            do { report = try transport.receive(timeout: slice) } catch { throw .transport }
            guard let report else { continue }
            if let message = try reassembler.feed(report) { return message }
        }
    }

    static func seconds(_ d: Duration) -> TimeInterval {
        let c = d.components
        return TimeInterval(c.seconds) + TimeInterval(c.attoseconds) / 1e18
    }
}
