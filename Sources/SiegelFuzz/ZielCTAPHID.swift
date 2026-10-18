#if DEBUG
import CryptoKit
import Foundation
import SiegelCore
import Synchronization
@testable import SiegelHardware

/// Entscheidungen eines gestörten Geräts, gelesen aus den Eingabebytes (reproduzierbar: gleiche Eingabe, gleiche
/// Störungen). Sind die Bytes aufgebraucht, stört das Gerät nicht mehr.
final class Steuerung {
    private let bytes: [UInt8]
    private var i = 0
    private(set) var gestoert = false
    /// Ab hier keine Störungen mehr (zweiter Ablauf nach einem Abbruch).
    private var aus = false
    init(_ bytes: [UInt8]) { self.bytes = bytes }

    func abschalten() { aus = true }

    func byte() -> UInt8 {
        guard !aus, i < bytes.count else { return 0xFF }
        defer { i += 1 }
        return bytes[i]
    }

    /// Mit Wahrscheinlichkeit ≈ schwelle/256 stören (und das merken).
    func stoere(_ schwelle: UInt8) -> Bool {
        let s = byte() < schwelle
        if s { gestoert = true }
        return s
    }

    func zahl(_ n: Int) -> Int { n <= 1 ? 0 : Int(byte()) % n }
}

/// Gegenseite eines FIDO2-Sicherheitsschlüssels für den Fuzzer (CTAPHID + CTAP2 mit hmac-secret, PIN/UV-Protokoll
/// 1 und 2), mit Störungen auf Ebene der CBOR-Antwort, der Rohbytes und der HID-Pakete.
final class FuzzGeraet: CTAPHIDTransport, @unchecked Sendable {
    let st: Steuerung
    private let agreement = P256.KeyAgreement.PrivateKey()
    let credRandom = [UInt8](repeating: 0x5C, count: 32)
    var credentialID: [UInt8]
    private var cid: UInt32 = 0x0A0B_0C0D
    private var outbox: [[UInt8]] = []
    private var broadcast = CTAPHID.Reassembler(cid: CTAPHID.broadcastCID)
    private var kanal: CTAPHID.Reassembler
    private let protokolle: [Int]
    var antworten = 0

    init(_ st: Steuerung) {
        self.st = st
        credentialID = [UInt8](repeating: 0xC1, count: [16, 48, 64, 1024][Int(st.byte()) % 4])
        kanal = CTAPHID.Reassembler(cid: 0x0A0B_0C0D)
        protokolle = [[2, 1], [1], [2], [1, 2]][Int(st.byte()) % 4]
    }

    func send(report: [UInt8]) throws {
        if st.stoere(2) { throw FIDOError.transport }
        guard report.count == CTAPHID.reportSize else { return }
        let r = report.readBE32(at: 0)
        do {
            if r == CTAPHID.broadcastCID {
                if let m = try broadcast.feed(report) { antworte(m) }
            } else if r == cid {
                if let m = try kanal.feed(report) { antworte(m) }
            }
        } catch {
            kanal = CTAPHID.Reassembler(cid: cid)
            ausgeben(cid, CTAPHID.Command.error, [CTAPHID.ErrorCode.invalidSequence])
        }
    }

    func receive(timeout: Duration) throws -> [UInt8]? {
        if !outbox.isEmpty { return outbox.removeFirst() }
        let warten = min(CTAPHIDChannel.seconds(timeout), 0.001)
        if warten > 0 { Thread.sleep(forTimeInterval: warten) }
        return nil
    }

    func close() {}

    // MARK: Antworten

    private func ausgeben(_ c: UInt32, _ cmd: UInt8, _ payload: [UInt8]) {
        guard var pakete = try? CTAPHID.fragment(cid: c, command: cmd, payload: payload) else { return }
        // Paket-Störungen
        if !pakete.isEmpty, st.stoere(24) {
            let i = st.zahl(pakete.count)
            switch st.zahl(9) {
            case 0: pakete[i][st.zahl(64)] ^= UInt8(1) << UInt8(st.zahl(8))
            case 1: pakete.remove(at: i)
            case 2: pakete.insert(pakete[i], at: i)
            case 3: if pakete.count > 1 { pakete.swapAt(i, (i + 1) % pakete.count) }
            case 4:
                var fremd = pakete[i]
                fremd[0] ^= 0x40
                pakete.insert(fremd, at: i)
            case 5: pakete[i] = Array(pakete[i].prefix(st.zahl(64)))
            case 6: pakete[i][4] = UInt8(st.zahl(256))
            case 7: pakete[i][5] = UInt8(st.zahl(256)); pakete[i][6] = UInt8(st.zahl(256))
            default:
                pakete.insert((try? CTAPHID.fragment(cid: c, command: CTAPHID.Command.error,
                                                     payload: [CTAPHID.ErrorCode.channelBusy]))?.first ?? [], at: i)
            }
        }
        outbox += pakete
    }

    private func antworte(_ m: CTAPHID.Message) {
        antworten += 1
        if st.stoere(4) { return }      // Stille
        switch m.command {
        case CTAPHID.Command.initialize:
            guard m.payload.count == 8 else { return ausgeben(m.cid, CTAPHID.Command.error, [CTAPHID.ErrorCode.invalidLength]) }
            var p = m.payload
            if st.stoere(6) { p[st.zahl(8)] ^= 1 }          // fremde Nonce
            var neu = cid
            if st.stoere(4) { neu = st.chance0 ? 0 : CTAPHID.broadcastCID }
            p.appendBE32(neu)
            p += [st.stoere(4) ? 1 : 2, 2, 1, 0, st.stoere(4) ? CTAPHID.Capability.wink : 0x05]
            if st.stoere(4) { p = Array(p.prefix(st.zahl(17))) }
            ausgeben(CTAPHID.broadcastCID, CTAPHID.Command.initialize, p)
        case CTAPHID.Command.cbor:
            guard let befehl = m.payload.first else { return }
            for _ in 0..<st.zahl(3) {
                ausgeben(cid, CTAPHID.Command.keepalive, st.stoere(8) ? [UInt8(st.zahl(4)), 0] : [2])
            }
            if st.stoere(4) {
                ausgeben(cid, CTAPHID.Command.error, [st.chance0 ? CTAPHID.ErrorCode.channelBusy : UInt8(st.zahl(256))])
                return
            }
            var antwort = ctap(befehl, Array(m.payload.dropFirst()))
            if st.stoere(10) {
                antwort = [st.chance0 ? CTAPStatus.operationDenied : UInt8(st.zahl(256))]
            } else if st.stoere(16), antwort.count > 1 {
                antwort = [antwort[0]] + Mutator.steuerMutation(Array(antwort.dropFirst()), st)
            }
            ausgeben(cid, CTAPHID.Command.cbor, antwort)
        case CTAPHID.Command.cancel:
            ausgeben(cid, CTAPHID.Command.cbor, [CTAPStatus.keepaliveCancel])
        default:
            ausgeben(m.cid, CTAPHID.Command.error, [CTAPHID.ErrorCode.invalidCommand])
        }
    }

    private func ok(_ v: CBOR) -> [UInt8] { [CTAPStatus.ok] + ((try? CBOREncoder.encode(v)) ?? []) }

    private func ctap(_ befehl: UInt8, _ body: [UInt8]) -> [UInt8] {
        let params = body.isEmpty ? nil : try? CBORDecoder.decode(body)
        switch befehl {
        case CTAPCommand.getInfo:
            var optionen: [CBORPair] = [CBORPair(.text("rk"), .bool(true)), CBORPair(.text("up"), .bool(true))]
            if st.stoere(6) { optionen.append(CBORPair(.text("clientPin"), .bool(true))) }
            if !st.stoere(6) { optionen.append(CBORPair(.text("makeCredUvNotRqd"), .bool(true))) }
            if st.stoere(4) { optionen.append(CBORPair(.text("alwaysUv"), .bool(true))) }
            var karte: [CBORPair] = [
                CBORPair(.int(1), .array((st.stoere(4) ? ["U2F_V2"] : ["FIDO_2_0", "FIDO_2_1"]).map { .text($0) })),
                CBORPair(.int(2), .array((st.stoere(4) ? ["credProtect"] : ["hmac-secret"]).map { .text($0) })),
                CBORPair(.int(3), .bytes([UInt8](repeating: 0xA5, count: 16))),
                CBORPair(.int(4), .map(optionen)),   // der Kodierer ordnet kanonisch
                // maxMsgSize passend zur eigenen Credential-Länge (getAssertion muss hineinpassen)
                CBORPair(.int(5), .int(st.stoere(4) ? 64 : (credentialID.count > 512 ? 2048 : 1200))),
            ]
            karte.append(CBORPair(.int(6), .array(protokolle.map { .int(Int64($0)) })))
            return ok(.map(karte))
        case CTAPCommand.clientPIN:
            guard let p = params?[int: 1]?.intValue, protokolle.contains(Int(p)) else { return [CTAPStatus.invalidParameter] }
            return ok(.map([CBORPair(.int(1), PinUvSession.coseKey(agreement.publicKey))]))
        case CTAPCommand.makeCredential:
            var flags = AuthenticatorData.flagUP | AuthenticatorData.flagAT | AuthenticatorData.flagED
            if st.stoere(4) { flags ^= UInt8(1) << UInt8(st.zahl(8)) }
            var ad = Array(SHA256.hash(data: Data("siegel".utf8))) + [flags, 0, 0, 0, 1]
            ad += [UInt8](repeating: 0xA5, count: 16)
            ad.appendBE16(UInt16(credentialID.count))
            ad += credentialID
            ad += (try? CBOREncoder.encode(PinUvSession.coseKey(P256.KeyAgreement.PrivateKey().publicKey))) ?? []
            ad += (try? CBOREncoder.encode(.map([CBORPair(.text("hmac-secret"), .bool(!st.stoere(4)))]))) ?? []
            return ok(.map([CBORPair(.int(1), .text("none")), CBORPair(.int(2), .bytes(ad)), CBORPair(.int(3), .map([]))]))
        case CTAPCommand.getAssertion:
            guard let params, let input = params[int: 4]?[text: "hmac-secret"], let cose = input[int: 1],
                  let saltEnc = input[int: 2]?.bytesValue,
                  let plattform = try? PinUvSession.publicKey(fromCOSE: cose),
                  let zz = try? agreement.sharedSecretFromKeyAgreement(with: plattform) else {
                return [CTAPStatus.missingParameter]
            }
            let version: PinUvProtocol = input[int: 4]?.intValue == 2 ? .two : .one
            let (_, aes) = PinUvSession.derive(version, z: zz)
            let iv = version == .one ? [UInt8](repeating: 0, count: 16) : Array(saltEnc.prefix(16))
            let koerper = version == .one ? saltEnc : Array(saltEnc.dropFirst(16))
            var salze = [UInt8](repeating: 0, count: koerper.count)
            let entschluesselt = salze.withUnsafeMutableBytes { d in
                koerper.withUnsafeBytes { s in PinUvSession.cbc(encrypt: false, key: aes, iv: iv, input: s, output: d) }
            }
            guard entschluesselt, salze.count == 32 || salze.count == 64 else { return [CTAPStatus.invalidLength] }
            var ausgaben: [UInt8] = []
            for k in 0..<(salze.count / 32) {
                let mac = HMAC<SHA256>.authenticationCode(for: Array(salze[(32 * k)..<(32 * k + 32)]),
                                                          using: SymmetricKey(data: credRandom))
                ausgaben += Array(mac)
            }
            if st.stoere(4) { ausgaben = Array(ausgaben.prefix(32)) + Array(ausgaben.prefix(32)) }   // gleiche Ausgaben
            let outIV = version == .one ? [UInt8](repeating: 0, count: 16) : [UInt8](repeating: 0x1F, count: 16)
            guard let enc = try? PinUvSession.aesCBC(encrypt: true, key: aes, iv: outIV, input: ausgaben) else {
                return [CTAPStatus.invalidParameter]
            }
            var flags = AuthenticatorData.flagUP | AuthenticatorData.flagED
            if st.stoere(4) { flags |= AuthenticatorData.flagUV }
            var ad = Array(SHA256.hash(data: Data("siegel".utf8))) + [flags, 0, 0, 0, 2]
            ad += (try? CBOREncoder.encode(.map([CBORPair(.text("hmac-secret"), .bytes(version == .one ? enc : outIV + enc))]))) ?? []
            let id = st.stoere(4) ? Array(credentialID.dropLast()) : credentialID
            salze.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) }
            return ok(.map([
                CBORPair(.int(1), .map([CBORPair(.text("id"), .bytes(id)), CBORPair(.text("type"), .text("public-key"))])),
                CBORPair(.int(2), .bytes(ad)),
                CBORPair(.int(3), .bytes([UInt8](repeating: 0x30, count: 70))),
            ]))
        default:
            return [CTAPStatus.invalidCommand]
        }
    }
}

extension Steuerung {
    var chance0: Bool { byte() < 128 }
}

extension Mutator {
    /// Byte-Mutation mit Entscheidungen aus der Steuerung.
    static func steuerMutation(_ b: [UInt8], _ st: Steuerung) -> [UInt8] {
        var x = b
        guard !x.isEmpty else { return x }
        switch st.zahl(5) {
        case 0: x[st.zahl(x.count)] ^= UInt8(1) << UInt8(st.zahl(8))
        case 1: x = Array(x.prefix(st.zahl(x.count)))
        case 2: x.insert(st.byte(), at: st.zahl(x.count + 1))
        case 3: x[st.zahl(x.count)] = [0x18, 0x19, 0x1A, 0x1B, 0x1F, 0x9F, 0xBF, 0xFF, 0xF6][st.zahl(9)]
        default: x.remove(at: st.zahl(x.count))
        }
        return x
    }
}

/// Abbruch über `SecurityKeyCancellation` zu einem gefuzzten Zeitpunkt (v4.4, Befund hardware-4): Die Hülle um das
/// Gerät setzt das Token beim n-ten Ereignis (vor dem Start, KEEPALIVE, Antwortpaket, Senden, Stille, Empfang) und
/// hält auf Wunsch die Antwort auf makeCredential/getAssertion zurück (Gerät wartet auf Berührung, sendet KEEPALIVE).
/// Mit `haltezeit` hält sie die Antwort stattdessen so lange zurück und schweigt dabei (manche Schlüssel senden kein
/// KEEPALIVE): Ein Empfang wartet dann wirklich bis zu seinem Zeitlimit, aufgeweckt nur durch CTAPHID_CANCEL – so wird
/// messbar, ob der Kanal das Token zwischen den Empfängen prüft (`cancelPoll`). Das Token kann auch ein zweiter Thread
/// setzen (Wettlauf mit der Oberfläche). Die Hülle protokolliert, ob beim Abbruch eine CBOR-Anfrage offen war, ob danach
/// CTAPHID_CANCEL kam und ob danach noch eine neue CBOR-Anfrage begann. Threadsicher (Zustand unter einer Bedingung).
final class AbbruchHuelle: CTAPHIDTransport, @unchecked Sendable {
    /// 0 vor dem Start, 1 beim n-ten KEEPALIVE, 2 beim n-ten Antwortpaket, 3 beim n-ten Senden, 4 beim n-ten leeren
    /// Empfang (Stille), 5 beim n-ten Empfang überhaupt, 6/7 nie (zweiter Thread)
    let art: UInt8
    let n: Int
    let halten: Int
    /// Sekunden, die das Gerät die Antwort schweigend zurückhält (0 = abwechselnd Stille und KEEPALIVE, `halten`-mal).
    let haltezeit: Double
    let innen: FuzzGeraet
    let token = SecurityKeyCancellation()
    let cid: UInt32 = 0x0A0B_0C0D
    private let bedingung = NSCondition()
    private var _gesetzt = false
    private var _gesetztUm = 0.0
    private var _offen = false
    private var _offenBeimAbbruch = false
    private var _cancelNachAbbruch = false
    private var _anfragenNachAbbruch = 0
    /// Die beim Abbruch offene Anfrage wurde danach doch noch beantwortet (Antwort war schon unterwegs).
    private var _antwortNachAbbruch = false
    private var _gesendet = 0
    private var _haltBeginn = 0.0
    private var empfangen = 0
    private var keepalives = 0
    private var antwortPakete = 0
    private var leer = 0
    private var letzteAnfrage: UInt8 = 0
    private var gehalten: [[UInt8]] = []
    private var halteRest = 0
    private var haltBis = 0.0
    private var antwort: CTAPHID.Reassembler
    /// Wird beim Beginn des Zurückhaltens einmal signalisiert (für den zweiten Thread).
    let haltBegonnen = DispatchSemaphore(value: 0)

    init(art: UInt8, n: Int, halten: Int, haltezeit: Double = 0, innen: FuzzGeraet) {
        self.art = art
        self.n = n
        self.halten = halten
        self.haltezeit = haltezeit
        self.innen = innen
        antwort = CTAPHID.Reassembler(cid: 0x0A0B_0C0D)
    }

    var gesetzt: Bool { bedingung.withLock { _gesetzt } }
    var gesetztUm: Double { bedingung.withLock { _gesetztUm } }
    var offenBeimAbbruch: Bool { bedingung.withLock { _offenBeimAbbruch } }
    var cancelNachAbbruch: Bool { bedingung.withLock { _cancelNachAbbruch } }
    var anfragenNachAbbruch: Int { bedingung.withLock { _anfragenNachAbbruch } }
    var antwortNachAbbruch: Bool { bedingung.withLock { _antwortNachAbbruch } }
    var gesendet: Int { bedingung.withLock { _gesendet } }
    var haltBeginn: Double { bedingung.withLock { _haltBeginn } }

    func abbrechen() {
        bedingung.withLock {
            guard !_gesetzt else { return }
            _gesetzt = true
            _gesetztUm = jetztSekunden()
            _offenBeimAbbruch = _offen
            token.cancel()
        }
    }

    func send(report: [UInt8]) throws {
        var abbruch = false
        bedingung.withLock {
            _gesendet += 1
            if report.count == CTAPHID.reportSize, report.readBE32(at: 0) == cid {
                if report[4] == CTAPHID.Command.cbor {
                    if _gesetzt { _anfragenNachAbbruch += 1 }
                    _offen = true
                    letzteAnfrage = report[7]
                } else if report[4] == CTAPHID.Command.cancel {
                    if _gesetzt { _cancelNachAbbruch = true }
                    // Das Gerät bricht die wartende Anfrage ab: zurückgehaltene Antwort verwerfen, Warten beenden.
                    gehalten = []
                    halteRest = 0
                    haltBis = 0
                    bedingung.broadcast()
                }
            }
            abbruch = art == 3 && _gesendet == n
        }
        if abbruch { abbrechen() }
        try innen.send(report: report)
    }

    func receive(timeout: Duration) throws -> [UInt8]? {
        bedingung.lock()
        empfangen += 1
        var paket: [UInt8]?
        if haltBis > 0 {
            // Schweigend auf Berührung warten: bis zum Zeitlimit dieses Empfangs bzw. bis CTAPHID_CANCEL.
            let ende = min(jetztSekunden() + CTAPHIDChannel.seconds(timeout), haltBis)
            while haltBis > 0, jetztSekunden() < ende {
                _ = bedingung.wait(until: Date(timeIntervalSinceNow: max(0, ende - jetztSekunden())))
            }
            if haltBis > 0, jetztSekunden() >= haltBis {
                haltBis = 0
                paket = gehalten.isEmpty ? nil : gehalten.removeFirst()
            }
        } else if halteRest > 0 {
            // Warten auf Berührung: abwechselnd Stille und KEEPALIVE (2)
            halteRest -= 1
            paket = halteRest % 2 == 1 ? nil
                : (try? CTAPHID.fragment(cid: cid, command: CTAPHID.Command.keepalive, payload: [2]))?.first
        } else if !gehalten.isEmpty {
            paket = gehalten.removeFirst()
        } else {
            bedingung.unlock()
            paket = try innen.receive(timeout: timeout)
            bedingung.lock()
            if let p = paket, p.count == CTAPHID.reportSize, p.readBE32(at: 0) == cid, p[4] == CTAPHID.Command.cbor,
               halten > 0, letzteAnfrage == 0x01 || letzteAnfrage == 0x02 {
                // Gerät wartet auf Berührung: Antwort zurückhalten, solange KEEPALIVE (2) senden bzw. schweigen
                gehalten = [p]
                letzteAnfrage = 0
                _haltBeginn = jetztSekunden()
                haltBegonnen.signal()
                if haltezeit > 0 {
                    haltBis = jetztSekunden() + haltezeit
                    paket = nil
                } else {
                    halteRest = 2 * halten - 1
                    paket = (try? CTAPHID.fragment(cid: cid, command: CTAPHID.Command.keepalive, payload: [2]))?.first
                }
            }
        }
        var abbruch = false
        if let p = paket, p.count == CTAPHID.reportSize, p.readBE32(at: 0) == cid {
            if p[4] == CTAPHID.Command.keepalive {
                keepalives += 1
                abbruch = art == 1 && keepalives == n
            } else {
                antwortPakete += 1
                do {
                    if let m = try antwort.feed(p), m.command == CTAPHID.Command.cbor || m.command == CTAPHID.Command.error {
                        // Nur die Antwort auf die Anfrage selbst, nicht die auf CTAPHID_CANCEL (KEEPALIVE_CANCEL).
                        if _offen, _gesetzt, !_cancelNachAbbruch { _antwortNachAbbruch = true }
                        _offen = false
                    }
                } catch {
                    antwort = CTAPHID.Reassembler(cid: cid)
                }
                abbruch = art == 2 && antwortPakete == n
            }
        } else if paket == nil {
            leer += 1
            abbruch = art == 4 && leer == n
        }
        if art == 5, empfangen == n { abbruch = true }
        bedingung.unlock()
        if abbruch { abbrechen() }
        return paket
    }

    func close() {}
}

/// Ziel „ctaphid“: CTAPHID-Rahmung (Pakete zusammensetzen) und die ganzen FIDO2-Abläufe gegen ein gestörtes Gerät.
///
/// Rahmung: Byte 0 = Art (0 Reassembler mit Rohpaketen, 1 Zerlegen ↔ Zusammensetzen, 2 Registrieren, 3 Ausgabe holen,
/// 4 Registrieren mit Abbruch, 5 Ausgabe holen mit Abbruch, 6 Abbruch aus einem zweiten Thread nach 0–50 ms (Wettlauf),
/// 7 Abbruch aus einem zweiten Thread, während das Gerät schweigend auf Berührung wartet), danach Bytes (Pakete bzw.
/// Steuerbytes für die Störungen des Geräts; bei 4/5 zuerst Abbruch-Art, n, Halten, Störungen an/aus; bei 6/7
/// Registrieren/Ausgabe, Verzögerung, Halten).
/// Abbruch (4–7): ergibt `factorCancelled` (Erfolg nur, wenn das Token erst nach der letzten Antwort kam), endet
/// innert einer Sekunde (Art 7: innert 0,25 s nach dem Setzen, ×2 unter ASan – das Gerät schweigt 1,5 s, nur die
/// `cancelPoll`-Scheiben des Kanals erkennen das Token), beginnt danach keine neue CBOR-Anfrage (keine halbe
/// Registrierung), sendet CTAPHID_CANCEL, wenn eine Anfrage offen war, und vor dem Start geht gar nichts ans Gerät.
/// Danach liefert ein zweiter, ungestörter Ablauf auf demselben Gerät genau HMAC(credRandom, Salz) (keine Restantwort
/// des Abbruchs stört ihn).
/// Invarianten: kein Absturz/Hänger (alle Fristen halten); Nachrichten haben genau die angekündigte Länge; ein
/// ungestörtes Gerät liefert genau HMAC(credRandom, Salz); jedes Scheitern wird nach aussen zu
/// `factorUnavailable(.securityKey)`, `factorCancelled`, `wrongSecurityKey` oder `factorTemporarilyUnavailable(.securityKey,
/// "fido.busy")` (v4.4).
final class ZielCTAPHID: FuzzZiel {
    let name = "ctaphid"
    let zeitlimit = 8.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 8)
    var zusatz: [String: Int] = [:]

    static let fristen: CTAPHIDTimeouts = {
        var t = CTAPHIDTimeouts()
        t.initialize = .milliseconds(500)
        t.command = .milliseconds(500)
        t.userPresence = .milliseconds(800)
        t.cancelDrain = .milliseconds(30)
        t.busyRetry = .milliseconds(5)
        t.cancelPoll = .milliseconds(20)
        return t
    }()

    func vorbereiten(_ u: Umgebung) throws {
        korpus.saatAufnehmen([2] + [UInt8](repeating: 0xFF, count: 8))
        korpus.saatAufnehmen([3] + [UInt8](repeating: 0xFF, count: 8))
        korpus.saatAufnehmen([2, 0, 1] + [UInt8](repeating: 0xFF, count: 8))
        korpus.saatAufnehmen([3, 3, 2] + [UInt8](repeating: 0x80, count: 64))
        korpus.saatAufnehmen([1, 0x1D, 0xB9])
        for art in 0..<6 {
            korpus.saatAufnehmen([4, UInt8(art), 2, 3, 0, 1, 2])
            korpus.saatAufnehmen([5, UInt8(art), 1, 0, 0, 0, 0])
        }
        for d: UInt8 in [0, 10, 25, 50] {
            korpus.saatAufnehmen([6, 0, d, 2, 0, 1])
            korpus.saatAufnehmen([6, 1, d, 1, 1, 2])
            korpus.saatAufnehmen([7, d & 1, d, 1, 0, 1])
        }
        let msg = (try? CTAPHID.fragment(cid: 7, command: CTAPHID.Command.cbor, payload: [UInt8](repeating: 3, count: 300))) ?? []
        korpus.saatAufnehmen([0] + msg.joined())
        // Selbsttest: ungestörtes Gerät
        for art: UInt8 in [2, 3] {
            let c = try pruefe([art, 0, 0] + [UInt8](repeating: 0xFF, count: 64))
            guard c.hasSuffix(":ok") else { throw Fund("saat", "ungestörtes Gerät: \(c)") }
        }
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    func naechste(_ z: inout Zufall) -> [UInt8] {
        if z.chance(0.3) {
            let art = UInt8(z.pick([0, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7]))
            let n = art >= 2 ? z.int(8...120) : z.int(64...640)
            return [art] + z.bytes(n)
        }
        let basis = korpus.waehle(&z)
        return [basis.first ?? 0] + Mutator.bytes(Array(basis.dropFirst()), &z, maxLaenge: 32 << 10)
    }

    private static func pruefeAbbildung(_ f: FIDOError) throws {
        let s = f.siegelError
        // v4.4: auch `wrongSecurityKey` (0x2E) und `factorTemporarilyUnavailable(.securityKey, "fido.busy")`.
        guard FIDOError.isAllowedOutward(s), s != .crypto("fido.input") else {
            throw Fund("fehlertyp", "FIDO-Fehler nach aussen: " + fehlerCode(s))
        }
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard let art = e.first else { return "leer" }
        let b = Array(e.dropFirst())
        switch art % 8 {
        case 4, 5:
            return try abbruch(b, registrieren: art % 8 == 4)
        case 6, 7:
            return try abbruchThread(b, schweigen: art % 8 == 7)
        case 0:
            var r = CTAPHID.Reassembler(cid: b.count >= 4 ? b.readBE32(at: 0) : 7)
            var n = 0
            var i = 0
            while i < b.count {
                let laenge = (b[i] & 0x07) == 0 ? max(1, Int(b[i] >> 3)) : 64
                let bericht = Array(b[i..<min(b.count, i + laenge)])
                i += laenge
                do {
                    if let m = try r.feed(bericht) {
                        n += 1
                        guard m.payload.count <= CTAPHID.maxPayload else { throw Fund("ctaphid", "Nachricht zu lang") }
                    }
                } catch let f as FIDOError {
                    try Self.pruefeAbbildung(f)
                    r = CTAPHID.Reassembler(cid: r.cid)
                }
            }
            return "reassembler:\(min(n, 3))"
        case 1:
            let laenge = b.count >= 2 ? Int(b.readBE16(at: 0)) : 0
            let nutz = [UInt8](repeating: 0x5A, count: laenge)
            do {
                let pakete = try CTAPHID.fragment(cid: 0x0102_0304, command: CTAPHID.Command.cbor, payload: nutz)
                var r = CTAPHID.Reassembler(cid: 0x0102_0304)
                var ergebnis: CTAPHID.Message?
                for p in pakete {
                    guard ergebnis == nil else { throw Fund("ctaphid", "Nachricht vor dem letzten Paket fertig") }
                    ergebnis = try r.feed(p)
                }
                guard let ergebnis, ergebnis.payload == nutz, ergebnis.command == CTAPHID.Command.cbor else {
                    throw Fund("ctaphid", "Zerlegen ↔ Zusammensetzen nicht gleich")
                }
                return "fragment:ok"
            } catch let f as FIDOError {
                guard laenge > CTAPHID.maxPayload else { throw Fund("ctaphid", "gültige Länge abgelehnt: " + fehlerCode(f)) }
                return "fragment:zuLang"
            }
        default:
            let st = Steuerung(b)
            let geraet = FuzzGeraet(st)
            let t0 = jetztSekunden()
            defer {
                if jetztSekunden() - t0 > 4 { zusatz["ablauf_ueber_4s", default: 0] += 1 }
            }
            do {
                let flows = FIDO2Flows(transport: geraet, timeouts: Self.fristen)
                if art % 8 == 2 {
                    let en = try flows.register()
                    let ausgabe = en.output.withUnsafeBytes { Array($0) }
                    let eintrag = en.entryOutput.withUnsafeBytes { Array($0) }
                    guard FIDO2Flows.credentialIDRange.contains(en.credentialID.count), en.salt.count == 32,
                          en.entrySalt.count == 32, ausgabe != eintrag else {
                        throw Fund("fido", "Registrierung mit unplausiblem Ergebnis")
                    }
                    if !st.gestoert {
                        let soll = Array(HMAC<SHA256>.authenticationCode(for: Array(en.salt), using: SymmetricKey(data: geraet.credRandom)))
                        guard soll == ausgabe else { throw Fund("fido", "ungestörtes Gerät, falsche Ausgabe") }
                    }
                    return "register:" + (st.gestoert ? "ok-gestoert" : "ok")
                } else {
                    let salz = [UInt8](repeating: 0x77, count: 32)
                    let s = try flows.secret(credentialID: Data(geraet.credentialID), salt: Data(salz))
                    if !st.gestoert {
                        let soll = Array(HMAC<SHA256>.authenticationCode(for: salz, using: SymmetricKey(data: geraet.credRandom)))
                        guard soll == s.withUnsafeBytes({ Array($0) }) else { throw Fund("fido", "ungestörtes Gerät, falsche Ausgabe") }
                    }
                    return "secret:" + (st.gestoert ? "ok-gestoert" : "ok")
                }
            } catch let f as FIDOError {
                try Self.pruefeAbbildung(f)
                if !st.gestoert { throw Fund("fido", "ungestörtes Gerät, trotzdem Fehler " + fehlerCode(f)) }
                return (art % 8 == 2 ? "register:" : "secret:") + fehlerCode(f)
            }
        }
    }

    /// Abbruch über `SecurityKeyCancellation` zu einem gefuzzten Zeitpunkt (Rahmung: Abbruch-Art, n, Halten,
    /// Störungen, danach Steuerbytes des Geräts).
    private func abbruch(_ b: [UInt8], registrieren: Bool) throws -> String {
        let art = (b.first ?? 0) % 6
        let n = Int(b.count > 1 ? b[1] : 1) % 40 + 1
        let halten = Int(b.count > 2 ? b[2] : 0) % 8
        let stoeren = b.count > 3 && b[3] & 1 == 1
        // Ohne Störungen: nur die zwei Bytes für Credential-Länge und PIN/UV-Protokolle, danach ungestört.
        let steuer = Array(b.dropFirst(4).prefix(stoeren ? Int.max : 2))
        let st = Steuerung(steuer)
        let geraet = FuzzGeraet(st)
        let huelle = AbbruchHuelle(art: art, n: n, halten: halten, innen: geraet)
        if art == 0 { huelle.abbrechen() }
        let flows = FIDO2Flows(transport: huelle, timeouts: Self.fristen, cancellation: huelle.token)
        var fehler: FIDOError?
        var erfolg = false
        do {
            if registrieren {
                let en = try flows.register()
                let ausgabe = en.output.withUnsafeBytes { Array($0) }
                if !st.gestoert {
                    let soll = Array(HMAC<SHA256>.authenticationCode(for: Array(en.salt), using: SymmetricKey(data: geraet.credRandom)))
                    guard soll == ausgabe, FIDO2Flows.credentialIDRange.contains(en.credentialID.count) else {
                        throw Fund("abbruch", "Registrierung nach Abbruch unvollständig oder falsch")
                    }
                }
            } else {
                let salz = [UInt8](repeating: 0x77, count: 32)
                let s = try flows.secret(credentialID: Data(geraet.credentialID), salt: Data(salz))
                if !st.gestoert {
                    let soll = Array(HMAC<SHA256>.authenticationCode(for: salz, using: SymmetricKey(data: geraet.credRandom)))
                    guard soll == s.withUnsafeBytes({ Array($0) }) else { throw Fund("abbruch", "falsche Ausgabe nach Abbruch") }
                }
            }
            erfolg = true
        } catch let f as FIDOError {
            try Self.pruefeAbbildung(f)
            fehler = f
        }
        let ende = jetztSekunden()
        let ablauf = registrieren ? "register" : "secret"
        guard huelle.gesetzt else {
            // Der Abbruch kam nie (n zu gross): wie ein gewöhnlicher Ablauf.
            if !st.gestoert, let fehler { throw Fund("fido", "ungestörtes Gerät ohne Abbruch, trotzdem " + fehlerCode(fehler)) }
            return ablauf + ":ohneAbbruch:" + (fehler.map { fehlerCode($0) } ?? "ok")
        }
        if art == 0, huelle.gesendet != 0 { throw Fund("abbruch", "vor dem Start abgebrochen, trotzdem ans Gerät gesendet") }
        if huelle.anfragenNachAbbruch > 0 {
            throw Fund("abbruch", "nach dem Abbruch noch \(huelle.anfragenNachAbbruch) neue CBOR-Anfrage(n) (halbe Registrierung)")
        }
        if ende - huelle.gesetztUm > 1.0 * (Waechter.mitASan ? 4 : 1) {
            zusatz["abbruch_langsam", default: 0] += 1
            throw Fund("abbruch", String(format: "Abbruch erst nach %.2f s wirksam", ende - huelle.gesetztUm))
        }
        if !st.gestoert {
            if erfolg {
                guard !huelle.offenBeimAbbruch else {
                    throw Fund("abbruch", "Anfrage war beim Abbruch offen, trotzdem Erfolg")
                }
            } else if let fehler, fehler.siegelError != .factorCancelled {
                throw Fund("abbruch", "Abbruch ergibt " + fehlerCode(fehler.siegelError) + " statt factorCancelled")
            }
            if huelle.offenBeimAbbruch, !huelle.cancelNachAbbruch {
                throw Fund("abbruch", "Anfrage offen beim Abbruch, aber kein CTAPHID_CANCEL")
            }
            try zweiterAblauf(geraet)
        }
        return ablauf + ":abbruch\(art):" + (erfolg ? "ok" : fehlerCode(fehler.map(\.siegelError) ?? .factorCancelled))
            + (huelle.offenBeimAbbruch ? ":offen" : "")
    }

    /// Nach einem Abbruch: ein ungestörter `secret`-Ablauf auf demselben Gerät liefert genau HMAC(credRandom, Salz).
    private func zweiterAblauf(_ geraet: FuzzGeraet) throws {
        geraet.st.abschalten()
        let salz = [UInt8](repeating: 0x66, count: 32)
        do {
            let s = try FIDO2Flows(transport: geraet, timeouts: Self.fristen).secret(credentialID: Data(geraet.credentialID),
                                                                                     salt: Data(salz))
            let soll = Array(HMAC<SHA256>.authenticationCode(for: salz, using: SymmetricKey(data: geraet.credRandom)))
            guard soll == s.withUnsafeBytes({ Array($0) }) else { throw Fund("abbruch", "zweiter Ablauf nach dem Abbruch: falsche Ausgabe") }
        } catch let f as FIDOError {
            throw Fund("abbruch", "zweiter Ablauf nach dem Abbruch scheitert: " + fehlerCode(f.siegelError))
        }
    }

    /// Fristen für Art 7: Berührung bis 3 s (das Gerät schweigt 1,5 s), sonst wie `fristen`.
    static let fristenLang: CTAPHIDTimeouts = {
        var t = fristen
        t.userPresence = .seconds(3)
        return t
    }()

    /// Abbruch aus einem zweiten Thread (Rahmung: Registrieren ‖ Verzögerung ms ‖ Halten): Art 6 nach 0–50 ms ab
    /// dem Start (Wettlauf an beliebiger Stelle, nicht deterministisch), Art 7 0–50 ms nach Beginn des schweigenden
    /// Wartens auf Berührung (Antwortzeit messbar). Ungestörtes Gerät, danach ein zweiter Ablauf.
    private func abbruchThread(_ b: [UInt8], schweigen: Bool) throws -> String {
        let registrieren = (b.first ?? 0) & 1 == 1
        let verzoegerung = Double(Int(b.count > 1 ? b[1] : 0) % 51) / 1000
        let halten = schweigen ? 1 : Int(b.count > 2 ? b[2] : 0) % 8
        let st = Steuerung(Array(b.dropFirst(3).prefix(2)))
        let geraet = FuzzGeraet(st)
        let huelle = AbbruchHuelle(art: schweigen ? 7 : 6, n: 0, halten: halten, haltezeit: schweigen ? 1.5 : 0,
                                   innen: geraet)
        let fertig = DispatchSemaphore(value: 0)
        let ende = Atomic<Bool>(false)
        Thread.detachNewThread {
            if schweigen {
                // Auf den Beginn des Wartens warten (höchstens bis zum Ende des Ablaufs).
                while !ende.load(ordering: .acquiring), huelle.haltBegonnen.wait(timeout: .now() + .milliseconds(20)) == .timedOut {}
            }
            if !ende.load(ordering: .acquiring) {
                Thread.sleep(forTimeInterval: verzoegerung)
                if !ende.load(ordering: .acquiring) { huelle.abbrechen() }
            }
            fertig.signal()
        }
        let flows = FIDO2Flows(transport: huelle, timeouts: schweigen ? Self.fristenLang : Self.fristen,
                               cancellation: huelle.token)
        var fehler: FIDOError?
        var erfolg = false
        do {
            if registrieren {
                let en = try flows.register()
                let soll = Array(HMAC<SHA256>.authenticationCode(for: Array(en.salt), using: SymmetricKey(data: geraet.credRandom)))
                guard soll == en.output.withUnsafeBytes({ Array($0) }) else { throw Fund("abbruch", "Registrierung falsch") }
            } else {
                let salz = [UInt8](repeating: 0x77, count: 32)
                let s = try flows.secret(credentialID: Data(geraet.credentialID), salt: Data(salz))
                let soll = Array(HMAC<SHA256>.authenticationCode(for: salz, using: SymmetricKey(data: geraet.credRandom)))
                guard soll == s.withUnsafeBytes({ Array($0) }) else { throw Fund("abbruch", "falsche Ausgabe") }
            }
            erfolg = true
        } catch let f as FIDOError {
            try Self.pruefeAbbildung(f)
            fehler = f
        }
        let t = jetztSekunden()
        ende.store(true, ordering: .releasing)
        fertig.wait()
        let ablauf = (registrieren ? "register" : "secret") + ":thread\(schweigen ? 7 : 6)"
        guard huelle.gesetzt, huelle.gesetztUm <= t else {
            if let fehler { throw Fund("fido", "ungestörtes Gerät ohne Abbruch, trotzdem " + fehlerCode(fehler)) }
            return ablauf + ":ohneAbbruch"
        }
        // Wettlauf (Art 6): Das Token kann zwischen der Prüfung vor dem Senden und dem Senden selbst kommen – höchstens
        // diese eine Anfrage, und sie wird mit CTAPHID_CANCEL beendet. Art 7 (Abbruch während des Wartens): keine.
        let n = huelle.anfragenNachAbbruch
        if n > (schweigen ? 0 : 1) {
            throw Fund("abbruch", "nach dem Abbruch noch \(n) neue CBOR-Anfrage(n) (halbe Registrierung)")
        }
        if n == 1, !huelle.cancelNachAbbruch {
            throw Fund("abbruch", "Anfrage im Wettlauf mit dem Abbruch, aber kein CTAPHID_CANCEL")
        }
        if n == 1 { zusatz["abbruch_wettlauf_anfrage", default: 0] += 1 }
        let grenze = schweigen ? 0.25 * (Waechter.mitASan ? 2 : 1) : 1.0 * (Waechter.mitASan ? 4 : 1)
        if t - huelle.gesetztUm > grenze {
            zusatz["abbruch_langsam", default: 0] += 1
            throw Fund("abbruch", String(format: "Abbruch aus dem zweiten Thread erst nach %.2f s wirksam", t - huelle.gesetztUm))
        }
        // Wettlauf (Art 6): Kam das Token, während die Antwort schon unterwegs war, nimmt der Kanal sie noch an (er prüft
        // vor jedem Empfang, nicht danach) – dann ist nichts mehr offen, und weder Erfolg noch ein fehlendes
        // CTAPHID_CANCEL ist ein Fehler. Im Warten auf Berührung (Art 7) kommt keine Antwort.
        let unterwegs = huelle.offenBeimAbbruch && huelle.antwortNachAbbruch
        if unterwegs {
            guard !schweigen else { throw Fund("abbruch", "Antwort trotz schweigendem Gerät") }
            zusatz["abbruch_wettlauf_antwort_unterwegs", default: 0] += 1
        }
        if erfolg, huelle.offenBeimAbbruch, !unterwegs {
            throw Fund("abbruch", "Anfrage war beim Abbruch offen, trotzdem Erfolg")
        } else if !erfolg, let fehler, fehler.siegelError != .factorCancelled {
            throw Fund("abbruch", "Abbruch ergibt " + fehlerCode(fehler.siegelError) + " statt factorCancelled")
        }
        if !erfolg, huelle.offenBeimAbbruch, !unterwegs, !huelle.cancelNachAbbruch {
            throw Fund("abbruch", "Anfrage offen beim Abbruch, aber kein CTAPHID_CANCEL")
        }
        try zweiterAblauf(geraet)
        if schweigen { zusatz["abbruch_im_warten", default: 0] += huelle.haltBeginn > 0 ? 1 : 0 }
        return ablauf + ":" + (erfolg ? "ok" : "abgebrochen") + (huelle.offenBeimAbbruch ? ":offen" : "")
    }
}
#endif
