#if DEBUG
import CryptoKit
import Foundation
import SiegelCore
@testable import SiegelHardware

/// Ziel „cbor“: strikter CBOR-Dekodierer und die CTAP2-Antwort-Parser (SPEC §14.3) – Daten vom USB-Gerät sind
/// Angriffsfläche.
///
/// Rahmung: Byte 0 = Art (0 CBOR, 1 getInfo, 2 authenticatorData, 3 COSE-Schlüssel, 4 CBOR ab Versatz), danach Bytes.
/// Invarianten: kein Absturz/Hänger (Tiefe, Anzahl, Längen begrenzt); was angenommen wird, kodiert der Kodierer
/// Byte für Byte gleich zurück (nur kanonische Form); Fehler der Abläufe werden nach aussen nur zu
/// `factorUnavailable(.securityKey)`, `factorCancelled`, `wrongSecurityKey`, `factorTemporarilyUnavailable(.securityKey,
/// "fido.busy")` oder `crypto("fido.input")` (v4.4).
final class ZielCBOR: FuzzZiel {
    let name = "cbor"
    let zeitlimit = 5.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 7)
    var zusatz: [String: Int] = [:]
    private var baeume: [CBOR] = []

    static func authData(credLaenge: Int, mitKey: Bool, ext: CBOR?) -> [UInt8] {
        var flags = AuthenticatorData.flagUP
        if mitKey { flags |= AuthenticatorData.flagAT }
        if ext != nil { flags |= AuthenticatorData.flagED }
        var b = Array(SHA256.hash(data: Data("siegel".utf8))) + [flags, 0, 0, 0, 7]
        if mitKey {
            b += [UInt8](repeating: 0xA5, count: 16)
            b.appendBE16(UInt16(credLaenge))
            b += [UInt8](repeating: 0x33, count: credLaenge)
            let k = (try? P256.KeyAgreement.PrivateKey(rawRepresentation: [UInt8](repeating: 0x2B, count: 32)))
                ?? P256.KeyAgreement.PrivateKey()
            b += (try? CBOREncoder.encode(PinUvSession.coseKey(k.publicKey))) ?? []
        }
        if let ext { b += (try? CBOREncoder.encode(ext)) ?? [] }
        return b
    }

    func vorbereiten(_ u: Umgebung) throws {
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: [UInt8](repeating: 0x2A, count: 32)).publicKey
        let info: CBOR = .map([
            CBORPair(.int(1), .array([.text("FIDO_2_0"), .text("FIDO_2_1")])),
            CBORPair(.int(2), .array([.text("hmac-secret")])),
            CBORPair(.int(3), .bytes([UInt8](repeating: 1, count: 16))),
            CBORPair(.int(4), .map([CBORPair(.text("rk"), .bool(true)), CBORPair(.text("clientPin"), .bool(false)),
                                    CBORPair(.text("makeCredUvNotRqd"), .bool(true))])),
            CBORPair(.int(5), .int(1200)),
            CBORPair(.int(6), .array([.int(2), .int(1)])),
        ])
        let cose = PinUvSession.coseKey(key)
        let assertion: CBOR = .map([
            CBORPair(.int(1), .map([CBORPair(.text("id"), .bytes([UInt8](repeating: 2, count: 64))),
                                    CBORPair(.text("type"), .text("public-key"))])),
            CBORPair(.int(2), .bytes(Self.authData(credLaenge: 0, mitKey: false,
                                                   ext: .map([CBORPair(.text("hmac-secret"), .bytes([UInt8](repeating: 9, count: 80)))])))),
            CBORPair(.int(3), .bytes([UInt8](repeating: 4, count: 71))),
        ])
        baeume = [info, cose, assertion, .map([CBORPair(.int(1), cose)]), .array([.int(-1), .negative(UInt64.max), .null])]
        korpus.saatAufnehmen([0] + (try CBOREncoder.encode(info)))
        korpus.saatAufnehmen([1] + (try CBOREncoder.encode(info)))
        korpus.saatAufnehmen([3] + (try CBOREncoder.encode(cose)))
        korpus.saatAufnehmen([0] + (try CBOREncoder.encode(assertion)))
        for (l, k, e) in [(16, true, true), (64, true, false), (1024, true, true), (0, false, true)] {
            let ad = Self.authData(credLaenge: l, mitKey: k, ext: e ? .map([CBORPair(.text("hmac-secret"), .bool(true))]) : nil)
            korpus.saatAufnehmen([2] + ad)
        }
        korpus.saatAufnehmen([4, 3] + Array(repeating: 0, count: 3) + (try CBOREncoder.encode(cose)))
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    // MARK: Erzeugen

    /// Locker kodieren: nicht minimale Längen, unbestimmte Längen, Tags, Fliesskomma, ungeordnete/doppelte Schlüssel.
    private func locker(_ v: CBOR, _ z: inout Zufall, tiefe: Int = 0) -> [UInt8] {
        var out: [UInt8] = []
        func kopf(_ major: UInt8, _ wert: UInt64) {
            if z.chance(0.05), wert < 0x1_0000 {
                out.append(major << 5 | 25)
                out.append(UInt8(wert >> 8)); out.append(UInt8(wert & 0xFF))
            } else {
                CBOREncoder.head(major, wert, into: &out)
            }
        }
        if z.chance(0.02) { out += [0xC0 | UInt8(z.int(0...23))] }          // Tag
        switch v {
        case let .unsigned(u): kopf(0, u)
        case let .negative(n): kopf(1, n)
        case let .bytes(b):
            if z.chance(0.03) { out += [0x5F, 0x40 | UInt8(min(b.count, 23))] + b.prefix(23) + [0xFF] } else { kopf(2, UInt64(b.count)); out += b }
        case let .text(t):
            let u = Array(t.utf8)
            kopf(3, UInt64(u.count)); out += u
        case let .array(a):
            let unbestimmt = z.chance(0.03)
            if unbestimmt { out.append(0x9F) } else { kopf(4, UInt64(a.count)) }
            for x in a { out += locker(x, &z, tiefe: tiefe + 1) }
            if unbestimmt { out.append(0xFF) }
        case let .map(p):
            var paare = p
            if z.chance(0.05), paare.count > 1 { paare.swapAt(0, paare.count - 1) }
            if z.chance(0.03), let erstes = paare.first { paare.append(erstes) }
            kopf(5, UInt64(paare.count))
            for x in paare { out += locker(x.key, &z, tiefe: tiefe + 1); out += locker(x.value, &z, tiefe: tiefe + 1) }
        case let .bool(b): out.append(b ? 0xF5 : 0xF4)
        case .null: out.append(z.chance(0.05) ? 0xF7 : 0xF6)
        }
        if z.chance(0.01) { out += [0xFB] + z.bytes(8) }
        return out
    }

    private func zufallsKnoten(_ z: inout Zufall, tiefe: Int) -> CBOR {
        switch z.int(9) {
        case 0: return .unsigned(z.pick([0, 23, 24, 255, 256, 65_535, 65_536, UInt64(UInt32.max), UInt64.max]))
        case 1: return .negative(z.pick([0, 23, 24, UInt64.max]))
        case 2: return .bytes(z.bytes(z.pick([0, 1, 15, 16, 31, 32, 33, 64, 65, 8192, 8193])))
        case 3: return .text(String(repeating: z.pick(["a", "é", "😀"]), count: z.pick([0, 1, 100, 2731, 2800])))
        case 4: return .bool(z.chance(0.5))
        case 5: return .null
        case 6 where tiefe < 10:
            // Breite Felder nur mit Blättern (sonst wächst der Baum exponentiell)
            if z.chance(0.2) { return .array((0..<z.pick([300, 4095, 4097])).map { _ in .unsigned(UInt64(z.int(0...30))) }) }
            return .array((0..<z.int(0...3)).map { _ in zufallsKnoten(&z, tiefe: tiefe + 1) })
        case 7 where tiefe < 10:
            return .map((0..<z.int(0...3)).map { i in CBORPair(.int(Int64(i)), zufallsKnoten(&z, tiefe: tiefe + 1)) })
        default: return z.pick(baeume)
        }
    }

    private func mutiereBaum(_ v: CBOR, _ z: inout Zufall, tiefe: Int = 0) -> CBOR {
        switch v {
        case let .map(p) where !p.isEmpty && z.chance(0.75):
            var q = p
            let i = z.int(q.count)
            switch z.int(5) {
            case 0: q.remove(at: i)
            case 1: q[i] = CBORPair(zufallsKnoten(&z, tiefe: tiefe), q[i].value)
            default: q[i] = CBORPair(q[i].key, mutiereBaum(q[i].value, &z, tiefe: tiefe + 1))
            }
            return .map(q)
        case let .array(a) where !a.isEmpty && z.chance(0.75):
            var q = a
            let i = z.int(q.count)
            switch z.int(4) {
            case 0: q.remove(at: i)
            case 1: q.append(zufallsKnoten(&z, tiefe: tiefe))
            default: q[i] = mutiereBaum(q[i], &z, tiefe: tiefe + 1)
            }
            return .array(q)
        case let .bytes(b) where z.chance(0.5):
            return .bytes(Mutator.bytes(b, &z))
        default:
            // Verschachteln (Tiefengrenze) oder ersetzen
            return z.chance(0.2) ? .array([v]) : zufallsKnoten(&z, tiefe: tiefe)
        }
    }

    func naechste(_ z: inout Zufall) -> [UInt8] {
        let basis = korpus.waehle(&z)
        guard let art = basis.first else { return [0] }
        var b = Array(basis.dropFirst())
        if art != 2, z.chance(0.5), let v = try? CBORDecoder.decode(art == 4 ? Array(b.dropFirst(4)) : b) {
            let neu = mutiereBaum(v, &z)
            let kodiert = z.chance(0.7) ? ((try? CBOREncoder.encode(neu)) ?? locker(neu, &z)) : locker(neu, &z)
            b = art == 4 ? Array(b.prefix(4)) + kodiert : kodiert
        } else {
            b = Mutator.bytes(b, &z, maxLaenge: 64 << 10)
        }
        if z.chance(0.05) { return [UInt8(z.int(0...4))] + b }
        return [art] + b
    }

    // MARK: Prüfen

    private static func pruefeAbbildung(_ f: FIDOError) throws {
        let s = f.siegelError
        guard FIDOError.isAllowedOutward(s) else {
            throw Fund("fehlertyp", "FIDO-Fehler nach aussen: " + fehlerCode(s))
        }
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard let art = e.first else { return "leer" }
        let b = Array(e.dropFirst())
        switch art % 5 {
        case 0:
            do {
                let v = try CBORDecoder.decode(b)
                guard let r = try? CBOREncoder.encode(v), r == b else {
                    throw Fund("cbor", "angenommene Kodierung ist nicht kanonisch (Rundlauf)")
                }
                return "cbor:ok"
            } catch let x as CBORError {
                return "cbor:" + fehlerCode(x)
            }
        case 1:
            do {
                let v = try CBORDecoder.decode(b)
                let info = try AuthenticatorInfo.parse(v)
                do { try info.requireUsable(forRegistration: true) } catch { try Self.pruefeAbbildung(error) }
                do { _ = try info.preferredPinProtocol() } catch { try Self.pruefeAbbildung(error) }
                return "info:ok"
            } catch let x as CBORError {
                return "info:cbor:" + fehlerCode(x)
            } catch let x as FIDOError {
                try Self.pruefeAbbildung(x)
                return "info:" + fehlerCode(x)
            }
        case 2:
            do {
                let ad = try AuthenticatorData.parse(b)
                guard ad.rpIDHash.count == 32, b.count >= 37 else { throw Fund("authdata", "Kopf unvollständig angenommen") }
                if let id = ad.credentialID, !(1...1024).contains(id.count) { throw Fund("authdata", "Credential-Länge") }
                return "authdata:ok"
            } catch let x as FIDOError {
                try Self.pruefeAbbildung(x)
                return "authdata:" + fehlerCode(x)
            }
        case 3:
            do {
                let v = try CBORDecoder.decode(b)
                let k = try PinUvSession.publicKey(fromCOSE: v)
                _ = try? P256.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: k)
                return "cose:ok"
            } catch let x as CBORError {
                return "cose:cbor:" + fehlerCode(x)
            } catch let x as FIDOError {
                try Self.pruefeAbbildung(x)
                return "cose:" + fehlerCode(x)
            }
        default:
            let versatz = Int(b.first ?? 0) % 8
            do {
                let (v, ende) = try CBORDecoder.decodePrefix(b, at: versatz)
                guard ende > versatz, ende <= b.count else { throw Fund("cbor", "Versatz nach decodePrefix unplausibel") }
                guard let r = try? CBOREncoder.encode(v), Array(b[versatz..<ende]) == r else {
                    throw Fund("cbor", "decodePrefix nicht kanonisch")
                }
                return "prefix:ok"
            } catch let x as CBORError {
                return "prefix:" + fehlerCode(x)
            }
        }
    }
}
#endif
