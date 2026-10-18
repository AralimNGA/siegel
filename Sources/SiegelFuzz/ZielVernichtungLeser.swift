#if DEBUG
import Clibsodium
import CryptoKit
import Darwin
import Foundation
@testable import SiegelCore

// Ziel „vernichtung“ (SPEC §23), Teil 1: eigene Leser (zustand.json, Ablage des Vernichtungs-Passworts) und eigene
// Prüfwert-Rechnung. Das Ziel selbst steht in ZielVernichtung.swift, das Modell in ZielVernichtungModell.swift, der
// Ablauf einer Eingabe in ZielVernichtungAblauf.swift.
//
// Der eigene Leser liest nach dem dokumentierten Format (JSONSerialization statt JSONDecoder, unbekannte Schlüssel
// übergangen). Ob der Kern eine Datei annimmt, entscheidet sein Parser (`DestructionState.decode`, @testable); der
// eigene Leser wird dagegen Feld für Feld verglichen (Differenztest, s. `ZielVernichtung.zustandLesen`).

// MARK: - JSON mit fester Schreibweise

/// JSON-Wert für den gefuzzten Zustand. `roh` ist ein wörtliches Zahl-Token (1e999, NaN, -0, …).
indirect enum JWert: Equatable {
    case obj([String: JWert])
    case arr([JWert])
    case str(String)
    case int(Int64)
    case dbl(Double)
    case roh(String)
    case bool(Bool)
    case null

    static func aus(_ a: Any) -> JWert? {
        if a is NSNull { return .null }
        if let s = a as? String { return .str(s) }
        if let n = a as? NSNumber {
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return .bool(n.boolValue) }
            let t = String(cString: n.objCType)
            if t == "d" || t == "f" || n is NSDecimalNumber { return .dbl(n.doubleValue) }
            if t == "Q", n.uint64Value > UInt64(Int64.max) { return .dbl(n.doubleValue) }
            return .int(n.int64Value)
        }
        if let d = a as? [String: Any] {
            var o: [String: JWert] = [:]
            for (k, v) in d {
                guard let w = aus(v) else { return nil }
                o[k] = w
            }
            return .obj(o)
        }
        if let arr = a as? [Any] {
            var out: [JWert] = []
            for v in arr {
                guard let w = aus(v) else { return nil }
                out.append(w)
            }
            return .arr(out)
        }
        return nil
    }

    static func lesen(_ b: [UInt8]) -> JWert? {
        guard let a = try? JSONSerialization.jsonObject(with: Data(b), options: [.fragmentsAllowed]) else { return nil }
        return aus(a)
    }

    /// Bekannte Nachsicht von JSONDecoder (swift-foundation), gemessen mit dem Fuzzer: ungültiges UTF-8 und rohe
    /// Steuerzeichen in Zeichenketten (etwa im Wert eines unbekannten, übergangenen Schlüssels) verwirft er nicht,
    /// JSONSerialization schon. Für den Differenztest: verlustbehaftet als UTF-8 lesen, Steuerzeichen als Leerzeichen.
    static func lesenWieJSONDecoder(_ b: [UInt8]) -> JWert? {
        let t = String(decoding: b, as: UTF8.self).unicodeScalars.map { $0.value < 0x20 ? " " : String($0) }.joined()
        return lesen(Array(t.utf8))
    }

    var text: String {
        switch self {
        case let .obj(o): return "{" + o.keys.sorted().map { Self.zeichenkette($0) + ":" + (o[$0] ?? .null).text }
            .joined(separator: ",") + "}"
        case let .arr(a): return "[" + a.map(\.text).joined(separator: ",") + "]"
        case let .str(s): return Self.zeichenkette(s)
        case let .int(i): return String(i)
        case let .dbl(d): return d.isFinite ? "\(d)" : (d.isNaN ? "NaN" : (d > 0 ? "1e999" : "-1e999"))
        case let .roh(t): return t
        case let .bool(b): return b ? "true" : "false"
        case .null: return "null"
        }
    }

    var bytes: [UInt8] { Array(text.utf8) }

    static func zeichenkette(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            default:
                if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
            }
        }
        return out + "\""
    }

    /// Kennungen, die ein Zustand nennt – nur die Felder vKeyID, duressFileID und destroyed.keyID (feldbewusst, nicht
    /// als Teilstring im ganzen Text).
    var genannteKennungen: Set<UUID> {
        var out = Set<UUID>()
        for w in [self["vKeyID"], self["duressFileID"], self["destroyed"]?["keyID"]] {
            if case let .str(s)? = w, let u = UUID(uuidString: s) { out.insert(u) }
        }
        return out
    }

    subscript(k: String) -> JWert? {
        get { if case let .obj(o) = self { return o[k] } else { return nil } }
        set {
            guard case var .obj(o) = self else { return }
            o[k] = newValue
            self = .obj(o)
        }
    }
}

// MARK: - Modell des Zustands

/// Was `DestructionState.read` liefert (unabhängig nachgebaut).
struct ZustandM: Equatable {
    struct Vermerk: Equatable {
        var keyID: UUID
        var trigger: String
        var at: Date
    }

    var vaultID: UUID
    var deadmanDays: Int?
    var maxFailed: Int?
    var duressEnabled = false
    var vKeyID: UUID?
    var duressFileID: UUID?
    var last: Date?
    var failed = 0
    var destroyed: Vermerk?
    var rekeyPending = false

    init(vaultID: UUID) { self.vaultID = vaultID }

    /// Was der Kern gelesen hat (für den Differenztest des eigenen Lesers und als Modell-Zustand).
    static func aus(_ k: DestructionState) -> ZustandM {
        var m = ZustandM(vaultID: k.vaultID)
        m.deadmanDays = k.settings.deadmanDays
        m.maxFailed = k.settings.maxFailedAttempts
        m.duressEnabled = k.settings.duressEnabled
        m.vKeyID = k.vKeyID
        m.duressFileID = k.duressFileID
        m.last = k.lastGenuineUnlock.map(ZielVernichtung.kanonisch)
        m.failed = k.failedAttempts
        m.destroyed = k.destroyed.map { Vermerk(keyID: $0.keyID, trigger: $0.trigger.rawValue, at: ZielVernichtung.kanonisch($0.at)) }
        m.rekeyPending = k.rekeyPending
        return m
    }

    /// Dokumentierte Bereiche (§23.3), unabhängig vom Kern geprüft.
    var inBereichen: Bool {
        (0...1_000_000).contains(failed) && deadmanDays.map { (7...365).contains($0) } != false
            && maxFailed.map { (10...100).contains($0) } != false && duressEnabled == (duressFileID != nil)
    }

    var anyTrigger: Bool { deadmanDays != nil || maxFailed != nil || duressEnabled }
    var isEmpty: Bool { !anyTrigger && vKeyID == nil && duressFileID == nil && destroyed == nil && !rekeyPending }

    var deadline: Date? {
        guard let d = deadmanDays, let last else { return nil }
        return ZielVernichtung.kanonisch(last.addingTimeInterval(TimeInterval(d) * 86_400))
    }

    func nennt(_ id: UUID?) -> Bool {
        guard let id else { return false }
        return vKeyID == id || destroyed?.keyID == id || duressFileID == id
    }

    enum Lesart {
        case gueltig(ZustandM)
        case ungueltig
        case unbestimmt
    }

    /// Eigener Leser nach dem dokumentierten Format (KERN-NOTIZEN: „streng gelesen“). Unbekannte Schlüssel zählen
    /// nicht (JSONDecoder übergeht sie). Typen, deren Annahme durch JSONDecoder nicht sicher ist (z. B. 3.0 für eine
    /// ganze Zahl), ergeben `unbestimmt`.
    private final class Merker {
        var unsicher = false
    }

    /// `nachsichtig`: Zahlen in anderer Schreibweise (10.0, 1e1, 1792000000.0) wie JSONDecoder sie vielleicht doch
    /// annimmt – nur als zusätzlicher Kandidat des Orakels.
    static func lesen(_ w: JWert, nachsichtig: Bool = false) -> Lesart {
        let merker = Merker()
        func zahl(_ v: JWert?) -> Double? {
            switch v {
            case let .dbl(d)?: return d
            case let .roh(t)?: return Double(t)
            default: return nil
            }
        }
        enum Abbruch: Error { case ungueltig }
        func ganz(_ v: JWert?, pflicht: Bool) throws -> Int? {
            switch v {
            case nil, .null?: if pflicht { throw Abbruch.ungueltig }; return nil
            case let .int(i)?: return Int(i)
            case .dbl?, .roh?:
                if nachsichtig, let d = zahl(v), d.isFinite, d == d.rounded(), abs(d) < 9e15 { return Int(d) }
                merker.unsicher = true; return nil
            default: throw Abbruch.ungueltig
            }
        }
        func wahr(_ v: JWert?, pflicht: Bool) throws -> Bool? {
            switch v {
            case nil, .null?: if pflicht { throw Abbruch.ungueltig }; return nil
            case let .bool(b)?: return b
            case .int?, .dbl?, .roh?: merker.unsicher = true; return nil
            default: throw Abbruch.ungueltig
            }
        }
        func kennung(_ v: JWert?, pflicht: Bool) throws -> UUID? {
            switch v {
            case nil, .null?: if pflicht { throw Abbruch.ungueltig }; return nil
            case let .str(s)?:
                guard let u = UUID(uuidString: s) else { throw Abbruch.ungueltig }
                return u
            default: throw Abbruch.ungueltig
            }
        }
        func zeit(_ v: JWert?, pflicht: Bool) throws -> Date? {
            switch v {
            case nil, .null?: if pflicht { throw Abbruch.ungueltig }; return nil
            case let .int(i)?: return ZielVernichtung.kanonisch(Date(timeIntervalSince1970: Double(i)))
            case let .dbl(d)?:
                guard d.isFinite else { merker.unsicher = true; return nil }
                return ZielVernichtung.kanonisch(Date(timeIntervalSince1970: d))
            case .roh?:
                if nachsichtig, let d = zahl(v), d.isFinite { return ZielVernichtung.kanonisch(Date(timeIntervalSince1970: d)) }
                merker.unsicher = true; return nil
            default: throw Abbruch.ungueltig
            }
        }
        do {
            guard case let .obj(o) = w else { return .ungueltig }
            let v = try ganz(o["v"], pflicht: true)
            guard let vid = try kennung(o["vaultID"], pflicht: true) else { return .ungueltig }
            guard case let .obj(s)? = o["settings"] else {
                if o["settings"] == nil || o["settings"] == .null { return .ungueltig }
                return .ungueltig
            }
            var m = ZustandM(vaultID: vid)
            m.deadmanDays = try ganz(s["deadmanDays"], pflicht: false)
            m.maxFailed = try ganz(s["maxFailedAttempts"], pflicht: false)
            let du = try wahr(s["duressEnabled"], pflicht: true)
            m.duressEnabled = du ?? false
            m.vKeyID = try kennung(o["vKeyID"], pflicht: false)
            m.duressFileID = try kennung(o["duressFileID"], pflicht: false)
            m.last = try zeit(o["lastGenuineUnlock"], pflicht: false)
            let f = try ganz(o["failedAttempts"], pflicht: true)
            switch o["destroyed"] {
            case nil, .null?: m.destroyed = nil
            case let .obj(d)?:
                guard let k = try kennung(d["keyID"], pflicht: true) else { return .ungueltig }
                guard case let .str(t)? = d["trigger"], ["deadman", "failedAttempts", "duressPassword"].contains(t) else {
                    return .ungueltig
                }
                let at = try zeit(d["at"], pflicht: true)
                if let at { m.destroyed = Vermerk(keyID: k, trigger: t, at: at) }
            default: return .ungueltig
            }
            m.rekeyPending = try wahr(o["rekeyPending"], pflicht: false) ?? false
            if merker.unsicher { return .unbestimmt }
            guard v == 1, let f, (0...1_000_000).contains(f) else { return .ungueltig }
            m.failed = f
            if let d = m.deadmanDays, !(7...365).contains(d) { return .ungueltig }
            if let n = m.maxFailed, !(10...100).contains(n) { return .ungueltig }
            guard m.duressEnabled == (m.duressFileID != nil) else { return .ungueltig }
            return .gueltig(m)
        } catch {
            return merker.unsicher ? .unbestimmt : .ungueltig
        }
    }
}

/// Selbstvernichtung im (massgeblichen) Inhalt, wie das Modell sie braucht.
struct InhaltM: Equatable {
    var deadmanDays: Int?
    var maxFailed: Int?
    var duressEnabled: Bool
    var vKeyID: UUID?
    var duressFileID: UUID?
}

// MARK: - Ablage des Vernichtungs-Passworts (eigener Leser)

struct AblageBefund: Equatable {
    let id: UUID
    let salt: [UInt8]
    let check: [UInt8]
    /// salt ‖ check ‖ ctM ‖ ctX ‖ wrap (1704 B)
    let nutzlast: [UInt8]

    static let laenge = 2048
    static let nutzEnde = 29 + 1704
    static let punktAnfang = 29 + 1922
    static let summeAnfang = 2048 - 32

    static func pruefsumme(_ b: ArraySlice<UInt8>) -> [UInt8] {
        var h = SHA3_256()
        h.update(data: Array("Siegel v2 hw file check".utf8))
        h.update(data: Array(b))
        return Array(h.finalize())
    }

    /// Dokumentiertes Format (KERN-NOTIZEN): „SIEGELHW“ ‖ v1 ‖ kind 2 ‖ fileID ‖ 1922 ‖ blob ‖ Punkt ‖ Prüfsumme.
    static func lesen(_ b: [UInt8], erwartet: UUID) -> AblageBefund? {
        guard b.count == laenge, pruefsumme(b[0..<summeAnfang]) == Array(b[summeAnfang...]),
              Array(b[0..<8]) == Array("SIEGELHW".utf8), b[8] == 1, b[9] == 0, b[10] == 2,
              ZielVernichtung.uuid(Array(b[11..<27])) == erwartet, b[27] == UInt8(1922 & 0xFF), b[28] == UInt8(1922 >> 8)
        else { return nil }
        let punkt = Array(b[punktAnfang..<summeAnfang])
        guard punkt.first == 0x04, (try? P256.KeyAgreement.PublicKey(x963Representation: punkt)) != nil else { return nil }
        return AblageBefund(id: erwartet, salt: Array(b[29..<45]), check: Array(b[45..<61]),
                            nutzlast: Array(b[29..<nutzEnde]))
    }

    /// Form einer Ablage (Länge, magic, Version 1, kind 2, Bloblänge 1922) – ohne Prüfsumme und Kennung.
    static func hatForm(_ b: [UInt8]) -> Bool {
        b.count == laenge && Array(b[0..<8]) == Array("SIEGELHW".utf8) && b[8] == 1 && b[9] == 0 && b[10] == 2
            && b[27] == UInt8(1922 & 0xFF) && b[28] == UInt8(1922 >> 8)
    }

    /// Eine gültige Ablage mit dieser Kennung aus einer Vorlage (Platzhalter im Modell für frisch gekapselte: Form,
    /// Kennung und Prüfsumme stimmen, den Inhalt liest das Modell daraus nie).
    static func mitKennung(_ vorlage: [UInt8], _ id: UUID) -> [UInt8] {
        guard vorlage.count == laenge else { return vorlage }
        var b = vorlage
        b.replaceSubrange(11..<27, with: VaultHeader.bytes(of: id))
        b.replaceSubrange(summeAnfang..<laenge, with: pruefsumme(b[0..<summeAnfang]))
        return b
    }

    /// Prüfwert unabhängig: d = Argon2id (libsodium), check = HKDF-SHA512(d, salt = vaultID, "Siegel v2 duress check").
    static func erkannt(_ pw: String, _ f: AblageBefund, vaultID: [UInt8], kdf: KDFParameters) -> Bool {
        let roh = Array(PasswordNormalizer.normalize(pw).utf8)
        var d = [UInt8](repeating: 0, count: 32)
        let rc: Int32 = d.withUnsafeMutableBufferPointer { out in
            roh.withUnsafeBufferPointer { p in
                f.salt.withUnsafeBufferPointer { s in
                    guard let o = out.baseAddress, let pp = p.baseAddress, let sp = s.baseAddress else { return -1 }
                    return pp.withMemoryRebound(to: CChar.self, capacity: p.count) { cp in
                        crypto_pwhash(o, 32, cp, UInt64(p.count), sp, UInt64(kdf.opsLimit), Int(kdf.memLimitBytes),
                                      crypto_pwhash_alg_argon2id13())
                    }
                }
            }
        }
        guard rc == 0 else { return false }
        let c = HKDF<SHA512>.deriveKey(inputKeyMaterial: SymmetricKey(data: d), salt: vaultID,
                                       info: Array("Siegel v2 duress check".utf8), outputByteCount: 16)
        return c.withUnsafeBytes { Array($0) } == f.check
    }
}
#endif
