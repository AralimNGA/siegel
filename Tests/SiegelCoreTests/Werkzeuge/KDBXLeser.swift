import Clibsodium
import CryptoKit
import Foundation

/// Unabhängiger KDBX-4-Leser **nur für Tests** (SPEC §19 „Prüfung“). Nach der KDBX-4-Beschreibung geschrieben,
/// nicht aus `KeePassExport` abgeleitet: eigene Byte-Lesung, CryptoKit für SHA-256/SHA-512/HMAC, libsodium nur für
/// Argon2id und den ChaCha20-Strom, XML über `XMLDocument`, Schlüsselstrom für geschützte Werte in einem Stück.
/// Prüft alles, was ein strenger Leser prüfen muss: Signaturen, Version, Kopf-Hash, Kopf-HMAC (falsches Passwort),
/// jeden Block-HMAC, Abschlussblock, keine Restbytes.
struct KDBXLeser {
    enum Fehler: Error, Equatable {
        case kurz, signatur, version, kopf, kopfHash, kopfHMAC, kdf(String), block(Int), restbytes
        case cipher, kompression, innererKopf, innererStrom, xml, utf8
    }

    struct Eintrag: Equatable {
        var uuid: Data
        var werte: [String: String]
        var geschuetzt: Set<String>
        var erstellt: Date
        var geaendert: Date
    }

    struct Datei {
        var version: UInt32
        var kopfFelder: [UInt8: Data]
        var kdf: [String: Data]
        var kdfTypen: [String: UInt8]
        var bloecke: Int
        var innererStromID: UInt32
        var xml: String
        var gruppe: String
        var eintraege: [Eintrag]
    }

    static let argon2id = Data([0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6])
    static let chacha20 = Data([0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A])

    private struct Cursor {
        let data: [UInt8]
        var position = 0

        mutating func bytes(_ n: Int) throws -> [UInt8] {
            guard n >= 0, position + n <= data.count else { throw Fehler.kurz }
            defer { position += n }
            return Array(data[position..<(position + n)])
        }

        mutating func u8() throws -> UInt8 { try bytes(1)[0] }

        mutating func u16() throws -> UInt16 {
            let b = try bytes(2)
            return UInt16(b[0]) | UInt16(b[1]) << 8
        }

        mutating func u32() throws -> UInt32 {
            let b = try bytes(4)
            return b.enumerated().reduce(0) { $0 | UInt32($1.element) << (8 * UInt32($1.offset)) }
        }
    }

    /// libsodium unabhängig vom Kern initialisieren.
    private static let sodiumBereit: Bool = sodium_init() >= 0

    static func lesen(_ data: Data, passwort: String) throws -> Datei {
        guard sodiumBereit else { throw Fehler.kdf("sodium") }
        var c = Cursor(data: Array(data))
        guard try c.u32() == 0x9AA2_D903, try c.u32() == 0xB54B_FB67 else { throw Fehler.signatur }
        let version = try c.u32()
        guard version >> 16 == 4, version & 0xFFFF <= 1 else { throw Fehler.version }

        // Äusserer Kopf
        var felder: [UInt8: Data] = [:]
        while true {
            let id = try c.u8()
            let laenge = Int(try c.u32())
            let wert = try c.bytes(laenge)
            guard felder[id] == nil else { throw Fehler.kopf }
            felder[id] = Data(wert)
            if id == 0 { break }
        }
        let kopf = Array(c.data[0..<c.position])
        let kopfHash = try c.bytes(32)
        guard Array(SHA256.hash(data: kopf)) == kopfHash else { throw Fehler.kopfHash }
        let kopfHMAC = try c.bytes(32)

        guard felder[2] == chacha20 else { throw Fehler.cipher }
        guard let kompression = felder[3], kompression == Data([0, 0, 0, 0]) else { throw Fehler.kompression }
        guard let seed = felder[4], seed.count == 32, let iv = felder[7], iv.count == 12,
              let kdfDaten = felder[11] else { throw Fehler.kopf }

        // VariantDictionary
        var kdf: [String: Data] = [:]
        var typen: [String: UInt8] = [:]
        var v = Cursor(data: Array(kdfDaten))
        guard try v.u16() >> 8 == 1 else { throw Fehler.kdf("version") }
        while true {
            let typ = try v.u8()
            if typ == 0 { break }
            let schluessel = String(decoding: try v.bytes(Int(try v.u32())), as: UTF8.self)
            kdf[schluessel] = Data(try v.bytes(Int(try v.u32())))
            typen[schluessel] = typ
        }
        guard v.position == v.data.count else { throw Fehler.kdf("rest") }
        guard kdf["$UUID"] == argon2id else { throw Fehler.kdf("uuid") }
        guard let salz = kdf["S"], let p = kdf["P"], let m = kdf["M"], let i = kdf["I"], let ver = kdf["V"],
              p == Data([1, 0, 0, 0]), ver == Data([0x13, 0, 0, 0]), m.count == 8, i.count == 8 else {
            throw Fehler.kdf("parameter")
        }
        guard salz.count == crypto_pwhash_argon2id_saltbytes() else { throw Fehler.kdf("salz") }
        let speicher = m.enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }
        let durchlaeufe = i.enumerated().reduce(UInt64(0)) { $0 | UInt64($1.element) << (8 * UInt64($1.offset)) }

        // Schlüssel
        let zusammengesetzt = Array(SHA256.hash(data: Array(SHA256.hash(data: Array(passwort.utf8)))))
        var transformiert = [UInt8](repeating: 0, count: 32)
        let passwortZeichen = zusammengesetzt.map { CChar(bitPattern: $0) }
        let rc = crypto_pwhash(&transformiert, 32, passwortZeichen, 32, Array(salz), durchlaeufe, Int(speicher),
                               crypto_pwhash_alg_argon2id13())
        guard rc == 0 else { throw Fehler.kdf("argon2") }
        let hmacBasis = Array(SHA512.hash(data: Array(seed) + transformiert + [0x01]))
        let inhaltsSchluessel = Array(SHA256.hash(data: Array(seed) + transformiert))

        func blockSchluessel(_ index: UInt64) -> SymmetricKey {
            SymmetricKey(data: Array(SHA512.hash(data: le64(index) + hmacBasis)))
        }
        guard Array(HMAC<SHA256>.authenticationCode(for: kopf, using: blockSchluessel(.max))) == kopfHMAC else {
            throw Fehler.kopfHMAC
        }

        // Blöcke
        var geheimtext: [UInt8] = []
        var index: UInt64 = 0
        while true {
            let mac = try c.bytes(32)
            let laenge = try c.u32()
            guard laenge <= Int32.max else { throw Fehler.block(Int(index)) }
            let daten = try c.bytes(Int(laenge))
            let erwartet = HMAC<SHA256>.authenticationCode(for: le64(index) + le32(laenge) + daten,
                                                           using: blockSchluessel(index))
            guard Array(erwartet) == mac else { throw Fehler.block(Int(index)) }
            index += 1
            if laenge == 0 { break }
            geheimtext += daten
        }
        guard c.position == c.data.count else { throw Fehler.restbytes }

        // Entschlüsseln (ChaCha20, Zähler 0)
        var klartext = [UInt8](repeating: 0, count: geheimtext.count)
        _ = crypto_stream_chacha20_ietf_xor(&klartext, geheimtext, UInt64(geheimtext.count), Array(iv), inhaltsSchluessel)

        // Innerer Kopf
        var k = Cursor(data: klartext)
        var innen: [UInt8: [UInt8]] = [:]
        while true {
            let id = try k.u8()
            let wert = try k.bytes(Int(try k.u32()))
            if id == 0 { break }
            innen[id] = wert
        }
        guard let streamID = innen[1], streamID.count == 4, let streamKey = innen[2], streamKey.count == 64 else {
            throw Fehler.innererKopf
        }
        let stromID = UInt32(streamID[0]) | UInt32(streamID[1]) << 8 | UInt32(streamID[2]) << 16 | UInt32(streamID[3]) << 24
        guard stromID == 3 else { throw Fehler.innererStrom }
        let xmlBytes = Array(klartext[k.position...])
        guard let xmlText = String(validating: xmlBytes, as: UTF8.self) else { throw Fehler.utf8 }

        // XML und geschützte Werte (ein Schlüsselstrom in Dokumentreihenfolge)
        let dokument: XMLDocument
        do { dokument = try XMLDocument(data: Data(xmlBytes), options: [.nodePreserveWhitespace]) } catch { throw Fehler.xml }
        let geschuetzte = (try? dokument.nodes(forXPath: "//Value[@Protected='True']")) ?? []
        var gesamt = 0
        for knoten in geschuetzte {
            guard let roh = Data(base64Encoded: knoten.stringValue ?? "") else { throw Fehler.xml }
            gesamt += roh.count
        }
        let strom = Array(SHA512.hash(data: streamKey))
        var schluesselstrom = [UInt8](repeating: 0, count: gesamt)
        if gesamt > 0 {
            _ = crypto_stream_chacha20_ietf(&schluesselstrom, UInt64(gesamt), Array(strom[32..<44]), Array(strom[0..<32]))
        }
        var verbraucht = 0
        func entschluesseln(_ base64: String) throws -> String {
            guard let roh = Data(base64Encoded: base64), verbraucht + roh.count <= gesamt else { throw Fehler.xml }
            let bytes = roh.enumerated().map { $0.element ^ schluesselstrom[verbraucht + $0.offset] }
            verbraucht += roh.count
            guard let text = String(validating: bytes, as: UTF8.self) else { throw Fehler.utf8 }
            return text
        }

        let gruppe = (try? dokument.nodes(forXPath: "/KeePassFile/Root/Group/Name").first?.stringValue) ?? nil
        var eintraege: [Eintrag] = []
        for eintrag in (try? dokument.nodes(forXPath: "/KeePassFile/Root/Group/Entry")) ?? [] {
            guard let element = eintrag as? XMLElement else { throw Fehler.xml }
            let uuid = Data(base64Encoded: element.elements(forName: "UUID").first?.stringValue ?? "") ?? Data()
            var werte: [String: String] = [:]
            var geschuetztSet = Set<String>()
            for s in element.elements(forName: "String") {
                guard let schluessel = s.elements(forName: "Key").first?.stringValue,
                      let wert = s.elements(forName: "Value").first else { throw Fehler.xml }
                if wert.attribute(forName: "Protected")?.stringValue == "True" {
                    werte[schluessel] = try entschluesseln(wert.stringValue ?? "")
                    geschuetztSet.insert(schluessel)
                } else {
                    werte[schluessel] = wert.stringValue ?? ""
                }
            }
            let zeiten = element.elements(forName: "Times").first
            eintraege.append(Eintrag(uuid: uuid, werte: werte, geschuetzt: geschuetztSet,
                                     erstellt: zeit(zeiten?.elements(forName: "CreationTime").first?.stringValue),
                                     geaendert: zeit(zeiten?.elements(forName: "LastModificationTime").first?.stringValue)))
        }
        guard verbraucht == gesamt else { throw Fehler.xml }     // alle geschützten Werte liegen in Einträgen
        return Datei(version: version, kopfFelder: felder, kdf: kdf, kdfTypen: typen, bloecke: Int(index),
                     innererStromID: stromID, xml: xmlText, gruppe: gruppe ?? "", eintraege: eintraege)
    }

    static func zeit(_ text: String?) -> Date {
        guard let text, let roh = Data(base64Encoded: text), roh.count == 8 else { return .distantPast }
        let sekunden = roh.enumerated().reduce(Int64(0)) { $0 | Int64($1.element) << (8 * Int64($1.offset)) }
        return Date(timeIntervalSince1970: TimeInterval(sekunden - 62_135_596_800))
    }

    static func le64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: v >> (8 * UInt64($0))) } }
    static func le32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * UInt32($0))) } }
}
