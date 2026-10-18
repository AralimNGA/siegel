#if DEBUG
import CryptoKit
import Foundation
import SiegelCore
@testable import SiegelHardware

/// Ziel „hwdatei“: Ablage eines Secure-Enclave-Schlüssels `<keyID>.siegelhw` (SPEC §14.1, `HardwareKeyFile.decode`).
/// Liegt neben dem Tresor und ist darum genauso Angriffsfläche.
///
/// Rahmung: Byte 0 = erwartete Art (1 Entsperren, 2 Einträge), Byte 1…16 = erwartete keyID, danach die Datei.
/// Invarianten: kein Absturz; Fehler nur `corruptFile("hw.…")`; angenommen wird nur, was die Prüfsumme trägt, die
/// erwartete Art und keyID hat und bytegleich neu kodiert wird.
final class ZielHWDatei: FuzzZiel {
    let name = "hwdatei"
    let zeitlimit = 5.0
    private let korpus = Korpus()
    private var z = Zufall(saat: 9)
    var zusatz: [String: Int] = [:]

    func vorbereiten(_ u: Umgebung) throws {
        var z = Zufall(saat: 0x4857)
        for (kind, laenge) in [(HardwareKeyFile.Kind.unlock, 1), (.entry, 200), (.unlock, 4096)] {
            let id = z.uuid()
            let punkt = try P256.KeyAgreement.PrivateKey(rawRepresentation: [UInt8](repeating: UInt8(laenge % 200 + 1), count: 32))
            let datei = HardwareKeyFile(kind: kind, keyID: id, blob: Data(repeating: 0xB1, count: laenge),
                                        point: punkt.publicKey.x963Representation)
            korpus.saatAufnehmen([kind.rawValue] + id.hwBytes + (try datei.encoded()))
        }
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    func naechste(_ z: inout Zufall) -> [UInt8] {
        let basis = korpus.waehle(&z)
        guard basis.count > 17 else { return basis }
        var kopf = Array(basis.prefix(17))
        var b = Array(basis.dropFirst(17))
        if z.chance(0.05) { kopf[0] = UInt8(z.int(0...3)) }
        if z.chance(0.6), b.count > 29 {
            // Feldbewusst: magic 0–7, version 8–9, kind 10, keyID 11–26, blobLength 27–28
            switch z.int(6) {
            case 0: b[z.int(8)] ^= 0x20
            case 1: b[8] = UInt8(z.int(0...3)); b[9] = z.chance(0.8) ? 0 : 1
            case 2: b[10] = UInt8(z.int(0...3))
            case 3: b[11 + z.int(16)] ^= 1
            case 4:
                let n = z.pick([0, 1, 2, 4095, 4096, 4097, 0xFFFF, (Int(b[27]) | Int(b[28]) << 8) + z.int(-2...2)])
                b[27] = UInt8(truncatingIfNeeded: n)
                b[28] = UInt8(truncatingIfNeeded: n >> 8)
            default:
                // Punkt (65 Byte vor der Prüfsumme) verändern
                if b.count > 97 { b[b.count - 32 - 65 + z.int(65)] ^= UInt8(1) << UInt8(z.int(8)) }
            }
        } else {
            b = Mutator.bytes(b, &z, maxLaenge: 8192)
        }
        if z.chance(0.7), b.count > 32 {
            let koerper = Array(b.dropLast(32))
            b = koerper + HardwareKeyFile.checksum(koerper)
        }
        return kopf + b
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard e.count >= 17 else { return "kurz" }
        let id = UUID(hwBytes: Array(e[1..<17]))
        let art = HardwareKeyFile.Kind(rawValue: e[0]) ?? .unlock
        let b = Array(e.dropFirst(17))
        do {
            let d = try HardwareKeyFile.decode(b, expectedKeyID: id, expectedKind: art)
            guard b.count > 32, HardwareKeyFile.checksum(Array(b.dropLast(32))) == Array(b.suffix(32)) else {
                throw Fund("hwdatei", "angenommen ohne gültige Prüfsumme")
            }
            guard d.keyID == id, d.kind == art, (try? d.encoded()) == b else {
                throw Fund("hwdatei", "angenommen, aber nicht bytegleich neu kodierbar")
            }
            return "ok"
        } catch let x as SiegelError {
            guard case let .corruptFile(c) = x, c.hasPrefix("hw.") else { throw Fund("fehlertyp", "hw: " + fehlerCode(x)) }
            return "hw:" + c
        }
    }
}
#endif
