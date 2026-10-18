import CryptoKit
import Foundation

/// QR-Schlüsselkarte, reines Format ohne Kamera (SPEC §14.2, §22).
///   q = 32 Zufallsbytes; Inhalt = "SIEGELKARTE1:" + Crockford-Base32(q ‖ Prüfsumme 2 B), MSB-first, 55 Zeichen
///   (3 Füllbits = 0, wie beim Notfallcode); Prüfsumme = SHA3-256("Siegel v2 card checksum" ‖ q)[0..<2].
///   cardTag = SHA3-256("Siegel v2 card tag" ‖ vaultID ‖ q)[0..<4] (steht im Kopf bzw. im Inhalt).
public enum CardCode {
    static let prefix = "SIEGELKARTE1:"
    static let prefixFamily = "SIEGELKARTE"
    static let checksumLabel = Array("Siegel v2 card checksum".utf8)
    static let tagLabel = Array("Siegel v2 card tag".utf8)

    /// Neues Kartengeheimnis q (32 Byte aus `randombytes_buf`).
    public static func generate() -> FactorSecret {
        guard let s = try? SecureBytes.random(count: 32), let q = try? FactorSecret(storage: s) else {
            fatalError("card.generate")
        }
        return q
    }

    /// QR-Inhalt "SIEGELKARTE1:XXXX…" (nur Zeichen des QR-Alphanumerik-Modus).
    public static func payload(for q: FactorSecret) -> String {
        prefix + RecoveryCodeCodec.formatSymbols(symbols(q), groupSize: RecoveryCodeCodec.symbolCount)
    }

    /// Derselbe Code in 11 Gruppen à 5 zum Abtippen (Notlösung bei defekter Kamera).
    public static func groupedText(for q: FactorSecret) -> String {
        RecoveryCodeCodec.formatSymbols(symbols(q), groupSize: RecoveryCodeCodec.groupSize)
    }

    /// Gescannter Inhalt (mit Präfix) oder abgetippte Gruppen (Gross/Klein egal, Leerraum und "-" ignoriert,
    /// O→0, I/L→1). Falsche Länge/Zeichen, Füllbits ≠ 0, unbekannte Kartenversion oder falsche Prüfsumme →
    /// `invalidRecoveryCodeFormat`.
    public static func decode(_ scannedOrTyped: String) throws -> FactorSecret {
        var rest = Substring(scannedOrTyped.trimmingCharacters(in: .whitespacesAndNewlines))
        if rest.uppercased().hasPrefix(prefixFamily) {
            guard rest.uppercased().hasPrefix(prefix) else { throw SiegelError.invalidRecoveryCodeFormat }
            rest = rest.dropFirst(prefix.count)
        }
        var syms = try RecoveryCodeCodec.parseSymbols(String(rest), allowUnknown: false)
        defer { for i in syms.indices { syms[i] = 0 } }
        let packed = try SecureBytes.scratch(count: RecoveryCodeCodec.packedBytes)
        try packed.withUnsafeMutableBytes { out in
            syms.withUnsafeBytes { RecoveryCodeCodec.pack($0, into: out) }
            let v = RecoveryCodeCodec.packedIsValid(UnsafeRawBufferPointer(out), label: checksumLabel)
            guard v.paddingOK, v.checksumOK else { throw SiegelError.invalidRecoveryCodeFormat }
        }
        return try FactorSecret(storage: try packed.slice(0..<32))
    }

    /// Karten-Kennung für diesen Tresor (4 Byte, nicht geheim).
    public static func tag(for q: FactorSecret, vaultID: UUID) -> Data {
        Data(tagBytes(q: q, vaultID: VaultHeader.bytes(of: vaultID)))
    }

    static func tagBytes(q: FactorSecret, vaultID: [UInt8]) -> [UInt8] {
        var h = SHA3_256()
        h.update(data: tagLabel)
        h.update(data: vaultID)
        q.withUnsafeBytes { h.update(bufferPointer: $0) }
        return Array(h.finalize().prefix(VaultHeader.cardTagBytes))
    }

    /// q ‖ Prüfsumme als 55 Base32-Symbole.
    private static func symbols(_ q: FactorSecret) -> [UInt8] {
        guard let payload = try? SecureBytes(count: RecoveryCodeCodec.payloadBytes, { out in
            q.withUnsafeBytes { src in
                for i in 0..<32 { out[i] = src[i] }
                let (a, b) = RecoveryCodeCodec.checksum(src, label: checksumLabel)
                out[32] = a
                out[33] = b
            }
        }) else { fatalError("card.encode") }
        return payload.withUnsafeBytes { RecoveryCodeCodec.symbols(fromBytes: $0) }
    }
}
