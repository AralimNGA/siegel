import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

@Suite("QR-Schlüsselkarte (CardCode, §14.2)")
struct KernCardCodeTests {
    private static let q0 = (0..<32).map { UInt8($0) }
    private static let vaultA = (0xa0...0xaf).map { UInt8($0) }

    @Test("Testvektor q = 00…1f: Inhalt, Gruppen, Kennung (unabhängig in Python nachgerechnet)")
    func testvektor() throws {
        let q = try FactorSecret(copying: Self.q0)
        #expect(CardCode.payload(for: q) == "SIEGELKARTE1:000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFQVT8")
        #expect(CardCode.groupedText(for: q) == "000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FQVT8")
        #expect(CardCode.tag(for: q, vaultID: VaultHeader.uuid(Self.vaultA)) == Data([0x08, 0xb8, 0xde, 0x3f]))
        // Fixture v2: q = 22…22
        let q22 = try FactorSecret(copying: KernBeispielDateiV2.q)
        let vid = try #require(UUID(uuidString: KernBeispielDateiV2.vaultID))
        #expect(KT.hex(CardCode.tag(for: q22, vaultID: vid)) == KernBeispielDateiV2.cardTag)
    }

    @Test("Rundlauf: gescannt, abgetippt, klein, mit Leerraum")
    func rundlauf() throws {
        for _ in 0..<50 {
            let q = CardCode.generate()
            let payload = CardCode.payload(for: q)
            #expect(payload.hasPrefix("SIEGELKARTE1:"))
            #expect(payload.count == 13 + 55)
            // nur Zeichen des QR-Alphanumerik-Modus
            #expect(payload.allSatisfy { "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".contains($0) })
            let grouped = CardCode.groupedText(for: q)
            #expect(grouped.split(separator: "-").count == 11)
            for input in [payload, grouped, grouped.lowercased(), " " + payload.lowercased() + "\n",
                          grouped.replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "0", with: "O")] {
                let back = try CardCode.decode(input)
                #expect(back.constantTimeEquals(q))
            }
        }
        #expect(!CardCode.generate().constantTimeEquals(CardCode.generate()))
    }

    @Test("Fehler: Prüfsumme, Füllbits, Länge, Zeichen, unbekannte Kartenversion → invalidRecoveryCodeFormat")
    func fehler() throws {
        let q = try FactorSecret(copying: Self.q0)
        let grouped = Array(CardCode.groupedText(for: q).replacingOccurrences(of: "-", with: ""))
        var typo = grouped
        typo[10] = typo[10] == "A" ? "B" : "A"
        var pad = grouped
        pad[54] = "9"   // letztes Zeichen 8 → 9 setzt ein Füllbit
        let bad = [String(typo), String(pad), String(grouped.dropLast()), String(grouped) + "0",
                   String(grouped.dropLast()) + "U", "SIEGELKARTE2:" + String(grouped), "SIEGELKARTE1:", "",
                   "?" + String(grouped.dropFirst())]
        for b in bad {
            #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try CardCode.decode(b) }
        }
        // Ein Notfallcode ist keine Karte (anderes Prüfsummen-Label)
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try CardCode.decode(KernTestvektor.code) }
    }

    @Test("Kennung hängt am Tresor; Kopf und Inhalt tragen dieselbe")
    func kennung() throws {
        let q = CardCode.generate()
        let a = CardCode.tag(for: q, vaultID: UUID())
        let b = CardCode.tag(for: q, vaultID: UUID())
        #expect(a.count == 4)
        #expect(a != b)
        #expect(CardCode.tag(for: q, vaultID: VaultHeader.uuid(Self.vaultA))
                == Data(CardCode.tagBytes(q: q, vaultID: Self.vaultA)))
    }
}

@Suite("Mehrfaktor-Ableitung (§13.1)")
struct KernKEKTests {
    private typealias B = KernBeispielDateiV2

    @Test("KAT: e, c, y und KEK_pw der Beispieldatei v2 (ohne Argon2)")
    func kat() throws {
        let vid = VaultHeader.bytes(of: try #require(UUID(uuidString: B.vaultID)))
        let salt = KT.bytes(fromHex: B.salt)
        let p = try SecureBytes.copy(KT.bytes(fromHex: B.p))
        let e = try FactorKDF.factorKey(try B.secret(B.ecdhSE), kind: .secureEnclave, vaultID: vid)
        let c = try FactorKDF.factorKey(try B.secret(B.q), kind: .card, vaultID: vid)
        let y = try FactorKDF.factorKey(try B.secret(B.hmacOutput), kind: .securityKey, vaultID: vid)
        #expect(e.hexForTesting() == B.e)
        #expect(c.hexForTesting() == B.c)
        #expect(y.hexForTesting() == B.y)
        let kek = try FactorKDF.kek(p: p, factorKeys: [e, c, y], salt: salt, mask: 7)
        #expect(kek.hexForTesting() == B.kek)
        // Über den Kopf der Datei (Reihenfolge und Maske aus dem Kopf)
        let file = try VaultFile.parse(try FileIO.read(try B.url(), maxSize: FileFormat.maxFileBytes))
        #expect(try FactorKDF.kek(p: p, header: file.header, factors: try B.factors()).hexForTesting() == B.kek)
        // und dieser KEK öffnet den pwSlot der Datei
        let dek = AEAD.unwrap(kek: kek, blob: file.slots.pwSlot, ad: VaultSlots.pwAD(file.header))
        #expect(dek != nil)
        if let dek {
            let (content, _) = try VaultCrypto.decryptPayload(file, dek: dek)
            #expect(content.level == .festung)
            #expect(content.entries.count == B.erwartet.count)
            #expect(content.entryFactors.enrolled == .all)
            #expect(content.entryFactors.secureEnclave?.keyID == B.entryKeyID)
            #expect(content.entryFactors.securityKey?.credentialID == B.credentialID)
            #expect(content.entryFactors.securityKey?.entrySalt == B.entrySalt)
        }
    }

    @Test("Reihenfolge, Maske und jeder Faktor gehen in den KEK ein")
    func bindung() throws {
        let p = try SecureBytes.random(count: 32)
        let salt = randomBytes(16)
        let keys = try (0..<3).map { _ in try SecureBytes.random(count: 32) }
        let base = try FactorKDF.kek(p: p, factorKeys: keys, salt: salt, mask: 7)
        let variants = [
            try FactorKDF.kek(p: p, factorKeys: [keys[1], keys[0], keys[2]], salt: salt, mask: 7),
            try FactorKDF.kek(p: p, factorKeys: keys, salt: salt, mask: 6),
            try FactorKDF.kek(p: p, factorKeys: Array(keys.prefix(2)), salt: salt, mask: 7),
            try FactorKDF.kek(p: p, factorKeys: keys, salt: randomBytes(16), mask: 7),
            try FactorKDF.kek(p: try SecureBytes.random(count: 32), factorKeys: keys, salt: salt, mask: 7),
            try FactorKDF.kek(p: p, factorKeys: [keys[0], keys[1], try SecureBytes.random(count: 32)], salt: salt, mask: 7),
        ]
        for v in variants { #expect(!v.constantTimeEquals(base)) }
        // Ohne Faktoren: HKDF über p allein, nicht p selbst (v2 unterscheidet sich von v1)
        let noFactors = try FactorKDF.kek(p: p, factorKeys: [], salt: salt, mask: 0)
        #expect(!noFactors.constantTimeEquals(p))
        // Faktor-Schlüssel sind domänengetrennt: gleicher Rohwert, anderer Faktor → anderer Schlüssel
        let raw = try FactorSecret(copying: randomBytes(32))
        let vid = randomBytes(16)
        let se = try FactorKDF.factorKey(raw, kind: .secureEnclave, vaultID: vid)
        let card = try FactorKDF.factorKey(raw, kind: .card, vaultID: vid)
        let fido = try FactorKDF.factorKey(raw, kind: .securityKey, vaultID: vid)
        #expect(!se.constantTimeEquals(card) && !card.constantTimeEquals(fido) && !se.constantTimeEquals(fido))
        #expect(!se.constantTimeEquals(try FactorKDF.factorKey(raw, kind: .secureEnclave, vaultID: randomBytes(16))))
    }
}
