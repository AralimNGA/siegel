import Foundation
import Testing
@testable import SiegelCore

/// Dateiformat v2 (§13.2): strenger Parser, Konsistenz Maske ↔ Nullfelder, Bitfäule und Manipulation.
@Suite("Dateiformat v2")
struct KernFormatV2Tests {
    /// Offsets im Kopf v2.
    enum Off {
        static let mask = 53
        static let scheme = 54
        static let se = 55
        static let tag = 71
        static let credLen = 75
        static let cred = 77
    }

    private static func pk() -> RecoveryPublicKeys {
        RecoveryPublicKeys(pkM: randomBytes(RecoveryPublicKeys.pkMBytes), pkX: randomBytes(RecoveryPublicKeys.pkXBytes))
    }

    @Test("Kopf v2: Rundlauf aller Masken und Schemata, Credential 16 und 1024 Byte, Nullfelder")
    func rundlauf() throws {
        let vaultID = randomBytes(16)
        for raw in UInt8(0)...7 {
            for scheme in [RecoveryScheme.single, .shamir2of3] {
                for credLen in [16, 1024] {
                    let mask = FactorSet(rawValue: raw)
                    var fields = HeaderFactorFields.none
                    if mask.contains(.secureEnclave) { fields.seKeyID = UUID() }
                    if mask.contains(.card) { fields.cardTag = randomBytes(4) }
                    if mask.contains(.securityKey) {
                        fields.fidoCredentialID = randomBytes(credLen)
                        fields.fidoSalt = randomBytes(32)
                    }
                    let h = try VaultHeader(vaultID: vaultID, kdf: KT.kdf, salt: randomBytes(16), factors: fields,
                                            recoveryScheme: scheme, pk: Self.pk())
                    let extra = mask.contains(.securityKey) ? credLen : 0
                    #expect(h.bytes.count == VaultHeader.v2FixedSize + extra)
                    var r = ByteReader(h.bytes + [9, 9, 9])
                    let back = try VaultHeader.parse(&r)
                    #expect(back == h)
                    #expect(r.remaining == 3)
                    #expect(back.factors == mask)
                    let info = back.info
                    #expect(info.formatVersion == 2)
                    #expect(info.factors == mask)
                    #expect(info.recoveryScheme == scheme)
                    #expect((info.seKeyID != nil) == mask.contains(.secureEnclave))
                    #expect((info.cardTag != nil) == mask.contains(.card))
                    #expect((info.fidoCredentialID != nil) == mask.contains(.securityKey))
                    #expect((info.fidoSalt != nil) == mask.contains(.securityKey))
                    // ungesetzte Felder sind Nullbytes
                    if !mask.contains(.secureEnclave) { #expect(h.bytes[Off.se..<Off.tag].allSatisfy { $0 == 0 }) }
                    if !mask.contains(.card) { #expect(h.bytes[Off.tag..<Off.credLen].allSatisfy { $0 == 0 }) }
                    if !mask.contains(.securityKey) {
                        #expect(h.bytes[Off.credLen..<(Off.cred + 32)].allSatisfy { $0 == 0 })
                    }
                }
            }
        }
    }

    @Test("Kopf v2 schreiben: falsche Faktor-Felder werden abgelehnt")
    func schreibenGeprueft() {
        let vid = randomBytes(16)
        let bad: [HeaderFactorFields] = [
            HeaderFactorFields(seKeyID: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)), cardTag: nil,
                               fidoCredentialID: nil, fidoSalt: nil),
            HeaderFactorFields(seKeyID: nil, cardTag: [1, 2, 3], fidoCredentialID: nil, fidoSalt: nil),
            HeaderFactorFields(seKeyID: nil, cardTag: nil, fidoCredentialID: randomBytes(15), fidoSalt: randomBytes(32)),
            HeaderFactorFields(seKeyID: nil, cardTag: nil, fidoCredentialID: randomBytes(1025), fidoSalt: randomBytes(32)),
            HeaderFactorFields(seKeyID: nil, cardTag: nil, fidoCredentialID: randomBytes(16), fidoSalt: nil),
            HeaderFactorFields(seKeyID: nil, cardTag: nil, fidoCredentialID: nil, fidoSalt: randomBytes(32)),
            HeaderFactorFields(seKeyID: nil, cardTag: nil, fidoCredentialID: randomBytes(16), fidoSalt: [UInt8](repeating: 0, count: 32)),
        ]
        for f in bad {
            let e = #expect(throws: SiegelError.self) {
                _ = try VaultHeader(vaultID: vid, kdf: KT.kdf, salt: randomBytes(16), factors: f, recoveryScheme: .single,
                                    pk: Self.pk())
            }
            if case .crypto = e {} else { Issue.record("erwartet crypto(...)") }
        }
    }

    /// Stufe-5-Testtresor: Dateibytes, Faktoren, Notfall-R.
    private func level5() throws -> (KernVault, KernFaktoren, [UInt8], SecureBytes, SecureBytes) {
        let (f, k, kit) = try KernStufen.make(.festung)
        try f.vault.upsert(kernEntry("Bank", password: "Konto-123", notes: "Notiz"))
        let bytes = try f.fileBytes()
        let pw = try PasswordNormalizer.secureBytes(KT.pw1)
        let shares = try #require(kit?.shares.map(\.formatted))
        let r = try VaultStore.combineShares([shares[0], shares[1]])
        let file = try VaultFile.parse(bytes)
        _ = try VaultCrypto.openWithPassword(file, password: pw, factors: try k.secrets(), limits: .testing)
        _ = try VaultCrypto.openWithRecovery(file, r: r)
        return (f, k, bytes, pw, r)
    }

    @Test("Strenger Parser: Masken, Schema, Nullfelder, Credential-Länge (Prüfsumme neu berechnet)")
    func strengerParser() throws {
        let (_, k, bytes, _, _) = try level5()
        let credLen = k.credentialID.count
        let saltAt = Off.cred + credLen
        func variant(_ change: (inout [UInt8]) -> Void) -> [UInt8] {
            var b = bytes
            change(&b)
            return KT.withFixedChecksum(b)
        }
        let cases: [(String, [UInt8])] = [
            ("header.factorMask", variant { $0[Off.mask] |= 0x08 }),
            ("header.factorMask", variant { $0[Off.mask] = 0x80 }),
            ("header.recoveryScheme", variant { $0[Off.scheme] = 0 }),
            ("header.recoveryScheme", variant { $0[Off.scheme] = 3 }),
            ("header.seKeyID", variant { $0[Off.mask] &= ~0x01 }),
            ("header.seKeyID", variant { for i in Off.se..<Off.tag { $0[i] = 0 } }),
            ("header.cardTag", variant { $0[Off.mask] &= ~0x02 }),
            ("header.fidoCredential", variant { $0[Off.mask] &= ~0x04 }),
            ("header.fidoCredential", variant { $0[Off.credLen] = 15; $0[Off.credLen + 1] = 0 }),
            ("header.fidoCredential", variant { $0[Off.credLen] = 0x01; $0[Off.credLen + 1] = 0x04 }),   // 1025
            ("header.fidoCredential", variant { $0[Off.credLen] = 0; $0[Off.credLen + 1] = 0 }),
            ("header.fidoSalt", variant { for i in saltAt..<(saltAt + 32) { $0[i] = 0 } }),
            ("header.fidoSalt", variant { b in
                // FIDO-Bit aus, Credential entfernt, Länge 0, aber Salz nicht null
                b[Off.mask] &= ~0x04
                b[Off.credLen] = 0
                b[Off.credLen + 1] = 0
                b.removeSubrange(Off.cred..<(Off.cred + credLen))
            }),
            ("header.version", variant { $0[6] = 0 }),
            ("header.kdfAlg", variant { $0[24] = 2 }),
        ]
        for (code, v) in cases {
            #expect(throws: SiegelError.corruptFile(code), "\(code)") { try VaultFile.parse(v) }
        }
    }

    @Test("Jedes einzelne Byte einer v2-Datei (Stufe 5) gekippt → corruptFile(\"file.checksum\")")
    func jedesByteV2() throws {
        let (_, k, bytes, pw, r) = try level5()
        let factors = try k.secrets()
        let findings = KernFindings()
        for mask: UInt8 in [0x01, 0x80, 0xFF] {
            KernParallel.forEach(bytes.count) { i in
                var b = bytes
                b[i] ^= mask
                for path in 0..<2 {
                    do {
                        let file = try VaultFile.parse(b)
                        if path == 0 {
                            _ = try VaultCrypto.openWithPassword(file, password: pw, factors: factors, limits: .testing)
                        } else {
                            _ = try VaultCrypto.openWithRecovery(file, r: r)
                        }
                        findings.add("ok \(i)")
                    } catch let e as SiegelError {
                        if e != .corruptFile("file.checksum") { findings.add("\(i): \(e)") }
                    } catch {
                        findings.add("\(i): fremder Fehler")
                    }
                }
            }
        }
        #expect(findings.all.isEmpty, "\(findings.all.prefix(10))")
    }

    @Test("Angreifer (v2, Stufe 5): Byte kippen + Prüfsumme neu → beide Wege nie Erfolg, nie Absturz")
    func angreiferV2() throws {
        let (f, k, bytes, pw, r) = try level5()
        let factors = try k.secrets()
        let original = f.vault.allEntriesForTesting
        let findings = KernFindings()
        let body = bytes.count - FileFormat.checksumBytes
        for mask: UInt8 in [0x01, 0x80] {
            KernParallel.forEach(body) { i in
                var b = bytes
                b[i] ^= mask
                let forged = KT.withFixedChecksum(b)
                do {
                    let opened = try VaultCrypto.openWithPassword(try VaultFile.parse(forged), password: pw,
                                                                  factors: factors, limits: .testing)
                    findings.add("pw ok \(i) gleich=\(opened.content.entries == original)")
                } catch let e as SiegelError {
                    switch e {
                    case .wrongPassword, .corruptFile, .kdfParametersOutOfRange, .unsupportedVersion, .factorMissing,
                         .wrongCard:
                        break
                    default: findings.add("pw \(i): \(e)")
                    }
                } catch {
                    findings.add("pw \(i): fremder Fehler")
                }
                do {
                    let opened = try VaultCrypto.openWithRecovery(try VaultFile.parse(forged), r: r)
                    findings.add("rec ok \(i) gleich=\(opened.content.entries == original)")
                } catch let e as SiegelError {
                    switch e {
                    case .wrongRecoveryCode, .corruptFile, .unsupportedVersion: break
                    default: findings.add("rec \(i): \(e)")
                    }
                } catch {
                    findings.add("rec \(i): fremder Fehler")
                }
            }
        }
        #expect(findings.all.isEmpty, "\(findings.all.prefix(10))")
    }

    @Test("Herabstufung durch Kopf-Änderung (Faktoren entfernen, v1-Kopf, Schema) → nie Erfolg")
    func herabstufung() throws {
        let (f, k, bytes, pw, r) = try level5()
        let file = try VaultFile.parse(bytes)
        let h = file.header
        let rest = Array(bytes[h.bytes.count..<(bytes.count - FileFormat.checksumBytes)])
        func with(_ header: [UInt8]) -> [UInt8] { KT.withFixedChecksum(header + rest + [UInt8](repeating: 0, count: 32)) }
        var variants: [(String, [UInt8], FactorSecrets)] = []
        for drop in [FactorSet.secureEnclave, .card, .securityKey, .all] {
            var fields = h.factorFields
            if drop.contains(.secureEnclave) { fields.seKeyID = nil }
            if drop.contains(.card) { fields.cardTag = nil }
            if drop.contains(.securityKey) {
                fields.fidoCredentialID = nil
                fields.fidoSalt = nil
            }
            let nh = try VaultHeader(vaultID: h.vaultID, kdf: h.kdf, salt: h.salt, factors: fields,
                                     recoveryScheme: h.recoveryScheme, pk: h.pk)
            variants.append(("ohne \(drop.rawValue)", with(nh.bytes), try k.secrets(fields.mask)))
        }
        let single = try VaultHeader(vaultID: h.vaultID, kdf: h.kdf, salt: h.salt, factors: h.factorFields,
                                     recoveryScheme: .single, pk: h.pk)
        variants.append(("Schema 1", with(single.bytes), try k.secrets()))
        let v1 = VaultHeader(v1: h.vaultID, kdf: h.kdf, salt: h.salt, pk: h.pk)
        variants.append(("v1-Kopf", with(v1.bytes), FactorSecrets()))
        for (name, v, factors) in variants {
            let parsed = try VaultFile.parse(v)
            #expect(throws: SiegelError.wrongPassword, "\(name)") {
                try VaultCrypto.openWithPassword(parsed, password: pw, factors: factors, limits: .testing)
            }
            #expect(throws: SiegelError.corruptFile("rec.slot"), "\(name)") { try VaultCrypto.openWithRecovery(parsed, r: r) }
        }
        _ = f
    }

    @Test("Stufe im Inhalt muss zu den Faktoren im Kopf passen (lesen und schreiben)")
    func konsistenz() throws {
        let f = try KernVault.make()
        let s = f.vault.headerForTesting
        let header = try #require(s)
        let dek = try SecureBytes.random(count: 32)
        let kek = try SecureBytes.random(count: 32)
        let slots = try VaultCrypto.makeSlots(header: header, kekPw: kek, dek: dek)
        var content = VaultContent.empty(now: Clock.now())
        content.level = .festung
        let built = try VaultCrypto.buildFile(header: header, slots: slots, generation: 9, dek: dek, content: content)
        #expect(throws: SiegelError.corruptFile("payload.level")) {
            try VaultCrypto.decryptPayload(try VaultFile.parse(built.bytes), dek: dek)
        }
        #expect(throws: SiegelError.crypto("level.mismatch")) {
            try f.store.persist(header: header, slots: slots, dek: dek, content: content, baseGeneration: 1,
                                expectation: .generation(f.vault.vaultID, 1), reason: nil)
        }
        // Format v1 wird nie geschrieben
        let v1 = VaultHeader(v1: header.vaultID, kdf: header.kdf, salt: header.salt, pk: header.pk)
        let v1Slots = try VaultCrypto.makeSlots(header: v1, kekPw: kek, dek: dek)
        #expect(throws: SiegelError.crypto("format.version")) {
            try f.store.persist(header: v1, slots: v1Slots, dek: dek, content: .empty(now: Clock.now()), baseGeneration: 1,
                                expectation: .generation(f.vault.vaultID, 1), reason: nil)
        }
        #expect(try f.parsedFile().generation == 1)
    }

    @Test("inspect(): nur Kopf + Prüfsumme; fehlend, beschädigt, v1")
    func inspect() throws {
        let f = try KernVault.make()
        let info = try f.store.inspect()
        #expect(info.formatVersion == 2)
        #expect(info.vaultID == f.vault.vaultID)
        #expect(info.factors.isEmpty)
        #expect(info.recoveryScheme == .single)
        #expect(info.seKeyID == nil && info.cardTag == nil && info.fidoCredentialID == nil && info.fidoSalt == nil)
        #expect(info.kdf == KT.kdf)
        #expect(info.kitID == f.pending.code.kitID)
        #expect(info == f.vault.headerInfo)
        var b = try f.fileBytes()
        b[b.count / 2] ^= 1
        try f.writeFile(b)
        #expect(throws: SiegelError.corruptFile("file.checksum")) { try f.store.inspect() }
        FileIO.remove(f.store.vaultURL)
        #expect(throws: SiegelError.vaultMissing) { try f.store.inspect() }
        let v1 = try VaultStore.inspect(fileAt: try KernBeispielDatei.url())
        #expect(v1.formatVersion == 1)
        #expect(v1.factors.isEmpty)
        #expect(v1.recoveryScheme == .single)
        #expect(v1.kitID == KernBeispielDatei.kitID)
        #expect(v1.kdf == KernBeispielDatei.kdf)
        #expect(f.store.hardwareDirectory.lastPathComponent == "Hardware")
        #expect(f.store.hardwareDirectory.deletingLastPathComponent().standardizedFileURL
                == f.store.directory.standardizedFileURL)
    }
}

/// Sammelt Befunde aus parallelen Läufen.
final class KernFindings: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ s: String) { lock.withLock { items.append(s) } }
    var all: [String] { lock.withLock { items } }
}

enum KernParallel {
    /// Parallel über alle Positionen in Blöcken.
    static func forEach(_ count: Int, _ body: @escaping @Sendable (Int) -> Void) {
        let chunk = 256
        DispatchQueue.concurrentPerform(iterations: (count + chunk - 1) / chunk) { c in
            for i in (c * chunk)..<min(count, (c + 1) * chunk) { body(i) }
        }
    }
}
