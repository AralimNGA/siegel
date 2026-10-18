import Foundation
import Testing
@testable import SiegelCore

/// Bitfäule und gezielte Manipulation (SPEC §2, §10). Alles mit dem Testschalter-KDF (8 KiB, t = 1).
@Suite("Manipulation und Bitfäule")
struct KernByteKippTests {
    private final class Findings: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [String] = []
        func add(_ s: String) { lock.withLock { items.append(s) } }
        var all: [String] { lock.withLock { items } }
    }

    /// Tresor mit Inhalt; liefert Dateibytes, Passwort- und Notfallschlüssel.
    private func prepared() throws -> (KernVault, [UInt8], SecureBytes, SecureBytes) {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("Bank", user: "anna", password: "Konto-123", notes: "Notiz"))
        try f.vault.upsert(kernEntry("Mail", user: "anna@example.ch", password: "Post-456"))
        let bytes = try f.fileBytes()
        let pw = try PasswordNormalizer.secureBytes(KT.pw1)
        let r = try RecoveryCodeCodec.decode(f.code)
        // Kontrolle: unverändert öffnen beide Wege
        let file = try VaultFile.parse(bytes)
        _ = try VaultCrypto.openWithPassword(file, password: pw, limits: .testing)
        _ = try VaultCrypto.openWithRecovery(file, r: r)
        return (f, bytes, pw, r)
    }

    /// Parallel über alle Positionen in Blöcken.
    private func forEachPosition(_ count: Int, _ body: @escaping @Sendable (Int) -> Void) {
        let chunk = 256
        let chunks = (count + chunk - 1) / chunk
        DispatchQueue.concurrentPerform(iterations: chunks) { c in
            for i in (c * chunk)..<min(count, (c + 1) * chunk) { body(i) }
        }
    }

    @Test("Jedes einzelne Byte gekippt → corruptFile(\"file.checksum\")")
    func jedesByte() throws {
        let (_, bytes, pw, r) = try prepared()
        let findings = Findings()
        for mask: UInt8 in [0x01, 0x80, 0xFF] {
            forEachPosition(bytes.count) { i in
                var b = bytes
                b[i] ^= mask
                for path in 0..<2 {
                    do {
                        let file = try VaultFile.parse(b)
                        if path == 0 {
                            _ = try VaultCrypto.openWithPassword(file, password: pw, limits: .testing)
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

    @Test("Angreifer: Byte kippen und Prüfsumme neu berechnen → beide Wege nie Erfolg, nie Absturz")
    func angreiferMitPruefsumme() throws {
        let (f, bytes, pw, r) = try prepared()
        let original = f.vault.allEntriesForTesting
        let findings = Findings()
        let body = bytes.count - FileFormat.checksumBytes
        for mask: UInt8 in [0x01, 0x80] {
            forEachPosition(body) { i in
                var b = bytes
                b[i] ^= mask
                let forged = KT.withFixedChecksum(b)
                // Passwortweg
                do {
                    let file = try VaultFile.parse(forged)
                    let opened = try VaultCrypto.openWithPassword(file, password: pw, limits: .testing)
                    findings.add("pw ok \(i) gleich=\(opened.content.entries == original)")
                } catch let e as SiegelError {
                    switch e {
                    case .wrongPassword, .corruptFile, .kdfParametersOutOfRange, .unsupportedVersion: break
                    default: findings.add("pw \(i): \(e)")
                    }
                } catch {
                    findings.add("pw \(i): fremder Fehler")
                }
                // Notfallweg
                do {
                    let file = try VaultFile.parse(forged)
                    let opened = try VaultCrypto.openWithRecovery(file, r: r)
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

    @Test("Abgeschnitten oder verlängert → corruptFile (auch mit neu berechneter Prüfsumme)")
    func laenge() throws {
        let (f, bytes, pw, r) = try prepared()
        let hl = KT.headerLength(bytes)
        var variants: [[UInt8]] = []
        for cut in [1, 31, 32, 33, 100, 16_384, bytes.count - hl, bytes.count - 1653, bytes.count - 1, bytes.count] {
            variants.append(Array(bytes.prefix(bytes.count - cut)))
        }
        for extra in [1, 16, 32, 16_384] {
            variants.append(bytes + [UInt8](repeating: 0, count: extra))
        }
        // Angreifer: Länge ändern und Prüfsumme neu berechnen
        variants.append(KT.withFixedChecksum(Array(bytes.dropLast(1))))
        variants.append(KT.withFixedChecksum(bytes + [0]))
        variants.append(KT.withFixedChecksum(Array(bytes.prefix(hl + VaultSlots.size + 36 + 32))))
        var inserted = bytes
        inserted.insert(0, at: hl + VaultSlots.size + 36)
        variants.append(KT.withFixedChecksum(inserted))
        for v in variants {
            let e1 = #expect(throws: SiegelError.self) {
                _ = try VaultCrypto.openWithPassword(try VaultFile.parse(v), password: pw, limits: .testing)
            }
            #expect(KT.isCorrupt(e1), "Länge \(v.count): \(String(describing: e1))")
            let e2 = #expect(throws: SiegelError.self) {
                _ = try VaultCrypto.openWithRecovery(try VaultFile.parse(v), r: r)
            }
            #expect(KT.isCorrupt(e2), "Länge \(v.count): \(String(describing: e2))")
        }
        // Über die öffentliche API (Platte)
        try f.writeFile(Array(bytes.dropLast(5)))
        let e3 = #expect(throws: SiegelError.self) { try f.store.unlock(masterPassword: KT.pw1) }
        #expect(KT.isCorrupt(e3))
        let e4 = #expect(throws: SiegelError.self) {
            try f.store.recover(code: f.code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        #expect(KT.isCorrupt(e4))
    }

    @Test("Über die öffentliche API: gekipptes Byte → corruptFile, Datei bleibt unberührt")
    func oeffentlicheAPI() throws {
        let (f, bytes, _, _) = try prepared()
        for i in [0, 7, 100, KT.headerLength(bytes) + 3, bytes.count / 2, bytes.count - 40, bytes.count - 1] {
            var b = bytes
            b[i] ^= 0x10
            try f.writeFile(b)
            #expect(throws: SiegelError.corruptFile("file.checksum")) { try f.store.unlock(masterPassword: KT.pw1) }
            #expect(throws: SiegelError.corruptFile("file.checksum")) {
                try f.store.recover(code: f.code, newMasterPassword: KT.pw2, kdf: KT.kdf)
            }
            #expect(try f.fileBytes() == b)
        }
        // Notfallcode prüfen liest für den Treffer nur den Kopf: Inhalt beschädigt → Code trotzdem erkannt
        var b = bytes
        b[bytes.count / 2] ^= 0x10
        try f.writeFile(b)
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
        // Befund #22: Kopf beschädigt (vaultID, pkM, pkX) → ohne Treffer zuerst die Prüfsumme → corruptFile statt
        // einer erfundenen Kit-Kennung
        let hl = KT.headerLength(bytes)
        for i in [10, 200, hl - 10] {
            var h = bytes
            h[i] ^= 0x01
            try f.writeFile(h)
            #expect(throws: SiegelError.corruptFile("file.checksum"), "Byte \(i)") { try f.store.checkRecoveryCode(f.code) }
            // auch mit einem Tippfehler (Korrektur findet nichts)
            var typo = Array(f.code)
            typo[0] = typo[0] == "A" ? "B" : "A"
            #expect(throws: SiegelError.corruptFile("file.checksum"), "Byte \(i)") {
                try f.store.checkRecoveryCode(String(typo))
            }
        }
    }

    @Test("Teile zwischen Tresoren vertauschen → nie Erfolg")
    func teileVertauschen() throws {
        let (a, bytesA, pw, rA) = try prepared()
        let b = try KernVault.make()   // gleiches Passwort
        try b.vault.upsert(kernEntry("B-Eintrag"))
        let bytesB = try b.fileBytes()
        let h = KT.headerLength(bytesA)
        #expect(h == KT.headerLength(bytesB))
        let s = VaultSlots.size
        let body = bytesA.count - 32
        // KOPF von A + SLOTS/INHALT von B
        let mix1 = KT.withFixedChecksum(Array(bytesA[0..<h]) + Array(bytesB[h...]))
        // KOPF+SLOTS von A + INHALT von B
        let mix2 = KT.withFixedChecksum(Array(bytesA[0..<(h + s)]) + Array(bytesB[(h + s)...]))
        // pwSlot von B in A
        var mix3 = bytesA
        mix3.replaceSubrange(h..<(h + 72), with: bytesB[h..<(h + 72)])
        mix3 = KT.withFixedChecksum(mix3)
        // recSlot (ctM/ctX/Wrap) von B in A
        var mix4 = bytesA
        mix4.replaceSubrange((h + 72)..<(h + s), with: bytesB[(h + 72)..<(h + s)])
        mix4 = KT.withFixedChecksum(mix4)
        // Inhalt einer anderen Generation desselben Tresors mit der Generation-Zahl der neueren Datei
        try a.vault.upsert(kernEntry("Neu"))
        let newer = try a.fileBytes()
        var mix5 = bytesA
        mix5.replaceSubrange((h + s)..<(h + s + 8), with: newer[(h + s)..<(h + s + 8)])
        mix5 = KT.withFixedChecksum(mix5)
        _ = body
        for (n, m) in [mix1, mix2, mix3, mix4, mix5].enumerated() {
            #expect(throws: SiegelError.self, "Variante \(n + 1) Passwort") {
                _ = try VaultCrypto.openWithPassword(try VaultFile.parse(m), password: pw, limits: .testing)
            }
            #expect(throws: SiegelError.self, "Variante \(n + 1) Notfall") {
                _ = try VaultCrypto.openWithRecovery(try VaultFile.parse(m), r: rA)
            }
        }
    }

    @Test("Höhere Formatversion → unsupportedVersion, Datei wird nie überschrieben")
    func hoehereVersion() throws {
        let (f, bytes, _, _) = try prepared()
        var b = bytes
        b[6] = 3
        b[7] = 0
        b = KT.withFixedChecksum(b)   // Label "Siegel v3 file check" (Muster aller Versionen)
        try f.writeFile(b)
        #expect(throws: SiegelError.unsupportedVersion(3)) { try f.store.unlock(masterPassword: KT.pw1) }
        #expect(throws: SiegelError.unsupportedVersion(3)) { try f.store.checkRecoveryCode(f.code) }
        #expect(throws: SiegelError.unsupportedVersion(3)) { try f.store.inspect() }
        #expect(throws: SiegelError.unsupportedVersion(3)) {
            try f.store.recover(code: f.code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        // Speichern aus einer offenen Sitzung überschreibt die neuere Datei nicht
        #expect(throws: SiegelError.vaultChangedOnDisk) { try f.vault.upsert(kernEntry("X")) }
        #expect(try f.fileBytes() == b)
        // Wiederherstellen/Einspielen überschreibt sie auch nicht
        let backup = try #require(f.localBackups().first)
        #expect(throws: SiegelError.unsupportedVersion(3)) { try f.store.restoreBackup(backup, masterPassword: KT.pw1) }
        #expect(throws: SiegelError.unsupportedVersion(3)) { try f.store.restoreNewestReadableBackup(masterPassword: KT.pw1) }
        // Versionsbyte gekippt, Prüfsumme alt → Bitfäule, nicht „neuere Version“
        var flipped = bytes
        flipped[6] ^= 0x01
        try f.writeFile(flipped)
        #expect(throws: SiegelError.corruptFile("file.checksum")) { try f.store.unlock(masterPassword: KT.pw1) }
        try f.writeFile(b)
        #expect(try f.fileBytes() == b)
        // Version 0, falsche Magie, falscher KDF-Algorithmus
        var v0 = bytes
        v0[6] = 0
        #expect(throws: SiegelError.corruptFile("header.version")) { try VaultFile.parse(KT.withFixedChecksum(v0)) }
        var magic = bytes
        magic[0] = UInt8(ascii: "X")
        #expect(throws: SiegelError.corruptFile("header.magic")) { try VaultFile.parse(KT.withFixedChecksum(magic)) }
        var alg = bytes
        alg[24] = 2
        #expect(throws: SiegelError.corruptFile("header.kdfAlg")) { try VaultFile.parse(KT.withFixedChecksum(alg)) }
    }
}
