import Foundation
import Testing
@testable import SiegelCore

@Suite("Notfallcode in Teilen (Shamir 2 aus 3, §15)")
struct KernShamirTests {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    private func chars(_ s: String) -> [Character] { Array(s.replacingOccurrences(of: "-", with: "")) }
    private func other(_ c: Character, shift: Int = 7) -> Character {
        let i = Self.alphabet.firstIndex(of: c) ?? 0
        return Self.alphabet[(i + shift) % 32]
    }
    private func grouped(_ c: [Character]) -> String {
        stride(from: 0, to: c.count, by: 5).map { String(c[$0..<min(c.count, $0 + 5)]) }.joined(separator: "-")
    }

    @Test("GF(2^8): Multiplikation (FIPS-197-Beispiele) und Inverse")
    func gf256() {
        #expect(GF256.mul(0x57, 0x83) == 0xC1)
        #expect(GF256.mul(0x57, 0x13) == 0xFE)
        #expect(GF256.mul(0, 0xAB) == 0)
        #expect(GF256.mul(1, 0xAB) == 0xAB)
        #expect(GF256.inv(0) == 0)
        for a in 1...255 {
            #expect(GF256.mul(UInt8(a), GF256.inv(UInt8(a))) == 1)
        }
        // Kommutativ und distributiv (Stichprobe)
        for (a, b, c) in [(0x12, 0x34, 0x56), (0xFF, 0x80, 0x01), (0x8D, 0xF6, 0x7B)] as [(UInt8, UInt8, UInt8)] {
            #expect(GF256.mul(a, b) == GF256.mul(b, a))
            #expect(GF256.mul(a, b ^ c) == GF256.mul(a, b) ^ GF256.mul(a, c))
        }
    }

    @Test("Testvektor: R = 00…1f, a = a0…bf → feste Teile; jedes Paar ergibt R")
    func testvektor() throws {
        let r = try SecureBytes.copy((0..<32).map { UInt8($0) })
        let a = try SecureBytes.copy((0..<32).map { UInt8(0xA0 + $0) })
        let ys = try Shamir.split(r, coefficients: a)
        #expect(ys[0].hexForTesting() == String(repeating: "a0", count: 32))
        #expect(ys[1].hexForTesting() == "5b585d5e57545152434045464f4c494a6b686d6e67646162737075767f7c797a")
        #expect(ys[2].hexForTesting() == "fbf9fffdf3f1f7f5ebe9efede3e1e7e5dbd9dfddd3d1d7d5cbc9cfcdc3c1c7c5")
        let codes = try ys.enumerated().map { i, y in try Shamir.format(x: UInt8(i + 1), y: y) }
        #expect(codes == [
            "06GA1-850M2-GA185-0M2GA-1850M-2GA18-50M2G-A1850-M2GA1-850M2-GA1GP-B",
            "09DNG-QAYAX-A52MJ-3812M-CKTC9-556PT-3DDSK-P8RB2-EDR7A-XKZFH-WQNY6-N",
            "0FXZK-ZZXYF-RZFXF-BX7QY-VRZ1W-ZJXQP-EZVQ9-X3NYN-SF4WZ-KE3R7-3WATN-T",
        ])
        for (i, j) in [(0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (2, 1)] {
            let back = try VaultStore.combineShares([codes[i], codes[j]])
            #expect(back.constantTimeEquals(r))
        }
        // Ein Teil allein verrät nichts Bestimmtes: zu jedem R' gibt es ein a' mit gleichem Teil 1
        #expect(codes.allSatisfy { $0.count == 56 + 11 })
        #expect(codes.map { VaultStore.recoveryShareIndex($0) } == [1, 2, 3])
    }

    @Test("Zufälliges R: alle drei Paare in beiden Reihenfolgen")
    func zufaellig() throws {
        for _ in 0..<20 {
            let r = try SecureBytes.random(count: 32)
            let ys = try Shamir.split(r)
            let codes = try ys.enumerated().map { i, y in try Shamir.format(x: UInt8(i + 1), y: y) }
            for (i, j) in [(0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (2, 1)] {
                #expect(try VaultStore.combineShares([codes[i], codes[j]]).constantTimeEquals(r))
            }
        }
    }

    @Test("Format: Länge, Zeichen, Prüfsumme, Teilnummer, gleiche Teile")
    func format() throws {
        let r = try SecureBytes.random(count: 32)
        let codes = try Shamir.split(r).enumerated().map { i, y in try Shamir.format(x: UInt8(i + 1), y: y) }
        let c = chars(codes[0])
        #expect(c.count == 56)
        #expect(codes[0].split(separator: "-").count == 12)
        // Eingabe tolerant
        for v in [codes[0].lowercased(), String(c), codes[0].replacingOccurrences(of: "-", with: " ")] {
            #expect(try Shamir.decode(v).x == 1)
        }
        for bad in [String(c.dropLast()), String(c) + "0", String(c.dropLast()) + "U", "", String(c.dropLast()) + "?"] {
            #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try Shamir.decode(bad) }
        }
        var d = c
        d[30] = other(d[30])
        #expect(throws: SiegelError.recoveryCodeChecksum) { try Shamir.decode(String(d)) }
        #expect(VaultStore.recoveryShareIndex(String(d)) == nil)
        // x = 0 oder 4 (gültige Prüfsumme dazu) → wie ein Tippfehler
        for x: UInt8 in [0, 4] {
            let y = try SecureBytes.random(count: 32)
            let fake = try Shamir.format(x: x, y: y)
            #expect(throws: SiegelError.recoveryCodeChecksum) { try Shamir.decode(fake) }
        }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try VaultStore.combineShares([codes[1], codes[1]]) }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try VaultStore.combineShares([codes[1]]) }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try VaultStore.combineShares(codes) }
        #expect(VaultStore.recoveryShareInputIsComplete(codes[2]))
        #expect(VaultStore.recoveryShareInputIsComplete("????" + String(c.dropFirst(4))))
        #expect(!VaultStore.recoveryShareInputIsComplete(String(c.dropLast())))
        // geschwärzt
        let share = RecoveryShare(index: 1, formatted: codes[0], kitID: "AAAA-BBBB")
        #expect(!String(describing: share).contains(codes[0]))
        var dumped = ""
        dump(share, to: &dumped)
        #expect(!dumped.contains(String(c.prefix(10))))
    }

    @Test("prepareRecovery(.shamir2of3) + commitRecovery mit 3 Gruppen (Stufe 4)")
    func vorbereitenUndBestaetigen() throws {
        let (f, k, kit) = try KernStufen.make(.maximal)
        let current = try k.secrets([.secureEnclave, .card])
        #expect(kit?.scheme == .shamir2of3)
        let p = try f.vault.prepareRecovery(masterPassword: KT.pw1, factors: current, scheme: .shamir2of3)
        #expect(p.scheme == .shamir2of3)
        #expect(p.shares.count == 3)
        #expect(p.shares.map(\.index) == [1, 2, 3])
        #expect(p.shares.allSatisfy { $0.kitID == p.code.kitID })
        #expect(p.code.formatted.isEmpty)             // nie ein ganzer Code
        #expect(p.confirmationGroups.isEmpty)
        #expect(p.shareConfirmationGroups.count == 3)
        #expect(p.shareConfirmationGroups.allSatisfy { (0..<11).contains($0) })
        #expect(throws: SiegelError.wrongPassword) {
            try f.vault.prepareRecovery(masterPassword: KT.pw2, factors: current, scheme: .shamir2of3)
        }
        #expect(throws: SiegelError.factorMissing(.card)) {
            try f.vault.prepareRecovery(masterPassword: KT.pw1, factors: try k.secrets([.secureEnclave]), scheme: .shamir2of3)
        }
        let gen = f.vault.generation
        let right = KernStufen.confirmation(p)
        var wrong = right
        wrong[1] = String(wrong[1].map { other($0) })
        #expect(throws: SiegelError.recoveryConfirmationMismatch) { try f.vault.commitRecovery(p, confirmation: wrong) }
        #expect(throws: SiegelError.recoveryConfirmationMismatch) {
            try f.vault.commitRecovery(p, confirmation: Array(right.prefix(2)))
        }
        #expect(f.vault.generation == gen)
        // alter Kit gilt bis zum commit
        let oldShares = try #require(kit?.shares.map(\.formatted))
        #expect(try f.store.checkRecoveryShares([oldShares[0], oldShares[1]]) == [.exact, .exact])
        try f.vault.commitRecovery(p, confirmation: right.map { " " + $0.lowercased() })
        #expect(f.vault.kitID == p.code.kitID)
        #expect(f.vault.recoveryConfirmed)
        #expect(f.localBackups().contains { $0.reason == "neues-kit" })
        let newShares = p.shares.map(\.formatted)
        #expect(try f.store.checkRecoveryShares([newShares[2], newShares[1]]) == [.exact, .exact])
        let e = #expect(throws: SiegelError.self) { try f.store.checkRecoveryShares([oldShares[0], oldShares[1]]) }
        if case .wrongRecoveryCode(_, let vaultKit) = e { #expect(vaultKit == p.code.kitID) } else {
            Issue.record("erwartet wrongRecoveryCode")
        }
        // Faktoren bleiben
        #expect(f.vault.headerInfo.factors == [.secureEnclave, .card])
        f.vault.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1, factors: current)) != nil)
    }

    @Test("Ein Kit mit anderem Schema als die Stufe lässt sich nicht direkt schreiben")
    func schemaPasstNicht() throws {
        let f = try KernVault.make()
        let p = try f.vault.prepareRecovery(masterPassword: KT.pw1, factors: FactorSecrets(), scheme: .shamir2of3)
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try f.vault.commitRecovery(p, confirmation: KernStufen.confirmation(p))
        }
        #expect(f.vault.generation == 1)
        // Ohne Angabe: Schema der Stufe
        #expect(try f.vault.prepareRecovery(masterPassword: KT.pw1).scheme == .single)
    }

    @Test("checkRecoveryShares: exakt, ?-Stellen, 1 und 2 Fehler, vertauschte Nachbarn, pro Teil")
    func korrektur() throws {
        let (f, _, kit) = try KernStufen.make(.maximal)
        let s = try #require(kit?.shares.map(\.formatted))
        let a = chars(s[0])
        let b = chars(s[2])
        #expect(try f.store.checkRecoveryShares([s[0], s[2]]) == [.exact, .exact])
        // 1 Fehler in Teil A
        var a1 = a
        a1[17] = other(a1[17])
        #expect(try f.store.checkRecoveryShares([grouped(a1), s[2]])
                == [.corrected(formatted: s[0], changedPositions: [17]), .exact])
        // 2 Fehler in Teil B (auch im letzten Zeichen) und 1 in A
        var b2 = b
        b2[3] = other(b2[3])
        b2[55] = other(b2[55], shift: 11)
        #expect(try f.store.checkRecoveryShares([grouped(a1), String(b2)])
                == [.corrected(formatted: s[0], changedPositions: [17]),
                    .corrected(formatted: s[2], changedPositions: [3, 55])])
        // vertauschte Nachbarn
        if let pos = (0..<55).first(where: { a[$0] != a[$0 + 1] }) {
            var sw = a
            sw.swapAt(pos, pos + 1)
            #expect(try f.store.checkRecoveryShares([s[2], grouped(sw)])
                    == [.exact, .corrected(formatted: s[0], changedPositions: [pos, pos + 1])])
        }
        // 4 unleserliche Zeichen in einem Teil, 1 Fehler im anderen
        var q = b
        for p in [0, 9, 30, 55] { q[p] = "?" }
        #expect(try f.store.checkRecoveryShares([String(q), grouped(a1)])
                == [.corrected(formatted: s[2], changedPositions: [0, 9, 30, 55]),
                    .corrected(formatted: s[0], changedPositions: [17])])
    }

    @Test("checkRecoveryShares: fremde Teile, gleicher Teil zweimal, Unsinn, Bitfäule im Kopf")
    func fehlerfaelle() throws {
        let (f, _, kit) = try KernStufen.make(.maximal)
        let (g, _, otherKit) = try KernStufen.make(.maximal)
        let s = try #require(kit?.shares.map(\.formatted))
        let t = try #require(otherKit?.shares.map(\.formatted))
        let e = #expect(throws: SiegelError.self) { try f.store.checkRecoveryShares([t[0], t[1]]) }
        if case .wrongRecoveryCode(let codeKit, let vaultKit) = e {
            #expect(vaultKit == f.vault.kitID)
            #expect(codeKit != vaultKit)
        } else {
            Issue.record("erwartet wrongRecoveryCode")
        }
        // gemischt: ein eigener, ein fremder Teil → nie ein Treffer
        let mixed = #expect(throws: SiegelError.self) { try f.store.checkRecoveryShares([s[0], t[1]]) }
        if case .wrongRecoveryCode = mixed {} else { Issue.record("erwartet wrongRecoveryCode") }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try f.store.checkRecoveryShares([s[1], s[1]]) }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try f.store.checkRecoveryShares([s[1]]) }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try f.store.checkRecoveryShares([s[0], "ABC"]) }
        var junk = chars(s[0])
        for i in [1, 2, 3, 20, 40] { junk[i] = other(junk[i], shift: 5) }
        #expect(throws: SiegelError.recoveryCodeChecksum) { try f.store.checkRecoveryShares([String(junk), s[1]]) }
        // recover verlangt exakte Teile
        #expect(throws: SiegelError.recoveryCodeChecksum) {
            try f.store.recover(shares: [String(junk), s[1]], newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        #expect(throws: SiegelError.wrongRecoveryCode(codeKit: try codeKit(t, for: f), vaultKit: f.vault.kitID)) {
            try f.store.recover(shares: [t[0], t[2]], newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        // Bitfäule im Kopf (pkX): richtige Teile → corruptFile statt erfundener Kit-Kennung (Befund #22)
        var bytes = try f.fileBytes()
        let hl = KT.headerLength(bytes)
        bytes[hl - 10] ^= 0x01
        try f.writeFile(bytes)
        #expect(throws: SiegelError.corruptFile("file.checksum")) { try f.store.checkRecoveryShares([s[0], s[1]]) }
        _ = g
    }

    private func codeKit(_ shares: [String], for f: KernVault) throws -> String {
        let r = try VaultStore.combineShares([shares[0], shares[2]])
        return try RecoveryKEM.derivePublicKeys(r: r, vaultID: VaultHeader.bytes(of: f.vault.vaultID)).kitID
    }

    @Test("recover(shares:) mit jedem Paar; Teile bleiben gültig; Bestätigung eines bestehenden Kits")
    func wiederherstellen() throws {
        let (f, _, kit) = try KernStufen.make(.festung)
        try f.vault.upsert(kernEntry("Bank"))
        let s = try #require(kit?.shares.map(\.formatted))
        f.vault.lock()
        for (i, j) in [(0, 1), (1, 2), (2, 0)] {
            let pw = [KT.pw2, KT.pw3, KT.pw4][i]
            let v = try f.store.recover(shares: [s[i], s[j]], newMasterPassword: pw, kdf: KT.kdf)
            #expect(v.entries.map(\.title) == ["Bank"])
            #expect(v.level == .standard)
            #expect(v.kitID == kit?.code.kitID)
            #expect(try f.store.checkRecoveryShares([s[i], s[j]]) == [.exact, .exact])
            v.lock()
            #expect(KT.unlocked(try f.store.unlock(masterPassword: pw)) != nil)
        }
        // bestehendes Kit mit zwei ganzen Teilen bestätigen (nach Wiederherstellen einer alten Sicherung)
        let v = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw4)))
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try v.confirmExistingRecovery(shares: [s[0]]) }
        try v.confirmExistingRecovery(shares: [s[1], s[0]])
        #expect(v.recoveryConfirmed)
    }

    @Test("Notfallweg bei beschädigter Datei: Teile gegen die Sicherungen")
    func sicherungen() throws {
        let (f, k, kit) = try KernStufen.make(.maximal)
        try f.vault.upsert(kernEntry("A"))
        try f.vault.upsert(kernEntry("B"))
        let s = try #require(kit?.shares.map(\.formatted))
        f.vault.lock()
        var b = try f.fileBytes()
        b[b.count / 2] ^= 1
        try f.writeFile(b)
        #expect(throws: SiegelError.corruptFile("file.checksum")) {
            try f.store.recover(shares: [s[0], s[1]], newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        #expect(try f.store.checkRecoverySharesAgainstBackups([s[0], s[1]]) == [.exact, .exact])
        let (v, used) = try f.store.recoverFromNewestReadableBackup(shares: [s[1], s[2]], newMasterPassword: KT.pw2,
                                                                    kdf: KT.kdf)
        #expect(used.vaultID == f.vault.vaultID)
        #expect(v.entries.map(\.title) == ["A"])
        #expect(v.level == .standard)
        #expect(v.recoveryConfirmed)
        _ = k
    }
}
