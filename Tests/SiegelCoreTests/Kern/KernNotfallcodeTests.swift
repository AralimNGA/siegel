import Foundation
import Testing
@testable import SiegelCore

@Suite("Notfallcode")
struct KernNotfallcodeTests {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// Code ohne Bindestriche als Zeichenfeld.
    private func chars(_ code: String) -> [Character] { Array(code.replacingOccurrences(of: "-", with: "")) }

    private func grouped(_ c: [Character]) -> String {
        stride(from: 0, to: c.count, by: 5).map { String(c[$0..<min(c.count, $0 + 5)]) }.joined(separator: "-")
    }

    /// Anderes Zeichen als `c` (deterministisch).
    private func other(_ c: Character, shift: Int = 7) -> Character {
        let i = Self.alphabet.firstIndex(of: c) ?? 0
        return Self.alphabet[(i + shift) % 32]
    }

    @Test("Rundlauf: Code aus create öffnet über recover; DEK und Salz werden erneuert (Befund #23)")
    func rundlauf() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("Bank"))
        let oldFile = try f.parsedFile()
        let oldDEK = try f.vault.dekForTesting()   // Kopie, übersteht lock()
        f.vault.lock()
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
        let v = try f.store.recover(code: f.code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        #expect(v.entries.map(\.title) == ["Bank"])
        // §1.1/§1.2: neues KDF-Salz, neuer DEK; der alte DEK liest den neuen Inhalt nicht
        let newFile = try f.parsedFile()
        #expect(newFile.header.salt != oldFile.header.salt)
        #expect(try !v.dekForTesting().constantTimeEquals(oldDEK))
        #expect(throws: SiegelError.corruptFile("payload.auth")) { try VaultCrypto.decryptPayload(newFile, dek: oldDEK) }
        // Der neue DEK ist neu in den Notfall-Slot gekapselt (Code liefert genau ihn)
        let viaCode = try VaultCrypto.openWithRecovery(newFile, r: try RecoveryCodeCodec.decode(f.code))
        #expect(try viaCode.dek.constantTimeEquals(v.dekForTesting()))
        #expect(v.recoveryConfirmed)    // Code wurde vollständig eingegeben
        #expect(v.kitID == f.pending.code.kitID)
        v.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw2)) != nil)
        #expect(throws: SiegelError.wrongPassword) { try f.store.unlock(masterPassword: KT.pw1) }
        // Code bleibt gültig (Kit unverändert)
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
        #expect(f.localBackups().contains { $0.reason == "notfall" })
    }

    @Test("Eingabe: Gross/Klein, Leerraum, Bindestriche, O/I/L")
    func eingabeVarianten() throws {
        let f = try KernVault.make()
        let r = try RecoveryCodeCodec.decode(f.code)
        let plain = f.code.replacingOccurrences(of: "-", with: "")
        let variants = [
            f.code.lowercased(),
            plain,
            plain.map { String($0) }.joined(separator: " "),
            f.code.replacingOccurrences(of: "-", with: "\n"),
            "  " + f.code.replacingOccurrences(of: "-", with: "\u{00A0}") + "\t",
            f.code.replacingOccurrences(of: "0", with: "O").replacingOccurrences(of: "1", with: "I"),
            f.code.replacingOccurrences(of: "0", with: "o").replacingOccurrences(of: "1", with: "l"),
            f.code.replacingOccurrences(of: "1", with: "L"),
            "--" + f.code + "--",
        ]
        for v in variants {
            let back = try RecoveryCodeCodec.decode(v)
            #expect(back.constantTimeEquals(r))
            #expect(try f.store.checkRecoveryCode(v) == .exact)
        }
    }

    @Test("Format: falsche Länge, ungültige Zeichen, U, zu viele ?")
    func format() throws {
        let f = try KernVault.make()
        let c = chars(f.code)
        let bad = [
            String(c.dropLast()),
            String(c) + "0",
            "",
            String(c.dropLast()) + "U",
            String(c.dropLast()) + "*",
            String(c.dropLast()) + "Ä",
            "?????" + String(c.dropFirst(5)),
        ]
        for b in bad {
            #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try RecoveryCodeCodec.decode(b) }
            #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try f.store.checkRecoveryCode(b) }
        }
        // ? ist beim exakten Dekodieren (recover) nicht erlaubt
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) {
            try RecoveryCodeCodec.decode("?" + String(c.dropFirst()))
        }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) {
            try f.store.recover(code: "?" + String(c.dropFirst()), newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
    }

    @Test("Füllbits ≠ 0 → invalidRecoveryCodeFormat")
    func fuellbits() throws {
        let f = try KernVault.make()
        var c = chars(f.code)
        let last = Self.alphabet.firstIndex(of: c[54]) ?? 0
        #expect(last % 8 == 0)
        c[54] = Self.alphabet[last + 1]
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try RecoveryCodeCodec.decode(String(c)) }
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) {
            try f.store.recover(code: String(c), newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        // KernTestvektor: letztes Zeichen 8 → 9 setzt ein Füllbit
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) {
            try RecoveryCodeCodec.decode(String(KernTestvektor.code.dropLast()) + "9")
        }
        // Befund #42: Die Oberfläche unterscheidet „volle Länge, aber Füllbits/zu viele Fehler“ von „falsche Länge“.
        // Der Fehlercode bleibt invalidRecoveryCodeFormat (§1.5); der Helfer sagt, dass die Länge stimmt.
        // Ein Fehler im letzten Zeichen wird korrigiert; drei Fehler (eins davon im letzten Zeichen) nicht.
        #expect(try f.store.checkRecoveryCode(String(c)) == .corrected(formatted: f.code, changedPositions: [54]))
        var three = c
        three[5] = other(three[5])
        three[20] = other(three[20])
        #expect(throws: SiegelError.invalidRecoveryCodeFormat) { try f.store.checkRecoveryCode(String(three)) }
        #expect(VaultStore.recoveryCodeInputIsComplete(String(three)))
        #expect(VaultStore.recoveryCodeInputIsComplete("????" + String(c.dropFirst(4))))
        #expect(!VaultStore.recoveryCodeInputIsComplete(String(c.dropLast())))
        #expect(!VaultStore.recoveryCodeInputIsComplete(String(c.dropLast()) + "U"))
        #expect(!VaultStore.recoveryCodeInputIsComplete("?????" + String(c.dropFirst(5))))
    }

    @Test("Prüfsumme falsch → recoveryCodeChecksum")
    func pruefsumme() throws {
        var c = chars(KernTestvektor.code)
        c[10] = other(c[10])
        #expect(throws: SiegelError.recoveryCodeChecksum) { try RecoveryCodeCodec.decode(String(c)) }
        let f = try KernVault.make()
        var d = chars(f.code)
        d[20] = other(d[20])
        d[21] = other(d[21])
        #expect(throws: SiegelError.recoveryCodeChecksum) {
            try f.store.recover(code: String(d), newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
    }

    @Test("Fremder Tresor → wrongRecoveryCode mit beiden Kit-Kennungen")
    func fremderTresor() throws {
        let a = try KernVault.make()
        let b = try KernVault.make()
        // codeKit wird mit der vaultID DIESES Tresors abgeleitet (HKDF-Salz) – bei einem fremden Tresor ist es
        // also nicht die Kennung auf dessen Blatt, aber immer verschieden von der des Tresors.
        let r = try RecoveryCodeCodec.decode(b.code)
        let codeKit = try RecoveryKEM.derivePublicKeys(r: r, vaultID: a.vault.vaultID.kernBytes).kitID
        let expected = SiegelError.wrongRecoveryCode(codeKit: codeKit, vaultKit: a.pending.code.kitID)
        #expect(throws: expected) { try a.store.recover(code: b.code, newMasterPassword: KT.pw2, kdf: KT.kdf) }
        #expect(throws: expected) { try a.store.checkRecoveryCode(b.code) }
        #expect(codeKit != a.pending.code.kitID)
        #expect(a.pending.code.kitID != b.pending.code.kitID)
        #expect(try a.parsedFile().generation == 1)
    }

    @Test("Korrektur: 1 ersetztes Zeichen (jede Gruppe, auch das letzte Zeichen)")
    func korrekturEins() throws {
        let f = try KernVault.make()
        let original = chars(f.code)
        for pos in [0, 4, 5, 27, 53, 54] {
            var c = original
            c[pos] = other(c[pos], shift: 3)
            let result = try f.store.checkRecoveryCode(grouped(c))
            #expect(result == .corrected(formatted: f.code, changedPositions: [pos]))
        }
    }

    @Test("Korrektur: 2 ersetzte Zeichen")
    func korrekturZwei() throws {
        let f = try KernVault.make()
        var c = chars(f.code)
        c[3] = other(c[3])
        c[41] = other(c[41], shift: 11)
        #expect(try f.store.checkRecoveryCode(String(c)) == .corrected(formatted: f.code, changedPositions: [3, 41]))
    }

    @Test("Korrektur: vertauschte Nachbarn")
    func korrekturVertauscht() throws {
        let f = try KernVault.make()
        let original = chars(f.code)
        guard let pos = (0..<54).first(where: { original[$0] != original[$0 + 1] }) else { return }
        var c = original
        c.swapAt(pos, pos + 1)
        #expect(try f.store.checkRecoveryCode(grouped(c)) == .corrected(formatted: f.code, changedPositions: [pos, pos + 1]))
    }

    @Test("Korrektur: 4 unleserliche Zeichen (?)")
    func korrekturFragezeichen() throws {
        let f = try KernVault.make()
        var c = chars(f.code)
        let positions = [2, 17, 33, 54]
        for p in positions { c[p] = "?" }
        #expect(try f.store.checkRecoveryCode(grouped(c)) == .corrected(formatted: f.code, changedPositions: positions))
        // Ein ? und kleingeschrieben
        var d = Array(f.code.lowercased().replacingOccurrences(of: "-", with: ""))
        d[30] = "?"
        #expect(try f.store.checkRecoveryCode(String(d)) == .corrected(formatted: f.code, changedPositions: [30]))
    }

    @Test("Zufälliger Code → kein Treffer")
    func zufaellig() throws {
        let f = try KernVault.make()
        // gültige Prüfsumme, aber anderes R
        let r = try SecureBytes.random(count: 32)
        let code = try RecoveryCodeCodec.format(r: r)
        let pk = try RecoveryKEM.derivePublicKeys(r: r, vaultID: f.vault.vaultID.kernBytes)
        #expect(throws: SiegelError.wrongRecoveryCode(codeKit: pk.kitID, vaultKit: f.vault.kitID)) {
            try f.store.checkRecoveryCode(code)
        }
        // zufällige Zeichen (Füllbits 0) → keine Korrektur, Prüfsumme falsch
        var c = (0..<55).map { _ in Self.alphabet[Int(secureUniform(32))] }
        c[54] = "0"
        let start = Date()
        let e = #expect(throws: SiegelError.self) { try f.store.checkRecoveryCode(String(c)) }
        var isWrongKit = false
        if case .wrongRecoveryCode = e { isWrongKit = true }   // Prüfsumme zufällig gültig (2^-16)
        #expect(e == .recoveryCodeChecksum || isWrongKit)
        // Nur Schranke gegen grobe Rückschritte (z. B. versehentlich 3 Ersetzungen): Wanduhrzeit hängt von der
        // Last anderer Prozesse ab. Gemessen ohne Fremdlast: optimiert ≈ 0.12 s pro voller Suche
        // (1.43 Mio. Kandidaten, M5 Max), Testbau ≈ 0.3 s; Ziel laut SPEC ≤ ca. 1 s. Die Suche ist instrumentierter
        // Swift-Code: unter ASan/TSan gestreckt (TSan-Lauf vom 17.10.2026 abends unter Volllast: über 60 s).
        #expect(Date().timeIntervalSince(start) < 60 * Double(Sanitizer.zeitfaktor))
        // ? ohne passende Belegung (Rest falsch)
        var q = chars(f.code)
        q[0] = "?"
        q[10] = other(q[10])
        #expect(throws: SiegelError.recoveryCodeChecksum) { try f.store.checkRecoveryCode(String(q)) }
    }

    @Test("Lebenszyklus: create unbestätigt; falsche Gruppen → nichts geschrieben; richtige → bestätigt")
    func lebenszyklus() throws {
        let f = try KernVault.make()
        #expect(f.vault.recoveryConfirmed == false)
        let before = try f.fileBytes()
        let groups = f.pending.code.groups
        let wanted = f.pending.confirmationGroups.map { groups[$0] }
        let wrong = [wanted[0], other(Array(wanted[1])[0]).description + String(wanted[1].dropFirst())]
        #expect(throws: SiegelError.recoveryConfirmationMismatch) { try f.vault.commitRecovery(f.pending, confirmation: wrong) }
        #expect(throws: SiegelError.recoveryConfirmationMismatch) { try f.vault.commitRecovery(f.pending, confirmation: [wanted[0]]) }
        if wanted[0] != wanted[1] {
            #expect(throws: SiegelError.recoveryConfirmationMismatch) {
                try f.vault.commitRecovery(f.pending, confirmation: [wanted[1], wanted[0]])
            }
        }
        #expect(try f.fileBytes() == before)
        #expect(f.vault.recoveryConfirmed == false)
        // Kleinschreibung und Leerzeichen sind erlaubt
        try f.vault.commitRecovery(f.pending, confirmation: wanted.map { " " + $0.lowercased() })
        #expect(f.vault.recoveryConfirmed)
        #expect(f.vault.generation == 2)
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
        f.vault.lock()
        let again = try #require(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)))
        #expect(again.recoveryConfirmed)
    }

    @Test("prepareRecovery ohne commit lässt den alten Code gültig; commit macht ihn ungültig")
    func neuesKit() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("Bank"))
        let oldDEK = try f.vault.dekForTesting()
        let oldFile = try f.parsedFile()
        #expect(throws: SiegelError.wrongPassword) { try f.vault.prepareRecovery(masterPassword: KT.pw2) }
        let pending = try f.vault.prepareRecovery(masterPassword: KT.pw1)
        #expect(pending.code.kitID != f.pending.code.kitID)
        #expect(pending.code.formatted != f.code)
        // nichts geschrieben
        #expect(try f.parsedFile().generation == oldFile.generation)
        #expect(try f.store.checkRecoveryCode(f.code) == .exact)
        #expect(f.vault.kitID == f.pending.code.kitID)
        let newCodeError = #expect(throws: SiegelError.self) { try f.store.checkRecoveryCode(pending.code.formatted) }
        if case .wrongRecoveryCode = newCodeError {} else { Issue.record("erwartet wrongRecoveryCode") }
        // falsche Gruppen → nichts geschrieben
        #expect(throws: SiegelError.recoveryConfirmationMismatch) {
            try f.vault.commitRecovery(pending, confirmation: ["00000", "00000"])
        }
        #expect(try f.parsedFile().generation == oldFile.generation)
        // richtig bestätigen
        let groups = pending.confirmationGroups.map { pending.code.groups[$0] }
        try f.vault.commitRecovery(pending, confirmation: groups)
        #expect(f.vault.kitID == pending.code.kitID)
        #expect(f.vault.recoveryConfirmed)
        #expect(try f.store.checkRecoveryCode(pending.code.formatted) == .exact)
        #expect(throws: SiegelError.wrongRecoveryCode(codeKit: f.pending.code.kitID, vaultKit: pending.code.kitID)) {
            try f.store.recover(code: f.code, newMasterPassword: KT.pw2, kdf: KT.kdf)
        }
        // DEK rotiert; DEK aus dem alten recSlot entschlüsselt den neuen Inhalt nicht
        let newFile = try f.parsedFile()
        #expect(try !f.vault.dekForTesting().constantTimeEquals(oldDEK))
        let oldR = try RecoveryCodeCodec.decode(f.code)
        let oldOpened = try VaultCrypto.openWithRecovery(oldFile, r: oldR)
        #expect(oldOpened.dek.constantTimeEquals(oldDEK))
        #expect(throws: SiegelError.corruptFile("payload.auth")) { try VaultCrypto.decryptPayload(newFile, dek: oldOpened.dek) }
        #expect(newFile.header.salt != oldFile.header.salt)
        // Passwort bleibt, neuer Code öffnet
        f.vault.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw1)) != nil)
        let rec = try f.store.recover(code: pending.code.formatted, newMasterPassword: KT.pw2, kdf: KT.kdf)
        #expect(rec.entries.map(\.title) == ["Bank"])
        // angeheftete Sicherung „vor-neues-kit“
        #expect(f.localBackups().contains { $0.reason == "neues-kit" })
        // erneutes commit desselben (jetzt aktuellen) Kits ist nur eine Bestätigung: kein neuer DEK, Kit bleibt
        let dekBefore = try rec.dekForTesting()
        try rec.commitRecovery(pending, confirmation: groups)
        #expect(try rec.dekForTesting().constantTimeEquals(dekBefore))
        #expect(rec.kitID == pending.code.kitID)
        #expect(try f.store.checkRecoveryCode(pending.code.formatted) == .exact)
    }

    @Test("Passwortwechsel zwischen prepare und commit macht das vorbereitete Kit ungültig")
    func veraltetesKit() throws {
        let f = try KernVault.make()
        let pending = try f.vault.prepareRecovery(masterPassword: KT.pw1)
        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw2)
        let groups = pending.confirmationGroups.map { pending.code.groups[$0] }
        #expect(throws: SiegelError.crypto("recovery.pendingStale")) {
            try f.vault.commitRecovery(pending, confirmation: groups)
        }
        // Passwort wurde nicht zurückgesetzt
        f.vault.lock()
        #expect(KT.unlocked(try f.store.unlock(masterPassword: KT.pw2)) != nil)
    }
}

extension UUID {
    var kernBytes: [UInt8] { VaultHeader.bytes(of: self) }
}
