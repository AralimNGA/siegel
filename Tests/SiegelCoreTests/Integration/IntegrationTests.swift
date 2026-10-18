import Foundation
import Testing
@testable import SiegelCore

/// Fälle, die erst beim Zusammenbau von Kern und Oberfläche aufgefallen sind.
@Suite("Integration Kern ↔ Oberfläche")
struct IntegrationTests {
    /// Die Oberfläche wechselt das KDF-Profil über `changeMasterPassword(current: pw, new: pw, kdf:)`.
    /// Ein Eintrag mit dem Master-Passwort („Gleich wie Master-Passwort“) darf das nicht blockieren:
    /// Das unveränderte Passwort ist kein *neues* Passwort (§1.6 sperrt nur neue).
    @Test("Profilwechsel mit gleichem Passwort trotz Eintrag gleich wie Master-Passwort")
    func profilwechselTrotzWiederverwendung() throws {
        let f = try KernVault.make()
        let gleich = kernEntry("Gleich", password: KT.pw1)
        try f.vault.upsert(gleich)
        #expect(f.vault.masterPasswordReuse == [gleich.id])

        try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw1, kdf: KT.kdf2)
        #expect(f.vault.kdf == KT.kdf2)
        #expect(f.vault.masterPasswordReuse == [gleich.id])

        // Gleich nach RFC-8265-Abbildung zählt ebenfalls als unverändert.
        let g = try KernVault.make(password: "t=5:U.+F3mYW O6#O8@s~@~4_q:")
        try g.vault.upsert(kernEntry("NBSP", password: "t=5:U.+F3mYW O6#O8@s~@~4_q:"))
        try g.vault.changeMasterPassword(current: "t=5:U.+F3mYW O6#O8@s~@~4_q:",
                                         new: "t=5:U.+F3mYW\u{00A0}O6#O8@s~@~4_q:", kdf: KT.kdf2)
        #expect(g.vault.kdf == KT.kdf2)

        // Ein wirklich neues Passwort, das als Eintragspasswort vorkommt, bleibt gesperrt.
        try f.vault.upsert(kernEntry("Anders", password: KT.pw3))
        #expect(throws: SiegelError.masterPasswordReused) {
            try f.vault.changeMasterPassword(current: KT.pw1, new: KT.pw3)
        }
        // Falsches aktuelles Passwort bei gleichem „neuen“ → wrongPassword, nichts geschrieben.
        let vorher = try f.parsedFile().generation
        #expect(throws: SiegelError.wrongPassword) {
            try f.vault.changeMasterPassword(current: KT.pw2, new: KT.pw2, kdf: KT.kdf)
        }
        #expect(try f.parsedFile().generation == vorher)
    }

    /// Die Oberfläche vergleicht Passwort und Wiederholung über `VaultStore.passwordsMatch`.
    @Test("passwordsMatch nach RFC 8265")
    func passwortVergleich() {
        #expect(VaultStore.passwordsMatch("a\u{00A0}b", "a b"))
        #expect(VaultStore.passwordsMatch("e\u{0301}", "é"))
        #expect(!VaultStore.passwordsMatch("abc", "abc "))
        #expect(!VaultStore.passwordsMatch("Abc", "abc"))
    }

    /// Die Oberfläche bestätigt Gruppen gross und ohne Bindestriche; Kleinschreibung und O/I/L gehen auch.
    @Test("commitRecovery nimmt Gruppen so, wie die Oberfläche sie liefert")
    func gruppenAusDerOberflaeche() throws {
        let f = try KernVault.make()
        let gruppen = f.pending.code.groups
        let verlangt = f.pending.confirmationGroups.map { gruppen[$0] }
        let klein = verlangt.map { $0.lowercased() }
        try f.vault.commitRecovery(f.pending, confirmation: klein)
        #expect(f.vault.recoveryConfirmed)
    }
}
