import CryptoKit
import Foundation
import Testing
@testable import SiegelCore

/// v4.6 (SPEC §12, `windows/SPEC-WINDOWS.md` W4.1): Die Windows-Hello-Art des Eintrags-Gerätefaktors im Swift-Kern –
/// lesen, Konsistenz prüfen, unverändert weiterschreiben, als „anderes Gerät“ behandeln. Die Interop-Beweise mit den
/// Dateien des C#-Kerns stehen in `Interop/CSharpFixtureTests.swift`; hier die Regeln an manipulierten Inhalten.
@Suite("Windows-Hello-Art (v4.6)")
struct KernWindowsHelloTests {
    /// Inhalt der Stufe 4 mit Eintrags-Gerätefaktor und V der Windows-Hello-Art (vom C#-Kern, eingefroren).
    static func inhalt() throws -> VaultContent {
        let json = try String(contentsOf: CSharpFixtureTests.fixtures.appendingPathComponent("cs_inhalt_hello.json"),
                              encoding: .utf8)
        return try PayloadCodec.decode(try KernBerichtTests.padded(json)).content
    }

    static func rejected(_ c: VaultContent) -> Bool {
        do {
            try c.checkSealing { .corruptFile($0) }
            return false
        } catch {
            return KT.isCorrupt(error as? SiegelError)
        }
    }

    static func macPunkt() -> [UInt8] { Array(P256.KeyAgreement.PrivateKey().publicKey.x963Representation) }

    @Test func geraetefaktorZaehltInBeidenArten() throws {
        let c = try Self.inhalt()
        let hello = try #require(c.entryFactors.windowsHello)
        #expect(hello.version == 1 && c.entryFactors.secureEnclave == nil)
        #expect(c.entryFactors.enrolled == .all && c.entryFactors.deviceKeyID == hello.keyID)
        for s in c.sealed.values {
            #expect(s.blob.factors.mask.contains(.secureEnclave) && s.blob.factors.hello?.salt.count == 32)
        }
        #expect(!Self.rejected(c))
    }

    @Test func mischformenSindBeschaedigt() throws {
        let c = try Self.inhalt()
        let id = try #require(c.sealed.keys.first)
        let eph = Self.macPunkt()
        var beide = c
        beide.sealed[id]?.blob.factors.seEphemeral = eph
        #expect(Self.rejected(beide), "beide Arten in einem Siegel")
        var macSiegel = c
        macSiegel.sealed[id]?.blob.factors.seEphemeral = eph
        macSiegel.sealed[id]?.blob.factors.hello = nil
        #expect(Self.rejected(macSiegel), "Siegel der Mac-Art in einem Hello-Tresor")
        var macSchluessel = c
        macSchluessel.entryFactors.windowsHello = nil
        macSchluessel.entryFactors.secureEnclave = .init(keyID: UUID(), publicKey: eph)
        #expect(Self.rejected(macSchluessel), "Hello-Siegel ohne Hello-Schlüssel")
        var salz = c
        salz.sealed[id]?.blob.factors.hello?.salt = [UInt8](repeating: 1, count: 16)
        #expect(Self.rejected(salz), "Salz 16 Byte")
        var version = c
        version.sealed[id]?.blob.factors.hello?.version = 2
        #expect(Self.rejected(version), "unbekannte Version im Siegel")
        var zwei = c.entryFactors
        zwei.secureEnclave = .init(keyID: UUID(), publicKey: eph)
        #expect(throws: SiegelError.corruptFile("payload.factors")) { try zwei.validate() }
        var helloV2 = c.entryFactors
        helloV2.windowsHello?.version = 2
        #expect(throws: SiegelError.corruptFile("payload.factors")) { try helloV2.validate() }
        // V der Hello-Art: kein öffentlicher Schlüssel, nie die Kennung des Gerätefaktors.
        var vMitSchluessel = c
        vMitSchluessel.destruction?.vKey?.publicKey = eph
        #expect(Self.rejected(vMitSchluessel), "V der Hello-Art mit öffentlichem Schlüssel")
        var vGleich = c
        vGleich.destruction?.vKey?.keyID = try #require(c.entryFactors.windowsHello?.keyID)
        #expect(Self.rejected(vGleich), "V = Eintrags-Gerätefaktor")
        let did = try #require(c.destructible.keys.first)
        var vernichtbarMac = c
        vernichtbarMac.destructible[did]?.factors.hello = nil
        vernichtbarMac.destructible[did]?.factors.seEphemeral = eph
        #expect(Self.rejected(vernichtbarMac), "vernichtbares Siegel der Mac-Art bei V der Hello-Art")
    }

    @Test func inhaltVonV45BleibtBytegleich() throws {
        // Vom Swift-Kern v4.5 geschrieben (vor der Hello-Art): v4.6 liest und schreibt ihn bytegleich, ohne neue Schlüssel.
        let json = try String(contentsOf: CSharpFixtureTests.fixtures.appendingPathComponent("swift_inhalt_stufe_b.json"),
                              encoding: .utf8)
        let (c, _) = try PayloadCodec.decode(try KernBerichtTests.padded(json))
        #expect(c.entryFactors.windowsHello == nil && c.destruction?.vKey?.isWindowsHello == false)
        let (again, _) = try PayloadCodec.encode(c)
        #expect(PayloadCodec.jsonStringForTesting(again) == json)
        #expect(!json.contains("windowsHello") && !json.contains("\"hello\""))
    }

    @Test func versiegelnUndVernichtbarVersiegelnSindAufDemMacNichtMoeglich() throws {
        var c = try Self.inhalt()
        let i = try #require(c.entries.firstIndex { $0.title == "Mail" })
        // Offen machen und neu versiegeln wollen (wie upsert/setProtection): Windows Hello fehlt hier.
        c.sealed[c.entries[i].id] = nil
        c.entries[i].secretsSealed = false
        c.entries[i].password = "neu"
        let vaultID = [UInt8](repeating: 0x10, count: 16)
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try c.seal(at: i, vaultID: vaultID, kit: try RecoveryKEM.derivePublicKeys(
                ikm: try SecureBytes.random(count: 32), vaultID: vaultID, seedInfo: EntrySealing.groupSeedInfo,
                x25519Info: EntrySealing.groupX25519Info), now: Date())
        }
        let j = try #require(c.entries.firstIndex { $0.title == "Wallet «Kalt»" })
        c.sealed[c.entries[j].id] = nil
        c.entries[j].secretsSealed = false
        #expect(throws: SiegelError.factorUnavailable(.secureEnclave)) {
            try c.sealDestructible(at: j, vaultID: vaultID, now: Date())
        }
    }

    @Test func macSchluesselErsetztHelloNurOhneSiegelDaran() throws {
        let c = try Self.inhalt()
        var neu = c.entryFactors
        neu.secureEnclave = .init(keyID: UUID(), publicKey: Self.macPunkt())
        neu.windowsHello = nil
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try UnlockedVault.checkReplacement(old: c.entryFactors, new: neu, content: c)
        }
        var offen = c
        offen.sealed = [:]
        offen.destructible = [:]
        for k in offen.entries.indices { offen.entries[k].secretsSealed = false }
        try UnlockedVault.checkReplacement(old: c.entryFactors, new: neu, content: offen)

        // Über den Tresor: Einträge hängen am Windows-Hello-Schlüssel → nicht ersetzen, nichts schreiben.
        let (dir, store) = try CSharpFixtureTests.store("cs_v2_hello.siegel")
        let vault = try #require(KT.unlocked(try store.unlock(masterPassword: CSharpFixtureTests.helloPassword,
                                                              factors: try CSharpFixtureTests.helloFactors())))
        let generation = vault.generation
        let mac = EntryKeyEnrollment(keyID: UUID(), publicKey: Data(Self.macPunkt()))
        #expect(throws: SiegelError.notAllowedAtLevel) {
            try vault.enrollFactors(NewFactorMaterial(entryKey: mac), masterPassword: CSharpFixtureTests.helloPassword,
                                    currentFactors: try CSharpFixtureTests.helloFactors())
        }
        #expect(vault.generation == generation && vault.entryDeviceIsWindowsHello)
        vault.lock()
        _ = dir
    }
}
