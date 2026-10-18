import Foundation
import Testing
@testable import SiegelCore

/// Master-Passwort-Regel nach SPEC §1.6/§8 und Normalisierung nach §1.1.
@Suite struct StaerkeRegelTests {

    @Test func grenzwerte() {
        #expect(MasterPasswordPolicy.minimumBits == 60)
        #expect(MasterPasswordPolicy.minimumLength == 12)
        #expect(MasterPasswordPolicy.maximumUTF8Bytes == 1024)
    }

    @Test func passphraseIstOk() {
        let phrase = PassphraseGenerator.generate()
        let result = MasterPasswordPolicy.check(phrase)
        #expect(result.ok)
        #expect(result.bits >= 60)
    }

    @Test func zuKurzIstNieOk() {
        // 11 Zeichen: auch völlig zufällig höchstens 11·log2(10) ≈ 36.5 Bit, und die Länge allein verbietet es
        let result = MasterPasswordPolicy.check("kV7#pQ2$mZ9")
        #expect(!result.ok)
        #expect(result.bits < 60)
    }

    @Test func hoechstens1024Bytes() {
        let prefix = "kV7#pQ2$mZ9!xR4@tL8&"                            // 20 Zufallszeichen
        let exact = prefix + String(repeating: "a", count: 1024 - prefix.utf8.count)
        #expect(exact.utf8.count == 1024)
        #expect(MasterPasswordPolicy.check(exact).ok)
        let tooLong = exact + "a"
        let result = MasterPasswordPolicy.check(tooLong)
        #expect(!result.ok)
        #expect(result.bits >= 60)                                     // stark, aber zu lang
        // Umlaute zählen doppelt (UTF-8)
        let umlaut = prefix + String(repeating: "ä", count: 503)       // 20 + 1006 = 1026 Byte
        #expect(umlaut.utf8.count > 1024)
        #expect(!MasterPasswordPolicy.check(umlaut).ok)
    }

    @Test func normalisierungZsUndNFC() {
        #expect(MasterPasswordPolicy.normalized("a\u{00A0}b") == "a b")
        #expect(MasterPasswordPolicy.normalized("e\u{0301}") == "\u{00E9}")
        #expect(MasterPasswordPolicy.normalized("a\u{2003}b\u{202F}c\u{3000}d") == "a b c d")
        // keine Zs-Zeichen: unverändert (Tabulator ist Cc, Nullbreite ist Cf)
        #expect(MasterPasswordPolicy.normalized("a\tb\u{200B}c") == "a\tb\u{200B}c")
        // nichts trimmen
        #expect(MasterPasswordPolicy.normalized("  wort  ") == "  wort  ")
        #expect(MasterPasswordPolicy.normalized("\u{00A0}x\u{00A0}") == " x ")
    }

    @Test func pruefungNachNormalisierung() {
        let mitNBSP = "Kerze\u{00A0}Vulkan\u{00A0}Flaute\u{00A0}Pirat\u{00A0}Seide\u{00A0}Hafen"
        let mitLeer = "Kerze Vulkan Flaute Pirat Seide Hafen"
        #expect(MasterPasswordPolicy.check(mitNBSP).bits == MasterPasswordPolicy.check(mitLeer).bits)
        #expect(MasterPasswordPolicy.check(mitNBSP).ok == MasterPasswordPolicy.check(mitLeer).ok)
        // 12 Zeichen nach NFC: "é" aus zwei Skalaren zählt als eines
        let zerlegt = String(repeating: "e\u{0301}", count: 11)
        #expect(MasterPasswordPolicy.normalized(zerlegt).count == 11)
        #expect(!MasterPasswordPolicy.check(zerlegt).ok)
    }

    /// v4.7 (Befund krypto-2): nur Zeichen aus Unicode 15.0. Foundation setzt Unicode-16-Paare teils nicht zusammen
    /// (gemessen auf macOS 26: U+16D67 U+16D67 bleibt, U+1611E U+1611E → U+16121), ein späteres System könnte es
    /// anders tun; der C#-Kern rechnet mit einer Tabelle. Nichtzeichen und private Zeichen sind alt und erlaubt.
    @Test func nurZeichenAusUnicode15() {
        let stark = "u,F?CfDuMlYWuJASPVQ*6GUG@O"
        #expect(MasterPasswordPolicy.check(stark).ok)
        #expect(MasterPasswordPolicy.unicodeVersion == (15, 0))
        for neu in ["\u{16D67}\u{16D67}", "\u{105D2}\u{0307}", "\u{1611E}", "\u{2EBF0}", "\u{1FAE9}", "\u{E0080}",
                    "\u{0378}", "\u{10FFFD}\u{0378}"] {
            let r = MasterPasswordPolicy.check(stark + neu)
            #expect(!r.ok, "nicht abgelehnt: \(neu.unicodeScalars.map { String($0.value, radix: 16) })")
            #expect(r.bits >= 60)
        }
        // U+FDD0 lässt Swift nicht als Literal zu, nur als Skalar
        for alt in ["\u{FFFE}", "\u{FFFF}", String(Unicode.Scalar(0xFDD0)!), "\u{E000}", "\u{10FFFD}", "\u{31350}", "e\u{0301}",
                    "\u{AC00}", "\u{1F600}", "\u{1FAE8}"] {
            #expect(MasterPasswordPolicy.check(stark + alt).ok, "abgelehnt: \(alt.unicodeScalars.map { String($0.value, radix: 16) })")
        }
        #expect(MasterPasswordPolicy.usesStableCharacters(""))
    }

    @Test func benutzereingabenAusKontonamen() {
        let inputs = MasterPasswordPolicy.userInputs(userName: "jmueller", fullName: "Jürg Müller-Zbinden")
        #expect(inputs.first == "siegel")
        for expected in ["jmueller", "jürg", "juerg", "jurg", "müller", "mueller", "muller", "zbinden",
                         "jürgmüllerzbinden", "jürg müller-zbinden"] {
            #expect(inputs.contains(expected), "fehlt: \(expected)")
        }
        #expect(Set(inputs).count == inputs.count)
        let ohne = MasterPasswordPolicy.check("JuergMueller1971!", userInputs: ["siegel"]).bits
        let mit = MasterPasswordPolicy.check("JuergMueller1971!", userInputs: inputs).bits
        #expect(mit <= ohne)
        #expect(MasterPasswordPolicy.check("Siegel2026Siegel!", userInputs: ["siegel"]).bits < 60)
    }

    @Test func standardEingabenEnthaltenSiegelUndKonto() {
        let inputs = MasterPasswordPolicy.defaultUserInputs()
        #expect(inputs.contains("siegel"))
        #expect(inputs.contains(NSUserName().lowercased()))
    }
}
