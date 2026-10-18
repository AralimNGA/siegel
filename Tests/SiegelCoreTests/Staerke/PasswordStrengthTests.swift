import Clibsodium
import Foundation
import Testing
@testable import SiegelCore

/// Schätzung nach SPEC §1.6: Beispiele, Muster, Listen, Grenzen, Laufzeit.
@Suite struct StaerkeSchaetzungTests {

    // MARK: - Beispiele aus SPEC §1.6

    static let unter60: [(String, [String])] = [
        ("Passwort1234!", []), ("Passwort2026!", []), ("Sommer2026!!!", []), ("Qwertz123456!", []),
        ("aaaaaaaaaaaaa", []), ("Aaaaaaaaaaaa1!", []), ("Aralim2008!!!", ["aralim"]), ("YB-Meister-2026", []),
    ]

    @Test(arguments: unter60.map { $0.0 })
    func specBeispielUnter60(_ password: String) {
        let inputs = Self.unter60.first { $0.0 == password }?.1 ?? []
        let (bits, level) = PasswordStrength.estimate(password, userInputs: inputs)
        #expect(bits < 60)
        #expect(level.rawValue <= PasswordStrength.Level.fair.rawValue)
        #expect(MasterPasswordPolicy.check(password, userInputs: inputs).ok == false)
    }

    @Test func aralimNurMitBenutzereingabeSchwach() {
        let ohne = PasswordStrength.estimate("Aralim2008!!!").bits
        let mit = PasswordStrength.estimate("Aralim2008!!!", userInputs: ["aralim"]).bits
        #expect(mit < ohne)
        #expect(mit < 30)
    }

    @Test func generiertePassphraseMindestens60() {
        for _ in 0..<300 {
            let phrase = PassphraseGenerator.generate()
            let bits = PasswordStrength.estimate(phrase).bits
            #expect(bits >= 60)
            #expect(MasterPasswordPolicy.check(phrase, userInputs: ["siegel"]).ok)
        }
    }

    @Test func zwanzigZufallszeichenAus94() {
        _ = Sodium.ready
        let pool = (33...126).map { Character(Unicode.Scalar(UInt8($0))) }
        #expect(pool.count == 94)
        #expect(PasswordStrength.estimate("kV7#pQ2$mZ9!xR4@tL8&").bits >= 60)
        // Zufällig: zxcvbn findet selten ein Wort im Zufall (z. B. "lISA" → 59.8 Bit, etwa 1 von 20 000).
        let count = 2000
        var atLeast60 = 0
        var minimum = Double.infinity
        for _ in 0..<count {
            let password = String((0..<20).map { _ in pool[Int(randombytes_uniform(94))] })
            let bits = PasswordStrength.estimate(password).bits
            if bits >= 60 { atLeast60 += 1 }
            minimum = min(minimum, bits)
        }
        #expect(Double(atLeast60) / Double(count) >= 0.995)
        #expect(minimum >= 50)
    }

    // MARK: - Muster

    private func matcher(_ inputs: [String] = []) -> ZxcvbnMatcher {
        ZxcvbnMatcher(dictionary: .shared, userInputs: inputs, referenceYear: 2026, graphs: KeyboardGraphs.all)
    }

    private func covers(_ password: String, _ pattern: ZxcvbnMatch.Pattern, inputs: [String] = []) -> Bool {
        let chars = Array(password)
        return matcher(inputs).omnimatch(chars).contains {
            $0.pattern == pattern && $0.i == 0 && $0.j == chars.count - 1
        }
    }

    @Test func tastaturQwertzUndQwerty() {
        #expect(covers("qwertzuiop", .spatial))
        #expect(covers("yxcvbnm", .spatial))            // untere Reihe QWERTZ-CH
        #expect(covers("asdfghjklöä", .spatial))
        #expect(covers("+\"*ç%&/()=", .spatial))        // Ziffernreihe CH mit Umschalt
        #expect(covers("zxcvbnm", .spatial))            // QWERTY
        #expect(covers("1qay2wsx", .spatial) || covers("1qay2wsx", .dictionary))
        #expect(covers("7412369", .spatial))            // Ziffernblock
        #expect(PasswordStrength.estimate("ztrewq").bits < 20)
    }

    @Test func tastaturGraphenSindKorrekt() {
        for graph in KeyboardGraphs.all {
            #expect(graph.misalignedTokens.isEmpty)
            #expect(graph.averageDegree > 2)
        }
        let byName = Dictionary(grouping: KeyboardGraphs.all, by: \.name)
        let qwertz = byName["qwertz_ch"]?.first
        let neighborsOfZ = Set((qwertz?.neighbors["z"] ?? []).compactMap { $0 }.flatMap { $0 })
        #expect(neighborsOfZ.isSuperset(of: ["t", "u", "g", "h", "6", "7"]))
        let neighborsOfY = Set((qwertz?.neighbors["y"] ?? []).compactMap { $0 }.flatMap { $0 })
        #expect(neighborsOfY.isSuperset(of: ["<", "a", "s", "x"]))
        #expect(qwertz?.shifted.contains("ç") == true)
        let qwerty = byName["qwerty"]?.first
        let neighborsOfQ = Set((qwerty?.neighbors["q"] ?? []).compactMap { $0 }.flatMap { $0 })
        #expect(neighborsOfQ == ["1", "!", "2", "@", "w", "W", "a", "A"])
        let keypad = byName["keypad"]?.first
        #expect((keypad?.neighbors["5"] ?? []).compactMap { $0 }.count == 8)
    }

    @Test func wiederholungenFolgenJahreDaten() {
        #expect(covers("aaaaaaaa", .repeated))
        #expect(covers("abcabcabc", .repeated))
        #expect(covers("abcdefgh", .sequence))
        #expect(covers("98765", .sequence))
        #expect(covers("acegi", .sequence))
        #expect(covers("1999", .year))
        #expect(covers("2099", .year))
        #expect(!covers("1899", .year))
        #expect(covers("24.12.1990", .date))
        #expect(covers("241290", .date))
        #expect(covers("1990-12-24", .date))
        #expect(covers("1.1.91", .date))
        #expect(PasswordStrength.estimate("24.12.1990").bits < 20)
    }

    @Test func woerterbuchUmgekehrtUndL33t() {
        #expect(covers("passwort", .dictionary))
        #expect(covers("trowssap", .dictionary))        // umgekehrt
        #expect(covers("P@ssw0rt", .dictionary))        // l33t
        #expect(covers("s0mm3r", .dictionary))
        #expect(covers("|1eb3", .dictionary))           // | → l, 3 → e
        #expect(PasswordStrength.estimate("P@ssw0rt").bits < 15)
        #expect(PasswordStrength.estimate("TROWSSAP").bits < 15)
    }

    @Test func grossschreibungKostetWenig() {
        let klein = PasswordStrength.estimate("sommer").bits
        let gross = PasswordStrength.estimate("Sommer").bits
        let alle = PasswordStrength.estimate("SOMMER").bits
        let gemischt = PasswordStrength.estimate("sOmMeR").bits
        #expect(gross - klein <= 1.01)
        #expect(alle - klein <= 1.01)
        #expect(gemischt > gross)
    }

    @Test func benutzereingabenWerdenErkannt() {
        #expect(covers("zwurbelmann", .dictionary, inputs: ["Zwurbelmann"]))
        #expect(!covers("zwurbelmann", .dictionary))
        let mit = PasswordStrength.estimate("Zwurbelmann1999", userInputs: ["zwurbelmann"]).bits
        let ohne = PasswordStrength.estimate("Zwurbelmann1999").bits
        #expect(mit < ohne)
    }

    @Test func passphrasenKetteAusEigenerListe() {
        // 4 Wörter aus der Liste ≈ 44 Bit Zufall: unter der Schwelle, auch wenn zxcvbn allein mehr schätzt
        #expect(covers("kerze-vulkan-flaute-pirat", .passphrase))
        let vier = PasswordStrength.estimate("kerze-vulkan-flaute-pirat").bits
        #expect(vier < 60)
        #expect(vier > 40)
        #expect(covers("Kerze Vulkan Flaute", .passphrase))
        #expect(covers("kerzevulkanflaute", .passphrase))
        // verschiedene Trennzeichen bilden auch eine Kette (je Lücke teurer, aber kein Zuschlag ×10000)
        #expect(covers("kerze-vulkan_flaute", .passphrase))
    }

    /// Befund #17: Ein anderes Trennstück (mehrere Zeichen, Ziffern, je Lücke verschieden) oder l33t in den
    /// Wörtern machte aus einer gekürzten 4-Wort-Passphrase (44 Bit Zufall) wieder 69–86 Bit.
    @Test(arguments: ["kerze, vulkan, flaute, pirat", "kerze - vulkan - flaute - pirat", "kerze--vulkan--flaute--pirat",
                      "kerze  vulkan  flaute  pirat", "kerze1vulkan2flaute3pirat", "k3rze-vulk4n-fl4ute-pir4t",
                      "Kerze. Vulkan. Flaute. Pirat", "kerze_vulkan-flaute.pirat"])
    func gekuerztePassphraseMitAnderemTrenner(_ password: String) {
        #expect(covers(password, .passphrase))
        #expect(PasswordStrength.estimate(password).bits < 60)
        #expect(MasterPasswordPolicy.check(password, userInputs: []).ok == false)
    }

    @Test func vierWoerterMitBeliebigemTrennerAbgelehnt() {
        for separator in [", ", " - ", "--", "  ", ". ", "; ", "~", "1"] {
            for _ in 0..<60 {
                let words = PassphraseGenerator.generate(words: 4).split(separator: "-")
                let password = words.joined(separator: separator)
                #expect(PasswordStrength.estimate(password).bits < 60, "Trenner \(separator.debugDescription)")
            }
        }
        // die vollständige 6-Wort-Passphrase bleibt mit jedem dieser Trenner stark
        for separator in [", ", " - ", "--", "  "] {
            for _ in 0..<40 {
                let phrase = PassphraseGenerator.generate().replacingOccurrences(of: "-", with: separator)
                #expect(PasswordStrength.estimate(phrase).bits >= 60, "Trenner \(separator.debugDescription)")
            }
        }
    }

    @Test func wortfolgenMitTrennzeichen() {
        #expect(covers("Mein Hund heisst Bello", .phrase))
        #expect(covers("Ich wohne seit 2015 in Biel", .phrase))
        #expect(PasswordStrength.estimate("Mein Hund heisst Bello").bits < 60)
        #expect(PasswordStrength.estimate("Ich wohne seit 2015 in Biel").bits < 60)
        #expect(covers("Mein Hund-heisst Bello", .phrase))                 // gemischte Trennzeichen (teurer)
        #expect(PasswordStrength.estimate("Mein  Hund  heisst  Bello").bits < 60)   // doppeltes Leerzeichen
        #expect(PasswordStrength.estimate("Mein, Hund, heisst, Bello").bits < 60)
        // generierte Passphrase mit Leerzeichen statt Bindestrich bleibt stark
        for _ in 0..<100 {
            let phrase = PassphraseGenerator.generate().replacingOccurrences(of: "-", with: " ")
            #expect(PasswordStrength.estimate(phrase).bits >= 60)
        }
        // lange Sätze werden nicht beliebig billig (Zahl der Wortfolgen mit kleinerem Rangprodukt)
        #expect(PasswordStrength.estimate("Der rote Fuchs springt über den faulen Hund").bits >= 60)
    }

    @Test func kleinereRangprodukte() {
        #expect(ZxcvbnMatcher.log2SmallerProducts(log2P: 40, count: 1) == 0)
        #expect(ZxcvbnMatcher.log2SmallerProducts(log2P: 1, count: 5) == 0)
        // k = 4, P = 2^36: (ln P)^3 / 3! ≈ 2.5·10^3 → ≈ 11.3 Bit
        let value = ZxcvbnMatcher.log2SmallerProducts(log2P: 36, count: 4)
        #expect(abs(value - log2(pow(36 * log(2.0), 3) / 6)) < 1e-9)
    }

    // MARK: - Listen

    @Test func listenSindGeladen() {
        let ranks = ZxcvbnDictionary.shared.ranks
        #expect(ranks.count > 250_000)
        #expect(ranks["123456"] == 1)
        #expect(ranks["passwort"] ?? .max <= 10)
        for word in ["grüezi", "gruezi", "zürich", "zuerich", "zurich", "müller", "mueller", "yb", "scb", "fcb",
                     "biel", "bern", "thun", "meister", "sommer", "schatz", "matterhorn", "eishockey",
                     "michael", "sabine", "smith", "the", "correct"] {
            #expect(ranks[word] != nil, "fehlt: \(word)")
        }
        #expect(ranks["zymotic"] == ZxcvbnDictionary.web2Rank)    // nur in web2
        #expect(ranks["kerze"] ?? .max <= ZxcvbnDictionary.passphraseRank)
        #expect(ZxcvbnDictionary.shared.maxWordLength >= 20)
    }

    @Test func vornKomprimierteListeWirdRichtigEntpackt() {
        var words: [String] = []
        ZxcvbnDictionary.forEachFrontCoded("0aardwolf\n5ic\n4\n3c") { word, _ in words.append(word) }
        #expect(words == ["aardwolf", "aardwic", "aard", "aarc"])
    }

    // MARK: - Normalisierung, Grenzen, Stufen

    @Test func normalisierungWieSpec() {
        #expect(PasswordStrength.estimate("ab\u{00A0}cd ef").bits == PasswordStrength.estimate("ab cd ef").bits)
        #expect(PasswordStrength.estimate("caf\u{0065}\u{0301}").bits == PasswordStrength.estimate("café").bits)
    }

    @Test func stufenGrenzen() {
        #expect(PasswordStrength.level(forBits: 0) == .veryWeak)
        #expect(PasswordStrength.level(forBits: 27.99) == .veryWeak)
        #expect(PasswordStrength.level(forBits: 28) == .weak)
        #expect(PasswordStrength.level(forBits: 35.99) == .weak)
        #expect(PasswordStrength.level(forBits: 36) == .fair)
        #expect(PasswordStrength.level(forBits: 59.99) == .fair)
        #expect(PasswordStrength.level(forBits: 60) == .strong)
        #expect(PasswordStrength.level(forBits: 79.99) == .strong)
        #expect(PasswordStrength.level(forBits: 80) == .veryStrong)
        #expect(PasswordStrength.estimate("").bits == 0)
        #expect(PasswordStrength.estimate("").level == .veryWeak)
    }

    @Test func brutForceZehnJeZeichen() {
        // nicht erkannte Zeichen: Kardinalität 10 je Zeichen (zxcvbn)
        let bits = PasswordStrength.estimate("龍虎鳳凰麒麟亀蛇").bits
        #expect(abs(bits - 8 * log2(10.0)) < 0.01)
    }

    @Test func sehrLangeEingabeBleibtSchnellUndEndlich() {
        var state: UInt32 = 12345                                       // feste Pseudo-Zufallsfolge
        let lang = String((0..<4800).map { _ -> Character in
            state = state &* 1_103_515_245 &+ 12345
            return Character(Unicode.Scalar(UInt8(33 + (state >> 16) % 94)))
        })
        let start = ContinuousClock.now
        let bits = PasswordStrength.estimate(lang).bits
        #expect(bits.isFinite)
        #expect(bits > 60)
        #expect(ContinuousClock.now - start < Sanitizer.grenze(.seconds(2)))   // unter ASan/TSan gestreckt
    }

    @Test func nebenlaeufigGleichesErgebnis() async {
        let password = "Sommer2026!!!Kerze"
        let expected = PasswordStrength.estimate(password).bits
        let results = await withTaskGroup(of: Double.self) { group in
            for _ in 0..<16 { group.addTask { PasswordStrength.estimate(password).bits } }
            var all: [Double] = []
            for await value in group { all.append(value) }
            return all
        }
        #expect(results.allSatisfy { $0 == expected })
    }

    // MARK: - Laufzeit (Oberfläche schätzt bei jedem Tastendruck)

    @Test func laufzeit64Zeichen() {
        _ = ZxcvbnDictionary.shared                                    // Listen einmalig laden
        let samples = [
            "P@ssw0rd!|1Sommer2026-qwertz-147258-abcabc-Kerze-Vulkan-24.12.19",
            String(repeating: "1!|l", count: 16),
            "kerze-vulkan-flaute-pirat-seide-hafen-kerze-vulkan-flaute-pirat-",
            "IchLiebeMeinenHundUndMeineKatzeSehrSehrFestUndImmerWiederGern!!!",
            "jK8#mW2$qP5!vB9@zR4&tY7*nL3%hG6^fD1(sA0)xC2+eU5=oI8?wQ4:rT7;yE1~",
        ]
        #if DEBUG
        let limit = Duration.milliseconds(150)                         // Debug-Build ohne Optimierung
        #else
        let limit = Duration.milliseconds(20)                          // SPEC-Vorgabe für den Release-Build
        #endif
        for sample in samples {
            #expect(sample.count == 64)
            var worst = Duration.zero
            for _ in 0..<5 {
                let start = ContinuousClock.now
                _ = PasswordStrength.estimate(sample)
                worst = max(worst, ContinuousClock.now - start)
            }
            #expect(worst < Sanitizer.grenze(limit))                     // unter ASan/TSan gestreckt
        }
    }
}
