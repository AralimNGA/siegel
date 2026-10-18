import Foundation
import Testing
@testable import SiegelCore

/// Passphrasen-Generator nach SPEC §1.6: Liste genau 2048, Regeln, Format, grobe Gleichverteilung.
@Suite struct StaerkePassphraseTests {

    @Test func listeGenau2048() {
        #expect(PassphraseGenerator.wordListCount == 2048)
        #expect(PassphraseGenerator.words.count == 2048)
        #expect(Set(PassphraseGenerator.words).count == 2048)
    }

    @Test func listeNurKleinbuchstabenVierBisAcht() {
        let allowed = Set("abcdefghijklmnopqrstuvwxyz".unicodeScalars)
        for word in PassphraseGenerator.words {
            #expect((4...8).contains(word.count), "Länge: \(word)")
            #expect(word.unicodeScalars.allSatisfy { allowed.contains($0) }, "Zeichen: \(word)")
        }
    }

    @Test func listeOhneGesperrteStaemme() {
        let blocked = ["arsch", "fick", "hure", "nazi", "sex", "porn", "nackt", "mord", "leiche", "bombe", "waffen",
                       "krieg", "drog", "teufel", "idiot", "dumm", "doof", "jude", "sarg", "kotz", "kack"]
        for word in PassphraseGenerator.words {
            #expect(!blocked.contains { word.contains($0) }, "gesperrt: \(word)")
        }
    }

    @Test func formatSechsWoerterMitBindestrich() {
        let list = Set(PassphraseGenerator.words)
        for _ in 0..<200 {
            let phrase = PassphraseGenerator.generate()
            let parts = phrase.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
            #expect(parts.count == 6)
            #expect(parts.allSatisfy { list.contains($0) })
        }
        #expect(PassphraseGenerator.generate(words: 0) == "")
        #expect(PassphraseGenerator.generate(words: -3) == "")
        #expect(PassphraseGenerator.generate(words: 1).contains("-") == false)
        #expect(PassphraseGenerator.generate(words: 10).split(separator: "-").count == 10)
    }

    @Test func entropie() {
        #expect(PassphraseGenerator.entropyBits(words: 6) == 66)
        #expect(PassphraseGenerator.entropyBits(words: 1) == 11)
        #expect(PassphraseGenerator.entropyBits(words: 0) == 0)
        #expect(PassphraseGenerator.entropyBits(words: -1) == 0)
    }

    @Test func zufallUnterschiedlich() {
        var seen = Set<String>()
        for _ in 0..<500 { seen.insert(PassphraseGenerator.generate()) }
        #expect(seen.count == 500)
    }

    @Test func grobGleichverteilt() {
        // Rohe Ziehung (ohne die seltene Neu-Ziehung in generate). 2048 · 50 Ziehungen: jede Zahl erwartet 50 (Poisson, σ ≈ 7). Chi-Quadrat mit 2047 Freiheitsgraden:
        // Erwartung 2047, σ ≈ 64; Grenze 2047 + 6σ. Einzelwerte ausserhalb 10…110 sind praktisch unmöglich.
        let words = PassphraseGenerator.words
        var index: [String: Int] = [:]
        for (i, word) in words.enumerated() { index[word] = i }
        var counts = [Int](repeating: 0, count: words.count)
        let draws = words.count * 50
        var done = 0
        while done < draws {
            for part in PassphraseGenerator.draw(8).split(separator: "-") {
                if let i = index[String(part)] { counts[i] += 1 }
                done += 1
            }
        }
        let expected = Double(done) / Double(words.count)
        let chi2 = counts.reduce(0.0) { $0 + pow(Double($1) - expected, 2) / expected }
        #expect(chi2 < 2047 + 6 * 64)
        #expect(counts.min() ?? 0 >= 10)
        #expect(counts.max() ?? 0 <= 110)
        // erste und letzte Hälfte der Liste gleich oft (prüft, dass randombytes_uniform den ganzen Bereich nutzt)
        let firstHalf = counts[0..<1024].reduce(0, +)
        let secondHalf = counts[1024...].reduce(0, +)
        #expect(abs(Double(firstHalf - secondHalf)) < 6 * sqrt(Double(done)))   // 6σ
    }

    @Test func vorschlagErfuelltRegelImmer() {
        // sechs sehr häufige Listenwörter lägen unter 60 Bit; generate zieht dann neu
        let ranks = ZxcvbnDictionary.shared.ranks
        let haeufigste = PassphraseGenerator.words.sorted { (ranks[$0] ?? .max) < (ranks[$1] ?? .max) }.prefix(6)
        #expect(PasswordStrength.estimate(haeufigste.joined(separator: "-")).bits < 60)
        for _ in 0..<200 {
            #expect(PasswordStrength.estimate(PassphraseGenerator.generate()).bits >= 60)
        }
    }
}
