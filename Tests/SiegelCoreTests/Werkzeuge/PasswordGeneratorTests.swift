import Foundation
import Testing
@testable import SiegelCore

// Tests für PasswordGenerator (SPEC §7.5, §8, §10): Länge, Klassen, erstes Zeichen, ähnliche Zeichen,
// Gleichverteilung (Chi-Quadrat) und exakte Entropie (Abgleich per Vollaufzählung).

private func makeOptions(length: Int = 24, upper: Bool = true, lower: Bool = true, digits: Bool = true,
                         symbols: Bool = true, avoid: Bool = false) -> PasswordGenerator.Options {
    var o = PasswordGenerator.Options()
    o.length = length
    o.uppercase = upper
    o.lowercase = lower
    o.digits = digits
    o.symbols = symbols
    o.avoidAmbiguous = avoid
    return o
}

/// Alle 16 Klassen-Kombinationen (inkl. „keine“) × ähnliche Zeichen an/aus.
private let allCombinations: [PasswordGenerator.Options] = {
    var result: [PasswordGenerator.Options] = []
    for mask in 0..<16 {
        for avoid in [false, true] {
            result.append(makeOptions(length: 8, upper: mask & 1 != 0, lower: mask & 2 != 0,
                                      digits: mask & 4 != 0, symbols: mask & 8 != 0, avoid: avoid))
        }
    }
    return result
}()

/// Kritischer Chi-Quadrat-Wert (Wilson–Hilferty) für sehr kleines Fehlalarm-Risiko (z = 4.75, p ≈ 1e-6).
private func chiSquareCritical(df: Int) -> Double {
    let k = Double(df)
    let z = 4.75
    let a = 2.0 / (9.0 * k)
    return k * pow(1 - a + z * sqrt(a), 3)
}

private func chiSquare(_ counts: [Int]) -> Double {
    let total = Double(counts.reduce(0, +))
    let expected = total / Double(counts.count)
    return counts.reduce(0.0) { $0 + pow(Double($1) - expected, 2) / expected }
}

@Suite("Passwort-Generator")
struct PasswordGeneratorTests {

    @Test("Länge wird eingehalten", arguments: [8, 9, 12, 24, 32, 63, 64])
    func laenge(length: Int) {
        for _ in 0..<50 {
            #expect(PasswordGenerator.generate(makeOptions(length: length)).utf8.count == length)
        }
    }

    @Test("Länge wird auf 8…64 geklemmt")
    func laengeGeklemmt() {
        for (input, expected) in [(Int.min, 8), (-5, 8), (0, 8), (7, 8), (65, 64), (1000, 64), (Int.max, 64)] {
            #expect(PasswordGenerator.generate(makeOptions(length: input)).utf8.count == expected)
            #expect(PasswordGenerator.entropyBits(makeOptions(length: input))
                    == PasswordGenerator.entropyBits(makeOptions(length: expected)))
        }
    }

    @Test("Zeichenvorräte: Symbole = druckbares ASCII ohne Leerzeichen, ähnliche Zeichen dokumentiert")
    func vorraete() {
        let symbols = PasswordGenerator.symbolCharacters
        #expect(symbols.count == 32)
        #expect(Set(symbols).count == 32)
        #expect(symbols.allSatisfy { $0 >= 0x21 && $0 <= 0x7E })
        #expect(!symbols.contains(0x20))
        let all = Set(PasswordGenerator.uppercaseCharacters + PasswordGenerator.lowercaseCharacters
                      + PasswordGenerator.digitCharacters + symbols)
        #expect(all == Set(UInt8(0x21)...UInt8(0x7E)))   // genau die 94 druckbaren Zeichen

        #expect(Set(PasswordGenerator.ambiguousCharacters) == Set("0Oo1lI|!`'\",.;:".utf8))
        let reduced = PasswordGenerator.characterClasses(makeOptions(avoid: true)).map(\.count)
        #expect(reduced == [24, 24, 8, 23])
        // Formel-Präfixe sind keine „ähnlichen Zeichen“ (sonst wären sie nirgends erlaubt).
        #expect(Set(PasswordGenerator.forbiddenFirstCharacters).isDisjoint(with: PasswordGenerator.ambiguousCharacters))
    }

    @Test("Jede gewählte Klasse kommt vor, nur Zeichen aus dem Vorrat (alle Kombinationen, Länge 8)")
    func klassenGarantie() {
        for options in allCombinations {
            let classes = PasswordGenerator.characterClasses(options).map { Set($0) }
            let pool = classes.reduce(into: Set<UInt8>()) { $0.formUnion($1) }
            for _ in 0..<300 {
                let bytes = Array(PasswordGenerator.generate(options).utf8)
                #expect(bytes.count == 8)
                #expect(bytes.allSatisfy { pool.contains($0) })
                for cls in classes {
                    #expect(bytes.contains { cls.contains($0) })
                }
            }
        }
    }

    @Test("Keine Klasse gewählt → Kleinbuchstaben")
    func fallbackKlein() {
        let none = makeOptions(upper: false, lower: false, digits: false, symbols: false)
        #expect(PasswordGenerator.characterClasses(none) == [PasswordGenerator.lowercaseCharacters])
        for _ in 0..<100 {
            #expect(PasswordGenerator.generate(none).utf8.allSatisfy { $0 >= 0x61 && $0 <= 0x7A })
        }
        #expect(PasswordGenerator.entropyBits(none) == PasswordGenerator.entropyBits(makeOptions(upper: false, digits: false, symbols: false)))
    }

    @Test("Erstes Zeichen nie = + - @, an anderen Stellen schon")
    func erstesZeichen() {
        let forbidden = Set(PasswordGenerator.forbiddenFirstCharacters)
        let onlySymbols = makeOptions(length: 8, upper: false, lower: false, digits: false, symbols: true)
        var seenLater = Set<UInt8>()
        for _ in 0..<4000 {
            let bytes = Array(PasswordGenerator.generate(onlySymbols).utf8)
            #expect(!forbidden.contains(bytes[0]))
            seenLater.formUnion(bytes.dropFirst().filter { forbidden.contains($0) })
        }
        #expect(seenLater == forbidden)
        for options in allCombinations {
            for _ in 0..<100 {
                let first = PasswordGenerator.generate(options).utf8.first ?? 0
                #expect(!forbidden.contains(first))
            }
        }
    }

    @Test("Ähnliche Zeichen vermeiden")
    func aehnlicheZeichen() {
        let ambiguous = Set(PasswordGenerator.ambiguousCharacters)
        let options = makeOptions(length: 64, avoid: true)
        for _ in 0..<2000 {
            #expect(PasswordGenerator.generate(options).utf8.allSatisfy { !ambiguous.contains($0) })
        }
    }

    @Test("Gleichverteilung: winziger Fall exakt (Verwerfen statt Einfügen)")
    func gleichverteilungKleinsterFall() {
        // Klassen {a,b} und {=,1}, Länge 2: erlaubt sind genau a=, a1, b=, b1, 1a, 1b (6 gleich wahrscheinlich).
        let classes: [[UInt8]] = [Array("ab".utf8), Array("=1".utf8)]
        let valid = ["a=", "a1", "b=", "b1", "1a", "1b"]
        var counts = [Int](repeating: 0, count: valid.count)
        for _ in 0..<60_000 {
            let s = PasswordGenerator.generate(classes: classes, length: 2)
            guard let index = valid.firstIndex(of: s) else {
                Issue.record("unerwartete Zeichenkette")
                return
            }
            counts[index] += 1
        }
        #expect(chiSquare(counts) < chiSquareCritical(df: valid.count - 1))
        #expect(abs(PasswordGenerator.exactEntropyBits(classes: classes, length: 2) - log2(6)) < 1e-12)
    }

    @Test("Gleichverteilung: Chi-Quadrat je Klasse, je Stelle und über alle 94 Zeichen")
    func gleichverteilungChiQuadrat() {
        let classes = PasswordGenerator.characterClasses(makeOptions())
        let classOf: [UInt8: Int] = {
            var map: [UInt8: Int] = [:]
            for (i, cls) in classes.enumerated() { for b in cls { map[b] = i } }
            return map
        }()

        // (a) Länge 24, Stellen 1…23: innerhalb jeder Klasse gleichverteilt.
        var later = [UInt8: Int]()
        var first = [UInt8: Int]()
        for _ in 0..<20_000 {
            let bytes = Array(PasswordGenerator.generate(makeOptions(length: 24)).utf8)
            first[bytes[0], default: 0] += 1
            for b in bytes.dropFirst() { later[b, default: 0] += 1 }
        }
        for cls in classes {
            let counts = cls.map { later[$0, default: 0] }
            #expect(chiSquare(counts) < chiSquareCritical(df: cls.count - 1))
            // Stelle 0: innerhalb der Klasse gleichverteilt über die erlaubten Zeichen.
            let allowed = cls.filter { !PasswordGenerator.forbiddenFirstCharacters.contains($0) }
            let firstCounts = allowed.map { first[$0, default: 0] }
            #expect(chiSquare(firstCounts) < chiSquareCritical(df: allowed.count - 1))
        }

        // (b) Länge 8: Die Klassen-Garantie sitzt an keiner festen Stelle (Stellen 1…7 austauschbar).
        var digitsAt = [Int](repeating: 0, count: 7)
        var symbolsAt = [Int](repeating: 0, count: 7)
        for _ in 0..<30_000 {
            let bytes = Array(PasswordGenerator.generate(makeOptions(length: 8)).utf8)
            for position in 1..<8 {
                if classOf[bytes[position]] == 2 { digitsAt[position - 1] += 1 }
                if classOf[bytes[position]] == 3 { symbolsAt[position - 1] += 1 }
            }
        }
        #expect(chiSquare(digitsAt) < chiSquareCritical(df: 6))
        #expect(chiSquare(symbolsAt) < chiSquareCritical(df: 6))

        // (c) Länge 64: Bedingung greift praktisch nie → über alle 94 Zeichen gleichverteilt.
        var all = [UInt8: Int]()
        for _ in 0..<4_000 {
            for b in PasswordGenerator.generate(makeOptions(length: 64)).utf8.dropFirst() { all[b, default: 0] += 1 }
        }
        let allCounts = (UInt8(0x21)...UInt8(0x7E)).map { all[$0, default: 0] }
        #expect(chiSquare(allCounts) < chiSquareCritical(df: 93))

        // (d) Nur eine Klasse: exakt gleichverteilt.
        var lower = [UInt8: Int]()
        for _ in 0..<5_000 {
            for b in PasswordGenerator.generate(makeOptions(length: 32, upper: false, digits: false, symbols: false)).utf8 {
                lower[b, default: 0] += 1
            }
        }
        #expect(chiSquare(PasswordGenerator.lowercaseCharacters.map { lower[$0, default: 0] }) < chiSquareCritical(df: 25))
    }

    @Test("Entropie exakt: Abgleich mit Vollaufzählung")
    func entropieBruteForce() {
        let forbidden = Set(PasswordGenerator.forbiddenFirstCharacters)
        func bruteForceBits(_ classes: [[UInt8]], _ length: Int) -> Double {
            let pool = classes.flatMap { $0 }
            let sets = classes.map { Set($0) }
            var count = 0
            var indices = [Int](repeating: 0, count: length)
            outer: while true {
                if !forbidden.contains(pool[indices[0]]) {
                    let chars = indices.map { pool[$0] }
                    if sets.allSatisfy({ set in chars.contains { set.contains($0) } }) { count += 1 }
                }
                var position = length - 1
                while position >= 0 {
                    indices[position] += 1
                    if indices[position] < pool.count { continue outer }
                    indices[position] = 0
                    position -= 1
                }
                break
            }
            return log2(Double(count))
        }

        let reduced = PasswordGenerator.characterClasses(makeOptions(avoid: true))
        let full = PasswordGenerator.characterClasses(makeOptions())
        let cases: [([[UInt8]], Int)] = [
            ([PasswordGenerator.digitCharacters, PasswordGenerator.symbolCharacters], 3),
            ([reduced[0], reduced[2], reduced[3]], 3),
            ([full[2], full[3]], 4),
            ([Array("AB".utf8), Array("a".utf8), Array("012".utf8), Array("=+!#".utf8)], 5),
            ([Array("AB".utf8), Array("a".utf8), Array("012".utf8), Array("=+!#".utf8)], 4),
            ([Array("-@".utf8), Array("x".utf8)], 3),
        ]
        for (classes, length) in cases {
            let exact = PasswordGenerator.exactEntropyBits(classes: classes, length: length)
            #expect(abs(exact - bruteForceBits(classes, length)) < 1e-9)
        }
    }

    @Test("Entropie plausibel")
    func entropiePlausibel() {
        // Eine Klasse ohne Formel-Zeichen: genau L·log2(n).
        let digits8 = makeOptions(length: 8, upper: false, lower: false, digits: true, symbols: false)
        #expect(abs(PasswordGenerator.entropyBits(digits8) - 8 * log2(10)) < 1e-9)
        let lower24 = makeOptions(length: 24, upper: false, digits: false, symbols: false)
        #expect(abs(PasswordGenerator.entropyBits(lower24) - 24 * log2(26)) < 1e-9)

        // Standard (24, alle Klassen): knapp unter log2(90) + 23·log2(94) ≈ 157.25; die Ziffern-Garantie
        // kostet ≈ 0.1 Bit (Annahme ≈ 0.93).
        let standard = PasswordGenerator.entropyBits(makeOptions())
        let upperBound = log2(90.0) + 23 * log2(94.0)
        #expect(standard < upperBound)
        #expect(standard > upperBound - 0.2)
        #expect(standard > 150 && standard < 158)

        // Ähnliche Zeichen vermeiden kostet Entropie; mehr Länge bringt mehr.
        #expect(PasswordGenerator.entropyBits(makeOptions(avoid: true)) < standard)
        var previous = 0.0
        for length in 8...64 {
            let bits = PasswordGenerator.entropyBits(makeOptions(length: length))
            #expect(bits > previous)
            #expect(bits <= Double(length) * log2(94))
            previous = bits
        }
        // 20 Zeichen aus 94 erreichen die Master-Passwort-Schwelle von 60 Bit deutlich.
        #expect(PasswordGenerator.entropyBits(makeOptions(length: 20)) > 120)
        #expect(PasswordGenerator.entropyBits(makeOptions(length: 8)) > 50)
    }

    @Test("Annahmewahrscheinlichkeit des Verwerfens > 0.3 für alle Optionen")
    func annahmewahrscheinlichkeit() {
        for options in allCombinations {
            let classes = PasswordGenerator.characterClasses(options)
            let pool = Double(classes.reduce(0) { $0 + $1.count })
            let firstPool = Double(classes.reduce(0) { sum, cls in
                sum + cls.filter { !PasswordGenerator.forbiddenFirstCharacters.contains($0) }.count
            })
            let bits = PasswordGenerator.entropyBits(options)
            let acceptance = pow(2, bits - log2(firstPool) - 7 * log2(pool))
            #expect(acceptance > 0.3)
            #expect(acceptance <= 1 + 1e-12)
            #expect(abs(acceptance - PasswordGenerator.acceptanceProbability(classes: classes, length: 8)) < 1e-9)
        }
    }

    @Test("Unmögliche interne Vorgaben enden sofort statt endlos zu verwerfen")
    func unmoeglich() {
        #expect(PasswordGenerator.generate(classes: [Array("=".utf8)], length: 1) == "")
        #expect(PasswordGenerator.generate(classes: [Array("ab".utf8), Array("01".utf8)], length: 1) == "")
        #expect(PasswordGenerator.generate(classes: [], length: 8) == "")
        #expect(PasswordGenerator.exactEntropyBits(classes: [Array("=".utf8)], length: 1) == 0)
        #expect(PasswordGenerator.generate(classes: [Array("=".utf8), Array("a".utf8)], length: 2) == "a=")
    }
}
