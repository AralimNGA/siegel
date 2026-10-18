import Foundation

// Bewertung (zxcvbn scoring.coffee): Rateversuche je Muster und die kleinste Zerlegung des Passworts
// in eine Musterfolge per dynamischer Programmierung. Minimiert wird wie bei zxcvbn
//   g(Folge der Länge l) = l! · Π guesses(m) + 10000^(l−1),
// alles in log2 gerechnet.

enum ZxcvbnScoring {
    static let bruteforceCardinality: Double = 10
    static let minGuessesBeforeGrowingSequence: Double = 10_000
    static let minSubmatchGuessesSingleChar: Double = 10
    static let minSubmatchGuessesMultiChar: Double = 50
    static let minYearSpace = 20

    struct Result {
        let log2Guesses: Double
        let sequence: [ZxcvbnMatch]
    }

    // MARK: - Schätzung je Muster

    /// Untergrenze für Teilstücke kürzer als das ganze Passwort (estimate_guesses).
    static func adjustedLog2(_ match: ZxcvbnMatch, passwordLength: Int) -> Double {
        guard match.length < passwordLength else { return max(match.log2Guesses, 0) }
        let floor = match.length == 1 ? minSubmatchGuessesSingleChar : minSubmatchGuessesMultiChar
        return max(match.log2Guesses, log2(floor))
    }

    static func bruteforceLog2(length: Int) -> Double {
        let raw = Double(length) * log2(bruteforceCardinality)
        let floor = length == 1 ? minSubmatchGuessesSingleChar + 1 : minSubmatchGuessesMultiChar + 1
        return max(raw, log2(floor))
    }

    /// Varianten der Gross-/Kleinschreibung (zxcvbn uppercase_variations, auf Unicode erweitert).
    static func uppercaseVariations(_ token: ArraySlice<Character>) -> Double {
        var upper = 0
        var lower = 0
        for c in token {
            if c.isUppercase { upper += 1 } else if c.isLowercase { lower += 1 }
        }
        if upper == 0 { return 1 }                                 // alles klein
        if token.count > 1 && upper == 1 {
            if let first = token.first, first.isUppercase { return 2 }   // Wort
            if let last = token.last, last.isUppercase { return 2 }      // worT
        }
        if lower == 0 { return 2 }                                 // WORT
        var variations = 0.0
        for k in 1...min(upper, lower) { variations += ZxcvbnMath.nCk(upper + lower, k) }
        return max(variations, 1)
    }

    /// Varianten der l33t-Ersetzungen (zxcvbn l33t_variations). `lowerToken` ist kleingeschrieben.
    static func l33tVariations(_ lowerToken: ArraySlice<Character>, sub: [Character: Character]) -> Double {
        var variations = 1.0
        for (subbed, unsubbed) in sub {
            var s = 0
            var u = 0
            for c in lowerToken {
                if c == subbed { s += 1 } else if c == unsubbed { u += 1 }
            }
            if s == 0 { continue }                                 // Ersetzung kommt im Teilstück nicht vor
            if u == 0 {
                variations *= 2
            } else {
                var possibilities = 0.0
                for k in 1...min(u, s) { possibilities += ZxcvbnMath.nCk(u + s, k) }
                variations *= possibilities
            }
        }
        return variations
    }

    static func spatialLog2Guesses(length: Int, turns: Int, shifted: Int, graph: KeyboardGraph) -> Double {
        let s = graph.startingPositions
        let d = graph.averageDegree
        var guesses = 0.0
        if length >= 2 {
            for i in 2...length {
                let possibleTurns = min(turns, i - 1)
                if possibleTurns < 1 { continue }
                for j in 1...possibleTurns {
                    guesses += ZxcvbnMath.nCk(i - 1, j - 1) * s * pow(d, Double(j))
                }
            }
        }
        var lg = log2(max(guesses, 1))
        if shifted > 0 {
            let unshifted = length - shifted
            if unshifted == 0 {
                lg += 1
            } else {
                var variations = 0.0
                for k in 1...min(shifted, unshifted) { variations += ZxcvbnMath.nCk(shifted + unshifted, k) }
                lg += log2(max(variations, 1))
            }
        }
        return lg
    }

    static func sequenceLog2Guesses(_ token: ArraySlice<Character>, ascending: Bool) -> Double {
        guard let first = token.first else { return 0 }
        var base: Double
        if ["a", "A", "z", "Z", "0", "1", "9"].contains(first) {
            base = 4
        } else if first.zxcvbnDigit != nil {
            base = 10
        } else {
            base = 26                                           // auch für andere Alphabete (konservativ)
        }
        if !ascending { base *= 2 }
        return log2(base * Double(token.count))
    }

    // MARK: - Kleinste Zerlegung (most_guessable_match_sequence)

    private struct Entry {
        let l: Int
        let lg: Double      // log2 g
        let lpi: Double     // log2 Π guesses
        let match: ZxcvbnMatch
    }

    static func mostGuessable(_ password: [Character], matches: [ZxcvbnMatch],
                              excludeAdditive: Bool = false) -> Result {
        let n = password.count
        guard n > 0 else { return Result(log2Guesses: 0, sequence: []) }

        var byEnd = [[ZxcvbnMatch]](repeating: [], count: n)
        for m in matches where m.i >= 0 && m.j < n && m.i <= m.j { byEnd[m.j].append(m) }
        for k in 0..<n { byEnd[k].sort { $0.i < $1.i } }

        var optimal = [[Entry]](repeating: [], count: n)
        let log2Additive = log2(minGuessesBeforeGrowingSequence)

        func entry(_ k: Int, _ l: Int) -> Entry? {
            for e in optimal[k] where e.l == l { return e }
            return nil
        }

        func update(_ m: ZxcvbnMatch, _ l: Int) {
            let k = m.j
            var lpi = adjustedLog2(m, passwordLength: n)
            if l > 1 {
                guard let previous = entry(m.i - 1, l - 1) else { return }
                lpi += previous.lpi
            }
            var lg = ZxcvbnMath.log2Factorial(l) + lpi
            if !excludeAdditive {
                lg = ZxcvbnMath.logAdd(lg, Double(l - 1) * log2Additive)
            }
            for competing in optimal[k] where competing.l <= l {
                if competing.lg <= lg { return }
            }
            let new = Entry(l: l, lg: lg, lpi: lpi, match: m)
            if let index = optimal[k].firstIndex(where: { $0.l == l }) {
                optimal[k][index] = new
            } else {
                optimal[k].append(new)
            }
        }

        func bruteforce(_ i: Int, _ j: Int) -> ZxcvbnMatch {
            ZxcvbnMatch(pattern: .bruteforce, i: i, j: j, log2Guesses: bruteforceLog2(length: j - i + 1))
        }

        func bruteforceUpdate(_ k: Int) {
            update(bruteforce(0, k), 1)
            if k < 1 { return }
            for i in 1...k {
                let m = bruteforce(i, k)
                let previous = optimal[i - 1]
                for e in previous where e.match.pattern != .bruteforce {
                    update(m, e.l + 1)
                }
            }
        }

        for k in 0..<n {
            for m in byEnd[k] {
                if m.i > 0 {
                    let previous = optimal[m.i - 1]
                    for e in previous { update(m, e.l + 1) }
                } else {
                    update(m, 1)
                }
            }
            bruteforceUpdate(k)
        }

        // Zurückverfolgen
        var best: Entry?
        for e in optimal[n - 1] where best == nil || e.lg < (best?.lg ?? .infinity) { best = e }
        guard let final = best else { return Result(log2Guesses: bruteforceLog2(length: n), sequence: []) }
        var sequence: [ZxcvbnMatch] = []
        var k = n - 1
        var l = final.l
        while k >= 0, l >= 1, let e = entry(k, l) {
            sequence.insert(e.match, at: 0)
            k = e.match.i - 1
            l -= 1
        }
        return Result(log2Guesses: final.lg, sequence: sequence)
    }
}
