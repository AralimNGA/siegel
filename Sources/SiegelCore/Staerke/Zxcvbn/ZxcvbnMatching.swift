import Foundation

// Muster-Erkennung (zxcvbn matching.coffee): Wörterbuch (auch umgekehrt und l33t), Tastaturfolgen,
// Wiederholungen, Folgen, Jahre, Daten, Benutzereingaben. Dazu Siegel-Erweiterungen, die Schätzungen nur senken
// können: Ketten aus der eigenen Passphrasen-Liste, Wortfolgen mit Trennzeichen und (ZxcvbnVorlagen.swift)
// Zähler-Vorlagen, Kalenderfolgen sowie Ort + Postleitzahl.
// Jede Erkennung liefert sofort ihre Schätzung (log2 Versuche).

struct ZxcvbnMatcher: Sendable {
    let dictionary: ZxcvbnDictionary
    /// Benutzereingaben (kleingeschrieben) → Rang (Position + 1), wie zxcvbn user_inputs.
    let userRanks: [String: Int]
    let userMaxLength: Int
    let referenceYear: Int
    let graphs: [KeyboardGraph]

    init(dictionary: ZxcvbnDictionary, userInputs: [String], referenceYear: Int, graphs: [KeyboardGraph]) {
        self.dictionary = dictionary
        var ranks: [String: Int] = [:]
        var maxLength = 0
        var rank = 0
        for input in userInputs {
            let key = String(Array(input).map { $0.zxcvbnLower })
            guard !key.isEmpty else { continue }
            rank += 1
            if ranks[key] == nil { ranks[key] = rank }
            maxLength = max(maxLength, key.utf8.count)
        }
        self.userRanks = ranks
        self.userMaxLength = maxLength
        self.referenceYear = referenceYear
        self.graphs = graphs
    }

    // MARK: - Alle Muster

    func omnimatch(_ password: [Character]) -> [ZxcvbnMatch] {
        guard !password.isEmpty else { return [] }
        let lower = password.map { $0.zxcvbnLower }
        var matches: [ZxcvbnMatch] = []
        dictionaryMatches(password, lower: lower, into: &matches)
        reverseDictionaryMatches(password, lower: lower, into: &matches)
        l33tMatches(password, lower: lower, into: &matches)
        spatialMatches(password, into: &matches)
        repeatMatches(password, into: &matches)
        sequenceMatches(password, into: &matches)
        yearMatches(password, into: &matches)
        dateMatches(password, into: &matches)
        passphraseMatches(password, lower: lower, into: &matches)
        phraseMatches(password, lower: lower, into: &matches)
        counterMatches(password, into: &matches)
        calendarMatches(password, lower: lower, into: &matches)
        placeCodeMatches(password, lower: lower, into: &matches)
        return matches
    }

    // MARK: - Wörterbuch

    /// Alle Teilstücke von `keys`, die in einer Liste stehen: (i, j, kleinster Rang).
    /// Mit `marked` nur Teilstücke, die mindestens eine markierte Stelle enthalten (l33t-Ersetzung).
    private func rankHits(_ keys: [Character], marked: [Bool]?) -> [(i: Int, j: Int, rank: Int)] {
        let n = keys.count
        let limit = max(dictionary.maxWordLength, userMaxLength)
        var hits: [(i: Int, j: Int, rank: Int)] = []
        var nextMarked = [Int](repeating: n, count: n + 1)
        if let marked {
            for k in stride(from: n - 1, through: 0, by: -1) {
                nextMarked[k] = marked[k] ? k : nextMarked[k + 1]
            }
        }
        let ranks = dictionary.ranks
        for i in 0..<n {
            let firstUseful = marked == nil ? i : nextMarked[i]
            if firstUseful >= n { break }
            let end = min(n, i + limit)
            if firstUseful >= end { continue }
            var word = ""
            for j in i..<end {
                word.append(keys[j])
                if j < firstUseful { continue }
                var best = ranks[word]
                if let user = userRanks[word], user < (best ?? Int.max) { best = user }
                if let best { hits.append((i, j, best)) }
            }
        }
        return hits
    }

    private func dictionaryMatches(_ password: [Character], lower: [Character], into matches: inout [ZxcvbnMatch]) {
        for hit in rankHits(lower, marked: nil) {
            let token = password[hit.i...hit.j]
            let lg = log2(Double(hit.rank)) + log2(ZxcvbnScoring.uppercaseVariations(token))
            matches.append(ZxcvbnMatch(pattern: .dictionary, i: hit.i, j: hit.j, log2Guesses: lg))
        }
    }

    private func reverseDictionaryMatches(_ password: [Character], lower: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        guard n > 1 else { return }
        for hit in rankHits(Array(lower.reversed()), marked: nil) {
            let i = n - 1 - hit.j
            let j = n - 1 - hit.i
            let token = password[i...j]
            // umgekehrt: doppelte Versuche
            let lg = log2(Double(hit.rank)) + log2(ZxcvbnScoring.uppercaseVariations(token)) + 1
            matches.append(ZxcvbnMatch(pattern: .dictionary, i: i, j: j, log2Guesses: lg))
        }
    }

    /// l33t-Tabelle nach SPEC §1.6: Zeichen → mögliche Buchstaben.
    static let l33tTable: [Character: [Character]] = [
        "@": ["a"], "4": ["a"], "3": ["e"],
        "1": ["i", "l"], "!": ["i", "l"], "|": ["i", "l"],
        "0": ["o"], "$": ["s"], "5": ["s"], "7": ["t"], "9": ["g"],
    ]

    private func l33tMatches(_ password: [Character], lower: [Character], into matches: inout [ZxcvbnMatch]) {
        var present: [Character] = []
        for c in password where ZxcvbnMatcher.l33tTable[c] != nil && !present.contains(c) {
            present.append(c)
        }
        guard !present.isEmpty else { return }
        // Alle vollständigen Zuordnungen (jedes vorkommende l33t-Zeichen → genau ein Buchstabe).
        var subs: [[Character: Character]] = [[:]]
        for c in present {
            let letters = ZxcvbnMatcher.l33tTable[c] ?? []
            var next: [[Character: Character]] = []
            for sub in subs {
                for letter in letters {
                    var extended = sub
                    extended[c] = letter
                    next.append(extended)
                }
            }
            subs = next
        }
        let n = password.count
        for sub in subs {
            var translated = lower
            var marked = [Bool](repeating: false, count: n)
            for k in 0..<n {
                if let letter = sub[password[k]] {
                    translated[k] = letter
                    marked[k] = true
                }
            }
            for hit in rankHits(translated, marked: marked) where hit.j > hit.i {
                let token = password[hit.i...hit.j]
                let lg = log2(Double(hit.rank))
                    + log2(ZxcvbnScoring.uppercaseVariations(token))
                    + log2(ZxcvbnScoring.l33tVariations(lower[hit.i...hit.j], sub: sub))
                matches.append(ZxcvbnMatch(pattern: .dictionary, i: hit.i, j: hit.j, log2Guesses: lg))
            }
        }
    }

    // MARK: - Passphrasen aus der eigenen Liste (Siegel-Erweiterung, nicht in zxcvbn)

    /// zxcvbn bewertet eine Kette einzelner Wörter mit dem Zuschlag 10000^(l−1) je Teil sehr hoch. Wer die
    /// gebündelte Passphrasen-Liste kennt, braucht für k Wörter aber nur 2048^k Versuche (mal Trennstücke,
    /// Schreibweise und l33t). Dieses Muster kann Schätzungen nur senken: Eine gekürzte Passphrase mit 4 Wörtern
    /// ergibt so ≈ 48 Bit statt ≈ 69 Bit, eine vollständige mit 6 Wörtern ≈ 70 Bit. Trennstücke dürfen 0–3
    /// Zeichen lang sein, die keine Buchstaben sind (auch Ziffern, auch je Lücke verschieden, siehe
    /// `separatorsLog2`), und Wörter dürfen l33t-Ersetzungen enthalten: Ein anderes Trennzeichen macht aus
    /// 44 Bit Zufall nicht 78 Bit.
    static let passphraseWords: Set<String> = Set(PassphraseGenerator.words)
    /// Mögliche Trennzeichen (Leerzeichen, - _ . , ; : / + * | ~ # ! ? oder keins), als Zahl der Varianten.
    static let passphraseSeparatorChoices = 16
    private static let maxPassphraseMatches = 4096
    /// Obergrenze der durchsuchten Ketten (Laufzeit bei konstruierten Eingaben).
    private static let maxPassphraseSteps = 50_000

    private struct PassphraseChain {
        let end: Int                    // exklusiv
        let tokens: [Range<Int>]
        let gaps: [Range<Int>]          // Trennstücke zwischen den Wörtern (Positionen im Passwort)
        let l33tLog2: Double            // Summe der l33t-Varianten der Wörter
    }

    private func passphraseMatches(_ password: [Character], lower: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        guard n >= 8 else { return }
        let words = ZxcvbnMatcher.passphraseWords
        // Gelesen in Kleinschreibung und – falls l33t-Zeichen vorkommen – in zwei Übersetzungen (1 ! | → i bzw. l)
        var variants: [[Character]] = [lower]
        if password.contains(where: { ZxcvbnMatcher.l33tTable[$0] != nil }) {
            for choice in 0..<2 {
                variants.append(lower.map { c in
                    guard let letters = ZxcvbnMatcher.l33tTable[c], !letters.isEmpty else { return c }
                    return letters[min(choice, letters.count - 1)]
                })
            }
        }
        // Wörter (4–8 Buchstaben) je Startposition mit ihren l33t-Varianten (log2)
        var wordsAt = [[(length: Int, l33t: Double)]](repeating: [], count: n)
        for p in 0..<n {
            for (index, chars) in variants.enumerated() {
                var key = ""
                for length in 1...8 {
                    guard p + length <= n else { break }
                    key.append(chars[p + length - 1])
                    guard length >= 4, words.contains(key) else { continue }
                    var l33t = 0.0
                    if index > 0 {
                        var sub: [Character: Character] = [:]
                        for q in p..<(p + length) where chars[q] != lower[q] { sub[lower[q]] = chars[q] }
                        if sub.isEmpty { continue }            // ohne Ersetzung: schon in Variante 0
                        l33t = log2(ZxcvbnScoring.l33tVariations(lower[p..<(p + length)], sub: sub))
                    }
                    if let k = wordsAt[p].firstIndex(where: { $0.length == length }) {
                        if l33t < wordsAt[p][k].l33t { wordsAt[p][k].l33t = l33t }
                    } else {
                        wordsAt[p].append((length, l33t))
                    }
                }
            }
        }
        let perWord = log2(Double(PassphraseGenerator.wordListCount))
        var emitted = 0
        var steps = 0
        for start in 0..<n where !wordsAt[start].isEmpty {
            var stack: [PassphraseChain] = wordsAt[start].map {
                PassphraseChain(end: start + $0.length, tokens: [start..<(start + $0.length)], gaps: [],
                                l33tLog2: $0.l33t)
            }
            while let chain = stack.popLast() {
                steps += 1
                if steps > ZxcvbnMatcher.maxPassphraseSteps { return }
                if chain.tokens.count >= 2 {
                    let lg = Double(chain.tokens.count) * perWord
                        + ZxcvbnMatcher.separatorsLog2(chain.gaps.map { password[$0] })
                        + passphraseCaseLog2(password, chain.tokens) + chain.l33tLog2
                    matches.append(ZxcvbnMatch(pattern: .passphrase, i: start, j: chain.end - 1, log2Guesses: lg))
                    emitted += 1
                    if emitted >= ZxcvbnMatcher.maxPassphraseMatches { return }
                }
                // nächstes Wort nach einem Trennstück aus 0–3 Zeichen, die keine Buchstaben sind
                var gapLength = 0
                while gapLength <= ZxcvbnMatcher.maxSeparatorLength {
                    let next = chain.end + gapLength
                    guard next < n else { break }
                    if gapLength > 0, password[next - 1].isLetter { break }
                    for word in wordsAt[next] {
                        stack.append(PassphraseChain(end: next + word.length,
                                                     tokens: chain.tokens + [next..<(next + word.length)],
                                                     gaps: chain.gaps + [chain.end..<next],
                                                     l33tLog2: chain.l33tLog2 + word.l33t))
                    }
                    gapLength += 1
                }
            }
        }
    }

    /// Schreibweise einer Wortkette: alles klein = 1; jedes Wort klein oder mit grossem Anfang (natürliche
    /// Schreibweise, auch deutsche Nomen) oder alles GROSS = 2; sonst Varianten je Wort wie zxcvbn.
    private func passphraseCaseLog2(_ password: [Character], _ tokens: [Range<Int>]) -> Double {
        var state = CaseState()
        for range in tokens { state.add(password[range]) }
        return state.log2Variations
    }

    /// Schreibweise einer wachsenden Wortkette, schrittweise (siehe `passphraseCaseLog2`).
    struct CaseState {
        var allLower = true
        var allNatural = true
        var allUpper = true
        var log2Product = 0.0

        mutating func add(_ token: ArraySlice<Character>) {
            var upper = 0
            var lower = 0
            for c in token {
                if c.isUppercase { upper += 1 } else if c.isLowercase { lower += 1 }
            }
            if upper > 0 { allLower = false }
            if lower > 0 { allUpper = false }
            let capitalized = upper == 1 && (token.first?.isUppercase ?? false)
            if upper > 0 && !capitalized { allNatural = false }
            log2Product += log2(ZxcvbnScoring.uppercaseVariations(token))
        }

        var log2Variations: Double {
            if allLower { return 0 }
            if allNatural || allUpper { return 1 }
            return log2Product
        }
    }

    // MARK: - Trennstücke (gemeinsam für Passphrasen-Ketten und Wortfolgen)

    /// Häufige Trennzeichen; zusammen mit „keins“ die 16 Varianten aus `passphraseSeparatorChoices`.
    static let commonSeparators: Set<Character> = [" ", "-", "_", ".", ",", ";", ":", "/", "+", "*", "|", "~",
                                                    "#", "!", "?"]
    /// Längstes Trennstück zwischen zwei Wörtern.
    static let maxSeparatorLength = 3

    /// log2 der Varianten eines einzelnen Zeichens in einem Trennstück.
    static func separatorCharLog2(_ c: Character) -> Double {
        if commonSeparators.contains(c) { return log2(Double(commonSeparators.count)) }
        if c.zxcvbnDigit != nil { return ZxcvbnMath.log2Of10 }
        if c.isASCII { return log2(33) }                // übrige druckbare Satz- und Sonderzeichen
        return 7                                        // seltene Zeichen (≈ 128 Varianten)
    }

    /// Zeichen für Zeichen, mit Wahl der Länge (1–3).
    static func freeSeparatorLog2(_ gap: ArraySlice<Character>) -> Double {
        gap.reduce(0) { $0 + separatorCharLog2($1) } + (gap.count > 1 ? log2(Double(maxSeparatorLength)) : 0)
    }

    /// „--“, „  “, „, “, „ -“, „ - “: übliche Muster aus zwei bis drei häufigen Trennzeichen.
    static func isCommonSeparatorPattern(_ gap: ArraySlice<Character>) -> Bool {
        let a = Array(gap)
        guard a.count == 2 || a.count == 3, a.allSatisfy({ commonSeparators.contains($0) }) else { return false }
        if Set(a).count == 1 { return true }
        if a.count == 2 { return a[0] == " " || a[1] == " " }
        return a[0] == " " && a[2] == " "
    }

    /// log2 der Varianten für ein Trennstück, das überall gleich ist: ein häufiges Zeichen oder keins = 16
    /// (wie bisher); übliche Muster aus 2–3 Zeichen = 16 · 5; sonst Zeichen für Zeichen plus 1 Bit.
    static func constantSeparatorLog2(_ gap: ArraySlice<Character>) -> Double {
        let base = log2(Double(passphraseSeparatorChoices))
        if gap.isEmpty { return base }
        if gap.count == 1, let c = gap.first, commonSeparators.contains(c) { return base }
        if isCommonSeparatorPattern(gap) { return base + log2(5) }
        return freeSeparatorLog2(gap) + 1
    }

    /// log2 der Varianten aller Trennstücke einer Kette. Überall gleich: `constantSeparatorLog2`. Verschieden:
    /// 1 Bit für diese Wahl plus das Günstigere aus (a) jedes Stück für sich (1 Bit leer oder nicht, dazu seine
    /// Zeichen) und (b) ein Grund-Trennstück mit einzelnen Abweichungen (Lage der Abweichungen, je Abweichung
    /// wie ein eigenes Trennstück) – so kostet ein Komma in einem Satz nicht so viel wie lauter Zufall.
    static func separatorsLog2(_ gaps: [ArraySlice<Character>]) -> Double {
        var tracker = SeparatorTracker()
        for gap in gaps { tracker.add(gap) }
        return tracker.log2Variants
    }

    /// Schrittweise Berechnung von `separatorsLog2` für wachsende Ketten (O(verschiedene Trennstücke) je Schritt).
    struct SeparatorTracker {
        private var distinct: [(gap: ArraySlice<Character>, count: Int, log2: Double)] = []
        private var total = 0
        private var independent = 0.0
        /// Σ count · log2 über alle verschiedenen Trennstücke
        private var weighted = 0.0

        mutating func add(_ gap: ArraySlice<Character>) {
            total += 1
            independent += 1 + (gap.isEmpty ? 0 : ZxcvbnMatcher.freeSeparatorLog2(gap))
            if let k = distinct.firstIndex(where: { $0.gap.elementsEqual(gap) }) {
                distinct[k].count += 1
                weighted += distinct[k].log2
            } else {
                let cost = ZxcvbnMatcher.constantSeparatorLog2(gap)
                distinct.append((gap, 1, cost))
                weighted += cost
            }
        }

        var log2Variants: Double {
            guard let first = distinct.first else { return 0 }
            if distinct.count == 1 { return first.log2 }
            var best = independent
            for base in distinct {
                // Grund-Trennstück einmal, Lage der Abweichungen, jede Abweichung wie ein eigenes Trennstück
                let cost = base.log2 + ZxcvbnMath.log2Binomial(total, total - base.count)
                    + (weighted - Double(base.count) * base.log2)
                best = min(best, cost)
            }
            return 1 + best
        }
    }

    // MARK: - Wortfolgen mit Trennzeichen (Siegel-Erweiterung, nicht in zxcvbn)

    /// zxcvbn zerlegt "Mein Hund heisst Bello" in Wörter und Leerzeichen; jedes Teil kostet ×10000, so dass
    /// Sätze aus Alltagswörtern ≥ 60 Bit erreichen. Ein Angreifer mit Wortlisten probiert Wortfolgen aber nach
    /// dem Produkt der Ränge: Für k Wörter mit Rangprodukt P gibt es etwa N(P) = P · (ln P)^(k−1)/(k−1)!
    /// Folgen mit kleinerem Produkt (Anzahl k-Tupel natürlicher Zahlen mit Produkt ≤ P). Dazu kommen
    /// Schreibweise und Trennstücke (`separatorsLog2`: 0–3 Zeichen, gleich oder je Lücke verschieden). Läufe
    /// sind Buchstaben- bzw. Ziffernfolgen (an der Grenze Buchstabe/Ziffer mit leerem Trennstück); Ziffern
    /// zählen wie Jahr bzw. 10^Länge, unbekannte Wörter wie Brute-Force (10^Länge), damit kurze Wörter wie "da"
    /// die Kette nicht trennen. Das Muster kann Schätzungen nur senken. Generierte 6-Wort-Passphrasen bleiben
    /// deutlich über 60 Bit, weil N(P) für k = 6 rund 2^18 beiträgt (siehe Tests).
    private func phraseMatches(_ password: [Character], lower: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        var runs: [Range<Int>] = []
        var k = 0
        while k < n {
            let c = password[k]
            if c.isLetter {
                let start = k
                while k < n, password[k].isLetter { k += 1 }
                runs.append(start..<k)
            } else if c.isNumber {
                let start = k
                while k < n, password[k].isNumber, !password[k].isLetter { k += 1 }
                runs.append(start..<k)
            } else {
                k += 1
            }
        }
        guard runs.count >= 2 else { return }
        let logRanks: [Double] = runs.map { tokenLog2Rank(lower[$0]) }
        for a in 0..<runs.count {
            var log2P = logRanks[a]
            var separators = SeparatorTracker()
            var casing = CaseState()
            casing.add(password[runs[a]])
            var count = 1
            var b = a + 1
            while b < runs.count {
                let gap = runs[b - 1].upperBound..<runs[b].lowerBound
                guard gap.count <= ZxcvbnMatcher.maxSeparatorLength else { break }
                separators.add(password[gap])
                casing.add(password[runs[b]])
                log2P += logRanks[b]
                count += 1
                let lg = log2P + ZxcvbnMatcher.log2SmallerProducts(log2P: log2P, count: count)
                    + casing.log2Variations + separators.log2Variants
                matches.append(ZxcvbnMatch(pattern: .phrase, i: runs[a].lowerBound, j: runs[b].upperBound - 1,
                                           log2Guesses: lg))
                b += 1
            }
        }
    }

    /// log2 von max(1, (ln P)^(k−1)/(k−1)!): Wortfolgen mit kleinerem Rangprodukt.
    static func log2SmallerProducts(log2P: Double, count: Int) -> Double {
        guard count >= 2 else { return 0 }
        let lnP = log2P * log(2)
        guard lnP > 1 else { return 0 }
        let value = Double(count - 1) * log2(lnP) - ZxcvbnMath.log2Factorial(count - 1)
        return max(0, value)
    }

    /// log2 des Rangs eines Laufs (kleingeschrieben): Ziffern als Jahr (1900–2099) oder 10^Länge, Wörter
    /// mit ihrem Rang aus Listen bzw. Benutzereingaben, höchstens aber 10^Länge (Brute-Force).
    private func tokenLog2Rank(_ token: ArraySlice<Character>) -> Double {
        let bruteforce = Double(token.count) * ZxcvbnMath.log2Of10
        let digits = token.compactMap { $0.zxcvbnDigit }
        if digits.count == token.count {
            if digits.count == 4, (digits[0] == 1 && digits[1] == 9) || (digits[0] == 2 && digits[1] == 0) {
                let year = digits.reduce(0) { $0 * 10 + $1 }
                return log2(Double(max(abs(year - referenceYear), ZxcvbnScoring.minYearSpace)))
            }
            return bruteforce
        }
        let word = String(token)
        var best = dictionary.ranks[word]
        if let user = userRanks[word], user < (best ?? Int.max) { best = user }
        guard let best else { return bruteforce }
        return min(log2(Double(best)), bruteforce)
    }

    // MARK: - Tastaturfolgen

    private func spatialMatches(_ password: [Character], into matches: inout [ZxcvbnMatch]) {
        for graph in graphs {
            spatialMatches(password, graph: graph, into: &matches)
        }
    }

    private func spatialMatches(_ password: [Character], graph: KeyboardGraph, into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        var i = 0
        while i < n - 1 {
            var j = i + 1
            var lastDirection = -1
            var turns = 0
            var shiftedCount = (!graph.isKeypad && graph.shifted.contains(password[i])) ? 1 : 0
            while true {
                let previous = password[j - 1]
                var found = false
                if j < n, let adjacents = graph.neighbors[previous] {
                    let current = password[j]
                    for (direction, adjacent) in adjacents.enumerated() {
                        guard let adjacent, let position = adjacent.firstIndex(of: current) else { continue }
                        found = true
                        if position == 1 { shiftedCount += 1 }
                        if lastDirection != direction {
                            turns += 1
                            lastDirection = direction
                        }
                        break
                    }
                }
                if found {
                    j += 1
                } else {
                    if j - i > 2 {
                        let lg = ZxcvbnScoring.spatialLog2Guesses(length: j - i, turns: turns,
                                                                  shifted: shiftedCount, graph: graph)
                        matches.append(ZxcvbnMatch(pattern: .spatial, i: i, j: j - 1, log2Guesses: lg))
                    }
                    i = j
                    break
                }
            }
        }
    }

    // MARK: - Wiederholungen

    private func repeatMatches(_ password: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        func equal(_ a: Int, _ b: Int, _ length: Int) -> Bool {
            var k = 0
            while k < length {
                if password[a + k] != password[b + k] { return false }
                k += 1
            }
            return true
        }
        func repetitions(_ start: Int, _ length: Int) -> Int {
            var reps = 2
            while start + (reps + 1) * length <= n, equal(start, start + reps * length, length) { reps += 1 }
            return reps
        }
        var lastIndex = 0
        while lastIndex < n {
            // gierig (.+)\1+ und genügsam (.+?)\1+ ab der ersten Stelle, an der es eine Wiederholung gibt
            var found: (start: Int, greedyLength: Int, greedyReps: Int, lazyLength: Int, lazyReps: Int)?
            var start = lastIndex
            while start < n, found == nil {
                let maxLength = (n - start) / 2
                if maxLength >= 1 {
                    var greedy: (Int, Int)?
                    for length in stride(from: maxLength, through: 1, by: -1) where equal(start, start + length, length) {
                        greedy = (length, repetitions(start, length))
                        break
                    }
                    if let greedy {
                        var lazy = greedy
                        for length in 1...maxLength where equal(start, start + length, length) {
                            lazy = (length, repetitions(start, length))
                            break
                        }
                        found = (start, greedy.0, greedy.1, lazy.0, lazy.1)
                    }
                }
                if found == nil { start += 1 }
            }
            guard let match = found else { break }
            let total: Int
            let baseLength: Int
            if match.greedyLength * match.greedyReps > match.lazyLength * match.lazyReps {
                total = match.greedyLength * match.greedyReps
                // kürzeste Periode des gierigen Treffers (^(.+?)\1+$)
                var period = match.greedyLength
                for length in 1...(total / 2) where total % length == 0 {
                    var periodic = true
                    var k = length
                    while k < total {
                        if password[match.start + k] != password[match.start + k - length] { periodic = false; break }
                        k += 1
                    }
                    if periodic { period = length; break }
                }
                baseLength = period
            } else {
                total = match.lazyLength * match.lazyReps
                baseLength = match.lazyLength
            }
            let i = match.start
            let j = i + total - 1
            let base = Array(password[i..<(i + baseLength)])
            let baseResult = ZxcvbnScoring.mostGuessable(base, matches: omnimatch(base))
            let lg = baseResult.log2Guesses + log2(Double(total / baseLength))
            matches.append(ZxcvbnMatch(pattern: .repeated, i: i, j: j, log2Guesses: lg))
            lastIndex = j + 1
        }
    }

    // MARK: - Folgen (abc, 9876, aceg)

    static let maxSequenceDelta = 5

    private func sequenceMatches(_ password: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        guard n > 1 else { return }
        let noDelta = 1 << 40
        func delta(_ k: Int) -> Int {
            guard let a = password[k].zxcvbnScalar, let b = password[k - 1].zxcvbnScalar else { return noDelta }
            return a - b
        }
        func update(_ i: Int, _ j: Int, _ delta: Int) {
            let magnitude = abs(delta)
            guard j - i > 1 || magnitude == 1 else { return }
            guard magnitude > 0, magnitude <= ZxcvbnMatcher.maxSequenceDelta else { return }
            let token = password[i...j]
            let lg = ZxcvbnScoring.sequenceLog2Guesses(token, ascending: delta > 0)
            matches.append(ZxcvbnMatch(pattern: .sequence, i: i, j: j, log2Guesses: lg))
        }
        var i = 0
        var lastDelta = delta(1)
        for k in 1..<n {
            let d = delta(k)
            if d == lastDelta { continue }
            let j = k - 1
            update(i, j, lastDelta)
            i = j
            lastDelta = d
        }
        update(i, n - 1, lastDelta)
    }

    // MARK: - Jahre 1900–2099

    private func yearMatches(_ password: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        guard n >= 4 else { return }
        for i in 0...(n - 4) {
            guard let a = password[i].zxcvbnDigit, let b = password[i + 1].zxcvbnDigit,
                  let c = password[i + 2].zxcvbnDigit, let d = password[i + 3].zxcvbnDigit else { continue }
            guard (a == 1 && b == 9) || (a == 2 && b == 0) else { continue }
            let year = a * 1000 + b * 100 + c * 10 + d
            let space = max(abs(year - referenceYear), ZxcvbnScoring.minYearSpace)
            matches.append(ZxcvbnMatch(pattern: .year, i: i, j: i + 3, log2Guesses: log2(Double(space))))
        }
    }

    // MARK: - Daten (1.1.91, 01.01.1991, 010191, 19910101 …)

    static let dateMinYear = 1000
    static let dateMaxYear = 2099

    private static let dateSplits: [Int: [(Int, Int)]] = [
        4: [(1, 2), (2, 3)],
        5: [(1, 3), (2, 3)],
        6: [(1, 2), (2, 4), (4, 5)],
        7: [(1, 3), (2, 3), (4, 5), (4, 6)],
        8: [(2, 4), (4, 6)],
    ]

    private static let dateSeparators: Set<Character> = [" ", "/", "\\", "_", ".", "-"]

    private struct DMY {
        let year: Int
        let month: Int
        let day: Int
    }

    private func dateMatches(_ password: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        var found: [(i: Int, j: Int, year: Int, separator: Bool)] = []
        let digits = password.map { $0.zxcvbnDigit }

        func number(_ from: Int, _ to: Int) -> Int {          // [from, to)
            var value = 0
            for k in from..<to { value = value * 10 + (digits[k] ?? 0) }
            return value
        }

        // ohne Trennzeichen: 4 bis 8 Ziffern
        if n >= 4 {
            for i in 0...(n - 4) {
                for j in (i + 3)...(i + 7) {
                    if j >= n { break }
                    var allDigits = true
                    for k in i...j where digits[k] == nil { allDigits = false; break }
                    if !allDigits { break }
                    let length = j - i + 1
                    var best: DMY?
                    var bestDistance = Int.max
                    for (k, l) in ZxcvbnMatcher.dateSplits[length] ?? [] {
                        let ints = [number(i, i + k), number(i + k, i + l), number(i + l, j + 1)]
                        guard let dmy = ZxcvbnMatcher.mapIntsToDMY(ints) else { continue }
                        let distance = abs(dmy.year - referenceYear)
                        if best == nil || distance < bestDistance {
                            best = dmy
                            bestDistance = distance
                        }
                    }
                    if let best { found.append((i, j, best.year, false)) }
                }
            }
        }

        // mit Trennzeichen: 6 bis 10 Zeichen, d{1,4} s d{1,2} s d{1,4} mit gleichem Trennzeichen
        if n >= 6 {
            for i in 0...(n - 6) {
                for j in (i + 5)...(i + 9) {
                    if j >= n { break }
                    guard let parsed = parseSeparatedDate(password, digits: digits, i, j) else { continue }
                    guard let dmy = ZxcvbnMatcher.mapIntsToDMY(parsed) else { continue }
                    found.append((i, j, dmy.year, true))
                }
            }
        }

        // Treffer entfernen, die echt in einem anderen Datum enthalten sind
        for (index, candidate) in found.enumerated() {
            var isSubmatch = false
            for (other, outer) in found.enumerated() where other != index {
                if outer.i <= candidate.i && outer.j >= candidate.j { isSubmatch = true; break }
            }
            if isSubmatch { continue }
            var guesses = Double(max(abs(candidate.year - referenceYear), ZxcvbnScoring.minYearSpace)) * 365
            if candidate.separator { guesses *= 4 }
            matches.append(ZxcvbnMatch(pattern: .date, i: candidate.i, j: candidate.j, log2Guesses: log2(guesses)))
        }
    }

    private func parseSeparatedDate(_ password: [Character], digits: [Int?], _ i: Int, _ j: Int) -> [Int]? {
        // erster Block 1–4 Ziffern
        var k = i
        var first = 0
        while k <= j, let d = digits[k], k - i < 4 { first = first * 10 + d; k += 1 }
        let firstLength = k - i
        guard firstLength >= 1, k <= j else { return nil }
        let separator = password[k]
        guard ZxcvbnMatcher.dateSeparators.contains(separator) else { return nil }
        k += 1
        let secondStart = k
        var second = 0
        while k <= j, let d = digits[k], k - secondStart < 2 { second = second * 10 + d; k += 1 }
        guard k - secondStart >= 1, k <= j, password[k] == separator else { return nil }
        k += 1
        let thirdStart = k
        var third = 0
        while k <= j, let d = digits[k], k - thirdStart < 4 { third = third * 10 + d; k += 1 }
        guard k - thirdStart >= 1, k == j + 1 else { return nil }
        return [first, second, third]
    }

    private static func mapIntsToDMY(_ ints: [Int]) -> DMY? {
        guard ints.count == 3 else { return nil }
        if ints[1] > 31 || ints[1] <= 0 { return nil }
        var over12 = 0, over31 = 0, under1 = 0
        for value in ints {
            if (value > 99 && value < dateMinYear) || value > dateMaxYear { return nil }
            if value > 31 { over31 += 1 }
            if value > 12 { over12 += 1 }
            if value <= 0 { under1 += 1 }
        }
        if over31 >= 2 || over12 == 3 || under1 >= 2 { return nil }

        let splits: [(Int, [Int])] = [(ints[2], [ints[0], ints[1]]), (ints[0], [ints[1], ints[2]])]
        for (year, rest) in splits where year >= dateMinYear && year <= dateMaxYear {
            guard let dm = mapIntsToDM(rest) else { return nil }
            return DMY(year: year, month: dm.month, day: dm.day)
        }
        for (year, rest) in splits {
            guard let dm = mapIntsToDM(rest) else { continue }
            return DMY(year: twoToFourDigitYear(year), month: dm.month, day: dm.day)
        }
        return nil
    }

    private static func mapIntsToDM(_ ints: [Int]) -> (day: Int, month: Int)? {
        for (d, m) in [(ints[0], ints[1]), (ints[1], ints[0])] where (1...31).contains(d) && (1...12).contains(m) {
            return (d, m)
        }
        return nil
    }

    private static func twoToFourDigitYear(_ year: Int) -> Int {
        if year > 99 { return year }
        if year > 50 { return year + 1900 }
        return year + 2000
    }
}
