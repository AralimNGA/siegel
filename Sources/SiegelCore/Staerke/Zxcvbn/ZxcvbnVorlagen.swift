import Foundation

// Siegel-Erweiterungen der Muster-Erkennung (Befund #18, 17.10.2026): Zähler-Vorlagen („Hund1Hund2Hund3“),
// Kalenderfolgen („Mo-Di-Mi-Do“, „Jan.Feb.Mar“) und Ort + Postleitzahl („Thun3600“, „3600 Thun“). Wie die übrigen
// Erweiterungen können sie Schätzungen nur senken, denn die Zerlegung nimmt immer das Minimum. Ohne sie zerfielen
// solche Passwörter in viele Teilstücke, und der zxcvbn-Zuschlag 10000^(l−1) trieb sie über 60 Bit.

extension ZxcvbnMatcher {

    // MARK: - Zähler-Vorlage (Grundwort mit hochzählender Zahl)

    /// Erlaubte Schrittweiten (Betrag) einer Zähler-Vorlage; beide Richtungen.
    static let counterSteps: Set<Int> = [1, 2, 5, 10]
    private static let maxCounterMatches = 64

    private struct CounterToken {
        /// nil = Platzhalter für einen maximalen Ziffernlauf
        let char: Character?
        /// Zahlenwert des Laufs (nil bei mehr als 9 Ziffern)
        let value: Int?
        let width: Int
        let lower: Int
        let upper: Int
    }

    /// Jeder maximale Ziffernlauf wird zu einem Platzhalter; gesucht werden Wiederholungen einer Vorlage mit genau
    /// einem Platzhalter, deren Zahlen eine arithmetische Folge mit Schritt ±1, ±2, ±5 oder ±10 bilden (auch mit
    /// führenden Nullen, `01 02 03`). Eine abgebrochene letzte Wiederholung zählt mit.
    /// Kosten: Grundwort (Vorlage ohne Zahl, kleinste Zerlegung) + Startzahl (10^Breite) + Schrittweite (8) +
    /// Lage der Zahl in der Vorlage + Zahl der Wiederholungen.
    func counterMatches(_ password: [Character], into matches: inout [ZxcvbnMatch]) {
        var tokens: [CounterToken] = []
        var placeholders: [Int] = []
        var k = 0
        let n = password.count
        while k < n {
            if password[k].zxcvbnDigit != nil {
                let start = k
                var value = 0
                while k < n, let digit = password[k].zxcvbnDigit {
                    if k - start < 9 { value = value * 10 + digit }
                    k += 1
                }
                placeholders.append(tokens.count)
                tokens.append(CounterToken(char: nil, value: k - start <= 9 ? value : nil, width: k - start,
                                           lower: start, upper: k))
            } else {
                tokens.append(CounterToken(char: password[k], value: nil, width: 0, lower: k, upper: k + 1))
                k += 1
            }
        }
        guard placeholders.count >= 2 else { return }

        func same(_ a: Int, _ b: Int) -> Bool { tokens[a].char == tokens[b].char }
        var baseCache: [String: Double] = [:]
        var emitted = 0
        var next = 0                                    // Index in `placeholders`: erster Platzhalter ≥ s
        for s in 0..<tokens.count {
            while next < placeholders.count, placeholders[next] < s { next += 1 }
            guard next + 1 < placeholders.count else { break }
            // Genau ein Platzhalter je Vorlage: Periode = Abstand zum nächsten Platzhalter.
            let p = placeholders[next]
            let period = placeholders[next + 1] - p
            guard period >= 2, s >= p - period + 1 else { continue }

            var reps = 1
            repetition: while s + (reps + 1) * period <= tokens.count {
                for t in 0..<period where !same(s + t, s + reps * period + t) { break repetition }
                reps += 1
            }
            guard reps >= 2 else { continue }

            let offset = p - s
            var values: [Int] = []
            for r in 0..<reps {
                guard let v = tokens[s + r * period + offset].value else { break }
                values.append(v)
            }
            guard values.count >= 2 else { continue }
            let step = values[1] - values[0]
            guard ZxcvbnMatcher.counterSteps.contains(abs(step)) else { continue }
            var count = 2
            while count < values.count, values[count] - values[count - 1] == step { count += 1 }
            reps = count

            // Abgebrochene letzte Wiederholung (Anfang der Vorlage, Zahl nur, wenn sie die Folge fortsetzt)
            let tailStart = s + reps * period
            var tail = 0
            while tail < period - 1, tailStart + tail < tokens.count, same(s + tail, tailStart + tail) {
                if tail == offset {
                    guard let v = tokens[tailStart + tail].value, v - values[reps - 1] == step else { break }
                }
                tail += 1
            }

            var base: [Character] = []
            for t in 0..<period { if let c = tokens[s + t].char { base.append(c) } }
            let key = String(base)
            let baseLog2: Double
            if let cached = baseCache[key] {
                baseLog2 = cached
            } else {
                baseLog2 = ZxcvbnScoring.mostGuessable(base, matches: omnimatch(base)).log2Guesses
                baseCache[key] = baseLog2
            }
            let repetitions = Double(reps + (tail > 0 ? 1 : 0))
            let lg = baseLog2 + Double(tokens[p].width) * ZxcvbnMath.log2Of10 + log2(Double(2 * ZxcvbnMatcher.counterSteps.count))
                + log2(Double(period)) + log2(repetitions)
            let last = tokens[tailStart + tail - 1]
            matches.append(ZxcvbnMatch(pattern: .counter, i: tokens[s].lower, j: last.upper - 1, log2Guesses: lg))
            emitted += 1
            if emitted >= ZxcvbnMatcher.maxCounterMatches { return }
        }
    }

    // MARK: - Kalenderfolgen (Wochentage, Monate)

    /// Feste Reihen (klein): Wochentage und Monate in Kurz- und Langform, DE/EN/FR/IT. Je Stelle mehrere
    /// Schreibweisen; die erste ist die Hauptform (andere kosten 1 Bit).
    static let calendarSeries: [[[String]]] = [
        // Wochentage
        [["mo"], ["di"], ["mi"], ["do"], ["fr"], ["sa"], ["so"]],
        [["montag"], ["dienstag"], ["mittwoch"], ["donnerstag"], ["freitag"], ["samstag", "sonnabend"], ["sonntag"]],
        [["mo"], ["tu"], ["we"], ["th"], ["fr"], ["sa"], ["su"]],
        [["mon"], ["tue", "tues"], ["wed"], ["thu", "thur", "thurs"], ["fri"], ["sat"], ["sun"]],
        [["monday"], ["tuesday"], ["wednesday"], ["thursday"], ["friday"], ["saturday"], ["sunday"]],
        [["lu"], ["ma"], ["me"], ["je"], ["ve"], ["sa"], ["di"]],
        [["lun"], ["mar"], ["mer"], ["jeu"], ["ven"], ["sam"], ["dim"]],
        [["lundi"], ["mardi"], ["mercredi"], ["jeudi"], ["vendredi"], ["samedi"], ["dimanche"]],
        [["lu"], ["ma"], ["me"], ["gi"], ["ve"], ["sa"], ["do"]],
        [["lun"], ["mar"], ["mer"], ["gio"], ["ven"], ["sab"], ["dom"]],
        [["lunedì", "lunedi"], ["martedì", "martedi"], ["mercoledì", "mercoledi"], ["giovedì", "giovedi"],
         ["venerdì", "venerdi"], ["sabato"], ["domenica"]],
        // Monate
        [["jan"], ["feb"], ["mär", "mar", "maer", "mrz"], ["apr"], ["mai"], ["jun"], ["jul"], ["aug"],
         ["sep", "sept"], ["okt"], ["nov"], ["dez"]],
        [["januar", "jänner", "jaenner"], ["februar", "feber"], ["märz", "maerz", "marz"], ["april"], ["mai"],
         ["juni"], ["juli"], ["august"], ["september"], ["oktober"], ["november"], ["dezember"]],
        [["jan"], ["feb"], ["mar"], ["apr"], ["may"], ["jun"], ["jul"], ["aug"], ["sep", "sept"], ["oct"],
         ["nov"], ["dec"]],
        [["january"], ["february"], ["march"], ["april"], ["may"], ["june"], ["july"], ["august"],
         ["september"], ["october"], ["november"], ["december"]],
        [["janv", "jan"], ["févr", "fevr", "fév", "fev"], ["mars"], ["avr"], ["mai"], ["juin"], ["juil"],
         ["août", "aout"], ["sept", "sep"], ["oct"], ["nov"], ["déc", "dec"]],
        [["janvier"], ["février", "fevrier"], ["mars"], ["avril"], ["mai"], ["juin"], ["juillet"],
         ["août", "aout"], ["septembre"], ["octobre"], ["novembre"], ["décembre", "decembre"]],
        [["gen"], ["feb"], ["mar"], ["apr"], ["mag"], ["giu"], ["lug"], ["ago"], ["set"], ["ott"], ["nov"],
         ["dic"]],
        [["gennaio"], ["febbraio"], ["marzo"], ["aprile"], ["maggio"], ["giugno"], ["luglio"], ["agosto"],
         ["settembre"], ["ottobre"], ["novembre"], ["dicembre"]],
    ]

    private struct CalendarStart {
        let series: Int
        let item: Int
        let spelling: [Character]
        let primary: Bool
    }

    /// Schreibweisen je Reihe und Stelle als Zeichenfolgen, längste zuerst (damit „sept“ vor „sep“ geprüft wird).
    private static let calendarSpellings: [[[(chars: [Character], primary: Bool)]]] = calendarSeries.map { series in
        series.map { spellings in
            spellings.enumerated()
                .map { (chars: Array($0.element), primary: $0.offset == 0) }
                .sorted { $0.chars.count > $1.chars.count }
        }
    }

    /// Erste Buchstaben → mögliche Anfänge (Reihe, Stelle, Schreibweise).
    private static let calendarIndex: [Character: [CalendarStart]] = {
        var index: [Character: [CalendarStart]] = [:]
        for (s, series) in calendarSpellings.enumerated() {
            for (item, spellings) in series.enumerated() {
                for spelling in spellings {
                    guard let first = spelling.chars.first else { continue }
                    index[first, default: []].append(CalendarStart(series: s, item: item, spelling: spelling.chars,
                                                                   primary: spelling.primary))
                }
            }
        }
        return index
    }()

    /// Aufeinanderfolgende Einträge einer Reihe ab beliebigem Start, vorwärts oder rückwärts (auch über das Ende
    /// hinweg), mit überall gleichem Trennstück aus 0–3 Zeichen, die keine Buchstaben sind. Mindestens 2 Einträge.
    /// Kosten: Reihe × Start × Richtung × Trennstück × Schreibweise × Länge (+1 Bit für Nebenformen).
    func calendarMatches(_ password: [Character], lower: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = lower.count
        guard n >= 4 else { return }
        func matchesAt(_ position: Int, _ spelling: [Character]) -> Bool {
            guard position + spelling.count <= n else { return false }
            for (offset, c) in spelling.enumerated() where lower[position + offset] != c { return false }
            return true
        }
        let seriesLog2 = log2(Double(ZxcvbnMatcher.calendarSeries.count))
        for i in 0..<n {
            guard let starts = ZxcvbnMatcher.calendarIndex[lower[i]] else { continue }
            for start in starts where matchesAt(i, start.spelling) {
                let series = ZxcvbnMatcher.calendarSpellings[start.series]
                let length = series.count
                for direction in [1, -1] {
                    var item = start.item
                    var end = i + start.spelling.count
                    var count = 1
                    var variant = !start.primary
                    var separator: ArraySlice<Character>?
                    var casing = CaseState()
                    casing.add(password[i..<end])
                    while count < length {
                        let nextItem = (item + direction + length) % length
                        var found: (gap: Int, chars: Int, primary: Bool)?
                        gaps: for gap in 0...ZxcvbnMatcher.maxSeparatorLength {
                            let position = end + gap
                            guard position < n else { break }
                            if gap > 0, password[position - 1].isLetter { break }
                            if let separator, !password[end..<position].elementsEqual(separator) { continue }
                            for spelling in series[nextItem] where matchesAt(position, spelling.chars) {
                                found = (gap, spelling.chars.count, spelling.primary)
                                break gaps
                            }
                        }
                        guard let step = found else { break }
                        if separator == nil { separator = password[end..<(end + step.gap)] }
                        let itemStart = end + step.gap
                        end = itemStart + step.chars
                        casing.add(password[itemStart..<end])
                        variant = variant || !step.primary
                        item = nextItem
                        count += 1
                        let lg = seriesLog2 + log2(Double(length)) + 1
                            + ZxcvbnMatcher.constantSeparatorLog2(separator ?? [])
                            + casing.log2Variations + log2(Double(count)) + (variant ? 1 : 0)
                        matches.append(ZxcvbnMatch(pattern: .calendar, i: i, j: end - 1, log2Guesses: lg))
                    }
                }
            }
        }
    }

    // MARK: - Ort + Postleitzahl

    /// Ränge der eigenen Orts- und Vereinsliste (`placesCH`), Wort → Rang.
    static let placeRanks: [String: Int] = {
        var ranks: [String: Int] = [:]
        ZxcvbnDictionary.forEachLine(ZxcvbnListData.placesCH) { index, fields in
            for field in fields where ranks[field.word] == nil { ranks[field.word] = index + 1 }
        }
        return ranks
    }()

    static let placeMaxLength: Int = placeRanks.keys.reduce(0) { max($0, $1.count) }
    /// Schweizer Postleitzahlen (mit Liechtenstein): 1000–9699.
    static let postalCodes = 1000...9699
    /// Trennzeichen zwischen Ort und Postleitzahl.
    static let placeSeparators: Set<Character> = [" ", "-", "_", ".", "/", ","]

    /// Ein Ort + Postleitzahl als Einheit (für Ketten mit gleicher Form).
    private struct PlaceUnit {
        let i: Int
        let j: Int
        /// log2(Rang) + Schreibweise + Postleitzahl
        let core: Double
        /// Ort vor (true) oder nach der Zahl
        let placeFirst: Bool
        /// Trennzeichen zwischen Ort und Zahl (nil = keins)
        let inner: Character?

        /// Form: Reihenfolge (1 Bit) + mit/ohne Trennzeichen (1 Bit) + welches Trennzeichen.
        var formatLog2: Double { 2 + (inner == nil ? 0 : log2(Double(ZxcvbnMatcher.placeSeparators.count))) }
    }

    /// Ein Ort aus der Ortsliste direkt vor oder nach einer vierstelligen Zahl 1000–9699 (wahlweise mit einem
    /// Trennzeichen) ergibt EIN Teilstück. Kosten: Rang des Orts × Schreibweise × Postleitzahl (87 Möglichkeiten,
    /// wenn sie auf 00 endet wie die Hauptnummern der Städte, sonst 8700) × Form (Reihenfolge, Trennzeichen).
    /// Mehrere solche Einheiten gleicher Form hintereinander (mit überall gleichem Trennstück aus 0–3 Zeichen
    /// ohne Buchstaben und Ziffern) sind ebenfalls EIN Teilstück: Summe der Einheiten + einmal Form + Trennstück –
    /// ohne den zxcvbn-Zuschlag 10000 je Teil. Ohne eingebaute PLZ-Tabelle wird nicht geprüft, ob die Zahl wirklich
    /// zum Ort gehört (konservativ: die Zahl kostet immer etwas).
    func placeCodeMatches(_ password: [Character], lower: [Character], into matches: inout [ZxcvbnMatch]) {
        let n = password.count
        var units: [PlaceUnit] = []
        var k = 0
        while k < n {
            guard password[k].zxcvbnDigit != nil else {
                k += 1
                continue
            }
            let start = k
            var value = 0
            while k < n, let digit = password[k].zxcvbnDigit {
                if k - start < 4 { value = value * 10 + digit }
                k += 1
            }
            guard k - start == 4, ZxcvbnMatcher.postalCodes.contains(value) else { continue }
            let codeLog2 = value % 100 == 0 ? log2(87.0) : log2(8700.0)

            for gap in 0...1 {
                // Ort davor: "Thun3600", "Thun 3600"
                var inner: Character?
                if gap == 1 {
                    guard start >= 1, ZxcvbnMatcher.placeSeparators.contains(password[start - 1]) else { continue }
                    inner = password[start - 1]
                }
                let wordEnd = start - gap
                guard wordEnd > 0 else { continue }
                for wordStart in stride(from: wordEnd - 1, through: max(0, wordEnd - ZxcvbnMatcher.placeMaxLength), by: -1) {
                    guard let rank = placeRank(lower[wordStart..<wordEnd]) else { continue }
                    let core = log2(Double(rank)) + log2(ZxcvbnScoring.uppercaseVariations(password[wordStart..<wordEnd])) + codeLog2
                    units.append(PlaceUnit(i: wordStart, j: k - 1, core: core, placeFirst: true, inner: inner))
                }
            }
            for gap in 0...1 {
                // Ort danach: "3600Thun", "3600 Thun" (Schweizer Adressform)
                var inner: Character?
                if gap == 1 {
                    guard k < n, ZxcvbnMatcher.placeSeparators.contains(password[k]) else { continue }
                    inner = password[k]
                }
                let wordStart = k + gap
                guard wordStart < n else { continue }
                for wordEnd in (wordStart + 1)...min(n, wordStart + ZxcvbnMatcher.placeMaxLength) {
                    guard let rank = placeRank(lower[wordStart..<wordEnd]) else { continue }
                    let core = log2(Double(rank)) + log2(ZxcvbnScoring.uppercaseVariations(password[wordStart..<wordEnd])) + codeLog2
                    units.append(PlaceUnit(i: start, j: wordEnd - 1, core: core, placeFirst: false, inner: inner))
                }
            }
        }
        guard !units.isEmpty else { return }
        for unit in units {
            matches.append(ZxcvbnMatch(pattern: .placeCode, i: unit.i, j: unit.j, log2Guesses: unit.core + unit.formatLog2))
        }

        // Ketten gleicher Form: Tiefensuche über alle passenden Einheiten (begrenzt)
        struct Chain {
            let first: PlaceUnit
            let sum: Double
            let end: Int
            let separator: ArraySlice<Character>?
            let count: Int
        }
        var stack = units.map { Chain(first: $0, sum: $0.core, end: $0.j + 1, separator: nil, count: 1) }
        var steps = 0
        while let chain = stack.popLast() {
            steps += 1
            if steps > ZxcvbnMatcher.maxPlaceChainSteps { return }
            for gap in 0...ZxcvbnMatcher.maxSeparatorLength {
                let position = chain.end + gap
                guard position < n else { break }
                if gap > 0 {
                    let c = password[position - 1]
                    if c.isLetter || c.zxcvbnDigit != nil { break }
                }
                if let separator = chain.separator, !password[chain.end..<position].elementsEqual(separator) { continue }
                for unit in units where unit.i == position && unit.placeFirst == chain.first.placeFirst
                    && unit.inner == chain.first.inner {
                    let separator = chain.separator ?? password[chain.end..<position]
                    let next = Chain(first: chain.first, sum: chain.sum + unit.core, end: unit.j + 1,
                                     separator: separator, count: chain.count + 1)
                    let lg = next.sum + chain.first.formatLog2 + ZxcvbnMatcher.constantSeparatorLog2(separator)
                        + log2(Double(next.count))
                    matches.append(ZxcvbnMatch(pattern: .placeCode, i: chain.first.i, j: unit.j, log2Guesses: lg))
                    stack.append(next)
                }
            }
        }
    }

    private static let maxPlaceChainSteps = 2000

    /// Rang eines Orts (kleinster aus Ortsliste und Gesamtwörterbuch), nil wenn kein Ort.
    private func placeRank(_ token: ArraySlice<Character>) -> Int? {
        let word = String(token)
        guard let place = ZxcvbnMatcher.placeRanks[word] else { return nil }
        return min(place, dictionary.ranks[word] ?? Int.max)
    }
}
