import Foundation

/// Schätzt die Stärke eines Passworts wie zxcvbn (SPEC §1.6): kleinste Zahl Rateversuche über eine
/// Zerlegung in erkannte Muster, `bits = log2(guesses)`.
///
/// Stufen (`Level`), in Bit geschätzter Rateversuche:
/// - `veryWeak`   < 28 Bit (unter ~2.7·10^8 Versuchen, fällt auch gegen Argon2 rasch)
/// - `weak`       < 36 Bit
/// - `fair`       < 60 Bit (die Untergrenze für das Master-Passwort, `MasterPasswordPolicy.minimumBits`)
/// - `strong`     < 80 Bit
/// - `veryStrong` ≥ 80 Bit
///
/// Die Schätzung ist schnell genug für jeden Tastendruck (Listen werden einmalig beim ersten Aufruf geladen).
/// Analysiert werden höchstens die ersten `maximumAnalyzedLength` Zeichen. Muster, die über diese Grenze
/// hinausreichen, erkennt die Zerlegung nicht; die Schätzung kann dadurch auch **höher** ausfallen (Befund #49:
/// ein zweimal getipptes langes Passwort zerfiel in viele Teilstücke). Darum wird bei Kürzung zusätzlich die
/// längste periodische Anfangsfolge der ganzen Eingabe bestimmt (KMP, O(n)) und als Deckel genommen:
/// Schätzung(Periode) + log2(Wiederholungen) [+ Rest wie zwei Teilstücke bei zxcvbn].
public enum PasswordStrength {
    public enum Level: Int, Sendable { case veryWeak, weak, fair, strong, veryStrong }

    /// Stufengrenzen in Bit (untere Grenze der jeweiligen Stufe).
    static let weakBits: Double = 28
    static let fairBits: Double = 36
    static let strongBits: Double = 60
    static let veryStrongBits: Double = 80

    /// Längere Eingaben werden nur bis hierhin analysiert (Laufzeit wächst etwa quadratisch).
    static let maximumAnalyzedLength = 256

    public static func estimate(_ password: String, userInputs: [String] = []) -> (bits: Double, level: Level) {
        let bits = analyze(password, userInputs: userInputs).bits
        return (bits, level(forBits: bits))
    }

    static func level(forBits bits: Double) -> Level {
        if bits < weakBits { return .veryWeak }
        if bits < fairBits { return .weak }
        if bits < strongBits { return .fair }
        if bits < veryStrongBits { return .strong }
        return .veryStrong
    }

    /// Ergebnis mit Zerlegung (für Tests und Dokumentation; enthält das Passwort, nie protokollieren).
    struct Analysis {
        let bits: Double
        let sequence: [ZxcvbnMatch]
        let characters: [Character]
    }

    static func analyze(_ password: String, userInputs: [String] = [], referenceYear: Int = currentYear) -> Analysis {
        let normalized = MasterPasswordPolicy.normalized(password)
        let full = Array(normalized)
        var characters = full
        if characters.count > maximumAnalyzedLength {
            characters = Array(characters[0..<maximumAnalyzedLength])
        }
        guard !characters.isEmpty else { return Analysis(bits: 0, sequence: [], characters: []) }
        let inputs = userInputs.map { MasterPasswordPolicy.normalized($0) }
        let matcher = ZxcvbnMatcher(dictionary: ZxcvbnDictionary.shared, userInputs: inputs,
                                    referenceYear: referenceYear, graphs: KeyboardGraphs.all)
        let result = ZxcvbnScoring.mostGuessable(characters, matches: matcher.omnimatch(characters))
        var bits = max(result.log2Guesses, 0)
        if full.count > maximumAnalyzedLength,
           let cap = periodicCap(full, userInputs: userInputs, referenceYear: referenceYear), cap < bits {
            bits = cap
        }
        return Analysis(bits: bits, sequence: result.sequence, characters: characters)
    }

    struct PeriodicPrefix: Equatable {
        let length: Int
        let period: Int
    }

    /// Längste Anfangsfolge mit Periode p und mindestens zwei vollen Wiederholungen (2p ≤ Länge), per
    /// KMP-Präfixfunktion in O(n).
    static func longestPeriodicPrefix(_ chars: [Character]) -> PeriodicPrefix? {
        let n = chars.count
        guard n >= 2 else { return nil }
        var prefix = [Int](repeating: 0, count: n)
        for i in 1..<n {
            var k = prefix[i - 1]
            while k > 0, chars[i] != chars[k] { k = prefix[k - 1] }
            if chars[i] == chars[k] { k += 1 }
            prefix[i] = k
        }
        for length in stride(from: n, through: 2, by: -1) {
            let period = length - prefix[length - 1]
            if 2 * period <= length { return PeriodicPrefix(length: length, period: period) }
        }
        return nil
    }

    /// Deckel für gekürzte Eingaben (Befund #49): Periode + log2(Länge/Periode), ein Rest nach der periodischen
    /// Anfangsfolge zählt wie ein zweites Teilstück (2! · g1 · g2 + 10000, wie zxcvbn).
    static func periodicCap(_ full: [Character], userInputs: [String], referenceYear: Int) -> Double? {
        guard let periodic = longestPeriodicPrefix(full), periodic.length > maximumAnalyzedLength else { return nil }
        let base = analyze(String(full[0..<periodic.period]), userInputs: userInputs, referenceYear: referenceYear).bits
        var bits = base + log2(Double(periodic.length) / Double(periodic.period))
        if periodic.length < full.count {
            let rest = analyze(String(full[periodic.length...]), userInputs: userInputs, referenceYear: referenceYear).bits
            bits = ZxcvbnMath.logAdd(1 + bits + rest, log2(ZxcvbnScoring.minGuessesBeforeGrowingSequence))
        }
        return bits
    }

    /// Bezugsjahr für Jahres- und Datumsmuster (zxcvbn REFERENCE_YEAR).
    static let currentYear: Int = Calendar(identifier: .gregorian).component(.year, from: Date())
}
