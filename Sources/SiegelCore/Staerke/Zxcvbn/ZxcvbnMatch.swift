import Foundation

// Gemeinsame Typen und Rechenhilfen der zxcvbn-Schätzung (Port von zxcvbn 4.4.2, Dropbox, MIT).
// Alle Rateversuche werden als log2 geführt, damit lange Passwörter nicht überlaufen.

/// Ein erkanntes Muster über password[i...j] (Zeichen = Graphem-Cluster) mit seiner Schätzung.
struct ZxcvbnMatch: Sendable {
    enum Pattern: String, Sendable {
        case dictionary, spatial, repeated, sequence, year, date, bruteforce
        /// Siegel-Erweiterung: Kette aus Wörtern der eigenen Passphrasen-Liste (Angreifer kennt die Liste).
        case passphrase
        /// Siegel-Erweiterung: Wortfolge mit gleichem Trennzeichen ("Mein Hund heisst Bello").
        case phrase
        /// Siegel-Erweiterung (Befund #18): Grundwort mit hochzählender Zahl ("Hund1Hund2Hund3").
        case counter
        /// Siegel-Erweiterung (Befund #18): Folge von Wochentagen oder Monaten ("Mo-Di-Mi", "Jan.Feb.Mar").
        case calendar
        /// Siegel-Erweiterung (Befund #18): Ort mit Postleitzahl ("Thun3600", "3600 Thun").
        case placeCode
    }

    let pattern: Pattern
    let i: Int
    let j: Int
    /// log2 der Rateversuche nach dem Mustermodell, noch ohne Untergrenze für Teilstücke.
    let log2Guesses: Double

    var length: Int { j - i + 1 }
}

/// Rechenhilfen (alle Ergebnisse als Double, Logarithmen zur Basis 2).
enum ZxcvbnMath {
    static let log2Of10: Double = log2(10)

    /// Binomialkoeffizient n über k als Double (für die Varianten-Zählung).
    static func nCk(_ n: Int, _ k: Int) -> Double {
        if k < 0 || k > n { return 0 }
        if k == 0 || k == n { return 1 }
        let kk = min(k, n - k)
        var r = 1.0
        var top = Double(n)
        for d in 1...kk {
            r *= top
            r /= Double(d)
            top -= 1
        }
        return r
    }

    /// log2 des Binomialkoeffizienten n über k (über lgamma, O(1)).
    static func log2Binomial(_ n: Int, _ k: Int) -> Double {
        if k <= 0 || k >= n { return 0 }
        return (lgamma(Double(n) + 1) - lgamma(Double(k) + 1) - lgamma(Double(n - k) + 1)) / log(2)
    }

    /// log2(2^a + 2^b) ohne Überlauf.
    static func logAdd(_ a: Double, _ b: Double) -> Double {
        let hi = max(a, b)
        let lo = min(a, b)
        if lo == -Double.infinity { return hi }
        return hi + log2(1 + exp2(lo - hi))
    }

    /// log2(l!) für kleine l per Tabelle, sonst per lgamma.
    static func log2Factorial(_ l: Int) -> Double {
        if l < 2 { return 0 }
        if l < factorialTable.count { return factorialTable[l] }
        return lgamma(Double(l) + 1) / log(2)
    }

    private static let factorialTable: [Double] = {
        var table = [Double](repeating: 0, count: 300)
        var acc = 0.0
        for l in 2..<table.count {
            acc += log2(Double(l))
            table[l] = acc
        }
        return table
    }()
}

extension Character {
    /// Ziffer 0–9 (nur ASCII), sonst nil.
    var zxcvbnDigit: Int? {
        guard let a = asciiValue, a >= 48, a <= 57 else { return nil }
        return Int(a - 48)
    }

    /// Unicode-Wert, falls das Zeichen aus genau einem Skalar besteht.
    var zxcvbnScalar: Int? {
        let scalars = unicodeScalars
        guard scalars.count == 1, let s = scalars.first else { return nil }
        return Int(s.value)
    }

    /// Kleinbuchstabe, falls die Kleinschreibung wieder genau ein Zeichen ergibt (Indizes bleiben gleich).
    var zxcvbnLower: Character {
        if let a = asciiValue {
            return (a >= 65 && a <= 90) ? Character(Unicode.Scalar(a + 32)) : self
        }
        let lowered = lowercased()
        guard lowered.count == 1, let c = lowered.first else { return self }
        return c
    }
}
