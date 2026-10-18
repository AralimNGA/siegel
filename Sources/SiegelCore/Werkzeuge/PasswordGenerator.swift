import Clibsodium
import Foundation

/// Zufallspasswörter für die Bearbeiten-Ansicht (SPEC §7.5, §8).
///
/// Verteilung: Das Ergebnis ist **gleichverteilt** über die Menge S aller Zeichenketten der Länge L, die
/// - nur Zeichen aus den gewählten Klassen enthalten,
/// - aus jeder gewählten Klasse mindestens ein Zeichen enthalten,
/// - nicht mit `=`, `+`, `-` oder `@` beginnen (Tabellenprogramme deuten das als Formel).
///
/// Verfahren: Das erste Zeichen wird gleichverteilt aus dem Vorrat ohne `= + - @` gezogen, alle weiteren
/// gleichverteilt aus dem ganzen Vorrat (`randombytes_uniform`, ohne Modulo-Verzerrung). Fehlt danach eine
/// gewählte Klasse, wird die **ganze** Zeichenkette verworfen und neu gezogen. Verwerfen erhält die
/// Gleichverteilung über S; ein nachträgliches Einfügen fehlender Klassen würde sie verzerren und wird
/// darum nicht gemacht. Die Annahmewahrscheinlichkeit liegt für alle Optionen über 0.3 (schlechtester
/// Fall: Länge 8, alle Klassen, ähnliche Zeichen vermieden), es sind also im Mittel höchstens ~3 Züge.
///
/// Zeichenklassen (ASCII):
/// - Gross: `A–Z` (26), Klein: `a–z` (26), Ziffern: `0–9` (10)
/// - Symbole: alle druckbaren ASCII-Sonderzeichen ohne Leerzeichen (32):
///   ``!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~``
///
/// „Ähnliche Zeichen vermeiden“ entfernt diese 15 Zeichen (`ambiguousCharacters`):
/// - `0 O o` (Null und O), `1 l I` (Eins, kleines L, grosses i), `|` (senkrechter Strich, wie l/I/1),
///   `!` (wie l/1/|),
/// - `` ` ' " `` (Gravis, Apostroph, Anführungszeichen: untereinander und mit typografischen
///   Anführungszeichen verwechselbar, werden beim Abschreiben oft ersetzt),
/// - `, . ; :` (sehr kleine Zeichen, auf Papier leicht übersehen oder verwechselt).
/// Danach: Gross 24, Klein 24, Ziffern 8, Symbole 23.
///
/// Keine Klasse gewählt → Fallback auf Kleinbuchstaben. Länge wird auf 8…64 geklemmt.
public enum PasswordGenerator {
    public struct Options: Equatable, Sendable {
        public var length: Int = 24
        public var uppercase = true, lowercase = true, digits = true, symbols = true
        public var avoidAmbiguous = false
        public init() {}
    }

    // MARK: Zeichenvorräte (intern, für Tests sichtbar)

    static let minimumLength = 8
    static let maximumLength = 64

    static let uppercaseCharacters: [UInt8] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ".utf8)
    static let lowercaseCharacters: [UInt8] = Array("abcdefghijklmnopqrstuvwxyz".utf8)
    static let digitCharacters: [UInt8] = Array("0123456789".utf8)
    /// Druckbare ASCII-Sonderzeichen 0x21–0x7E ohne Buchstaben und Ziffern (32 Zeichen, ohne Leerzeichen).
    static let symbolCharacters: [UInt8] = Array("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".utf8)
    /// Siehe Typ-Dokumentation.
    static let ambiguousCharacters: [UInt8] = Array("0Oo1lI|!`'\",.;:".utf8)
    /// Nie als erstes Zeichen (Formel-Präfixe in Tabellenprogrammen).
    static let forbiddenFirstCharacters: [UInt8] = Array("=+-@".utf8)

    /// Die tatsächlich verwendeten, nicht leeren Klassen in fester Reihenfolge (Gross, Klein, Ziffern, Symbole).
    static func characterClasses(_ options: Options) -> [[UInt8]] {
        var chosen: [[UInt8]] = []
        if options.uppercase { chosen.append(uppercaseCharacters) }
        if options.lowercase { chosen.append(lowercaseCharacters) }
        if options.digits { chosen.append(digitCharacters) }
        if options.symbols { chosen.append(symbolCharacters) }
        if chosen.isEmpty { chosen.append(lowercaseCharacters) }
        if options.avoidAmbiguous {
            chosen = chosen.map { cls in cls.filter { !ambiguousCharacters.contains($0) } }
        }
        return chosen.filter { !$0.isEmpty }
    }

    static func clampedLength(_ length: Int) -> Int {
        min(max(length, minimumLength), maximumLength)
    }

    // MARK: Erzeugen

    public static func generate(_ options: Options) -> String {
        _ = Sodium.ready
        let classes = characterClasses(options)
        let length = clampedLength(options.length)
        return generate(classes: classes, length: length)
    }

    /// Kern ohne Klemmen (Tests ziehen auch kurze Längen). Klassen: disjunkt, nicht leer, ASCII.
    /// Ist keine gültige Zeichenkette möglich, kommt "" zurück (über die öffentliche API nie der Fall).
    static func generate(classes: [[UInt8]], length: Int) -> String {
        _ = Sodium.ready
        let pool = classes.flatMap { $0 }
        let firstPool = pool.filter { !forbiddenFirstCharacters.contains($0) }
        guard length > 0, !pool.isEmpty, !firstPool.isEmpty, classes.count <= length, classes.count < 31,
              pool.allSatisfy({ $0 < 128 }), acceptanceProbability(classes: classes, length: length) > 1e-6
        else { return "" }

        // Byte → Bitmaske der Klassen, zu denen es gehört.
        var classMask = [Int](repeating: 0, count: 128)
        for (index, cls) in classes.enumerated() {
            for byte in cls { classMask[Int(byte)] |= 1 << index }
        }
        let fullMask = (1 << classes.count) - 1

        var buffer = [UInt8](repeating: 0, count: length)
        defer { buffer.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) } }

        while true {
            var seen = 0
            for position in 0..<length {
                let source = position == 0 ? firstPool : pool
                let pick = Int(randombytes_uniform(UInt32(source.count)))
                let byte = source[pick]
                buffer[position] = byte
                seen |= classMask[Int(byte)]
            }
            if seen == fullMask { break }   // sonst ganz verwerfen und neu ziehen
        }
        return String(decoding: buffer, as: UTF8.self)
    }

    // MARK: Entropie

    /// Exakte Zufalls-Entropie log2(|S|) der tatsächlichen Verteilung (Gleichverteilung über S, siehe oben).
    ///
    /// |S| per Inklusion–Exklusion über die Teilmengen T der gewählten Klassen, die *fehlen*:
    /// |S| = Σ_T (−1)^|T| · a_T · b_T^(L−1), mit b_T = Zeichen der Klassen ausserhalb T und
    /// a_T = davon die Zeichen, die als erstes Zeichen erlaubt sind (ohne `= + - @`).
    /// Gerechnet wird in Verhältnisform relativ zum Hauptterm (kein Überlauf, keine Auslöschung):
    /// log2|S| = log2(a_∅) + (L−1)·log2(b_∅) + log2(1 + Σ_{T≠∅} (−1)^|T| (a_T/a_∅)(b_T/b_∅)^(L−1)).
    /// Der Klammerausdruck ist genau die Annahmewahrscheinlichkeit des Verwerfens und liegt in (0, 1].
    public static func entropyBits(_ options: Options) -> Double {
        exactEntropyBits(classes: characterClasses(options), length: clampedLength(options.length))
    }

    /// Kern ohne Klemmen (für Tests mit Brute-Force-Abgleich bei kurzen Längen). Klassen disjunkt.
    static func exactEntropyBits(classes: [[UInt8]], length: Int) -> Double {
        let acceptance = acceptanceProbability(classes: classes, length: length)
        guard acceptance > 0 else { return 0 }
        let a0 = Double(classes.reduce(0) { $0 + firstAllowedCount($1) })
        let b0 = Double(classes.reduce(0) { $0 + $1.count })
        return log2(a0) + Double(length - 1) * log2(b0) + log2(acceptance)
    }

    private static func firstAllowedCount(_ cls: [UInt8]) -> Int {
        cls.filter { !forbiddenFirstCharacters.contains($0) }.count
    }

    /// Wahrscheinlichkeit, dass ein Zug (erstes Zeichen ohne `= + - @`, Rest frei) alle Klassen enthält,
    /// = |S| / (a_∅ · b_∅^(L−1)) per Inklusion–Exklusion (siehe `entropyBits`). 0 = unmöglich.
    static func acceptanceProbability(classes: [[UInt8]], length: Int) -> Double {
        guard length > 0, !classes.isEmpty, classes.count <= length, classes.count < 31 else { return 0 }
        let sizes = classes.map { Double($0.count) }
        let firstSizes = classes.map { Double(firstAllowedCount($0)) }
        let b0 = sizes.reduce(0, +)
        let a0 = firstSizes.reduce(0, +)
        guard a0 > 0, b0 > 0 else { return 0 }

        let k = classes.count
        var correction = 0.0
        for mask in 1..<(1 << k) {
            var aT = a0, bT = b0, excluded = 0
            for c in 0..<k where mask & (1 << c) != 0 {
                aT -= firstSizes[c]
                bT -= sizes[c]
                excluded += 1
            }
            guard aT > 0, bT > 0 else { continue }   // Term ist 0
            let term = (aT / a0) * pow(bT / b0, Double(length - 1))
            correction += excluded % 2 == 1 ? -term : term
        }
        return max(0, min(1, 1 + correction))
    }
}
