import Clibsodium
import Foundation

/// Schlägt eine Passphrase vor (SPEC §1.6): Wörter gleichverteilt per `randombytes_uniform` aus einer
/// gebündelten deutschen Liste mit genau 2048 Wörtern (4–8 Kleinbuchstaben a–z, eindeutig, unanstössig),
/// getrennt mit "-". 6 Wörter = 66 Bit Zufalls-Entropie.
/// Die Liste stammt aus `skripte/woerter/quellen/passphrase_de.txt` (Generator prüft Anzahl und Regeln).
public enum PassphraseGenerator {
    public static let wordListCount: Int = 2048

    /// Die Wortliste (genau `wordListCount` Einträge, siehe Tests).
    static let words: [String] = ZxcvbnDictionary.lines(ZxcvbnListData.passphraseWords)

    /// Höchstens so oft neu ziehen, falls eine Passphrase trotz voller Entropie unter der Regel läge.
    static let maximumDraws = 64

    public static func generate(words count: Int = 6) -> String {
        guard count > 0, !words.isEmpty else { return "" }
        // Ab 6 Wörtern (≥ 60 Bit Entropie) soll der Vorschlag die Master-Passwort-Regel immer erfüllen.
        // Die Schätzung kennt auch Wortfolgen nach Häufigkeit; sechs sehr häufige Wörter (z. B.
        // "hallo-keller-fischer-…") lägen darunter. Das ist extrem selten (< 1 von 2 Mio. simuliert),
        // darum wird dann neu gezogen; die Gleichverteilung ändert sich dadurch nicht messbar.
        let mustPass = entropyBits(words: count) >= MasterPasswordPolicy.minimumBits
        var phrase = draw(count)
        var attempts = 1
        while mustPass, attempts < maximumDraws,
              PasswordStrength.estimate(phrase).bits < MasterPasswordPolicy.minimumBits {
            phrase = draw(count)
            attempts += 1
        }
        return phrase
    }

    public static func entropyBits(words: Int) -> Double {
        Double(max(0, words)) * log2(Double(wordListCount))
    }

    /// `count` Wörter gleichverteilt, mit "-" verbunden.
    static func draw(_ count: Int) -> String {
        _ = Sodium.ready
        let list = words
        var parts: [String] = []
        parts.reserveCapacity(count)
        for _ in 0..<count {
            let index = Int(randombytes_uniform(UInt32(list.count)))
            parts.append(list[index])
        }
        return parts.joined(separator: "-")
    }
}
