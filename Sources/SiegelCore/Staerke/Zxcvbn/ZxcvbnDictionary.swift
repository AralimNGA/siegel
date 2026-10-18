import Foundation

/// Namensraum der generierten Wortlisten (Dateien in `Staerke/Woerter/`, erzeugt von
/// `skripte/woerter/listen_bauen.py`). Jede Liste ist EIN String-Literal, eine Zeile je Eintrag,
/// kleingeschrieben, nach Häufigkeit sortiert. Tabulator trennt Schreibvarianten mit gleichem Rang
/// (z. B. "müller\tmueller\tmuller").
enum ZxcvbnListData {}

/// Alle gebündelten Listen als ein Wörterbuch Wort → Rang (kleinster Rang über alle Listen).
/// Wird beim ersten Gebrauch einmal aufgebaut (Swift initialisiert `static let` threadsicher und lazy).
struct ZxcvbnDictionary: Sendable {
    /// Rang = geschätzte Zahl Versuche, bis ein Angreifer das Wort in seiner Liste erreicht.
    let ranks: [String: Int]
    /// Längstes Wort in UTF-8-Bytes (obere Schranke für die Zeichenzahl, begrenzt die Suche).
    let maxWordLength: Int

    static let shared = ZxcvbnDictionary.load()

    /// Uniformer Rang der englischen Zusatzwörter aus web2 (alphabetisch, nicht nach Häufigkeit):
    /// ein Angreifer probiert sie nach den häufigen Listen, im Mittel nach etwa so vielen Versuchen.
    static let web2Rank = 150_000
    /// Uniformer Rang der Passphrasen-Wörter: Wer die Liste kennt, braucht höchstens 2048 Versuche je Wort.
    static let passphraseRank = 2048

    enum Mode {
        case ranked
        case uniform(Int)
        case frontCoded(Int)
    }

    static var sources: [(String, Mode)] {
        [
            (ZxcvbnListData.passwords, .ranked),
            (ZxcvbnListData.passwordsGerman, .ranked),
            (ZxcvbnListData.englishWikipedia, .ranked),
            (ZxcvbnListData.usTvAndFilm, .ranked),
            (ZxcvbnListData.germanWords, .ranked),
            (ZxcvbnListData.surnames, .ranked),
            (ZxcvbnListData.maleNames, .ranked),
            (ZxcvbnListData.femaleNames, .ranked),
            (ZxcvbnListData.firstNamesCHDE, .ranked),
            (ZxcvbnListData.surnamesCHDE, .ranked),
            (ZxcvbnListData.placesCH, .ranked),
            (ZxcvbnListData.passphraseWords, .uniform(passphraseRank)),
            (ZxcvbnListData.englishWeb2, .frontCoded(web2Rank)),
        ]
    }

    static func load() -> ZxcvbnDictionary {
        var ranks = [String: Int](minimumCapacity: 320_000)
        var maxLength = 0
        func insert(_ word: String, _ rank: Int, _ byteCount: Int) {
            if let old = ranks[word], old <= rank { return }
            ranks[word] = rank
            if byteCount > maxLength { maxLength = byteCount }
        }
        for (text, mode) in sources {
            switch mode {
            case .ranked:
                forEachLine(text) { index, fields in
                    for field in fields { insert(field.word, index + 1, field.bytes) }
                }
            case .uniform(let rank):
                forEachLine(text) { _, fields in
                    for field in fields { insert(field.word, rank, field.bytes) }
                }
            case .frontCoded(let rank):
                forEachFrontCoded(text) { word, bytes in insert(word, rank, bytes) }
            }
        }
        return ZxcvbnDictionary(ranks: ranks, maxWordLength: maxLength)
    }

    struct Field {
        let word: String
        let bytes: Int
    }

    /// Ruft `body(zeilennummer, felder)` für jede nicht leere Zeile auf (Felder durch Tabulator getrennt).
    static func forEachLine(_ text: String, _ body: (Int, [Field]) -> Void) {
        var copy = text
        copy.withUTF8 { buffer in
            var index = 0
            var start = 0
            var fields: [Field] = []
            var fieldStart = 0
            var position = 0
            let count = buffer.count
            while position <= count {
                let byte: UInt8 = position < count ? buffer[position] : 0x0A
                if byte == 0x09 || byte == 0x0A {
                    if position > fieldStart {
                        let slice = UnsafeBufferPointer(rebasing: buffer[fieldStart..<position])
                        fields.append(Field(word: String(decoding: slice, as: UTF8.self), bytes: slice.count))
                    }
                    fieldStart = position + 1
                    if byte == 0x0A {
                        if position > start, !fields.isEmpty {
                            body(index, fields)
                            index += 1
                        }
                        fields.removeAll(keepingCapacity: true)
                        start = position + 1
                    }
                }
                position += 1
            }
        }
    }

    /// Vorn-komprimierte Liste: erstes Zeichen jeder Zeile = Länge des gemeinsamen Anfangs mit dem
    /// Vorgängerwort (0–9, a–z = 10–35), danach der Rest des Wortes.
    static func forEachFrontCoded(_ text: String, _ body: (String, Int) -> Void) {
        var copy = text
        copy.withUTF8 { buffer in
            var previous: [UInt8] = []
            var current: [UInt8] = []
            var lineStart = 0
            let count = buffer.count
            var position = 0
            while position <= count {
                let byte: UInt8 = position < count ? buffer[position] : 0x0A
                if byte == 0x0A {
                    if position > lineStart {
                        let code = buffer[lineStart]
                        var shared = 0
                        if code >= 48 && code <= 57 { shared = Int(code - 48) }
                        else if code >= 97 && code <= 122 { shared = Int(code - 97) + 10 }
                        shared = min(shared, previous.count)
                        current.removeAll(keepingCapacity: true)
                        current.append(contentsOf: previous[0..<shared])
                        current.append(contentsOf: buffer[(lineStart + 1)..<position])
                        body(String(decoding: current, as: UTF8.self), current.count)
                        swap(&previous, &current)
                    }
                    lineStart = position + 1
                }
                position += 1
            }
        }
    }

    /// Zeilen einer einfachen Liste (für die Passphrasen-Wörter).
    static func lines(_ text: String) -> [String] {
        var result: [String] = []
        forEachLine(text) { _, fields in
            if let first = fields.first { result.append(first.word) }
        }
        return result
    }
}
