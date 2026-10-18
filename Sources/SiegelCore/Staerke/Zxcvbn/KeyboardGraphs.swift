import Foundation

// Adjazenzgraphen der Tastaturen für Tastaturfolgen (wie zxcvbn build_keyboard_adjacency_graphs.py,
// selbst aufgebaut). Jede Taste ist ein Token aus "unverschoben verschoben" (z. B. "1+"); die Zeilen sind
// wie auf der Tastatur je um ein Zeichen eingerückt (schräge Anordnung). Ziffernblöcke stehen gerade.

struct KeyboardGraph: Sendable {
    let name: String
    let isKeypad: Bool
    /// Nachbartasten je Zeichen in fester Richtungsreihenfolge (nil = keine Taste in dieser Richtung).
    let neighbors: [Character: [[Character]?]]
    /// Zeichen, die nur mit Umschalttaste entstehen (zweites Zeichen eines Tokens).
    let shifted: Set<Character>
    /// Anzahl Startpositionen (Zeichen im Graphen) und mittlerer Grad (Nachbarn je Zeichen).
    let startingPositions: Double
    let averageDegree: Double
    /// Für Tests: Tokens, deren Spalte nicht auf das Raster fällt (muss leer sein).
    let misalignedTokens: [String]
}

enum KeyboardGraphs {
    /// QWERTY (US), wie in zxcvbn.
    static let qwertyLayout = """
    `~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) -_ =+
        qQ wW eE rR tT yY uU iI oO pP [{ ]} \\|
         aA sS dD fF gG hH jJ kK lL ;: '"
          zZ xX cC vV bB nN mM ,< .> /?
    """

    /// QWERTZ Schweiz (ISO, mit Taste <> links von Y).
    static let qwertzCHLayout = """
    §° 1+ 2" 3* 4ç 5% 6& 7/ 8( 9) 0= '? ^`
        qQ wW eE rR tT zZ uU iI oO pP üè ¨!
         aA sS dD fF gG hH jJ kK lL öé äà $£
       <> yY xX cC vV bB nN mM ,; .: -_
    """

    /// Ziffernblock (PC) und Ziffernblock (Mac).
    static let keypadLayout = """
      / * -
    7 8 9 +
    4 5 6
    1 2 3
      0 .
    """

    static let macKeypadLayout = """
      = / *
    7 8 9 -
    4 5 6 +
    1 2 3
      0 .
    """

    static let all: [KeyboardGraph] = [
        build(name: "qwerty", layout: qwertyLayout, slanted: true),
        build(name: "qwertz_ch", layout: qwertzCHLayout, slanted: true),
        build(name: "keypad", layout: keypadLayout, slanted: false),
        build(name: "mac_keypad", layout: macKeypadLayout, slanted: false),
    ]

    private struct Position: Hashable {
        let x: Int
        let y: Int
    }

    static func build(name: String, layout: String, slanted: Bool) -> KeyboardGraph {
        var table: [Position: [Character]] = [:]
        var misaligned: [String] = []
        var tokenSize = 0
        let lines = layout.split(separator: "\n", omittingEmptySubsequences: false)
        for (row, line) in lines.enumerated() {
            let y = row + 1                       // zxcvbn zählt ab 1 (erste Zeile ist leer)
            let slant = slanted ? y - 1 : 0
            let chars = Array(line)
            var col = 0
            while col < chars.count {
                if chars[col] == " " { col += 1; continue }
                var end = col
                while end < chars.count, chars[end] != " " { end += 1 }
                let token = Array(chars[col..<end])
                if tokenSize == 0 { tokenSize = token.count }
                let unit = tokenSize + 1
                let offset = col - slant
                if offset < 0 || offset % unit != 0 || token.count != tokenSize {
                    misaligned.append(String(token))
                } else {
                    table[Position(x: offset / unit, y: y)] = token
                }
                col = end
            }
        }

        func adjacent(_ p: Position) -> [Position] {
            let (x, y) = (p.x, p.y)
            if slanted {
                return [Position(x: x - 1, y: y), Position(x: x, y: y - 1), Position(x: x + 1, y: y - 1),
                        Position(x: x + 1, y: y), Position(x: x, y: y + 1), Position(x: x - 1, y: y + 1)]
            }
            return [Position(x: x - 1, y: y), Position(x: x - 1, y: y - 1), Position(x: x, y: y - 1),
                    Position(x: x + 1, y: y - 1), Position(x: x + 1, y: y), Position(x: x + 1, y: y + 1),
                    Position(x: x, y: y + 1), Position(x: x - 1, y: y + 1)]
        }

        var neighbors: [Character: [[Character]?]] = [:]
        var shifted = Set<Character>()
        for (pos, token) in table {
            let adj = adjacent(pos).map { table[$0] }
            for (index, ch) in token.enumerated() {
                neighbors[ch] = adj
                if !slanted { continue }
                if index == 1 { shifted.insert(ch) }
            }
        }
        var degreeSum = 0
        for (_, adj) in neighbors {
            degreeSum += adj.reduce(0) { $0 + ($1 == nil ? 0 : 1) }
        }
        let count = max(1, neighbors.count)
        return KeyboardGraph(name: name, isKeypad: !slanted, neighbors: neighbors, shifted: shifted,
                             startingPositions: Double(neighbors.count),
                             averageDegree: Double(degreeSum) / Double(count),
                             misalignedTokens: misaligned)
    }
}
