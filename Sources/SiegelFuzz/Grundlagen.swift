#if DEBUG
import CryptoKit
import Darwin
import Foundation
import Synchronization

// Gemeinsame Bausteine des Fuzzers: reproduzierbarer Zufall, Funde, Wächter gegen Absturz und Hänger,
// Ausgabe ohne Inhalte (SPEC §5: auch hier keine Geheimnisse ausgeben – nur Zähler, Codes und Prüfsummen).

/// SplitMix64: reproduzierbar aus einer protokollierten Saat.
struct Zufall: RandomNumberGenerator {
    private var zustand: UInt64

    init(saat: UInt64) { zustand = saat }

    mutating func next() -> UInt64 {
        zustand &+= 0x9E37_79B9_7F4A_7C15
        var z = zustand
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    /// 0 ..< n (n > 0).
    mutating func int(_ n: Int) -> Int { n <= 1 ? 0 : Int.random(in: 0..<n, using: &self) }
    mutating func int(_ r: ClosedRange<Int>) -> Int { Int.random(in: r, using: &self) }
    mutating func chance(_ p: Double) -> Bool { Double.random(in: 0..<1, using: &self) < p }
    mutating func byte() -> UInt8 { UInt8.random(in: 0...255, using: &self) }
    mutating func bytes(_ n: Int) -> [UInt8] { (0..<max(0, n)).map { _ in byte() } }
    mutating func pick<T>(_ a: [T]) -> T { a[int(a.count)] }
    /// Reproduzierbare UUID (statt `UUID()` aus dem System-Zufall).
    mutating func uuid() -> UUID {
        let b = bytes(16)
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }
}

/// Ein Fund: Absturz-freie Verletzung einer Invariante (manipulierte Datei öffnet, falscher Fehlertyp, …).
struct Fund: Error, CustomStringConvertible {
    let art: String
    let text: String
    init(_ art: String, _ text: String) {
        self.art = art
        self.text = text
    }
    var description: String { art + ": " + text }
}

/// Kurzform eines Fehlers für Statistik und Rückkopplung (nur feste Codes, nie Inhalte).
func fehlerCode(_ e: Error) -> String {
    let s = String(describing: e)
    // SiegelError-Fälle mit festen Codes; wrongRecoveryCode trägt Kit-Kennungen (nicht geheim, aber variabel).
    if s.hasPrefix("wrongRecoveryCode") { return "wrongRecoveryCode" }
    if s.hasPrefix("passwordTooWeak") { return "passwordTooWeak" }
    if s.hasPrefix("csvInvalid"), let r = s.range(of: "reason: ") {
        return "csvInvalid(" + s[r.upperBound...].trimmingCharacters(in: CharacterSet(charactersIn: "\")")) + ")"
    }
    // Zahlen-Nutzlast (unsupportedVersion(3), hidError(42), ctap(39)) zusammenfassen: sonst zählt jede Zahl als
    // „neues Ergebnis“ und verdrängt den Korpus.
    if let auf = s.firstIndex(of: "("), s.hasSuffix(")"), s[s.index(after: auf)..<s.index(before: s.endIndex)].allSatisfy(\.isNumber) {
        return String(s[..<auf]) + "(n)"
    }
    return s.count > 80 ? String(s.prefix(80)) : s
}

func sha256Hex(_ b: some Sequence<UInt8>) -> String {
    Array(SHA256.hash(data: Array(b))).map { String(format: "%02x", $0) }.joined()
}

func hexDekodieren(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    var it = s.makeIterator()
    while let a = it.next(), let b = it.next() { out.append(UInt8(String([a, b]), radix: 16) ?? 0) }
    return out
}

func jetztSekunden() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1e9 }

func meldung(_ s: String) {
    FileHandle.standardError.write(Data((s + "\n").utf8))
}

// MARK: - Wächter: aktuelle Eingabe sichern bei Absturz (Signal) und Hänger (Zeitlimit)

/// Höchste Eingabegrösse, die bei einem Absturz gesichert wird (grössere werden gekürzt gesichert).
let wachPufferGroesse = 8 << 20
nonisolated(unsafe) let wachPuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: wachPufferGroesse)
nonisolated(unsafe) var wachLaenge = 0
/// Vorbereitete C-Zeichenketten (im Signal-Handler wird nichts mehr angelegt).
nonisolated(unsafe) var wachPfadAbsturz: UnsafeMutablePointer<CChar>? = nil
nonisolated(unsafe) var wachPfadHaenger: UnsafeMutablePointer<CChar>? = nil
nonisolated(unsafe) var wachTextAbsturz: UnsafeMutablePointer<CChar>? = nil
nonisolated(unsafe) var wachTextHaenger: UnsafeMutablePointer<CChar>? = nil
let wachStart = Atomic<UInt64>(0)
let wachLimitNs = Atomic<UInt64>(10_000_000_000)

private func cString(_ s: String) -> UnsafeMutablePointer<CChar>? { strdup(s) }

/// Schreibt die aktuelle Eingabe nach `pfad` (nur async-signal-sichere Aufrufe).
private func wachSichern(_ pfad: UnsafeMutablePointer<CChar>?, _ text: UnsafeMutablePointer<CChar>?) {
    if let pfad {
        let fd = open(pfad, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        if fd >= 0 {
            var off = 0
            while off < wachLaenge {
                let n = write(fd, wachPuffer + off, wachLaenge - off)
                if n <= 0 { break }
                off += n
            }
            close(fd)
        }
    }
    if let text { _ = write(2, text, strlen(text)) }
}

private func absturzHandler(_ sig: Int32) {
    wachSichern(wachPfadAbsturz, wachTextAbsturz)
    signal(sig, SIG_DFL)
    raise(sig)
}

enum Waechter {
    /// Pfade für gesicherte Eingaben setzen, Signal-Handler und Hänger-Wächter starten.
    static func einrichten(fundOrdner: URL, ziel: String) {
        let pid = getpid()
        let a = fundOrdner.appendingPathComponent("absturz-\(ziel)-\(pid).bin").path
        let h = fundOrdner.appendingPathComponent("haenger-\(ziel)-\(pid).bin").path
        wachPfadAbsturz = cString(a)
        wachPfadHaenger = cString(h)
        wachTextAbsturz = cString("\nSiegelFuzz: ABSTURZ im Ziel \(ziel), Eingabe gesichert: \(a)\n")
        wachTextHaenger = cString("\nSiegelFuzz: HÄNGER im Ziel \(ziel) (Zeitlimit), Eingabe gesichert: \(h)\n")
        // Swift-Laufzeitfehler (brk → SIGTRAP), abort (auch nach ASan-Bericht: abort_on_error), SIGILL/SIGFPE.
        for sig in [SIGTRAP, SIGABRT, SIGILL, SIGFPE] { signal(sig, absturzHandler) }
        // SEGV/BUS nur ohne ASan (sonst berichtet ASan selbst und endet mit abort → SIGABRT oben).
        if dlsym(UnsafeMutableRawPointer(bitPattern: -2), "__asan_init") == nil {
            for sig in [SIGSEGV, SIGBUS] { signal(sig, absturzHandler) }
        }
        Thread.detachNewThread {
            while true {
                usleep(50_000)
                let s = wachStart.load(ordering: .acquiring)
                guard s != 0 else { continue }
                let jetzt = DispatchTime.now().uptimeNanoseconds
                if jetzt > s, jetzt - s > wachLimitNs.load(ordering: .relaxed) {
                    wachSichern(wachPfadHaenger, wachTextHaenger)
                    _exit(77)
                }
            }
        }
    }

    static var mitASan: Bool { dlsym(UnsafeMutableRawPointer(bitPattern: -2), "__asan_init") != nil }

    /// Eingabe für den Fall eines Absturzes merken und die Uhr starten.
    static func beginne(_ eingabe: [UInt8], limit: Double) {
        let n = min(eingabe.count, wachPufferGroesse)
        eingabe.withUnsafeBufferPointer { b in
            if let p = b.baseAddress { wachPuffer.update(from: p, count: n) }
        }
        wachLaenge = n
        wachLimitNs.store(UInt64(limit * 1e9), ordering: .relaxed)
        wachStart.store(DispatchTime.now().uptimeNanoseconds, ordering: .releasing)
    }

    static func ende() { wachStart.store(0, ordering: .releasing) }
}

// MARK: - Allgemeiner Byte-Mutator

enum Mutator {
    static let interessant8: [UInt8] = [0x00, 0x01, 0x7F, 0x80, 0xFF, 0x18, 0x19, 0x1A, 0x1B, 0x1F, 0x22, 0x2C, 0x0A,
                                       0x0D, 0x3F, 0x2D, 0x3A, 0x25, 0x3D, 0xF6, 0xF5, 0xF4, 0x9F, 0xBF, 0xC0, 0xEF]

    /// 1–n gestapelte allgemeine Mutationen (Bit kippen, Byte setzen, einfügen, löschen, Blöcke).
    static func bytes(_ input: [UInt8], _ z: inout Zufall, schritte: Int? = nil, maxLaenge: Int = 1 << 20) -> [UInt8] {
        var b = input
        for _ in 0..<(schritte ?? z.int(1...4)) {
            switch z.int(11) {
            case 0 where !b.isEmpty:
                b[z.int(b.count)] ^= UInt8(1) << UInt8(z.int(8))
            case 1 where !b.isEmpty:
                b[z.int(b.count)] = z.byte()
            case 2 where !b.isEmpty:
                b[z.int(b.count)] = z.pick(interessant8)
            case 3 where !b.isEmpty:
                b.remove(at: z.int(b.count))
            case 4:
                b.insert(z.chance(0.5) ? z.byte() : z.pick(interessant8), at: z.int(b.count + 1))
            case 5 where !b.isEmpty:
                // Block löschen
                let a = z.int(b.count)
                let n = min(b.count - a, z.int(1...64))
                b.removeSubrange(a..<(a + n))
            case 6 where !b.isEmpty:
                // Block verdoppeln
                let a = z.int(b.count)
                let n = min(b.count - a, z.int(1...128))
                let block = Array(b[a..<(a + n)])
                b.insert(contentsOf: block, at: z.int(b.count + 1))
            case 7 where b.count > 1:
                // zwei Blöcke tauschen (gleiche Länge)
                let n = z.int(1...max(1, min(32, b.count / 2)))
                let x = z.int(b.count - n + 1)
                let y = z.int(b.count - n + 1)
                for i in 0..<n { b.swapAt(x + i, y + i) }
            case 8 where !b.isEmpty:
                b = Array(b.prefix(z.int(b.count)))
            case 9:
                b += z.bytes(z.int(1...32))
            default:
                // Ganzzahl-Grenzwert an zufälliger Stelle (1, 2, 4 oder 8 Byte, LE oder BE)
                guard !b.isEmpty else { b = z.bytes(z.int(1...16)); break }
                let breite = z.pick([1, 2, 4, 8])
                let werte: [UInt64] = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x1_0000, 0x7FFF_FFFF,
                                       0xFFFF_FFFF, UInt64.max, UInt64.max / 2]
                var v = z.pick(werte)
                if z.chance(0.3) { v = v &+ UInt64(bitPattern: Int64(z.int(-2...2))) }
                let a = z.int(b.count)
                let le = z.chance(0.5)
                for i in 0..<breite where a + i < b.count {
                    let shift = le ? 8 * i : 8 * (breite - 1 - i)
                    b[a + i] = UInt8(truncatingIfNeeded: v >> UInt64(shift))
                }
            }
        }
        if b.count > maxLaenge { b = Array(b.prefix(maxLaenge)) }
        return b
    }

    /// Kreuzung: Anfang von a, Ende von b.
    static func kreuzen(_ a: [UInt8], _ b: [UInt8], _ z: inout Zufall) -> [UInt8] {
        let x = z.int(a.count + 1)
        let y = z.int(b.count + 1)
        return Array(a.prefix(x)) + Array(b.suffix(b.count - y))
    }
}

// MARK: - Zeichen für Code-Eingaben

enum Zeichen {
    /// Leerraum-Varianten (Unicode White_Space), die der Kern ignorieren muss.
    static let leerraum: [String] = [" ", "\t", "\n", "\r\n", "\u{00A0}", "\u{2003}", "\u{3000}", "\u{2028}", "\u{205F}",
                                     "\u{180E}", "\u{FEFF}", "\u{200B}"]
    /// Störende Zeichen (ungültig oder trickreich).
    static let stoerend: [String] = ["U", "u", "?", "*", "#", "é", "ß", "ﬁ", "K", "ı", "ſ", "Ｏ", "０", "\u{0301}", "\u{0000}",
                                     "😀", "\u{202E}", "--", ":", "SIEGELKARTE1:", "\u{FFFD}", "\u{10FFFF}"]

    /// Mutiert eine Zeichenkette auf Ebene der Unicode-Skalare.
    static func mutieren(_ s: String, _ z: inout Zufall) -> String {
        var a = Array(s.unicodeScalars).map { String($0) }
        for _ in 0..<z.int(1...3) {
            switch z.int(8) {
            case 0 where !a.isEmpty: a.remove(at: z.int(a.count))
            case 1: a.insert(z.pick(leerraum), at: z.int(a.count + 1))
            case 2: a.insert(z.pick(stoerend), at: z.int(a.count + 1))
            case 3 where !a.isEmpty: a[z.int(a.count)] = z.pick(stoerend)
            case 4 where a.count > 1:
                let i = z.int(a.count - 1)
                a.swapAt(i, i + 1)
            case 5: a = a.map { z.chance(0.5) ? $0.lowercased() : $0 }
            case 6 where !a.isEmpty:
                let i = z.int(a.count)
                a.insert(contentsOf: Array(repeating: a[i], count: z.int(1...80)), at: i)
            default:
                let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZOIL").map(String.init)
                if !a.isEmpty { a[z.int(a.count)] = z.pick(alphabet) }
            }
        }
        return a.joined()
    }
}
#endif
