// Normalisierung, wie Swift auf dem Mac sie rechnet (SPEC §1.1, SPEC-WINDOWS W7; Befunde krypto-1, krypto-2, krypto-4):
//
//   SiegelStaerkeExport nfc <ausgabe>
//       Tabelle für den C#-Kern (windows/src/Siegel.Werkzeuge/Unicode/swift_nfc.txt.gz), zwei Lesarten:
//       - Foundation `precomposedStringWithCanonicalMapping` (Master-Passwort, reuseTag): gemessen, nicht aus der
//         Unicode-Norm abgeleitet. Foundation kennt Unicode 16 nur zum Teil und hat eigene Hangul-Regeln.
//       - Swift-`String` (`==`, `Set`, `Dictionary`): kanonische Gleichheit der Standardbibliothek.
//       Dazu das Unicode-Alter ≤ 15.0 je Skalar (Master-Passwort-Regel, SPEC §1.6).
//   SiegelStaerkeExport nfc-korpus <korpus> <ausgabe>
//       Je Zeile (Base64): Base64(NFC wie Foundation) \t Base64(PasswordNormalizer.normalize).
//   SiegelStaerkeExport gleich <korpus> <ausgabe>
//       Je Zeile zwei Felder (Base64): 1, wenn Swift sie für gleich hält (`==`), sonst 0.

#if DEBUG
import Foundation
@testable import SiegelCore

enum Norm {
    static func text(_ werte: [UInt32]) -> String {
        var view = String.UnicodeScalarView()
        for w in werte {
            guard let s = Unicode.Scalar(w) else { Ausgabe.fehler("kein Skalar: \(Ausgabe.hex(w))") }
            view.append(s)
        }
        return String(view)
    }

    static func skalare(_ text: String) -> [UInt32] { text.unicodeScalars.map(\.value) }
    static func nfd(_ w: [UInt32]) -> [UInt32] { skalare(text(w).decomposedStringWithCanonicalMapping) }
    static func nfc(_ w: [UInt32]) -> [UInt32] { skalare(text(w).precomposedStringWithCanonicalMapping) }
    /// NFC der Standardbibliothek (die Form, die Swift-String vergleicht; unterstrichene, aber öffentliche API).
    static func nfcSwift(_ w: [UInt32]) -> [UInt32] { skalare(String(decoding: text(w)._nfcCodeUnits, as: UTF8.self)) }

    static func istSilbe(_ w: UInt32) -> Bool { (0xAC00...0xD7A3).contains(w) }

    /// Hangul-Silbe nach der Norm (Unicode §3.12).
    static func silbe(_ w: UInt32) -> [UInt32] {
        let i = w - 0xAC00
        let t = 0x11A7 + i % 28
        let lv: [UInt32] = [0x1100 + i / 588, 0x1161 + (i % 588) / 28]
        return t == 0x11A7 ? lv : lv + [t]
    }

    /// Alle Skalare (ohne Surrogate).
    static let alle: [UInt32] = Array(0...0xD7FF) + Array(0xE000...0x10FFFF)

    static func klasse(_ w: UInt32) -> Int { Int(Unicode.Scalar(w)!.properties.canonicalCombiningClass.rawValue) }

    /// Unicode-Alter ≤ 15.0 (vergeben in Unicode 15.0 oder früher; Nichtzeichen und private Zeichen zählen dazu).
    static func bis15(_ w: UInt32) -> Bool {
        guard let a = Unicode.Scalar(w)!.properties.age else { return false }
        return a.major < 15 || (a.major == 15 && a.minor == 0)
    }

    static func vergeben(_ w: UInt32) -> Bool { Unicode.Scalar(w)!.properties.age != nil }
}

/// Kombinationsklasse, wie Foundation sie beim Ordnen anwendet: gemessen an Vergleichszeichen je Klasse
/// (Foundation ordnet `a x r` um, wenn Klasse(x) > Klasse(r) > 0).
struct KlassenSonde {
    let referenzen: [(klasse: Int, skalar: UInt32)]

    init() {
        var bekannt: [Int: UInt32] = [:]
        for w in Norm.alle {
            let k = Norm.klasse(w)
            guard k != 0, bekannt[k] == nil, let a = Unicode.Scalar(w)!.properties.age, a.major <= 14,
                  Norm.nfd([w]) == [w] else { continue }
            bekannt[k] = w
        }
        referenzen = bekannt.map { (klasse: $0.key, skalar: $0.value) }.sorted { $0.klasse < $1.klasse }
        for (i, x) in referenzen.enumerated() {
            for y in referenzen[(i + 1)...] where !vertauscht(y.skalar, x.skalar) || vertauscht(x.skalar, y.skalar) {
                Ausgabe.fehler("Vergleichszeichen \(Ausgabe.hex(x.skalar))/\(Ausgabe.hex(y.skalar)) falsch geordnet")
            }
        }
    }

    func vertauscht(_ a: UInt32, _ b: UInt32) -> Bool { Norm.nfd([0x61, a, b]) != [0x61, a, b] }

    func klasse(_ w: UInt32, vermutet: Int) -> Int {
        // Starter: weder hinter U+0345 (240) noch vor U+0334 (1) umgeordnet
        if !vertauscht(0x0345, w) && !vertauscht(w, 0x0334) { return 0 }
        func gleich(_ r: UInt32) -> Bool { !vertauscht(w, r) && !vertauscht(r, w) }
        if let r = referenzen.first(where: { $0.klasse == vermutet }), gleich(r.skalar) { return vermutet }
        for r in referenzen where gleich(r.skalar) { return r.klasse }
        Ausgabe.fehler("Kombinationsklasse nicht bestimmbar: \(Ausgabe.hex(w))")
    }
}

func nfcTabelle(_ argumente: [String]) {
    guard argumente.count == 1 else { Ausgabe.fehler("nfc <ausgabe>") }
    let sonde = KlassenSonde()
    var zerlegung: [UInt32: [UInt32]] = [:]       // Foundation-NFD je Skalar (ohne Hangul-Silben)
    var opak = Set<UInt32>()                      // NFD zerlegt, NFC lässt stehen und setzt die Zerlegung nicht zusammen
    var klasseF: [UInt32: Int] = [:]
    var klasseS: [UInt32: Int] = [:]
    var alt: [(UInt32, UInt32)] = []
    var laufStart: UInt32? = nil
    var vorher: UInt32 = 0

    for w in Norm.alle {
        if Norm.bis15(w) {
            if laufStart == nil || vorher + 1 != w {
                if let s = laufStart { alt.append((s, vorher)) }
                laufStart = w
            }
            vorher = w
        }
        if Norm.istSilbe(w) {
            guard Norm.nfd([w]) == Norm.silbe(w), Norm.nfc([w]) == [w] else {
                Ausgabe.fehler("Hangul-Silbe anders als erwartet: \(Ausgabe.hex(w))")
            }
            continue
        }
        let d = Norm.nfd([w])
        if d != [w] {
            zerlegung[w] = d
            if Norm.nfc([w]) == [w] && Norm.nfc(d) != [w] { opak.insert(w) }
            // Swift-String hält Skalar und Zerlegung für gleich
            guard Norm.text([w]) == Norm.text(d) else { Ausgabe.fehler("Swift-String ≠ NFD: \(Ausgabe.hex(w))") }
        } else {
            let kS = Norm.klasse(w)
            let kF = sonde.klasse(w, vermutet: kS)
            if kF != 0 { klasseF[w] = kF }
            if kS != kF { klasseS[w] = kS }
        }
    }
    if let s = laufStart { alt.append((s, vorher)) }

    // Paare der Zusammensetzung (Foundation): Schritt für Schritt entlang der Zerlegung jedes stabilen Zeichens.
    var paare: [UInt64: UInt32] = [:]
    for (w, d) in zerlegung.sorted(by: { $0.key < $1.key }) where !opak.contains(w) && Norm.nfc([w]) == [w] {
        var aktuell = d[0]
        for j in 1..<d.count {
            let p = Norm.nfc(Array(d[0...j]))
            guard p.count == 1 else { Ausgabe.fehler("Zusammensetzung nicht schrittweise: \(Ausgabe.hex(w))") }
            let schluessel = UInt64(aktuell) << 32 | UInt64(d[j])
            if let bisher = paare[schluessel], bisher != p[0] { Ausgabe.fehler("Paar widersprüchlich: \(Ausgabe.hex(w))") }
            paare[schluessel] = p[0]
            aktuell = p[0]
        }
        guard aktuell == w else { Ausgabe.fehler("Zusammensetzung endet falsch: \(Ausgabe.hex(w))") }
    }

    // Träge Zeichen: Foundation zerlegt sie in NFC nicht und setzt sie aus der Eingabe nicht weiter zusammen (gemessen:
    // U+113C5, U+16121 … aus Unicode 16), obwohl NFD sie zerlegt. Erkannt an Proben, bei denen das Zeichen und seine
    // Zerlegung verschieden ausgehen: dahinter ein Kombinationszeichen, davor ein Partner des ersten Glieds, dahinter
    // ein Partner des Zeichens selbst.
    var zweiteZu: [UInt32: [UInt32]] = [:]        // erstes Glied → zweite Glieder
    var ersteZu: [UInt32: [UInt32]] = [:]         // zweites Glied → erste Glieder
    for s in paare.keys.sorted() {
        let (a, b) = (UInt32(s >> 32), UInt32(s & 0xFFFF_FFFF))
        zweiteZu[a, default: []].append(b)
        ersteZu[b, default: []].append(a)
    }
    for (w, d) in zerlegung.sorted(by: { $0.key < $1.key }) where !opak.contains(w) {
        var proben: [([UInt32], [UInt32])] = []
        for m: UInt32 in [0x0334, 0x0345, 0x0301, 0x0323, 0x0F71] { proben.append(([w, m], d + [m])) }
        for p in ersteZu[d[0], default: []] { proben.append(([p, w], [p] + d)) }
        for q in zweiteZu[w, default: []] { proben.append(([w, q], d + [q])) }
        if proben.contains(where: { Norm.nfc($0.0) != Norm.nfc($0.1) }) { opak.insert(w) }
    }
    // Träge/opake Zeichen sind in Foundation Starter (geprüft: Klasse 0 in der Standardbibliothek, keine Umordnung).
    for w in opak where Norm.klasse(w) != 0 || Norm.nfc([0x61, 0x0345, w]) != [0x61, 0x0345, w] {
        Ausgabe.fehler("träges Zeichen ist kein Starter: \(Ausgabe.hex(w))")
    }
    // Eigene Klasse zerlegbarer Zeichen (Standardbibliothek): Zeichen mit Klasse 0 beginnen beim Ordnen einen neuen
    // Abschnitt – auch wenn ihre Zerlegung mit einem Nicht-Starter beginnt (gemessen: U+0F73, U+0F75, U+0F81).
    var eigeneKlasse: [UInt32: Int] = [:]
    for w in zerlegung.keys.sorted() where Norm.klasse(w) != 0 { eigeneKlasse[w] = Norm.klasse(w) }

    // Swift-String: Zerlegungen, die Foundation nicht kennt (neuere Zeichen), über Gleichheit gesucht.
    let neu = Norm.alle.filter { Norm.vergeben($0) && !Norm.bis15($0) && !Norm.istSilbe($0) }
    var kandidaten: [Int: [UInt32]] = [:]
    for c in neu where zerlegung[c] == nil { kandidaten[Norm.text([c]).hashValue, default: []].append(c) }
    var stufe: [UInt32: [UInt32]] = [:]           // c ≡ Folge (eine Stufe)
    func pruefe(_ folge: [UInt32]) {
        let t = Norm.text(folge)
        guard let cs = kandidaten[t.hashValue] else { return }
        for c in cs where folge != [c] && stufe[c] == nil && Norm.text([c]) == t { stufe[c] = folge }
    }
    for a in Norm.alle where Norm.vergeben(a) { pruefe([a]) }
    var zweite = Set(neu)
    for w in Norm.alle where Norm.klasse(w) != 0 { zweite.insert(w) }
    for s in paare.keys { zweite.insert(UInt32(s & 0xFFFF_FFFF)) }
    let zweiteListe = zweite.sorted()
    for a in neu { for b in zweiteListe { pruefe([a, b]) } }
    let neueMarken = neu.filter {
        let g = Unicode.Scalar($0)!.properties.generalCategory
        return g == .nonspacingMark || g == .spacingMark || g == .enclosingMark || Norm.klasse($0) != 0
    }
    for a in Norm.alle where Norm.vergeben(a) && Norm.bis15(a) && Norm.klasse(a) == 0 {
        for b in neueMarken { pruefe([a, b]) }
    }
    func klasseSwift(_ w: UInt32) -> Int { Norm.klasse(w) }
    func zerlegtSwift(_ w: UInt32) -> [UInt32] {
        if Norm.istSilbe(w) { return Norm.silbe(w) }
        if let d = zerlegung[w] { return d }
        if let f = stufe[w] { return f.flatMap(zerlegtSwift) }
        return [w]
    }
    func geordnetSwift(_ w: UInt32) -> [UInt32] {
        var d = zerlegtSwift(w)
        // kanonisch ordnen (Klassen der Standardbibliothek)
        for i in 1..<max(d.count, 1) {
            let k = klasseSwift(d[i])
            guard k != 0 else { continue }
            var j = i
            while j > 0, klasseSwift(d[j - 1]) > k { d.swapAt(j - 1, j); j -= 1 }
        }
        return d
    }
    var zusatz: [UInt32: [UInt32]] = [:]
    for c in stufe.keys.sorted() {
        let d = geordnetSwift(c)
        guard Norm.text([c]) == Norm.text(d) else { Ausgabe.fehler("Swift-Zerlegung falsch: \(Ausgabe.hex(c))") }
        zusatz[c] = d
    }
    // Paare der Standardbibliothek (ihre NFC ist die Form, die Swift-String vergleicht), wie oben Schritt für Schritt.
    var paareSwift: [UInt64: UInt32] = [:]
    for w in Set(zerlegung.keys).union(zusatz.keys).sorted() where Norm.nfcSwift([w]) == [w] {
        let d = geordnetSwift(w)
        var aktuell = d[0]
        for j in 1..<d.count {
            let p = Norm.nfcSwift(Array(d[0...j]))
            guard p.count == 1 else { Ausgabe.fehler("Swift-Zusammensetzung nicht schrittweise: \(Ausgabe.hex(w))") }
            paareSwift[UInt64(aktuell) << 32 | UInt64(d[j])] = p[0]
            aktuell = p[0]
        }
        guard aktuell == w else { Ausgabe.fehler("Swift-Zusammensetzung endet falsch: \(Ausgabe.hex(w))") }
    }

    let h = Ausgabe.hex
    var zeilen = [
        "# SiegelStaerkeExport nfc: Normalisierung, wie Swift auf dem Mac sie rechnet (Format 1)",
        "# D <skalar> <zerlegung…>   Foundation precomposedStringWithCanonicalMapping: kanonische Zerlegung",
        "# O <skalar> <zerlegung…>   wie D, aber träge: NFC zerlegt den Skalar nicht und setzt ihn nicht weiter zusammen",
        "# C <skalar> <klasse>       Foundation: Kombinationsklasse ≠ 0 (gemessen an Vergleichszeichen)",
        "# K <skalar> <klasse>       eigene Klasse ≠ 0 eines zerlegbaren Skalars (sonst beginnt er einen Ordnungsabschnitt)",
        "# P <erster> <zweiter> <ergebnis>   Foundation: Paar der Zusammensetzung (ohne Hangul)",
        "# SD <skalar> <zerlegung…>  Swift-String (==, Set, Dictionary): zusätzliche kanonische Zerlegung",
        "# SC <skalar> <klasse>      Swift-String: Kombinationsklasse, wo sie von Foundation abweicht",
        "# SP <erster> <zweiter> <ergebnis>   Swift-String: Paar, das Foundation nicht (so) hat; SX <erster> <zweiter>: Paar nur in Foundation",
        "# A <von> <bis>             Unicode-Alter ≤ 15.0 (Master-Passwort-Regel, SPEC §1.6)",
        "# Hangul-Silben: Swift-String nach der Norm; Foundation zerlegt sie in NFC nicht (C#: SwiftNormalisierung)",
        "# zerlegungen=\(zerlegung.count) traege=\(opak.count) klassen=\(klasseF.count) eigeneKlassen=\(eigeneKlasse.count) "
            + "paare=\(paare.count) swiftZerlegungen=\(zusatz.count) swiftKlassen=\(klasseS.count) swiftPaare=\(paareSwift.count) "
            + "alterBereiche=\(alt.count)",
    ]
    for (w, d) in zerlegung.sorted(by: { $0.key < $1.key }) {
        zeilen.append((opak.contains(w) ? "O " : "D ") + h(w) + " " + d.map(h).joined(separator: " "))
    }
    for (w, k) in klasseF.sorted(by: { $0.key < $1.key }) { zeilen.append("C \(h(w)) \(k)") }
    for (w, k) in eigeneKlasse.sorted(by: { $0.key < $1.key }) { zeilen.append("K \(h(w)) \(k)") }
    for (s, c) in paare.sorted(by: { $0.key < $1.key }) {
        zeilen.append("P \(h(UInt32(s >> 32))) \(h(UInt32(s & 0xFFFF_FFFF))) \(h(c))")
    }
    for (w, d) in zusatz.sorted(by: { $0.key < $1.key }) { zeilen.append("SD \(h(w)) " + d.map(h).joined(separator: " ")) }
    for (w, k) in klasseS.sorted(by: { $0.key < $1.key }) { zeilen.append("SC \(h(w)) \(k)") }
    for (s, c) in paareSwift.sorted(by: { $0.key < $1.key }) where paare[s] != c {
        zeilen.append("SP \(h(UInt32(s >> 32))) \(h(UInt32(s & 0xFFFF_FFFF))) \(h(c))")
    }
    for s in paare.keys.sorted() where paareSwift[s] == nil {
        zeilen.append("SX \(h(UInt32(s >> 32))) \(h(UInt32(s & 0xFFFF_FFFF)))")
    }
    for (von, bis) in alt { zeilen.append("A \(h(von)) \(h(bis))") }
    Ausgabe.schreiben(zeilen, nach: argumente[0])
}

func nfcKorpus(_ argumente: [String]) {
    guard argumente.count == 2 else { Ausgabe.fehler("nfc-korpus <korpus> <ausgabe>") }
    let faelle = Ausgabe.datensaetze(argumente[0])
    var zeilen = ["# SiegelStaerkeExport nfc-korpus: Base64(precomposedStringWithCanonicalMapping) \\t "
                  + "Base64(PasswordNormalizer.normalize)", "# faelle=\(faelle.count)"]
    for felder in faelle {
        let nfc = felder[0].precomposedStringWithCanonicalMapping
        let pw = PasswordNormalizer.normalize(felder[0])
        zeilen.append(Data(nfc.utf8).base64EncodedString() + "\t" + Data(pw.utf8).base64EncodedString())
    }
    Ausgabe.schreiben(zeilen, nach: argumente[1])
}

func gleich(_ argumente: [String]) {
    guard argumente.count == 2 else { Ausgabe.fehler("gleich <korpus> <ausgabe>") }
    let faelle = Ausgabe.datensaetze(argumente[0])
    var zeilen = ["# SiegelStaerkeExport gleich: 1 = Swift-String ==", "# faelle=\(faelle.count)"]
    for felder in faelle {
        guard felder.count == 2 else { Ausgabe.fehler("gleich: zwei Felder je Zeile") }
        let gleich = felder[0] == felder[1]
        guard gleich == (Set([felder[0]]).contains(felder[1])) else { Ausgabe.fehler("gleich: Hash ≠ ==") }
        zeilen.append(gleich ? "1" : "0")
    }
    Ausgabe.schreiben(zeilen, nach: argumente[1])
}
#endif
