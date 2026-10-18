// SiegelStaerkeExport (SPEC-WINDOWS W7): gibt die Stärke-Schätzung der Swift-Referenz für einen festen Korpus aus,
// damit die Windows-Version (C#) bit-genau dagegen prüfen kann, und exportiert die Unicode-Eigenschaften, mit denen
// Swift arbeitet (Character-Eigenschaften, Gross-/Kleinschreibung, Graphem-Grenzen), als Tabelle für C#.
//
// Nur Debug-Bau (`@testable` für Bezugsjahr und interne Listen). Aufruf über windows/skripte/*.py:
//   SiegelStaerkeExport bewerten <korpus> <ausgabe> [--jahr 2026]
//       Korpus: eine Zeile je Fall, Felder durch Tabulator getrennt, je Base64 (UTF-8): Passwort, danach
//       Benutzereingaben. Zeilen mit '#' am Anfang sind Kommentare. Ausgabe je Fall:
//       bits (17 signifikante Stellen) \t Stufe (0–4) \t Zeichenzahl (Graphem-Cluster) \t Regel erfüllt (0/1)
//   SiegelStaerkeExport graphem <korpus> <ausgabe>
//       Je Zeile (Base64) die Längen der Character in UTF-16-Einheiten, durch Komma getrennt.
//   SiegelStaerkeExport unicode <ausgabe>
//       Tabelle aller Skalare: Character-Eigenschaften, allgemeine Kategorie, Graphem-Klasse (aus Swifts eigenem
//       Verhalten abgeleitet), Kleinschreibung/Grossschreibung (volle Abbildung je Skalar).
//   SiegelStaerkeExport kennzahlen <ausgabe>
//       Prüfsummen der Listen (wie Swift sie sieht) und Kennzahlen des Wörterbuchs und der Tastaturgraphen.
//   SiegelStaerkeExport autofill <korpus> <ausgabe>    Gegenprobe AutofillMatcher (Felder: Eintrag, Website) → 0/1
//   SiegelStaerkeExport titel <korpus> <ausgabe>       Gegenprobe CSV-Titel aus der URL → Base64(Titel)
//   SiegelStaerkeExport nfc | nfc-korpus | gleich …     Normalisierung wie Foundation und Swift-String (Normalisierung.swift)
//
// Ausgaben enthalten nie Passwörter, nur Zahlen (der Korpus ist erfundenes Testmaterial).

#if DEBUG
import CryptoKit
import Foundation
@testable import SiegelCore

enum Ausgabe {
    static func fehler(_ text: String) -> Never {
        FileHandle.standardError.write(Data((text + "\n").utf8))
        exit(2)
    }

    static func schreiben(_ zeilen: [String], nach pfad: String) {
        let text = zeilen.joined(separator: "\n") + "\n"
        do {
            try Data(text.utf8).write(to: URL(fileURLWithPath: pfad), options: .atomic)
        } catch {
            fehler("Schreiben fehlgeschlagen: \(pfad)")
        }
    }

    static func lesen(_ pfad: String) -> String {
        guard let data = FileManager.default.contents(atPath: pfad) else { fehler("Lesen fehlgeschlagen: \(pfad)") }
        return String(decoding: data, as: UTF8.self)
    }

    /// Datensätze einer Korpus-Datei (ohne Kommentare); die letzte Zeile endet mit einem Umbruch.
    static func datensaetze(_ pfad: String) -> [[String]] {
        var zeilen = lesen(pfad).components(separatedBy: "\n")
        if zeilen.last == "" { zeilen.removeLast() }
        var ergebnis: [[String]] = []
        for (nummer, zeile) in zeilen.enumerated() where !zeile.hasPrefix("#") {
            var felder: [String] = []
            for feld in zeile.components(separatedBy: "\t") {
                // String(validating:as:) statt String(data:encoding:): Foundation entfernt sonst ein führendes BOM.
                guard let data = Data(base64Encoded: feld), let text = String(validating: data, as: UTF8.self) else {
                    fehler("Zeile \(nummer + 1): kein Base64/UTF-8")
                }
                felder.append(text)
            }
            ergebnis.append(felder)
        }
        return ergebnis
    }

    /// 17 signifikante Stellen (rundet sicher zurück auf denselben Double).
    static func zahl(_ wert: Double) -> String { String(format: "%.17g", wert) }

    static func hex(_ wert: UInt32) -> String { String(wert, radix: 16, uppercase: true) }
}

// MARK: - bewerten

func bewerten(_ argumente: [String]) {
    guard argumente.count >= 2 else { Ausgabe.fehler("bewerten <korpus> <ausgabe> [--jahr N]") }
    var jahr = 2026
    if let index = argumente.firstIndex(of: "--jahr"), index + 1 < argumente.count, let wert = Int(argumente[index + 1]) {
        jahr = wert
    }
    let faelle = Ausgabe.datensaetze(argumente[0])
    var zeilen = ["# SiegelStaerkeExport bewerten: bits \\t Stufe \\t Zeichen \\t Regel", "# jahr=\(jahr)",
                  "# faelle=\(faelle.count)"]
    zeilen.reserveCapacity(faelle.count + 3)
    for felder in faelle {
        let passwort = felder[0]
        let eingaben = Array(felder.dropFirst())
        let analyse = PasswordStrength.analyze(passwort, userInputs: eingaben, referenceYear: jahr)
        let stufe = PasswordStrength.level(forBits: analyse.bits)
        let normalisiert = MasterPasswordPolicy.normalized(passwort)
        // Wie MasterPasswordPolicy.check, aber mit festem Bezugsjahr.
        let ok = MasterPasswordPolicy.satisfied(normalized: normalisiert, bits: analyse.bits)
        zeilen.append("\(Ausgabe.zahl(analyse.bits))\t\(stufe.rawValue)\t\(normalisiert.count)\t\(ok ? 1 : 0)")
    }
    Ausgabe.schreiben(zeilen, nach: argumente[1])
}

// MARK: - graphem

func graphem(_ argumente: [String]) {
    guard argumente.count == 2 else { Ausgabe.fehler("graphem <korpus> <ausgabe>") }
    let faelle = Ausgabe.datensaetze(argumente[0])
    var zeilen = ["# SiegelStaerkeExport graphem: UTF-16-Längen der Character", "# faelle=\(faelle.count)"]
    for felder in faelle {
        zeilen.append(felder[0].map { String($0.utf16.count) }.joined(separator: ","))
    }
    Ausgabe.schreiben(zeilen, nach: argumente[1])
}

// MARK: - unicode

/// Graphem-Klassen (UAX #29), abgeleitet aus Swifts eigenem Zerlegen kleiner Proben.
enum Klasse: Int {
    case other = 0, cr, lf, control, extend, zwj, regionalIndicator, prepend, spacingMark, l, v, t, lv, lvt
}

func zaehlen(_ skalare: [Unicode.Scalar]) -> Int {
    var view = String.UnicodeScalarView()
    view.append(contentsOf: skalare)
    return String(view).count
}

let probeA: Unicode.Scalar = "a"
let probeTrema: Unicode.Scalar = "\u{0308}"
let probeEmoji: Unicode.Scalar = "\u{1F600}"
let probeZWJ: Unicode.Scalar = "\u{200D}"
let probeL: Unicode.Scalar = "\u{1100}"
let probeV: Unicode.Scalar = "\u{1161}"
let probeT: Unicode.Scalar = "\u{11A8}"
let probeKa: Unicode.Scalar = "\u{0915}"
let probeVirama: Unicode.Scalar = "\u{094D}"

func klasse(_ x: Unicode.Scalar) -> Klasse {
    switch x.value {
    case 0x0D: return .cr
    case 0x0A: return .lf
    case 0x200D: return .zwj
    default: break
    }
    if zaehlen([x, probeTrema]) == 2 { return .control }                       // GB4: nach Control immer Grenze
    if zaehlen([probeA, x]) == 1 {                                             // GB9/GB9a
        return zaehlen([probeEmoji, x, probeZWJ, probeEmoji]) == 1 ? .extend : .spacingMark   // GB11 nur mit Extend
    }
    if zaehlen([x, probeA]) == 1 { return .prepend }                           // GB9b
    if zaehlen([x, probeL]) == 1 { return .l }                                 // GB6
    let vorV = zaehlen([x, probeV]) == 1
    let vorT = zaehlen([x, probeT]) == 1
    if vorV && vorT { return zaehlen([probeV, x]) == 1 ? .v : .lv }            // GB7
    if vorT { return zaehlen([probeV, x]) == 1 ? .t : .lvt }                   // GB7/GB8
    if zaehlen([x, x]) == 1 && zaehlen([x, x, x]) == 2 { return .regionalIndicator }   // GB12/GB13
    return .other
}

func unicodeTabelle(_ argumente: [String]) {
    guard argumente.count == 1 else { Ausgabe.fehler("unicode <ausgabe>") }
    var zeilen = ["# SiegelStaerkeExport unicode: Eigenschaften, wie Swift sie sieht",
                  "# R <von> <bis> <merkmale> <kategorie> <klasse> <bildzeichen> <incb>   (Hex für Skalare und Merkmale)",
                  "# merkmale: 1 isLetter, 2 isNumber, 4 isUppercase, 8 isLowercase (Character), 16 isWhitespace (Skalar)",
                  "# kategorie: Reihenfolge wie .NET UnicodeCategory; klasse: Graphem-Klasse; incb: 1 Konsonant, 2 Linker, 3 Extend",
                  "# K <skalar> <abbildung…>   volle Kleinschreibung, G <skalar> <abbildung…>   volle Grossschreibung"]
    var kleinZeilen: [String] = []
    var grossZeilen: [String] = []
    var laufStart: UInt32 = 0
    var laufWert: [Int]? = nil
    var laufEnde: UInt32 = 0

    func laufAbschliessen() {
        guard let w = laufWert else { return }
        zeilen.append("R \(Ausgabe.hex(laufStart)) \(Ausgabe.hex(laufEnde)) \(String(w[0], radix: 16, uppercase: true)) "
                      + "\(w[1]) \(w[2]) \(w[3]) \(w[4])")
    }

    var wert: UInt32 = 0
    while wert <= 0x10FFFF {
        if wert == 0xD800 { wert = 0xE000 ; laufAbschliessen(); laufWert = nil }
        guard let s = Unicode.Scalar(wert) else { wert += 1; continue }
        let c = Character(s)
        var merkmale = 0
        if c.isLetter { merkmale |= 1 }
        if c.isNumber { merkmale |= 2 }
        if c.isUppercase { merkmale |= 4 }
        if c.isLowercase { merkmale |= 8 }
        if s.properties.isWhitespace { merkmale |= 16 }
        let kategorie = kategorieNummer(s.properties.generalCategory)
        let k = klasse(s)
        let istTrennbar = k != .extend && k != .zwj && k != .spacingMark
        let bild = istTrennbar && zaehlen([probeEmoji, probeZWJ, s]) == 1 ? 1 : 0
        var incb = 0
        if k == .other && zaehlen([probeKa, probeVirama, s]) == 1 {
            incb = 1
        } else if zaehlen([probeKa, s, probeKa]) == 1 {
            incb = 2
        } else if zaehlen([probeKa, s, probeVirama, probeKa]) == 1 {
            incb = 3
        }
        let eintrag = [merkmale, kategorie, k.rawValue, bild, incb]
        if let w = laufWert, w == eintrag, laufEnde + 1 == wert {
            laufEnde = wert
        } else {
            laufAbschliessen()
            laufWert = eintrag
            laufStart = wert
            laufEnde = wert
        }
        let selbst = [s]
        let klein = Array(s.properties.lowercaseMapping.unicodeScalars)
        if klein != selbst {
            kleinZeilen.append("K \(Ausgabe.hex(wert)) " + klein.map { Ausgabe.hex($0.value) }.joined(separator: " "))
        }
        let gross = Array(s.properties.uppercaseMapping.unicodeScalars)
        if gross != selbst {
            grossZeilen.append("G \(Ausgabe.hex(wert)) " + gross.map { Ausgabe.hex($0.value) }.joined(separator: " "))
        }
        wert += 1
    }
    laufAbschliessen()
    Ausgabe.schreiben(zeilen + kleinZeilen + grossZeilen, nach: argumente[0])
}

func kategorieNummer(_ g: Unicode.GeneralCategory) -> Int {
    switch g {
    case .uppercaseLetter: 0
    case .lowercaseLetter: 1
    case .titlecaseLetter: 2
    case .modifierLetter: 3
    case .otherLetter: 4
    case .nonspacingMark: 5
    case .spacingMark: 6
    case .enclosingMark: 7
    case .decimalNumber: 8
    case .letterNumber: 9
    case .otherNumber: 10
    case .spaceSeparator: 11
    case .lineSeparator: 12
    case .paragraphSeparator: 13
    case .control: 14
    case .format: 15
    case .surrogate: 16
    case .privateUse: 17
    case .connectorPunctuation: 18
    case .dashPunctuation: 19
    case .openPunctuation: 20
    case .closePunctuation: 21
    case .initialPunctuation: 22
    case .finalPunctuation: 23
    case .otherPunctuation: 24
    case .mathSymbol: 25
    case .currencySymbol: 26
    case .modifierSymbol: 27
    case .otherSymbol: 28
    case .unassigned: 29
    @unknown default: 29
    }
}

// MARK: - kennzahlen

func kennzahlen(_ argumente: [String]) {
    guard argumente.count == 1 else { Ausgabe.fehler("kennzahlen <ausgabe>") }
    func sha(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    let listen: [(String, String)] = [
        ("passwords", ZxcvbnListData.passwords), ("passwordsGerman", ZxcvbnListData.passwordsGerman),
        ("englishWikipedia", ZxcvbnListData.englishWikipedia), ("usTvAndFilm", ZxcvbnListData.usTvAndFilm),
        ("germanWords", ZxcvbnListData.germanWords), ("surnames", ZxcvbnListData.surnames),
        ("maleNames", ZxcvbnListData.maleNames), ("femaleNames", ZxcvbnListData.femaleNames),
        ("firstNamesCHDE", ZxcvbnListData.firstNamesCHDE), ("surnamesCHDE", ZxcvbnListData.surnamesCHDE),
        ("placesCH", ZxcvbnListData.placesCH), ("passphraseWords", ZxcvbnListData.passphraseWords),
        ("englishWeb2", ZxcvbnListData.englishWeb2),
    ]
    var zeilen = ["# SiegelStaerkeExport kennzahlen"]
    for (name, text) in listen {
        zeilen.append("liste \(name) \(text.utf8.count) \(sha(text))")
    }
    let d = ZxcvbnDictionary.shared
    zeilen.append("woerter \(d.ranks.count)")
    zeilen.append("maxWortLaenge \(d.maxWordLength)")
    var rangSumme: UInt64 = 0
    for (_, r) in d.ranks { rangSumme &+= UInt64(r) }
    zeilen.append("rangSumme \(rangSumme)")
    zeilen.append("passphrase \(PassphraseGenerator.words.count) \(sha(PassphraseGenerator.words.joined(separator: "\n")))")
    zeilen.append("orte \(ZxcvbnMatcher.placeRanks.count) \(ZxcvbnMatcher.placeMaxLength)")
    for g in KeyboardGraphs.all {
        zeilen.append("graph \(g.name) \(Ausgabe.zahl(g.startingPositions)) \(Ausgabe.zahl(g.averageDegree)) "
                      + "\(g.shifted.count) \(g.misalignedTokens.count)")
    }
    let eingaben = MasterPasswordPolicy.userInputs(userName: "jmueller", fullName: "Jürg Müller-Zbinden")
    zeilen.append("benutzer " + eingaben.map { Data($0.utf8).base64EncodedString() }.joined(separator: " "))
    let eingaben2 = MasterPasswordPolicy.userInputs(userName: "Max", fullName: "Max Ößmüster İlse-Çora")
    zeilen.append("benutzer " + eingaben2.map { Data($0.utf8).base64EncodedString() }.joined(separator: " "))
    Ausgabe.schreiben(zeilen, nach: argumente[0])
}

// MARK: - autofill, titel (Gegenproben für AutofillMatcher und den CSV-Titel aus der URL)

func autofill(_ argumente: [String]) {
    guard argumente.count == 2 else { Ausgabe.fehler("autofill <korpus> <ausgabe>") }
    let faelle = Ausgabe.datensaetze(argumente[0])
    var zeilen = ["# SiegelStaerkeExport autofill: 1 = Treffer", "# faelle=\(faelle.count)"]
    for felder in faelle {
        zeilen.append(AutofillMatcher.matches(entryURL: felder[0], serviceIdentifier: felder[1]) ? "1" : "0")
    }
    Ausgabe.schreiben(zeilen, nach: argumente[1])
}

func titel(_ argumente: [String]) {
    guard argumente.count == 2 else { Ausgabe.fehler("titel <korpus> <ausgabe>") }
    let faelle = Ausgabe.datensaetze(argumente[0])
    var zeilen = ["# SiegelStaerkeExport titel: Base64(Titel aus der URL)", "# faelle=\(faelle.count)"]
    for felder in faelle {
        zeilen.append(Data(CSVText.titleFromURL(felder[0]).utf8).base64EncodedString())
    }
    Ausgabe.schreiben(zeilen, nach: argumente[1])
}

// MARK: - Start

let argumente = Array(CommandLine.arguments.dropFirst())
switch argumente.first {
case "bewerten": bewerten(Array(argumente.dropFirst()))
case "graphem": graphem(Array(argumente.dropFirst()))
case "unicode": unicodeTabelle(Array(argumente.dropFirst()))
case "kennzahlen": kennzahlen(Array(argumente.dropFirst()))
case "autofill": autofill(Array(argumente.dropFirst()))
case "titel": titel(Array(argumente.dropFirst()))
case "nfc": nfcTabelle(Array(argumente.dropFirst()))
case "nfc-korpus": nfcKorpus(Array(argumente.dropFirst()))
case "gleich": gleich(Array(argumente.dropFirst()))
default: Ausgabe.fehler("Aufruf: SiegelStaerkeExport bewerten|graphem|unicode|kennzahlen|autofill|titel|nfc|nfc-korpus|gleich …")
}
#else
import Foundation

FileHandle.standardError.write(Data("SiegelStaerkeExport läuft nur im Debug-Bau (windows/skripte/*.py).\n".utf8))
exit(2)
#endif
