import Foundation
import Testing
@testable import SiegelCore

/// Befund #18 (17.10.2026): Wort + Zähler, Wochentags-/Monatsfolgen und Ort + PLZ dürfen nicht als stark gelten.
/// Befund #49: Die Kürzung auf 256 Zeichen darf die Schätzung nicht erhöhen (Wiederholung über die Grenze).
@Suite struct StaerkeVorlagenTests {

    /// Alle im Befund gemessenen Fälle (vorher 64–89 Bit, von `create` angenommen) und die dort geforderten Tests.
    static let befund18: [String] = [
        "Hund1Hund2Hund3Hund4Hund5Hund6", "Hund1Hund2Hund3Hund4Hund5", "Hund1Hund2Hund3Hund4",
        "Basel1Basel2Basel3Basel4", "Bello1Bello2Bello3Bello4", "Katze1Katze2Katze3Katze4Katze5",
        "Basel4000Bern3000Zürich8000", "Thun3600Bern3000Biel2500",
        "Mo-Di-Mi-Do-Fr-Sa-So", "Mo.Di.Mi.Do.Fr.Sa.So", "Lu-Ma-Me-Je-Ve-Sa-Di",
        "Jan.Feb.Mar.Apr.Mai.Jun", "Jan-Feb-Mar-Apr-May-Jun",
        // Varianten: Schrittweiten, führende Nullen, rückwärts, Trennzeichen, abgebrochene letzte Wiederholung
        "Hund01Hund02Hund03Hund04Hund05", "Velo10-Velo20-Velo30-Velo40", "Ski2026Ski2025Ski2024Ski2023",
        "Hund1Hund2Hund3Hund4Hund5Hun", "1Hund2Hund3Hund4Hund5Hund6Hund",
        "Montag-Dienstag-Mittwoch-Donnerstag", "SonntagSamstagFreitagDonnerstag", "Januar.Februar.März.April",
        "janvier-fevrier-mars-avril-mai", "lunedi martedi mercoledi giovedi", "Sa-So-Mo-Di-Mi-Do",
        "3600 Thun 3000 Bern 2500 Biel", "Luzern6000Zug6300Basel4000",
    ]

    @Test(arguments: befund18)
    func befund18Unter60(_ password: String) {
        let analysis = PasswordStrength.analyze(password, userInputs: ["siegel"], referenceYear: 2026)
        #expect(analysis.bits < 60, "\(password): \(analysis.bits) Bit, \(analysis.patternSummary)")
        #expect(MasterPasswordPolicy.check(password, userInputs: ["siegel"]).ok == false)
    }

    @Test func zaehlerVorlageWirdAlsEinStueckErkannt() {
        let analysis = PasswordStrength.analyze("Hund1Hund2Hund3Hund4Hund5Hund6", userInputs: [], referenceYear: 2026)
        #expect(analysis.sequence.count == 1)
        #expect(analysis.sequence.first?.pattern == .counter)
        #expect(analysis.bits < 30, "\(analysis.bits)")
        // Grundwort + Startzahl + Schritt + Lage + Wiederholungen: deutlich unter dem Brute-Force-Wert
        let hund = PasswordStrength.analyze("Hund", userInputs: [], referenceYear: 2026).bits
        #expect(abs(analysis.bits - (hund + log2(10) + 3 + log2(5) + log2(6))) < 0.5)
    }

    @Test func zaehlerNurMitArithmetischerFolge() {
        // Zufällige Zahlen sind keine Zähler-Vorlage
        let m = ZxcvbnMatcher(dictionary: .shared, userInputs: [], referenceYear: 2026, graphs: KeyboardGraphs.all)
        #expect(!m.omnimatch(Array("Hund7Hund3Hund9Hund1")).contains { $0.pattern == .counter })
        #expect(!m.omnimatch(Array("Hund1Hund4Hund7")).contains { $0.pattern == .counter })     // Schritt 3
        #expect(m.omnimatch(Array("Hund1Hund3Hund5")).contains { $0.pattern == .counter })      // Schritt 2
        #expect(m.omnimatch(Array("Hund9Hund10Hund11")).contains { $0.pattern == .counter && $0.i == 0 && $0.j == 16 })
        #expect(!m.omnimatch(Array("Hund1Katz2Maus3")).contains { $0.pattern == .counter })    // keine Vorlage
        #expect(!m.omnimatch(Array("Hund1Hund2")).isEmpty)
        // Die Folge bricht ab: nur der arithmetische Teil zählt
        let broken = m.omnimatch(Array("Ab1Ab2Ab3Ab9")).filter { $0.pattern == .counter }
        #expect(broken.contains { $0.i == 0 && $0.j == 10 })                                    // "Ab1Ab2Ab3Ab"
        #expect(!broken.contains { $0.j == 11 })
    }

    @Test func kalenderfolgen() {
        let m = ZxcvbnMatcher(dictionary: .shared, userInputs: [], referenceYear: 2026, graphs: KeyboardGraphs.all)
        func covers(_ text: String) -> Bool {
            let chars = Array(text)
            return m.omnimatch(chars).contains { $0.pattern == .calendar && $0.i == 0 && $0.j == chars.count - 1 }
        }
        #expect(covers("Mo-Di-Mi-Do-Fr-Sa-So"))
        #expect(covers("MoDiMiDoFr"))
        #expect(covers("So.Sa.Fr.Do"))                     // rückwärts
        #expect(covers("Sa-So-Mo-Di"))                     // über das Ende hinweg
        #expect(covers("Jan.Feb.Mar.Apr.Mai.Jun"))         // DE mit Nebenform "mar"
        #expect(covers("sept-okt-nov-dez"))
        #expect(covers("JANUARY FEBRUARY MARCH"))
        #expect(covers("août/septembre/octobre"))
        #expect(!covers("Mo-Mi-Fr"))                       // keine aufeinanderfolgenden Einträge
        #expect(!covers("Mo-Di.Mi"))                       // Trennstück wechselt
        #expect(!covers("Mo-Di-Mi-Do-Fr-Sa-So-Mo"))        // höchstens ein Umlauf
    }

    @Test func ortUndPostleitzahl() {
        let m = ZxcvbnMatcher(dictionary: .shared, userInputs: [], referenceYear: 2026, graphs: KeyboardGraphs.all)
        func covers(_ text: String) -> Bool {
            let chars = Array(text)
            return m.omnimatch(chars).contains { $0.pattern == .placeCode && $0.i == 0 && $0.j == chars.count - 1 }
        }
        #expect(covers("Thun3600"))
        #expect(covers("thun 3600"))
        #expect(covers("3600Thun"))
        #expect(covers("3600 Thun"))
        #expect(covers("Zürich8000"))
        #expect(covers("Zuerich-8000"))
        #expect(!covers("Thun0999"))                      // keine Schweizer PLZ
        #expect(!covers("Thun9700"))
        #expect(!covers("Thun36001"))                     // fünf Ziffern
        #expect(!covers("Kerze3600"))                     // kein Ort
        // Runde PLZ (Hauptnummer) kosten weniger als beliebige
        let rund = PasswordStrength.analyze("Thun3600", userInputs: [], referenceYear: 2026).bits
        let krumm = PasswordStrength.analyze("Thun3613", userInputs: [], referenceYear: 2026).bits
        #expect(rund < krumm)
        #expect(rund < 20, "\(rund)")
    }

    @Test func gegenprobenBleibenStark() {
        // Zufall ohne Muster bleibt bei ≥ 60 Bit (die 300 Passphrasen und 2000 Zufallsfolgen prüft
        // StaerkeSchaetzungTests; hier Fälle mit Ziffern, Tagen und Orten im Zufall).
        for password in ["kV7#pQ2$mZ9!xR4@tL8&", "Mo7#Di2$Zug9!xR4@tL8&q", "Thun3600-kerze-vulkan-flaute-pirat-seide",
                         "q9Xf3Lp8Vm2Zr7Wk4Tn6", "kerze-vulkan-flaute-pirat-seide-hafen"] {
            let bits = PasswordStrength.analyze(password, userInputs: ["siegel"], referenceYear: 2026).bits
            #expect(bits >= 60, "\(password): \(bits)")
        }
    }

    // MARK: - Befund #49: Kürzung auf 256 Zeichen

    @Test func wiederholungUeberDieKuerzungsgrenze() {
        let b = String(repeating: "a", count: 33) + String(repeating: "b", count: 33)
            + String(repeating: "c", count: 33) + String(repeating: "d", count: 33)
        #expect(b.count == 132)
        let bb = b + b
        let einfach = PasswordStrength.estimate(b).bits
        let doppelt = PasswordStrength.estimate(bb).bits
        #expect(doppelt < 60, "\(doppelt)")
        #expect(doppelt <= einfach + 1.01)
        #expect(MasterPasswordPolicy.check(bb, userInputs: ["siegel"]).ok == false)
    }

    @Test func langerSatzZweimalGetippt() {
        let satz = "Der Fuchs springt am Montag über den Zaun, weil der Hund im Garten bellt und die Katze auf dem "
            + "Dach sitzt und in die Sonne blinzelt, bis es Abend wird."
        #expect(satz.count > 128 && satz.count < 256)
        let einmal = PasswordStrength.estimate(satz).bits
        let zweimal = PasswordStrength.estimate(satz + satz).bits
        #expect(zweimal <= einmal + 1.01, "\(einmal) → \(zweimal)")
        // Mit Rest nach der Wiederholung: höchstens Wiederholung + Rest + Zuschlag für zwei Teile
        let mitRest = PasswordStrength.estimate(satz + satz + "!!").bits
        #expect(mitRest <= einmal + 1 + 20, "\(mitRest)")
    }

    @Test func kuerzungErhoehtNieGegenueberDerGanzenPeriode() {
        // Für periodische Eingaben über 256 Zeichen: Schätzung ≤ Schätzung der Periode + log2(Anzahl)
        var state: UInt32 = 99
        for length in [129, 150, 200, 300] {
            let periode = String((0..<length).map { _ -> Character in
                state = state &* 1_103_515_245 &+ 12345
                return Character(Unicode.Scalar(UInt8(97 + (state >> 16) % 26)))
            })
            let einmal = PasswordStrength.estimate(periode).bits
            let dreimal = PasswordStrength.estimate(periode + periode + periode).bits
            #expect(dreimal <= einmal + log2(3) + 0.01, "Länge \(length): \(einmal) → \(dreimal)")
        }
    }

    @Test func periodeNachKMP() {
        typealias P = PasswordStrength.PeriodicPrefix
        #expect(PasswordStrength.longestPeriodicPrefix(Array("abcabcabcab")) == P(length: 11, period: 3))
        #expect(PasswordStrength.longestPeriodicPrefix(Array("abababx")) == P(length: 6, period: 2))
        #expect(PasswordStrength.longestPeriodicPrefix(Array("abcdef")) == nil)
        #expect(PasswordStrength.longestPeriodicPrefix(Array("aaaa")) == P(length: 4, period: 1))
    }

    @Test func laufzeitMitNeuenMustern() {
        _ = ZxcvbnDictionary.shared
        let samples = [
            String(repeating: "Hund1", count: 12) + "Hund",
            "Mo-Di-Mi-Do-Fr-Sa-So-Jan-Feb-Mar-Apr-Mai-Jun-Jul-Aug-Sep-Okt-Nov",
            "Thun3600Bern3000Biel2500Basel4000Zürich8000Luzern6000Chur7000ab",
            String(repeating: "1a", count: 32),
            String(repeating: "a1b2", count: 16),
        ]
        #if DEBUG
        let limit = Duration.milliseconds(250)
        #else
        let limit = Duration.milliseconds(20)
        #endif
        for sample in samples {
            var worst = Duration.zero
            for _ in 0..<3 {
                let start = ContinuousClock.now
                _ = PasswordStrength.estimate(sample)
                worst = max(worst, ContinuousClock.now - start)
            }
            #expect(worst < Sanitizer.grenze(limit), "\(sample.prefix(20)): \(worst)")   // unter ASan/TSan gestreckt
        }
    }
}
