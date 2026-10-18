import Foundation
import Testing
@testable import SiegelCore

/// 30 typische Passwörter gegen die Intuition geprüft (Tabelle in Staerke/Woerter/HERKUNFT.md).
/// `intuitionMax` = obere Grenze nach Bauchgefühl (Bit). Reines zxcvbn überschätzte die Sätze mit Leerzeichen
/// (63.7 bzw. 78.8 Bit); das Wortfolgen-Muster (Siegel-Erweiterung) bringt sie unter 60.
/// Tabelle ausgeben: SIEGEL_STAERKE_TABELLE=1 swift test --filter StaerkeTypischTests
@Suite struct StaerkeTypischTests {
    struct Fall: Sendable, CustomTestStringConvertible {
        let password: String
        let inputs: [String]
        let gruppe: String
        let intuitionMax: Double
        var testDescription: String { password }
    }

    static let faelle: [Fall] = [
        Fall(password: "YB1898", inputs: [], gruppe: "Verein+Jahr", intuitionMax: 20),
        Fall(password: "FCBasel1893!", inputs: [], gruppe: "Verein+Jahr", intuitionMax: 25),
        Fall(password: "scbern2026", inputs: [], gruppe: "Verein+Jahr", intuitionMax: 22),
        Fall(password: "EHCBiel2025!", inputs: [], gruppe: "Verein+Jahr", intuitionMax: 30),
        Fall(password: "HCDavos1921", inputs: [], gruppe: "Verein+Jahr", intuitionMax: 30),
        Fall(password: "BVB09Dortmund", inputs: [], gruppe: "Verein+Jahr", intuitionMax: 30),
        Fall(password: "Michael1985", inputs: [], gruppe: "Name+Jahr", intuitionMax: 22),
        Fall(password: "Sabine1972!", inputs: [], gruppe: "Name+Jahr", intuitionMax: 30),
        Fall(password: "Lukas2008", inputs: [], gruppe: "Name+Jahr", intuitionMax: 22),
        Fall(password: "LaraMüller2010", inputs: [], gruppe: "Name+Jahr", intuitionMax: 32),
        Fall(password: "Thomas.Meier1979", inputs: [], gruppe: "Name+Jahr", intuitionMax: 36),
        Fall(password: "Jürg1965!", inputs: [], gruppe: "Name+Jahr", intuitionMax: 30),
        Fall(password: "qwertz123", inputs: [], gruppe: "Tastatur", intuitionMax: 15),
        Fall(password: "1qay2wsx", inputs: [], gruppe: "Tastatur", intuitionMax: 15),
        Fall(password: "asdfghjklöä", inputs: [], gruppe: "Tastatur", intuitionMax: 18),
        Fall(password: "yxcvbnm,.-", inputs: [], gruppe: "Tastatur", intuitionMax: 18),
        Fall(password: "147258369", inputs: [], gruppe: "Tastatur", intuitionMax: 15),
        Fall(password: "+\"*ç%&/()=", inputs: [], gruppe: "Tastatur", intuitionMax: 18),
        Fall(password: "IchLiebeMeinenHund", inputs: [], gruppe: "Satz", intuitionMax: 40),
        Fall(password: "Mein Hund heisst Bello", inputs: [], gruppe: "Satz", intuitionMax: 58),
        Fall(password: "DieSonneScheintHeute!", inputs: [], gruppe: "Satz", intuitionMax: 55),
        Fall(password: "ichgehejetztnachhause", inputs: [], gruppe: "Satz", intuitionMax: 55),
        Fall(password: "Ich wohne seit 2015 in Olten", inputs: [], gruppe: "Satz", intuitionMax: 58),
        Fall(password: "EsWarEinmalEinKönig1990", inputs: [], gruppe: "Satz", intuitionMax: 45),
        Fall(password: "Sommer2025!", inputs: [], gruppe: "Sonstiges", intuitionMax: 22),
        Fall(password: "Grüezi123", inputs: [], gruppe: "Sonstiges", intuitionMax: 22),
        Fall(password: "Zürich2026", inputs: [], gruppe: "Sonstiges", intuitionMax: 22),
        Fall(password: "P@ssw0rt!", inputs: [], gruppe: "Sonstiges", intuitionMax: 20),
        Fall(password: "kerze-vulkan-flaute-pirat", inputs: [], gruppe: "Passphrase (4 Wörter)", intuitionMax: 55),
        Fall(password: "correcthorsebatterystaple", inputs: [], gruppe: "Passphrase (englisch)", intuitionMax: 55),
    ]

    @Test func genauDreissig() {
        #expect(Self.faelle.count == 30)
        #expect(Set(Self.faelle.map(\.password)).count == 30)
    }

    @Test(arguments: faelle)
    func gegenIntuition(_ fall: Fall) {
        let bits = PasswordStrength.estimate(fall.password, userInputs: fall.inputs).bits
        #expect(bits < fall.intuitionMax)
        #expect(!MasterPasswordPolicy.check(fall.password, userInputs: ["siegel"] + fall.inputs).ok)
    }

    @Test func tabelleAusgeben() {
        guard ProcessInfo.processInfo.environment["SIEGEL_STAERKE_TABELLE"] == "1" else { return }
        var lines = ["| Gruppe | Passwort | Bit | Stufe | Zerlegung |", "|---|---|---|---|---|"]
        for fall in Self.faelle {
            let analysis = PasswordStrength.analyze(fall.password, userInputs: fall.inputs)
            let level = PasswordStrength.level(forBits: analysis.bits)
            let shown = fall.password.replacingOccurrences(of: "|", with: "\\|")
            lines.append("| \(fall.gruppe) | `\(shown)` | \(String(format: "%.1f", analysis.bits)) | \(level) | "
                         + analysis.patternSummary.replacingOccurrences(of: "|", with: "\\|") + " |")
        }
        print(lines.joined(separator: "\n"))
    }
}
