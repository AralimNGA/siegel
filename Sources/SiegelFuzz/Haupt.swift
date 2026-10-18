#if DEBUG
import Foundation
@testable import SiegelCore

/// Eine JSON-Zeile (Schlüssel sortiert); Werte sind nur Codes und Zähler.
func jsonZeile(_ obj: [String: Any]) -> String {
    let d = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data("{}".utf8)
    return String(decoding: d, as: UTF8.self)
}

enum FuzzHaupt {
    static let zielNamen = ["datei", "inhalt", "notfall", "karte", "csv", "totp", "cbor", "ctaphid", "hwdatei",
                             "sicherung", "autofill", "vernichtung"]

    static func ziel(_ name: String, neueSaat: Bool) -> FuzzZiel? {
        switch name {
        case "datei": let z = ZielDatei(); z.neueSaat = neueSaat; return z
        case "inhalt": let z = ZielInhalt(); z.neueSaat = neueSaat; return z
        case "notfall": let z = ZielNotfall(); z.neueSaat = neueSaat; return z
        case "karte": return ZielKarte()
        case "csv": return ZielCSV()
        case "totp": return ZielTOTP()
        case "cbor": return ZielCBOR()
        case "ctaphid": return ZielCTAPHID()
        case "hwdatei": return ZielHWDatei()
        case "sicherung": let z = ZielSicherung(); z.neueSaat = neueSaat; return z
        case "autofill": return ZielAutofill()
        case "vernichtung": let z = ZielVernichtung(); z.neueSaat = neueSaat; return z
        default: return nil
        }
    }

    static func start(_ args: [String]) {
        var werte: [String: String] = [:]
        var schalter = Set<String>()
        var i = 0
        while i < args.count {
            let a = args[i]
            if ["--weiter", "--neue-saat", "--liste"].contains(a) {
                schalter.insert(a)
            } else if a.hasPrefix("--"), i + 1 < args.count {
                werte[a] = args[i + 1]
                i += 1
            } else {
                meldung("SiegelFuzz: unbekanntes Argument " + a)
                exit(2)
            }
            i += 1
        }
        if schalter.contains("--liste") {
            print(zielNamen.joined(separator: " "))
            return
        }
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        let wurzel = werte["--wurzel"].map { URL(fileURLWithPath: $0, isDirectory: true) } ?? cwd
        let arbeit = werte["--arbeitsordner"].map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? wurzel.appendingPathComponent("build/fuzz", isDirectory: true)
        let funde = werte["--fundordner"].map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? arbeit.appendingPathComponent("funde", isDirectory: true)
        try? FileManager.default.createDirectory(at: funde, withIntermediateDirectories: true)
        let u = Umgebung(wurzel: wurzel, arbeitsordner: arbeit, fundOrdner: funde)
        let namen: [String]
        switch werte["--ziel"] ?? "alle" {
        case "alle": namen = zielNamen
        case let n: namen = n.split(separator: ",").map(String.init)
        }
        let neueSaat = schalter.contains("--neue-saat")

        if let datei = werte["--wiederholen"] {
            guard namen.count == 1, let ziel = ziel(namen[0], neueSaat: false),
                  let daten = FileManager.default.contents(atPath: datei) else {
                meldung("SiegelFuzz: --wiederholen braucht genau ein --ziel und eine lesbare Datei")
                exit(2)
            }
            do {
                try ziel.vorbereiten(u)
                Waechter.einrichten(fundOrdner: funde, ziel: ziel.name)
                Waechter.beginne([UInt8](daten), limit: ziel.zeitlimit * (Waechter.mitASan ? 4 : 1))
                let code = try ziel.pruefe([UInt8](daten))
                Waechter.ende()
                print(jsonZeile(["ziel": ziel.name, "wiederholt": true, "ergebnis": code]))
            } catch {
                print(jsonZeile(["ziel": ziel.name, "wiederholt": true, "fund": String(describing: error)]))
                exit(1)
            }
            return
        }

        if let ordner = werte["--mutanten"] {
            // Mutanten der Fixtures samt Swift-Urteil schreiben (Python-Differenztest: referenz/differenz.sh)
            let ziel = ZielDatei()
            ziel.nurFixtures = true
            let anzahl = Int(werte["--anzahl"] ?? "200") ?? 200
            var z = Zufall(saat: UInt64(werte["--saat"] ?? "1") ?? 1)
            let aus = URL(fileURLWithPath: ordner, isDirectory: true)
            do {
                try FileManager.default.createDirectory(at: aus, withIntermediateDirectories: true)
                try ziel.vorbereiten(u)
                var zeilen: [String] = []
                for i in 0..<anzahl {
                    let e = ziel.naechste(&z)
                    let s = ziel.saaten[Int(e[0]) % ziel.saaten.count]
                    let b = Array(e.dropFirst())
                    let name = String(format: "m%05d.siegel", i)
                    try Data(b).write(to: aus.appendingPathComponent(name))
                    let parse: String
                    do { _ = try VaultFile.parse(b); parse = "ok" } catch { parse = fehlerCode(error) }
                    let urteil: String
                    do { urteil = try ziel.pruefe(e) } catch { urteil = "FUND " + String(describing: error) }
                    let obj: [String: Any] = ["datei": name, "saat": s.name, "swiftParse": parse, "swift": urteil,
                                              "unveraendert": b == s.bytes]
                    let d = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
                    zeilen.append(String(decoding: d, as: UTF8.self))
                }
                try Data((zeilen.joined(separator: "\n") + "\n").utf8).write(to: aus.appendingPathComponent("swift.jsonl"))
                print("{\"mutanten\":\(anzahl)}")
            } catch {
                meldung("SiegelFuzz: Mutanten gescheitert: \(String(describing: error))")
                exit(1)
            }
            return
        }

        let sekunden = Double(werte["--sekunden"] ?? "60") ?? 60
        let saat = UInt64(werte["--saat"] ?? "1") ?? 1
        let maxEingaben = werte["--max-eingaben"].flatMap { Int($0) }
        var fehler = false
        let proZiel = sekunden / Double(max(1, namen.count))
        for n in namen {
            guard let ziel = ziel(n, neueSaat: neueSaat) else {
                meldung("SiegelFuzz: unbekanntes Ziel " + n + " (" + zielNamen.joined(separator: ", ") + ")")
                exit(2)
            }
            Waechter.einrichten(fundOrdner: funde, ziel: n)
            meldung("SiegelFuzz: Ziel \(n), Saat \(saat), \(Int(proZiel)) s, ASan \(Waechter.mitASan ? "an" : "aus")")
            do {
                Waechter.beginne([], limit: 600)
                try ziel.vorbereiten(u)
                Waechter.ende()
            } catch {
                Waechter.ende()
                meldung("SiegelFuzz: Vorbereitung von \(n) gescheitert: \(String(describing: error))")
                print(jsonZeile(["ziel": n, "vorbereitung": "gescheitert"]))
                fehler = true
                continue
            }
            let st = Lauf.fahre(ziel, sekunden: proZiel, saat: saat, umgebung: u,
                                weiter: schalter.contains("--weiter"), maxEingaben: maxEingaben)
            print(st.json(ziel: n, saat: saat, korpus: st.aufgenommen, zusatz: ziel.zusatz, asan: Waechter.mitASan))
            if !st.funde.isEmpty { fehler = true }
        }
        exit(fehler ? 1 : 0)
    }
}
#endif
