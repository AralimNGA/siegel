#if DEBUG
import Foundation
import SiegelFuzzAbdeckung

/// Ein Fuzz-Ziel. Eingaben sind immer Bytefolgen (so lassen sie sich bei Absturz/Hänger sichern und mit
/// `--wiederholen` erneut einspielen); jedes Ziel legt seine eigene Rahmung fest.
protocol FuzzZiel: AnyObject {
    var name: String { get }
    /// Zeitlimit pro Eingabe (Sekunden, ohne ASan-Zuschlag).
    var zeitlimit: Double { get }
    /// Saat laden/erzeugen und selbst prüfen (gültige Eingaben müssen gelingen).
    func vorbereiten(_ umgebung: Umgebung) throws
    /// Nächste Eingabe (meist Mutation eines Korpus-Elements).
    func naechste(_ z: inout Zufall) -> [UInt8]
    /// Eingabe ausführen und Invarianten prüfen. Liefert einen Ergebnis-Code (Rückkopplung); wirft `Fund`.
    func pruefe(_ eingabe: [UInt8]) throws -> String
    /// Eingabe mit neuem Ergebnis-Code in den Korpus aufnehmen.
    func aufnehmen(_ eingabe: [UInt8])
    /// Zusatzzähler für den Bericht (z. B. übersprungene teure Fälle).
    var zusatz: [String: Int] { get }
}

/// Gemeinsamer Korpus mit Obergrenze (zufälliges Ersetzen, Saat bleibt immer drin).
final class Korpus {
    private(set) var saat: [[UInt8]] = []
    private(set) var neu: [[UInt8]] = []
    let grenze: Int
    init(grenze: Int = 1000) { self.grenze = grenze }

    func saatAufnehmen(_ e: [UInt8]) { saat.append(e) }

    func aufnehmen(_ e: [UInt8], _ z: inout Zufall) {
        if neu.count < grenze { neu.append(e) } else { neu[z.int(neu.count)] = e }
    }

    var anzahl: Int { saat.count + neu.count }

    /// 60 % Saat, 40 % neue (falls vorhanden).
    func waehle(_ z: inout Zufall) -> [UInt8] {
        if !neu.isEmpty, z.chance(0.4) { return z.pick(neu) }
        return z.pick(saat)
    }
}

/// Laufzeit-Umgebung (Pfade, Optionen).
struct Umgebung {
    let wurzel: URL
    let arbeitsordner: URL
    let fundOrdner: URL
    var fixtures: URL { wurzel.appendingPathComponent("Tests/SiegelCoreTests/Fixtures", isDirectory: true) }
}

struct Statistik {
    var eingaben = 0
    var aufgenommen = 0
    var kantenStart: UInt32 = 0
    var kantenEnde: UInt32 = 0
    var ergebnisse: [String: Int] = [:]
    var funde: [String] = []
    var sekunden = 0.0
    var langsamste = 0.0

    func json(ziel: String, saat: UInt64, korpus: Int, zusatz: [String: Int], asan: Bool) -> String {
        let top = ergebnisse.sorted { $0.value > $1.value }.prefix(60)
        var obj: [String: Any] = [
            "ziel": ziel, "saat": String(saat), "sekunden": (sekunden * 10).rounded() / 10, "eingaben": eingaben,
            "proSekunde": sekunden > 0 ? (Double(eingaben) / sekunden).rounded() : 0,
            "ergebnisArten": ergebnisse.count, "korpusAufgenommen": aufgenommen, "funde": funde, "asan": asan,
            "kantenGesamt": Int(siegel_abdeckung_gesamt()), "kantenNachVorbereitung": Int(kantenStart),
            "kantenEnde": Int(kantenEnde),
            "langsamsteEingabeSekunden": (langsamste * 1000).rounded() / 1000,
            "ergebnisse": Dictionary(top.map { ($0.key, $0.value) }, uniquingKeysWith: { a, _ in a }),
        ]
        if !zusatz.isEmpty { obj["zusatz"] = zusatz }
        let data = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }
}

enum Lauf {
    /// Fährt ein Ziel `sekunden` lang. Bricht beim ersten Fund ab (ausser `weiter`), sichert die Eingabe.
    static func fahre(_ ziel: FuzzZiel, sekunden: Double, saat: UInt64, umgebung: Umgebung, weiter: Bool,
                      maxEingaben: Int?) -> Statistik {
        var z = Zufall(saat: saat ^ UInt64(truncatingIfNeeded: ziel.name.hashValueStabil))
        var st = Statistik()
        let limitFaktor = Waechter.mitASan ? 4.0 : 1.0
        let start = jetztSekunden()
        var naechsteMeldung = start + 15
        st.kantenStart = siegel_abdeckung_erreicht()
        while jetztSekunden() - start < sekunden {
            if let maxEingaben, st.eingaben >= maxEingaben { break }
            let eingabe = ziel.naechste(&z)
            let t0 = jetztSekunden()
            Waechter.beginne(eingabe, limit: ziel.zeitlimit * limitFaktor)
            let code: String
            let kantenVorher = siegel_abdeckung_erreicht()
            do {
                code = try ziel.pruefe(eingabe)
            } catch let f as Fund {
                Waechter.ende()
                let datei = sichern(eingabe, ziel: ziel.name, art: "fund", text: f.description, umgebung: umgebung)
                meldung("SiegelFuzz: FUND im Ziel \(ziel.name): \(f.description) – Eingabe: \(datei)")
                st.funde.append(f.description + " [" + datei + "]")
                st.ergebnisse["FUND " + f.art, default: 0] += 1
                st.eingaben += 1
                if !weiter { break }
                continue
            } catch {
                Waechter.ende()
                code = "unerwartet:" + fehlerCode(error)
            }
            Waechter.ende()
            let dauer = jetztSekunden() - t0
            st.langsamste = max(st.langsamste, dauer)
            st.eingaben += 1
            // Rückkopplung: neue Kanten (mit -sanitize-coverage) oder ein neuer Ergebnis-Code
            if st.ergebnisse[code] == nil || siegel_abdeckung_erreicht() > kantenVorher {
                ziel.aufnehmen(eingabe)
                st.aufgenommen += 1
            }
            st.ergebnisse[code, default: 0] += 1
            let jetzt = jetztSekunden()
            if jetzt >= naechsteMeldung {
                naechsteMeldung = jetzt + 30
                let rate = Double(st.eingaben) / max(0.001, jetzt - start)
                meldung(String(format: "  %@: %d Eingaben (%.0f/s), %d Ergebnisarten, %u Kanten, %d Funde",
                               ziel.name, st.eingaben, rate, st.ergebnisse.count, siegel_abdeckung_erreicht(),
                               st.funde.count))
            }
        }
        st.sekunden = jetztSekunden() - start
        st.kantenEnde = siegel_abdeckung_erreicht()
        return st
    }

    /// Sichert eine Eingabe mit Beschreibung in den Fundordner; Name aus SHA-256.
    static func sichern(_ eingabe: [UInt8], ziel: String, art: String, text: String, umgebung: Umgebung) -> String {
        let name = "\(art)-\(ziel)-\(sha256Hex(eingabe).prefix(12))"
        let bin = umgebung.fundOrdner.appendingPathComponent(name + ".bin")
        let txt = umgebung.fundOrdner.appendingPathComponent(name + ".txt")
        try? Data(eingabe).write(to: bin)
        try? Data((text + "\n").utf8).write(to: txt)
        return bin.path
    }
}

extension String {
    /// Stabiler Hash (FNV-1a), unabhängig vom Prozess (Swift-`hashValue` ist pro Lauf zufällig).
    var hashValueStabil: UInt64 {
        var h: UInt64 = 0xCBF2_9CE4_8422_2325
        for b in utf8 {
            h ^= UInt64(b)
            h = h &* 0x0000_0100_0000_01B3
        }
        return h
    }
}
#endif
