import Foundation
import SiegelCore

// Brücke zum Kern-Anteil der Selbstvernichtung (§23.2) für die Snapshots. Entsperren, Zähler, Totmann-Schalter und
// Vernichtungs-Passwort macht der echte Kern (`store.unlock`, `checkDeadman`). Die Bilder brauchen nur einen Zustand,
// den die Uhr erst nach Tagen erreicht: Dafür ändert diese Datei die zwei Felder `lastGenuineUnlock` und
// `failedAttempts` in `Hardware/zustand.json` (nicht geheim, Format des Kerns nach §23.3 und KERN-NOTIZEN.md). Die
// Testschalter des Kerns (Uhr) gibt es nur im Debug-Bau über `@testable`; die Snapshots laufen im Release-Bau.

/// Letztes echtes Entsperren und Fehlversuche setzen (Frist und Zähler für Bilder). false = kein Zustand vorhanden.
@discardableResult
func kernZustand(_ store: VaultStore, letztesEntsperren: Date?, fehlversuche: Int) -> Bool {
    let url = store.hardwareDirectory.appendingPathComponent("zustand.json", isDirectory: false)
    guard let daten = try? Data(contentsOf: url),
          var json = (try? JSONSerialization.jsonObject(with: daten)) as? [String: Any] else { return false }
    json["lastGenuineUnlock"] = letztesEntsperren.map { $0.timeIntervalSince1970.rounded() } ?? NSNull()
    json["failedAttempts"] = fehlversuche
    guard let neu = try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]) else { return false }
    return (try? neu.write(to: url, options: .atomic)) != nil
}

/// Zustand für die Prüfung der Anzeige-Regeln ohne Tresor (öffentlicher Init des Kerns, Frist wie im Kern).
func kernStatus(totmann: Int?, letztesEntsperren: Date?, zaehler: Int?, fehlversuche: Int) -> DestructionStatus {
    let frist = totmann.flatMap { tage in letztesEntsperren.map { $0.addingTimeInterval(TimeInterval(tage) * 86_400) } }
    return DestructionStatus(settings: DestructionSettings(deadmanDays: totmann, maxFailedAttempts: zaehler),
                             lastGenuineUnlock: letztesEntsperren, failedAttempts: fehlversuche, deadline: frist,
                             destroyedTrigger: nil, destroyedAt: nil)
}
