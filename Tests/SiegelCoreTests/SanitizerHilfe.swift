import Darwin
import Foundation

/// Läuft der Test unter einem Sanitizer (`skripte/sanitizer.sh`, `swift test --sanitize=…`)?
/// ASan und TSan verlangsamen den Code 5–20× (Laufzeitgrenzen werden darum gestreckt) und vertragen Exit-Tests nicht:
/// Der Kindprozess lädt die Sanitizer-Laufzeit zu spät (ASan: „Interceptors are not working“).
enum Sanitizer {
    static let aktiv: Bool = {
        let standard = UnsafeMutableRawPointer(bitPattern: -2)   // RTLD_DEFAULT
        return dlsym(standard, "__asan_init") != nil || dlsym(standard, "__tsan_init") != nil
    }()

    /// Faktor für Laufzeitgrenzen: `SIEGEL_ZEITFAKTOR` (setzt sanitizer.sh), sonst 10 unter einem Sanitizer, sonst 1.
    /// Ohne Sanitizer gelten die Grenzen unverändert.
    static let zeitfaktor: Int = {
        if let s = ProcessInfo.processInfo.environment["SIEGEL_ZEITFAKTOR"], let f = Int(s), f >= 1 { return f }
        return aktiv ? 10 : 1
    }()

    static func grenze(_ d: Duration) -> Duration { d * zeitfaktor }
}
