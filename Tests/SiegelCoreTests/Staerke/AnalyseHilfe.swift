@testable import SiegelCore

extension PasswordStrength.Analysis {
    /// Lesbare Zerlegung, z. B. "dictionary(Sommer) year(2026) repeated(!!!)" (nur in Tests).
    var patternSummary: String {
        sequence.map { "\($0.pattern.rawValue)(\(String(characters[$0.i...$0.j])))" }.joined(separator: " ")
    }
}
