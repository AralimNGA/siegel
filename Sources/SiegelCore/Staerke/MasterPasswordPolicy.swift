import Foundation

/// Regel für das Master-Passwort (SPEC §1.6, im Kern erzwungen): geschätzte Stärke ≥ 60 Bit,
/// mindestens 12 Zeichen, höchstens 1024 UTF-8-Bytes, nur Zeichen aus Unicode 15.0 (v4.7). Geprüft wird nach der
/// Abbildung aus §1.1 (Zs → U+0020, dann NFC), also genau die Form, die später in Argon2 geht.
/// Benutzereingaben für die Schätzung: "siegel", NSUserName(), NSFullUserName() und deren Teile.
public enum MasterPasswordPolicy {
    public static let minimumBits: Double = 60
    public static let minimumLength: Int = 12
    public static let maximumUTF8Bytes: Int = 1024
    /// Neuere Zeichen lehnt die Regel ab (v4.7, Befund krypto-2): Für Zeichen, die in Unicode 15.0 vergeben sind, ist
    /// die NFC nach der Stabilitätsregel in jeder späteren Unicode-Version gleich – in Foundation wie im C#-Kern unter
    /// Windows. Foundation (macOS 26) kennt Unicode 16 nur zum Teil; ein Passwort mit solchen Zeichen ergäbe nach einem
    /// Systemupdate andere Argon2-Bytes. Nichtzeichen (U+FFFE …) und private Zeichen sind seit Unicode 1.1/2.0 vergeben.
    public static let unicodeVersion = (major: 15, minor: 0)

    public static func check(_ password: String) -> (bits: Double, ok: Bool) {
        check(password, userInputs: defaultUserInputs())
    }

    /// Wie `check(_:)`, mit eigenen Benutzereingaben (für Tests).
    static func check(_ password: String, userInputs: [String]) -> (bits: Double, ok: Bool) {
        let normalized = normalized(password)
        let bits = PasswordStrength.estimate(normalized, userInputs: userInputs).bits
        return (bits, satisfied(normalized: normalized, bits: bits))
    }

    /// Die Regel auf ein schon abgebildetes Passwort mit seiner Schätzung (auch für SiegelStaerkeExport).
    static func satisfied(normalized: String, bits: Double) -> Bool {
        bits >= minimumBits
            && normalized.count >= minimumLength
            && normalized.utf8.count <= maximumUTF8Bytes
            && usesStableCharacters(normalized)
    }

    /// Jeder Skalar ist spätestens in `unicodeVersion` vergeben (Unicode-Eigenschaft Age, unveränderlich).
    static func usesStableCharacters(_ text: String) -> Bool {
        text.unicodeScalars.allSatisfy { scalar in
            guard let age = scalar.properties.age else { return false }
            return age.major < unicodeVersion.major || (age.major == unicodeVersion.major && age.minor <= unicodeVersion.minor)
        }
    }

    /// RFC 8265 OpaqueString wie SPEC §1.1: jedes Zeichen der Kategorie Zs ausser U+0020 → U+0020, dann NFC.
    /// Nichts trimmen.
    static func normalized(_ password: String) -> String {
        var scalars = String.UnicodeScalarView()
        var changed = false
        for scalar in password.unicodeScalars {
            if scalar.value != 0x20, scalar.properties.generalCategory == .spaceSeparator {
                scalars.append(" ")
                changed = true
            } else {
                scalars.append(scalar)
            }
        }
        let mapped = changed ? String(scalars) : password
        return mapped.precomposedStringWithCanonicalMapping
    }

    /// "siegel", Benutzername und voller Name des macOS-Kontos samt Teilen.
    static func defaultUserInputs() -> [String] {
        userInputs(userName: NSUserName(), fullName: NSFullUserName())
    }

    /// Teile: ganzer Wert, Wörter (an Leerraum und Satzzeichen getrennt), Wörter zusammengeschrieben,
    /// je mit Umschrift der Umlaute (ü → ue und u, ß → ss).
    static func userInputs(userName: String, fullName: String) -> [String] {
        var result: [String] = []
        func add(_ value: String) {
            let lowered = normalized(value).lowercased()
            guard !lowered.isEmpty else { return }
            for variant in asciiVariants(lowered) where !result.contains(variant) {
                result.append(variant)
            }
        }
        add("siegel")
        for value in [userName, fullName] {
            add(value)
            let parts = value.split { !$0.isLetter && !$0.isNumber }.map(String.init)
            if parts.count > 1 {
                for part in parts where part.count >= 2 { add(part) }
                add(parts.joined())
            }
        }
        return result
    }

    /// Schreibvarianten ohne Umlaute (zuerst das Original).
    static func asciiVariants(_ word: String) -> [String] {
        let long: [(String, String)] = [("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss"),
                                         ("é", "e"), ("è", "e"), ("ê", "e"), ("à", "a"), ("ç", "c")]
        let short: [(String, String)] = [("ä", "a"), ("ö", "o"), ("ü", "u"), ("ß", "ss"),
                                          ("é", "e"), ("è", "e"), ("ê", "e"), ("à", "a"), ("ç", "c")]
        var variants = [word]
        for table in [long, short] {
            var v = word
            for (from, to) in table { v = v.replacingOccurrences(of: from, with: to) }
            if !variants.contains(v) { variants.append(v) }
        }
        return variants
    }
}
