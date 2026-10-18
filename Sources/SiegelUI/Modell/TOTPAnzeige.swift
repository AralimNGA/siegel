import Foundation
import SiegelCore

// 2FA-Codes (SPEC v4 §18) für die Oberfläche. Gerechnet wird nur im Kern (`TOTP.parse`, `TOTP.code`); die
// Oberfläche liest Code, Restsekunden und die Periode aus `TOTP.Parameters`. Snapshots können eine eigene Quelle
// einsetzen (nur, falls der Kern nichts rechnet).

/// Ablesung eines 2FA-Codes zu einem Zeitpunkt.
public struct TOTPReading: Sendable, Equatable {
    public let code: String
    /// Sekunden, bis der Code wechselt (1 … Periode).
    public let remaining: Int
    /// Periode in Sekunden (15 … 120, meist 30).
    public let period: Int

    public init(code: String, remaining: Int, period: Int) {
        self.code = code
        self.remaining = remaining
        self.period = period
    }

    /// Ziffern des Codes (6 oder 8).
    public var digits: Int { code.count }

    /// „123 456“ bzw. „1234 5678“ (zum Lesen; kopiert wird ohne Leerzeichen).
    public var grouped: String {
        guard code.count >= 6 else { return code }
        let mitte = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<mitte]) + " " + String(code[mitte...])
    }
}

/// Prüfergebnis eines eingegebenen 2FA-Geheimnisses (Bearbeiten).
public enum TOTPCheck: Sendable, Equatable {
    case empty
    case valid(digits: Int, period: Int)
    case invalid
}

/// Quelle für 2FA-Codes (die App: der Kern; Snapshots: eine Attrappe, solange der Kern-Platzhalter nichts rechnet).
public protocol TOTPSource: Sendable {
    /// nil = kein gültiges Geheimnis.
    func reading(_ uriOrSecret: String, at date: Date) -> TOTPReading?
}

/// Die echte Quelle: `TOTP.parse` + `TOTP.code` aus SiegelCore.
public struct CoreTOTPSource: TOTPSource {
    public init() {}

    public func reading(_ uriOrSecret: String, at date: Date) -> TOTPReading? {
        guard let parameter = try? TOTP.parse(uriOrSecret) else { return nil }
        let jetzt = TOTP.code(parameter, at: date)
        // Periode aus den Parametern (TOTP.parse prüft 15…120 s).
        let gueltig = (15...120).contains(parameter.period) ? parameter.period : max(jetzt.remaining, 30)
        return TOTPReading(code: jetzt.code, remaining: min(max(jetzt.remaining, 1), gueltig), period: gueltig)
    }
}

/// Zugriff der Oberfläche auf 2FA-Codes.
@MainActor
public enum TOTPDisplay {
    static var source: any TOTPSource = CoreTOTPSource()

    /// Aktueller Code (nil = ungültiges Geheimnis).
    public static func reading(_ secret: String, at date: Date = Date()) -> TOTPReading? {
        let text = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        return source.reading(text, at: date)
    }

    /// Prüfung beim Bearbeiten (über `TOTP.parse` im Kern).
    public static func check(_ secret: String) -> TOTPCheck {
        guard !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return .empty }
        guard let ablesung = reading(secret) else { return .invalid }
        return .valid(digits: ablesung.digits, period: ablesung.period)
    }

    /// Grund, warum ein Geheimnis ungültig ist (fester `totpInvalid`-Code aus `TOTP.parse`, für die Meldung).
    public static func problem(_ secret: String) -> SiegelError {
        let text = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            _ = try TOTP.parse(text)
            return .totpInvalid("totp.parse")
        } catch let error as SiegelError {
            return error
        } catch {
            return .totpInvalid("totp.parse")
        }
    }

    /// Nur für SiegelSnapshots: eigene Quelle einsetzen.
    @_spi(Snapshots) public static func snapshotUse(_ source: any TOTPSource) {
        self.source = source
    }
}
