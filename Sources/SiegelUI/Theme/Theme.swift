import AppKit
import SwiftUI

/// Farben, Schriften und Masse (SPEC §7). Strikt monochrom: nur diese vier Farben.
public enum Theme {
    // MARK: Farben (exakt §7)

    /// Hintergrund #FFFFFF
    public static let background = Color(red: 1, green: 1, blue: 1)
    /// Text #000000
    public static let text = Color(red: 0, green: 0, blue: 0)
    /// Nebentext #6E6E6E
    public static let secondary = Color(red: 0x6E / 255.0, green: 0x6E / 255.0, blue: 0x6E / 255.0)
    /// Haarlinien #E5E5E5
    public static let hairline = Color(red: 0xE5 / 255.0, green: 0xE5 / 255.0, blue: 0xE5 / 255.0)

    public static let nsBackground = NSColor(srgbRed: 1, green: 1, blue: 1, alpha: 1)
    public static let nsText = NSColor(srgbRed: 0, green: 0, blue: 0, alpha: 1)
    public static let nsSecondary = NSColor(srgbRed: 0x6E / 255.0, green: 0x6E / 255.0, blue: 0x6E / 255.0, alpha: 1)
    public static let nsHairline = NSColor(srgbRed: 0xE5 / 255.0, green: 0xE5 / 255.0, blue: 0xE5 / 255.0, alpha: 1)

    // MARK: Schriften (Systemschrift; ab 20 pt automatisch SF Pro Display)

    /// Wortmarke «Siegel»: SF Pro Display Semibold
    public static let wordmark = Font.system(size: 30, weight: .semibold)
    /// Grosser Seitentitel
    public static let title = Font.system(size: 24, weight: .semibold)
    /// Abschnittstitel in Seiten
    public static let heading = Font.system(size: 15, weight: .semibold)
    public static let body = Font.system(size: 13)
    public static let bodyMedium = Font.system(size: 13, weight: .medium)
    public static let caption = Font.system(size: 12)
    /// Kleine Abschnittsbeschriftung (Einstellungen)
    public static let label = Font.system(size: 11, weight: .semibold)
    /// Passwörter und Codes: SF Mono
    public static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }

    public static func nsFont(_ size: CGFloat = 13, weight: NSFont.Weight = .regular) -> NSFont {
        .systemFont(ofSize: size, weight: weight)
    }

    public static func nsMono(_ size: CGFloat, weight: NSFont.Weight = .regular) -> NSFont {
        .monospacedSystemFont(ofSize: size, weight: weight)
    }

    // MARK: Masse

    /// Logo im Sperrbildschirm und in der Einrichtung (u = 4 pt)
    public static let markLarge: CGFloat = 84
    /// Logo in der Seitenleiste (u = 1 pt)
    public static let markSmall: CGFloat = 21
    public static let corner: CGFloat = 8
    public static let fieldHeight: CGFloat = 36
    public static let buttonHeight: CGFloat = 34
    /// Breite der schmalen Formularspalte
    public static let formWidth: CGFloat = 340
    /// Breite der Textspalte
    public static let columnWidth: CGFloat = 460
    public static let hairlineWidth: CGFloat = 1
}
