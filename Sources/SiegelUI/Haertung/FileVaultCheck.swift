import AppKit
import SiegelCore

/// FileVault-Hinweis (SPEC §6): prüft `volumeIsEncryptedKey` des Tresor-Ordners.
@MainActor
public enum FileVaultCheck {
    public static let hint = "FileVault ist aus: Exporte, Druckaufträge und Arbeitsspeicherabbilder sind auf diesem Mac nicht geschützt."
    static let settingsURL = "x-apple.systempreferences:com.apple.preference.security?FileVault"

    /// true = verschlüsselt, false = nicht verschlüsselt, nil = unbekannt.
    public static func isEncrypted(_ directory: URL) -> Bool? {
        VaultStore.volumeIsEncrypted(directory)
    }

    /// Öffnet die FileVault-Einstellungen.
    public static func openSettings() {
        guard let url = URL(string: settingsURL) else { return }
        NSWorkspace.shared.open(url)
    }
}
