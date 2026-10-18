import AppKit
import CoreGraphics
import SwiftUI

/// Externe Bildschirme (SPEC §6): Liegt das Fenster auf einem Bildschirm mit `CGDisplayIsBuiltin == 0`
/// (Sidecar, AirPlay, Monitor), bleiben sichtbares Passwort und Notfallcode verdeckt – ausser die
/// Einstellung „Geheimnisse auf externen Bildschirmen zeigen“ ist an.
///
/// Befund #6: Beim **Spiegeln** (AirPlay, Beamer, „Eingebauten Bildschirm spiegeln“) vertritt der eingebaute
/// Bildschirm das ganze Spiegel-Set; `CGDisplayIsBuiltin` ist dort 1, das Bild erscheint aber auch extern.
/// Darum zählt jeder Bildschirm in einem Spiegel-Set als extern. Und ein Fenster, das über zwei Bildschirme
/// ragt (ohne „Bildschirme verwenden verschiedene Spaces“), wird an jedem Bildschirm geprüft, den es schneidet,
/// nicht nur am grössten Anteil (`window.screen`).
@MainActor
public enum ExternalDisplayGuard {
    public static func isOnExternalDisplay(_ window: NSWindow?) -> Bool {
        // Ohne Bildschirm (Offscreen) ist nichts sichtbar.
        guard let window, let hauptschirm = window.screen else { return false }
        var schirme = [hauptschirm]
        for screen in NSScreen.screens where screen != hauptschirm && screen.frame.intersects(window.frame) {
            schirme.append(screen)
        }
        return schirme.contains { isExternal($0) }
    }

    /// Extern: nicht eingebaut, oder Teil eines Spiegel-Sets (das Bild erscheint auch auf einem anderen Gerät).
    static func isExternal(_ screen: NSScreen) -> Bool {
        guard let nummer = screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber else {
            return true
        }
        let id = CGDirectDisplayID(nummer.uint32Value)
        return CGDisplayIsBuiltin(id) == 0 || CGDisplayIsInMirrorSet(id) != 0
    }

    /// Darf ein Geheimnis in diesem Fenster gezeichnet werden?
    public static func allowsSecrets(in window: NSWindow?, allowExternal: Bool) -> Bool {
        guard let window else { return false }
        guard WindowGuard.isProtected(window) else { return false }
        if !allowExternal && isOnExternalDisplay(window) { return false }
        return true
    }
}

/// Meldet das Fenster, in dem eine SwiftUI-Ansicht liegt, und schützt es sofort.
struct WindowProbe: NSViewRepresentable {
    var onWindow: @MainActor (NSWindow?) -> Void

    func makeNSView(context: Context) -> ProbeView {
        let view = ProbeView()
        view.onWindow = onWindow
        return view
    }

    func updateNSView(_ nsView: ProbeView, context: Context) {
        nsView.onWindow = onWindow
    }

    final class ProbeView: NSView {
        var onWindow: (@MainActor (NSWindow?) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window { WindowGuard.shared.protect(window) }
            let w = window
            let callback = onWindow
            // RunLoop statt DispatchQueue: läuft auch in verschachtelten Ereignisschleifen (Modal, Druck).
            RunLoop.main.perform(inModes: [.common]) {
                MainActor.assumeIsolated { callback?(w) }
            }
        }

        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }
}

/// Zeigt `content` nur, wenn das Fenster geschützt ist und nicht auf einem externen Bildschirm liegt
/// (SPEC §6 „Geheimnis-Ansichten prüfen vor dem Zeichnen“). Sonst den Platzhalter. Liegt es nur auf einem
/// externen Bildschirm, bekommt der Platzhalter eine `reveal`-Aktion („Hier zeigen“, gilt nur für diese
/// Ansicht) – sonst wäre ein Mac ohne eingebauten Bildschirm im gesperrten Zustand ohne Notfallcode-Weg.
public struct SecretGate<Content: View, Placeholder: View>: View {
    @Environment(AppSettings.self) private var settings: AppSettings?
    @Environment(\.secretGateOverride) private var override
    @State private var window: NSWindow?
    @State private var lastProtected = false
    @State private var tick = 0
    @State private var manualReveal = false
    private let content: Content
    private let placeholder: ((() -> Void)?) -> Placeholder

    public init(@ViewBuilder content: () -> Content, @ViewBuilder placeholder: @escaping ((() -> Void)?) -> Placeholder) {
        self.content = content()
        self.placeholder = placeholder
    }

    private enum Zustand { case show, external, unprotected }

    private var zustand: Zustand {
        _ = tick
        guard let window, WindowGuard.isProtected(window) else { return .unprotected }
        let allowExternal = (settings?.showSecretsOnExternalDisplays ?? false) || manualReveal
        let external = override == .external || ExternalDisplayGuard.isOnExternalDisplay(window)
        if !allowExternal && external { return .external }
        return .show
    }

    public var body: some View {
        ZStack {
            switch zustand {
            case .show: content
            case .external: placeholder({ manualReveal = true })
            case .unprotected: placeholder(nil)
            }
        }
        .background(WindowProbe { neu in
            window = neu
            lastProtected = WindowGuard.isProtected(neu)
            tick += 1
        })
        // Schutz kann sich ändern (z. B. fremder Code setzt sharingType zurück): bei jedem Fenster-Update prüfen.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didUpdateNotification)) { note in
            guard let window, (note.object as? NSWindow) === window else { return }
            let jetzt = WindowGuard.isProtected(window)
            if jetzt != lastProtected {
                lastProtected = jetzt
                tick += 1
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didChangeScreenNotification)) { note in
            if (note.object as? NSWindow) === window {
                manualReveal = false
                tick += 1
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didChangeScreenParametersNotification)) { _ in
            tick += 1
        }
        // Ohne getrennte Spaces kann das Fenster über zwei Bildschirme ragen, ohne den Bildschirm zu wechseln.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didMoveNotification)) { note in
            guard !NSScreen.screensHaveSeparateSpaces, (note.object as? NSWindow) === window else { return }
            tick += 1
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResizeNotification)) { note in
            guard !NSScreen.screensHaveSeparateSpaces, (note.object as? NSWindow) === window else { return }
            tick += 1
        }
    }
}

/// Standard-Platzhalter für verdeckte Geheimnisse.
public struct HiddenSecretPlaceholder: View {
    var reveal: (() -> Void)?

    public init(reveal: (() -> Void)? = nil) {
        self.reveal = reveal
    }

    public var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "eye.slash")
            Text(reveal == nil ? "Verdeckt" : "Auf diesem Bildschirm verdeckt")
            if let reveal {
                Button("Hier zeigen", action: reveal)
                    .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    .foregroundStyle(Theme.text)
            }
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.secondary)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Geheimnis verborgen")
    }
}

/// Nur für Snapshots: Zustand der Geheimnis-Ansichten erzwingen (externer Bildschirm).
public enum SecretGateOverride: Sendable, Equatable {
    case external
}

// Klassischer EnvironmentKey statt @Entry: baut auch ohne SwiftUI-Makro-Plugin (Command Line Tools, ältere Xcode).
private struct SecretGateOverrideKey: EnvironmentKey {
    static let defaultValue: SecretGateOverride? = nil
}

extension EnvironmentValues {
    var secretGateOverride: SecretGateOverride? {
        get { self[SecretGateOverrideKey.self] }
        set { self[SecretGateOverrideKey.self] = newValue }
    }
}

extension View {
    @_spi(Snapshots) public func snapshotSecretGate(_ value: SecretGateOverride?) -> some View {
        environment(\.secretGateOverride, value)
    }
}
