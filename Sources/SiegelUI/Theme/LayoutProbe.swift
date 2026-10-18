import SwiftUI

/// Nur für SiegelSnapshots: sammelt die Rahmen ausgewählter Ansichten (Fensterpunkte, Ursprung oben links), damit das
/// Snapshot-Programm prüfen kann, dass sich nichts überdeckt (Befund design-2). In der App ist kein Sammler gesetzt –
/// dann beobachtet `layoutProbe(_:)` nichts.
@_spi(Snapshots) @MainActor public final class LayoutRecorder {
    public private(set) var frames: [String: CGRect] = [:]

    public init() {}

    func record(_ name: String, _ frame: CGRect) {
        frames[name] = frame
    }
}

extension EnvironmentValues {
    @Entry var layoutRecorder: LayoutRecorder? = nil
}

extension View {
    @_spi(Snapshots) public func snapshotLayoutRecorder(_ recorder: LayoutRecorder?) -> some View {
        environment(\.layoutRecorder, recorder)
    }

    /// Meldet den Rahmen an den Sammler der Snapshots; ohne Sammler (App) ohne Wirkung.
    func layoutProbe(_ name: String) -> some View {
        modifier(LayoutProbeModifier(name: name))
    }
}

private struct LayoutProbeModifier: ViewModifier {
    let name: String
    @Environment(\.layoutRecorder) private var recorder

    func body(content: Content) -> some View {
        if let recorder {
            content.onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: { rahmen in
                recorder.record(name, rahmen)
            }
        } else {
            content
        }
    }
}
