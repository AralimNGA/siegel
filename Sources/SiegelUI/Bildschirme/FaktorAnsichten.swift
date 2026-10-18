import AppKit
import QuartzCore
import SiegelCore
import SwiftUI

// Ansichten der Faktoren (SPEC v4 §13–§16): Fortschritt beim Einsammeln, Kamera-Sheet für die
// Schlüsselkarte, Sheet für den Sicherheitsschlüssel. Strikt schwarz/weiss wie der Rest.

extension FactorUI {
    /// Aufforderung, solange ein Faktor eingesammelt wird.
    static func prompt(_ kind: FactorKind) -> String {
        switch kind {
        case .secureEnclave: "Lege den Finger auf Touch ID."
        case .card: "Halte deine Schlüsselkarte vor die Kamera."
        case .securityKey: "Stecke den Sicherheitsschlüssel ein und berühre ihn."
        }
    }
}

// MARK: - Fortschritt

/// Ein Faktor als kleine Kapsel: offen (grau), aktiv (schwarzer Rand), erledigt (schwarz gefüllt), gescheitert.
struct FactorPill: View {
    var symbol: String
    var title: String
    var status: FactorStepStatus

    var body: some View {
        HStack(spacing: 6) {
            ZStack {
                switch status {
                case .done:
                    Image(systemName: "checkmark")
                        .font(.system(size: 10, weight: .bold))
                case .failed:
                    Image(systemName: "exclamationmark")
                        .font(.system(size: 10, weight: .bold))
                case .active:
                    PulsingSymbol(symbol: symbol)
                case .pending:
                    Image(systemName: symbol)
                        .font(.system(size: 11, weight: .medium))
                }
            }
            .frame(width: 14)
            Text(title)
                .font(Theme.caption.weight(.medium))
        }
        .foregroundStyle(foreground)
        .padding(.horizontal, 11)
        .frame(height: 26)
        // RoundedRectangle statt Capsule: Capsule.strokeBorder zeichnet hier senkrechte Kanten (gemessen).
        .background(RoundedRectangle(cornerRadius: 13, style: .circular).fill(status == .done ? Theme.text : Theme.background))
        .overlay(
            RoundedRectangle(cornerRadius: 13, style: .circular)
                .strokeBorder(border, lineWidth: status == .active || status == .failed ? 1.5 : 1)
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title + ", " + statusText)
    }

    private var foreground: Color {
        switch status {
        case .done: Theme.background
        case .pending: Theme.secondary
        case .active, .failed: Theme.text
        }
    }

    private var border: Color {
        switch status {
        case .done: Theme.text
        case .pending: Theme.hairline
        case .active, .failed: Theme.text
        }
    }

    private var statusText: String {
        switch status {
        case .done: "erledigt"
        case .pending: "offen"
        case .active: "läuft"
        case .failed: "fehlgeschlagen"
        }
    }
}

/// SF Symbol, das ruhig pulsiert (aktiver Faktor).
struct PulsingSymbol: View {
    var symbol: String
    var size: CGFloat = 11

    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 30)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            let phase = 0.55 + 0.45 * (0.5 + 0.5 * cos(t * 2 * .pi / 1.4))
            Image(systemName: symbol)
                .font(.system(size: size, weight: .medium))
                .opacity(phase)
        }
    }
}

/// Fortschritt beim Einsammeln: Kapseln für Passwort und Faktoren, darunter die Aufforderung bzw. der Fehler
/// mit „Erneut versuchen“ und (wenn der Faktor hier nicht nutzbar ist) dem Notfallweg.
struct FactorProgressView: View {
    var kinds: [FactorKind]
    var status: [FactorKind: FactorStepStatus]
    var active: FactorKind?
    var failure: FactorFailure?
    /// Passwort als erste Kapsel (Sperrbildschirm).
    var passwordStatus: FactorStepStatus?
    /// Text vor dem Start („Zum Öffnen nötig“).
    var caption: String?
    var opening = false
    var alignment: HorizontalAlignment = .center
    var onRetry: (() -> Void)?
    var onRecovery: (() -> Void)?

    var body: some View {
        VStack(alignment: alignment, spacing: 10) {
            if let caption {
                Text(caption)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
            }
            HStack(spacing: 6) {
                if let passwordStatus {
                    FactorPill(symbol: FactorUI.passwordSymbol, title: "Passwort", status: passwordStatus)
                    connector(done: passwordStatus == .done)
                }
                ForEach(Array(kinds.enumerated()), id: \.offset) { index, kind in
                    if index > 0 { connector(done: status[kind] == .done || status[kind] == .active) }
                    FactorPill(symbol: FactorUI.symbol(kind), title: FactorUI.name(kind),
                               status: status[kind] ?? .pending)
                }
            }
            line
        }
    }

    private func connector(done: Bool) -> some View {
        Rectangle()
            .fill(done ? Theme.text : Theme.hairline)
            .frame(width: 10, height: 1)
    }

    @ViewBuilder
    private var line: some View {
        if let failure {
            VStack(alignment: alignment, spacing: 8) {
                MessageText(failure.message)
                    .multilineTextAlignment(alignment == .center ? .center : .leading)
                HStack(spacing: 14) {
                    if failure.offerRecovery, let onRecovery {
                        Button("Notfallcode verwenden", action: onRecovery)
                            .buttonStyle(CompactButtonStyle(primary: true))
                    }
                    if let onRetry {
                        // Vorübergehend (Touch ID gesperrt/nicht erreichbar): „Erneut versuchen“ ist der Hauptknopf.
                        // Mit Notfallweg bleibt es ein sichtbarer Knopf mit Rahmen, kein leiser Link (Befund bau-1): Die
                        // Diagnose „Schlüssel fehlt“ kann sich irren, und der Notfallweg setzt auf Stufe 1 zurück.
                        Button("Erneut versuchen", action: onRetry)
                            .buttonStyle(CompactButtonStyle(primary: failure.temporary && !failure.offerRecovery))
                    }
                }
            }
        } else if let active {
            Text(FactorUI.prompt(active))
                .font(Theme.caption)
                .foregroundStyle(Theme.text)
        } else if opening {
            Text("Tresor wird geöffnet …")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
        }
    }
}

/// Kurzform für eine `FactorCollection`.
struct CollectionProgress: View {
    let collection: FactorCollection
    var caption: String?
    var alignment: HorizontalAlignment = .leading
    var onRetry: (() -> Void)?
    var onRecovery: (() -> Void)?

    var body: some View {
        FactorProgressView(kinds: collection.kinds, status: collection.status, active: collection.active,
                           failure: collection.failure, caption: caption, alignment: alignment,
                           onRetry: onRetry, onRecovery: onRecovery)
    }
}

/// Faktoren eines Kopfs vor dem Start (nur Anzeige, was nötig ist).
struct FactorRequirementLine: View {
    var factors: FactorSet
    var prefix = "Dazu nötig:"

    var body: some View {
        HStack(spacing: 8) {
            Text(prefix)
                .foregroundStyle(Theme.secondary)
            ForEach(factors.kinds, id: \.self) { kind in
                HStack(spacing: 4) {
                    Image(systemName: FactorUI.symbol(kind))
                        .font(.system(size: 11, weight: .medium))
                    Text(FactorUI.name(kind))
                }
            }
        }
        .font(Theme.caption)
        .foregroundStyle(Theme.text)
    }
}

// MARK: - Sheets (Ebene im Hauptfenster)

/// Zeigt Kamera- bzw. Schlüssel-Sheet über allem; der Rest des Fensters ist dann nicht bedienbar.
struct FactorSheetHost: View {
    let model: AppModel

    var body: some View {
        if let scan = model.cardScan {
            SheetBackdrop {
                CardScanSheet(model: model, state: scan)
            }
            .transition(.opacity)
        } else if let touch = model.keyTouch {
            SheetBackdrop {
                SecurityKeySheet(model: model, state: touch)
            }
            .transition(.opacity)
        }
    }
}

/// Abgedunkelter Hintergrund mit einer weissen Karte in der Mitte.
struct SheetBackdrop<Content: View>: View {
    var content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ZStack {
            Theme.text.opacity(0.16)
                .ignoresSafeArea()
                .contentShape(Rectangle())
                .onTapGesture {}
            content
                .padding(26)
                .frame(width: 480)
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Theme.background)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
                )
                // Ohne compositingGroup wirft jedes Kind einen eigenen Schatten.
                .compositingGroup()
                .shadow(color: Theme.text.opacity(0.14), radius: 28, y: 12)
        }
    }
}

/// Kopf eines Sheets: Symbol, Titel, Erklärung.
struct SheetHeader: View {
    var symbol: String
    var title: String
    var message: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: symbol)
                .font(.system(size: 17, weight: .medium))
                .frame(width: 36, height: 36)
                .background(Circle().strokeBorder(Theme.hairline, lineWidth: 1))
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(Theme.heading)
                Text(Typo.keepCompounds(message))
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }
}

/// Kamera-Sheet: Vorschau aus `QRScanner.previewLayer` (ohne Kamera ein Platzhalter), Abtipp-Notlösung.
/// Bilder werden nie gespeichert; der Scanner stoppt nach der Erkennung und beim Schliessen.
struct CardScanSheet: View {
    let model: AppModel
    @Bindable var state: CardScanState

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SheetHeader(symbol: "qrcode.viewfinder", title: state.title,
                        message: state.typing ? state.typingMessage : state.message)
            if state.typing {
                typing.padding(.top, 20)
                if let error = state.error {
                    MessageText(error)
                        .padding(.top, 12)
                }
            } else {
                camera.padding(.top, 18)
            }
            HStack(spacing: 12) {
                if state.typing {
                    if state.camera != .denied, state.camera != .unavailable {
                        Button("Zur Kamera") { model.cardScanShowCamera() }
                            .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    }
                } else {
                    Button("Code von der Karte abtippen") { model.cardScanShowTyping() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                }
                Spacer()
                Button("Abbrechen") { model.cancelCardScan() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                if state.typing {
                    Button("Prüfen") { model.cardScanSubmitTyped() }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(RecoveryCodeFormatting.significant(state.typed).count != 55)
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(.top, 20)
        }
    }

    private var camera: some View {
        VStack(alignment: .leading, spacing: 10) {
            ZStack {
                if let layer = state.previewLayer, state.camera == .running {
                    // Befund hygiene-4: Das Kamerabild zeigt die Karte (q) – auf externen und gespiegelten
                    // Bildschirmen verdeckt wie Passwort und Notfallcode. Die Erkennung braucht die Vorschau nicht.
                    SecretGate {
                        CameraPreview(layer: layer)
                    } placeholder: { reveal in
                        CameraPreviewHidden(reveal: reveal)
                    }
                } else {
                    CameraPlaceholder(camera: state.camera)
                }
                Viewfinder(light: state.camera == .running)
                    .frame(width: 136, height: 136)
                if state.recognized {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 44, weight: .regular))
                        .foregroundStyle(Theme.text)
                        .background(Circle().fill(Theme.background))
                }
            }
            .frame(height: 206)
            .frame(maxWidth: .infinity)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Kamera-Vorschau")

            cameraStatus
        }
    }

    @ViewBuilder
    private var cameraStatus: some View {
        if let error = state.error {
            MessageText(error)
        } else {
            cameraStatusLine
        }
    }

    @ViewBuilder
    private var cameraStatusLine: some View {
        switch state.camera {
        case .starting:
            NoticeLine("Kamera wird gestartet …", symbol: "camera")
        case .running, .placeholder:
            NoticeLine("Suche QR-Code … Halte die Karte ruhig, etwa 20 cm vor der Kamera.", symbol: "viewfinder")
        case .denied:
            HStack(spacing: 10) {
                MessageText("Siegel darf die Kamera nicht verwenden.", symbol: "video.slash")
                Button("Systemeinstellungen öffnen") { model.openCameraSettings() }
                    .buttonStyle(QuietButtonStyle(font: Theme.caption.weight(.semibold)))
            }
        case .unavailable:
            MessageText("Keine Kamera gefunden. Tippe den Code von der Karte ab.", symbol: "video.slash")
        }
    }

    private var typing: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Befund design-4: neutral – passt zur gedruckten Karte (Code neben dem QR-Code) und zur Abschrift.
            Text("Kartencode, 11 Gruppen")
                .font(Theme.caption.weight(.medium))
                .foregroundStyle(Theme.secondary)
            RecoveryCodeField("XXXXX-XXXXX-…", text: $state.typed, groups: 11, fontSize: 14, autoFocus: true) {
                model.cardScanSubmitTyped()
            }
            HStack {
                Text("Gross- und Kleinschreibung und Bindestriche spielen keine Rolle.")
                Spacer()
                Text("\(RecoveryCodeFormatting.significant(state.typed).count) / 55")
                    .monospacedDigit()
            }
            .font(Theme.caption)
            .foregroundStyle(Theme.secondary)
        }
    }
}

/// Verdeckte Kamera-Vorschau (externer oder gespiegelter Bildschirm, ungeschütztes Fenster): Sucher und Häkchen
/// bleiben darüber sichtbar, der Scanner läuft weiter. Die Texte stehen über und unter dem Sucher, „Hier zeigen“
/// in seiner Mitte.
struct CameraPreviewHidden: View {
    var reveal: (() -> Void)?

    var body: some View {
        ZStack {
            Theme.background
            VStack(spacing: 6) {
                Image(systemName: "eye.slash")
                    .font(.system(size: 20, weight: .light))
                if let reveal {
                    Button("Hier zeigen", action: reveal)
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                }
            }
            VStack {
                Text("Vorschau auf diesem Bildschirm verdeckt")
                Spacer(minLength: 0)
                Text("Halte die Karte trotzdem vor die Kamera.")
            }
            .font(Theme.caption)
            .lineLimit(1)
            .padding(.vertical, 11)
        }
        .foregroundStyle(Theme.secondary)
    }
}

/// Platzhalter ohne Kamerabild (Attrappe, Snapshot, Kamera aus).
struct CameraPlaceholder: View {
    var camera: CardScanState.Camera

    var body: some View {
        ZStack {
            Theme.background
            VStack(spacing: 6) {
                Image(systemName: camera == .denied || camera == .unavailable ? "video.slash" : "camera")
                    .font(.system(size: 20, weight: .light))
                Text(camera == .starting ? "Kamera wird gestartet"
                     : (camera == .denied || camera == .unavailable ? "Kamera aus" : "Kamera-Vorschau"))
                    .font(.system(size: 11))
            }
            .foregroundStyle(Theme.secondary)
        }
    }
}

/// Sucher-Ecken in der Mitte der Vorschau.
struct Viewfinder: View {
    /// Über einem Kamerabild weiss mit feinem Rand, sonst schwarz.
    var light: Bool

    var body: some View {
        Canvas { context, size in
            let laenge: CGFloat = 26
            var pfad = Path()
            let w = size.width, h = size.height
            pfad.move(to: CGPoint(x: 0, y: laenge)); pfad.addLine(to: .zero); pfad.addLine(to: CGPoint(x: laenge, y: 0))
            pfad.move(to: CGPoint(x: w - laenge, y: 0)); pfad.addLine(to: CGPoint(x: w, y: 0)); pfad.addLine(to: CGPoint(x: w, y: laenge))
            pfad.move(to: CGPoint(x: w, y: h - laenge)); pfad.addLine(to: CGPoint(x: w, y: h)); pfad.addLine(to: CGPoint(x: w - laenge, y: h))
            pfad.move(to: CGPoint(x: laenge, y: h)); pfad.addLine(to: CGPoint(x: 0, y: h)); pfad.addLine(to: CGPoint(x: 0, y: h - laenge))
            if light {
                context.stroke(pfad, with: .color(Theme.text.opacity(0.35)), style: StrokeStyle(lineWidth: 5, lineCap: .round))
                context.stroke(pfad, with: .color(Theme.background), style: StrokeStyle(lineWidth: 3, lineCap: .round))
            } else {
                context.stroke(pfad, with: .color(Theme.text), style: StrokeStyle(lineWidth: 3, lineCap: .round))
            }
        }
        .allowsHitTesting(false)
    }
}

/// Bettet die Vorschau-Ebene des Scanners ein (Ebene wird nur angezeigt, nie gespeichert).
struct CameraPreview: NSViewRepresentable {
    let layer: CALayer

    func makeNSView(context: Context) -> PreviewHostView {
        let view = PreviewHostView()
        view.wantsLayer = true
        view.layer?.backgroundColor = NSColor.black.cgColor
        view.preview = layer
        return view
    }

    func updateNSView(_ view: PreviewHostView, context: Context) {
        if view.preview !== layer { view.preview = layer }
    }

    final class PreviewHostView: NSView {
        var preview: CALayer? {
            didSet {
                oldValue?.removeFromSuperlayer()
                if let preview { layer?.addSublayer(preview) }
                needsLayout = true
            }
        }

        override func layout() {
            super.layout()
            preview?.frame = bounds
        }

        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }
}

/// Sicherheitsschlüssel: „einstecken und berühren“, Geräteliste bei mehreren Schlüsseln.
struct SecurityKeySheet: View {
    let model: AppModel
    @Bindable var state: KeyTouchState

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SheetHeader(symbol: "key.horizontal", title: state.title, message: state.message)
            center.padding(.top, 22)
            if let error = state.error {
                VStack(alignment: .leading, spacing: 8) {
                    MessageText(error)
                    Button("Erneut versuchen") { model.retrySecurityKey() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption.weight(.semibold)))
                }
                .padding(.top, 14)
            }
            Text("FIDO2-Schlüssel mit hmac-secret, z. B. YubiKey 5. Mit echter Hardware noch ungetestet.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 18)
            HStack {
                Spacer()
                Button("Abbrechen") { model.cancelKeyTouch() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.top, 18)
        }
    }

    @ViewBuilder
    private var center: some View {
        switch state.phase {
        case .searching:
            VStack(spacing: 14) {
                KeyGlyph(touching: false)
                Text("Kein Sicherheitsschlüssel gefunden. Stecke ihn an einen USB-Anschluss.")
                    .font(Theme.body)
                    .multilineTextAlignment(.center)
                ProgressLine(active: true)
                    .frame(width: 180)
            }
            .frame(maxWidth: .infinity)
        case .choose:
            VStack(alignment: .leading, spacing: 8) {
                Text("Mehrere Schlüssel angeschlossen – welchen verwenden?")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                VStack(spacing: 0) {
                    ForEach(Array(state.devices.enumerated()), id: \.offset) { index, device in
                        if index > 0 { Hairline() }
                        Button {
                            model.chooseSecurityKey(device)
                        } label: {
                            HStack(spacing: 10) {
                                Image(systemName: "key.horizontal")
                                    .font(.system(size: 12))
                                Text(device.name)
                                    .font(Theme.body)
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 10, weight: .semibold))
                                    .foregroundStyle(Theme.secondary)
                            }
                            .padding(.horizontal, 12)
                            .frame(height: 40)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(PlainActionButtonStyle())
                    }
                }
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
            }
        case let .touching(name):
            VStack(spacing: 14) {
                KeyGlyph(touching: true)
                VStack(spacing: 4) {
                    Text("Berühre jetzt den Schlüssel")
                        .font(Theme.bodyMedium)
                    Text("„" + name + "“ blinkt – tippe auf die Kontaktfläche.")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                }
                .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
        }
    }
}

/// Schlüssel-Symbol im Kreis; beim Warten auf die Berührung mit ruhig pulsierendem Ring.
struct KeyGlyph: View {
    var touching: Bool

    var body: some View {
        ZStack {
            if touching {
                TimelineView(.animation(minimumInterval: 1 / 30)) { context in
                    let t = context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.6) / 1.6
                    Circle()
                        .strokeBorder(Theme.text, lineWidth: 1.5)
                        .frame(width: 72 + 34 * t, height: 72 + 34 * t)
                        .opacity(1 - t)
                }
            }
            Circle()
                .fill(touching ? Theme.text : Theme.background)
                .overlay(Circle().strokeBorder(touching ? Theme.text : Theme.hairline, lineWidth: 1))
                .frame(width: 72, height: 72)
            Image(systemName: "key.horizontal")
                .font(.system(size: 26, weight: .regular))
                .foregroundStyle(touching ? Theme.background : Theme.text)
        }
        .frame(width: 110, height: 110)
        .accessibilityHidden(true)
    }
}

/// Anzeige „Touch ID“ (Einrichten, Aufdecken): Symbol in einem Kreis, aktiv mit pulsierendem Ring.
struct TouchIDGlyph: View {
    var active: Bool
    var done = false

    var body: some View {
        ZStack {
            if active {
                TimelineView(.animation(minimumInterval: 1 / 30)) { context in
                    let t = context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.6) / 1.6
                    Circle()
                        .strokeBorder(Theme.text, lineWidth: 1.5)
                        .frame(width: 64 + 30 * t, height: 64 + 30 * t)
                        .opacity(1 - t)
                }
            }
            Circle()
                .fill(done ? Theme.text : Theme.background)
                .overlay(Circle().strokeBorder(done || active ? Theme.text : Theme.hairline, lineWidth: 1))
                .frame(width: 64, height: 64)
            Image(systemName: done ? "checkmark" : "touchid")
                .font(.system(size: done ? 22 : 30, weight: done ? .semibold : .light))
                .foregroundStyle(done ? Theme.background : Theme.text)
        }
        .frame(width: 96, height: 96)
        .accessibilityHidden(true)
    }
}
