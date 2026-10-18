@preconcurrency import AVFoundation
import CoreMedia
import CoreVideo
import Foundation
import QuartzCore
import SiegelCore
import Synchronization

/// Kamera-Scanner für die QR-Schlüsselkarte (SPEC §14.2).
///
/// Eingebaute Kamera → `AVCaptureVideoDataOutput` → Vision (nur `.qr`). Bilder bleiben nur im Speicher und werden
/// nie gespeichert; nach der ersten erkannten Siegel-Karte stoppt die Sitzung sofort und `onPayload` läuft auf dem
/// Main-Thread (genau einmal pro `start()`). Andere QR-Codes im Bild werden ignoriert. Beim Sperren `stop()` rufen.
/// Die Vorschau (`previewLayer`) zeigt Kamerabilder: nur in einem Fenster unter dem WindowGuard verwenden.
@MainActor public final class QRScanner {
    public static func authorization() -> AVAuthorizationStatus {
        AVCaptureDevice.authorizationStatus(for: .video)
    }

    public static func requestAccess() async -> Bool {
        await AVCaptureDevice.requestAccess(for: .video)
    }

    private let onPayload: @MainActor (String) -> Void
    private let core: QRScanCore
    private var preview: AVCaptureVideoPreviewLayer?
    private var generation = 0

    public init(onPayload: @escaping @MainActor (String) -> Void) {
        self.onPayload = onPayload
        self.core = QRScanCore()
    }

    deinit {
        core.stop()
    }

    /// Startet die eingebaute Kamera. Ohne Freigabe oder ohne eingebaute Kamera (z. B. zugeklappt)
    /// → `factorUnavailable(.card)`; die Oberfläche bietet dann das Abtippen an.
    public func start() throws {
        guard Self.authorization() == .authorized else { throw SiegelError.factorUnavailable(.card) }
        guard let device = QRScanCore.builtInCamera() else { throw SiegelError.factorUnavailable(.card) }
        generation += 1
        let current = generation
        let ref = ScannerRef(self)
        try core.start(device: device) { payload in
            Task { @MainActor in ref.scanner?.deliver(payload, generation: current) }
        }
    }

    public func stop() {
        generation += 1
        core.stop()
    }

    public var previewLayer: CALayer {
        if let preview { return preview }
        let layer = AVCaptureVideoPreviewLayer(session: core.session)
        layer.videoGravity = .resizeAspectFill
        preview = layer
        return layer
    }

    private func deliver(_ payload: String, generation delivered: Int) {
        // Nach stop() oder einem neuen start() verspätete Treffer verwerfen.
        guard delivered == generation else { return }
        generation += 1
        core.stop()
        onPayload(payload)
    }
}

/// Schwache Referenz, die zwischen Video-Queue und Main-Actor wandern darf (gelesen nur auf dem Main-Actor).
private final class ScannerRef: @unchecked Sendable {
    weak var scanner: QRScanner?
    init(_ scanner: QRScanner) { self.scanner = scanner }
}

/// Kamera-Sitzung und Bildauswertung ausserhalb des Main-Actors. `startRunning`/`stopRunning` blockieren und laufen
/// darum auf einer eigenen Queue.
final class QRScanCore: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate, @unchecked Sendable {
    let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "siegel.qr.session")
    private let videoQueue = DispatchQueue(label: "siegel.qr.video")

    private struct State {
        var detecting = false
        var handler: (@Sendable (String) -> Void)?
    }
    private let state = Mutex(State())

    static func builtInCamera() -> AVCaptureDevice? {
        AVCaptureDevice.DiscoverySession(deviceTypes: [.builtInWideAngleCamera], mediaType: .video,
                                         position: .unspecified).devices.first
    }

    func start(device: AVCaptureDevice, handler: @escaping @Sendable (String) -> Void) throws {
        let input: AVCaptureDeviceInput
        do {
            input = try AVCaptureDeviceInput(device: device)
        } catch {
            throw SiegelError.factorUnavailable(.card)
        }
        let configured = sessionQueue.sync { () -> Bool in
            session.beginConfiguration()
            defer { session.commitConfiguration() }
            removeAll()
            if session.canSetSessionPreset(.hd1280x720) { session.sessionPreset = .hd1280x720 }
            guard session.canAddInput(input) else { return false }
            session.addInput(input)
            let output = AVCaptureVideoDataOutput()
            output.alwaysDiscardsLateVideoFrames = true
            output.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange]
            output.setSampleBufferDelegate(self, queue: videoQueue)
            guard session.canAddOutput(output) else { return false }
            session.addOutput(output)
            return true
        }
        guard configured else {
            stop()
            throw SiegelError.factorUnavailable(.card)
        }
        arm(handler: handler)
        sessionQueue.async { [self] in
            if state.withLock({ $0.detecting }), !session.isRunning { session.startRunning() }
        }
    }

    /// Erkennung scharf schalten (auch für Tests ohne Kamera).
    func arm(handler: @escaping @Sendable (String) -> Void) {
        state.withLock {
            $0.detecting = true
            $0.handler = handler
        }
    }

    func stop() {
        state.withLock {
            $0.detecting = false
            $0.handler = nil
        }
        sessionQueue.async { [self] in
            if session.isRunning { session.stopRunning() }
            // Eingang lösen: Kamera sofort frei (Kontrolllicht aus).
            session.beginConfiguration()
            removeAll()
            session.commitConfiguration()
        }
    }

    /// Nur auf `sessionQueue` aufrufen.
    private func removeAll() {
        for output in session.outputs {
            (output as? AVCaptureVideoDataOutput)?.setSampleBufferDelegate(nil, queue: nil)
            session.removeOutput(output)
        }
        for input in session.inputs { session.removeInput(input) }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer,
                       from connection: AVCaptureConnection) {
        guard state.withLock({ $0.detecting }), let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        process(pixelBuffer)
    }

    /// Wertet ein Bild aus. Bei einer Siegel-Karte: Erkennung aus, Sitzung stoppen, Handler genau einmal rufen.
    @discardableResult
    func process(_ pixelBuffer: CVPixelBuffer) -> Bool {
        guard let payload = QRDetector.cardPayload(in: QRDetector.payloads(in: pixelBuffer)) else { return false }
        let handler = state.withLock { s -> (@Sendable (String) -> Void)? in
            guard s.detecting else { return nil }
            s.detecting = false
            defer { s.handler = nil }
            return s.handler
        }
        guard let handler else { return false }
        sessionQueue.async { [self] in
            if session.isRunning { session.stopRunning() }
        }
        handler(payload)
        return true
    }
}
