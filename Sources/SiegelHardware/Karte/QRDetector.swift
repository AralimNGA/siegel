import CoreGraphics
import CoreVideo
import Foundation
import ImageIO
import Vision

/// QR-Erkennung mit Vision (`VNDetectBarcodesRequest`, nur `.qr`). Ohne Kamera nutzbar (Tests, Fuzzer).
enum QRDetector {
    /// Nur Inhalte von Siegel-Karten werden weitergegeben (andere QR-Codes im Bild stoppen nichts).
    static let cardPrefix = "SIEGELKARTE"
    static let maxPayloadLength = 256

    static func payloads(in image: CGImage) -> [String] {
        run(VNImageRequestHandler(cgImage: image, options: [:]))
    }

    static func payloads(in pixelBuffer: CVPixelBuffer, orientation: CGImagePropertyOrientation = .up) -> [String] {
        run(VNImageRequestHandler(cvPixelBuffer: pixelBuffer, orientation: orientation, options: [:]))
    }

    /// Erster Inhalt, der wie eine Siegel-Karte aussieht (Prüfsumme prüft erst `CardCode.decode`).
    static func cardPayload(in payloads: [String]) -> String? {
        payloads.first(where: isCardPayload)
    }

    static func isCardPayload(_ s: String) -> Bool {
        s.utf8.count <= maxPayloadLength && s.hasPrefix(cardPrefix)
    }

    private static func run(_ handler: VNImageRequestHandler) -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        do {
            try handler.perform([request])
        } catch {
            return []
        }
        return (request.results ?? []).compactMap { $0.payloadStringValue }
    }
}
