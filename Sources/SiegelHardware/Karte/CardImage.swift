import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import Darwin
import Foundation

/// QR-Bild der Schlüsselkarte (SPEC §14.2): CoreImage `CIQRCodeGenerator`, Korrekturstufe M, scharf skaliert.
///
/// Der Generator liefert ein Modul pro Pixel. Daraus wird die Modul-Matrix gelesen und ganzzahlig, ohne
/// Interpolation, auf `pixels × pixels` gezeichnet (nur reines Schwarz und Weiss, Ruhezone 4 Module).
/// Zwischenpuffer werden genullt; das zurückgegebene `CGImage` enthält das Kartengeheimnis und gehört dem
/// Aufrufer (nur anzeigen/drucken, nie speichern).
public enum CardImage {
    /// Ruhezone in Modulen (ISO/IEC 18004 verlangt mindestens 4).
    static let quietZoneModules = 4
    static let maxPixels = 4096
    static let maxPayloadBytes = 1024

    public static func qr(payload: String, pixels: Int) -> CGImage? {
        let message = Array(payload.utf8)
        guard !message.isEmpty, message.count <= maxPayloadBytes, pixels > 0, pixels <= maxPixels else { return nil }
        guard var modules = moduleMatrix(message) else { return nil }
        defer { wipe(&modules.dark) }
        return render(modules, pixels: pixels)
    }

    /// Modul-Matrix (Zeile 0 = oben), nur das Symbol ohne Rand des Generators.
    struct Modules {
        let size: Int
        var dark: [UInt8]   // size × size, 1 = dunkel

        func isDark(row: Int, column: Int) -> Bool { dark[row * size + column] != 0 }
    }

    static func moduleMatrix(_ message: [UInt8]) -> Modules? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(message)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let extent = output.extent.integral
        let width = Int(extent.width), height = Int(extent.height)
        guard width > 0, width == height, width <= 400 else { return nil }

        let context = CIContext(options: [.useSoftwareRenderer: true, .cacheIntermediates: false])
        guard let cg = context.createCGImage(output, from: extent) else { return nil }
        // In einen eigenen Graustufen-Puffer zeichnen (1:1, ohne Interpolation); Speicherzeile 0 = oben.
        var gray = [UInt8](repeating: 255, count: width * height)
        defer { wipe(&gray) }
        let drawn = gray.withUnsafeMutableBytes { buf -> Bool in
            guard let ctx = CGContext(data: buf.baseAddress, width: width, height: height, bitsPerComponent: 8,
                                      bytesPerRow: width, space: CGColorSpaceCreateDeviceGray(),
                                      bitmapInfo: CGImageAlphaInfo.none.rawValue) else { return false }
            ctx.interpolationQuality = .none
            ctx.setShouldAntialias(false)
            ctx.draw(cg, in: CGRect(x: 0, y: 0, width: width, height: height))
            return true
        }
        guard drawn else { return nil }

        // Begrenzung der dunklen Module = das eigentliche Symbol.
        var minR = width, maxR = -1, minC = width, maxC = -1
        for r in 0..<height {
            for c in 0..<width where gray[r * width + c] < 128 {
                minR = min(minR, r); maxR = max(maxR, r); minC = min(minC, c); maxC = max(maxC, c)
            }
        }
        guard maxR >= 0 else { return nil }
        let size = maxR - minR + 1
        // QR-Versionen 1…40: 21 + 4·(v−1) Module, quadratisch.
        guard size == maxC - minC + 1, size >= 21, size <= 177, (size - 17) % 4 == 0 else { return nil }
        var dark = [UInt8](repeating: 0, count: size * size)
        for r in 0..<size {
            for c in 0..<size where gray[(minR + r) * width + (minC + c)] < 128 {
                dark[r * size + c] = 1
            }
        }
        return Modules(size: size, dark: dark)
    }

    static func render(_ modules: Modules, pixels: Int) -> CGImage? {
        let total = modules.size + 2 * quietZoneModules
        let scale = pixels / total
        guard scale >= 1 else { return nil }
        let offset = (pixels - modules.size * scale) / 2
        var bitmap = [UInt8](repeating: 255, count: pixels * pixels)
        defer { wipe(&bitmap) }
        for r in 0..<modules.size {
            for c in 0..<modules.size where modules.isDark(row: r, column: c) {
                let y0 = offset + r * scale, x0 = offset + c * scale
                for y in y0..<(y0 + scale) {
                    let row = y * pixels
                    for x in x0..<(x0 + scale) { bitmap[row + x] = 0 }
                }
            }
        }
        guard let provider = CGDataProvider(data: Data(bitmap) as CFData) else { return nil }
        return CGImage(width: pixels, height: pixels, bitsPerComponent: 8, bitsPerPixel: 8, bytesPerRow: pixels,
                       space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.none.rawValue),
                       provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent)
    }
}
