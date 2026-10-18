import AVFoundation
import CoreGraphics
import CoreVideo
import Foundation
import SiegelCore
import Synchronization
import Testing
@testable import SiegelHardware

/// QR-Karte: Erzeugen mit CoreImage, Erkennen mit Vision (Bild → Inhalt). Die Kamera wird nie gestartet.
@Suite("QR-Karte")
struct QRTests {
    let payload = cardPayloadForTests()

    func pixels(_ image: CGImage) -> [UInt8] {
        let w = image.width, h = image.height
        var out = [UInt8](repeating: 0, count: w * h)
        out.withUnsafeMutableBytes { buf in
            let ctx = CGContext(data: buf.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w,
                                space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)
            ctx?.interpolationQuality = .none
            ctx?.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
        }
        return out
    }

    @Test func formatDesTestinhalts() {
        #expect(payload.hasPrefix("SIEGELKARTE1:"))
        #expect(payload.count == 13 + 55)
    }

    @Test(arguments: [300, 600, 1024, 2048])
    func erzeugenUndMitVisionLesen(size: Int) throws {
        let image = try #require(CardImage.qr(payload: payload, pixels: size))
        #expect(image.width == size)
        #expect(image.height == size)
        #expect(QRDetector.payloads(in: image) == [payload])
        #expect(QRDetector.cardPayload(in: QRDetector.payloads(in: image)) == payload)
    }

    @Test func scharfOhneZwischentoeneMitRuhezone() throws {
        let size = 777
        let image = try #require(CardImage.qr(payload: payload, pixels: size))
        let p = pixels(image)
        #expect(p.allSatisfy { $0 == 0 || $0 == 255 })
        let modules = try #require(CardImage.moduleMatrix(Array(payload.utf8)))
        let scale = size / (modules.size + 8)
        let offset = (size - modules.size * scale) / 2
        #expect(offset >= 4 * scale)
        // Ruhezone ringsum weiss.
        for y in 0..<offset { #expect(p[(y * size)..<(y * size + size)].allSatisfy { $0 == 255 }) }
        for y in 0..<size {
            #expect(p[y * size..<(y * size + offset)].allSatisfy { $0 == 255 })
        }
        // Jedes Modul ist ein einfarbiges Quadrat der Kantenlänge `scale` und passt zur Matrix.
        for r in 0..<modules.size {
            for c in 0..<modules.size {
                let want: UInt8 = modules.isDark(row: r, column: c) ? 0 : 255
                let y0 = offset + r * scale, x0 = offset + c * scale
                #expect(p[y0 * size + x0] == want)
                #expect(p[(y0 + scale - 1) * size + (x0 + scale - 1)] == want)
            }
        }
        // Finder-Muster oben links: dunkle 7×7-Ecke (Orientierung stimmt, nicht gespiegelt).
        #expect(modules.isDark(row: 0, column: 0))
        #expect(modules.isDark(row: 0, column: modules.size - 1))
        #expect(modules.isDark(row: modules.size - 1, column: 0))
    }

    @Test func korrekturstufeMBestimmtDieGroesse() throws {
        // 68 Zeichen Byte-Modus mit Stufe M → Version 5 (37 Module); bei H wäre es Version 7 (45).
        let modules = try #require(CardImage.moduleMatrix(Array(payload.utf8)))
        #expect([33, 37].contains(modules.size))
    }

    @Test func grenzen() {
        #expect(CardImage.qr(payload: "", pixels: 500) == nil)
        #expect(CardImage.qr(payload: payload, pixels: 0) == nil)
        #expect(CardImage.qr(payload: payload, pixels: 20) == nil)      // kleiner als Symbol + Ruhezone
        #expect(CardImage.qr(payload: payload, pixels: 5000) == nil)
        #expect(CardImage.qr(payload: String(repeating: "A", count: 1025), pixels: 500) == nil)
    }

    @Test func andereQRCodesWerdenIgnoriert() throws {
        let image = try #require(CardImage.qr(payload: "https://example.com/siegel", pixels: 400))
        #expect(QRDetector.payloads(in: image) == ["https://example.com/siegel"])
        #expect(QRDetector.cardPayload(in: QRDetector.payloads(in: image)) == nil)
        #expect(!QRDetector.isCardPayload(String(repeating: "X", count: 300)))
        #expect(!QRDetector.isCardPayload("SIEGELKARTE" + String(repeating: "X", count: 300)))
    }

    @Test func leeresBildOhneTreffer() throws {
        let blank = try #require(CardImage.render(CardImage.Modules(size: 21, dark: [UInt8](repeating: 0, count: 441)),
                                                  pixels: 300))
        #expect(QRDetector.payloads(in: blank).isEmpty)
    }

    // MARK: Scanner-Pipeline ohne Kamera

    func pixelBuffer(_ image: CGImage) throws -> CVPixelBuffer {
        var buffer: CVPixelBuffer?
        let attrs = [kCVPixelBufferCGImageCompatibilityKey: true, kCVPixelBufferCGBitmapContextCompatibilityKey: true] as CFDictionary
        let status = CVPixelBufferCreate(kCFAllocatorDefault, image.width, image.height, kCVPixelFormatType_32BGRA, attrs, &buffer)
        let pb = try #require(status == kCVReturnSuccess ? buffer : nil)
        CVPixelBufferLockBaseAddress(pb, [])
        let ctx = CGContext(data: CVPixelBufferGetBaseAddress(pb), width: image.width, height: image.height,
                            bitsPerComponent: 8, bytesPerRow: CVPixelBufferGetBytesPerRow(pb),
                            space: CGColorSpaceCreateDeviceRGB(),
                            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)
        ctx?.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
        CVPixelBufferUnlockBaseAddress(pb, [])
        return pb
    }

    @Test func scanKernLiefertGenauEinmal() throws {
        let core = QRScanCore()
        let received = Mutex<[String]>([])
        core.arm { payload in received.withLock { $0.append(payload) } }
        let frame = try pixelBuffer(try #require(CardImage.qr(payload: payload, pixels: 640)))
        #expect(core.process(frame))
        #expect(!core.process(frame))   // nach dem Treffer aus
        #expect(received.withLock { $0 } == [payload])
        core.stop()
    }

    @Test func scanKernIgnoriertFremdeCodesUndStop() throws {
        let core = QRScanCore()
        let received = Mutex<[String]>([])
        core.arm { payload in received.withLock { $0.append(payload) } }
        let other = try pixelBuffer(try #require(CardImage.qr(payload: "WIFI:S:Gast;;", pixels: 400)))
        #expect(!core.process(other))
        core.stop()
        let card = try pixelBuffer(try #require(CardImage.qr(payload: payload, pixels: 400)))
        #expect(!core.process(card))    // gestoppt: nichts mehr
        #expect(received.withLock { $0 }.isEmpty)
    }

    @MainActor @Test func scannerOhneKameraStart() {
        let scanner = QRScanner { _ in }
        #expect(scanner.previewLayer is AVCaptureVideoPreviewLayer)
        #expect(scanner.previewLayer === scanner.previewLayer)
        scanner.stop()
        scanner.stop()
        _ = QRScanner.authorization()   // zeigt keinen Dialog
    }
}
