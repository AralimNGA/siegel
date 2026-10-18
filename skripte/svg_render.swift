// Rendert eine SVG-Datei mit dem macOS-eigenen SVG-Renderer (NSImage) als PNG.
// Aufruf: swift skripte/svg_render.swift <ein.svg> <aus.png> <pixel> [hintergrund]
//   hintergrund: "transparent" (Standard), "white", "black" oder "#RRGGBB"
import AppKit

let args = CommandLine.arguments
guard args.count >= 4, let px = Int(args[3]), px > 0 else {
    FileHandle.standardError.write("Aufruf: svg_render.swift <ein.svg> <aus.png> <pixel> [hintergrund]\n".data(using: .utf8)!)
    exit(2)
}
guard let image = NSImage(contentsOfFile: args[1]) else {
    FileHandle.standardError.write("SVG nicht lesbar: \(args[1])\n".data(using: .utf8)!)
    exit(1)
}

func color(_ spec: String) -> NSColor? {
    switch spec {
    case "transparent": return nil
    case "white": return .white
    case "black": return .black
    default:
        guard spec.hasPrefix("#"), spec.count == 7, let v = Int(spec.dropFirst(), radix: 16) else { return nil }
        return NSColor(srgbRed: CGFloat((v >> 16) & 255) / 255, green: CGFloat((v >> 8) & 255) / 255,
                       blue: CGFloat(v & 255) / 255, alpha: 1)
    }
}

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                           colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
rep.size = NSSize(width: px, height: px)
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
NSGraphicsContext.current?.imageInterpolation = .high
let rect = NSRect(x: 0, y: 0, width: px, height: px)
if args.count >= 5, let bg = color(args[4]) { bg.setFill(); rect.fill() }
image.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 1)
NSGraphicsContext.restoreGraphicsState()

guard let png = rep.representation(using: .png, properties: [:]) else { exit(1) }
do { try png.write(to: URL(fileURLWithPath: args[2])) } catch {
    FileHandle.standardError.write("Schreiben fehlgeschlagen: \(error)\n".data(using: .utf8)!)
    exit(1)
}
