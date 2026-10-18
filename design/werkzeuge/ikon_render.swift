// Rendert das System-Icon eines App-Bundles (NSWorkspace) pixelgenau in PNGs.
// Aufruf: ikon_render <App.app> <ausgabe-präfix> [hell|dunkel]
import AppKit

let args = CommandLine.arguments
let app = args[1], prefix = args[2]
let modus = args.count > 3 ? args[3] : "hell"
let appearance = NSAppearance(named: modus == "dunkel" ? .darkAqua : .aqua)!
let icon = NSWorkspace.shared.icon(forFile: app)

for (pt, scale) in [(16, 1), (16, 2), (32, 1), (32, 2), (64, 2), (128, 2), (512, 2)] {
    let px = pt * scale
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: pt, height: pt)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    appearance.performAsCurrentDrawingAppearance {
        icon.draw(in: NSRect(x: 0, y: 0, width: pt, height: pt), from: .zero, operation: .copy, fraction: 1)
    }
    NSGraphicsContext.restoreGraphicsState()
    try! rep.representation(using: .png, properties: [:])!
        .write(to: URL(fileURLWithPath: "\(prefix)-\(pt)@\(scale)x.png"))
}
print("ok")
