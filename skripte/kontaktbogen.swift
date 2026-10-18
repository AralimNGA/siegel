// Legt alle Snapshot-PNGs als Kontaktbögen zusammen (zum schnellen Durchsehen nach einem Neu-Rendern).
// Aufruf: swift skripte/kontaktbogen.swift [quelle] [ziel] [spalten] [zeilen] [bogenbreite]
//   Standard: snapshots  build/kontaktbogen  2  3  1600
// Ergebnis: <ziel>/kontaktbogen-01.png … in natürlicher Reihenfolge der Dateinamen (9b vor 10), Name über jedem Bild.
// Vorher liegende kontaktbogen-*.png im Ziel werden ersetzt.
import AppKit

let args = Array(CommandLine.arguments.dropFirst())
let quelle = URL(fileURLWithPath: args.count > 0 ? args[0] : "snapshots", isDirectory: true)
let ziel = URL(fileURLWithPath: args.count > 1 ? args[1] : "build/kontaktbogen", isDirectory: true)
let spalten = max(1, args.count > 2 ? Int(args[2]) ?? 2 : 2)
let zeilen = max(1, args.count > 3 ? Int(args[3]) ?? 3 : 3)
let breite = max(400, args.count > 4 ? Int(args[4]) ?? 1600 : 1600)

func fehler(_ text: String) -> Never {
    FileHandle.standardError.write(Data((text + "\n").utf8))
    exit(1)
}

let fm = FileManager.default
guard let inhalt = try? fm.contentsOfDirectory(at: quelle, includingPropertiesForKeys: nil) else {
    fehler("Ordner nicht lesbar: \(quelle.path)")
}
let bilder = inhalt.filter { $0.pathExtension.lowercased() == "png" }
    .sorted { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }
guard !bilder.isEmpty else { fehler("Keine PNGs in \(quelle.path)") }

try? fm.createDirectory(at: ziel, withIntermediateDirectories: true)
for alt in (try? fm.contentsOfDirectory(at: ziel, includingPropertiesForKeys: nil)) ?? []
where alt.lastPathComponent.hasPrefix("kontaktbogen-") && alt.pathExtension == "png" {
    try? fm.removeItem(at: alt)
}

let rand = 12
let beschriftung = 26
let zelleB = (breite - rand * (spalten + 1)) / spalten
// Seitenverhältnis aus dem ersten Bild (alle Snapshots sind 920×600 @2x; abweichende werden eingepasst)
let erstes = NSImage(contentsOf: bilder[0])
let verhaeltnis = (erstes.map { $0.size.height / max($0.size.width, 1) }) ?? (600.0 / 920.0)
let bildH = Int((CGFloat(zelleB) * verhaeltnis).rounded())
let zelleH = beschriftung + bildH
let hoehe = rand + zeilen * (zelleH + rand)
let proBogen = spalten * zeilen
let schrift = NSFont.monospacedSystemFont(ofSize: 15, weight: .medium)

var bogenNr = 0
for start in stride(from: 0, to: bilder.count, by: proBogen) {
    bogenNr += 1
    guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: breite, pixelsHigh: hoehe, bitsPerSample: 8,
                                     samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                     bytesPerRow: 0, bitsPerPixel: 0),
          let ctx = NSGraphicsContext(bitmapImageRep: rep) else { fehler("Bitmap nicht anlegbar") }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = ctx
    NSColor(white: 0.82, alpha: 1).setFill()
    NSRect(x: 0, y: 0, width: breite, height: hoehe).fill()
    for (i, url) in bilder[start..<min(start + proBogen, bilder.count)].enumerated() {
        let sp = i % spalten, ze = i / spalten
        let x = rand + sp * (zelleB + rand)
        let yOben = rand + ze * (zelleH + rand)              // von oben gezählt
        let yUnten = hoehe - yOben - zelleH                     // AppKit zählt von unten
        let name = url.deletingPathExtension().lastPathComponent
        (name as NSString).draw(at: NSPoint(x: x + 2, y: yUnten + bildH + 5),
                                withAttributes: [.font: schrift, .foregroundColor: NSColor.black])
        let feld = NSRect(x: x, y: yUnten, width: zelleB, height: bildH)
        NSColor.white.setFill()
        feld.fill()
        if let bild = NSImage(contentsOf: url), bild.size.width > 0, bild.size.height > 0 {
            let s = min(CGFloat(zelleB) / bild.size.width, CGFloat(bildH) / bild.size.height)
            let w = bild.size.width * s, h = bild.size.height * s
            bild.draw(in: NSRect(x: feld.minX + (feld.width - w) / 2, y: feld.maxY - h, width: w, height: h),
                      from: .zero, operation: .sourceOver, fraction: 1)
        } else {
            ("nicht lesbar" as NSString).draw(at: NSPoint(x: feld.minX + 10, y: feld.midY),
                                              withAttributes: [.font: schrift, .foregroundColor: NSColor.red])
        }
        NSColor(white: 0.55, alpha: 1).setStroke()
        NSBezierPath(rect: feld.insetBy(dx: 0.5, dy: 0.5)).stroke()
    }
    NSGraphicsContext.restoreGraphicsState()
    guard let png = rep.representation(using: .png, properties: [:]) else { fehler("PNG nicht erzeugbar") }
    let datei = ziel.appendingPathComponent(String(format: "kontaktbogen-%02d.png", bogenNr))
    do { try png.write(to: datei) } catch { fehler("Schreiben gescheitert: \(datei.path)") }
}
print("Kontaktbögen: \(bogenNr) (\(bilder.count) Bilder, je \(proBogen)) in \(ziel.path)")
