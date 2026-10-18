// Listet alle Fenster des laufenden Siegel-Prozesses mit kCGWindowSharingState (SPEC §6 Fensterschutz, §10).
// Erwartung: jedes eigene Fenster hat sharingState 0 (kCGWindowSharingNone), auch Sheets, Alerts, Panels.
//
// Aufruf:  swift skripte/fenster_pruefen.swift                 einmal prüfen (sucht com.aralim.siegel)
//          swift skripte/fenster_pruefen.swift <PID>           anderen Prozess prüfen (Gegenprobe)
//          swift skripte/fenster_pruefen.swift --beobachten    alle 0.2 s, meldet Änderungen, Ende mit ctrl-C;
//                                                              währenddessen Sheets, Alerts, Panels öffnen
// Exit: 0 = alle Fenster 0, 1 = mindestens ein Fenster 1/2, 2 = Prozess nicht gefunden.
// Fensternamen erscheinen nur mit Bildschirmaufnahme-Recht; für die Prüfung sind sie nicht nötig.
//
// macOS 26 legt für jede App eigene, unsichtbare Menüleisten-Streifen an (bildschirmbreit, so hoch wie die
// Menüleiste, oben am Bildschirm; Finder hat sie auch). Sie stehen nicht in NSApp.windows, die WindowGuard
// kann sie nicht setzen, und sie enthalten nur die Menütitel. Sie werden als «Menüleiste (System)» gezeigt
// und nicht gewertet.
import AppKit
import CoreGraphics

let bundleID = "com.aralim.siegel"

var arguments = Array(CommandLine.arguments.dropFirst())
let watch = arguments.contains("--beobachten")
arguments.removeAll { $0 == "--beobachten" }

let pid: pid_t
if let first = arguments.first {
    guard let value = Int32(first) else {
        FileHandle.standardError.write(Data("Aufruf: fenster_pruefen.swift [PID] [--beobachten]\n".utf8))
        exit(2)
    }
    pid = value
} else {
    guard let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).first else {
        print("Siegel läuft nicht (\(bundleID)). Zuerst ./build.sh run")
        exit(2)
    }
    pid = app.processIdentifier
}

struct WindowInfo: Hashable {
    let number: Int
    let x: Int
    let y: Int
    let layer: Int
    let onScreen: Bool
    let sharing: Int
    let width: Int
    let height: Int
    let name: String
}

func windows() -> [WindowInfo] {
    let raw = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? []
    return raw.compactMap { w -> WindowInfo? in
        guard (w[kCGWindowOwnerPID as String] as? Int) == Int(pid) else { return nil }
        let bounds = w[kCGWindowBounds as String] as? [String: Any] ?? [:]
        return WindowInfo(number: w[kCGWindowNumber as String] as? Int ?? -1,
                          x: Int(bounds["X"] as? Double ?? -1),
                          y: Int(bounds["Y"] as? Double ?? -1),
                          layer: w[kCGWindowLayer as String] as? Int ?? 0,
                          onScreen: w[kCGWindowIsOnscreen as String] as? Bool ?? false,
                          sharing: w[kCGWindowSharingState as String] as? Int ?? -1,
                          width: Int(bounds["Width"] as? Double ?? 0),
                          height: Int(bounds["Height"] as? Double ?? 0),
                          name: w[kCGWindowName as String] as? String ?? "")
    }.sorted { $0.number < $1.number }
}

// Menüleisten-Streifen des Systems: bildschirmbreit, höchstens 50 pt hoch, oben am Bildschirm (CG-Koordinaten)
let screenTops: [(x: Int, y: Int, width: Int)] = {
    let mainHeight = NSScreen.screens.first?.frame.height ?? 0
    return NSScreen.screens.map { s in
        (Int(s.frame.minX), Int(mainHeight - s.frame.maxY), Int(s.frame.width))
    }
}()

func isMenuBarStrip(_ w: WindowInfo) -> Bool {
    w.height > 0 && w.height <= 50 && screenTops.contains { $0.x == w.x && $0.y == w.y && $0.width == w.width }
}

func counts(_ w: WindowInfo) -> Bool { !isMenuBarStrip(w) }

func sharingText(_ s: Int) -> String {
    switch s {
    case 0: return "0 none"
    case 1: return "1 readOnly"
    case 2: return "2 readWrite"
    default: return "\(s) ?"
    }
}

func pad(_ s: String, _ n: Int) -> String { s + String(repeating: " ", count: max(1, n - s.count)) }

func columns(_ c: [String]) -> String {
    "  " + pad(c[0], 8) + pad(c[1], 7) + pad(c[2], 10) + pad(c[3], 12) + pad(c[4], 14) + pad(c[5], 24) + c[6]
}

func line(_ w: WindowInfo) -> String {
    let status = isMenuBarStrip(w) ? "Menüleiste (System)"
        : w.sharing == 0 ? "ok" : (w.onScreen ? "OFFEN" : "offen (nicht sichtbar)")
    return columns([String(w.number), String(w.layer), w.onScreen ? "ja" : "nein", "\(w.width)×\(w.height)",
                    sharingText(w.sharing), status, w.name])
}

func report(_ list: [WindowInfo]) {
    print(columns(["Nr.", "Ebene", "sichtbar", "Grösse", "sharingState", "Status", "Name"]))
    for w in list { print(line(w)) }
}

let header = "Siegel-Prozess \(pid)"

if !watch {
    let all = windows()
    let list = all.filter(counts)
    print("\(header): \(all.count) Fenster")
    report(all)
    let bad = list.filter { $0.sharing != 0 }
    let strips = all.count - list.count
    if strips > 0 { print("(\(strips) Menüleisten-Streifen des Systems nicht gewertet)") }
    if list.isEmpty {
        print("Ergebnis: keine Fenster gefunden")
        exit(2)
    } else if bad.isEmpty {
        print("Ergebnis: ok – \(list.count) Fenster geprüft, alle mit sharingState 0")
        exit(0)
    } else {
        print("Ergebnis: FEHLER – \(bad.count) von \(list.count) geprüften Fenstern sind für Bildschirmaufnahmen offen")
        exit(1)
    }
}

// Beobachten: jede Änderung ausgeben, am Ende (ctrl-C) Zusammenfassung
print("\(header): beobachte alle 0.2 s, Ende mit ctrl-C. Jetzt Sheets, Alerts, Einstellungen, Panels öffnen.")
nonisolated(unsafe) var last: [WindowInfo] = []
nonisolated(unsafe) var seen = Set<Int>()
nonisolated(unsafe) var openSeen = Set<Int>()

func tick() {
    if kill(pid, 0) != 0 {
        print("Prozess beendet.")
        finish()
    }
    let list = windows()
    for w in list where counts(w) {
        seen.insert(w.number)
        if w.sharing != 0 && w.onScreen { openSeen.insert(w.number) }
    }
    if list != last {
        print("\(Date().formatted(date: .omitted, time: .standard)): \(list.count) Fenster")
        report(list)
        last = list
    }
}

func finish() -> Never {
    if openSeen.isEmpty {
        print("Ergebnis: ok – \(seen.count) Fenster gesehen, keines sichtbar mit sharingState ≠ 0")
        exit(0)
    }
    print("Ergebnis: FEHLER – sichtbar und offen waren: \(openSeen.sorted().map(String.init).joined(separator: ", "))")
    exit(1)
}

signal(SIGINT, SIG_IGN)
let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
interrupt.setEventHandler { print(""); finish() }
interrupt.resume()
let timer = DispatchSource.makeTimerSource(queue: .main)
timer.schedule(deadline: .now(), repeating: .milliseconds(200))
timer.setEventHandler { tick() }
timer.resume()
dispatchMain()
