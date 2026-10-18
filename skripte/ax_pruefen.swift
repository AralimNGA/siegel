// Prüft den Bedienungshilfen-Baum (AX) des laufenden Siegel-Prozesses auf Geheimnisse (SPEC §6, B3).
// Liest wie ein fremdes Programm mit Bedienungshilfen-Recht nicht nur AXValue, sondern auch die
// parametrisierten Text-Attribute AXStringForRange, AXAttributedStringForRange, AXRTFForRange sowie
// AXSelectedText und AXNumberOfCharacters jedes Elements.
//
// Aufruf:  swift skripte/ax_pruefen.swift --suche <Testgeheimnis> [--suche <weiteres>] [PID]
//          z. B. ein Testeintrag mit Passwort "AXPROBE-4711", Passwort aufgedeckt, dann
//          swift skripte/ax_pruefen.swift --suche AXPROBE-4711
// Erwartung ohne VoiceOver: «Ergebnis: ok» (kein Element liefert den gesuchten Text).
// Exit: 0 = nichts gefunden, 1 = Geheimnis im AX-Baum, 2 = Aufruf/Prozess/Recht fehlt.
// Das aufrufende Terminal braucht das Recht «Bedienungshilfen» (Systemeinstellungen → Datenschutz).
import AppKit
import ApplicationServices

let bundleID = "com.aralim.siegel"

var suche: [String] = []
var pidArgument: pid_t?
var args = Array(CommandLine.arguments.dropFirst())
while !args.isEmpty {
    let a = args.removeFirst()
    if a == "--suche", !args.isEmpty {
        suche.append(args.removeFirst())
    } else if let p = Int32(a) {
        pidArgument = p
    } else {
        FileHandle.standardError.write(Data("Aufruf: ax_pruefen.swift --suche <Text> [PID]\n".utf8))
        exit(2)
    }
}
guard !suche.isEmpty else {
    FileHandle.standardError.write(Data("Aufruf: ax_pruefen.swift --suche <Text> [PID]\n".utf8))
    exit(2)
}

let pid: pid_t
if let pidArgument {
    pid = pidArgument
} else {
    guard let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).first else {
        print("Siegel läuft nicht (\(bundleID)). Zuerst ./build.sh run")
        exit(2)
    }
    pid = app.processIdentifier
}

guard AXIsProcessTrusted() else {
    print("Dieses Terminal hat kein Recht «Bedienungshilfen». Freigeben und erneut aufrufen.")
    exit(2)
}

func attr(_ el: AXUIElement, _ name: String) -> CFTypeRef? {
    var v: CFTypeRef?
    return AXUIElementCopyAttributeValue(el, name as CFString, &v) == .success ? v : nil
}

func param(_ el: AXUIElement, _ name: String, _ p: CFTypeRef) -> CFTypeRef? {
    var v: CFTypeRef?
    return AXUIElementCopyParameterizedAttributeValue(el, name as CFString, p, &v) == .success ? v : nil
}

/// Text aus einem AX-Wert (String, attributierter String, RTF-Daten).
func text(_ v: CFTypeRef?) -> String? {
    guard let v else { return nil }
    if let s = v as? String { return s }
    if CFGetTypeID(v) == CFAttributedStringGetTypeID(), let a = v as? NSAttributedString { return a.string }
    if CFGetTypeID(v) == CFDataGetTypeID(), let d = v as? Data {
        if let a = NSAttributedString(rtf: d, documentAttributes: nil) { return a.string }
        return String(decoding: d, as: UTF8.self)
    }
    return nil
}

var treffer = 0
var geprueft = 0
var besucht = Set<Int>()

func pruefe(_ el: AXUIElement, pfad: String) {
    let role = (attr(el, kAXRoleAttribute) as? String) ?? "?"
    let bezeichnung = (attr(el, kAXDescriptionAttribute) as? String) ?? ""
    var quellen: [(String, String)] = []
    if let v = text(attr(el, kAXValueAttribute)) { quellen.append(("AXValue", v)) }
    if let v = text(attr(el, kAXSelectedTextAttribute)) { quellen.append(("AXSelectedText", v)) }
    if let v = text(attr(el, kAXTitleAttribute)) { quellen.append(("AXTitle", v)) }
    quellen.append(("AXDescription", bezeichnung))
    let anzahl = (attr(el, kAXNumberOfCharactersAttribute) as? Int) ?? 0
    let laenge = max(anzahl, 4096)
    var bereich = CFRange(location: 0, length: laenge)
    if let r = AXValueCreate(.cfRange, &bereich) {
        for name in [kAXStringForRangeParameterizedAttribute, kAXAttributedStringForRangeParameterizedAttribute,
                     kAXRTFForRangeParameterizedAttribute] {
            // Zu langer Bereich wird abgelehnt: dann mit der gemeldeten Länge erneut
            if let v = text(param(el, name, r)) {
                quellen.append((name, v))
            } else if anzahl > 0 {
                var exakt = CFRange(location: 0, length: anzahl)
                if let r2 = AXValueCreate(.cfRange, &exakt), let v = text(param(el, name, r2)) {
                    quellen.append((name, v))
                }
            }
        }
    }
    geprueft += 1
    for (quelle, wert) in quellen {
        for s in suche where wert.contains(s) {
            treffer += 1
            print("GEFUNDEN  \(role) «\(bezeichnung)» über \(quelle)   (\(pfad))")
        }
    }
    if let kinder = attr(el, kAXChildrenAttribute) as? [AXUIElement] {
        for (i, k) in kinder.enumerated() {
            let key = Int(CFHash(k))
            if besucht.contains(key) { continue }
            besucht.insert(key)
            pruefe(k, pfad: pfad + "/" + role + "[\(i)]")
        }
    }
}

enum TextHardeningProbe {
    static let voiceOver = NSWorkspace.shared.isVoiceOverEnabled
}

let appEl = AXUIElementCreateApplication(pid)
guard let fenster = attr(appEl, kAXWindowsAttribute) as? [AXUIElement], !fenster.isEmpty else {
    print("Keine Fenster gefunden (Siegel im Vordergrund? Recht «Bedienungshilfen»?)")
    exit(2)
}
for (i, w) in fenster.enumerated() { pruefe(w, pfad: "Fenster[\(i)]") }
print("\(geprueft) Elemente geprüft, VoiceOver \(TextHardeningProbe.voiceOver ? "an" : "aus")")
if treffer == 0 {
    print("Ergebnis: ok")
    exit(0)
}
print("Ergebnis: FEHLER (\(treffer) Treffer)")
exit(1)
