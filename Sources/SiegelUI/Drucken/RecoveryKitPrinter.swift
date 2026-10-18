import AppKit
import ApplicationServices
import SiegelCore
import SwiftUI

/// Notfallkit drucken (SPEC §7.6): ohne Vorschau, Auftragsname „Dokument“. Zuerst der Druckdialog, dann die
/// Prüfung genau des darin gewählten Druckers (Befund #15), dann der Druck ohne zweiten Dialog. Der Code wird
/// nur auf Papier ausgegeben: Wählt jemand im Dialog „PDF ▾“ (Als PDF sichern, In Vorschau öffnen, iCloud Drive,
/// Mail …), zeichnet das Blatt statt des Codes einen Hinweis, und Siegel meldet nicht „Gedruckt“ (Befund #7).
@MainActor
public enum RecoveryKitPrinter {
    public enum PrinterCheck: Equatable, Sendable {
        /// USB, IPPS, HTTPS oder unbekannte Art ohne Hinweis auf Klartext im Netz
        case secure
        /// Empfängt unverschlüsselt über das Netzwerk
        case insecure
        /// Kein Drucker oder keine Geräte-URI lesbar
        case unknown
    }

    /// Ergebnis eines Druckversuchs.
    public enum PrintOutcome: Equatable, Sendable {
        /// Auf einem Drucker ausgegeben (mit Code).
        case paper
        /// Keine Ausgabe auf Papier gewählt (PDF, Vorschau, Datei, PDF-Dienst): Code nicht ausgegeben.
        case notPaper
        /// Abgebrochen oder gescheitert.
        case cancelled
    }

    public static let insecureWarning = "Dieser Drucker empfängt unverschlüsselt über das Netzwerk; Firmendrucker speichern Aufträge oft."
    public static let unknownWarning = "Siegel kann nicht prüfen, wie dieser Drucker angebunden ist. Netzwerkdrucker empfangen oft unverschlüsselt; Firmendrucker speichern Aufträge oft."
    public static let notPaperMessage = "Als PDF, in der Vorschau oder in einer Cloud gibt Siegel den Code nicht aus. Bitte auf einem Drucker drucken oder von Hand abschreiben."
    /// Steht auf dem Blatt statt des Codes, wenn die Ausgabe kein Drucker ist.
    static let notPaperSheetText = "Notfallkit nur auf Papier – Code nicht enthalten."

    /// Druckeinstellungen für das Blatt (randlos zentriert, eine Seite).
    static func makePrintInfo() -> NSPrintInfo? {
        guard let info = NSPrintInfo.shared.copy() as? NSPrintInfo else { return nil }
        info.topMargin = 0
        info.bottomMargin = 0
        info.leftMargin = 0
        info.rightMargin = 0
        info.horizontalPagination = .fit
        info.verticalPagination = .fit
        info.isHorizontallyCentered = true
        info.isVerticallyCentered = true
        return info
    }

    /// Druckdialog ohne Vorschau; nil bei „Abbrechen“.
    public static func choosePrinter() -> NSPrintInfo? {
        guard let info = makePrintInfo() else { return nil }
        let panel = NSPrintPanel()
        panel.options = [.showsCopies, .showsPaperSize, .showsOrientation]
        WindowGuard.shared.protectAll()
        guard panel.runModal(with: info) == NSApplication.ModalResponse.OK.rawValue else { return nil }
        return info
    }

    /// Liest die Geräte-URI des in `info` gewählten Druckers (`PMSessionGetCurrentPrinter` + `PMPrinterCopyDeviceURI`).
    public static func check(_ info: NSPrintInfo) -> PrinterCheck {
        let session = PMPrintSession(info.pmPrintSession())
        var printer: PMPrinter?
        guard PMSessionGetCurrentPrinter(session, &printer) == noErr, let printer else { return .unknown }
        var uri: Unmanaged<CFURL>?
        guard PMPrinterCopyDeviceURI(printer, &uri) == noErr, let cf = uri?.takeRetainedValue() else { return .unknown }
        return classify(cf as URL)
    }

    /// Geht die Ausgabe mit diesen Einstellungen wirklich an einen Drucker? Nicht bei Vorschau, Datei, PDF-Diensten
    /// (iCloud Drive, Mail, Web Receipts melden `jobDisposition == .spool`, aber Ziel „ProcessPDF“).
    public static func isPaper(_ info: NSPrintInfo) -> Bool {
        guard info.jobDisposition == .spool else { return false }
        var ziel = PMDestinationType(kPMDestinationInvalid)
        let session = PMPrintSession(info.pmPrintSession())
        let settings = PMPrintSettings(info.pmPrintSettings())
        guard PMSessionGetDestinationType(session, settings, &ziel) == noErr else { return false }
        return ziel == PMDestinationType(kPMDestinationPrinter)
    }

    /// ipp, http, socket, lpd, smb oder dnssd-Dienst `_pdl-datastream`, `_printer`, `_ipp` (ohne s) → unsicher.
    public static func classify(_ url: URL) -> PrinterCheck {
        let scheme = (url.scheme ?? "").lowercased()
        if ["ipp", "http", "socket", "lpd", "smb"].contains(scheme) { return .insecure }
        if scheme == "dnssd" || scheme == "mdns" {
            let text = (url.absoluteString.removingPercentEncoding ?? url.absoluteString).lowercased()
            for dienst in ["._pdl-datastream.", "._printer.", "._ipp."] where text.contains(dienst) {
                return .insecure
            }
        }
        return .secure
    }

    /// Druckt das Blatt mit den im Dialog gewählten Einstellungen (kein zweiter Dialog). Den Code zeichnet die
    /// Ansicht nur, wenn die Ausgabe zur Druckzeit ein Drucker ist.
    public static func printSheet(_ code: RecoveryCode, info: NSPrintInfo) -> PrintOutcome {
        printSheet(.recovery(code), info: info)
    }

    /// Wie oben, für einen Teil des geteilten Codes (§15) oder die Schlüsselkarte (§14.2).
    public static func printSheet(_ content: PrintSheetContent, info: NSPrintInfo) -> PrintOutcome {
        guard isPaper(info) else { return .notPaper }
        let view = RecoveryKitSheetView(content: content, paper: info.paperSize)
        let operation = NSPrintOperation(view: view, printInfo: info)
        operation.jobTitle = "Dokument"
        operation.showsPrintPanel = false
        operation.showsProgressPanel = true
        operation.canSpawnSeparateThread = false
        WindowGuard.shared.protectAll()
        let ok = operation.run()
        let mitCode = view.drewCode
        view.wipe()
        guard ok else { return .cancelled }
        return mitCode ? .paper : .notPaper
    }

    /// Für Snapshots: das Blatt als Ansicht (A4), mit Code.
    @_spi(Snapshots) public static func makeSheetView(_ code: RecoveryCode) -> NSView {
        RecoveryKitSheetView(content: .recovery(code), paper: NSSize(width: 595, height: 842), preview: true)
    }

    /// Für Snapshots: das Blatt, wie es bei Ausgabe als PDF aussieht (ohne Code).
    @_spi(Snapshots) public static func makeSheetViewWithoutPrinter(_ code: RecoveryCode) -> NSView {
        RecoveryKitSheetView(content: .recovery(code), paper: NSSize(width: 595, height: 842), preview: false)
    }

    /// Für Snapshots: beliebiges Blatt (Teil, Karte) als Vorschau mit Code.
    @_spi(Snapshots) public static func makeSheetView(_ content: PrintSheetContent) -> NSView {
        RecoveryKitSheetView(content: content, paper: NSSize(width: 595, height: 842), preview: true)
    }
}

/// Inhalt eines gedruckten Blatts: Notfallkit, ein Teil des geteilten Codes oder die Schlüsselkarte.
public struct PrintSheetContent {
    public enum Kind: Equatable, Sendable {
        case recovery
        case share(index: Int, total: Int)
        case card
    }

    let kind: Kind
    let groups: [String]
    let kitID: String?
    let qr: CGImage?

    public static func recovery(_ code: RecoveryCode) -> PrintSheetContent {
        PrintSheetContent(kind: .recovery, groups: code.groups, kitID: code.kitID, qr: nil)
    }

    public static func share(_ share: RecoveryShare, total: Int) -> PrintSheetContent {
        PrintSheetContent(kind: .share(index: share.index, total: total), groups: share.groups, kitID: share.kitID, qr: nil)
    }

    public static func card(groups: [String], qr: CGImage?) -> PrintSheetContent {
        PrintSheetContent(kind: .card, groups: groups, kitID: nil, qr: qr)
    }

    var subtitle: String {
        switch kind {
        case .recovery: "Notfallkit"
        case let .share(index, total): "Notfallkit · Teil \(index) von \(total)"
        case .card: "Schlüsselkarte"
        }
    }

    var codeTitle: String {
        switch kind {
        case .recovery: "Notfallcode"
        case let .share(index, total): "Teil \(index) von \(total)"
        case .card: "Kartencode"
        }
    }

    var warning: String {
        switch kind {
        case .recovery: RecoveryKitTexts.warning
        case .share: RecoveryKitTexts.shareWarning
        case .card: CardTexts.warning
        }
    }

    var howTo: String {
        switch kind {
        case .recovery: RecoveryKitTexts.howTo
        case .share: RecoveryKitTexts.shareHowTo
        case .card: CardTexts.howTo
        }
    }
}

/// Das gedruckte Blatt: schlicht schwarz auf weiss, Logo, Code in Gruppen (bzw. Karte mit QR-Code), Kit-Kennung,
/// Warnung, Anleitung.
final class RecoveryKitSheetView: NSView {
    private var groups: [String]
    private var qr: CGImage?
    private let content: PrintSheetContent
    private let created = Date()
    /// Nur Snapshots: Code ohne Druckauftrag zeichnen.
    private let preview: Bool
    /// Wurde der Code in einen Druckauftrag an einen Drucker gezeichnet?
    private(set) var drewCode = false

    init(content: PrintSheetContent, paper: NSSize, preview: Bool = false) {
        self.content = content
        self.groups = content.groups
        self.qr = content.qr
        self.preview = preview
        super.init(frame: NSRect(origin: .zero, size: paper))
    }

    required init?(coder: NSCoder) {
        self.content = PrintSheetContent(kind: .recovery, groups: [], kitID: nil, qr: nil)
        self.groups = []
        self.qr = nil
        self.preview = false
        super.init(coder: coder)
    }

    /// Den Code nur auf Papier: im laufenden Druckauftrag an einen Drucker (oder in der Snapshot-Vorschau).
    private var mayDrawCode: Bool {
        if let operation = NSPrintOperation.current {
            return RecoveryKitPrinter.isPaper(operation.printInfo)
        }
        return preview
    }

    override var isFlipped: Bool { true }

    func wipe() {
        groups = []
        qr = nil
    }

    override func draw(_ dirtyRect: NSRect) {
        guard let context = NSGraphicsContext.current?.cgContext else { return }
        NSColor.white.setFill()
        bounds.fill()

        let rand: CGFloat = 64
        let breite = bounds.width - 2 * rand
        var y: CGFloat = 70

        // Kopf: Logo 42 pt (u = 2) und Titel
        let logo = SiegelMark().path(in: CGRect(x: rand, y: y, width: 42, height: 42)).cgPath
        context.addPath(logo)
        context.setFillColor(NSColor.black.cgColor)
        context.fillPath()
        text("Siegel", size: 22, weight: .semibold).draw(at: NSPoint(x: rand + 42 + 16, y: y - 1))
        text(content.subtitle, size: 13, weight: .regular).draw(at: NSPoint(x: rand + 42 + 16, y: y + 26))

        let datum = DateFormatter.localizedString(from: created, dateStyle: .long, timeStyle: .none)
        if let kitID = content.kitID {
            let rechts = text("Kit-Kennung " + kitID, size: 11, weight: .medium, mono: true)
            rechts.draw(at: NSPoint(x: rand + breite - rechts.size().width, y: y + 4))
        }
        let erstellt = text("Erstellt am " + datum, size: 10, weight: .regular)
        erstellt.draw(at: NSPoint(x: rand + breite - erstellt.size().width, y: y + 22))

        y += 42 + 40
        line(context, y: y, from: rand, width: breite, weight: 0.75)
        y += 28

        if content.kind == .card {
            y = drawCard(context, x: rand, y: y, width: breite)
        } else {
            text(content.codeTitle, size: 11, weight: .semibold).draw(at: NSPoint(x: rand, y: y))
            y += 26
            let zeilen = CGFloat((max(groups.count, 1) + 2) / 3)
            // Code: 3 Spalten, je mit Gruppennummer – nur auf Papier
            if mayDrawCode {
                let spalten = 3
                let spaltenBreite = breite / CGFloat(spalten)
                for (index, gruppe) in groups.enumerated() {
                    let spalte = index % spalten
                    let zeile = index / spalten
                    let x = rand + CGFloat(spalte) * spaltenBreite
                    let gy = y + CGFloat(zeile) * 58
                    text(String(index + 1), size: 9, weight: .medium).draw(at: NSPoint(x: x, y: gy))
                    text(gruppe, size: 24, weight: .medium, mono: true, kern: 2).draw(at: NSPoint(x: x, y: gy + 13))
                }
                if NSPrintOperation.current != nil, !groups.isEmpty { drewCode = true }
            } else {
                text(RecoveryKitPrinter.notPaperSheetText, size: 14, weight: .medium).draw(at: NSPoint(x: rand, y: y + 80))
            }
            y += max(zeilen, 4) * 58 + 18
        }
        line(context, y: y, from: rand, width: breite, weight: 0.75)
        y += 28

        let warnung = NSAttributedString(string: content.warning, attributes: [
            .font: NSFont.systemFont(ofSize: 11.5, weight: .medium),
            .foregroundColor: NSColor.black,
            .paragraphStyle: paragraph(lineSpacing: 3),
        ])
        let warnungsHoehe = warnung.boundingRect(with: NSSize(width: breite, height: 400),
                                                 options: [.usesLineFragmentOrigin]).height
        warnung.draw(with: NSRect(x: rand, y: y, width: breite, height: warnungsHoehe + 4),
                     options: [.usesLineFragmentOrigin])
        y += warnungsHoehe + 26

        let anleitung = NSAttributedString(string: content.howTo, attributes: [
            .font: NSFont.systemFont(ofSize: 10.5),
            .foregroundColor: NSColor.black,
            .paragraphStyle: paragraph(lineSpacing: 3),
        ])
        let anleitungsHoehe = anleitung.boundingRect(with: NSSize(width: breite, height: 400),
                                                     options: [.usesLineFragmentOrigin]).height
        anleitung.draw(with: NSRect(x: rand, y: y, width: breite, height: anleitungsHoehe + 4),
                       options: [.usesLineFragmentOrigin])
    }

    /// Karte in Originalgrösse (85,6 × 54 mm) mit Schnittlinie: QR-Code links, Code in Gruppen rechts.
    private func drawCard(_ context: CGContext, x: CGFloat, y: CGFloat, width: CGFloat) -> CGFloat {
        let mm: CGFloat = 72 / 25.4
        let karte = CGRect(x: x, y: y, width: 85.6 * mm, height: 54 * mm)
        context.saveGState()
        context.setStrokeColor(NSColor.black.cgColor)
        context.setLineWidth(0.6)
        context.setLineDash(phase: 0, lengths: [3, 3])
        context.addPath(CGPath(roundedRect: karte, cornerWidth: 3.2 * mm, cornerHeight: 3.2 * mm, transform: nil))
        context.strokePath()
        context.restoreGState()

        if mayDrawCode {
            // QR links (≈ 40 mm), Code rechts in 4 Zeilen à 3 Gruppen – alles innerhalb der Karte.
            let seite = karte.height - 40
            let qrRect = CGRect(x: karte.minX + 12, y: karte.minY + 20, width: seite, height: seite)
            if let qr {
                context.saveGState()
                context.interpolationQuality = .none
                // Ansicht ist gespiegelt (isFlipped): Bild aufrecht zeichnen.
                context.translateBy(x: qrRect.minX, y: qrRect.maxY)
                context.scaleBy(x: 1, y: -1)
                context.draw(qr, in: CGRect(origin: .zero, size: qrRect.size))
                context.restoreGState()
            } else {
                text("QR-Code", size: 10, weight: .medium).draw(at: NSPoint(x: qrRect.minX + 10, y: qrRect.midY - 6))
            }
            let textX = qrRect.maxX + 12
            text("Siegel", size: 9, weight: .semibold).draw(at: NSPoint(x: textX, y: qrRect.minY))
            text("Schlüsselkarte", size: 7.5, weight: .regular).draw(at: NSPoint(x: textX, y: qrRect.minY + 12))
            for (zeile, start) in stride(from: 0, to: groups.count, by: 3).enumerated() {
                let teil = groups[start..<min(start + 3, groups.count)].joined(separator: " ")
                text(teil, size: 7.4, weight: .medium, mono: true)
                    .draw(at: NSPoint(x: textX, y: qrRect.minY + 38 + CGFloat(zeile) * 13))
            }
            if NSPrintOperation.current != nil, !groups.isEmpty { drewCode = true }
        } else {
            text(RecoveryKitPrinter.notPaperSheetText, size: 12, weight: .medium)
                .draw(at: NSPoint(x: karte.minX + 14, y: karte.midY - 8))
        }
        text("Entlang der Linie ausschneiden. Am besten auf festes Papier drucken.", size: 9.5, weight: .regular)
            .draw(at: NSPoint(x: x, y: karte.maxY + 10))
        return karte.maxY + 40
    }

    private func text(_ string: String, size: CGFloat, weight: NSFont.Weight, mono: Bool = false,
                      kern: CGFloat = 0) -> NSAttributedString {
        let font = mono ? NSFont.monospacedSystemFont(ofSize: size, weight: weight) : NSFont.systemFont(ofSize: size, weight: weight)
        return NSAttributedString(string: string, attributes: [.font: font, .foregroundColor: NSColor.black, .kern: kern])
    }

    private func paragraph(lineSpacing: CGFloat) -> NSParagraphStyle {
        let style = NSMutableParagraphStyle()
        style.lineSpacing = lineSpacing
        return style
    }

    private func line(_ context: CGContext, y: CGFloat, from x: CGFloat, width: CGFloat, weight: CGFloat) {
        context.setStrokeColor(NSColor.black.cgColor)
        context.setLineWidth(weight)
        context.move(to: CGPoint(x: x, y: y))
        context.addLine(to: CGPoint(x: x + width, y: y))
        context.strokePath()
    }
}

/// Texte des Notfallkits (Bildschirm und Blatt).
public enum RecoveryKitTexts {
    /// Wörtlich aus SPEC §7.6.
    public static let warning = "Wer dieses Blatt und eine Kopie der Tresordatei hat, hat alle Passwörter – ohne Master-Passwort. Nur auf Papier aufbewahren, nicht als PDF, Foto oder in einer Cloud speichern. Nicht fotografieren – Live Text macht den Code in Fotos durchsuchbar."

    public static let howTo = "So verwendest du den Code: Siegel öffnen, im Sperrbildschirm „Notfallcode verwenden“ wählen, den Code abtippen und ein neues Master-Passwort festlegen. Auf einem neuen Mac: in der Einrichtung „Aus Sicherung wiederherstellen…“ wählen, die Sicherung (z. B. vom USB-Stick) öffnen und „Notfallcode verwenden“. Unleserliche Zeichen als\u{00A0}„\u{2060}?\u{2060}“\u{00A0}eingeben – Siegel ergänzt bis zu vier davon. Gross- und Kleinschreibung und Bindestriche spielen keine Rolle."

    /// Geteilter Code (§15, Stufen 4/5).
    public static let shareWarning = "Je zwei dieser drei Teile und eine Kopie der Tresordatei öffnen alle Passwörter – ohne Master-Passwort, Touch ID, Karte oder Schlüssel. Bewahre die Teile an drei verschiedenen Orten auf. Nur auf Papier, nicht als PDF, Foto oder in einer Cloud. Nicht fotografieren – Live Text macht den Code in Fotos durchsuchbar."

    public static let shareHowTo = "So verwendest du die Teile: Siegel öffnen, im Sperrbildschirm „Notfallcode verwenden“ wählen und zwei beliebige der drei Teile abtippen. Auf einem neuen Mac: in der Einrichtung „Aus Sicherung wiederherstellen…“ wählen, die Sicherung (z. B. vom USB-Stick) öffnen und „Notfallcode verwenden“. Unleserliche Zeichen als\u{00A0}„\u{2060}?\u{2060}“\u{00A0}eingeben. Ein einzelner Teil verrät nichts über den Code."

    /// Erklärung auf dem Bildschirm (geteilter Code).
    public static let shareIntro = "Dein Notfallcode ist in drei Teile geteilt. Je zwei Teile öffnen den Tresor, ein einzelner Teil verrät nichts. Bewahre sie an drei verschiedenen Orten auf – zum Beispiel zuhause, im Bankschliessfach und bei einer Vertrauensperson."
}

/// Texte der QR-Schlüsselkarte (§14.2).
public enum CardTexts {
    /// Wörtlich aus SPEC §14.2.
    public static let warning = "Diese Karte ist ein Schlüssel. Getrennt vom Mac aufbewahren. Nicht fotografieren."
    public static let howTo = "Siegel fragt beim Öffnen nach dieser Karte: Halte den QR-Code vor die Kamera des Macs. Ist die Kamera defekt, tippe den Code neben dem QR-Code ab."
}
