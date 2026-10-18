import AppKit
import AuthenticationServices
import SiegelCore

/// Autofill-Erweiterung von Siegel (SPEC §20, vorbereitet). Ablauf: Kopf prüfen (Stufe 4/5 → „nur in der App“),
/// Master-Passwort und bei Stufe 2/3 Touch ID, Liste der passenden Einträge (AutofillMatcher), Auswahl
/// (Schutz Fingerabdruck → Touch ID) → Zugang an das System, Tresor sofort sperren.
/// Nie still: `provideCredentialWithoutUserInteraction` verlangt immer eine Bedienung. Es werden keine
/// Kennungen beim System hinterlegt (ASCredentialIdentityStore), damit keine Titel oder Benutzernamen den
/// Tresor verlassen.
/// Nicht privat, was `Tests/SiegelAutofillTests` braucht (das Paket übersetzt diese Quellen als
/// `SiegelAutofillErweiterung`).
final class CredentialProviderViewController: ASCredentialProviderViewController, NSTextFieldDelegate {
    enum Zustand { case laden, passwort, arbeitet, liste, hinweis }

    /// Höchstens so lange bleibt eine offene Anfrage stehen, dann wird gesperrt und abgebrochen.
    private static let frist: TimeInterval = 120
    private static let maxZeilen = 8
    private static let breite: CGFloat = 400
    private static let grau = NSColor(srgbRed: 0x6E / 255, green: 0x6E / 255, blue: 0x6E / 255, alpha: 1)

    private(set) var zustand = Zustand.laden
    private var dienste: [String] = []
    private var hostText = ""
    private var sitzung: AutofillSitzung?
    private var kopf: VaultHeaderInfo?
    var treffer: [AutofillTreffer] = []
    private var fristTimer: Timer?
    private var erledigt = false

    /// Allgemeine Zwischenablage (Tests setzen eine eigene ein). Siegel liest ihren Inhalt nie.
    var zwischenablage: any AutofillZwischenablage = NSPasteboard.general
    /// Ereignis, das eine Textänderung ausgelöst hat (Tests setzen es selbst).
    var aktuellesEreignis: @MainActor () -> NSEvent? = { NSApp?.currentEvent }
    /// `changeCount` der Zwischenablage beim Einfügen ins Passwortfeld (SPEC §6, Befund bau-2), sonst nil.
    private var eingefuegtCC: Int?
    private var letzteLaenge = 0

    private let titel = NSTextField(labelWithString: "Siegel")
    private let unterzeile = NSTextField(labelWithString: "")
    let passwortFeld = NSSecureTextField()
    let meldung = NSTextField(wrappingLabelWithString: "")
    private let fortschritt = NSProgressIndicator()
    private let listenStapel = NSStackView()
    private let abbrechenKnopf = NSButton(title: "Abbrechen", target: nil, action: nil)
    private let entsperrenKnopf = NSButton(title: "Entsperren", target: nil, action: nil)

    // MARK: - Ansicht

    override func loadView() {
        let wurzel = NSView(frame: NSRect(x: 0, y: 0, width: Self.breite, height: 260))
        wurzel.appearance = NSAppearance(named: .aqua)
        wurzel.wantsLayer = true
        wurzel.layer?.backgroundColor = NSColor.white.cgColor

        titel.font = .systemFont(ofSize: 17, weight: .semibold)
        titel.textColor = .black
        unterzeile.font = .systemFont(ofSize: 13)
        unterzeile.textColor = Self.grau
        unterzeile.lineBreakMode = .byTruncatingMiddle

        passwortFeld.placeholderString = "Master-Passwort"
        passwortFeld.target = self
        passwortFeld.action = #selector(entsperrenGedrueckt(_:))
        passwortFeld.isAutomaticTextCompletionEnabled = false
        passwortFeld.setAccessibilityLabel("Master-Passwort")
        passwortFeld.delegate = self   // Einfügen erkennen (controlTextDidChange)

        meldung.font = .systemFont(ofSize: 12)
        meldung.textColor = .black
        meldung.isSelectable = false

        fortschritt.style = .bar
        fortschritt.isIndeterminate = true
        fortschritt.controlSize = .small

        listenStapel.orientation = .vertical
        listenStapel.alignment = .leading
        listenStapel.spacing = 6

        abbrechenKnopf.target = self
        abbrechenKnopf.action = #selector(abbrechenGedrueckt(_:))
        abbrechenKnopf.keyEquivalent = "\u{1b}"
        entsperrenKnopf.target = self
        entsperrenKnopf.action = #selector(entsperrenGedrueckt(_:))
        entsperrenKnopf.keyEquivalent = "\r"
        entsperrenKnopf.bezelColor = .black

        let knopfZeile = NSStackView(views: [abbrechenKnopf, entsperrenKnopf])
        knopfZeile.orientation = .horizontal
        knopfZeile.spacing = 8

        let stapel = NSStackView(views: [titel, unterzeile, passwortFeld, meldung, fortschritt, listenStapel, knopfZeile])
        stapel.orientation = .vertical
        stapel.alignment = .leading
        stapel.spacing = 10
        stapel.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 20, right: 24)
        stapel.setCustomSpacing(4, after: titel)
        stapel.setCustomSpacing(16, after: unterzeile)
        stapel.translatesAutoresizingMaskIntoConstraints = false
        wurzel.addSubview(stapel)

        let innen = Self.breite - 48
        NSLayoutConstraint.activate([
            stapel.leadingAnchor.constraint(equalTo: wurzel.leadingAnchor),
            stapel.trailingAnchor.constraint(equalTo: wurzel.trailingAnchor),
            stapel.topAnchor.constraint(equalTo: wurzel.topAnchor),
            stapel.bottomAnchor.constraint(equalTo: wurzel.bottomAnchor),
            wurzel.widthAnchor.constraint(equalToConstant: Self.breite),
            passwortFeld.widthAnchor.constraint(equalToConstant: innen),
            meldung.widthAnchor.constraint(equalToConstant: innen),
            fortschritt.widthAnchor.constraint(equalToConstant: innen),
            listenStapel.widthAnchor.constraint(equalToConstant: innen),
            knopfZeile.widthAnchor.constraint(equalToConstant: innen),
        ])
        knopfZeile.insertView(NSView(), at: 0, in: .leading)   // Knöpfe rechts
        view = wurzel
        setze(.laden)
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        view.window?.sharingType = .none   // nicht in Bildschirmaufnahmen (SPEC §6)
        if zustand == .passwort { view.window?.makeFirstResponder(passwortFeld) }
    }

    override func viewWillDisappear() {
        super.viewWillDisappear()
        aufraeumen()
    }

    private func setze(_ neu: Zustand) {
        zustand = neu
        passwortFeld.isHidden = neu != .passwort && neu != .arbeitet
        passwortFeld.isEnabled = neu == .passwort
        entsperrenKnopf.isHidden = neu != .passwort && neu != .arbeitet
        entsperrenKnopf.isEnabled = neu == .passwort
        abbrechenKnopf.title = neu == .hinweis ? "Schliessen" : "Abbrechen"
        fortschritt.isHidden = neu != .arbeitet && neu != .laden
        if fortschritt.isHidden { fortschritt.stopAnimation(nil) } else { fortschritt.startAnimation(nil) }
        listenStapel.isHidden = neu != .liste
        if neu != .liste { listenStapel.arrangedSubviews.forEach { $0.removeFromSuperview() } }
        meldung.isHidden = meldung.stringValue.isEmpty
        if neu == .passwort { view.window?.makeFirstResponder(passwortFeld) }
    }

    private func zeigeMeldung(_ text: String) {
        meldung.stringValue = text
        meldung.isHidden = text.isEmpty
    }

    // MARK: - Zwischenablage (SPEC §6, Befund bau-2)

    /// Einfügen ins Passwortfeld erkennen, ohne die Zwischenablage zu lesen (wie `MasterPasswordCoordinator` der App):
    /// Der Text wird länger, aber nicht durch einfaches Tippen (⌘V, Kontextmenü „Einfügen“). Gemerkt wird nur der
    /// `changeCount`.
    func controlTextDidChange(_ obj: Notification) {
        guard (obj.object as? NSTextField) === passwortFeld else { return }
        let laenge = (passwortFeld.stringValue as NSString).length
        if laenge > letzteLaenge, Self.istEinfuegeArtig(aktuellesEreignis()) {
            eingefuegtCC = zwischenablage.changeCount
        }
        letzteLaenge = laenge
    }

    static func istEinfuegeArtig(_ ereignis: NSEvent?) -> Bool {
        guard let ereignis else { return true }
        if ereignis.type == .keyDown { return ereignis.modifierFlags.contains(.command) }
        return true
    }

    /// Leert die Zwischenablage, wenn sie seit dem Einfügen unverändert ist (sie enthält dann vermutlich das
    /// Master-Passwort). Nach dem Entsperren und beim Aufräumen (Auswahl, Abbruch, Frist). true = geleert.
    @discardableResult
    private func zwischenablageLeeren() -> Bool {
        defer { eingefuegtCC = nil }
        guard let cc = eingefuegtCC, zwischenablage.changeCount == cc else { return false }
        zwischenablage.leeren()
        return true
    }

    // MARK: - Anfragen des Systems

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        starten(mit: serviceIdentifiers)
    }

    /// Siegel füllt nie ohne Bedienung aus (Master-Passwort, Touch ID).
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        beenden(.userInteractionRequired)
    }

    /// Wird nur für hinterlegte Kennungen gerufen (Siegel hinterlegt keine); dann wie die Liste für diesen Dienst.
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        starten(mit: [credentialRequest.credentialIdentity.serviceIdentifier])
    }

    private func starten(mit kennungen: [ASCredentialServiceIdentifier]) {
        dienste = kennungen.map(\.identifier)
        hostText = kennungen.first.map(Self.host) ?? ""
        unterzeile.stringValue = hostText.isEmpty ? "Passwort einsetzen" : "Passwort für \(hostText)"
        zeigeMeldung("")
        setze(.laden)
        fristTimer?.invalidate()
        fristTimer = Timer.scheduledTimer(withTimeInterval: Self.frist, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated { self?.beenden(.userCanceled) }
        }
        Task.detached(priority: .userInitiated) { [weak self] in
            let ergebnis = Result { () throws -> (AutofillSitzung, VaultHeaderInfo) in
                let s = try AutofillSitzung.oeffnen()
                return (s, try s.vorpruefen())
            }
            await self?.nachVorpruefung(ergebnis)
        }
    }

    private func nachVorpruefung(_ ergebnis: Result<(AutofillSitzung, VaultHeaderInfo), any Error>) {
        guard !erledigt else { return }
        switch ergebnis {
        case let .success((s, k)):
            sitzung = s
            kopf = k
            setze(.passwort)
        case let .failure(fehler):
            zeigeMeldung(Self.text(fehler, kopf: nil))
            setze(.hinweis)
        }
    }

    // MARK: - Entsperren und Auswahl

    @objc private func entsperrenGedrueckt(_ sender: Any?) {
        guard zustand == .passwort, let sitzung, let kopf else { return }
        let passwort = passwortFeld.stringValue
        passwortFeld.stringValue = ""
        view.window?.fieldEditor(false, for: nil)?.string = ""
        letzteLaenge = 0
        guard !passwort.isEmpty else { return }
        zeigeMeldung("")
        setze(.arbeitet)
        let dienste = self.dienste
        Task.detached(priority: .userInitiated) { [weak self] in
            let ergebnis = Result { try sitzung.entsperren(masterPassword: passwort, kopf: kopf, dienste: dienste) }
            await self?.nachEntsperren(ergebnis)
        }
    }

    func nachEntsperren(_ ergebnis: Result<[AutofillTreffer], any Error>) {
        guard !erledigt else {
            sitzung?.sperren()
            return
        }
        switch ergebnis {
        case let .success(liste):
            let geleert = zwischenablageLeeren()
            treffer = liste
            zeigeListe(vorspann: geleert ? Self.zwischenablageGeleert : nil)
        case let .failure(fehler):
            zeigeMeldung(Self.text(fehler, kopf: kopf))
            setze(Self.istEndgueltig(fehler) ? .hinweis : .passwort)
        }
    }

    /// Liste der Treffer; `vorspann` (Fehler der letzten Auswahl, Zwischenablage geleert) steht vor dem Hinweis auf
    /// die Anzahl, statt von ihm überschrieben zu werden (Befund bau-3).
    private func zeigeListe(vorspann: String? = nil) {
        guard !treffer.isEmpty else {
            sitzung?.sperren()
            zeigeMeldung(Self.verbinde(vorspann, "Keine passenden Einträge für \(hostText.isEmpty ? "diese Seite" : hostText). "
                + "Einträge mit Schutz Hoch oder höher gibt es nur in der App."))
            setze(.hinweis)
            return
        }
        zeigeMeldung(Self.verbinde(vorspann, treffer.count > Self.maxZeilen
            ? "\(treffer.count) Einträge passen, gezeigt werden die ersten \(Self.maxZeilen)." : nil))
        setze(.liste)
        for (index, eintrag) in treffer.prefix(Self.maxZeilen).enumerated() {
            let knopf = NSButton(title: "", target: self, action: #selector(waehlen(_:)))
            knopf.bezelStyle = .flexiblePush
            knopf.alignment = .left
            knopf.tag = index
            knopf.attributedTitle = Self.zeile(eintrag)
            knopf.setAccessibilityLabel(eintrag.username.isEmpty ? eintrag.title : "\(eintrag.title), \(eintrag.username)")
            if treffer.count == 1 { knopf.keyEquivalent = "\r" }
            knopf.translatesAutoresizingMaskIntoConstraints = false
            listenStapel.addArrangedSubview(knopf)
            NSLayoutConstraint.activate([
                knopf.widthAnchor.constraint(equalTo: listenStapel.widthAnchor),
                knopf.heightAnchor.constraint(greaterThanOrEqualToConstant: 40),
            ])
        }
    }

    @objc private func waehlen(_ sender: NSButton) {
        guard zustand == .liste, treffer.indices.contains(sender.tag), let sitzung else { return }
        let id = treffer[sender.tag].id
        zeigeMeldung("")   // keine alte Meldung, während Touch ID läuft
        setze(.arbeitet)
        Task { [weak self] in
            do {
                let zugang = try await sitzung.zugang(fuer: id)
                self?.abschliessen(user: zugang.user, password: zugang.password)
            } catch {
                self?.auswahlGescheitert(error)
            }
        }
    }

    /// Auswahl gescheitert: endgültig → Hinweis; sonst zurück zur Liste, die Meldung bleibt dabei sichtbar
    /// (Befund bau-3: `zeigeListe` überschrieb sie sofort).
    func auswahlGescheitert(_ fehler: any Error) {
        guard !erledigt else { return }
        let text = Self.text(fehler, kopf: kopf)
        if Self.istEndgueltig(fehler) {
            sitzung?.sperren()
            zeigeMeldung(text)
            setze(.hinweis)
        } else {
            zeigeListe(vorspann: text)
        }
    }

    @objc private func abbrechenGedrueckt(_ sender: Any?) {
        beenden(.userCanceled)
    }

    // MARK: - Abschluss

    private func abschliessen(user: String, password: String) {
        guard !erledigt else { return }
        erledigt = true
        let zugang = ASPasswordCredential(user: user, password: password)
        aufraeumen()
        extensionContext.completeRequest(withSelectedCredential: zugang, completionHandler: nil)
    }

    private func beenden(_ code: ASExtensionError.Code) {
        guard !erledigt else { return }
        erledigt = true
        aufraeumen()
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    /// Tresor sperren, Eingaben und Liste leeren (auch beim Verschwinden der Ansicht).
    private func aufraeumen() {
        fristTimer?.invalidate()
        fristTimer = nil
        sitzung?.sperren()
        treffer = []
        passwortFeld.stringValue = ""
        view.window?.fieldEditor(false, for: nil)?.string = ""
        letzteLaenge = 0
        zwischenablageLeeren()
        listenStapel.arrangedSubviews.forEach { $0.removeFromSuperview() }
    }

    // MARK: - Texte

    private static func host(_ kennung: ASCredentialServiceIdentifier) -> String {
        switch kennung.type {
        case .URL:
            return URL(string: kennung.identifier)?.host(percentEncoded: false) ?? ""
        default:
            return kennung.identifier
        }
    }

    private static func zeile(_ eintrag: AutofillTreffer) -> NSAttributedString {
        let text = NSMutableAttributedString(
            string: eintrag.title.isEmpty ? "Ohne Titel" : eintrag.title,
            attributes: [.font: NSFont.systemFont(ofSize: 13, weight: .medium), .foregroundColor: NSColor.black])
        var zweite = eintrag.username
        if eintrag.protection == .fingerabdruck { zweite += zweite.isEmpty ? "Touch ID" : " · Touch ID" }
        if !zweite.isEmpty {
            text.append(NSAttributedString(
                string: "\n" + zweite,
                attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: grau]))
        }
        return text
    }

    static let zwischenablageGeleert = "Zwischenablage geleert – sie enthielt dein Master-Passwort."

    /// Teile einer Meldung mit Leerzeichen verbinden; ein Teil ohne Schlusszeichen bekommt einen Punkt.
    static func verbinde(_ teile: String?...) -> String {
        let da = teile.compactMap { $0 }.filter { !$0.isEmpty }
        return da.enumerated().map { index, teil in
            index < da.count - 1 && !(teil.last.map { ".!?…".contains($0) } ?? false) ? teil + "." : teil
        }.joined(separator: " ")
    }

    /// Endgültig = mit diesem Tresor geht es in der Erweiterung nicht weiter (nur „Schliessen“). Touch ID gesperrt
    /// oder nicht erreichbar ist vorübergehend (Befund bau-1): erneut versuchen, kein Notfallweg.
    static func istEndgueltig(_ fehler: any Error) -> Bool {
        if fehler is AutofillHinweis { return true }
        switch fehler as? SiegelError {
        case .wrongPassword, .kdfFailed, .factorCancelled, .factorTemporarilyUnavailable:
            return false
        default:
            return true
        }
    }

    /// Feste Texte; Fehlercodes werden nie angezeigt.
    static func text(_ fehler: any Error, kopf: VaultHeaderInfo?) -> String {
        if let hinweis = fehler as? AutofillHinweis {
            switch hinweis {
            case .keinTresor:
                return "Kein Tresor gefunden. Autofill braucht die Siegel-Version mit Autofill; öffne zuerst Siegel."
            case let .nurInApp(stufe):
                return "Dein Tresor hat die Stufe \(stufe.title). Passwörter gibt es dort nur in der App."
            case .rollback:
                return "Die Tresordatei ist älter als zuletzt gesehen. Öffne Siegel, um das zu prüfen."
            case .eintragFehlt:
                return "Dieser Eintrag ist nicht mehr verfügbar."
            }
        }
        guard let fehler = fehler as? SiegelError else { return "Das hat nicht geklappt. Öffne Siegel." }
        switch fehler {
        case .wrongPassword:
            return (kopf?.factors.isEmpty ?? true) ? "Falsches Passwort" : "Passwort oder ein Faktor stimmt nicht"
        case .kdfFailed:
            let gib = max(1, Int((kopf?.kdf.memLimitBytes ?? (1 << 30)) >> 30))
            return "Nicht genug freier Arbeitsspeicher (\(gib) GiB nötig). Andere Programme schliessen und erneut versuchen."
        case .factorCancelled:
            return "Touch ID abgebrochen."
        case .factorTemporarilyUnavailable(_, "se.lockout"):
            // Vorübergehend (v4.4, Befunde hardware-1/ablaeufe-9/bau-1): nicht endgültig, kein Notfallweg.
            return "Touch ID ist nach zu vielen Versuchen gesperrt. Entsperre den Mac einmal mit deinem Passwort und versuche es erneut."
        case .factorTemporarilyUnavailable(_, "se.notReachable"):
            return "Touch ID ist gerade nicht erreichbar (Deckel zu oder Tastatur mit Touch ID nicht verbunden). Öffne den Deckel bzw. schliesse die Tastatur an und versuche es erneut."
        case .factorTemporarilyUnavailable:
            return "Touch ID geht gerade nicht. Versuche es in einem Moment erneut."
        case .factorUnavailable, .factorMissing:
            // Nur, wenn der Schlüssel wirklich fehlt oder abgelehnt wurde, während Touch ID bereit ist (§14.1, v4.4).
            return "Touch ID lässt sich für diesen Tresor nicht verwenden – der Schlüssel fehlt auf diesem Mac oder die Fingerabdrücke wurden geändert. Öffne Siegel und nutze den Notfallcode."
        case .notAllowedAtLevel:
            return "Dieser Eintrag ist nur in der App verfügbar."
        case .corruptFile, .kdfParametersOutOfRange:
            return "Die Tresordatei ist beschädigt. Öffne Siegel."
        case .unsupportedVersion:
            return "Diese Datei braucht eine neuere Siegel-Version."
        case .vaultMissing:
            return "Kein Tresor gefunden. Öffne zuerst Siegel."
        default:
            return "Das hat nicht geklappt. Öffne Siegel."
        }
    }
}

/// Was die Erweiterung von der allgemeinen Zwischenablage braucht: nur Zähler und Leeren, nie den Inhalt.
@MainActor
protocol AutofillZwischenablage: AnyObject {
    var changeCount: Int { get }
    func leeren()
}

extension NSPasteboard: AutofillZwischenablage {
    func leeren() {
        clearContents()
    }
}
