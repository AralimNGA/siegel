import AppKit
import SiegelCore
import SwiftUI

// Einstellungen → Sicherheitsstufe (SPEC v4 §13): Übersicht der fünf Stufen („Was du zum Öffnen brauchst /
// was im Notfall“) und der Assistent für den Wechsel bzw. für das Einrichten von Faktoren für Einträge (§16).

/// Texte zu den Stufen (ehrlich, für Laien).
enum LevelTexts {
    static func open(_ level: SecurityLevel) -> String {
        let teile = ["Passwort"] + level.factors.kinds.map { FactorUI.name($0) }
        return teile.joined(separator: " + ")
    }

    static func emergency(_ level: SecurityLevel) -> String {
        emergency(level.recoveryScheme)
    }

    /// Nach dem Notfall-Schema des Kits (Kopf): Nach einer Wiederherstellung mit Teilen ist der Tresor Stufe 1,
    /// das Kit bleibt aber „2 aus 3“, bis ein neues geschrieben wird (§15).
    static func emergency(_ scheme: RecoveryScheme) -> String {
        scheme == .shamir2of3 ? "2 von 3 Teilen" : "Ein Notfallcode"
    }

    static func rules(_ level: SecurityLevel) -> String {
        switch level {
        case .standard: "Wie bisher: das Master-Passwort öffnet den Tresor."
        case .erhoeht: "Zusätzlich Touch ID dieses Macs."
        case .hoch: "Wie Erhöht, mit strengen Regeln: Touch ID vor jedem Aufdecken, Sperre beim App-Wechsel."
        // Befund design-6: auch der verschlüsselte KeePass-Export ist gesperrt (LevelPolicy, §13).
        case .maximal: "Wie Hoch, dazu die QR-Schlüsselkarte. Kein CSV- und KeePass-Export."
        case .festung: "Wie Maximal, dazu ein FIDO2-Sicherheitsschlüssel."
        }
    }

    /// „Was du zum Öffnen brauchst“ ausführlich.
    static func openLong(_ level: SecurityLevel) -> String {
        switch level {
        case .standard: "Dein Master-Passwort."
        case .erhoeht, .hoch: "Dein Master-Passwort und deinen Finger auf Touch ID dieses Macs."
        case .maximal: "Dein Master-Passwort, Touch ID dieses Macs und die QR-Schlüsselkarte (vor die Kamera halten oder abtippen)."
        case .festung: "Dein Master-Passwort, Touch ID dieses Macs, die QR-Schlüsselkarte und deinen Sicherheitsschlüssel."
        }
    }

    /// „Was im Notfall“ ausführlich.
    static func emergencyLong(_ level: SecurityLevel) -> String {
        switch level.recoveryScheme {
        case .single:
            "Den Notfallcode auf deinem Blatt. Er ersetzt Passwort und Faktoren – bewahre ihn gut auf."
        case .shamir2of3:
            "Zwei der drei Teile des Notfallcodes, an verschiedenen Orten aufbewahrt. Ein Teil allein nützt niemandem."
        }
    }

    /// Regeln ausführlich (Detail der Übersicht).
    static func rulesLong(_ level: SecurityLevel) -> [String] {
        let p = level.policy
        var out: [String] = []
        out.append(level.kdf == .strong ? "Starke Schlüsselableitung (2 GiB, etwa 3 s)" : "Schlüsselableitung Standard (1 GiB, etwa 1 s)")
        if p.touchIDBeforeReveal { out.append("Touch ID vor jedem Aufdecken und Kopieren") }
        if p.lockOnDeactivate { out.append("Sperre beim Wechsel in ein anderes Programm") }
        if let s = p.clipboardSecondsMax { out.append("Zwischenablage höchstens \(s) s") }
        if let m = p.autoLockMinutesMax { out.append("Auto-Sperre höchstens \(m) Min.") }
        if p.defaultEntryProtection > .normal { out.append("Neue Einträge mit Schutz \(p.defaultEntryProtection.rawValue)") }
        // An beide Regeln gebunden, damit Text und Regel nicht auseinanderlaufen (Befund design-6).
        if !p.allowCSVExport && !p.allowKeePassExport {
            out.append("Kein CSV- und KeePass-Export")
        } else if !p.allowCSVExport {
            out.append("Kein CSV-Export")
        } else if !p.allowKeePassExport {
            out.append("Kein KeePass-Export")
        }
        if level >= .maximal { out.append("Selbstvernichtung ausgewählter Einträge möglich") }
        return out
    }

    static let touchIDCaveat = "Touch ID gilt nur auf diesem Mac. Auf einem anderen Mac oder nach geänderten Fingerabdrücken öffnet nur noch der Notfallcode."

    // Befund design-7: „die Secure Enclave“ (wie Apple: in der, die), nicht „im/den Secure Enclave“.
    static let touchIDPlanned = "Touch ID: Schlüssel in der Secure Enclave dieses Macs anlegen"
    static let touchIDSetupLevel = "Siegel legt in der Secure Enclave dieses Macs einen Schlüssel an. Er verlässt den Mac nie; nur dein Finger gibt ihn frei. Danach einmal mit Touch ID prüfen."
    static let touchIDSetupEntries = "Siegel legt in der Secure Enclave dieses Macs einen Schlüssel für geschützte Einträge an. Nur dein Finger gibt ihn frei."
}

/// Nur für SiegelSnapshots: Texte der Stufen und alle sichtbaren Sätze mit „Secure Enclave“ (Befunde design-6/-7).
@_spi(Snapshots) public enum LevelTextsProbe {
    public static func rules(_ level: SecurityLevel) -> String { LevelTexts.rules(level) }
    public static func rulesLong(_ level: SecurityLevel) -> [String] { LevelTexts.rulesLong(level) }
    public static var secureEnclaveTexts: [String] {
        [LevelTexts.touchIDPlanned, LevelTexts.touchIDSetupLevel, LevelTexts.touchIDSetupEntries, SecurityTexts.factors,
         DestructionTexts.honest]
    }
}

/// Stufen-Nummer im Kreis (aktuelle Stufe gefüllt).
struct LevelBadge: View {
    var number: Int
    var filled: Bool
    var size: CGFloat = 28

    var body: some View {
        Text("\(number)")
            .font(.system(size: size * 0.46, weight: .semibold))
            .monospacedDigit()
            .foregroundStyle(filled ? Theme.background : Theme.text)
            .frame(width: size, height: size)
            .background(Circle().fill(filled ? Theme.text : Theme.background))
            .overlay(Circle().strokeBorder(Theme.text, lineWidth: filled ? 0 : 1))
    }
}

/// Symbole der Faktoren in einer Zeile (Passwort zuerst).
struct FactorGlyphs: View {
    var factors: FactorSet
    var password = true
    var size: CGFloat = 12

    var body: some View {
        HStack(spacing: 7) {
            if password {
                Image(systemName: FactorUI.passwordSymbol)
                    .help("Master-Passwort")
            }
            ForEach(factors.kinds, id: \.self) { kind in
                Image(systemName: FactorUI.symbol(kind))
                    .help(FactorUI.longName(kind))
            }
        }
        .font(.system(size: size, weight: .medium))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel((password ? "Passwort" : "") + (factors.isEmpty ? "" : ", " + FactorUI.list(factors)))
    }
}

// MARK: - Übersicht

struct SecurityLevelOverview: View {
    let model: AppModel
    @Bindable var state: SettingsState

    private var chosen: SecurityLevel { state.chosenLevel ?? model.level }

    var body: some View {
        SettingsForm(title: "Sicherheitsstufe",
                     text: "Je höher die Stufe, desto mehr brauchst du zum Öffnen – und desto weniger nützt eine gestohlene Datei oder ein abgeschautes Passwort. Jeder Faktor geht in den Schlüssel ein; ohne ihn entsteht ein falscher Schlüssel.",
                     width: 560) {
            VStack(spacing: 0) {
                HStack(spacing: 14) {
                    Text("Stufe").frame(width: 28 + 14 + 196, alignment: .leading)
                    Text("Zum Öffnen").frame(width: 150, alignment: .leading)
                    Text("Im Notfall").frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(Theme.label)
                .foregroundStyle(Theme.secondary)
                .textCase(.uppercase)
                .kerning(0.6)
                .padding(.horizontal, 14)
                .padding(.bottom, 8)
                Hairline()
                ForEach(SecurityLevel.allCases, id: \.self) { level in
                    LevelRow(level: level, current: level == model.level, selected: level == chosen) {
                        state.chosenLevel = level
                    }
                    Hairline()
                }
            }

            detail
                .padding(.top, 14)

            HStack(spacing: 12) {
                Spacer()
                Button("Zurück") { model.settingsBack() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Button(chosen == model.level ? "Aktuelle Stufe" : "Zu Stufe \(chosen.rawValue) wechseln…") {
                    model.startLevelChange(to: chosen)
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(chosen == model.level || model.busy || model.blocksLevelChange(to: chosen))
                .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 10)
        }
    }

    private var detail: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                LevelBadge(number: chosen.rawValue, filled: true, size: 22)
                Text(chosen.title)
                    .font(Theme.heading)
                if chosen == model.level {
                    Text("Aktuell")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                }
            }
            HStack(alignment: .top, spacing: 20) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Was du zum Öffnen brauchst")
                        .font(Theme.caption.weight(.semibold))
                    Text(LevelTexts.openLong(chosen))
                        .font(Theme.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .leading, spacing: 5) {
                    Text("Was im Notfall")
                        .font(Theme.caption.weight(.semibold))
                    Text(LevelTexts.emergencyLong(chosen))
                        .font(Theme.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            VStack(alignment: .leading, spacing: 5) {
                Text("Regeln")
                    .font(Theme.caption.weight(.semibold))
                Text(LevelTexts.rulesLong(chosen).joined(separator: " · "))
                    .font(Theme.caption)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if chosen.factors.contains(.secureEnclave) {
                Text(LevelTexts.touchIDCaveat)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if chosen.factors.contains(.securityKey) {
                Text("Den Sicherheitsschlüssel spricht Siegel selbst über USB an (CTAP2, hmac-secret). Mit echter Hardware ist das noch ungetestet.")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if chosen.factors.contains(.secureEnclave), !model.hardware.secureEnclaveAvailable {
                MessageText("Dieser Mac hat kein nutzbares Touch ID. Für diese Stufe braucht es Touch ID mit eingerichtetem Fingerabdruck.")
            }
            if model.blocksLevelChange(to: chosen) {
                MessageText(DestructionTexts.levelBlocked)
            }
        }
        .lineSpacing(2)
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

/// Eine Zeile der Stufen-Tabelle; gewählt = schwarzer Rand.
struct LevelRow: View {
    var level: SecurityLevel
    var current: Bool
    var selected: Bool
    var onSelect: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack(alignment: .top, spacing: 14) {
                LevelBadge(number: level.rawValue, filled: current)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(level.title)
                            .font(Theme.bodyMedium)
                        if current {
                            Text("Aktuell")
                                .font(.system(size: 10, weight: .semibold))
                                .fixedSize()
                                .padding(.horizontal, 7)
                                .frame(height: 17)
                                .overlay(RoundedRectangle(cornerRadius: 8.5, style: .circular).strokeBorder(Theme.text, lineWidth: 1))
                        }
                    }
                    Text(LevelTexts.rules(level))
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .lineSpacing(1)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(width: 196, alignment: .leading)
                VStack(alignment: .leading, spacing: 5) {
                    FactorGlyphs(factors: level.factors)
                    Text(LevelTexts.open(level))
                        .font(Theme.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(width: 150, alignment: .leading)
                .padding(.top, 2)
                Text(LevelTexts.emergency(level))
                    .font(Theme.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            }
            .foregroundStyle(Theme.text)
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(selected ? Theme.text : Color.clear, lineWidth: 1.5)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityLabel("Stufe \(level.rawValue), \(level.title)")
    }
}

// MARK: - Assistent

struct SecurityWizardView: View {
    let model: AppModel
    @Bindable var wizard: SecurityWizardState

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if wizard.step != .done { kopf }
            Group {
                switch wizard.step {
                case .intro: intro
                case .verify: verify
                case .touchID: touchID
                case .card: card
                case .securityKey: securityKey
                case .recovery: recovery
                case .apply: apply
                case .done: done
                }
            }
            .padding(.top, wizard.step == .done ? 0 : 18)
        }
        .frame(width: 560, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Kopf

    private var kopf: some View {
        VStack(alignment: .leading, spacing: 10) {
            if wizard.step != .done {
                let (n, total) = wizard.stepNumber
                Text("Schritt \(n) von \(total)")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .monospacedDigit()
            }
            switch wizard.mode {
            case let .changeLevel(target):
                HStack(spacing: 10) {
                    LevelBadge(number: wizard.from.rawValue, filled: false, size: 24)
                    Image(systemName: "arrow.right")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.secondary)
                    LevelBadge(number: target.rawValue, filled: true, size: 24)
                    Text(target > wizard.from ? "Auf \(target.title) erhöhen" : "Auf \(target.title) senken")
                        .font(Theme.title)
                        .padding(.leading, 4)
                }
            case let .enroll(kinds):
                Text(kinds.kinds.count == 1 ? FactorUI.longName(kinds.kinds.first ?? .secureEnclave) + " für Einträge einrichten"
                                      : "Faktoren für Einträge einrichten")
                    .font(Theme.title)
            }
            if wizard.step != .done {
                StepDots(steps: wizard.steps.filter { $0 != .done }, current: wizard.step)
                    .padding(.top, 2)
            }
        }
    }

    // MARK: Vergleich

    @ViewBuilder
    private var intro: some View {
        if let target = wizard.target {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top, spacing: 0) {
                    comparison("Bisher", wizard.from, scheme: wizard.header.recoveryScheme)
                    Hairline(vertical: true).padding(.horizontal, 18)
                    comparison("Danach", target)
                }
                .padding(16)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))

                if !plannedSetup.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Das richtest du jetzt ein")
                            .font(Theme.caption.weight(.semibold))
                        ForEach(Array(plannedSetup.enumerated()), id: \.offset) { _, item in
                            HStack(spacing: 10) {
                                Image(systemName: item.symbol)
                                    .font(.system(size: 12, weight: .medium))
                                    .frame(width: 18)
                                Text(item.text)
                                    .font(Theme.caption)
                            }
                        }
                    }
                }
                Text(target > wizard.from
                     ? "Bis zum letzten Schritt ändert sich nichts. Danach verschlüsselt Siegel alles neu, und der Tresor öffnet sich nur noch mit: " + LevelTexts.open(target) + "."
                     : "Bis zum letzten Schritt ändert sich nichts. Danach verschlüsselt Siegel alles neu; bisherige Faktoren werden zum Öffnen nicht mehr gebraucht."
                       + (removesTouchID ? " Den Touch-ID-Schlüssel zum Öffnen entfernt Siegel danach von diesem Mac." : ""))
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
                if target.factors.contains(.secureEnclave), !model.hardware.secureEnclaveAvailable {
                    MessageText("Dieser Mac hat kein nutzbares Touch ID. Richte Touch ID in den Systemeinstellungen ein und versuche es dann erneut.")
                }
                buttons(primary: "Weiter",
                        enabled: !(target.factors.contains(.secureEnclave) && !model.hardware.secureEnclaveAvailable)) {
                    model.wizardAdvance()
                }
            }
        }
    }

    private func comparison(_ title: String, _ level: SecurityLevel, scheme: RecoveryScheme? = nil) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(Theme.label)
                .foregroundStyle(Theme.secondary)
                .textCase(.uppercase)
                .kerning(0.6)
            HStack(spacing: 8) {
                LevelBadge(number: level.rawValue, filled: false, size: 20)
                Text(level.title).font(Theme.bodyMedium)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text("Zum Öffnen").font(Theme.caption).foregroundStyle(Theme.secondary)
                HStack(spacing: 8) {
                    FactorGlyphs(factors: level.factors, size: 11)
                    Text(LevelTexts.open(level)).font(Theme.caption)
                }
            }
            VStack(alignment: .leading, spacing: 3) {
                Text("Im Notfall").font(Theme.caption).foregroundStyle(Theme.secondary)
                Text(LevelTexts.emergency(scheme ?? level.recoveryScheme)).font(Theme.caption)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Abwärts ohne Touch ID: der Entsperr-Schlüssel wird nach dem Schreiben entfernt.
    private var removesTouchID: Bool {
        guard let target = wizard.target else { return false }
        return wizard.header.factors.contains(.secureEnclave) && !target.factors.contains(.secureEnclave)
    }

    private var plannedSetup: [(symbol: String, text: String)] {
        var out: [(String, String)] = []
        for s in wizard.steps {
            switch s {
            case .touchID: out.append(("touchid", LevelTexts.touchIDPlanned))
            case .card:
                out.append(("qrcode", wizard.enrolledAtStart.contains(.card)
                            ? "Schlüsselkarte: deine vorhandene Karte einmal scannen"
                            : "Schlüsselkarte: drucken und zur Bestätigung scannen"))
            case .securityKey:
                out.append(("key.horizontal", wizard.keyReuse
                            ? "Sicherheitsschlüssel: deinen vorhandenen Schlüssel einmal berühren"
                            : "Sicherheitsschlüssel registrieren (einstecken und berühren)"))
            case .recovery:
                out.append(("doc.text", wizard.target?.recoveryScheme == .shamir2of3
                            ? "Notfallcode neu in drei Teilen (je zwei öffnen den Tresor)"
                            : "Notfallcode neu als ein einzelner Code"))
            default: break
            }
        }
        return out
    }

    // MARK: Passwort und aktuelle Faktoren

    private var verify: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(wizard.collection.isEmpty
                 ? "Bestätige mit deinem Master-Passwort."
                 : "Bestätige mit deinem Master-Passwort und den Faktoren der aktuellen Stufe.")
                .font(Theme.body)
                .foregroundStyle(Theme.secondary)
            MasterPasswordField("Master-Passwort", text: $wizard.password, autoFocus: true,
                                enabled: !model.busy && !model.factorInProgress) {
                Task { await model.wizardVerify() }
            }
            .frame(width: Theme.formWidth)
            if !wizard.collection.isEmpty {
                CollectionProgress(collection: wizard.collection,
                                   caption: wizard.collection.doneCount == 0 && wizard.collection.failure == nil
                                     ? "Danach nötig" : nil,
                                   onRetry: { Task { await model.wizardVerify() } })
            }
            buttons(primary: "Weiter", enabled: !wizard.password.isEmpty && !model.factorInProgress) {
                Task { await model.wizardVerify() }
            }
        }
    }

    // MARK: Touch ID

    private var touchID: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 18) {
                TouchIDGlyph(active: model.touchIDActive, done: wizard.touchIDDone)
                VStack(alignment: .leading, spacing: 6) {
                    Text(wizard.touchIDDone ? "Touch ID ist eingerichtet" : "Touch ID einrichten")
                        .font(Theme.heading)
                    Text(wizard.target != nil ? LevelTexts.touchIDSetupLevel : LevelTexts.touchIDSetupEntries)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .lineSpacing(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text(LevelTexts.touchIDCaveat)
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if wizard.touchIDDone {
                buttons(primary: "Weiter", enabled: true) { model.wizardAdvance() }
            } else {
                buttons(primary: model.touchIDActive ? "Finger auflegen …" : "Touch ID einrichten",
                        enabled: !model.touchIDActive) {
                    Task { await model.wizardSetupTouchID() }
                }
            }
        }
    }

    // MARK: Karte

    @ViewBuilder
    private var card: some View {
        if wizard.cardReuse {
            VStack(alignment: .leading, spacing: 14) {
                Text("Deine Schlüsselkarte schützt schon Einträge. Dieselbe Karte dient künftig auch zum Öffnen – scanne sie einmal.")
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                cardScanned
            }
        } else {
            VStack(alignment: .leading, spacing: 14) {
                Text("Drucke die Karte oder schreib den Code ab. Danach scannst du sie einmal – erst dann wird etwas geändert.")
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                SecretGate {
                    KeyCardPreview(qr: wizard.cardImage, groups: wizard.cardText.split(separator: "-").map(String.init))
                } placeholder: { reveal in
                    HiddenSecretPlaceholder(reveal: reveal)
                        .frame(width: 400, height: 200)
                }
                HintBox(symbol: "exclamationmark.triangle") {
                    Text(CardTexts.warning + " Am besten auf festes Papier drucken und ausschneiden.")
                }
                if wizard.cardPrintWarning {
                    VStack(alignment: .leading, spacing: 10) {
                        MessageText(wizard.cardPrintWarningText, symbol: "network")
                        HStack(spacing: 12) {
                            Button("Abbrechen") { model.wizardDismissCardWarning() }
                                .buttonStyle(SecondaryButtonStyle())
                            Button("Trotzdem drucken") { model.wizardPrintCardAnyway() }
                                .buttonStyle(PrimaryButtonStyle())
                        }
                    }
                } else if wizard.cardMethod == nil {
                    HStack(spacing: 12) {
                        Button("Karte drucken…") { model.wizardPrintCard() }
                            .buttonStyle(PrimaryButtonStyle())
                        Button("Code von Hand abschreiben") { model.wizardCardHandwritten() }
                            .buttonStyle(SecondaryButtonStyle())
                    }
                    if wizard.cardPrintNotPaper {
                        MessageText(RecoveryKitPrinter.notPaperMessage, symbol: "printer")
                    }
                    backOnly
                } else {
                    Text(wizard.cardMethod == .printed
                         ? "Gedruckt. Schneide die Karte aus und scanne sie zur Bestätigung."
                         : "Schreib den Code gut leserlich ab. Ohne QR-Code tippst du ihn beim Öffnen ab.")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                    cardScanned
                }
            }
        }
    }

    @ViewBuilder
    private var cardScanned: some View {
        if wizard.cardConfirmed {
            MessageText("Karte erkannt.", symbol: "checkmark.circle")
            buttons(primary: "Weiter", enabled: true) { model.wizardAdvance() }
        } else {
            buttons(primary: wizard.cardMethod == .handwritten ? "Code zur Bestätigung abtippen…" : "Karte scannen…",
                    enabled: !model.factorInProgress) {
                let tippen = wizard.cardMethod == .handwritten
                Task { await model.wizardScanCard(typing: tippen) }
            }
        }
    }

    // MARK: Sicherheitsschlüssel

    private var securityKey: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 18) {
                KeyGlyph(touching: false)
                VStack(alignment: .leading, spacing: 6) {
                    Text(wizard.keyReuse
                         ? (wizard.keyName == nil ? "Vorhandenen Schlüssel berühren" : "Schlüssel erkannt")
                         : (wizard.keyName.map { "Registriert: " + $0 } ?? "Sicherheitsschlüssel registrieren"))
                        .font(Theme.heading)
                    Text("Ein FIDO2-Schlüssel mit hmac-secret (z. B. YubiKey 5). Siegel registriert ihn einmal und fragt ihn danach bei jedem Öffnen. Mit echter Hardware noch ungetestet.")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .lineSpacing(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if wizard.keyReuse && wizard.keyName == nil {
                MessageText("Dein Sicherheitsschlüssel schützt schon Einträge. Derselbe Schlüssel dient künftig auch zum Öffnen – berühre ihn einmal.",
                            symbol: "info.circle")
            }
            if wizard.keyName != nil {
                buttons(primary: "Weiter", enabled: true) { model.wizardAdvance() }
            } else if wizard.keyReuse {
                buttons(primary: "Schlüssel berühren…", enabled: !model.factorInProgress) {
                    Task { await model.wizardTouchExistingKey() }
                }
            } else {
                buttons(primary: "Schlüssel registrieren…", enabled: !model.factorInProgress) {
                    Task { await model.wizardRegisterKey() }
                }
            }
        }
    }

    // MARK: Notfallkit

    private var recovery: some View {
        let geteilt = wizard.target?.recoveryScheme == .shamir2of3
        return VStack(alignment: .leading, spacing: 16) {
            Text(geteilt
                 ? "Ab dieser Stufe ist der Notfallcode in drei Teile geteilt. Je zwei Teile öffnen den Tresor; ein einzelner Teil verrät nichts. Dein bisheriger Code gilt danach nicht mehr."
                 : "In dieser Stufe gilt wieder ein einzelner Notfallcode. Die bisherigen drei Teile gelten danach nicht mehr.")
                .font(Theme.body)
                .foregroundStyle(Theme.secondary)
                .lineSpacing(2)
                .fixedSize(horizontal: false, vertical: true)
            if wizard.recoveryConfirmed {
                MessageText(geteilt ? "Alle drei Teile sind festgehalten und bestätigt." : "Der neue Code ist festgehalten und bestätigt.",
                            symbol: "checkmark.circle")
                buttons(primary: "Weiter", enabled: true) { model.wizardAdvance() }
            } else {
                buttons(primary: geteilt ? "Drei Teile erstellen…" : "Notfallcode erstellen…", enabled: true) {
                    Task { await model.wizardShowRecoveryKit() }
                }
            }
        }
    }

    // MARK: Schreiben

    private var apply: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(spacing: 0) {
                switch wizard.mode {
                case let .changeLevel(target):
                    FactRow(label: "Neue Stufe", value: "\(target.rawValue) · \(target.title)")
                    Hairline()
                    FactRow(label: "Zum Öffnen", value: LevelTexts.open(target))
                    Hairline()
                    FactRow(label: "Im Notfall", value: LevelTexts.emergency(target))
                    Hairline()
                    FactRow(label: "Schlüsselableitung", value: target.kdf == .strong ? "Stark (2 GiB)" : "Standard (1 GiB)")
                case let .enroll(kinds):
                    FactRow(label: "Für Einträge", value: FactorUI.list(kinds, long: true))
                }
            }
            .padding(.horizontal, 16)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
            Text(wizard.target != nil
                 ? "Siegel verschlüsselt jetzt alles neu und legt vorher eine Sicherung an. Das dauert einige Sekunden."
                 : "Siegel speichert die öffentlichen Teile im Tresor. Danach kannst du Einträge damit schützen.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
            buttons(primary: wizard.target != nil ? "Stufe wechseln" : "Einrichten", enabled: wizard.setupComplete) {
                Task { await model.wizardApply() }
            }
        }
    }

    // MARK: Fertig

    private var done: some View {
        VStack(alignment: .leading, spacing: 16) {
            switch wizard.mode {
            case let .changeLevel(target):
                HStack(spacing: 14) {
                    LevelBadge(number: target.rawValue, filled: true, size: 40)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Stufe \(target.title) ist aktiv")
                            .font(Theme.title)
                        HStack(spacing: 8) {
                            FactorGlyphs(factors: target.factors, size: 11)
                            Text("Zum Öffnen: " + LevelTexts.open(target) + " · Notfall: " + LevelTexts.emergency(target))
                                .font(Theme.caption)
                                .foregroundStyle(Theme.secondary)
                        }
                    }
                }
                .padding(.bottom, 10)
                Hairline()
                Text("Alte Sicherungen")
                    .font(Theme.heading)
                    .padding(.top, 6)
                Text(target > wizard.from
                     ? "Die bisherigen Sicherungen lassen sich mit dem bisherigen Zugang öffnen – ohne die neuen Faktoren. Entfernen?"
                     : (removesTouchID
                        ? "Die bisherigen Sicherungen verlangen weiter die Faktoren der höheren Stufe. Da der Touch-ID-Schlüssel entfernt ist, öffnet sie nur noch der Notfallcode (Einstellungen → „Sicherung einspielen…“, dann „Notfallcode verwenden“). Entfernen?"
                        : "Die bisherigen Sicherungen verlangen weiter die Faktoren der höheren Stufe. Entfernen?"))
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Siegel legt danach sofort eine neue Sicherung des aktuellen Stands an.")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                if let error = wizard.error {
                    MessageText(error)
                }
                HStack(spacing: 12) {
                    Spacer()
                    Button("Behalten") { Task { await model.wizardFinish(removeOldBackups: false) } }
                        .buttonStyle(SecondaryButtonStyle())
                    Button("Entfernen") { Task { await model.wizardFinish(removeOldBackups: true) } }
                        .buttonStyle(PrimaryButtonStyle())
                }
                .disabled(model.busy)
            case let .enroll(kinds):
                HStack(spacing: 14) {
                    ZStack {
                        Circle().fill(Theme.text).frame(width: 40, height: 40)
                        Image(systemName: "checkmark")
                            .font(.system(size: 17, weight: .semibold))
                            .foregroundStyle(Theme.background)
                    }
                    Text("Eingerichtet: " + FactorUI.list(kinds, long: true))
                        .font(Theme.title)
                }
                Text("Du kannst Einträge jetzt mit diesem Schutz versehen.")
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                HStack {
                    Spacer()
                    Button(wizard.returnsToEditor ? "Zurück zum Eintrag" : "Fertig") {
                        Task { await model.wizardFinish(removeOldBackups: false) }
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
                }
            }
        }
    }

    // MARK: Knöpfe

    private func buttons(primary: String, enabled: Bool, action: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if let error = wizard.error {
                MessageText(error)
                    .padding(.bottom, 4)
            }
            HStack(spacing: 12) {
                Button("Abbrechen") { model.wizardCancel() }
                    .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    .disabled(model.busy || model.isSaving)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if wizard.steps.firstIndex(of: wizard.step).map({ $0 > 0 }) == true, wizard.step != .done {
                    Button("Zurück") { model.wizardBack() }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(model.busy || model.factorInProgress)
                }
                Button(primary, action: action)
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(!enabled || model.busy)
                    .keyboardShortcut(.defaultAction)
            }
            ProgressLine(active: model.busy)
        }
        .padding(.top, 6)
    }

    private var backOnly: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let error = wizard.error {
                MessageText(error)
            }
            backRow
        }
    }

    private var backRow: some View {
        HStack {
            Button("Abbrechen") { model.wizardCancel() }
                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                .keyboardShortcut(.cancelAction)
            Spacer()
            Button("Zurück") { model.wizardBack() }
                .buttonStyle(SecondaryButtonStyle())
        }
        .padding(.top, 6)
    }
}

/// Punkte für die Schritte des Assistenten (erledigt schwarz, aktuell schwarz umrandet).
struct StepDots: View {
    var steps: [SecurityWizardState.Step]
    var current: SecurityWizardState.Step

    var body: some View {
        let index = steps.firstIndex(of: current) ?? 0
        HStack(spacing: 6) {
            ForEach(Array(steps.enumerated()), id: \.offset) { i, _ in
                Capsule()
                    .fill(i < index ? Theme.text : (i == index ? Theme.text : Theme.hairline))
                    .frame(width: i == index ? 22 : 8, height: 4)
            }
        }
        .accessibilityHidden(true)
    }
}

/// Bildschirm-Vorschau der Schlüsselkarte: QR-Code links, Code in Gruppen rechts. Nur in geschützten Fenstern.
struct KeyCardPreview: View {
    var qr: CGImage?
    var groups: [String]

    var body: some View {
        HStack(alignment: .center, spacing: 18) {
            ZStack {
                if let qr {
                    Image(decorative: qr, scale: 1)
                        .interpolation(.none)
                        .resizable()
                        .aspectRatio(1, contentMode: .fit)
                } else {
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .strokeBorder(Theme.hairline, lineWidth: 1)
                    VStack(spacing: 6) {
                        Image(systemName: "qrcode")
                            .font(.system(size: 30, weight: .light))
                        Text("QR-Code")
                            .font(Theme.caption)
                    }
                    .foregroundStyle(Theme.secondary)
                }
            }
            .frame(width: 150, height: 150)
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    SiegelLogo(size: 14)
                    Text("Schlüsselkarte")
                        .font(.system(size: 11, weight: .semibold))
                }
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(stride(from: 0, to: groups.count, by: 3)), id: \.self) { start in
                        Text(groups[start..<min(start + 3, groups.count)].joined(separator: " "))
                            .font(Theme.mono(12, weight: .medium))
                            .fixedSize()
                    }
                }
                .textSelection(.disabled)
                .accessibilityHidden(!TextHardening.exposesSecretsToAccessibility)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 22)
        .frame(width: 380, height: 240)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Theme.background))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Theme.text, lineWidth: 1))
        .accessibilityElement(children: TextHardening.exposesSecretsToAccessibility ? .contain : .ignore)
        .accessibilityLabel("Schlüsselkarte, verborgen")
    }
}
