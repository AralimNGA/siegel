import AppKit
import SiegelCore
import SwiftUI

/// Detail eines Eintrags (SPEC §7.4): grosser Titel, Benutzername (kopieren), Passwort (verdeckt, Auge,
/// kopieren), Website (öffnen nur http/https), Notizen, „Frühere Passwörter (n)“, ggf. „Gleich wie
/// Master-Passwort“. Bearbeiten (⌘E), Löschen (→ Zuletzt gelöscht).
struct EntryDetailView: View {
    let model: AppModel
    @Bindable var browser: VaultBrowserState
    let entry: VaultEntry

    private var revealed: Bool { browser.revealedPassword == entry.id }
    private var website: Website? { Website.parse(entry.url) }
    /// Geheimteile, soweit sichtbar (nil = noch nicht aufgedeckt).
    private var secrets: EntrySecrets? { model.visibleSecrets(entry) }
    /// Geschützt (Schutz ≥ 2) oder Stufe 3+: erst aufdecken.
    private var guarded: Bool { model.needsReveal(entry) }
    private var revealing: Bool { browser.revealing == entry.id }
    /// Vernichtet (§23, nur echte Sitzung): Geheimteile unlesbar, nur noch entfernen.
    private var destroyed: Bool { model.isDestroyed(entry) }

    var body: some View {
        VStack(spacing: 0) {
            DetailHeader {
                Button("Bearbeiten") { model.editSelected() }
                    .buttonStyle(CompactButtonStyle())
                    .help(destroyed ? "Vernichtete Einträge lassen sich nur noch entfernen." : "Bearbeiten (⌘E)")
                    .disabled(model.factorInProgress || destroyed)
            }
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 0) {
                    titleBlock
                    if destroyed {
                        destroyedStrip
                            .padding(.top, 18)
                    } else if guarded {
                        guardStrip
                            .padding(.top, 18)
                    }
                    fields
                        .padding(.top, guarded ? 12 : 26)
                    if let secrets, !secrets.history.isEmpty {
                        history(secrets.history)
                            .padding(.top, 22)
                    }
                    if let error = browser.error {
                        MessageText(error)
                            .padding(.top, 16)
                    }
                    Button {
                        Task { await model.deleteSelected() }
                    } label: {
                        Label("Eintrag löschen", systemImage: "trash")
                    }
                    .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    .disabled(model.busy)
                    .padding(.top, 30)
                    .help("In „Zuletzt gelöscht“ verschieben (30 Tage)")
                }
                .frame(maxWidth: DetailMetrics.column, alignment: .leading)
                .padding(.horizontal, DetailMetrics.side)
                .padding(.top, TresorMetrics.contentTop)
                .padding(.bottom, 48)
                .frame(maxWidth: .infinity)
            }
            .scrollIndicators(.automatic)
        }
    }

    // MARK: Titel

    private var titleBlock: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(AppModel.listTitle(entry))
                .font(.system(size: 26, weight: .semibold))
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Text("Geändert am " + Anzeige.datum(entry.modified))
                if entry.protection > .normal {
                    Text("·")
                    ProtectionGlyphs(protection: entry.protection, size: 10)
                        .foregroundStyle(Theme.text)
                    Text(ProtectionTexts.label(entry.protection))
                        .foregroundStyle(Theme.text)
                }
                // §23: dezent, nur solange nicht vernichtet (in einer Vernichtungs-Sitzung nie sichtbar).
                if model.isDestructible(entry), !destroyed {
                    Text("·")
                    DestructibleMark()
                }
            }
            .font(Theme.caption)
            .foregroundStyle(Theme.secondary)
            if let summary = model.reportSummary {
                // Befunde des Offline-Berichts (§17); Klick öffnet den Bericht.
                ReportFindingsLine(findings: summary.findings(for: entry.id), reuseCount: summary.reuseCount(for: entry.id)) {
                    model.showSecurityReport()
                }
                .padding(.top, 4)
            }
        }
    }

    // MARK: Vernichtet

    private var destroyedStrip: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "flame")
                .font(.system(size: 14, weight: .medium))
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text("Vernichtet" + (model.destructionBanner.map { " · " + $0.detail } ?? ""))
                    .font(Theme.caption.weight(.semibold))
                Text(DestructionTexts.destroyedDetail)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Entfernen") { Task { await model.removeDestroyedEntriesNow() } }
                .buttonStyle(CompactButtonStyle())
                .disabled(model.busy)
                .help("Alle vernichteten Einträge aus dem Tresor entfernen")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(minHeight: 66)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.text, lineWidth: 1))
    }

    // MARK: Geschützt

    /// Leiste über den Feldern: was das Aufdecken braucht bzw. „Aufgedeckt“ mit „Verbergen“.
    private var guardStrip: some View {
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                if revealing, let aktiv = model.touchIDActive ? FactorKind.secureEnclave
                    : (model.cardScan != nil ? .card : (model.keyTouch != nil ? .securityKey : nil)) {
                    PulsingSymbol(symbol: FactorUI.symbol(aktiv), size: 15)
                } else {
                    Image(systemName: secrets == nil ? "lock" : "lock.open")
                        .font(.system(size: 14, weight: .medium))
                }
            }
            .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(stripTitle)
                    .font(Theme.caption.weight(.semibold))
                Text(stripText)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if secrets == nil {
                Button {
                    Task { await model.revealEntry(entry) }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: revealFactors.isEmpty ? "touchid" : FactorUI.symbol(revealFactors.kinds.first ?? .secureEnclave))
                            .font(.system(size: 11, weight: .medium))
                        Text("Aufdecken")
                    }
                }
                .buttonStyle(CompactButtonStyle(primary: true))
                .disabled(revealing || model.factorInProgress)
            } else {
                Button("Verbergen") { model.hideEntrySecrets() }
                    .buttonStyle(CompactButtonStyle())
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(minHeight: 66)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(secrets == nil ? Theme.text : Theme.hairline, lineWidth: 1)
        )
    }

    /// Faktoren, die das Aufdecken verlangt (Stufe 3+ bei offenem Eintrag: Touch ID).
    private var revealFactors: FactorSet {
        entry.protection > .normal ? entry.protection.factors : [.secureEnclave]
    }

    private var stripTitle: String {
        if secrets != nil { return "Aufgedeckt" }
        if revealing { return "Aufdecken …" }
        return entry.protection > .normal ? "Geschützt" : "Stufe \(model.level.title) · Touch ID vor dem Aufdecken"
    }

    private var stripText: String {
        if secrets != nil { return "Wird beim Wechsel des Eintrags und beim Sperren wieder verborgen." }
        if revealing, let aktiv = model.touchIDActive ? FactorKind.secureEnclave
            : (model.cardScan != nil ? .card : (model.keyTouch != nil ? .securityKey : nil)) {
            return FactorUI.prompt(aktiv)
        }
        return "Passwort, Notizen, frühere Passwörter und 2FA-Code brauchen zum Aufdecken: "
            + FactorUI.list(revealFactors, long: true) + "."
    }

    // MARK: Felder

    private var fields: some View {
        VStack(spacing: 0) {
            DetailRow(label: "Benutzername") {
                Text(entry.username.isEmpty ? "–" : entry.username)
                    .font(Theme.body)
                    .foregroundStyle(entry.username.isEmpty ? Theme.secondary : Theme.text)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } actions: {
                if !entry.username.isEmpty {
                    IconButton(symbol: "doc.on.doc", label: "Benutzername kopieren", size: 12, quiet: true) {
                        model.copySecret(entry.username)
                    }
                }
            }
            Hairline()
            DetailRow(label: "Passwort", alignTop: model.masterPasswordReuse.contains(entry.id)) {
                VStack(alignment: .leading, spacing: 6) {
                    if destroyed {
                        Text("Vernichtet")
                            .font(Theme.body)
                            .foregroundStyle(Theme.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        // Versiegelt: Länge und Inhalt unbekannt – immer Punkte, bis aufgedeckt.
                        PasswordValue(password: secrets?.password ?? (guarded ? "•" : entry.password),
                                      revealed: revealed && secrets != nil)
                    }
                    if model.masterPasswordReuse.contains(entry.id) {
                        ReuseWarning()
                    }
                }
            } actions: {
                if (guarded || !entry.password.isEmpty) && !destroyed {
                    IconButton(symbol: revealed && secrets != nil ? "eye.slash" : "eye",
                               label: revealed && secrets != nil ? "Passwort verdecken" : "Passwort zeigen", size: 12,
                               quiet: true) {
                        Task { await model.toggleRevealPassword(entry) }
                    }
                    .disabled(revealing || model.factorInProgress)
                    IconButton(symbol: "doc.on.doc", label: "Passwort kopieren (⇧⌘C)", size: 12, quiet: true) {
                        Task { await model.copyEntrySecret(entry, .password) }
                    }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
                    .disabled(revealing || model.factorInProgress)
                }
            }
            Hairline()
            DetailRow(label: "Website") {
                VStack(alignment: .leading, spacing: 3) {
                    Text(website?.display ?? "–")
                        .font(Theme.body)
                        .foregroundStyle(website == nil ? Theme.secondary : Theme.text)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if website?.mixedScripts == true {
                        Text("Gemischte Schriftsysteme – als Punycode angezeigt. Prüfe die Adresse.")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if let website, !website.isOpenable {
                        Text("Nur http und https lassen sich öffnen.")
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } actions: {
                if let website {
                    IconButton(symbol: "arrow.up.right", label: "Website öffnen", size: 12, quiet: true) {
                        model.openWebsite(entry)
                    }
                    .disabled(!website.isOpenable)
                }
            }
            if secrets == nil, guarded, !entry.totp.isEmpty, !destroyed {
                // Stufe 3+: Der Eintrag hat ein 2FA-Geheimnis, gezeigt wird es erst nach dem Aufdecken.
                Hairline()
                DetailRow(label: "2FA-Code") {
                    Text("Verborgen")
                        .font(Theme.body)
                        .foregroundStyle(Theme.secondary)
                } actions: {
                    IconButton(symbol: "doc.on.doc", label: "2FA-Code kopieren", size: 12, quiet: true) {
                        Task { await model.copyEntrySecret(entry, .totpCode) }
                    }
                    .disabled(revealing || model.factorInProgress)
                }
            }
            if let secrets, !secrets.totp.isEmpty {
                Hairline()
                DetailRow(label: "2FA-Code") {
                    SecretGate {
                        TOTPValue(secret: secrets.totp)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } placeholder: { reveal in
                        HiddenSecretPlaceholder(reveal: reveal)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                } actions: {
                    IconButton(symbol: "doc.on.doc", label: "2FA-Code kopieren", size: 12, quiet: true) {
                        Task { await model.copyEntrySecret(entry, .totpCode) }
                    }
                }
            }
            if let secrets, !secrets.notes.isEmpty {
                Hairline()
                DetailRow(label: "Notizen", alignTop: true) {
                    SecretGate {
                        SecretNotesView(text: secrets.notes)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } placeholder: { reveal in
                        HiddenSecretPlaceholder(reveal: reveal)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(TextHardening.exposesSecretsToAccessibility ? secrets.notes : "Notizen, verborgen")
                } actions: {
                    IconButton(symbol: "doc.on.doc", label: "Notizen kopieren", size: 12, quiet: true) {
                        Task { await model.copyEntrySecret(entry, .notes) }
                    }
                }
            } else if secrets == nil, guarded {
                Hairline()
                DetailRow(label: "Notizen") {
                    Text(destroyed ? "Vernichtet" : "Verborgen")
                        .font(Theme.body)
                        .foregroundStyle(Theme.secondary)
                } actions: {
                    EmptyView()
                }
            }
        }
        .padding(.horizontal, 16)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
        )
    }

    // MARK: Verlauf

    private func history(_ items: [PasswordHistoryItem]) -> some View {
        let verlauf = Array(items.enumerated()).sorted { $0.element.changed > $1.element.changed }
        return VStack(alignment: .leading, spacing: 0) {
            Button {
                model.toggleHistory()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .rotationEffect(.degrees(browser.historyExpanded ? 90 : 0))
                        .frame(width: 12)
                    Text("Frühere Passwörter (\(items.count))")
                        .font(Theme.bodyMedium)
                    Spacer(minLength: 0)
                }
                .frame(height: 30)
                .contentShape(Rectangle())
            }
            .buttonStyle(PlainActionButtonStyle())
            .accessibilityValue(browser.historyExpanded ? "aufgeklappt" : "zugeklappt")

            if browser.historyExpanded {
                VStack(spacing: 0) {
                    ForEach(Array(verlauf.enumerated()), id: \.offset) { position, item in
                        if position > 0 { Hairline() }
                        let index = item.offset
                        let offen = browser.revealedHistory.contains(index)
                        DetailRow(label: Anzeige.kurz(item.element.changed), labelFont: Theme.caption, mono: true) {
                            PasswordValue(password: item.element.password, revealed: offen, size: 12)
                        } actions: {
                            IconButton(symbol: offen ? "eye.slash" : "eye",
                                       label: offen ? "Verdecken" : "Zeigen", size: 12, quiet: true) {
                                Task { await model.toggleHistoryEntry(entry, index: index) }
                            }
                            IconButton(symbol: "doc.on.doc", label: "Früheres Passwort kopieren", size: 12,
                                       quiet: true) {
                                Task { await model.copyEntrySecret(entry, .history(index)) }
                            }
                        }
                    }
                }
                .padding(.horizontal, 16)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
                )
                .padding(.top, 8)

                clearHistory(count: items.count)
                    .padding(.top, 12)
            }
        }
    }

    @ViewBuilder
    private func clearHistory(count: Int) -> some View {
        if browser.confirmingClearHistory {
            // Befund #41: Sicherungen enthalten den Verlauf weiterhin – nicht „endgültig“ versprechen.
            InlineConfirm(text: count == 1
                            ? "Das frühere Passwort aus dem Tresor löschen? Ältere Sicherungen enthalten es noch."
                            : "Alle \(count) früheren Passwörter aus dem Tresor löschen? Ältere Sicherungen enthalten sie noch.",
                          confirm: "Verlauf leeren",
                          busy: model.busy,
                          onCancel: { browser.confirmingClearHistory = false },
                          onConfirm: { Task { await model.clearHistory(of: entry.id) } })
        } else {
            Button("Verlauf leeren…") { browser.confirmingClearHistory = true }
                .buttonStyle(QuietButtonStyle(font: Theme.caption))
        }
    }
}

// MARK: - Bausteine des Details

/// Gemeinsame Masse der Tresor-Ansicht.
enum TresorMetrics {
    /// Kopfzeilen: Mitte knapp unter den Fensterknöpfen (verdeckte Titelleiste), oben 4 pt Luft.
    static let headerHeight: CGFloat = 36
    /// Abstand vom Kopf bis zum Seiteninhalt
    static let contentTop: CGFloat = 18
}

/// Leere Kopfflächen ziehen das Fenster (wie eine Titelleiste).
struct WindowDragArea: View {
    var body: some View {
        Color.clear
            .contentShape(Rectangle())
            .gesture(WindowDragGesture())
            .allowsWindowActivationEvents(true)
    }
}

enum DetailMetrics {
    /// Breite der Inhaltsspalte im Detail
    static let column: CGFloat = 540
    /// Mindestabstand links/rechts
    static let side: CGFloat = 40
}

/// Kopfzeile des Detailbereichs (Höhe wie die Seitenleiste), Knöpfe rechts.
struct DetailHeader<Trailing: View>: View {
    var trailing: Trailing

    init(@ViewBuilder trailing: () -> Trailing) {
        self.trailing = trailing()
    }

    var body: some View {
        HStack(spacing: 10) {
            Spacer()
            trailing
        }
        .padding(.horizontal, 16)
        .frame(height: TresorMetrics.headerHeight)
        .background(WindowDragArea())
    }
}

/// Zeile „Bezeichnung | Wert | Aktionen“ im Detail.
struct DetailRow<Value: View, Actions: View>: View {
    var label: String
    var labelFont: Font = Theme.body
    var mono = false
    var alignTop = false
    var value: Value
    var actions: Actions

    init(label: String, labelFont: Font = Theme.body, mono: Bool = false, alignTop: Bool = false,
         @ViewBuilder value: () -> Value, @ViewBuilder actions: () -> Actions) {
        self.label = label
        self.labelFont = labelFont
        self.mono = mono
        self.alignTop = alignTop
        self.value = value()
        self.actions = actions()
    }

    var body: some View {
        HStack(alignment: alignTop ? .top : .center, spacing: 12) {
            Text(label)
                .font(labelFont)
                .foregroundStyle(Theme.secondary)
                .monospacedDigit()
                .frame(width: 118, alignment: .leading)
                .padding(.top, alignTop ? 1 : 0)
            value
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 0) { actions }
                .padding(.top, alignTop ? -5 : 0)
        }
        .padding(.vertical, 12)
        .frame(minHeight: 50)
    }
}

/// „Gleich wie Master-Passwort“ (SPEC §1.6).
struct ReuseWarning: View {
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 11, weight: .medium))
            VStack(alignment: .leading, spacing: 1) {
                Text(Typo.keepCompounds("Gleich wie Master-Passwort"))
                    .font(Theme.caption.weight(.semibold))
                Text("Ändere eines der beiden.")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
            }
        }
        .foregroundStyle(Theme.text)
        .accessibilityElement(children: .combine)
    }
}

/// Bestätigung in der Zeile (statt Alert, der die Systemakzentfarbe zeigt).
struct InlineConfirm: View {
    var text: String
    var confirm: String
    var busy: Bool
    var onCancel: () -> Void
    var onConfirm: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Text(text)
                .font(Theme.caption)
                .foregroundStyle(Theme.text)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button("Abbrechen", action: onCancel)
                .buttonStyle(CompactButtonStyle())
                .keyboardShortcut(.cancelAction)
            Button(confirm, action: onConfirm)
                .buttonStyle(CompactButtonStyle(primary: true))
                .disabled(busy)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.text, lineWidth: 1)
        )
    }
}
