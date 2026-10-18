import AppKit
import SiegelCore
import SwiftUI

/// Abläufe aus Einstellungen und Seitenleiste (SPEC §7.7–7.9) als Seiten im Hauptfenster.
struct FlowView: View {
    let model: AppModel
    @Bindable var flow: FlowState

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Button {
                        model.finishFlow()
                    } label: {
                        Label("Zurück", systemImage: "chevron.left")
                    }
                    .buttonStyle(QuietButtonStyle())
                    .disabled(model.busy)
                    Spacer()
                }
                .padding(.bottom, 22)
                page
            }
            .frame(width: 520, alignment: .leading)
            .padding(.top, 40)
            .padding(.bottom, 36)
            .frame(maxWidth: .infinity)
        }
        .scrollIndicators(.automatic)
        .onExitCommand {
            if !model.busy { model.finishFlow() }
        }
    }

    @ViewBuilder
    private var page: some View {
        switch flow.step {
        case .importIntro: importIntro
        case .importPreview: importPreview
        case .importReport: importReport
        case .exportIntro: exportIntro
        case .exportUnencrypted: exportUnencrypted
        case .exportPassword: exportPassword
        case .exportDone: exportDone
        case .backupExportIntro: backupExportIntro
        case .backupExportDone: backupExportDone
        case .backupImportIntro: backupImportIntro
        case .backupImportPassword: backupImportPassword
        case .keepassIntro: keepassIntro
        case .keepassPassword: keepassPassword
        case .keepassDone: keepassDone
        }
    }

    // MARK: CSV-Import

    private var importIntro: some View {
        FlowPage(title: "CSV importieren",
                 text: "Übernimm Passwörter aus einem anderen Programm. Siegel liest Exporte aus Apple Passwörter, Chrome, Firefox und Bitwarden. Es wird nur angehängt – bestehende Einträge bleiben unverändert.") {
            HintBox(symbol: "clock.arrow.circlepath") {
                Text("Vor dem Import legt Siegel eine Sicherung des Tresors an.")
            }
            errorLine
            buttons(primary: "Datei wählen…", enabled: true) { model.csvImportChooseFile() }
        }
    }

    @ViewBuilder
    private var importPreview: some View {
        if let preview = flow.importPreview {
            FlowPage(title: "Vorschau", text: flow.sourceURL.map { "Datei „\($0.lastPathComponent)“" } ?? "") {
                FactList {
                    FactRow(label: "Format", value: Self.formatName(preview.format))
                    FactRow(label: "Einträge", value: "\(preview.count)")
                    FactRow(label: "Bereits vorhanden (übersprungen)", value: "\(preview.duplicates)")
                    FactRow(label: "Konflikte (als „… (Import)“)", value: "\(preview.conflicts)")
                }
                VStack(alignment: .leading, spacing: 8) {
                    SectionLabel("Spalten")
                    ColumnMap(format: preview.format)
                }
                .padding(.top, 8)
                if !preview.sample.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel("Erste Einträge")
                        VStack(spacing: 0) {
                            ForEach(Array(preview.sample.enumerated()), id: \.offset) { index, row in
                                if index > 0 { Hairline() }
                                HStack(spacing: 10) {
                                    Text(row.title).font(Theme.body).lineLimit(1)
                                    Spacer(minLength: 8)
                                    Text(row.username).font(Theme.caption).foregroundStyle(Theme.secondary)
                                        .lineLimit(1)
                                }
                                .padding(.vertical, 8)
                            }
                        }
                        .padding(.horizontal, 12)
                        .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(Theme.hairline, lineWidth: 1))
                    }
                    .padding(.top, 8)
                }
                hints(preview)
                errorLine
                // Dubletten werden übersprungen: der Knopf nennt, was wirklich dazukommt.
                let neu = max(0, preview.count - preview.duplicates)
                buttons(primary: neu == 1 ? "1 Eintrag importieren" : "\(neu) Einträge importieren",
                        enabled: neu > 0) {
                    Task { await model.csvImportRun() }
                }
            }
        }
    }

    @ViewBuilder
    private func hints(_ preview: ImportPreview) -> some View {
        let zeilen = Self.hintLines(preview)
        if !zeilen.isEmpty {
            HintBox(symbol: "info.circle") {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(zeilen, id: \.self) { Text($0) }
                }
            }
            .padding(.top, 8)
        }
    }

    static func hintLines(_ preview: ImportPreview) -> [String] {
        var zeilen: [String] = []
        if preview.withOTPSecret > 0 {
            // §18: Das 2FA-Geheimnis landet im Feld „2FA“ (nicht mehr in den Notizen).
            zeilen.append("\(preview.withOTPSecret) \(preview.withOTPSecret == 1 ? "Eintrag" : "Einträge") mit 2FA-Geheimnis – Siegel zeigt daraus den 2FA-Code. Damit liegt der zweite Faktor im selben Tresor wie das Passwort.")
        }
        if preview.movedToNotes > 0 {
            zeilen.append("Zusätzliche Spalten kommen als „Spalte: Wert“ in die Notizen (\(preview.movedToNotes)).")
        }
        if preview.controlCharacters > 0 {
            zeilen.append(preview.controlCharacters == 1
                ? "1 Passwort enthält Steuerzeichen. Siegel übernimmt es unverändert."
                : "\(preview.controlCharacters) Passwörter enthalten Steuerzeichen. Siegel übernimmt sie unverändert.")
        }
        if preview.apostrophePrefixed > 0 {
            zeilen.append(preview.apostrophePrefixed == 1
                ? "1 Passwort beginnt mit ' – vielleicht von einer Tabellenkalkulation. Siegel übernimmt es unverändert."
                : "\(preview.apostrophePrefixed) Passwörter beginnen mit ' – vielleicht von einer Tabellenkalkulation. Siegel übernimmt sie unverändert.")
        }
        return zeilen
    }

    private var importReport: some View {
        let report = flow.importReport ?? ImportReport()
        return FlowPage(title: "Import abgeschlossen", text: "Die Einträge stehen jetzt im Tresor.") {
            FactList {
                FactRow(label: "Importiert", value: "\(report.added)")
                FactRow(label: "Übersprungen (Dubletten)", value: "\(report.skippedDuplicates)")
                FactRow(label: "Mit Zusatz „(Import)“", value: "\(report.conflicts)")
                if report.withOTPSecret > 0 {
                    FactRow(label: "Mit 2FA-Geheimnis", value: "\(report.withOTPSecret)")
                }
            }
            sourceQuestion
                .padding(.top, 10)
            errorLine
            HStack {
                Spacer()
                Button("Fertig") { model.finishFlow() }
                    .buttonStyle(flow.sourceDeleted == nil ? AnyButtonStyle(SecondaryButtonStyle())
                                                         : AnyButtonStyle(PrimaryButtonStyle()))
                    .keyboardShortcut(flow.sourceDeleted == nil ? .cancelAction : .defaultAction)
            }
            .padding(.top, 8)
        }
    }

    @ViewBuilder
    private var sourceQuestion: some View {
        switch flow.sourceDeleted {
        case nil:
            VStack(alignment: .leading, spacing: 12) {
                Text("Quelldatei jetzt endgültig löschen?")
                    .font(Theme.heading)
                Text(FlowTexts.sourceDeleteHint)
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 12) {
                    Spacer()
                    Button("Behalten") { model.csvImportKeepSource() }
                        .buttonStyle(SecondaryButtonStyle())
                    Button("Endgültig löschen") { model.csvImportDeleteSource() }
                        .buttonStyle(PrimaryButtonStyle())
                }
            }
            .padding(16)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.text, lineWidth: 1))
        case true?:
            MessageText("Quelldatei gelöscht (nicht im Papierkorb).", symbol: "checkmark.circle")
        case false?:
            MessageText("Quelldatei behalten. Lösche sie, sobald du sie nicht mehr brauchst – sie enthält alle Passwörter im Klartext.",
                        symbol: "exclamationmark.circle")
        }
    }

    // MARK: CSV-Export

    private var exportIntro: some View {
        FlowPage(title: "CSV exportieren",
                 text: "Für den Umzug in ein anderes Programm. Die Datei enthält alle Passwörter im Klartext.") {
            HintBox(symbol: "exclamationmark.triangle") {
                VStack(alignment: .leading, spacing: 7) {
                    ForEach(FlowTexts.exportWarnings, id: \.self) { Text(Typo.keepCompounds($0)) }
                    if model.exportExcludedCount > 0 {
                        Text(FlowTexts.excluded(model.exportExcludedCount))
                    }
                }
            }
            errorLine
            buttons(primary: "Ordner wählen…", enabled: true) { model.csvExportChooseFolder() }
        }
    }

    private var exportUnencrypted: some View {
        let name = flow.exportFolder?.lastPathComponent ?? "Dieser Ordner"
        return FlowPage(title: flow.exportFolderEncrypted == false ? "Unverschlüsselter Speicherort" : "Verschlüsselung unbekannt",
                        text: flow.exportFolderEncrypted == false
                            ? "„\(name)“ liegt auf einem Volume ohne Verschlüsselung. Wer das Volume in die Hände bekommt, kann die Passwörter lesen – Reste bleiben auch nach dem Löschen."
                            : "Siegel kann nicht feststellen, ob „\(name)“ verschlüsselt ist. Ist es das nicht, kann jeder mit Zugriff auf das Volume die Passwörter lesen.") {
            HStack(spacing: 12) {
                Spacer()
                Button("Anderen Ordner wählen…") { model.csvExportChooseFolder() }
                    .buttonStyle(SecondaryButtonStyle())
                Button("Trotzdem hier exportieren") { model.csvExportAcceptUnencrypted() }
                    .buttonStyle(PrimaryButtonStyle())
            }
            .padding(.top, 8)
        }
    }

    private var exportPassword: some View {
        FlowPage(title: "Master-Passwort bestätigen",
                 text: "Siegel legt in „\(flow.exportFolder?.lastPathComponent ?? "–")“ den Ordner „Siegel-Export-\(AppModel.fileDate(Date())).noindex“ mit der Datei „Siegel-Export.csv“ an.") {
            MasterPasswordField("Master-Passwort", text: $flow.password, autoFocus: true,
                                enabled: !model.busy && !model.factorInProgress) {
                Task { await model.csvExportRun() }
            }
            if let collection = flow.collection {
                CollectionProgress(collection: collection, onRetry: { Task { await model.csvExportRun() } })
            } else if let factors = model.vaultHeader?.factors, !factors.isEmpty {
                FactorRequirementLine(factors: factors, prefix: "Danach nötig:")
            }
            errorLine
            buttons(primary: "Exportieren", enabled: !flow.password.isEmpty && !model.factorInProgress) {
                Task { await model.csvExportRun() }
            }
        }
    }

    private var exportDone: some View {
        // Befund #26: ehrlich, wie lange die Erinnerung reicht.
        FlowPage(title: "Exportiert",
                 text: "Lösche die Datei, sobald du sie nicht mehr brauchst. Solange Siegel offen ist, erinnert eine Zeile in der Seitenleiste daran; beim Beenden fragt Siegel nach.") {
            if let url = flow.exportedURL {
                FactList {
                    FactRow(label: "Ordner", value: url.deletingLastPathComponent().lastPathComponent)
                    FactRow(label: "Datei", value: url.lastPathComponent)
                }
            }
            HStack(spacing: 12) {
                Button("Im Finder zeigen") { model.revealExportedCSV() }
                    .buttonStyle(QuietButtonStyle())
                Spacer()
                if model.exportedCSV != nil {
                    Button("Exportdatei endgültig löschen") { model.deleteExportedCSV() }
                        .buttonStyle(SecondaryButtonStyle())
                }
                Button("Fertig") { model.finishFlow() }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 8)
        }
    }

    // MARK: Sicherung exportieren

    private var backupExportIntro: some View {
        // Befund design-3: ehrlich nach der Stufe – ab Stufe 2 hängt die Kopie an Touch ID dieses Macs.
        let factors = model.vaultHeader?.factors ?? []
        let scheme = model.vaultHeader?.recoveryScheme ?? .single
        return FlowPage(title: "Verschlüsselte Sicherung exportieren",
                        text: BackupTexts.exportIntro(factors: factors, scheme: scheme)) {
            HintBox(symbol: "externaldrive") {
                Text(Typo.keepCompounds(BackupTexts.exportHint(factors: factors)))
            }
            .layoutProbe("flow.backupExportHint")
            errorLine
            buttons(primary: "Sichern unter…", enabled: true) { model.backupExportChoose() }
        }
    }

    private var backupExportDone: some View {
        FlowPage(title: "Sicherung gespeichert", text: flow.backupURL?.lastPathComponent ?? "") {
            if flow.backupIsExternal {
                MessageText("Liegt ausserhalb dieses Macs.", symbol: "checkmark.circle")
            } else {
                MessageText("Liegt auf diesem Mac. Kopiere sie für den Ernstfall auf einen USB-Stick oder in iCloud Drive.",
                            symbol: "info.circle")
            }
            HStack(spacing: 12) {
                Button("Im Finder zeigen") {
                    if let url = flow.backupURL { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                }
                .buttonStyle(QuietButtonStyle())
                Spacer()
                Button("Fertig") { model.finishFlow() }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 8)
        }
    }

    // MARK: Sicherung einspielen

    private var backupImportIntro: some View {
        FlowPage(title: "Sicherung einspielen",
                 text: "Ersetzt den Tresor durch eine Siegel-Sicherung. Der jetzige Stand bleibt als Sicherung „vor Wiederherstellung“ erhalten.") {
            errorLine
            buttons(primary: "Datei wählen…", enabled: true) { model.backupImportChoose() }
        }
    }

    private var backupImportPassword: some View {
        FlowPage(title: "Sicherung einspielen",
                 text: "Gib das Master-Passwort ein, das beim Anlegen dieser Sicherung galt.") {
            FactList {
                FactRow(label: "Datei", value: flow.backupURL?.lastPathComponent ?? "–")
            }
            MasterPasswordField("Master-Passwort der Sicherung", text: $flow.password, autoFocus: true,
                                enabled: !model.busy && !model.factorInProgress) {
                Task { await model.backupImportRun() }
            }
            .padding(.top, 6)
            if flow.collection == nil {
                // Befund design-3: Welche Faktoren die Datei verlangt, steht erst nach dem Lesen fest (Einspielen).
                HintBox(symbol: "touchid") {
                    Text(Typo.keepCompounds(BackupTexts.importFactors))
                }
                .layoutProbe("flow.backupImportFactors")
            }
            if let collection = flow.collection {
                // §14.1, Befund datei-3: Faktor dieser Sicherung hier nicht nutzbar → Notfallcode für genau diese Datei.
                CollectionProgress(collection: collection, onRetry: { Task { await model.backupImportRun() } },
                                   onRecovery: { model.backupImportUseRecovery() })
            }
            errorLine
            // §23.2: Auch das Einspielen zählt falsche Passwörter (Befund datei-5).
            if let rest = model.lockRemainingAttempts {
                DestructionAttemptsWarning(remaining: rest)
            }
            buttons(primary: "Einspielen", enabled: !flow.password.isEmpty && !model.factorInProgress) {
                Task { await model.backupImportRun() }
            }
        }
    }

    // MARK: KeePass-Export (§19)

    private var keepassIntro: some View {
        FlowPage(title: "KeePass exportieren",
                 text: "Für den Umzug zu KeePassXC, KeePass oder Strongbox. Siegel schreibt eine verschlüsselte KDBX-4.1-Datei, die sich mit einem eigenen Export-Passwort öffnet.") {
            HintBox(symbol: "arrow.up.doc") {
                VStack(alignment: .leading, spacing: 7) {
                    Text("Exportiert werden Titel, Benutzername, Passwort, Website, Notizen und das 2FA-Geheimnis.")
                    Text(Typo.keepCompounds(FlowTexts.keepassExcluded(model.exportExcludedCount)))
                    Text("Wer die Datei und das Export-Passwort hat, hat alle exportierten Passwörter – ohne Touch ID, Karte oder Schlüssel.")
                    Text("Siegel legt die Datei in einen Ordner, den Spotlight und Time Machine auslassen. Nicht in iCloud Drive.")
                }
            }
            errorLine
            buttons(primary: "Ordner wählen…", enabled: true) { model.keepassChooseFolder() }
        }
    }

    private var keepassPassword: some View {
        FlowPage(title: "Passwörter für den Export",
                 text: "Siegel legt in „\(flow.exportFolder?.lastPathComponent ?? "–")“ den Ordner „Siegel-Export-\(AppModel.fileDate(Date())).noindex“ mit der KeePass-Datei an.") {
            FieldLabel("Dein Master-Passwort") {
                MasterPasswordField("Master-Passwort", text: $flow.password, autoFocus: true,
                                    enabled: !model.busy && !model.factorInProgress)
            }
            FieldLabel("Neues Export-Passwort – öffnet die KeePass-Datei") {
                MasterPasswordField("Export-Passwort", text: $flow.exportPassword,
                                    enabled: !model.busy && !model.factorInProgress)
            }
            .padding(.top, 8)
            MasterPasswordField("Wiederholen", text: $flow.exportPasswordRepeat,
                                enabled: !model.busy && !model.factorInProgress) {
                Task { await model.keepassExportRun() }
            }
            let bewertung = flow.exportAssessment
            StrengthMeter(bits: bewertung.bits, level: bewertung.level, meetsPolicy: bewertung.meetsPolicy,
                          isEmpty: bewertung.isEmpty)
                .padding(.top, 2)
            if !flow.exportPasswordRepeat.isEmpty, !flow.exportRepeatMatches,
               !PasswordNormalization.normalize(flow.exportPassword)
                .hasPrefix(PasswordNormalization.normalize(flow.exportPasswordRepeat)) {
                MessageText("Die Wiederholung stimmt nicht überein.")
            }
            if let collection = flow.collection {
                CollectionProgress(collection: collection, onRetry: { Task { await model.keepassExportRun() } })
            } else if let factors = model.vaultHeader?.factors, !factors.isEmpty {
                FactorRequirementLine(factors: factors, prefix: "Danach nötig:")
            }
            errorLine
            buttons(primary: "Exportieren", enabled: model.canRunKeePassExport && !model.factorInProgress) {
                Task { await model.keepassExportRun() }
            }
        }
    }

    private var keepassDone: some View {
        FlowPage(title: "Exportiert",
                 text: "Die Datei ist mit dem Export-Passwort verschlüsselt. Öffne sie in KeePassXC oder einem anderen KeePass-Programm und lösche sie danach. Bewahre das Export-Passwort nicht neben der Datei auf.") {
            if let url = flow.exportedURL {
                FactList {
                    FactRow(label: "Ordner", value: url.deletingLastPathComponent().lastPathComponent)
                    FactRow(label: "Datei", value: url.lastPathComponent)
                }
            } else if flow.sourceDeleted == true {
                MessageText("Exportdatei gelöscht.", symbol: "checkmark.circle")
            }
            errorLine
            HStack(spacing: 12) {
                if flow.exportedURL != nil {
                    Button("Im Finder zeigen") { model.revealExportedKeePass() }
                        .buttonStyle(QuietButtonStyle())
                }
                Spacer()
                if flow.exportedURL != nil {
                    Button("Exportdatei löschen") { model.deleteExportedKeePass() }
                        .buttonStyle(SecondaryButtonStyle())
                }
                Button("Fertig") { model.finishFlow() }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 8)
        }
    }

    // MARK: Gemeinsam

    @ViewBuilder
    private var errorLine: some View {
        if let error = flow.error {
            MessageText(error).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func buttons(primary: String, enabled: Bool, action: @escaping () -> Void) -> some View {
        VStack(spacing: 10) {
            HStack(spacing: 12) {
                Spacer()
                Button("Abbrechen") { model.finishFlow() }
                    .buttonStyle(SecondaryButtonStyle())
                    .keyboardShortcut(.cancelAction)
                    .disabled(model.busy)
                Button(primary, action: action)
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(!enabled || model.busy)
                    .keyboardShortcut(.defaultAction)
            }
            ProgressLine(active: model.busy)
        }
        .padding(.top, 8)
    }

    static func formatName(_ format: CSVImportResult.Format) -> String {
        switch format {
        case .applePasswords: "Apple Passwörter"
        case .chrome: "Chrome"
        case .firefox: "Firefox"
        case .bitwarden: "Bitwarden"
        }
    }
}

/// Seite eines Ablaufs: Titel, Erklärung, Inhalt.
struct FlowPage<Content: View>: View {
    var title: String
    var text: String
    var content: Content

    init(title: String, text: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.text = text
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(Theme.title)
                .fixedSize(horizontal: false, vertical: true)
            if !text.isEmpty {
                Text(Typo.keepCompounds(text))
                    .font(Theme.body)
                    .foregroundStyle(Theme.secondary)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, 10)
            }
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Mehrere FactRows mit Haarlinien dazwischen.
struct FactList<Content: View>: View {
    var content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        VStack(spacing: 0) {
            Hairline()
            Group(subviews: content) { subviews in
                ForEach(subviews) { subview in
                    subview
                    Hairline()
                }
            }
        }
    }
}

/// Spalten-Zuordnung je Format (SPEC §8 CSV-Details).
struct ColumnMap: View {
    var format: CSVImportResult.Format

    var body: some View {
        let paare = Self.pairs(format)
        Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 5) {
            ForEach(Array(paare.enumerated()), id: \.offset) { _, paar in
                GridRow {
                    Text(paar.0)
                        .font(Theme.mono(12))
                        .foregroundStyle(Theme.text)
                    Text(paar.1)
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                }
            }
        }
    }

    static func pairs(_ format: CSVImportResult.Format) -> [(String, String)] {
        switch format {
        case .applePasswords:
            [("Title", "Titel"), ("URL", "Website"), ("Username", "Benutzername"), ("Password", "Passwort"),
             ("Notes", "Notizen"), ("OTPAuth", "2FA-Geheimnis")]
        case .chrome:
            [("name", "Titel"), ("url", "Website"), ("username", "Benutzername"), ("password", "Passwort"),
             ("note", "Notizen")]
        case .firefox:
            [("url", "Website und Titel"), ("username", "Benutzername"), ("password", "Passwort"),
             ("timeCreated", "Erstellt"), ("timePasswordChanged", "Geändert"), ("übrige", "Notizen")]
        case .bitwarden:
            [("name", "Titel"), ("login_uri", "Website"), ("login_username", "Benutzername"),
             ("login_password", "Passwort"), ("notes", "Notizen"), ("login_totp", "2FA-Geheimnis")]
        }
    }
}

enum FlowTexts {
    static let sourceDeleteHint = "Siegel löscht die Datei sofort, nicht über den Papierkorb. Reste können trotzdem bleiben: im Spotlight-Index, in Vorschaubildern, in Time Machine und – technisch bedingt – auf der SSD, bis der Platz überschrieben wird."

    static let exportWarnings = [
        "Spotlight, Vorschaubilder, Time Machine und die SSD können Reste der Datei behalten, auch nach dem Löschen. Siegel legt sie darum in einen Ordner, den Spotlight und Time Machine auslassen.",
        "Nicht mit Excel/Numbers öffnen oder speichern – Passwörter können verändert werden.",
        "Der Verlauf früherer Passwörter wird nicht exportiert.",
        "2FA-Geheimnisse fehlen in der CSV-Datei (das Format hat keine Spalte dafür). Mit ihnen umziehen: KeePass-Export.",
        "Nicht in iCloud Drive: Siegel lehnt solche Ziele ab.",
    ]

    /// Einträge mit Schutz 4 oder 5 bleiben draussen (§16).
    static func excluded(_ n: Int) -> String {
        n == 1 ? "1 Eintrag mit Schutz 4 oder 5 wird nicht exportiert."
               : "\(n) Einträge mit Schutz 4 oder 5 werden nicht exportiert."
    }

    static func keepassExcluded(_ n: Int) -> String {
        let teile = n == 0 ? "" : (n == 1 ? " und 1 Eintrag mit Schutz 4 oder 5" : " und \(n) Einträge mit Schutz 4 oder 5")
        return "Nicht exportiert: frühere Passwörter, „Zuletzt gelöscht“" + teile + "."
    }
}

/// Texte zur verschlüsselten Sicherung (Befund design-3). Die Sicherung ist eine Kopie der Tresordatei: Ab Stufe 2
/// verlangt sie darum Touch ID genau dieses Macs (der Secure-Enclave-Schlüssel liegt nicht in der Datei, §14.1), ab
/// Stufe 4 dazu Karte bzw. Schlüssel. Auf einem anderen Mac öffnet sie nur der Notfallweg (Einrichtung → „Aus
/// Sicherung wiederherstellen…“, Befund datei-3). Öffentlich, damit SiegelSnapshots die Texte prüfen kann.
public enum BackupTexts {
    /// Einleitung „Verschlüsselte Sicherung exportieren“ nach Faktoren und Notfall-Schema des Kopfs.
    public static func exportIntro(factors: FactorSet, scheme: RecoveryScheme) -> String {
        let anfang = "Eine Kopie der Tresordatei, verschlüsselt wie der Tresor."
        guard !factors.isEmpty else {
            return anfang + (scheme == .shamir2of3
                ? " Sie öffnet sich mit dem Master-Passwort, das beim Sichern gilt, oder mit zwei der drei Teile des Notfallkits."
                : " Sie öffnet sich mit dem Master-Passwort oder dem Notfallcode, die beim Sichern gelten.")
        }
        let notfall = scheme == .shamir2of3 ? "öffnen sie nur zwei der drei Teile des Notfallkits, das beim Sichern gilt."
                                            : "öffnet sie nur der Notfallcode, der beim Sichern gilt."
        let sonst = factors.contains(.secureEnclave) ? "Auf einem anderen Mac " : "Ohne diese Faktoren "
        return anfang + " Zum Öffnen braucht sie das Master-Passwort, das beim Sichern gilt, dazu " + needed(factors)
            + ". " + sonst + notfall
    }

    /// Hinweis zum Ablageort: ab Stufe 2 übersteht die Sicherung einen verlorenen Mac nur zusammen mit dem Notfallkit.
    public static func exportHint(factors: FactorSet) -> String {
        factors.isEmpty
            ? "Am besten auf einen USB-Stick oder in iCloud Drive – dann übersteht sie auch einen verlorenen oder defekten Mac."
            : "Am besten auf einen USB-Stick oder in iCloud Drive – dann übersteht sie zusammen mit deinem Notfallkit auch einen verlorenen oder defekten Mac (dort in der Einrichtung „Aus Sicherung wiederherstellen…“)."
    }

    /// „Sicherung einspielen“: Die Faktoren der Datei stehen erst beim Einspielen fest.
    public static let importFactors = "Stammt die Sicherung aus Stufe 2 oder höher, braucht sie dazu Touch ID des Macs, auf dem sie entstand, ab Stufe 4 auch Karte bzw. Schlüssel. Fehlt einer, öffnet sie nur der Notfallcode."

    /// „Touch ID dieses Macs, die Schlüsselkarte und den Sicherheitsschlüssel“ (Akkusativ nach „braucht“).
    static func needed(_ factors: FactorSet) -> String {
        let namen = factors.kinds.map { kind -> String in
            switch kind {
            case .secureEnclave: "Touch ID dieses Macs"
            case .card: "die Schlüsselkarte"
            case .securityKey: "den Sicherheitsschlüssel"
            }
        }
        guard let letzter = namen.last else { return "" }
        return namen.count == 1 ? letzter : namen.dropLast().joined(separator: ", ") + " und " + letzter
    }
}
