import AppKit
import SiegelCore
import SwiftUI

// Bildschirme für Sonderfälle: Tresor fehlt, Beschädigt, Rollback-Frage, Start blockiert.

/// „Tresor fehlt“ (SPEC §4): Liste der Sicherungen (Datum, Generation) und „Wiederherstellen“.
/// Ein neuer leerer Tresor nur über einen zweiten Knopf mit Bestätigung. Ohne Passwort oder Faktor führt
/// „Passwort vergessen? Notfallcode verwenden“ zum Notfallweg (v4.4, Befund datei-2). Aus der Einrichtung
/// („Aus Sicherung wiederherstellen…“) heisst der Bildschirm „Sicherung wiederherstellen“ (Befund datei-3).
struct MissingVaultView: View {
    let model: AppModel
    @Bindable var state: MissingVaultState

    var body: some View {
        // Befund ablaeufe-10: Die Sicherungen werden im Hintergrund gelesen; ohne Liste bis dahin nur der Hinweis.
        if state.searching, state.backups.isEmpty {
            BackupSearchView()
        } else {
            page
        }
    }

    private var page: some View {
        CenteredPage {
            VStack(spacing: 0) {
                PageTitle(state.fromSetup ? "Sicherung wiederherstellen" : "Tresor fehlt",
                          subtitle: state.fromSetup
                            ? "Gib das Master-Passwort dieser Sicherung ein. Fehlen dir Touch ID, Karte oder Schlüssel – etwa auf einem neuen Mac –, öffne sie mit deinem Notfallkit."
                            : "Die Tresordatei ist nicht mehr da. Es gibt aber Sicherungen – wähle eine aus und stelle sie wieder her.")
                    .frame(width: Theme.columnWidth)

                BackupList(backups: state.backups, selection: $state.selection)
                    .frame(width: 440, height: BackupList.height(for: state.backups.count))
                    .padding(.top, 28)
                    // Ein erst jetzt eingesteckter zweiter Sicherungsort erscheint in der Liste (Befund #13).
                    .onAppear { model.retrySecondaryBackupLocation() }
                if state.searching {
                    Text("Weitere Sicherungen werden gesucht…")
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .padding(.top, 8)
                }

                VStack(spacing: 12) {
                    MasterPasswordField("Master-Passwort dieser Sicherung", text: $state.password,
                                        enabled: !model.busy && !model.factorInProgress) {
                        Task { await model.restoreSelectedBackup() }
                    }
                    if let collection = state.collection {
                        CollectionProgress(collection: collection, alignment: .center,
                                           onRetry: { Task { await model.restoreSelectedBackup() } },
                                           onRecovery: { model.missingUseRecovery() })
                    }
                    if let error = state.error {
                        MessageText(error).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    // §23.2: Auch hier zählen falsche Passwörter (Befund datei-5).
                    if let rest = model.lockRemainingAttempts {
                        DestructionAttemptsWarning(remaining: rest)
                    }
                    VStack(spacing: 10) {
                        Button("Wiederherstellen") { Task { await model.restoreSelectedBackup() } }
                            .buttonStyle(PrimaryButtonStyle(fullWidth: true))
                            .disabled(state.selectedBackup == nil || state.password.isEmpty || model.busy)
                            .keyboardShortcut(.defaultAction)
                        ProgressLine(active: model.busy)
                    }
                    // Bietet die Faktor-Zeile den Notfallweg schon an, hier nicht doppelt.
                    Button("Passwort vergessen? Notfallcode verwenden") { model.missingUseRecovery() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        .disabled(model.busy || model.factorInProgress)
                        .opacity(state.collection?.failure?.offerRecovery == true ? 0 : 1)
                }
                .frame(width: Theme.formWidth)
                .padding(.top, 22)

                Group {
                    if state.fromSetup {
                        HStack(spacing: 18) {
                            Button("Andere Sicherung wählen…") { model.chooseBackupFileForRestore() }
                                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                            Button("Zurück") { model.leaveBackupFileRestore() }
                                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        }
                        .disabled(model.busy)
                    } else if state.confirmingNewVault {
                        VStack(spacing: 12) {
                            Text("Neuen leeren Tresor anlegen? Die Sicherungen bleiben erhalten und lassen sich später wiederherstellen.")
                                .font(Theme.caption)
                                .foregroundStyle(Theme.text)
                                .multilineTextAlignment(.center)
                                .fixedSize(horizontal: false, vertical: true)
                            HStack(spacing: 12) {
                                Button("Abbrechen") { model.cancelNewVault() }
                                    .buttonStyle(SecondaryButtonStyle())
                                Button("Neuen Tresor anlegen") { model.confirmNewVault() }
                                    .buttonStyle(PrimaryButtonStyle())
                            }
                        }
                        .frame(width: 380)
                    } else {
                        HStack(spacing: 18) {
                            // Befund datei-3: auch eine Sicherung ausserhalb von Siegels Ordner (USB-Stick).
                            Button("Andere Sicherung wählen…") { model.chooseBackupFileForRestore() }
                                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                            Button("Neuen leeren Tresor anlegen…") { model.requestNewVault() }
                                .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        }
                        .disabled(model.busy)
                    }
                }
                .padding(.top, 26)
            }
        }
    }
}

/// Liste der Sicherungen mit selbst gezeichneter Auswahl (schwarze Fläche, weisse Schrift).
struct BackupList: View {
    var backups: [BackupInfo]
    @Binding var selection: URL?

    var body: some View {
        ScrollView(.vertical) {
            LazyVStack(spacing: 0) {
                ForEach(Array(backups.enumerated()), id: \.element.id) { index, backup in
                    let selected = backup.url == selection
                    Button {
                        selection = backup.url
                    } label: {
                        HStack(alignment: .firstTextBaseline, spacing: 12) {
                            Text(Anzeige.zeitpunkt(backup.date))
                                .font(Theme.bodyMedium)
                            Spacer(minLength: 8)
                            Text(details(backup))
                                .font(Theme.caption)
                                .foregroundStyle(selected ? Theme.background : Theme.secondary)
                                .monospacedDigit()
                        }
                        .foregroundStyle(selected ? Theme.background : Theme.text)
                        .padding(.horizontal, 14)
                        .frame(height: 38)
                        .background(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .fill(selected ? Theme.text : Color.clear)
                        )
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if index < backups.count - 1 && !selected && backups[index + 1].url != selection {
                        Hairline().padding(.horizontal, 14)
                    }
                }
            }
            .padding(4)
        }
        .scrollIndicators(.automatic)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
        )
    }

    /// Höhe für n Zeilen, höchstens fünf sichtbar.
    static func height(for count: Int) -> CGFloat {
        CGFloat(min(max(count, 1), 5)) * 39 + 8
    }

    private func details(_ backup: BackupInfo) -> String {
        var teile = ["Stand \(backup.generation)"]
        if let anlass = Anzeige.anlass(backup.reason) { teile.append(anlass) }
        if backup.isExternal { teile.append("extern") }
        if backup.vaultID == nil { teile.append("unlesbar") }
        return teile.joined(separator: " · ")
    }
}

/// „Sicherungen werden gesucht…“, solange sie im Hintergrund gelesen werden (Befund ablaeufe-10). Erst nach einer
/// kurzen Pause sichtbar: Lokal dauert das Lesen kaum, dann blitzt nichts auf.
struct BackupSearchView: View {
    @State private var sichtbar = false

    var body: some View {
        CenteredPage {
            VStack(spacing: 14) {
                ProgressView()
                    .controlSize(.small)
                Text("Sicherungen werden gesucht…")
                    .font(Theme.caption)
                    .foregroundStyle(Theme.secondary)
            }
            .opacity(sichtbar ? 1 : 0)
        }
        .task {
            try? await Task.sleep(for: .milliseconds(400))
            withAnimation(.easeIn(duration: 0.2)) { sichtbar = true }
        }
    }
}

/// „Tresordatei beschädigt“ (SPEC §4) bzw. „neuere Siegel-Version nötig“.
struct CorruptVaultView: View {
    let model: AppModel
    @Bindable var state: CorruptState

    var body: some View {
        CenteredPage {
            if let backup = state.restoredBackup {
                restored(backup)
            } else {
                question
            }
        }
    }

    private var question: some View {
        VStack(spacing: 0) {
            Image(systemName: isNewer ? "arrow.up.circle" : "exclamationmark.triangle")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(Theme.text)
            PageTitle(isNewer ? "Neuere Siegel-Version nötig" : "Tresordatei beschädigt", subtitle: subtitle)
                .frame(width: Theme.columnWidth)
                .padding(.top, 18)

            if isNewer {
                // SPEC §2: Eine Datei mit höherer Version wird nie überschrieben – auch nicht durch eine
                // Sicherung (der Kern lehnt das mit unsupportedVersion ab). Darum nur Hinweis und Finder.
                VStack(spacing: 12) {
                    Button("Tresor im Finder zeigen") { model.revealVaultInFinder() }
                        .buttonStyle(SecondaryButtonStyle(fullWidth: true))
                    Button("Zurück") { model.leaveCorrupt() }
                        .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        .padding(.top, 4)
                }
                .frame(width: Theme.formWidth)
                .padding(.top, 30)
            } else {
                VStack(spacing: 12) {
                    MasterPasswordField("Master-Passwort", text: $state.password,
                                        enabled: !model.busy && !model.factorInProgress) {
                        Task { await model.openNewestReadableBackup() }
                    }
                    if let collection = state.collection {
                        CollectionProgress(collection: collection, alignment: .center,
                                           onRetry: {
                                               if let datei = state.collectionFile {
                                                   Task { await model.corruptImportBackup(datei) }
                                               } else {
                                                   Task { await model.openNewestReadableBackup() }
                                               }
                                           },
                                           onRecovery: { model.corruptUseRecovery() })
                    }
                    if let error = state.error {
                        MessageText(error).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    // §23.2: Auch hier zählen falsche Passwörter (Befund datei-5).
                    if let rest = model.lockRemainingAttempts {
                        DestructionAttemptsWarning(remaining: rest)
                    }
                    VStack(spacing: 10) {
                        Button("Neueste lesbare Sicherung öffnen") { Task { await model.openNewestReadableBackup() } }
                            .buttonStyle(PrimaryButtonStyle(fullWidth: true))
                            .disabled(state.password.isEmpty || model.busy)
                        // Befund #29: auch eine exportierte Sicherung (USB-Stick) lässt sich einspielen.
                        Button("Sicherung aus Datei einspielen…") { model.corruptChooseBackupFile() }
                            .buttonStyle(SecondaryButtonStyle(fullWidth: true))
                            .disabled(state.password.isEmpty || model.busy)
                        ProgressLine(active: model.busy)
                    }
                    HStack(spacing: 18) {
                        // Befund datei-4: Passwort vergessen oder Faktor weg – direkt zum Notfallweg.
                        Button("Notfallcode verwenden") { model.corruptUseRecovery() }
                            .buttonStyle(QuietButtonStyle(font: Theme.caption))
                            .opacity(state.collection?.failure?.offerRecovery == true ? 0 : 1)
                        Button("Tresor im Finder zeigen") { model.revealVaultInFinder() }
                            .buttonStyle(QuietButtonStyle(font: Theme.caption))
                        Button("Zurück") { model.leaveCorrupt() }
                            .buttonStyle(QuietButtonStyle(font: Theme.caption))
                    }
                    .disabled(model.busy || model.factorInProgress)
                    .padding(.top, 4)
                }
                .frame(width: Theme.formWidth)
                .padding(.top, 30)
            }
        }
    }

    private var isNewer: Bool {
        if case .newerVersion = state.kind { return true }
        return false
    }

    private var subtitle: String {
        switch state.kind {
        case .damaged:
            "Siegel kann die Datei auch nach einem zweiten Versuch nicht lesen. Öffne die neueste lesbare Sicherung oder spiele eine exportierte ein; die beschädigte Datei bleibt unter „Sicherungen“ erhalten."
        case .newerVersion:
            Fehlertexte.newerVersion + ". Siegel ändert und ersetzt sie nicht. Öffne den Tresor mit der neueren Siegel-Version."
        }
    }

    private func restored(_ backup: BackupInfo) -> some View {
        VStack(spacing: 0) {
            SiegelLogo(size: 42, riegel: 1)
            PageTitle("Sicherung geöffnet", subtitle: "Änderungen nach diesem Stand fehlen.")
                .padding(.top, 22)
            VStack(spacing: 0) {
                FactRow(label: "Stand vom", value: Anzeige.datum(backup.date))
                Hairline()
                FactRow(label: "Einträge", value: "\(state.entryCount)")
                Hairline()
                FactRow(label: "Notfallkit", value: state.kitID)
            }
            .frame(width: Theme.formWidth + 40)
            .padding(.top, 26)
            if !state.kitConfirmed {
                HintBox(symbol: "exclamationmark.triangle") {
                    Text("Diese Sicherung nutzt Notfallkit \(state.kitID). Prüfe nach dem Öffnen, ob dein Blatt dazu passt (Einstellungen → Notfallcode prüfen), oder erstelle ein neues Notfallkit.")
                }
                .frame(width: Theme.formWidth + 40)
                .padding(.top, 18)
            }
            Button("Tresor öffnen") { model.finishCorruptRestore() }
                .buttonStyle(PrimaryButtonStyle())
                .keyboardShortcut(.defaultAction)
                .padding(.top, 28)
        }
    }
}

/// Typ-Löschung für ButtonStyle (zwei Stile in einem Ausdruck).
struct AnyButtonStyle: ButtonStyle {
    private let make: (Configuration) -> AnyView

    init<S: ButtonStyle>(_ style: S) {
        make = { AnyView(style.makeBody(configuration: $0)) }
    }

    func makeBody(configuration: Configuration) -> some View {
        make(configuration)
    }
}

/// Rollback-Frage (SPEC §4): „Trotzdem öffnen?“
struct RollbackView: View {
    let model: AppModel
    let state: RollbackState

    var body: some View {
        CenteredPage {
            VStack(spacing: 0) {
                Image(systemName: "clock.arrow.circlepath")
                    .font(.system(size: 30, weight: .light))
                PageTitle("Ältere Tresordatei",
                          subtitle: "Diese Datei ist älter als die zuletzt geöffnete (Stand \(state.fileGeneration) statt \(state.seenGeneration)). Das passiert, wenn eine Sicherung zurückgespielt wurde – oder wenn jemand eine alte Kopie untergeschoben hat.")
                    .frame(width: Theme.columnWidth)
                    .padding(.top, 18)
                Text("Trotzdem öffnen?")
                    .font(Theme.heading)
                    .padding(.top, 26)
                HStack(spacing: 12) {
                    Button("Abbrechen") { model.rejectRollback() }
                        .buttonStyle(SecondaryButtonStyle())
                        .keyboardShortcut(.cancelAction)
                    Button("Trotzdem öffnen") { Task { await model.acceptRollback() } }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(model.busy)
                }
                .padding(.top, 18)
            }
        }
    }
}

/// Start nicht möglich (zweite Instanz, fehlende Sandbox, Datenordner, ungültige Signatur).
struct BlockedView: View {
    let reason: AppModel.BlockReason

    var body: some View {
        CenteredPage {
            VStack(spacing: 0) {
                SiegelLogo(size: Theme.markLarge)
                PageTitle(title, subtitle: subtitle)
                    .frame(width: Theme.columnWidth)
                    .padding(.top, 32)
                Button("Beenden") { NSApp.terminate(nil) }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
                    .padding(.top, 28)
            }
        }
    }

    private var title: String {
        switch reason {
        case .alreadyRunning: "Siegel läuft bereits"
        case .sandboxMissing: "Siegel kann so nicht starten"
        case .storageFailed: "Datenordner nicht verfügbar"
        case .signatureInvalid: "Siegel ist beschädigt"
        }
    }

    private var subtitle: String {
        switch reason {
        case .alreadyRunning: "Es kann nur ein Siegel geöffnet sein. Das andere Fenster ist jetzt vorne."
        case .sandboxMissing: "Siegel läuft nur als signierte App in ihrer Sandbox. Bitte über „./build.sh run“ starten."
        case .storageFailed: "Siegel kann seinen Ordner unter „Application Support“ nicht anlegen. Prüfe den freien Speicherplatz."
        case .signatureInvalid: "Die App wurde verändert oder ist beschädigt. Bitte neu installieren. Dein Tresor bleibt unverändert."
        }
    }
}
