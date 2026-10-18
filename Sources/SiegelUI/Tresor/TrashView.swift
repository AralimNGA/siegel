import SiegelCore
import SwiftUI

/// „Zuletzt gelöscht“ (SPEC §3, §7.4): Einträge bleiben 30 Tage, Wiederherstellen oder endgültig löschen
/// (mit Bestätigung in der Zeile).
struct TrashView: View {
    let model: AppModel
    @Bindable var browser: VaultBrowserState

    var body: some View {
        VStack(spacing: 0) {
            DetailHeader {
                Button("Fertig") { model.closeTrash() }
                    .buttonStyle(CompactButtonStyle())
                    .keyboardShortcut(browser.confirmingPurge == nil ? .cancelAction : nil)
            }
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 0) {
                    Text("Zuletzt gelöscht")
                        .font(Theme.title)
                    Text("Gelöschte Einträge bleiben 30 Tage hier und werden danach aus dem Tresor entfernt. Ältere Sicherungen enthalten sie noch.")
                        .font(Theme.body)
                        .foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 6)
                    let liste = model.trashEntries
                    if liste.isEmpty {
                        Text("Nichts gelöscht.")
                            .font(Theme.body)
                            .foregroundStyle(Theme.secondary)
                            .padding(.top, 30)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(liste.enumerated()), id: \.element.id) { index, entry in
                                if index > 0 { Hairline() }
                                row(entry)
                            }
                        }
                        .padding(.horizontal, 16)
                        .background(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .strokeBorder(Theme.hairline, lineWidth: 1)
                        )
                        .padding(.top, 24)
                    }
                    if let error = browser.error {
                        MessageText(error).padding(.top, 14)
                    }
                }
                .frame(maxWidth: DetailMetrics.column, alignment: .leading)
                .padding(.horizontal, DetailMetrics.side)
                .padding(.top, TresorMetrics.contentTop)
                .padding(.bottom, 40)
                .frame(maxWidth: .infinity)
            }
            .scrollIndicators(.automatic)
        }
    }

    @ViewBuilder
    private func row(_ entry: VaultEntry) -> some View {
        let titel = AppModel.listTitle(entry)
        if browser.confirmingPurge == entry.id {
            VStack(alignment: .leading, spacing: 10) {
                // Befund #41: Sicherungen behalten den Eintrag – ehrlich sagen, wie er ganz verschwindet.
                Text(Typo.keepCompounds("„\(titel)“ aus dem Tresor löschen? Ältere Sicherungen enthalten den Eintrag weiterhin (Einstellungen → Ältere Sicherungen entfernen)."))
                    .font(Theme.body)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Spacer()
                    Button("Abbrechen") { model.requestPurge(nil) }
                        .buttonStyle(CompactButtonStyle())
                        .keyboardShortcut(.cancelAction)
                    Button("Löschen") { Task { await model.purgeDeleted(entry.id) } }
                        .buttonStyle(CompactButtonStyle(primary: true))
                        .disabled(model.busy)
                }
            }
            .padding(.vertical, 14)
        } else {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(titel)
                        .font(Theme.bodyMedium)
                        .lineLimit(1)
                    Text(subtitle(entry))
                        .font(Theme.caption)
                        .foregroundStyle(Theme.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 8)
                Button("Wiederherstellen") { Task { await model.restoreDeleted(entry.id) } }
                    .buttonStyle(CompactButtonStyle(quiet: true))
                    .disabled(model.busy)
                IconButton(symbol: "trash", label: "Aus dem Tresor löschen…", size: 12, quiet: true) {
                    model.requestPurge(entry.id)
                }
            }
            .padding(.vertical, 12)
        }
    }

    private func subtitle(_ entry: VaultEntry) -> String {
        let tage = Anzeige.tage(AppModel.daysLeft(entry))
        return entry.username.isEmpty ? tage : entry.username + " · " + tage
    }
}

/// Leerer Tresor: ruhig, mit den zwei sinnvollen nächsten Schritten.
struct EmptyVaultView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 24)
            SiegelLogo(size: 42, riegel: 1)
            Text("Dein Tresor ist leer")
                .font(.system(size: 20, weight: .semibold))
                .padding(.top, 22)
            Text("Lege den ersten Eintrag an oder übernimm deine Passwörter aus einer CSV-Datei.")
                .font(Theme.body)
                .foregroundStyle(Theme.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 320)
                .padding(.top, 8)
            HStack(spacing: 12) {
                Button("CSV importieren…") { model.request(.csvImport) }
                    .buttonStyle(SecondaryButtonStyle())
                Button("Neuer Eintrag") { model.newEntry() }
                    .buttonStyle(PrimaryButtonStyle())
            }
            .padding(.top, 26)
            Spacer(minLength: 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.horizontal, 32)
    }
}

/// Einträge vorhanden, aber nichts gewählt.
struct NoSelectionView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 24)
            SiegelMark(riegel: 0)
                .fill(Theme.hairline)
                .frame(width: 84, height: 84)
                .accessibilityHidden(true)
            Text(Anzeige.eintraege(model.entries.count))
                .font(Theme.bodyMedium)
                .padding(.top, 24)
            Text("Wähle links einen Eintrag – oder ⌘N für einen neuen.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .padding(.top, 5)
            Spacer(minLength: 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.horizontal, 32)
    }
}
