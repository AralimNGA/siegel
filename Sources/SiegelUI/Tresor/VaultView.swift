import SiegelCore
import SwiftUI

/// Tresor-Hauptansicht (SPEC §7.4): links Seitenleiste (Suche, Liste, Statuszeilen), rechts Detail,
/// Bearbeiten oder „Zuletzt gelöscht“. Keine NavigationSplitView/List-Systemauswahl.
struct VaultView: View {
    let model: AppModel
    @Bindable var browser: VaultBrowserState

    static let sidebarWidth: CGFloat = 268

    var body: some View {
        HStack(spacing: 0) {
            VaultSidebar(model: model, browser: browser)
                .frame(width: Self.sidebarWidth)
            Hairline(vertical: true)
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Theme.background)
        }
        .ignoresSafeArea()
        .onAppear { model.installVaultHooks() }
    }

    @ViewBuilder
    private var detail: some View {
        switch browser.mode {
        case .edit:
            if let editor = browser.editor {
                EntryEditView(model: model, editor: editor)
                    .id(editor.draft.id)
            }
        case .trash:
            TrashView(model: model, browser: browser)
        case .report:
            SecurityReportView(model: model)
        case .browse:
            if model.entries.isEmpty {
                EmptyVaultView(model: model)
            } else if let entry = model.selectedEntry {
                EntryDetailView(model: model, browser: browser, entry: entry)
                    .id(entry.id)
            } else {
                NoSelectionView(model: model)
            }
        }
    }
}

// MARK: - Seitenleiste

struct VaultSidebar: View {
    let model: AppModel
    @Bindable var browser: VaultBrowserState
    @FocusState private var listFocused: Bool

    private var editing: Bool { browser.mode == .edit }

    /// Auswahl schwarz zeigen? Nicht in „Zuletzt gelöscht“ und nicht beim Anlegen eines neuen Eintrags.
    private var showsSelection: Bool {
        switch browser.mode {
        case .browse: true
        case .trash, .report: false
        case .edit: browser.editor?.isNew == false
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            SearchField(text: Bindable(model).searchText, focusRequest: browser.searchFocusRequest,
                        enabled: !editing,
                        onSubmit: {
                            if browser.selection == nil || !model.visibleEntries.contains(where: { $0.id == browser.selection }) {
                                model.select(model.visibleEntries.first?.id)
                            }
                            listFocused = true
                        },
                        onMoveDown: {
                            model.moveSelection(by: 1)
                            listFocused = true
                        })
                .padding(.horizontal, 14)
                .padding(.bottom, 10)
            list
            footer
        }
        .background(Theme.background)
        .onChange(of: browser.listFocusRequest) { _, _ in listFocused = true }
    }

    // Kopf: Platz für die Fensterknöpfe, Logo 21 pt, Neuer Eintrag, Einstellungen, Sperren.
    private var header: some View {
        HStack(spacing: 2) {
            Spacer().frame(width: 76)
            SiegelLogo(size: Theme.markSmall)
                .padding(5)
            Spacer(minLength: 8)
            IconButton(symbol: "plus", label: "Neuer Eintrag (⌘N)", size: 15) { model.newEntry() }
                .disabled(editing)
            IconButton(symbol: "gearshape", label: "Einstellungen (⌘,)", size: 14) { model.openSettings() }
                .disabled(editing)
            IconButton(symbol: "lock", label: "Sperren (⌘L)", size: 14) { model.lock() }
        }
        .padding(.trailing, 10)
        // Mitte auf Höhe der Fensterknöpfe (16 pt); leere Fläche zieht das Fenster
        .frame(height: TresorMetrics.headerHeight)
        .background(WindowDragArea())
        .padding(.bottom, 10)
    }

    private var list: some View {
        let liste = model.visibleEntries
        return ScrollViewReader { proxy in
            ScrollView(.vertical) {
                LazyVStack(spacing: 2) {
                    ForEach(liste) { entry in
                        VaultRow(entry: entry,
                                 selected: showsSelection && entry.id == browser.selection,
                                 dimmed: editing)
                            .id(entry.id)
                            .onTapGesture {
                                guard !editing else { return }
                                model.select(entry.id)
                                listFocused = true
                            }
                            .accessibilityAction {
                                guard !editing else { return }
                                model.select(entry.id)
                            }
                    }
                    if liste.isEmpty {
                        emptyList
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            }
            .scrollIndicators(.automatic)
            .focusable(!editing)
            .focused($listFocused)
            .focusEffectDisabled()
            .onMoveCommand { richtung in
                switch richtung {
                case .up: model.moveSelection(by: -1)
                case .down: model.moveSelection(by: 1)
                default: break
                }
            }
            .onKeyPress(.return) {
                guard !editing, browser.selection != nil else { return .ignored }
                model.editSelected()
                return .handled
            }
            .onKeyPress(.escape) {
                guard !model.searchText.isEmpty else { return .ignored }
                model.searchText = ""
                return .handled
            }
            .onChange(of: browser.selection) { _, neu in
                guard let neu else { return }
                withAnimation(.easeOut(duration: 0.12)) { proxy.scrollTo(neu) }
            }
            .task {
                // Zurück aus Einstellungen/Abläufen: Auswahl sichtbar machen (nach dem ersten Layout)
                await Task.yield()
                if let auswahl = browser.selection { proxy.scrollTo(auswahl) }
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Einträge")
        }
    }

    @ViewBuilder
    private var emptyList: some View {
        let text: String = model.searchText.trimmingCharacters(in: .whitespaces).isEmpty
            ? "Keine Einträge" : "Keine Treffer"
        Text(text)
            .font(Theme.caption)
            .foregroundStyle(Theme.secondary)
            .frame(maxWidth: .infinity)
            .padding(.top, 28)
    }

    private var hasFooter: Bool {
        !model.entries.isEmpty || !model.deletedEntries.isEmpty || browser.mode == .trash || model.needsRecoveryKitConfirmation
            || model.exportedCSV != nil || model.showsExternalBackupHint || model.showsSecondaryBackupWarning
            || model.destructionBanner != nil
    }

    @ViewBuilder
    private var footer: some View {
        if hasFooter {
            VStack(spacing: 0) {
                Hairline()
                    .padding(.horizontal, 14)
                    .padding(.bottom, 8)
                if !model.entries.isEmpty || browser.mode == .report {
                    // Offline-Sicherheitsbericht (§17): Zahl der Einträge mit Hinweisen.
                    ReportLine(affected: model.reportSummary?.affected.count, active: browser.mode == .report) {
                        if browser.mode == .report { model.closeSecurityReport() } else { model.showSecurityReport() }
                    }
                    .disabled(editing)
                    .padding(.horizontal, 8)
                }
                if !model.deletedEntries.isEmpty || browser.mode == .trash {
                    TrashLine(count: model.deletedEntries.count, active: browser.mode == .trash) {
                        if browser.mode == .trash { model.closeTrash() } else { model.showTrash() }
                    }
                    .disabled(editing)
                    .padding(.horizontal, 8)
                }
                VaultStatusLines(model: model)
                    .padding(.horizontal, 14)
                    .padding(.top, 6)
            }
            .padding(.bottom, 10)
        }
    }
}

/// Zeile der Liste: Monogramm, Titel, darunter Benutzername grau. Auswahl als schwarze Fläche.
struct VaultRow: View {
    var entry: VaultEntry
    var selected: Bool
    var dimmed: Bool

    var body: some View {
        let titel = AppModel.listTitle(entry)
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(titel)
                    .font(Theme.bodyMedium)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Text(entry.username.isEmpty ? " " : entry.username)
                    .font(Theme.caption)
                    .foregroundStyle(selected ? Theme.background : Theme.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            // Schutz ≥ 2 (§16): nötige Faktoren als kleine Symbole.
            if entry.protection > .normal {
                ProtectionGlyphs(protection: entry.protection, size: 10)
                    .foregroundStyle(selected ? Theme.background : Theme.secondary)
            }
        }
        .foregroundStyle(selected ? Theme.background : (dimmed ? Theme.secondary : Theme.text))
        .padding(.horizontal, 12)
        .frame(height: 46)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(selected ? Theme.text : Color.clear)
        )
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
    }
}

/// „Zuletzt gelöscht (n)“ unten in der Seitenleiste.
struct TrashLine: View {
    var count: Int
    var active: Bool
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: "trash")
                    .font(.system(size: 12))
                    .frame(width: 18)
                Text("Zuletzt gelöscht (\(count))")
                    .font(Theme.caption)
                Spacer(minLength: 0)
            }
            .foregroundStyle(active ? Theme.background : Theme.secondary)
            .padding(.horizontal, 8)
            .frame(height: 30)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(active ? Theme.text : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(active ? .isSelected : [])
    }
}
