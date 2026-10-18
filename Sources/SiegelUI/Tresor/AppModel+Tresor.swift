import AppKit
import SiegelCore
import SwiftUI

// Tresor-Ansicht (SPEC §7.4, §7.5): Liste, Suche, Detail, Bearbeiten mit Generator, Löschen,
// „Zuletzt gelöscht“. Änderungen laufen über `perform` (transaktional im Kern); scheitert das Speichern,
// bleibt die Eingabe stehen. Nach jedem `await` wird geprüft, ob inzwischen gesperrt wurde.

extension AppModel {
    // MARK: Einhängen

    /// Von der Tresor-Ansicht beim Erscheinen aufgerufen (mehrfach unschädlich): Menübefehle und
    /// „Sperren ohne Datenverlust“ (offene Bearbeitung wird vor dem Verwerfen gespeichert).
    public func installVaultHooks() {
        commandHandler = { [weak self] command in self?.handle(command) }
        addLockParticipant(id: "tresor.bearbeiten") { [weak self] vault, attempt in
            self?.saveDraftBeforeLock(vault, mayRefuse: attempt.mayRefuse) ?? .done
        }
        syncVaultCommands()
    }

    func handle(_ command: VaultCommand) {
        switch command {
        case .newEntry: newEntry()
        case .find: focusSearch()
        case .edit: editSelected()
        }
    }

    /// ⌘E nur mit Auswahl und ausserhalb der Bearbeitung.
    func syncVaultCommands() {
        canEditEntry = browser.mode == .browse && selectedEntry != nil
    }

    // MARK: Liste

    /// Einträge alphabetisch, gefiltert nach Suchtext (nur Titel, Benutzername, Website).
    public var visibleEntries: [VaultEntry] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        if let cache = listCache, cache.revision == revision, cache.query == query {
            return cache.entries
        }
        let sortiert = entries.sorted { a, b in
            let ta = Self.listTitle(a)
            let tb = Self.listTitle(b)
            let ordnung = ta.localizedStandardCompare(tb)
            if ordnung != .orderedSame { return ordnung == .orderedAscending }
            return a.username.localizedStandardCompare(b.username) == .orderedAscending
        }
        let ergebnis = query.isEmpty ? sortiert : sortiert.filter { Self.matches($0, query) }
        listCache = VaultListCache(revision: revision, query: query, entries: ergebnis)
        return ergebnis
    }

    static func matches(_ entry: VaultEntry, _ query: String) -> Bool {
        let optionen: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive, .widthInsensitive]
        return entry.title.range(of: query, options: optionen) != nil
            || entry.username.range(of: query, options: optionen) != nil
            || entry.url.range(of: query, options: optionen) != nil
    }

    /// Titel für Liste und Detail (leer → Host der Website → „Ohne Titel“).
    public static func listTitle(_ entry: VaultEntry) -> String {
        if !entry.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return entry.title }
        if let host = Website.parse(entry.url)?.displayHost, !host.isEmpty { return host }
        return "Ohne Titel"
    }

    public var selectedEntry: VaultEntry? {
        guard let id = browser.selection else { return nil }
        return entries.first { $0.id == id }
    }

    public func select(_ id: UUID?) {
        guard browser.mode != .edit else { return }
        if browser.selection != id { browser.resetDetailState() }
        browser.selection = id
        browser.mode = .browse
        browser.confirmingPurge = nil
        syncVaultCommands()
    }

    /// Pfeiltasten in der Liste.
    public func moveSelection(by schritt: Int) {
        guard browser.mode != .edit else { return }
        let liste = visibleEntries
        guard !liste.isEmpty else { return }
        guard let aktuell = browser.selection, let index = liste.firstIndex(where: { $0.id == aktuell }) else {
            select(schritt >= 0 ? liste.first?.id : liste.last?.id)
            return
        }
        let ziel = min(max(index + schritt, 0), liste.count - 1)
        select(liste[ziel].id)
    }

    public func focusSearch() {
        guard browser.mode != .edit else { return }
        browser.searchFocusRequest += 1
    }

    public func focusList() {
        browser.listFocusRequest += 1
    }

    // MARK: Detail

    public func toggleReveal(_ id: UUID) {
        browser.revealedPassword = browser.revealedPassword == id ? nil : id
    }

    public func toggleHistoryReveal(_ index: Int) {
        if browser.revealedHistory.contains(index) {
            browser.revealedHistory.remove(index)
        } else {
            browser.revealedHistory.insert(index)
        }
    }

    public func toggleHistory() {
        withAnimation(.easeOut(duration: 0.18)) {
            browser.historyExpanded.toggle()
        }
        browser.revealedHistory = []
        browser.confirmingClearHistory = false
    }

    /// „Verlauf leeren“ nach Bestätigung (geschützt: über die aufgedeckten Geheimteile neu versiegeln).
    public func clearHistory(of id: UUID) async {
        let generation = lockGeneration
        browser.error = nil
        let error: SiegelError?
        if let entry = entries.first(where: { $0.id == id }), entry.protection > .normal || entry.secretsSealed {
            guard var offen = browser.unlockedSecrets, offen.id == id else { return }
            offen.secrets.history = []
            let teile = offen.secrets
            let schutz = entry.protection
            error = await perform { try $0.setProtection(schutz, id: id, secrets: teile) }
            if error == nil, generation == lockGeneration { browser.unlockedSecrets = offen }
        } else {
            error = await perform { try $0.clearHistory(id: id) }
        }
        guard generation == lockGeneration, isUnlocked else { return }
        browser.confirmingClearHistory = false
        if let error {
            browser.error = Fehlertexte.text(error)
        } else {
            browser.historyExpanded = false
            browser.revealedHistory = []
            show(Notice("Verlauf geleert"))
        }
    }

    public func openWebsite(_ entry: VaultEntry) {
        guard let url = Website.parse(entry.url)?.openURL else { return }
        NSWorkspace.shared.open(url)
    }

    // MARK: Löschen und „Zuletzt gelöscht“

    /// Löschen → „Zuletzt gelöscht“ (30 Tage). Danach den nächsten Eintrag wählen.
    public func deleteSelected() async {
        guard browser.mode == .browse, let entry = selectedEntry else { return }
        let liste = visibleEntries
        let index = liste.firstIndex { $0.id == entry.id }
        let generation = lockGeneration
        browser.error = nil
        let error = await perform { try $0.delete(id: entry.id) }
        guard generation == lockGeneration, isUnlocked else { return }
        if let error {
            browser.error = Fehlertexte.text(error)
            return
        }
        let rest = visibleEntries
        var naechste: UUID?
        if let index, !rest.isEmpty { naechste = rest[min(index, rest.count - 1)].id }
        browser.resetDetailState()
        browser.selection = naechste
        syncVaultCommands()
        show(Notice("In „Zuletzt gelöscht“ verschoben", symbol: "trash"))
    }

    public func showTrash() {
        guard browser.mode != .edit else { return }
        browser.resetDetailState()
        browser.confirmingPurge = nil
        browser.mode = .trash
        syncVaultCommands()
    }

    public func closeTrash() {
        browser.confirmingPurge = nil
        browser.mode = .browse
        syncVaultCommands()
    }

    /// Gelöschte Einträge, zuletzt gelöschte zuerst.
    public var trashEntries: [VaultEntry] {
        deletedEntries.sorted { ($0.deletedAt ?? .distantPast) > ($1.deletedAt ?? .distantPast) }
    }

    public func restoreDeleted(_ id: UUID) async {
        let generation = lockGeneration
        browser.error = nil
        let error = await perform { try $0.restore(id: id) }
        guard generation == lockGeneration, isUnlocked else { return }
        if let error {
            browser.error = Fehlertexte.text(error)
            return
        }
        browser.confirmingPurge = nil
        if deletedEntries.isEmpty {
            browser.mode = .browse
            browser.selection = id
            browser.resetDetailState()
        }
        syncVaultCommands()
        show(Notice("Wiederhergestellt", symbol: "arrow.uturn.backward"))
    }

    public func requestPurge(_ id: UUID?) {
        browser.confirmingPurge = id
    }

    /// Endgültig löschen (nach Bestätigung).
    public func purgeDeleted(_ id: UUID) async {
        let generation = lockGeneration
        browser.error = nil
        let error = await perform { try $0.purgeDeleted(id: id) }
        guard generation == lockGeneration, isUnlocked else { return }
        browser.confirmingPurge = nil
        if let error {
            browser.error = Fehlertexte.text(error)
            return
        }
        if deletedEntries.isEmpty { browser.mode = .browse }
        syncVaultCommands()
        show(Notice("Gelöscht", symbol: "trash"))
    }

    /// Verbleibende Tage in „Zuletzt gelöscht“.
    public static func daysLeft(_ entry: VaultEntry, now: Date = Date()) -> Int {
        guard let deleted = entry.deletedAt else { return 30 }
        let rest = deleted.addingTimeInterval(30 * 24 * 3600).timeIntervalSince(now)
        return max(0, Int((rest / (24 * 3600)).rounded(.up)))
    }

    // MARK: Bearbeiten

    public var editor: EntryEditorState? { browser.editor }

    /// ⌘N: neuer Eintrag (Schutz nach Vorgabe; Stufe 4/5 mindestens 2, §16).
    public func newEntry() {
        guard isUnlocked, browser.mode != .edit else { return }
        browser.resetDetailState()
        let editor = EntryEditorState(original: nil)
        editor.draft.protection = effectiveDefaultProtection
        browser.editor = editor
        browser.mode = .edit
        syncVaultCommands()
    }

    /// ⌘E: ausgewählten Eintrag bearbeiten. Versiegelte Geheimteile bleiben gesperrt, bis sie aufgedeckt werden
    /// (schon aufgedeckte werden übernommen). Offene Einträge in Stufe 3+: zuerst Touch ID (das Formular zeigt
    /// das Passwort).
    public func editSelected() {
        guard isUnlocked, browser.mode == .browse, let entry = selectedEntry else { return }
        let offen = browser.unlockedSecrets.flatMap { $0.id == entry.id ? $0.secrets : nil }
        if offen == nil, entry.protection == .normal, !entry.secretsSealed, policy.touchIDBeforeReveal {
            Task { @MainActor [weak self] in
                guard let self, await self.passTouchIDGate(), self.browser.mode == .browse,
                      self.selectedEntry?.id == entry.id else { return }
                self.openEditor(entry, secrets: nil)
            }
            return
        }
        openEditor(entry, secrets: offen)
    }

    private func openEditor(_ entry: VaultEntry, secrets: EntrySecrets?) {
        browser.resetDetailState()
        browser.editor = EntryEditorState(original: entry, secrets: secrets)
        browser.mode = .edit
        syncVaultCommands()
    }

    /// „Sichern“: prüfen, speichern, zurück zum Detail. Scheitert es, bleibt die Eingabe stehen.
    public func saveEdit() async {
        guard let editor = browser.editor, browser.mode == .edit, !busy, !isSaving else { return }
        editor.error = nil
        if let fehler = editor.limitViolation {
            editor.error = fehler
            return
        }
        guard let titel = EntryRules.effectiveTitle(editor.draft) else {
            editor.error = "Gib einen Titel oder eine Website ein."
            return
        }
        // §18: nur gültige 2FA-Geheimnisse speichern (Prüfung im Kern über TOTP.parse).
        if TOTPDisplay.check(editor.draft.totp) == .invalid {
            editor.error = Fehlertexte.text(TOTPDisplay.problem(editor.draft.totp))
            return
        }
        var bearbeitet = editor.draft
        bearbeitet.title = titel
        bearbeitet.totp = bearbeitet.totp.trimmingCharacters(in: .whitespacesAndNewlines)
        let entry = bearbeitet
        let generation = lockGeneration
        if editor.usesSealedPath {
            await saveSealedEdit(editor, entry: entry)
            return
        }
        if editor.persisted || !EntryRules.isBlank(entry) {
            let error = await perform { try $0.upsert(entry) }
            guard generation == lockGeneration, isUnlocked, browser.editor === editor else { return }
            if let error {
                editor.error = Self.saveErrorText(error)
                return
            }
        }
        closeEditor(select: entry.id)
        show(Notice(editor.isNew ? "Eintrag angelegt" : "Gespeichert"))
    }

    /// Sichern mit Schutz ≥ 2 (oder vorher geschützt): Metadaten + `setProtection` (§16).
    private func saveSealedEdit(_ editor: EntryEditorState, entry: VaultEntry) async {
        let schutz = entry.protection
        if let kind = missingFactors(for: schutz).kinds.first {
            editor.error = "Für Schutz \(schutz.rawValue) fehlt noch: \(FactorUI.longName(kind)). Richte es zuerst ein."
            return
        }
        if editor.secretsLocked, schutz != editor.originalProtection {
            editor.error = "Decke zuerst die Geheimteile auf, um den Schutz zu ändern."
            return
        }
        var geheim: EntrySecrets?
        if let teile = editor.draftSecrets, editor.isNew || editor.secretsChanged || schutz != editor.originalProtection {
            var neu = teile
            if let baseline = editor.baseline { neu.history = EntryRules.history(after: baseline, newPassword: teile.password) }
            geheim = neu
        }
        let isNew = !editor.persisted
        let metadaten = editor.metadataChanged || (editor.original?.title != entry.title)
        let generation = lockGeneration
        let secrets = geheim
        let error = await perform { vault in
            try Self.writeSealed(vault, draft: entry, isNew: isNew, metadataChanged: metadaten, protection: schutz,
                                 secrets: secrets)
        }
        guard generation == lockGeneration, isUnlocked, browser.editor === editor else { return }
        if let error {
            editor.error = Self.saveErrorText(error)
            return
        }
        closeEditor(select: entry.id)
        show(Notice(editor.isNew ? "Eintrag angelegt" : "Gespeichert"))
    }

    /// Fehler beim Sichern; scheitert jedes Speichern (Platz, fremde Änderung), sagt der Text, was beim Sperren
    /// passiert (Befund #27).
    static func saveErrorText(_ error: SiegelError) -> String {
        let text = Fehlertexte.text(error)
        guard failsForEveryEntry(error) else { return text }
        return text + " Solange das Speichern scheitert, ginge diese Eingabe beim automatischen Sperren verloren."
    }

    /// „Abbrechen“ (SPEC §6 b): Änderungen verwerfen. Wurde ein Generator-Passwort übernommen, wird das
    /// alte Passwort wiederhergestellt; das generierte bleibt im Verlauf. Ein erst durch „Übernehmen“
    /// angelegter Eintrag wandert nach „Zuletzt gelöscht“ (das Passwort geht so nicht verloren).
    public func cancelEdit() async {
        // Nicht während eines Speicherns (Befund #11): „Übernehmen“ wäre sonst geschrieben, ohne dass
        // `appliedGenerated` gesetzt ist, und das alte Passwort käme nicht zurück.
        guard let editor = browser.editor, browser.mode == .edit, !busy, !isSaving else { return }
        let generation = lockGeneration
        if editor.appliedGenerated, editor.originalProtection > .normal, let original = editor.original,
           let anfang = editor.initialSecrets, let jetzt = editor.baseline {
            // Versiegelt: bisheriges Passwort zurück, das übernommene bleibt im Verlauf.
            var zurueck = anfang
            zurueck.history = EntryRules.history(after: jetzt, newPassword: anfang.password)
            let schutz = original.protection
            let id = original.id
            let secrets = zurueck
            let error = await perform { try $0.setProtection(schutz, id: id, secrets: secrets) }
            guard generation == lockGeneration, isUnlocked, browser.editor === editor else { return }
            if let error {
                editor.error = Fehlertexte.text(error)
                return
            }
            closeEditor(select: original.id)
            return
        }
        if editor.appliedGenerated {
            if let original = editor.original {
                if var stored = entries.first(where: { $0.id == original.id }), stored.password != original.password {
                    stored.password = original.password
                    let restored = stored
                    let error = await perform { try $0.upsert(restored) }
                    guard generation == lockGeneration, isUnlocked, browser.editor === editor else { return }
                    if let error {
                        editor.error = Fehlertexte.text(error)
                        return
                    }
                }
            } else {
                let id = editor.draft.id
                let error = await perform { try $0.delete(id: id) }
                guard generation == lockGeneration, isUnlocked, browser.editor === editor else { return }
                if let error {
                    editor.error = Fehlertexte.text(error)
                    return
                }
                show(Notice("Mit dem übernommenen Passwort in „Zuletzt gelöscht“ abgelegt", symbol: "trash"),
                     seconds: 6)
            }
        }
        closeEditor(select: editor.original?.id ?? browser.selection)
    }

    private func closeEditor(select id: UUID?) {
        browser.editor = nil
        browser.mode = .browse
        browser.resetDetailState()
        browser.selection = id.flatMap { wanted in entries.contains { $0.id == wanted } ? wanted : nil }
        syncVaultCommands()
        focusList()
    }

    // MARK: Generator

    public func toggleGenerator() {
        guard let editor = browser.editor else { return }
        withAnimation(.easeOut(duration: 0.18)) {
            editor.generatorOpen.toggle()
        }
        if editor.generatorOpen && editor.generated.isEmpty {
            regenerate()
        }
    }

    public func regenerate() {
        guard let editor = browser.editor else { return }
        editor.generated = PasswordGenerator.generate(editor.options)
    }

    /// Optionen ändern; mindestens eine Zeichenklasse bleibt an.
    public func updateGenerator(_ change: (inout PasswordGenerator.Options) -> Void) {
        guard let editor = browser.editor else { return }
        var neu = editor.options
        change(&neu)
        neu.length = min(max(neu.length, 8), 64)
        guard neu.uppercase || neu.lowercase || neu.digits || neu.symbols else { return }
        guard neu != editor.options else { return }
        editor.options = neu
        regenerate()
    }

    /// „Übernehmen“ (SPEC §6 b): speichert sofort. Das generierte Passwort wird Eintragspasswort, das alte
    /// wandert in den Verlauf. Andere Änderungen im Formular bleiben ungespeichert (bis „Sichern“).
    public func applyGenerated() async {
        guard let editor = browser.editor, browser.mode == .edit, !busy, !isSaving, !editor.generated.isEmpty else { return }
        let password = editor.generated
        editor.error = nil
        if editor.originalProtection > .normal || (editor.original == nil && editor.draft.protection > .normal) {
            await applyGeneratedSealed(editor, password: password)
            return
        }
        let zuSpeichern: VaultEntry
        if editor.persisted, var stored = entries.first(where: { $0.id == editor.draft.id }) {
            stored.password = password
            zuSpeichern = stored
        } else {
            // Neuer Eintrag: mit dem Formularstand anlegen (Titel notfalls „Entwurf …“).
            var neu = EntryRules.clamped(editor.draft)
            neu.password = password
            neu.title = EntryRules.effectiveTitle(neu) ?? EntryRules.draftTitle()
            zuSpeichern = neu
        }
        let generation = lockGeneration
        let error = await perform { try $0.upsert(zuSpeichern) }
        guard generation == lockGeneration, isUnlocked, browser.editor === editor else { return }
        if let error {
            editor.error = Fehlertexte.text(error)
            return
        }
        editor.draft.password = password
        editor.persisted = true
        editor.appliedGenerated = true
        withAnimation(.easeOut(duration: 0.18)) { editor.generatorOpen = false }
        editor.generated = ""
        show(Notice("Passwort übernommen und gespeichert"))
    }

    /// „Übernehmen“ bei Schutz ≥ 2: neues Passwort sofort versiegelt speichern, altes in den Verlauf.
    private func applyGeneratedSealed(_ editor: EntryEditorState, password: String) async {
        guard !editor.secretsLocked else {
            editor.error = "Decke zuerst die Geheimteile auf."
            return
        }
        let schutz = editor.original?.protection ?? editor.draft.protection
        if let kind = missingFactors(for: schutz).kinds.first {
            editor.error = "Für Schutz \(schutz.rawValue) fehlt noch: \(FactorUI.longName(kind)). Richte es zuerst ein."
            return
        }
        let basis = editor.baseline ?? EntrySecrets()
        var neu = basis
        neu.password = password
        neu.history = EntryRules.history(after: basis, newPassword: password)
        var entwurf = EntryRules.clamped(editor.draft)
        entwurf.title = EntryRules.effectiveTitle(entwurf) ?? EntryRules.draftTitle()
        let isNew = !editor.persisted
        let draft = entwurf
        let secrets = neu
        let generation = lockGeneration
        let error = await perform { vault in
            try Self.writeSealed(vault, draft: draft, isNew: isNew, metadataChanged: false, protection: schutz,
                                 secrets: secrets)
        }
        guard generation == lockGeneration, isUnlocked, browser.editor === editor else { return }
        if let error {
            editor.error = Fehlertexte.text(error)
            return
        }
        editor.draft.password = password
        editor.baseline = neu
        if isNew { editor.initialSecrets = EntrySecrets() }
        editor.persisted = true
        editor.appliedGenerated = true
        withAnimation(.easeOut(duration: 0.18)) { editor.generatorOpen = false }
        editor.generated = ""
        show(Notice("Passwort übernommen und gespeichert"))
    }

    // MARK: Sperren ohne Datenverlust (SPEC §6 a)

    /// Läuft synchron vor dem Sperren (DEK noch da): geänderte Bearbeitung speichern; ungültige als „Entwurf <Datum>“.
    /// Scheitert das (Befund #27/#31: z. B. zu wenig Speicherplatz), meldet das Ergebnis den Grund – bei `mayRefuse`
    /// (⌘L) bleibt die Bearbeitung offen und das Sperren wird abgelehnt. Gespeichert, aber anders als gewählt (Schutz
    /// noch nicht eingerichtet, eigener Entwurf), sagt es der Hinweis auf dem Sperrbildschirm (Befund hygiene-1).
    func saveDraftBeforeLock(_ vault: UnlockedVault, mayRefuse: Bool = false) -> LockParticipantResult {
        guard let editor = browser.editor else { return .done }
        guard editor.hasChanges else {
            browser.editor = nil
            return .done
        }
        switch writeDraft(editor, vault) {
        case .saved:
            browser.editor = nil
            return .done
        case let .savedWithNotice(text):
            browser.editor = nil
            return .doneWithNotice(text)
        case let .failed(fehler, text):
            if mayRefuse {
                // Mit `text` sind Titel, Benutzer und Website schon gespeichert, nur die Geheimteile nicht.
                editor.error = (text == nil ? "Nicht gesperrt – die Bearbeitung liess sich nicht speichern: "
                                            : "Nicht gesperrt – die geänderten Geheimteile liessen sich nicht speichern: ")
                    + Fehlertexte.text(fehler) + " Sichere sie oder verwirf sie mit „Abbrechen“."
                return .refused(fehler)
            }
            browser.editor = nil
            return .lost(fehler, notice: text)
        }
    }

    /// Ergebnis von `writeDraft`.
    enum DraftWriteResult {
        case saved
        /// Gespeichert, aber nicht wie gewählt (anderer Schutz, eigener Entwurf).
        case savedWithNotice(String)
        /// Nicht (vollständig) gespeichert; `notice` nennt, was trotzdem gespeichert ist.
        case failed(SiegelError, notice: String?)
    }

    /// Schreibt eine offene Bearbeitung so gut es geht – aber nie mit tieferem Schutz als bisher (Befund hygiene-1,
    /// §16, §23.1): Geschützte, vernichtbare und vernichtete Einträge gehen nur über den versiegelten Weg; ein
    /// Klartext-Entwurf als eigener Eintrag nur, wenn der Eintrag vorher und nachher Schutz 1 hat.
    private func writeDraft(_ editor: EntryEditorState, _ vault: UnlockedVault) -> DraftWriteResult {
        let id = editor.draft.id
        let gespeichert = vault.entries.first { $0.id == id }
        let vernichtbar = destructibleEntries.contains(id) || destroyedEntries.contains(id)
        let offenVorher = [editor.original, gespeichert].allSatisfy { e in
            e.map { $0.protection == .normal && !$0.secretsSealed } ?? true
        }
        guard let ziel = draftProtection(editor, stored: gespeichert) else {
            // Nur bei neuen Einträgen (der bisherige Schutz eines bestehenden ist eingerichtet): Für die Vorgabe der
            // Stufe fehlt ein Faktor. Dann lieber nichts als etwas Offenes schreiben.
            let kind = missingFactors(for: max(editor.draft.protection, effectiveDefaultProtection)).kinds.first
            return .failed(.factorMissing(kind ?? .secureEnclave), notice: nil)
        }
        if (editor.usesSealedPath || vernichtbar) && !(ziel == .normal && offenVorher && !vernichtbar) {
            return writeSealedDraft(editor, vault, protection: ziel)
        }
        return writeOpenDraft(editor, vault, allowCopy: offenVorher && !vernichtbar)
    }

    /// Schutz, mit dem eine offene Bearbeitung beim Sperren gespeichert wird: der gewählte, wenn seine Faktoren
    /// eingerichtet sind; sonst der höchste eingerichtete zwischen dem bisherigen (neuer Eintrag: Vorgabe der Stufe
    /// und Einstellung) und dem gewählten. Versiegelte, nicht aufgedeckte Geheimteile behalten ihren Schutz.
    /// nil = keiner (nur bei neuen Einträgen möglich, deren Vorgabe einen nicht eingerichteten Faktor verlangt).
    func draftProtection(_ editor: EntryEditorState, stored: VaultEntry?) -> EntryProtection? {
        if editor.secretsLocked { return editor.originalProtection }
        let gewaehlt = editor.draft.protection
        if missingFactors(for: gewaehlt).isEmpty { return gewaehlt }
        let bisher = editor.original == nil ? effectiveDefaultProtection : editor.originalProtection
        let untergrenze = max(bisher, stored?.protection ?? .normal)
        return EntryProtection.allCases.reversed().first { p in
            p >= untergrenze && p <= gewaehlt && missingFactors(for: p).isEmpty
        }
    }

    /// Geschützter Weg: zuerst die Metadaten (neuer Eintrag ohne Geheimteile), dann die Geheimteile per
    /// `setProtection`. Scheitert das Versiegeln, bleiben die Metadaten gespeichert und die Geheimteile verloren –
    /// es entsteht nie eine Kopie mit tieferem Schutz.
    private func writeSealedDraft(_ editor: EntryEditorState, _ vault: UnlockedVault,
                                  protection ziel: EntryProtection) -> DraftWriteResult {
        var entry = EntryRules.clamped(editor.draft)
        entry.title = EntryRules.effectiveTitle(entry) ?? EntryRules.draftTitle()
        var geheim: EntrySecrets?
        if !editor.secretsLocked, editor.isNew || editor.secretsChanged || ziel != editor.originalProtection {
            var teile = EntrySecrets(password: entry.password, notes: entry.notes, totp: entry.totp,
                                     history: editor.baseline?.history ?? [])
            if let baseline = editor.baseline {
                teile.history = EntryRules.history(after: baseline, newPassword: entry.password)
            }
            geheim = teile
        }
        do {
            try Self.writeSealed(vault, draft: entry, isNew: !editor.persisted, metadataChanged: true, protection: ziel,
                                 secrets: nil)
        } catch let error as SiegelError {
            return .failed(error, notice: nil)
        } catch {
            return .failed(.io("unexpected"), notice: nil)
        }
        if let geheim {
            do {
                try vault.setProtection(ziel, id: entry.id, secrets: geheim)
            } catch {
                let fehler = (error as? SiegelError) ?? .io("unexpected")
                return .failed(fehler, notice: Self.secretsLostNotice(fehler))
            }
        }
        if !editor.secretsLocked, ziel != editor.draft.protection {
            return .savedWithNotice(protectionNotice(chosen: editor.draft.protection, saved: ziel))
        }
        return .saved
    }

    /// Offener Weg (Schutz 1 vorher und nachher): `upsert`; scheitert das am Eintrag, als eigener „Entwurf <Datum>“
    /// (mit 2FA-Geheimnis), aber nur bei `allowCopy`.
    private func writeOpenDraft(_ editor: EntryEditorState, _ vault: UnlockedVault, allowCopy: Bool) -> DraftWriteResult {
        var entry = editor.draft
        entry.protection = .normal
        entry.title = EntryRules.effectiveTitle(entry) ?? EntryRules.draftTitle()
        if editor.limitViolation != nil {
            entry = EntryRules.clamped(entry)
        }
        let gespeichert: DraftWriteResult = editor.draft.protection == .normal
            ? .saved : .savedWithNotice(protectionNotice(chosen: editor.draft.protection, saved: .normal))
        do {
            try vault.upsert(entry)
            return gespeichert
        } catch let error as SiegelError where Self.failsForEveryEntry(error) || !allowCopy {
            // Platz, fremde Änderung, Prüfung nach dem Speichern: ein zweiter Versuch scheitert gleich.
            return .failed(error, notice: nil)
        } catch {
            guard allowCopy else { return .failed(.io("unexpected"), notice: nil) }
            // Zweiter Versuch als eigener Entwurf (z. B. wenn der bestehende Eintrag nicht mehr passt).
            let titel = EntryRules.draftTitle()
            var entwurf = VaultEntry(title: titel, username: entry.username, password: entry.password, url: entry.url,
                                     notes: entry.notes, totp: entry.totp)
            entwurf = EntryRules.clamped(entwurf)
            do {
                try vault.upsert(entwurf)
                return .savedWithNotice("Als Entwurf gespeichert: Die offene Bearbeitung liess sich nicht in den Eintrag "
                    + "übernehmen und steht jetzt unter „" + titel + "“.")
            } catch let error as SiegelError {
                return .failed(error, notice: nil)
            } catch {
                return .failed(.io("unexpected"), notice: nil)
            }
        }
    }

    /// „Die offene Bearbeitung ist mit Schutz 3 statt 4 gespeichert – für Schutz 4 fehlt noch: QR-Schlüsselkarte.“
    func protectionNotice(chosen: EntryProtection, saved: EntryProtection) -> String {
        let fehlend = missingFactors(for: chosen)
        let grund = fehlend.isEmpty ? "" : " – für Schutz \(chosen.rawValue) fehlt noch: " + FactorUI.list(fehlend, long: true)
        return "Die offene Bearbeitung ist mit Schutz \(saved.rawValue) statt \(chosen.rawValue) gespeichert" + grund + "."
    }

    /// Geheimteile verloren, Titel, Benutzername und Website gespeichert (ohne Inhalt, ohne Eintragsnamen).
    static func secretsLostNotice(_ error: SiegelError) -> String {
        "Beim Sperren gingen die geänderten Geheimteile verloren (" + shortReason(error)
            + "); Titel, Benutzer und Website sind gespeichert."
    }

    /// Fehler, die nicht am Eintrag hängen (jedes Speichern scheitert gleich).
    nonisolated static func failsForEveryEntry(_ error: SiegelError) -> Bool {
        switch error {
        case .notEnoughDiskSpace, .vaultChangedOnDisk: return true
        case let .io(code): return !code.hasPrefix("entry.")
        default: return false
        }
    }
}

// MARK: - Anzeige-Hilfen

extension Anzeige {
    /// „16.10.2026, 21:30“
    static func kurz(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "de_CH")
        formatter.dateFormat = "dd.MM.yyyy, HH:mm"
        return formatter.string(from: date)
    }

    /// „16.10.2026“
    static func tag(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "de_CH")
        formatter.dateFormat = "dd.MM.yyyy"
        return formatter.string(from: date)
    }

    static func tage(_ n: Int) -> String {
        n == 1 ? "noch 1 Tag" : "noch \(n) Tage"
    }
}
