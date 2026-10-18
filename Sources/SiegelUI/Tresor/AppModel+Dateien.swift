import AppKit
import DiskArbitration
import SiegelCore
import SwiftUI
import UniformTypeIdentifiers

// Abläufe mit Dateien (SPEC §7.7–7.9): CSV-Import, CSV-Export, verschlüsselte Sicherung exportieren,
// Sicherung einspielen. Panels werden vor dem Zeigen geschützt (sharingType); jeder Abschluss-Handler
// prüft, ob inzwischen gesperrt wurde, und tut dann nichts.

extension AppModel {
    // MARK: Panels

    /// Zeigt ein Öffnen-/Sichern-Panel als Sheet. Der Handler läuft nur, wenn der Tresor noch offen und
    /// derselbe Ablauf noch aktiv ist.
    func presentFlowPanel(_ panel: NSSavePanel, flow: FlowState, onURL: @escaping @MainActor (URL) -> Void) {
        presentPanel(panel, flow: flow, onURL: onURL)
    }

    /// Geht ein Ergebnis noch an diesen Ablauf? (nach jedem `await`)
    func flowStillCurrent(_ flow: FlowState, _ generation: Int) -> Bool {
        stillCurrent(flow, generation)
    }

    private func presentPanel(_ panel: NSSavePanel, flow: FlowState, onURL: @escaping @MainActor (URL) -> Void) {
        guard isUnlocked, flowState === flow else { return }
        WindowGuard.shared.protect(panel)
        let start = epoch
        let handler: (NSApplication.ModalResponse) -> Void = { [weak self, weak panel, weak flow] response in
            MainActor.assumeIsolated {
                guard let self, let flow, start == self.epoch, self.isUnlocked, self.flowState === flow else { return }
                guard response == .OK, let url = panel?.url else { return }
                onURL(url)
            }
        }
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            panel.beginSheetModal(for: window, completionHandler: handler)
        } else {
            panel.begin(completionHandler: handler)
        }
    }

    /// Geht ein Ergebnis noch an diesen Ablauf? (nach jedem `await`)
    private func stillCurrent(_ flow: FlowState, _ generation: Int) -> Bool {
        generation == lockGeneration && isUnlocked && flowState === flow
    }

    // MARK: CSV-Import (SPEC §7.8)

    public func csvImportChooseFile() {
        guard let flow = flowState, flow.kind == .csvImport else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.commaSeparatedText, .plainText]
        panel.prompt = "Wählen"
        panel.message = "CSV-Export aus Apple Passwörter, Chrome, Firefox oder Bitwarden wählen."
        presentPanel(panel, flow: flow) { [weak self] url in
            Task { await self?.csvImportLoad(url) }
        }
    }

    /// Datei lesen und prüfen (im Hintergrund), dann Vorschau.
    public func csvImportLoad(_ url: URL) async {
        guard let flow = flowState, flow.kind == .csvImport, !busy else { return }
        flow.error = nil
        let generation = lockGeneration
        guard let result = await heavy({ () throws -> CSVImportResult in
            let groesse = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
            guard groesse <= 16 << 20 else { throw SiegelError.csvInvalid(line: 0, reason: "csv.fileTooLarge") }
            var data: Data
            do {
                data = try Data(contentsOf: url)
            } catch {
                throw SiegelError.io("csv.read")
            }
            defer { data.resetBytes(in: 0..<data.count) }
            return try CSVImport.parse(data)
        }) else { return }
        guard stillCurrent(flow, generation) else { return }
        switch result {
        case let .success(parsed):
            csvImportShowPreview(parsed, source: url)
        case let .failure(error):
            flow.error = Fehlertexte.text(error)
        }
    }

    /// Vorschau aus einem geprüften Ergebnis (auch für Snapshots).
    public func csvImportShowPreview(_ parsed: CSVImportResult, source: URL) {
        guard let flow = flowState, flow.kind == .csvImport else { return }
        flow.sourceURL = source
        flow.importResult = parsed
        flow.importPreview = ImportPreview.make(parsed, existing: entries)
        flow.error = parsed.entries.isEmpty ? "Die Datei enthält keine Einträge." : nil
        flow.step = .importPreview
    }

    /// „N Einträge importieren“: nur anhängen (vorher Sicherung „vor-import“ im Kern).
    public func csvImportRun() async {
        guard let flow = flowState, flow.step == .importPreview, let parsed = flow.importResult,
              !parsed.entries.isEmpty, !busy else { return }
        flow.error = nil
        let liste = parsed.entries
        let generation = lockGeneration
        busy = true
        let result = await performReturning { try $0.importEntries(liste) }
        guard stillCurrent(flow, generation) else { return }
        busy = false
        switch result {
        case let .success(report):
            flow.importReport = report
            flow.importResult = nil   // Klartext-Einträge nicht länger halten
            flow.step = .importReport
        case let .failure(error):
            flow.error = Fehlertexte.text(error)
        }
    }

    /// „Quelldatei jetzt endgültig löschen?“ → `FileManager.removeItem` (nicht in den Papierkorb).
    public func csvImportDeleteSource() {
        guard let flow = flowState, flow.step == .importReport, let url = flow.sourceURL else { return }
        do {
            try FileManager.default.removeItem(at: url)
            flow.sourceDeleted = true
            flow.error = nil
        } catch {
            flow.error = "Die Datei liess sich nicht löschen. Lösche sie im Finder und leere den Papierkorb."
        }
    }

    public func csvImportKeepSource() {
        flowState?.sourceDeleted = false
    }

    // MARK: CSV-Export (SPEC §7.9)

    public func csvExportChooseFolder() {
        guard let flow = flowState, flow.kind == .csvExport else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Hierhin exportieren"
        panel.message = "Ordner für den Export wählen – nicht in iCloud Drive."
        presentPanel(panel, flow: flow) { [weak self] url in
            self?.csvExportSetFolder(url)
        }
    }

    /// Ziel gewählt: bei unverschlüsseltem (oder unbekanntem) Volume zweite Bestätigung.
    public func csvExportSetFolder(_ url: URL) {
        guard let flow = flowState, flow.kind == .csvExport else { return }
        flow.exportFolder = url
        flow.exportFolderEncrypted = VaultStore.volumeIsEncrypted(url)
        flow.error = nil
        flow.password = ""
        flow.step = flow.exportFolderEncrypted == true ? .exportPassword : .exportUnencrypted
    }

    public func csvExportAcceptUnencrypted() {
        guard let flow = flowState, flow.step == .exportUnencrypted else { return }
        flow.step = .exportPassword
    }

    /// Master-Passwort prüfen und exportieren (der Kern prüft Passwort und iCloud-Ziel).
    public func csvExportRun() async {
        guard let flow = flowState, flow.step == .exportPassword, let folder = flow.exportFolder, let vault,
              !flow.password.isEmpty, !busy else { return }
        let password = flow.password
        flow.error = nil
        let generation = lockGeneration
        guard let factors = await vaultFactors(existing: flow.collection, assign: { flow.collection = $0 },
                                               reason: "CSV exportieren"),
              stillCurrent(flow, generation) else { return }
        // Versiegelte Einträge mit Schutz 2/3 (§16): eine Freigabe über den Provider, erst nach der Passwortprüfung.
        let provider = UIEntryFactorProvider(model: self)
        guard let result = await heavyAsync(writes: true, {
            try await vault.exportCSV(toParent: folder, masterPassword: password, factors: factors,
                                      entryFactors: provider)
        }) else { return }
        guard stillCurrent(flow, generation) else { return }
        flow.collection?.reset()
        flow.password = ""
        switch result {
        case let .success(url):
            flow.exportedURL = url
            exportedCSV = url
            flow.step = .exportDone
            clearPastedMasterPassword()
        case .failure(.wrongPassword):
            flow.error = wrongPasswordText
        case .failure(.exportLocationRejected):
            flow.error = Fehlertexte.text(.exportLocationRejected("icloud"))
            flow.exportFolder = nil
            flow.step = .exportIntro
        case let .failure(error) where error == .factorCancelled || error == .factorUnavailable(.secureEnclave):
            flow.error = Fehlertexte.protectedEntriesRelease(error)
        case let .failure(error):
            flow.error = Fehlertexte.text(error)
        }
    }

    /// „Exportdatei endgültig löschen“: Datei und den leeren `.noindex`-Ordner entfernen.
    public func deleteExportedCSV() {
        guard let url = exportedCSV else { return }
        let fm = FileManager.default
        do {
            if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
            let ordner = url.deletingLastPathComponent()
            if ordner.pathExtension == "noindex",
               (try? fm.contentsOfDirectory(atPath: ordner.path))?.isEmpty == true {
                try fm.removeItem(at: ordner)
            }
            exportedCSV = nil
            show(Notice("Exportdatei gelöscht", symbol: "trash"))
        } catch {
            show(Notice("Die Exportdatei liess sich nicht löschen.", symbol: "exclamationmark.circle"), seconds: 6)
        }
    }

    public func dismissExportedCSVLine() {
        exportedCSV = nil
    }

    public func revealExportedCSV() {
        guard let url = exportedCSV ?? flowState?.exportedURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    // MARK: Verschlüsselte Sicherung exportieren

    public func backupExportChoose() {
        guard let flow = flowState, flow.kind == .backupExport else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Siegel-Sicherung-" + Self.fileDate(Date()) + ".siegel"
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.prompt = "Sichern"
        panel.message = "Am besten auf einen USB-Stick oder in iCloud Drive."
        if let typ = UTType(filenameExtension: "siegel", conformingTo: .data) {
            panel.allowedContentTypes = [typ]
        }
        presentPanel(panel, flow: flow) { [weak self] url in
            Task { await self?.backupExportRun(to: url) }
        }
    }

    public func backupExportRun(to url: URL) async {
        guard let flow = flowState, flow.kind == .backupExport, let store, !busy else { return }
        flow.error = nil
        let generation = lockGeneration
        busy = true
        savesInFlight += 1
        let result = await Self.background { try store.exportBackup(to: url) }
        savesInFlight -= 1
        guard stillCurrent(flow, generation) else { return }
        busy = false
        switch result {
        case .success:
            flow.backupURL = url
            // Nur sicher ausserhalb dieses Macs zählt (Befund #40); im Zweifel bleibt die Mahnzeile stehen.
            flow.backupIsExternal = Self.isOutsideThisMac(url, vaultDirectory: vaultDirectory)
            if flow.backupIsExternal { noteExternalBackup() }
            flow.step = .backupExportDone
        case let .failure(error):
            flow.error = Fehlertexte.text(error)
        }
    }

    /// Liegt `url` sicher ausserhalb dieses Macs (Befund #40)? iCloud Drive ja; sonst nur ein anderes Volume, das
    /// weder intern noch ein eingebundenes Disk-Image ist und auswerfbar, entfernbar oder ein Netzlaufwerk ist.
    /// Lässt sich das nicht sicher bestimmen: nein (die Zeile „Keine Sicherung ausserhalb …“ bleibt).
    static func isOutsideThisMac(_ url: URL, vaultDirectory: URL?) -> Bool {
        let keys: Set<URLResourceKey> = [.isUbiquitousItemKey, .volumeIdentifierKey, .volumeIsInternalKey,
                                         .volumeIsEjectableKey, .volumeIsRemovableKey, .volumeIsLocalKey, .volumeURLKey]
        let werte = try? url.resourceValues(forKeys: keys)
        if werte?.isUbiquitousItem == true || url.path.contains("/Library/Mobile Documents/") { return true }
        guard let werte, let vaultDirectory, let ziel = werte.volumeIdentifier as? NSObject,
              let tresor = (try? vaultDirectory.resourceValues(forKeys: [.volumeIdentifierKey]))?.volumeIdentifier
                as? NSObject else {
            return false
        }
        let diskImage = werte.volume.flatMap { diskImageStatus($0) }
        return StorageLocation.isOutside(sameVolume: ziel.isEqual(tresor), isInternal: werte.volumeIsInternal,
                                         isDiskImage: diskImage, isEjectable: werte.volumeIsEjectable,
                                         isRemovable: werte.volumeIsRemovable, isLocal: werte.volumeIsLocal)
    }

    /// Ist das Volume ein eingebundenes Disk-Image (.dmg, .sparsebundle)? nil = nicht feststellbar.
    nonisolated static func diskImageStatus(_ volume: URL) -> Bool? {
        guard let session = DASessionCreate(kCFAllocatorDefault),
              let disk = DADiskCreateFromVolumePath(kCFAllocatorDefault, session, volume as CFURL),
              let beschreibung = DADiskCopyDescription(disk) as? [String: Any] else { return nil }
        let modell = beschreibung[kDADiskDescriptionDeviceModelKey as String] as? String
        let protokoll = beschreibung[kDADiskDescriptionDeviceProtocolKey as String] as? String
        if modell == nil, protokoll == nil { return nil }
        return modell == "Disk Image" || protokoll == "Virtual Interface"
    }

    static func fileDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }

    // MARK: Sicherung einspielen

    public func backupImportChoose() {
        guard let flow = flowState, flow.kind == .backupImport else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Wählen"
        panel.message = "Siegel-Sicherung (.siegel) wählen."
        if let typ = UTType(filenameExtension: "siegel", conformingTo: .data) {
            panel.allowedContentTypes = [typ]
        }
        // Befund datei-3: Siegels eigene Sicherungen (auch die angehefteten) sind sonst kaum zu finden.
        if let ordner = store?.backupsDirectory, FileManager.default.fileExists(atPath: ordner.path) {
            panel.directoryURL = ordner
        }
        presentPanel(panel, flow: flow) { [weak self] url in
            self?.backupImportSetFile(url)
        }
    }

    /// „Notfallcode verwenden“, wenn ein Faktor der gewählten Sicherung hier nicht nutzbar ist (§14.1, Befund datei-3):
    /// Tresor sperren (offene Bearbeitung wie beim Sperren sichern), dann der Notfallweg für genau diese Datei.
    public func backupImportUseRecovery() {
        guard let flow = flowState, flow.kind == .backupImport, let url = flow.backupURL, !busy else { return }
        flow.collection?.reset()
        lock(reason: .manual)
        guard vault == nil else { return }
        startRecovery(file: url)
    }

    public func backupImportSetFile(_ url: URL) {
        guard let flow = flowState, flow.kind == .backupImport else { return }
        flow.backupURL = url
        flow.password = ""
        flow.error = nil
        flow.step = .backupImportPassword
    }

    /// Ersetzt den Tresor durch die Sicherung (der Kern legt vorher die Sicherung „vor-wiederherstellung“ an).
    public func backupImportRun() async {
        guard let flow = flowState, flow.step == .backupImportPassword, let url = flow.backupURL, let store,
              !flow.password.isEmpty, !busy else { return }
        let password = flow.password
        flow.error = nil
        let generation = lockGeneration
        // Verlangt die Sicherung Faktoren (Stufe 2+)? Dann zuerst einsammeln.
        guard let factors = await factorsForFile(url, existing: flow.collection, assign: { flow.collection = $0 },
                                                 reason: "Sicherung einspielen"),
              stillCurrent(flow, generation) else { return }
        // Offene Bearbeitung zuerst in den bisherigen Tresor sichern (landet in „vor-wiederherstellung“). Geht das
        // nicht, wird nicht eingespielt (Befund #31: sonst verschwände die Eingabe ohne Spur).
        if let vault, browser.editor != nil {
            if case let .refused(error) = saveDraftBeforeLock(vault, mayRefuse: true) {
                flow.error = "Die offene Bearbeitung liess sich nicht speichern: " + Fehlertexte.text(error)
                return
            }
        }
        guard let result = await heavy(writes: true, {
            try store.importBackup(from: url, masterPassword: password, factors: factors)
        }) else { return }
        flow.collection?.reset()
        guard stillCurrent(flow, generation) else {
            if case let .success(neu) = result { neu.lock() }
            return
        }
        flow.password = ""
        switch result {
        case let .success(neu):
            vault?.lock()
            vault = nil
            browser = VaultBrowserState()
            listCache = nil
            flowState = nil
            pendingFlow = nil
            open(neu)
            if recoveryConfirmed {
                show(Notice("Sicherung eingespielt · " + Anzeige.eintraege(entries.count)), seconds: 5)
            } else {
                show(Notice("Sicherung eingespielt · " + Anzeige.eintraege(entries.count)
                            + " · Sie nutzt Notfallkit \(kitID) – prüfe dein Blatt oder erstelle ein neues Notfallkit.",
                            symbol: "exclamationmark.circle"), seconds: 10)
            }
        case .failure(.wrongPassword):
            flow.error = countsAttempt(flow.collection == nil ? "Falsches Passwort für diese Sicherung."
                                                             : "Passwort oder ein Faktor stimmt nicht für diese Sicherung.")
            // §23.2: zählt als Fehlversuch – Warnung ab N/2 auch hier (Befund datei-5, Nebenbefund).
            await refreshDestructionStatus()
        case let .failure(error):
            flow.error = Fehlertexte.text(error)
        }
    }
}

// MARK: - Snapshots (SPI)

extension AppModel {
    /// Nur für SiegelSnapshots: Schritt eines Ablaufs direkt setzen.
    @_spi(Snapshots) public func snapshotFlow(_ change: (FlowState) -> Void) {
        guard let flowState else { return }
        change(flowState)
    }

    @_spi(Snapshots) public func snapshotSetExportedCSV(_ url: URL?) {
        exportedCSV = url
    }
}

extension FlowState {
    @_spi(Snapshots) public func snapshotSet(step: Step, folder: URL? = nil, encrypted: Bool? = nil,
                                             exported: URL? = nil, backup: URL? = nil, external: Bool = false,
                                             report: ImportReport? = nil, sourceDeleted: Bool? = nil) {
        self.step = step
        if let folder { exportFolder = folder }
        if let encrypted { exportFolderEncrypted = encrypted }
        if let exported { exportedURL = exported }
        if let backup { backupURL = backup }
        backupIsExternal = external
        if let report { importReport = report }
        self.sourceDeleted = sourceDeleted
    }
}

/// Entscheidung „ausserhalb dieses Macs“ aus den Volume-Eigenschaften (rein, für Prüfungen ohne echte Volumes).
enum StorageLocation {
    static func isOutside(sameVolume: Bool, isInternal: Bool?, isDiskImage: Bool?, isEjectable: Bool?,
                          isRemovable: Bool?, isLocal: Bool?) -> Bool {
        if sameVolume { return false }
        // Zweites APFS-Volume oder eigene Partition auf der internen SSD
        if isInternal == true { return false }
        // Netzlaufwerk (NAS, Server)
        if isLocal == false { return true }
        // Nicht feststellbar
        guard isInternal == false else { return false }
        // Eingebundenes Disk-Image (liegt meist auf derselben SSD) oder nicht feststellbar
        guard isDiskImage == false else { return false }
        return isEjectable == true || isRemovable == true
    }
}

/// Nur für SiegelSnapshots: die Entscheidung „ausserhalb dieses Macs“ mit erfundenen Volume-Eigenschaften prüfen.
@_spi(Snapshots) public enum StorageLocationProbe {
    public static func outside(sameVolume: Bool, isInternal: Bool?, isDiskImage: Bool?, isEjectable: Bool?,
                               isRemovable: Bool?, isLocal: Bool?) -> Bool {
        StorageLocation.isOutside(sameVolume: sameVolume, isInternal: isInternal, isDiskImage: isDiskImage,
                                  isEjectable: isEjectable, isRemovable: isRemovable, isLocal: isLocal)
    }
}
