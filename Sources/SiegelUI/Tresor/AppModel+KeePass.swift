import AppKit
import SiegelCore
import SwiftUI

// KeePass-Export KDBX 4.1 (SPEC v4 §19): nur Stufen 1–3, mit Master-Passwort (+ Faktoren) und eigenem
// Export-Passwort nach der Master-Passwort-Regel. Die Datei ist verschlüsselt; der Kern legt sie wie den CSV-Export
// in einen `.noindex`-Ordner (Spotlight und Time Machine lassen ihn aus) und lehnt iCloud Drive ab.

extension AppModel {
    /// Einträge, die nicht exportiert werden (Schutz 4 und 5, §16).
    public var exportExcludedCount: Int {
        entries.filter { !$0.protection.exportAllowed }.count
    }

    public func keepassChooseFolder() {
        guard let flow = flowState, flow.kind == .keepassExport else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Hierhin exportieren"
        panel.message = "Ordner für den KeePass-Export wählen – nicht in iCloud Drive."
        presentFlowPanel(panel, flow: flow) { [weak self] url in
            self?.keepassSetFolder(url)
        }
    }

    public func keepassSetFolder(_ url: URL) {
        guard let flow = flowState, flow.kind == .keepassExport else { return }
        flow.exportFolder = url
        flow.error = nil
        flow.password = ""
        flow.clearExportPasswords()
        flow.step = .keepassPassword
    }

    /// Export-Passwort erfüllt die Regel, beide Eingaben gleich, Master-Passwort eingegeben.
    public var canRunKeePassExport: Bool {
        guard let flow = flowState, flow.step == .keepassPassword else { return false }
        return !flow.password.isEmpty && flow.exportAssessment.meetsPolicy && flow.exportRepeatMatches
    }

    public func keepassExportRun() async {
        guard let flow = flowState, flow.step == .keepassPassword, let folder = flow.exportFolder, let vault,
              canRunKeePassExport, !busy else { return }
        guard policy.allowKeePassExport else {
            flow.error = Fehlertexte.text(.notAllowedAtLevel)
            return
        }
        let password = flow.password
        let exportPassword = flow.exportPassword
        // Ein eigenes Passwort: Die Datei wandert oft auf andere Geräte.
        if VaultStore.passwordsMatch(password, exportPassword) {
            flow.error = "Nimm ein anderes Passwort als dein Master-Passwort – die Exportdatei wandert oft auf andere Geräte."
            flow.clearExportPasswords()
            return
        }
        flow.error = nil
        let generation = lockGeneration
        guard let factors = await vaultFactors(existing: flow.collection, assign: { flow.collection = $0 },
                                               reason: "KeePass exportieren"),
              flowStillCurrent(flow, generation) else { return }
        // Versiegelte Einträge mit Schutz 2/3 (§16): eine Freigabe über den Provider, erst nach der Passwortprüfung.
        let provider = UIEntryFactorProvider(model: self)
        guard let result = await heavyAsync(writes: true, {
            try await vault.exportKeePass(toParent: folder, masterPassword: password, factors: factors,
                                          exportPassword: exportPassword, entryFactors: provider)
        }) else { return }
        guard flowStillCurrent(flow, generation) else { return }
        flow.collection?.reset()
        flow.password = ""
        switch result {
        case let .success(url):
            flow.clearExportPasswords()
            flow.exportedURL = url
            flow.step = .keepassDone
            clearPastedMasterPassword()
        case .failure(.wrongPassword):
            flow.error = wrongPasswordText
        case .failure(.exportLocationRejected):
            flow.error = Fehlertexte.text(.exportLocationRejected("icloud"))
            flow.exportFolder = nil
            flow.clearExportPasswords()
            flow.step = .keepassIntro
        case .failure(.passwordTooWeak):
            flow.error = "Das Export-Passwort ist zu schwach. Nötig sind mindestens 12 Zeichen und 60 Bit."
        case .failure(.masterPasswordReused):
            flow.error = "Nimm ein anderes Passwort als dein Master-Passwort – die Exportdatei wandert oft auf andere Geräte."
            flow.clearExportPasswords()
        case let .failure(error) where error == .factorCancelled || error == .factorUnavailable(.secureEnclave):
            flow.error = Fehlertexte.protectedEntriesRelease(error)
        case let .failure(error):
            flow.error = Fehlertexte.text(error)
        }
    }

    /// „Exportdatei löschen“ nach dem KeePass-Export (Datei und leerer `.noindex`-Ordner).
    public func deleteExportedKeePass() {
        guard let flow = flowState, flow.kind == .keepassExport, let url = flow.exportedURL else { return }
        let fm = FileManager.default
        do {
            if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
            let ordner = url.deletingLastPathComponent()
            if ordner.pathExtension == "noindex",
               (try? fm.contentsOfDirectory(atPath: ordner.path))?.isEmpty == true {
                try fm.removeItem(at: ordner)
            }
            flow.exportedURL = nil
            flow.sourceDeleted = true
            show(Notice("Exportdatei gelöscht", symbol: "trash"))
        } catch {
            flow.error = "Die Exportdatei liess sich nicht löschen. Lösche sie im Finder."
        }
    }

    public func revealExportedKeePass() {
        guard let url = flowState?.exportedURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}
