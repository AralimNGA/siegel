import AppKit
import SiegelCore
import SwiftUI

// Schutz pro Eintrag (SPEC v4 §16) und die Stufenregel „Touch ID vor jedem Aufdecken/Kopieren“ (§13, Stufe 3+).
// Geschützte Einträge (Schutz ≥ 2) liefern ihre Geheimteile nur über `revealSecrets` mit einem
// `EntryFactorProvider`: Touch ID, Karte scannen, Schlüssel berühren – je Aufdecken neu. Aufgedeckte Teile hält
// die Oberfläche nur, solange sie angezeigt werden (Auswahlwechsel, Verbergen, Sperren verwerfen sie).

extension AppModel {
    // MARK: Abfragen

    /// Schutz neuer Einträge: Einstellung, mindestens die Vorgabe der Stufe (Stufe 4/5 → 2).
    public var effectiveDefaultProtection: EntryProtection {
        max(settings.defaultEntryProtection, policy.defaultEntryProtection)
    }

    /// Für diesen Schutz noch nicht eingerichtete Faktoren.
    public func missingFactors(for protection: EntryProtection) -> FactorSet {
        protection.factors.subtracting(enrolledFactors)
    }

    /// Müssen die Geheimteile erst aufgedeckt werden (Schutz ≥ 2 oder Stufe 3+)?
    public func needsReveal(_ entry: VaultEntry) -> Bool {
        entry.protection > .normal || entry.secretsSealed || policy.touchIDBeforeReveal
    }

    /// Geheimteile zum Anzeigen: bei offenen Einträgen direkt, sonst nur nach dem Aufdecken.
    public func visibleSecrets(_ entry: VaultEntry) -> EntrySecrets? {
        if !needsReveal(entry) {
            return EntrySecrets(password: entry.password, notes: entry.notes, totp: entry.totp, history: entry.history)
        }
        guard let offen = browser.unlockedSecrets, offen.id == entry.id else { return nil }
        return offen.secrets
    }

    // MARK: Aufdecken

    /// Holt die Geheimteile (geschützt: über die Faktoren; Stufe 3+: nach Touch ID). nil = abgebrochen/gescheitert.
    func obtainSecrets(_ entry: VaultEntry) async -> EntrySecrets? {
        if !needsReveal(entry) {
            return EntrySecrets(password: entry.password, notes: entry.notes, totp: entry.totp, history: entry.history)
        }
        if let offen = browser.unlockedSecrets, offen.id == entry.id { return offen.secrets }
        // §23: Vernichtet – der Schlüssel ist weg, kein Faktor öffnet den Eintrag mehr.
        if isDestroyed(entry) {
            browser.error = "Dieser Eintrag wurde vernichtet. " + DestructionTexts.destroyedDetail
            return nil
        }
        guard entry.protection > .normal || entry.secretsSealed else {
            // Offener Eintrag in Stufe 3+: Touch ID genügt (Regel der Oberfläche).
            guard await passTouchIDGate() else { return nil }
            return EntrySecrets(password: entry.password, notes: entry.notes, totp: entry.totp, history: entry.history)
        }
        guard let vault, !factorInProgress else { return nil }
        let fehlend = missingFactors(for: entry.protection)
        if let kind = fehlend.kinds.first {
            browser.error = Fehlertexte.text(.factorMissing(kind))
            return nil
        }
        let start = epoch
        let browserState = browser
        browserState.error = nil
        browserState.revealing = entry.id
        let provider = UIEntryFactorProvider(model: self)
        let id = entry.id
        let result = await Self.reveal(vault, id: id, provider: provider)
        guard start == epoch, browser === browserState else { return nil }
        browserState.revealing = nil
        switch result {
        case let .success(secrets):
            return secrets
        case let .failure(error):
            if error != .factorCancelled { browserState.error = Self.revealErrorText(error) }
            return nil
        }
    }

    nonisolated static func reveal(_ vault: UnlockedVault, id: UUID,
                                   provider: UIEntryFactorProvider) async -> Result<EntrySecrets, SiegelError> {
        await Task.detached(priority: .userInitiated) { () -> Result<EntrySecrets, SiegelError> in
            do {
                return .success(try await vault.revealSecrets(id: id, factors: provider))
            } catch let error as SiegelError {
                return .failure(error)
            } catch {
                return .failure(.factorCancelled)
            }
        }.value
    }

    static func revealErrorText(_ error: SiegelError) -> String {
        switch error {
        case .wrongCard, .factorMissing, .factorUnavailable, .factorTemporarilyUnavailable, .wrongSecurityKey:
            return Fehlertexte.text(error)
        default:
            return "Aufdecken gescheitert – ein Faktor stimmt nicht. Versuche es erneut."
        }
    }

    /// „Aufdecken“ im Detail: Geheimteile holen und anzeigen (Passwort sichtbar).
    public func revealEntry(_ entry: VaultEntry) async {
        guard let secrets = await obtainSecrets(entry), browser.selection == entry.id else { return }
        browser.unlockedSecrets = UnlockedSecrets(id: entry.id, secrets: secrets)
        browser.revealedPassword = entry.id
    }

    /// „Verbergen“: aufgedeckte Geheimteile verwerfen.
    public func hideEntrySecrets() {
        browser.unlockedSecrets = nil
        browser.revealedPassword = nil
        browser.revealedHistory = []
        browser.historyExpanded = false
    }

    /// Auge beim Passwort: offen → umschalten; sonst zuerst aufdecken.
    public func toggleRevealPassword(_ entry: VaultEntry) async {
        if browser.revealedPassword == entry.id {
            browser.revealedPassword = nil
            return
        }
        if needsReveal(entry), visibleSecrets(entry) == nil {
            await revealEntry(entry)
        } else {
            browser.revealedPassword = entry.id
        }
    }

    /// Früheres Passwort zeigen (Stufe 3+ bzw. geschützt: nur nach dem Aufdecken).
    public func toggleHistoryEntry(_ entry: VaultEntry, index: Int) async {
        if browser.revealedHistory.contains(index) {
            browser.revealedHistory.remove(index)
            return
        }
        if needsReveal(entry), visibleSecrets(entry) == nil {
            await revealEntry(entry)
            guard visibleSecrets(entry) != nil else { return }
        }
        browser.revealedHistory.insert(index)
    }

    // MARK: Kopieren

    public enum SecretPart: Sendable, Equatable {
        case password
        case notes
        case totpCode
        case history(Int)
    }

    /// Kopiert einen Geheimteil. Ist er noch nicht aufgedeckt, wird er für genau dieses Kopieren geholt
    /// (geschützt: Faktoren; Stufe 3+: Touch ID) und danach nicht behalten.
    public func copyEntrySecret(_ entry: VaultEntry, _ part: SecretPart) async {
        guard let secrets = await obtainSecrets(entry), isUnlocked else { return }
        let wert: String
        switch part {
        case .password: wert = secrets.password
        case .notes: wert = secrets.notes
        case .totpCode:
            guard let ablesung = TOTPDisplay.reading(secrets.totp) else {
                show(Notice(Fehlertexte.text(.totpInvalid("totp.parse")), symbol: "exclamationmark.circle"))
                return
            }
            wert = ablesung.code
        case let .history(index):
            guard index >= 0, index < secrets.history.count else { return }
            wert = secrets.history[index].password
        }
        guard !wert.isEmpty else { return }
        copySecret(wert, protection: entry.protection)
    }

    // MARK: Bearbeiten geschützter Einträge

    /// Geheimteile im Bearbeiten aufdecken (versiegelter Eintrag).
    public func unlockEditorSecrets() async {
        guard let editor = browser.editor, editor.secretsLocked, let original = editor.original else { return }
        guard let secrets = await obtainSecrets(original), browser.editor === editor else {
            if let fehler = browser.error { editor.error = fehler }
            return
        }
        editor.draft.password = secrets.password
        editor.draft.notes = secrets.notes
        editor.draft.totp = secrets.totp
        editor.draft.history = secrets.history
        editor.baseline = secrets
        editor.initialSecrets = secrets
        editor.secretsLocked = false
        editor.error = nil
    }

    /// Schreibt einen Eintrag mit Schutz bzw. versiegelten Geheimteilen (synchron, im Hintergrund oder beim
    /// Sperren). Metadaten über `upsert` (der Kern behält versiegelte Teile), Geheimteile über `setProtection`.
    /// Neue Einträge entstehen zuerst ohne Geheimteile, damit nie Klartext eines geschützten Eintrags geschrieben wird.
    nonisolated static func writeSealed(_ vault: UnlockedVault, draft: VaultEntry, isNew: Bool, metadataChanged: Bool,
                                        protection: EntryProtection, secrets: EntrySecrets?) throws {
        if isNew {
            var leer = draft
            leer.password = ""
            leer.notes = ""
            leer.totp = ""
            leer.history = []
            leer.protection = .normal
            try vault.upsert(leer)
        } else if metadataChanged, var gespeichert = vault.entries.first(where: { $0.id == draft.id }) {
            gespeichert.title = draft.title
            gespeichert.username = draft.username
            gespeichert.url = draft.url
            try vault.upsert(gespeichert)
        }
        if let secrets {
            try vault.setProtection(protection, id: draft.id, secrets: secrets)
        }
    }

    /// Fehlende Faktoren für den gewählten Schutz einrichten (aus der Bearbeitung).
    public func enrollForEditor() {
        guard let editor = browser.editor else { return }
        let fehlend = missingFactors(for: editor.draft.protection)
        guard !fehlend.isEmpty else { return }
        startEnroll(fehlend, fromEditor: true)
    }
}
