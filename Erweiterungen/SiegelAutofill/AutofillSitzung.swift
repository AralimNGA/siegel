import Foundation
import SiegelCore
import SiegelHardware

// Tresorzugriff der Autofill-Erweiterung (SPEC §20). Liest nur, schreibt nie: kein upsert, kein Speichern, keine
// Migration. Geheimnisse leben so kurz wie möglich; nach Auswahl oder Abbruch wird der Tresor gesperrt.

/// Ort des Tresors für App und Erweiterung. Die Erweiterung hat einen eigenen Sandbox-Container und sieht den
/// Tresor nur im gemeinsamen Gruppen-Container
/// `~/Library/Group Containers/<TEAM-ID>.com.aralim.siegel/Library/Application Support/Siegel/`.
enum AutofillOrt {
    /// Gruppen-Kennung ohne Team-Präfix. Das Präfix setzt Xcode beim Bauen in Info.plist (`SiegelAppGroup`).
    static let gruppenSuffix = "com.aralim.siegel"
    /// Tresor-Ordner im Gruppen-Container (gleich aufgebaut wie im Sandbox-Container der App).
    static let tresorOrdner = "Library/Application Support/Siegel"
    static let infoSchluessel = "SiegelAppGroup"

    /// `<TEAM-ID>.com.aralim.siegel`; nil, wenn ohne Team gebaut (dann gibt es keinen Gruppen-Container).
    static var gruppe: String? {
        guard let g = Bundle.main.object(forInfoDictionaryKey: infoSchluessel) as? String,
              g.hasSuffix("." + gruppenSuffix) else { return nil }
        return g
    }

    static func verzeichnis() throws -> URL {
        guard let g = gruppe,
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: g) else {
            throw AutofillHinweis.keinTresor
        }
        return container.appendingPathComponent(tresorOrdner, isDirectory: true)
    }

    /// Rollback-Merker gemeinsam mit der App (Gruppen-Einstellungen), sonst nur für diese Sitzung.
    static func rollbackGuard() -> RollbackGuard {
        if let g = gruppe, let defaults = UserDefaults(suiteName: g) {
            return UserDefaultsRollbackGuard(defaults: defaults)
        }
        return InMemoryRollbackGuard()
    }
}

/// Gründe, warum die Erweiterung keine Liste zeigt (neben den Fehlern des Kerns).
enum AutofillHinweis: Error, Equatable {
    case keinTresor
    case nurInApp(SecurityLevel)
    case rollback
    case eintragFehlt
}

/// Ein Treffer der Liste: nur Titel und Benutzername. Das Passwort wird erst bei der Auswahl gelesen.
struct AutofillTreffer: Sendable, Identifiable {
    let id: UUID
    let title: String
    let username: String
    let protection: EntryProtection
}

/// Eine Autofill-Anfrage vom Öffnen bis zum Sperren.
final class AutofillSitzung: @unchecked Sendable {
    private let store: VaultStore
    private let lock = NSLock()
    private var vault: UnlockedVault?

    private init(store: VaultStore) {
        self.store = store
    }

    static func oeffnen() throws -> AutofillSitzung {
        AutofillSitzung(store: VaultStore(directory: try AutofillOrt.verzeichnis(),
                                          rollbackGuard: AutofillOrt.rollbackGuard()))
    }

    /// Stufe aus dem Kopf (ohne Geheimnis). Karte oder Sicherheitsschlüssel im Kopf = Stufe 4/5.
    static func stufe(aus kopf: VaultHeaderInfo) -> SecurityLevel? {
        if kopf.factors.contains(.securityKey) { return .festung }
        if kopf.factors.contains(.card) { return .maximal }
        return nil
    }

    /// Liest nur Kopf und Prüfsumme (kein Argon2). Stufe 4/5 → `nurInApp`, bevor nach dem Passwort gefragt wird.
    func vorpruefen() throws -> VaultHeaderInfo {
        dispatchPrecondition(condition: .notOnQueue(.main))
        guard store.vaultExists else { throw AutofillHinweis.keinTresor }
        let kopf = try store.inspect()
        if let stufe = Self.stufe(aus: kopf) { throw AutofillHinweis.nurInApp(stufe) }
        return kopf
    }

    /// Entsperrt mit Master-Passwort und (Stufe 2/3) Touch ID und liefert die passenden Einträge.
    /// Nur Einträge, deren Schutz Autofill erlaubt (Normal, Fingerabdruck), und nur bis Tresor-Stufe 3.
    func entsperren(masterPassword: String, kopf: VaultHeaderInfo, dienste: [String]) throws -> [AutofillTreffer] {
        dispatchPrecondition(condition: .notOnQueue(.main))
        if let stufe = Self.stufe(aus: kopf) { throw AutofillHinweis.nurInApp(stufe) }
        // Das Faktor-Geheimnis lebt nur in diesem Block (FactorSecret nullt beim Freigeben).
        let ergebnis: UnlockOutcome = try {
            var faktoren = FactorSecrets()
            if kopf.factors.contains(.secureEnclave) {
                guard let keyID = kopf.seKeyID else { throw SiegelError.factorUnavailable(.secureEnclave) }
                faktoren.secureEnclave = try SecureEnclaveFactor.secret(keyID: keyID, directory: store.hardwareDirectory,
                                                                       reason: "Siegel entsperren")
            }
            return try store.unlock(masterPassword: masterPassword, factors: faktoren)
        }()
        let offen: UnlockedVault
        switch ergebnis {
        case let .unlocked(v):
            offen = v
        case let .rollbackSuspected(v, _, _):
            v.lock()
            throw AutofillHinweis.rollback
        }
        guard offen.level <= .hoch, offen.policy.autofillAllowed else {
            let stufe = offen.level
            offen.lock()
            throw AutofillHinweis.nurInApp(stufe)
        }
        let treffer = offen.entries
            .filter { eintrag in
                eintrag.protection.autofillAllowed
                    && dienste.contains { AutofillMatcher.matches(entryURL: eintrag.url, serviceIdentifier: $0) }
            }
            .map { AutofillTreffer(id: $0.id, title: $0.title, username: $0.username, protection: $0.protection) }
            .sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
        let alt = lock.withLock { () -> UnlockedVault? in
            let a = vault
            vault = offen
            return a
        }
        alt?.lock()
        return treffer
    }

    /// Benutzername und Passwort eines Treffers. Schutz Fingerabdruck: Touch ID über den Kern (§16), jedes Mal.
    func zugang(fuer id: UUID) async throws -> (user: String, password: String) {
        guard let offen = lock.withLock({ vault }),
              let eintrag = offen.entries.first(where: { $0.id == id }),
              eintrag.protection.autofillAllowed, offen.policy.autofillAllowed else {
            throw AutofillHinweis.eintragFehlt
        }
        if eintrag.protection == .normal && !eintrag.secretsSealed {
            return (eintrag.username, eintrag.password)
        }
        let geheim = try await offen.revealSecrets(id: id, factors: AutofillFaktoren(directory: store.hardwareDirectory))
        return (eintrag.username, geheim.password)
    }

    /// DEK und Inhalt verwerfen. Mehrfach aufrufbar.
    func sperren() {
        let offen = lock.withLock { () -> UnlockedVault? in
            let v = vault
            vault = nil
            return v
        }
        offen?.lock()
    }
}

/// Faktoren beim Aufdecken eines geschützten Eintrags. In der Erweiterung nur Touch ID (Schutz Fingerabdruck);
/// Karte und Sicherheitsschlüssel gibt es nur in der App (Schutz 4/5 ist für Autofill ohnehin gesperrt).
struct AutofillFaktoren: EntryFactorProvider {
    let directory: URL

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        let ordner = directory
        return try await ausserhalb {
            try SecureEnclaveFactor.sharedSecret(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey,
                                                 directory: ordner, reason: "Passwort einsetzen")
        }
    }

    func cardSecret() async throws -> FactorSecret {
        throw SiegelError.notAllowedAtLevel
    }

    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret {
        throw SiegelError.notAllowedAtLevel
    }
}

/// Blockierende Arbeit (Touch ID) nicht auf einem Thread des kooperativen Pools ausführen.
private func ausserhalb<T: Sendable>(_ arbeit: @escaping @Sendable () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { fortsetzung in
        DispatchQueue.global(qos: .userInitiated).async {
            fortsetzung.resume(with: Result { try arbeit() })
        }
    }
}
