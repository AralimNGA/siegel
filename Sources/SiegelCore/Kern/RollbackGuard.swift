import Foundation

/// Rollback-Stolperdraht (SPEC §4): merkt pro vaultID die zuletzt gesehene Generation.
/// Implementierungen speichern nur steigende Werte.
public protocol RollbackGuard: Sendable {
    func lastSeenGeneration(vaultID: UUID) -> UInt64?
    func record(vaultID: UUID, generation: UInt64)
}

/// Speichert in `UserDefaults` (Schlüssel `Siegel.rollback.<UUID>`, Wert als Dezimaltext).
public final class UserDefaultsRollbackGuard: RollbackGuard, @unchecked Sendable {
    private let defaults: UserDefaults
    private let lock = NSLock()

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    private func key(_ id: UUID) -> String { "Siegel.rollback." + id.uuidString }

    public func lastSeenGeneration(vaultID: UUID) -> UInt64? {
        lock.withLock {
            guard let s = defaults.string(forKey: key(vaultID)) else { return nil }
            return UInt64(s)
        }
    }

    public func record(vaultID: UUID, generation: UInt64) {
        lock.withLock {
            let k = key(vaultID)
            if let s = defaults.string(forKey: k), let current = UInt64(s), current >= generation { return }
            defaults.set(String(generation), forKey: k)
        }
    }
}

/// Nur im Speicher (Tests, SiegelSnapshots).
public final class InMemoryRollbackGuard: RollbackGuard, @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [UUID: UInt64] = [:]

    public init() {}

    public func lastSeenGeneration(vaultID: UUID) -> UInt64? {
        lock.withLock { seen[vaultID] }
    }

    public func record(vaultID: UUID, generation: UInt64) {
        lock.withLock { seen[vaultID] = max(seen[vaultID] ?? 0, generation) }
    }
}
