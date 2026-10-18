import Foundation

/// Zeitquelle des Kerns. Alle Zeitpunkte im Inhalt laufen durch `canonical`, damit sie den JSON-Rundlauf
/// (secondsSince1970) bitgenau überstehen.
enum Clock {
    static func now() -> Date {
        #if DEBUG
        if let fixed = TestHooks.now { return canonical(fixed) }
        #endif
        return canonical(Date())
    }

    /// Ein Rundlauf über `timeIntervalSince1970` ist danach ein Fixpunkt (gleich wie nach JSON-Kodieren).
    static func canonical(_ date: Date) -> Date {
        Date(timeIntervalSince1970: date.timeIntervalSince1970)
    }
}

#if DEBUG
/// Testschalter, nur in DEBUG-Bauten und nur über `@testable` erreichbar. Sie gelten pro Task
/// (`TaskLocal`) und beeinflussen parallel laufende Tests nicht. Keiner hebt eine Prüfung auf.
enum TestHooks {
    /// Erzwingt einen echten `crypto_pwhash`-Fehler (opslimit 0 → libsodium lehnt ab).
    @TaskLocal static var forceKDFFailure = false
    /// Kippt nach dem Schreiben ein Byte der Temp-Datei, damit die Rücklese-Prüfung scheitert.
    @TaskLocal static var corruptTempBeforeVerify = false
    /// Ersetzt den gemessenen freien Platz (Byte).
    @TaskLocal static var freeSpaceOverride: UInt64? = nil
    /// Feste Uhrzeit für Verlauf/Zuletzt-gelöscht/Sicherungsnamen.
    @TaskLocal static var now: Date? = nil
    /// Zählt Argon2-Läufe (KEK-Wiederverwendung prüfen).
    @TaskLocal static var kdfCounter: Counter? = nil
    /// Ersetzt das KDF-Profil aller Stufen (Fixture-Erzeugung mit 256 MiB, t = 3).
    @TaskLocal static var levelKDFOverride: KDFParameters? = nil
    /// Ersetzt `KeePassExport.kdbx` (Tests sehen, welche Einträge mit welchen Geheimteilen exportiert würden).
    @TaskLocal static var keePassExporter: KeePassHook? = nil
    /// Jeder Argon2-Lauf wartet hier, bis alle Teilnehmer da sind (belegt, dass zwei Läufe gleichzeitig laufen, §23.2).
    @TaskLocal static var kdfRendezvous: Rendezvous? = nil
    /// Wird vor jedem Argon2-Lauf mit dessen Nummer (ab 1) aufgerufen, z. B. um während einer Rechnung zu sperren.
    @TaskLocal static var kdfObserver: KDFObserver? = nil
    /// `purgeBackups` scheitert (nach dem Schreiben der Tresordatei, Befund datei-1).
    @TaskLocal static var failPurgeBackups = false
    /// Wird beim Entsperren gerufen, wenn das Vernichtungs-Passwort erkannt ist (nach beiden Argon2, vor dem Vermerk).
    /// Der Fuzzer tauscht hier `zustand.json` (Wettlauf zwischen Probe und Vermerk).
    @TaskLocal static var afterDuressArgon: Hook? = nil

    /// Treffpunkt für `parties` Argon2-Läufe. Kommt einer allein an (z. B. weil nacheinander gerechnet wird), wartet
    /// er höchstens `timeout` und zählt das als `missed`.
    final class Rendezvous: @unchecked Sendable {
        private let condition = NSCondition()
        private let parties: Int
        private let timeout: TimeInterval
        private var waiting = 0
        private var round = 0
        private var _arrivals = 0
        private var _missed = 0

        init(parties: Int = 2, timeout: TimeInterval = 5) {
            self.parties = parties
            self.timeout = timeout
        }

        var arrivals: Int { condition.withLock { _arrivals } }
        var missed: Int { condition.withLock { _missed } }

        func arrive() {
            condition.lock()
            defer { condition.unlock() }
            _arrivals += 1
            waiting += 1
            if waiting == parties {
                waiting = 0
                round += 1
                condition.broadcast()
                return
            }
            let myRound = round
            let deadline = Date().addingTimeInterval(timeout)
            while round == myRound {
                if !condition.wait(until: deadline) {
                    if round == myRound {
                        waiting -= 1
                        _missed += 1
                    }
                    return
                }
            }
        }
    }

    /// Momentaufnahme der Schalter, die auf einem anderen Thread gelten sollen (TaskLocal wird nicht vererbt).
    struct Snapshot: Sendable {
        let forceKDFFailure: Bool
        let kdfCounter: Counter?
        let kdfRendezvous: Rendezvous?
        let kdfObserver: KDFObserver?
        let now: Date?
        let levelKDFOverride: KDFParameters?

        static func current() -> Snapshot {
            Snapshot(forceKDFFailure: TestHooks.forceKDFFailure, kdfCounter: TestHooks.kdfCounter,
                     kdfRendezvous: TestHooks.kdfRendezvous, kdfObserver: TestHooks.kdfObserver, now: TestHooks.now,
                     levelKDFOverride: TestHooks.levelKDFOverride)
        }

        func apply(_ body: () -> Void) {
            TestHooks.$forceKDFFailure.withValue(forceKDFFailure) {
                TestHooks.$kdfCounter.withValue(kdfCounter) {
                    TestHooks.$kdfRendezvous.withValue(kdfRendezvous) {
                        TestHooks.$kdfObserver.withValue(kdfObserver) {
                            TestHooks.$now.withValue(now) {
                                TestHooks.$levelKDFOverride.withValue(levelKDFOverride) { body() }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Zählt die Argon2-Läufe und ruft `action` mit der Nummer des Laufs auf (vor der Rechnung).
    final class KDFObserver: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        private let action: @Sendable (Int) -> Void

        init(_ action: @escaping @Sendable (Int) -> Void) { self.action = action }

        var runs: Int { lock.withLock { n } }

        func observe() {
            let k = lock.withLock { () -> Int in
                n += 1
                return n
            }
            action(k)
        }
    }

    /// Ein Rückruf ohne Argumente.
    final class Hook: @unchecked Sendable {
        private let action: @Sendable () -> Void
        init(_ action: @escaping @Sendable () -> Void) { self.action = action }
        func run() { action() }
    }

    final class KeePassHook: @unchecked Sendable {
        let export: ([(VaultEntry, EntrySecrets)], String) throws -> Data
        init(_ export: @escaping ([(VaultEntry, EntrySecrets)], String) throws -> Data) { self.export = export }
    }

    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        init() {}
        func increment() { lock.withLock { n += 1 } }
        var value: Int { lock.withLock { n } }
    }
}
#endif
