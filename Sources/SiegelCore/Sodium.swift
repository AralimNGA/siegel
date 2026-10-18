import Clibsodium

/// Initialisiert libsodium genau einmal (threadsicher laut Doku). Vor jeder Krypto `_ = Sodium.ready`.
/// Scheitert `sodium_init`, endet der Prozess mit festem Text (SPEC §1).
enum Sodium {
    static let ready: Bool = {
        guard sodium_init() >= 0 else { fatalError("sodium_init") }
        return true
    }()
}
