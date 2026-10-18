import Carbon.HIToolbox

/// Secure Event Input für die sichtbare Notfallcode-Eingabe (SPEC §6): an, solange sie Fokus hat;
/// immer paarweise wieder aus (Fokusverlust, App inaktiv, Sperren). Andere Programme sehen die
/// Tastatureingaben dann nicht über Ereignis-Abgriffe.
@MainActor
public enum SecureEventInput {
    private static var enabledByUs = false

    public static func enable() {
        guard !enabledByUs else { return }
        if EnableSecureEventInput() == noErr {
            enabledByUs = true
        }
    }

    public static func disable() {
        guard enabledByUs else { return }
        _ = DisableSecureEventInput()
        enabledByUs = false
    }

    public static var isEnabled: Bool { enabledByUs }
}
