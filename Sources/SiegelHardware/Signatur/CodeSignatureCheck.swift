import Foundation
import Security

/// Selbstprüfung der Signatur beim Start (SPEC §21).
///
/// Ehrlich: Eine ad-hoc-Signatur lässt sich neu setzen. Die Prüfung erkennt versehentlich beschädigte oder
/// nachträglich veränderte Bündel (fehlende/geänderte Dateien, fremder Code darin), nicht einen Angreifer mit
/// Benutzerrechten, der neu signiert.
public enum CodeSignatureCheck {
    /// Statische Prüfung des eigenen `.app`-Bündels (strikt, mit verschachteltem Code, alle Architekturen) plus
    /// dynamische Prüfung des laufenden Prozesses. Ausserhalb eines `.app`-Bündels (`swift run`, Tests) gibt es
    /// keine Bündel-Signatur zu prüfen → true. Dauert einige Millisekunden (liest alle Dateien des Bündels).
    public static func mainBundleIsValid() -> Bool {
        let url = Bundle.main.bundleURL
        guard url.pathExtension == "app" else { return true }
        return bundleIsValid(at: url) && runningCodeIsValid()
    }

    static let staticFlags = SecCSFlags(rawValue: SecCSFlags.RawValue(
        kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate | kSecCSRestrictSymlinks))

    /// Strikte statische Prüfung eines Bündels (wie `codesign --verify --strict --deep`).
    static func bundleIsValid(at url: URL) -> Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { return false }
        var errors: Unmanaged<CFError>?
        let status = SecStaticCodeCheckValidityWithErrors(code, staticFlags, nil, &errors)
        errors?.release()
        return status == errSecSuccess
    }

    /// Der laufende Prozess gilt beim Kernel als gültig signiert.
    static func runningCodeIsValid() -> Bool {
        var me: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me else { return false }
        return SecCodeCheckValidity(me, [], nil) == errSecSuccess
    }
}
