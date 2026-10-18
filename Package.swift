// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "Siegel",
    platforms: [.macOS(.v26)],
    products: [
        .executable(name: "Siegel", targets: ["Siegel"]),
        // Für die Autofill-Variante (Erweiterungen/project.yml bindet diese Bibliotheken ein, SPEC §20)
        .library(name: "SiegelCore", targets: ["SiegelCore"]),
        .library(name: "SiegelHardware", targets: ["SiegelHardware"]),
        .library(name: "SiegelUI", targets: ["SiegelUI"]),
    ],
    targets: [
        .binaryTarget(name: "Clibsodium", path: "Vendor/Clibsodium.xcframework"),
        .target(name: "SiegelCore", dependencies: ["Clibsodium"],
                exclude: ["Staerke/Woerter/HERKUNFT.md", "Kern/KERN-NOTIZEN.md"]),
        .target(name: "SiegelHardware", dependencies: ["SiegelCore"], exclude: ["HARDWARE-NOTIZEN.md"],
                linkerSettings: [.linkedFramework("CryptoKit"), .linkedFramework("LocalAuthentication"),
                                 .linkedFramework("Security"), .linkedFramework("IOKit"),
                                 .linkedFramework("AVFoundation"), .linkedFramework("CoreMedia"),
                                 .linkedFramework("CoreVideo"), .linkedFramework("CoreImage"),
                                 .linkedFramework("Vision"), .linkedFramework("QuartzCore")]),
        .target(name: "SiegelUI", dependencies: ["SiegelCore", "SiegelHardware"], exclude: ["UI-NOTIZEN.md"]),
        .executableTarget(name: "Siegel", dependencies: ["SiegelUI"]),
        .executableTarget(name: "SiegelSnapshots", dependencies: ["SiegelUI", "SiegelHardware"]),
        // Fuzzer (SPEC §21): nur im Debug-Bau sinnvoll (@testable für den KDF-Testschalter und interne Parser),
        // gebaut und gefahren über skripte/fuzz.sh mit Address-Sanitizer. Im Release-Bau nur ein Hinweis.
        .executableTarget(name: "SiegelFuzz", dependencies: ["SiegelCore", "SiegelHardware", "SiegelFuzzAbdeckung"],
                          exclude: ["FUZZ-NOTIZEN.md"]),
        // Kanten-Abdeckung (SanitizerCoverage-Rückrufe in C) für SiegelFuzz; wirkt nur mit -sanitize-coverage.
        .target(name: "SiegelFuzzAbdeckung"),
        // Stärke-Referenz für die Windows-Version (SPEC-WINDOWS W7): Korpus bewerten, Unicode-Tabelle und Kennzahlen
        // exportieren. Nur im Debug-Bau sinnvoll (@testable), aufgerufen von windows/skripte/*.py.
        .executableTarget(name: "SiegelStaerkeExport", dependencies: ["SiegelCore"]),
        .testTarget(name: "SiegelCoreTests", dependencies: ["SiegelCore"], resources: [.copy("Fixtures")]),
        .testTarget(name: "SiegelHardwareTests", dependencies: ["SiegelHardware"]),
        // Dieselben Quellen wie die Autofill-Erweiterung (Xcode-Ziel aus Erweiterungen/project.yml, SPEC §20): nur
        // damit `swift build` sie übersetzt und `swift test` ihre Abläufe prüft (v4.4, Befunde bau-1 bis bau-3).
        // Kein Produkt, geht in keine App ein.
        .target(name: "SiegelAutofillErweiterung", dependencies: ["SiegelCore", "SiegelHardware"],
                path: "Erweiterungen/SiegelAutofill", exclude: ["Info.plist", "SiegelAutofill.entitlements"],
                linkerSettings: [.linkedFramework("AuthenticationServices")]),
        .testTarget(name: "SiegelAutofillTests", dependencies: ["SiegelAutofillErweiterung", "SiegelCore"]),
    ]
)
