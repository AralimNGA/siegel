#if DEBUG
import CryptoKit
import Foundation
@testable import SiegelCore

/// Eine gültige Tresordatei als Saat, mit allem, was zum Öffnen gehört (nur Testwerte).
final class TresorSaat {
    let name: String
    let bytes: [UInt8]
    let datei: VaultFile
    let pw: SecureBytes
    /// Master-Passwort als Text (Vernichtungs-Saaten können ein eigenes haben).
    let passwort: String
    let faktoren: FactorSecrets
    /// Notfallschlüssel R (aus Code bzw. zwei Teilen).
    let r: SecureBytes
    let code: String?
    let teile: [String]
    let limits: KDFLimits
    let cache = KEKCache()
    /// Fixtures (echtes Profil 256 MiB): teure Argon2-Läufe mit anderen Parametern werden übersprungen.
    let echtesProfil: Bool
    let layout: [Feld]
    /// Nach dem Selbsttest gesetzt.
    var dek: SecureBytes?
    var json: [UInt8] = []
    var inhalt: VaultContent?
    /// Saat mit eingerichteter Selbstvernichtung (§23): Plan und ganzer Tresorordner nach der Erzeugung.
    var vernichtung: VernichtungsSaat?

    /// V dieser Saat ist schon vernichtet (vernichtbare Einträge sind nie mehr lesbar).
    var vVernichtet: Bool { vernichtung?.plan.vVernichtet ?? false }

    init(name: String, bytes: [UInt8], passwort: String, faktoren: FactorSecrets, code: String?, teile: [String],
         limits: KDFLimits, echtesProfil: Bool) throws {
        self.name = name
        self.bytes = bytes
        self.datei = try VaultFile.parse(bytes)
        self.pw = try PasswordNormalizer.secureBytes(passwort)
        self.passwort = passwort
        self.faktoren = faktoren
        self.code = code
        self.teile = teile
        if let code {
            r = try RecoveryCodeCodec.decode(code)
        } else {
            r = try VaultStore.combineShares(Array(teile.prefix(2)))
        }
        self.limits = limits
        self.echtesProfil = echtesProfil
        self.layout = Feld.layout(of: datei)
    }

    var header: VaultHeader { datei.header }
}

/// Benanntes Feld einer Datei (Byte-Bereich), für strukturbewusste Mutationen.
struct Feld {
    let name: String
    let bereich: Range<Int>
    /// Ganzzahl (Little-Endian) mit dieser Breite, sonst 0.
    let ganzzahl: Int

    static func layout(of f: VaultFile) -> [Feld] {
        var out: [Feld] = []
        var o = 0
        func add(_ n: String, _ len: Int, _ int: Int = 0) {
            out.append(Feld(name: n, bereich: o..<(o + len), ganzzahl: int))
            o += len
        }
        add("magic", 6)
        add("version", 2, 2)
        add("vaultID", 16)
        add("kdfAlg", 1, 1)
        add("ops", 4, 4)
        add("mem", 8, 8)
        add("salt", 16)
        if f.header.formatVersion >= 2 {
            add("mask", 1, 1)
            add("scheme", 1, 1)
            add("seKeyID", 16)
            add("cardTag", 4)
            add("credLen", 2, 2)
            add("credID", f.header.factorFields.fidoCredentialID?.count ?? 0)
            add("fidoSalt", 32)
        }
        add("pkM", 1568)
        add("pkX", 32)
        add("pwSlot.nonce", 24)
        add("pwSlot.ct", 32)
        add("pwSlot.tag", 16)
        add("ctM", 1568)
        add("ctX", 32)
        add("recSlot.nonce", 24)
        add("recSlot.ct", 32)
        add("recSlot.tag", 16)
        add("generation", 8, 8)
        add("payload.nonce", 24)
        add("ctLen", 4, 4)
        add("payload.ct", f.ciphertext.count - 16)
        add("payload.tag", 16)
        add("checksum", 32)
        return out.filter { !$0.bereich.isEmpty }
    }
}

/// Feste Testwerte. Nichts davon wird ausgegeben.
enum SaatWerte {
    static let passwort = "q8,Vd:Lk3#xRw+Tz!mP9@bN6^cJ2-sGh"
    static let testKDF = KDFParameters(opsLimit: 1, memLimitBytes: 8 << 10)
    static let seKeyID = UUID(uuidString: "5E5E5E5E-0000-4000-8000-000000000001") ?? UUID()
    static let entryKeyID = UUID(uuidString: "5E5E5E5E-0000-4000-8000-000000000002") ?? UUID()
    static func wert(_ b: UInt8) -> FactorSecret {
        // 32 gleiche Bytes (wie die Fixtures); FactorSecret(copying:) wirft nur bei falscher Länge.
        (try? FactorSecret(copying: [UInt8](repeating: b, count: 32))) ?? CardCode.generate()
    }
    static let se = wert(0x41)
    static let q = wert(0x42)
    static let fido = wert(0x43)
    static let fidoEintrag = wert(0x44)
    static let entryPublicKey: Data = {
        let raw = [UInt8](repeating: 0x5A, count: 32)
        let key = (try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw)) ?? P256.KeyAgreement.PrivateKey()
        return key.publicKey.x963Representation
    }()

    static var alleFaktoren: FactorSecrets { FactorSecrets(secureEnclave: se, card: q, securityKey: fido) }

    /// Nur die Faktoren einer Stufe (so verlangt es `configureDestruction`).
    static func faktoren(_ set: FactorSet) -> FactorSecrets {
        FactorSecrets(secureEnclave: set.contains(.secureEnclave) ? se : nil, card: set.contains(.card) ? q : nil,
                      securityKey: set.contains(.securityKey) ? fido : nil)
    }

    // MARK: Selbstvernichtung (§23)

    /// Fester Zeitpunkt der Erzeugung der Vernichtungs-Saaten (TestHooks.now), damit Fristen reproduzierbar sind.
    static let zeitpunkt = Date(timeIntervalSince1970: 1_792_000_000)
    /// Privater Schlüssel des Eintrags-SE-Schlüssels der übrigen Saaten (roh, wie `entryPublicKey`). Der Fuzzer legt
    /// ihn und V – wie das Hardware-Modul die SE-Blobs – als `Hardware/<keyID>.siegelhw` ab; fehlt die Datei, ist der
    /// Schlüssel weg (Software-P256 statt Secure Enclave, keine Biometrie).
    static let eintragRoh = [UInt8](repeating: 0x5A, count: 32)
    /// Platzhalter für den Entsperr-SE-Schlüssel (`<seKeyID>.siegelhw`): Der Kern darf ihn nie löschen
    /// (sonst öffnet der Tresor nur noch mit dem Notfallcode).
    static let oeffnungRoh = [UInt8](repeating: 0x41, count: 32)
    /// Kennung von V pro Vernichtungs-Saat (verschieden, damit Vertauschen zwischen Saaten fremde Dateien nennt).
    static func vKeyID(_ n: Int) -> UUID {
        UUID(uuidString: String(format: "5E5E5E5E-0000-4000-8000-0000000001%02X", n & 0xFF)) ?? UUID()
    }
    /// Eigener Entsperr-SE-Schlüssel und Eintrags-SE-Schlüssel je Vernichtungs-Saat (Befund der Prüfung: alle Saaten
    /// teilten Kennungen und Schlüsselmaterial, „fremdes Material unter dem richtigen Namen“ entstand so nie).
    static func seKeyID(_ n: Int) -> UUID {
        UUID(uuidString: String(format: "5E5E5E5E-0000-4000-8000-0000000002%02X", n & 0xFF)) ?? UUID()
    }
    static func entryKeyID(_ n: Int) -> UUID {
        UUID(uuidString: String(format: "5E5E5E5E-0000-4000-8000-0000000003%02X", n & 0xFF)) ?? UUID()
    }
    /// Rohe private Schlüssel (32 gleiche Bytes, gültige P-256-Skalare): V = 0x5B + n, Eintrags-SE-Schlüssel 0x30 + n.
    static func vRoh(_ n: Int) -> [UInt8] { [UInt8](repeating: 0x5B &+ UInt8(n & 0x1F), count: 32) }
    static func eintragRoh(_ n: Int) -> [UInt8] { [UInt8](repeating: 0x30 &+ UInt8(n & 0x1F), count: 32) }
    static func oeffentlich(_ roh: [UInt8]) -> Data {
        let key = (try? P256.KeyAgreement.PrivateKey(rawRepresentation: roh)) ?? P256.KeyAgreement.PrivateKey()
        return key.publicKey.x963Representation
    }
    /// Zweites Master-Passwort (eigene Saat, Passwortwechsel und Notfallweg im Ziel „vernichtung“).
    static let passwort2 = "Zw8#kQ2@Wz7^Lm4&Rt9!Vs3-Hof-Weg"
    /// Zweites Vernichtungs-Passwort (Ersetzen des Vernichtungs-Passworts im Ziel „vernichtung“).
    static let zwang2 = "Kp4!Ns7#Qd2@Xv9^Lt6&Mz3-Zwang2"

    /// Roher privater Schlüssel zu einer Kennung (Eintrags-SE-Schlüssel und V aller Saaten), sonst nil.
    static func rohSchluessel(_ id: UUID) -> [UInt8]? {
        if id == entryKeyID { return eintragRoh }
        for p in SaatErzeugung.plaene {
            guard let v = p.vernichtung else { continue }
            if id == v.vKeyID { return vRoh(v.nummer) }
            if id == entryKeyID(v.nummer) { return eintragRoh(v.nummer) }
        }
        return nil
    }

    static func hwName(_ id: UUID) -> String { id.uuidString + "." + VaultStore.hardwareKeyExtension }

    /// Kennungen und Schlüssel einer Saat (Vernichtungs-Saaten haben eigene).
    struct Schluessel {
        let seKeyID: UUID
        let entryKeyID: UUID
        let eintragRoh: [UInt8]
        static let standard = Schluessel(seKeyID: SaatWerte.seKeyID, entryKeyID: SaatWerte.entryKeyID,
                                         eintragRoh: SaatWerte.eintragRoh)
        static func fuer(_ plan: SaatErzeugung.Plan) -> Schluessel {
            guard let v = plan.vernichtung else { return standard }
            return Schluessel(seKeyID: SaatWerte.seKeyID(v.nummer), entryKeyID: SaatWerte.entryKeyID(v.nummer),
                              eintragRoh: SaatWerte.eintragRoh(v.nummer))
        }
    }

    static func material(_ set: FactorSet, credLaenge: Int, eintragsSchluessel: Bool = true,
                         schluessel: Schluessel = .standard) -> NewFactorMaterial {
        NewFactorMaterial(
            secureEnclave: set.contains(.secureEnclave) ? SEEnrollment(keyID: schluessel.seKeyID, secret: se) : nil,
            entryKey: eintragsSchluessel
                ? EntryKeyEnrollment(keyID: schluessel.entryKeyID, publicKey: oeffentlich(schluessel.eintragRoh)) : nil,
            card: set.contains(.card) ? CardEnrollment(q: q) : nil,
            securityKey: set.contains(.securityKey)
                ? SecurityKeyEnrollment(credentialID: Data(repeating: 0x45, count: credLaenge),
                                        salt: Data(repeating: 0x46, count: 32), output: fido,
                                        entrySalt: Data(repeating: 0x47, count: 32), entryOutput: fidoEintrag)
                : nil)
    }

    static func beispielEintraege() -> [VaultEntry] {
        [
            VaultEntry(title: "Bibliothek Bern", username: "leserin.muster", password: "Buecher-Regal-42!",
                       url: "https://bibliothek.example.ch", notes: "Ausweis auf der Karte.",
                       totp: "otpauth://totp/Bibliothek:leserin?secret=JBSWY3DPEHPK3PXP&issuer=Bibliothek"),
            VaultEntry(title: "Velo-Club", username: "velofahrer", password: "Kette+Sattel-77", url: "velo.example.ch"),
            VaultEntry(title: "Notiz «ohne» Website", notes: "Zeile 1\nZeile 2 mit Umlauten äöü"),
            VaultEntry(title: "Bank", username: "kunde-1", password: "Kette+Sattel-77", url: "https://bank.example.ch",
                       totp: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
            VaultEntry(title: "Alt", username: "x", password: "passwort123", url: "https://alt.example.ch"),
        ]
    }
}

enum SaatErzeugung {
    struct Plan {
        let name: String
        let stufe: SecurityLevel
        let credLaenge: Int
        /// Faktoren nur für Einträge einrichten (ohne sie zum Öffnen zu verlangen).
        let eintragsFaktoren: Bool
        /// Schutz pro Eintrag (Index in den Beispiel-Einträgen).
        let schutz: [Int: EntryProtection]
        /// Selbstvernichtung einrichten (nur Stufe 4/5).
        var vernichtung: VernichtungsPlan? = nil
    }

    /// Selbstvernichtung einer Saat (§23): Einstellungen, Vernichtungs-Passwort, zusätzliche Einträge (vernichtbar
    /// oder nicht) und was danach noch geschieht (Fehlversuche bis kurz vor die Schwelle, schon vernichtet).
    struct VernichtungsPlan {
        enum Nachher {
            case nichts
            /// So viele falsche Passwörter (Zähler kurz vor der Schwelle).
            case fehlversuche(Int)
            /// Totmann-Schalter nach so vielen Tagen geprüft (vernichtet).
            case totmann(tage: Double)
            /// Mit dem Vernichtungs-Passwort entsperrt (vernichtet, `rekeyPending`).
            case vernichtungsPasswort
        }

        struct Zusatz {
            let titel: String
            let schutz: EntryProtection
            let vernichtbar: Bool
        }

        let einstellungen: DestructionSettings
        let passwort: String?
        let zusatz: [Zusatz]
        /// Nummer der Saat (Kennungen und Schlüsselmaterial, s. `SaatWerte`).
        let nummer: Int
        let nachher: Nachher
        /// Eigenes Master-Passwort (sonst `SaatWerte.passwort`).
        var masterPasswort: String? = nil

        var vKeyID: UUID { SaatWerte.vKeyID(nummer) }

        var vVernichtet: Bool {
            switch nachher {
            case .totmann, .vernichtungsPasswort: return true
            case .nichts, .fehlversuche: return false
            }
        }
    }

    static func z(_ t: String, _ s: EntryProtection, _ v: Bool) -> VernichtungsPlan.Zusatz {
        VernichtungsPlan.Zusatz(titel: t, schutz: s, vernichtbar: v)
    }

    static let plaene: [Plan] = [
        Plan(name: "t1", stufe: .standard, credLaenge: 48, eintragsFaktoren: false, schutz: [:]),
        Plan(name: "t1e", stufe: .standard, credLaenge: 48, eintragsFaktoren: true,
             schutz: [0: .fingerabdruck, 1: .maximal, 3: .festung]),
        Plan(name: "t2", stufe: .erhoeht, credLaenge: 48, eintragsFaktoren: false, schutz: [0: .fingerabdruck, 1: .hoch]),
        Plan(name: "t3", stufe: .hoch, credLaenge: 48, eintragsFaktoren: false, schutz: [3: .hoch]),
        Plan(name: "t4", stufe: .maximal, credLaenge: 48, eintragsFaktoren: false, schutz: [0: .maximal, 4: .fingerabdruck]),
        Plan(name: "t5", stufe: .festung, credLaenge: 16, eintragsFaktoren: false,
             schutz: [0: .festung, 1: .maximal, 3: .fingerabdruck]),
        Plan(name: "t5l", stufe: .festung, credLaenge: 1024, eintragsFaktoren: false, schutz: [2: .festung]),
        // Selbstvernichtung (§23): alle drei Auslöser eingerichtet, vernichtbare neben nicht vernichtbaren Einträgen.
        Plan(name: "v4", stufe: .maximal, credLaenge: 48, eintragsFaktoren: false,
             schutz: [0: .maximal, 1: .hoch, 3: .fingerabdruck],
             vernichtung: VernichtungsPlan(
                 einstellungen: DestructionSettings(deadmanDays: 30, maxFailedAttempts: 20, duressEnabled: true),
                 passwort: "w=8:Q.+F3mYWO6#O8@s~@~4_q:Zwang",
                 zusatz: [z("Tresorraum", .maximal, true), z("Depot", .maximal, true), z("Ausweis", .maximal, false)],
                 nummer: 1, nachher: .nichts)),
        Plan(name: "v5", stufe: .festung, credLaenge: 48, eintragsFaktoren: false,
             schutz: [0: .festung, 3: .fingerabdruck],
             vernichtung: VernichtungsPlan(
                 einstellungen: DestructionSettings(deadmanDays: 7, maxFailedAttempts: nil, duressEnabled: true),
                 passwort: "x_b,DV_>9Ml^Zx./m936@ziw:bNot",
                 zusatz: [z("Tresorraum", .festung, true), z("Depot", .maximal, true), z("Ausweis", .festung, false)],
                 nummer: 2, nachher: .nichts, masterPasswort: SaatWerte.passwort2)),
        // Zähler kurz vor der Schwelle (9 von 10), ohne Vernichtungs-Passwort.
        Plan(name: "v4z", stufe: .maximal, credLaenge: 48, eintragsFaktoren: false, schutz: [0: .maximal],
             vernichtung: VernichtungsPlan(
                 einstellungen: DestructionSettings(deadmanDays: nil, maxFailedAttempts: 10, duressEnabled: false),
                 passwort: nil,
                 zusatz: [z("Tresorraum", .maximal, true), z("Ausweis", .maximal, false)],
                 nummer: 3, nachher: .fehlversuche(9))),
        // Schon vernichtet: über den Totmann-Schalter bzw. über das Vernichtungs-Passwort (dann `rekeyPending`).
        Plan(name: "v4t", stufe: .maximal, credLaenge: 48, eintragsFaktoren: false, schutz: [3: .fingerabdruck],
             vernichtung: VernichtungsPlan(
                 einstellungen: DestructionSettings(deadmanDays: 7, maxFailedAttempts: nil, duressEnabled: true),
                 passwort: "R7#kq!Lm2@Vz9^Tx4&Pw8*NcHaus",
                 zusatz: [z("Depot", .maximal, true), z("Ausweis", .maximal, false)],
                 nummer: 4, nachher: .totmann(tage: 8))),
        Plan(name: "v5x", stufe: .festung, credLaenge: 48, eintragsFaktoren: false, schutz: [0: .festung],
             vernichtung: VernichtungsPlan(
                 einstellungen: DestructionSettings(deadmanDays: 365, maxFailedAttempts: 50, duressEnabled: true),
                 passwort: "Hj3$Qe7!Ws1@Xd5#Fr9%Gt2Kiesel",
                 zusatz: [z("Tresorraum", .festung, true), z("Depot", .maximal, true), z("Ausweis", .festung, false)],
                 nummer: 5, nachher: .vernichtungsPasswort)),
    ]

    /// Saat-Tresore: einmal erzeugt (Temp-Ordner, Testschalter-KDF, In-Memory-RollbackGuard, danach gelöscht),
    /// dann im Arbeitsordner aufbewahrt, damit Läufe mit derselben Saat-Zahl reproduzierbar bleiben.
    static func laden(_ u: Umgebung, neu: Bool) throws -> [TresorSaat] {
        let ordner = u.arbeitsordner.appendingPathComponent("saat", isDirectory: true)
        try FileManager.default.createDirectory(at: ordner, withIntermediateDirectories: true)
        var out: [TresorSaat] = []
        for plan in plaene {
            let datei = ordner.appendingPathComponent(plan.name + ".siegel")
            let info = ordner.appendingPathComponent(plan.name + ".json")
            let umgebung = ordner.appendingPathComponent(plan.name + ".umgebung", isDirectory: true)
            let fehlt = !FileManager.default.fileExists(atPath: datei.path) || !FileManager.default.fileExists(atPath: info.path)
                || (plan.vernichtung != nil && !FileManager.default.fileExists(atPath: umgebung.path))
            if neu || fehlt {
                let (bytes, code, teile, dateien) = try erzeuge(plan)
                try Data(bytes).write(to: datei)
                let obj: [String: Any] = ["code": code ?? "", "teile": teile]
                try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]).write(to: info)
                if let dateien { try UmgebungsDateien.schreiben(dateien, nach: umgebung) }
            }
            let bytes = [UInt8](try Data(contentsOf: datei))
            let obj = try JSONSerialization.jsonObject(with: Data(contentsOf: info)) as? [String: Any] ?? [:]
            let code = (obj["code"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            let teile = obj["teile"] as? [String] ?? []
            let s = try TresorSaat(name: plan.name, bytes: bytes,
                                   passwort: plan.vernichtung?.masterPasswort ?? SaatWerte.passwort,
                                   faktoren: SaatWerte.alleFaktoren, code: code, teile: teile,
                                   limits: .testing, echtesProfil: false)
            if let vp = plan.vernichtung {
                let dateien = try UmgebungsDateien.lesen(umgebung)
                guard dateien[VaultStore.vaultFileName] == bytes else {
                    throw Fund("saat", "Umgebung der Saat \(plan.name) passt nicht zur Tresordatei (--neue-saat)")
                }
                s.vernichtung = VernichtungsSaat(plan: vp, stufe: plan.stufe, dateien: dateien)
            }
            out.append(s)
        }
        out.append(try v1Testdatei(ordner: ordner, neu: neu))
        out.append(contentsOf: try fixtures(u))
        return out
    }

    /// Über die öffentliche Schnittstelle wie in den Kern-Tests (KernStufen.change). Vernichtungs-Saaten mit fester
    /// Uhr (`SaatWerte.zeitpunkt`) und dem ganzen Tresorordner (Tresordatei, Sicherungen, Hardware-Ordner).
    static func erzeuge(_ plan: Plan) throws
        -> (bytes: [UInt8], code: String?, teile: [String], umgebung: [String: [UInt8]]?) {
        if plan.vernichtung != nil {
            return try TestHooks.$now.withValue(SaatWerte.zeitpunkt) { try erzeugeKern(plan) }
        }
        return try erzeugeKern(plan)
    }

    private static func erzeugeKern(_ plan: Plan) throws
        -> (bytes: [UInt8], code: String?, teile: [String], umgebung: [String: [UInt8]]?) {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("siegelfuzz-saat-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        let store = VaultStore(directory: tmp.appendingPathComponent("Siegel", isDirectory: true),
                               rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        let pw = plan.vernichtung?.masterPasswort ?? SaatWerte.passwort
        let schluessel = SaatWerte.Schluessel.fuer(plan)
        let (vault, pending) = try store.create(masterPassword: pw, kdf: SaatWerte.testKDF)
        try vault.commitRecovery(pending, confirmation: pending.confirmationGroups.map { pending.code.groups[$0] })
        var code: String? = pending.code.formatted
        var teile: [String] = []
        for e in SaatWerte.beispielEintraege() { try vault.upsert(e) }
        // Verlauf: Passwortwechsel im zweiten Eintrag; ein gelöschter Eintrag
        if var e = vault.entries.first(where: { $0.title == "Velo-Club" }) {
            e.password = "Rad&Weg-2026"
            try vault.upsert(e)
        }
        try vault.upsert(VaultEntry(title: "Gelöscht", username: "weg", password: "Weg-damit-1"))
        if let id = vault.entries.first(where: { $0.title == "Gelöscht" })?.id { try vault.delete(id: id) }

        if plan.stufe != .standard {
            var neu: PendingRecovery?
            if plan.stufe.recoveryScheme != .single {
                neu = try vault.prepareRecovery(masterPassword: pw, factors: FactorSecrets(), scheme: plan.stufe.recoveryScheme)
            }
            let bestaetigung = neu.map { p in
                p.shareConfirmationGroups.enumerated().map { k, g in p.shares[k].groups[g] }
            } ?? []
            try vault.changeSecurityLevel(to: plan.stufe, masterPassword: pw, currentFactors: FactorSecrets(),
                                          newFactors: SaatWerte.material(plan.stufe.factors, credLaenge: plan.credLaenge,
                                                                         schluessel: schluessel),
                                          recovery: neu, recoveryConfirmation: bestaetigung)
            if let neu {
                code = nil
                teile = neu.shares.map(\.formatted)
            }
        }
        if plan.eintragsFaktoren {
            try vault.enrollFactors(SaatWerte.material([.card, .securityKey], credLaenge: plan.credLaenge),
                                    masterPassword: pw, currentFactors: SaatWerte.alleFaktoren)
        }
        let eintraege = vault.entries
        let reihenfolge = SaatWerte.beispielEintraege().map(\.title)
        for (i, schutz) in plan.schutz.sorted(by: { $0.key < $1.key }) {
            guard i < reihenfolge.count, let e = eintraege.first(where: { $0.title == reihenfolge[i] }) else { continue }
            try vault.setProtection(schutz, id: e.id,
                                    secrets: EntrySecrets(password: e.password, notes: e.notes, totp: e.totp,
                                                          history: e.history))
        }
        guard let vp = plan.vernichtung else {
            let bytes = try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes)
            vault.lock()
            return (bytes, code, teile, nil)
        }
        try vernichtungEinrichten(vp, stufe: plan.stufe, vault: vault, store: store, schluessel: schluessel, passwort: pw)
        let bytes = try FileIO.read(store.vaultURL, maxSize: FileFormat.maxFileBytes)
        return (bytes, code, teile, try UmgebungsDateien.einsammeln(store.directory))
    }

    /// Selbstvernichtung einrichten (§23.3, async-Weg mit Eintrags-Faktoren aus Dateien) und danach den Plan
    /// abschliessen (Fehlversuche, Totmann, Vernichtungs-Passwort). Der Tresor ist danach gesperrt.
    static func vernichtungEinrichten(_ vp: VernichtungsPlan, stufe: SecurityLevel, vault: UnlockedVault,
                                      store: VaultStore, schluessel: SaatWerte.Schluessel, passwort: String) throws {
        let hw = store.hardwareDirectory
        try FileManager.default.createDirectory(at: hw, withIntermediateDirectories: true)
        try Data(SaatWerte.oeffnungRoh).write(to: hw.appendingPathComponent(SaatWerte.hwName(schluessel.seKeyID)))
        try Data(schluessel.eintragRoh).write(to: hw.appendingPathComponent(SaatWerte.hwName(schluessel.entryKeyID)))
        try Data(SaatWerte.vRoh(vp.nummer)).write(to: hw.appendingPathComponent(SaatWerte.hwName(vp.vKeyID)))
        for z in vp.zusatz {
            var e = VaultEntry(title: z.titel, username: z.titel.lowercased() + "@example.ch",
                               password: "PW-" + z.titel + "-Fuzz-42!", url: "https://" + z.titel.lowercased() + ".example.ch",
                               notes: "Notiz zu " + z.titel, totp: "otpauth://totp/" + z.titel + "?secret=JBSWY3DPEHPK3PXP",
                               protection: z.schutz)
            e.history = [PasswordHistoryItem(password: "Alt-" + z.titel, changed: Date(timeIntervalSince1970: 1_790_000_000))]
            try vault.upsert(e)
        }
        let titel = Set(vp.zusatz.filter(\.vernichtbar).map(\.titel))
        let ids = Set(vault.entries.filter { titel.contains($0.title) }.map(\.id))
        guard ids.count == titel.count else { throw Fund("saat", "vernichtbare Einträge nicht gefunden") }
        let faktoren = SaatWerte.faktoren(stufe.factors)
        let anbieter = DateiAnbieter(hardware: hw)
        let enrollment = EntryKeyEnrollment(keyID: vp.vKeyID, publicKey: SaatWerte.oeffentlich(SaatWerte.vRoh(vp.nummer)))
        let jetzt = TestHooks.now
        _ = try synchron {
            try await TestHooks.$now.withValue(jetzt) {
                try await vault.configureDestruction(vp.einstellungen, duressPassword: vp.passwort, destructible: ids,
                                                     masterPassword: passwort, factors: faktoren,
                                                     vKey: enrollment, entryFactors: anbieter)
            }
        }
        guard vault.destructibleEntries == ids else { throw Fund("saat", "Markierung der Saat nicht übernommen") }
        vault.lock()
        switch vp.nachher {
        case .nichts:
            break
        case let .fehlversuche(n):
            for _ in 0..<n {
                do {
                    _ = try store.unlock(masterPassword: "Falsch-" + passwort, factors: faktoren)
                    throw Fund("saat", "falsches Passwort öffnet")
                } catch SiegelError.wrongPassword {}
            }
            guard store.destructionStatus().failedAttempts == n else { throw Fund("saat", "Zähler der Saat falsch") }
        case let .totmann(tage):
            guard try store.checkDeadman(now: SaatWerte.zeitpunkt.addingTimeInterval(tage * 86_400)) else {
                throw Fund("saat", "Totmann-Schalter der Saat hat nicht ausgelöst")
            }
        case .vernichtungsPasswort:
            guard let pw = vp.passwort else { throw Fund("saat", "Plan ohne Vernichtungs-Passwort") }
            let v: UnlockedVault
            switch try store.unlock(masterPassword: pw, factors: faktoren) {
            case let .unlocked(x): v = x
            case let .rollbackSuspected(x, _, _): v = x
            }
            guard v.isDuressSession else { throw Fund("saat", "Vernichtungs-Passwort öffnet keine Vernichtungs-Sitzung") }
            v.lock()
        }
        let status = store.destructionStatus()
        guard (status.destroyedTrigger != nil) == vp.vVernichtet,
              FileManager.default.fileExists(atPath: hw.appendingPathComponent(SaatWerte.hwName(vp.vKeyID)).path)
                == !vp.vVernichtet else {
            throw Fund("saat", "Vernichtungs-Zustand der Saat stimmt nicht mit dem Plan überein")
        }
    }

    /// Kleine v1-Datei im Speicher (Testschalter-KDF), wie die Migrations-Tests sie bauen.
    static func v1Testdatei(ordner: URL, neu: Bool) throws -> TresorSaat {
        let datei = ordner.appendingPathComponent("v1t.siegel")
        let info = ordner.appendingPathComponent("v1t.json")
        if neu || !FileManager.default.fileExists(atPath: datei.path) || !FileManager.default.fileExists(atPath: info.path) {
            let pw = try PasswordNormalizer.secureBytes(SaatWerte.passwort)
            let vaultID = VaultHeader.bytes(of: UUID())
            let r = try SecureBytes.random(count: RecoveryKEM.rBytes)
            let pk = try RecoveryKEM.derivePublicKeys(r: r, vaultID: vaultID)
            let header = VaultHeader(v1: vaultID, kdf: SaatWerte.testKDF, salt: randomBytes(KDF.saltBytes), pk: pk)
            let kek = try KDF.deriveKEK(password: pw, salt: header.salt, params: header.kdf, limits: .testing)
            let dek = try SecureBytes.random(count: AEAD.keyBytes)
            let slots = try VaultCrypto.makeSlots(header: header, kekPw: kek, dek: dek)
            var content = VaultContent.empty(now: Date(timeIntervalSince1970: 1_792_000_000))
            content.entries = SaatWerte.beispielEintraege().map { e in
                var x = e
                x.totp = ""
                x.created = Date(timeIntervalSince1970: 1_791_000_000)
                x.modified = x.created
                return x
            }
            content.recoveryConfirmedAt = content.savedAt
            let (padded, _) = try PayloadCodec.encode(content, legacyV1: true)
            let ad = VaultFile.payloadAD(header: header, slots: slots, generation: 3)
            let sealed = try AEAD.seal(key: dek, plaintext: padded, ad: ad)
            let file = VaultFile(header: header, slots: slots, generation: 3, nonce: sealed.nonce,
                                 ciphertext: sealed.ciphertext)
            try Data(file.serialize()).write(to: datei)
            let obj: [String: Any] = ["code": try RecoveryCodeCodec.format(r: r), "teile": [String]()]
            try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]).write(to: info)
        }
        let obj = try JSONSerialization.jsonObject(with: Data(contentsOf: info)) as? [String: Any] ?? [:]
        return try TresorSaat(name: "v1t", bytes: [UInt8](try Data(contentsOf: datei)), passwort: SaatWerte.passwort,
                              faktoren: FactorSecrets(), code: obj["code"] as? String, teile: [], limits: .testing,
                              echtesProfil: false)
    }

    /// Die eingefrorenen Beispieldateien (Tests/SiegelCoreTests/Fixtures/README.md), echtes Profil 256 MiB.
    static func fixtures(_ u: Umgebung) throws -> [TresorSaat] {
        let v1 = [UInt8](try Data(contentsOf: u.fixtures.appendingPathComponent("v1_beispiel.siegel")))
        let v2 = [UInt8](try Data(contentsOf: u.fixtures.appendingPathComponent("v2_beispiel.siegel")))
        let f2 = FactorSecrets(secureEnclave: SaatWerte.wert(0x11), card: SaatWerte.wert(0x22),
                               securityKey: SaatWerte.wert(0x33))
        return [
            try TresorSaat(name: "fx1", bytes: v1, passwort: "7:etFa_0+Isq#jQ0oeTb8nWKFM*9", faktoren: FactorSecrets(),
                           code: "NHZZD-BYYYZ-ZYMNR-W0S31-BZK7X-0S860-H7KZ4-YEBE7-7JNMC-G8367-YZ2N0", teile: [],
                           limits: .production, echtesProfil: true),
            try TresorSaat(name: "fx2", bytes: v2, passwort: "6Bn__S?ZC37umQe_9A!^6K!9_nNk", faktoren: f2, code: nil,
                           teile: ["04A6Z-0CJEQ-E7T55-1KVCB-7K5WQ-E3V63-2BGH5-P3KM3-RQF38-40TW4-Y1XQ2-N",
                                   "08F19-MM81R-FAMDM-D44N1-N36HJ-M1QKG-CG8GG-G7JF2-Q81KE-637EJ-35EMW-0",
                                   "0CC3V-RVQ4Y-MYEA3-0QP6Q-TH83H-XZKYW-YS0G3-X8F9M-CS43D-TAC0W-CSJTH-6"],
                           limits: .production, echtesProfil: true),
        ]
    }

    /// Selbsttest: jede Saat öffnet über Passwort (+ Faktoren) und Notfallweg; merkt DEK und Klartext-JSON.
    static func selbsttest(_ saaten: [TresorSaat]) throws {
        for s in saaten {
            let opened = try VaultCrypto.openWithPassword(s.datei, password: s.pw, factors: s.faktoren, limits: s.limits,
                                                          cache: s.cache)
            _ = try VaultStore.unsealed(try VaultCrypto.openWithRecovery(s.datei, r: s.r), r: s.r)
            s.dek = opened.dek
            s.inhalt = opened.content
            guard let padded = AEAD.open(key: opened.dek, nonce: s.datei.nonce, ciphertext: s.datei.ciphertext,
                                         ad: s.datei.payloadAD),
                  let text = PayloadCodec.jsonStringForTesting(padded) else {
                throw Fund("saat", "Klartext der Saat \(s.name) nicht lesbar")
            }
            s.json = Array(text.utf8)
        }
    }

    /// §23.1 an den Sicherungen einer Vernichtungs-Saat: Ältere Sicherungen enthielten die vernichtbaren Einträge
    /// noch mit Notfall-Umschlag; das Markieren entfernt sie (`purgeBackups`). Jede Sicherung im Tresorordner wird mit
    /// dem Notfallschlüssel R geöffnet und entsiegelt: Keine vernichtbare Kennung ist darin lesbar, und die
    /// Einstellungen der Selbstvernichtung fehlen oder sind dieselben wie in der Tresordatei. Braucht `selbsttest`.
    static func sicherungenPruefen(_ s: TresorSaat) throws {
        guard let vs = s.vernichtung, let inhalt = s.inhalt else { return }
        let vernichtbar = Set(inhalt.destructible.keys)
        let praefix = VaultStore.backupFolderName + "/"
        for (rel, bytes) in vs.dateien.sorted(by: { $0.key < $1.key }) where rel.hasPrefix(praefix) {
            // Sicherungen mit einem früheren Notfallkit (vor dem Stufenwechsel) öffnet dieser Code nicht.
            guard let f = try? VaultFile.parse(bytes), RecoveryKEM.matches(r: s.r, vaultID: f.header.vaultID,
                                                                           expected: f.header.pk) else { continue }
            let (lesbar, destruction) = try notfallLesbar(bytes, r: s.r)
            if let id = lesbar.intersection(vernichtbar).first {
                throw Fund("sicherung-notfall", "Saat \(s.name): Sicherung \(rel.split(separator: "/").last ?? "") liefert "
                           + "mit dem Notfallcode den vernichtbaren Eintrag \(id.uuidString.prefix(8)) (§23.1)")
            }
            guard destruction == nil || destruction == inhalt.destruction else {
                throw Fund("sicherung-notfall", "Saat \(s.name): Sicherung mit anderer Selbstvernichtung")
            }
        }
    }

    /// Kennungen, die eine Tresordatei über den Notfallweg (Code R, Entsiegeln wie `recover`) liefert, und ihre
    /// Selbstvernichtung vor dem Entsiegeln.
    static func notfallLesbar(_ bytes: [UInt8], r: SecureBytes) throws -> (Set<UUID>, DestructionConfig?) {
        let file = try VaultFile.parse(bytes)
        let roh = try VaultCrypto.openWithRecovery(file, r: r)
        let offen = try VaultStore.unsealed(roh, r: r)
        return (Set(offen.content.entries.map(\.id)), roh.content.destruction)
    }
}

// MARK: - Selbstvernichtung: Saat-Umgebung, Eintrags-Faktoren aus Dateien, async → sync

/// Vernichtungs-Teil einer Saat: Plan und der ganze Tresorordner (relativer Pfad → Bytes) nach der Erzeugung.
struct VernichtungsSaat {
    let plan: SaatErzeugung.VernichtungsPlan
    let stufe: SecurityLevel
    let dateien: [String: [UInt8]]

    var hardware: String { VaultStore.hardwareFolderName }
    func pfad(_ id: UUID) -> String { hardware + "/" + SaatWerte.hwName(id) }
    var zustand: [UInt8]? { dateien[hardware + "/" + DestructionState.fileName] }
}

/// Tresorordner als Dateiliste (nur reguläre Dateien, ohne Temp-Reste).
enum UmgebungsDateien {
    static func einsammeln(_ wurzel: URL) throws -> [String: [UInt8]] {
        var out: [String: [UInt8]] = [:]
        let basis = wurzel.standardizedFileURL.path
        guard let it = FileManager.default.enumerator(at: wurzel, includingPropertiesForKeys: [.isRegularFileKey]) else {
            return out
        }
        for case let u as URL in it {
            guard (try? u.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true else { continue }
            let p = u.standardizedFileURL.path
            guard p.hasPrefix(basis + "/") else { continue }
            let rel = String(p.dropFirst(basis.count + 1))
            if rel.split(separator: "/").last?.hasPrefix(".") == true { continue }
            out[rel] = [UInt8](try Data(contentsOf: u))
        }
        return out
    }

    static func schreiben(_ dateien: [String: [UInt8]], nach ordner: URL) throws {
        try? FileManager.default.removeItem(at: ordner)
        for (rel, bytes) in dateien {
            let ziel = ordner.appendingPathComponent(rel)
            try FileManager.default.createDirectory(at: ziel.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(bytes).write(to: ziel)
        }
    }

    static func lesen(_ ordner: URL) throws -> [String: [UInt8]] { try einsammeln(ordner) }
}

/// Eintrags-Faktoren wie in den Kern-Tests (`VernichtungsProvider`): Software-P256 statt Secure Enclave, der private
/// Schlüssel liegt roh (32 B) in `Hardware/<keyID>.siegelhw` – fehlt die Datei, ist der Schlüssel weg
/// (`factorUnavailable(.secureEnclave)` wie beim echten Secure Enclave ohne Blob). Karte und Sicherheitsschlüssel:
/// feste Testwerte. Keine Biometrie, keine Dialoge.
final class DateiAnbieter: EntryFactorProvider, @unchecked Sendable {
    let hardware: URL
    let vKeyID: UUID?
    private let lock = NSLock()
    private var vAufrufe = 0
    private var seAufrufe = 0

    init(hardware: URL, vKeyID: UUID? = nil) {
        self.hardware = hardware
        self.vKeyID = vKeyID
    }

    var vAnzahl: Int { lock.withLock { vAufrufe } }
    var seAnzahl: Int { lock.withLock { seAufrufe } }

    func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
        lock.withLock {
            seAufrufe += 1
            if keyID == vKeyID { vAufrufe += 1 }
        }
        let url = hardware.appendingPathComponent(SaatWerte.hwName(keyID))
        guard let raw = try? Data(contentsOf: url), raw.count == 32,
              let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw) else {
            throw SiegelError.factorUnavailable(.secureEnclave)
        }
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)
        let shared = try key.sharedSecretFromKeyAgreement(with: pub)
        return try shared.withUnsafeBytes { try FactorSecret(copying: Array($0)) }
    }

    func cardSecret() async throws -> FactorSecret { SaatWerte.q }

    func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret { SaatWerte.fidoEintrag }
}

final class ErgebnisKasten<T>: @unchecked Sendable {
    var ergebnis: Result<T, Error>?
}

/// Führt eine async-Funktion synchron aus (der Fuzzer läuft auf einem eigenen Thread, nie auf dem Main-Thread).
/// TaskLocal-Testschalter gelten im neuen Task nicht: wer sie braucht, setzt sie in `body` erneut.
func synchron<T>(_ body: @escaping @Sendable () async throws -> T) throws -> T {
    let kasten = ErgebnisKasten<T>()
    let fertig = DispatchSemaphore(value: 0)
    Task.detached {
        do {
            kasten.ergebnis = .success(try await body())
        } catch {
            kasten.ergebnis = .failure(error)
        }
        fertig.signal()
    }
    fertig.wait()
    guard let r = kasten.ergebnis else { throw SiegelError.io("fuzz.synchron") }
    return try r.get()
}
#endif
