#if DEBUG
import Clibsodium
import CryptoKit
import Foundation
@testable import SiegelCore

/// Ziel „inhalt“: das entschlüsselte Inhalts-JSON (SPEC §3, §16, §17). Erreichbar nur mit dem richtigen DEK, darum
/// verschlüsselt der Fuzzer die mutierten Inhalte selbst mit dem DEK der Saat und spielt den ganzen Weg nach dem
/// Entsperren durch (Datei bauen → lesen → Passwortweg → `UnlockedVault` → Liste, Bericht → Notfallweg mit Entsiegeln).
///
/// Rahmung: Byte 0 = Saat, Byte 1 = Polster-Art (0 korrekt, 1 ohne, 2 kaputt, 3 übergross), danach das JSON.
/// Invarianten: kein Absturz/Hänger; Fehler nur `corruptFile`; was sich lesen lässt, lässt sich auch wieder
/// schreiben und ergibt beim erneuten Lesen denselben Inhalt; direkter Weg und Dateiweg sind sich einig.
final class ZielInhalt: FuzzZiel {
    let name = "inhalt"
    let zeitlimit = 20.0
    private var saaten: [TresorSaat] = []
    private let korpus = Korpus()
    private var z = Zufall(saat: 2)
    private var store: VaultStore?
    private var jsonSaaten: [Any] = []
    /// Vernichtungs-Saaten: Kennungen der Schlüssel-Dateien (V, Eintrags- und Entsperr-SE-Schlüssel) für gezielte
    /// Mutationen der Ablage-Kennung bzw. von V.
    private var schluesselKennungen: [Int: [UUID]] = [:]
    private var wurzel: URL?
    private var zaehler = 0
    var zusatz: [String: Int] = [:]
    var neueSaat = false

    func vorbereiten(_ u: Umgebung) throws {
        saaten = try SaatErzeugung.laden(u, neu: neueSaat)
        try SaatErzeugung.selbsttest(saaten)
        store = VaultStore(directory: u.arbeitsordner.appendingPathComponent("nie-geschrieben", isDirectory: true),
                           rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        wurzel = FileManager.default.temporaryDirectory
            .appendingPathComponent("siegelfuzz-inhalt-\(getpid())", isDirectory: true)
        let wurzelPfad = wurzel?.path ?? ""
        _ = atexit_b { _ = try? FileManager.default.removeItem(atPath: wurzelPfad) }
        for (i, s) in saaten.enumerated() {
            korpus.saatAufnehmen([UInt8(i), 0] + s.json)
            jsonSaaten.append(try JSONSerialization.jsonObject(with: Data(s.json), options: [.fragmentsAllowed]))
            if s.vernichtung != nil, let c = s.inhalt {
                schluesselKennungen[i] = [c.destruction?.vKey?.keyID, c.entryFactors.secureEnclave?.keyID,
                                          s.header.factorFields.seKeyID].compactMap { $0 }
            }
        }
        // Selbsttest: unveränderte Saat besteht den ganzen Weg
        for i in saaten.indices {
            let code = try pruefe([UInt8(i), 0] + saaten[i].json)
            guard code.hasPrefix("ok") else { throw Fund("saat", "Inhalt der Saat \(saaten[i].name): \(code)") }
        }
    }

    func aufnehmen(_ e: [UInt8]) { korpus.aufnehmen(e, &z) }

    // MARK: Erzeugen

    func naechste(_ z: inout Zufall) -> [UInt8] {
        let basis = korpus.waehle(&z)
        let k = basis[0]
        var json = Array(basis.dropFirst(2))
        var polster = UInt8(0)
        if z.chance(0.04) { polster = UInt8(z.int(1...3)) }
        if let ids = schluesselKennungen[Int(k) % max(1, saaten.count)], z.chance(0.06),
           var baum = (try? JSONSerialization.jsonObject(with: Data(json), options: [])) as? [String: Any],
           var d = baum["destruction"] as? [String: Any] {
            // Gezielt: Ablage-Kennung bzw. V heisst wie eine Schlüssel-Datei (Tiefenverteidigung, §23).
            if z.chance(0.6), var x = d["duress"] as? [String: Any] {
                x["fileID"] = z.pick(ids).uuidString
                d["duress"] = x
            } else if var x = d["vKey"] as? [String: Any] {
                x["keyID"] = z.pick(ids).uuidString
                d["vKey"] = x
            }
            baum["destruction"] = d
            if let neu = try? JSONSerialization.data(withJSONObject: baum, options: [.sortedKeys]) { json = [UInt8](neu) }
        } else if z.chance(0.15) {
            json = Mutator.bytes(json, &z, maxLaenge: 4 << 20)
        } else if let baum = try? JSONSerialization.jsonObject(with: Data(json), options: [.fragmentsAllowed]) {
            var neu = baum
            for _ in 0..<z.int(1...3) { neu = mutiereBaum(neu, tiefe: 0, &z) }
            if let d = try? JSONSerialization.data(withJSONObject: neu, options: [.sortedKeys, .fragmentsAllowed]) {
                json = [UInt8](d)
            }
        } else {
            json = Mutator.bytes(json, &z, maxLaenge: 4 << 20)
        }
        return [k, polster] + json
    }

    private func zufallsWert(_ z: inout Zufall) -> Any {
        switch z.int(16) {
        case 0: return NSNull()
        case 1: return z.chance(0.5)
        case 2: return z.pick([0, -1, 1, 2, 3, 4, 5, 6, 255, 256, Int.max, Int.min, 1 << 53])
        case 3: return z.pick([0.5, -0.0, 1e300, -1e300, 1e-320, 1_792_000_000.25, 253_402_300_800.0, -62_135_596_800.0])
        case 4: return ""
        case 5: return String(repeating: z.pick(["a", "ä", "\"", "\\", "\u{0}", "😀"]), count: z.pick([1, 255, 2049, 4097, 300_000]))
        case 6:
            let n = z.pick([0, 1, 4, 15, 16, 17, 31, 32, 33, 64, 65, 66, 72, 1567, 1568, 1569])
            return Data(z.bytes(n)).base64EncodedString()
        case 7: return z.chance(0.5) ? z.uuid().uuidString : "nicht-uuid"
        case 8: return [Any]()
        case 9: return [String: Any]()
        case 10: return "==="
        case 11: return Data(z.bytes(z.int(0...40))).base64EncodedString().replacingOccurrences(of: "=", with: "")
        default:
            // Teilbaum aus einer Saat
            return beliebigerTeilbaum(z.pick(jsonSaaten), &z) ?? NSNull()
        }
    }

    private func beliebigerTeilbaum(_ v: Any, _ z: inout Zufall) -> Any? {
        var cur: Any = v
        for _ in 0..<z.int(1...6) {
            if let d = cur as? [String: Any], !d.isEmpty {
                cur = d[z.pick(Array(d.keys))] ?? NSNull()
            } else if let a = cur as? [Any], !a.isEmpty {
                cur = z.pick(a)
            } else {
                break
            }
        }
        return cur
    }

    private func mutiereBaum(_ v: Any, tiefe: Int, _ z: inout Zufall) -> Any {
        // Behälter: fast immer tiefer gehen; selten Behälter-Operationen (sonst endet fast alles als Typfehler)
        if var d = v as? [String: Any], !d.isEmpty, tiefe < 12 {
            if z.chance(0.03) { return z.chance(0.5) ? zufallsWert(&z) : (beliebigerTeilbaum(z.pick(jsonSaaten), &z) ?? NSNull()) }
            let schluessel = z.pick(Array(d.keys).sorted())
            switch z.int(40) {
            case 0: d.removeValue(forKey: schluessel)
            case 1: d[schluessel] = zufallsWert(&z)
            case 2: d[schluessel + "x"] = d[schluessel]
            case 3: d[schluessel] = NSNull()
            default: d[schluessel] = mutiereBaum(d[schluessel] ?? NSNull(), tiefe: tiefe + 1, &z)
            }
            return d
        }
        if var a = v as? [Any], tiefe < 12 {
            if a.isEmpty {
                // leere Liste: ein Element aus einer Saat (z. B. Eintrag, Gruppe, Verlauf)
                a.append(beliebigerTeilbaum(z.pick(jsonSaaten), &z) ?? zufallsWert(&z))
                return a
            }
            if z.chance(0.03) { return zufallsWert(&z) }
            let i = z.int(a.count)
            switch z.int(12) {
            case 0: a.remove(at: i)
            case 1: a.insert(a[i], at: i)          // doppelte Kennungen, doppelte Gruppen
            case 2: a.swapAt(i, z.int(a.count))
            case 3: a.append(beliebigerTeilbaum(z.pick(jsonSaaten), &z) ?? zufallsWert(&z))
            default: a[i] = mutiereBaum(a[i], tiefe: tiefe + 1, &z)
            }
            return a
        }
        // Blätter: meist typtreu ändern (sonst endet fast alles als Typfehler in „payload.json“)
        if let s = v as? String {
            switch z.int(10) {
            case 0, 1: return Zeichen.mutieren(s, &z)
            case 2: return String(s.prefix(z.int(s.count + 1)))
            case 3: return s + s
            case 4, 5:
                let n = z.pick([0, 1, 15, 16, 17, 31, 32, 33, 64, 65, 66, 72, 1567, 1568, 1569])
                return Data(z.bytes(n)).base64EncodedString()
            case 6:
                // Base64 gleicher Länge, anderer Inhalt
                if let d = Data(base64Encoded: s) { return Data(z.bytes(d.count)).base64EncodedString() }
                return z.uuid().uuidString
            case 7: return z.chance(0.5) ? z.uuid().uuidString : s.lowercased()
            default: return zufallsWert(&z)
            }
        }
        if let n = v as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() {
            return z.chance(0.8) ? !n.boolValue : zufallsWert(&z)
        }
        if let n = v as? NSNumber {
            switch z.int(6) {
            case 0, 1: return n.doubleValue + Double(z.int(-2...2))
            case 2: return n.int64Value &+ Int64(z.int(-1...1))
            case 3: return z.pick([0, 1, 2, 3, 4, 5, 6, 7, 255, -1, Int.max, 86_400 * 30, 1_792_000_000])
            case 4: return -n.doubleValue
            default: return zufallsWert(&z)
            }
        }
        if v is NSNull, z.chance(0.6) {
            return beliebigerTeilbaum(z.pick(jsonSaaten), &z) ?? NSNull()
        }
        return zufallsWert(&z)
    }

    // MARK: Prüfen

    private func polstern(_ json: [UInt8], art: UInt8) throws -> SecureBytes {
        let block = PayloadCodec.blockSize
        switch art {
        case 1:
            return try json.withUnsafeBytes { try SecureBytes(copying: $0) }
        default:
            let extra = art == 3 ? 2 * block : 0
            let groesse = (json.count / block + 1) * block + extra
            return try SecureBytes(count: groesse) { out in
                guard let p = out.u8, let roh = out.baseAddress else { return }
                json.withUnsafeBytes { src in
                    if let s = src.baseAddress { roh.copyMemory(from: s, byteCount: json.count) }
                }
                var n = 0
                _ = sodium_pad(&n, p, json.count, block, groesse)
                if art == 2 {
                    // Marker zerstören bzw. Müll ins Polster
                    if json.count < groesse { p[json.count] ^= 0x80 }
                    p[groesse - 1] = 0x55
                }
            }
        }
    }

    func pruefe(_ e: [UInt8]) throws -> String {
        guard e.count >= 2 else { return "leer" }
        let s = saaten[Int(e[0]) % saaten.count]
        let json = Array(e.dropFirst(2))
        guard let dek = s.dek, let store else { return "keine-saat" }
        let padded: SecureBytes
        do { padded = try polstern(json, art: e[1] & 3) } catch { return "polster:" + fehlerCode(error) }

        // 1. direkt dekodieren + Rundlauf
        var direkt: VaultContent?
        var ergebnis: String
        do {
            let (c, _) = try PayloadCodec.decode(padded)
            direkt = c
            let neu: SecureBytes
            do {
                neu = try PayloadCodec.encode(c).padded
            } catch {
                throw Fund("rundlauf", "Inhalt gelesen, aber nicht wieder schreibbar: " + fehlerCode(error))
            }
            let c2: VaultContent
            do {
                c2 = try PayloadCodec.decode(neu).content
            } catch {
                throw Fund("rundlauf", "neu geschriebener Inhalt nicht lesbar: " + fehlerCode(error))
            }
            guard c2 == c else { throw Fund("rundlauf", "Inhalt ändert sich beim Neuschreiben") }
            ergebnis = "ok"
        } catch let x as SiegelError {
            guard case .corruptFile = x else { throw Fund("fehlertyp", "decode: " + fehlerCode(x)) }
            ergebnis = "decode:" + fehlerCode(x)
        }

        // 2. ganzer Weg über die Datei (mit dem DEK der Saat verschlüsselt)
        let ad = VaultFile.payloadAD(header: s.header, slots: s.datei.slots, generation: s.datei.generation)
        let sealed: (nonce: [UInt8], ciphertext: [UInt8])
        do { sealed = try AEAD.seal(key: dek, plaintext: padded, ad: ad) } catch { return ergebnis + "|seal" }
        let datei = VaultFile(header: s.header, slots: s.datei.slots, generation: s.datei.generation,
                              nonce: sealed.nonce, ciphertext: sealed.ciphertext).serialize()
        do {
            let f = try VaultFile.parse(datei)
            let o = try VaultCrypto.openWithPassword(f, password: s.pw, factors: s.faktoren, limits: s.limits,
                                                     cache: s.cache)
            guard direkt != nil else { throw Fund("konsistenz", "Dateiweg öffnet, direktes Lesen scheitert") }
            let v = try UnlockedVault(store: store, header: f.header, slots: f.slots, dek: o.dek, content: o.content,
                                      generation: f.generation, password: s.pw)
            _ = v.entries.count + v.deletedEntries.count
            _ = v.lastModified
            _ = v.securityReport()
            _ = v.masterPasswordReuse
            _ = v.securityKeyCredential
            _ = v.recoveryConfirmed
            _ = v.enrolledFactors
            _ = v.headerInfo
            // Aufdecken (auch versiegelte Einträge) mit den Faktoren der Saat-Tresore
            let unveraendert = e[1] & 3 == 0 && json == s.json
            for eintrag in v.entries.prefix(12) {
                // Vernichtbare Einträge einer schon vernichteten Saat (§23.1): nie mehr lesbar.
                let vernichtet = s.vVernichtet && o.content.destructible[eintrag.id] != nil
                do {
                    _ = try Aufdecken.synchron(v, id: eintrag.id, vVorhanden: !s.vVernichtet)
                    if unveraendert, vernichtet {
                        throw Fund("vernichtung", "vernichteter Eintrag der Saat \(s.name) lässt sich aufdecken")
                    }
                } catch let x as SiegelError {
                    switch x {
                    case .corruptFile, .wrongPassword, .wrongCard, .factorMissing, .factorUnavailable: break
                    default: throw Fund("fehlertyp", "Aufdecken: " + fehlerCode(x))
                    }
                    if unveraendert, s.name.hasPrefix("t") || s.name.hasPrefix("v") {
                        if vernichtet, x == .factorUnavailable(.secureEnclave) {
                            zusatz["aufdecken_vernichtet", default: 0] += 1
                            continue
                        }
                        throw Fund("aufdecken", "unveränderter Eintrag der Saat lässt sich nicht aufdecken: " + fehlerCode(x))
                    }
                    zusatz["aufdecken_" + fehlerCode(x), default: 0] += 1
                }
            }
            v.lock()
            // Vernichtungs-Saaten: den gefuzzten Inhalt durch die Abläufe des Stores fahren (echtes Entsperren mit
            // Vermerk, Kapseln der Ablage, Rotation): ausser zustand.json und der Ablage des Inhalts ändert sich im
            // Hardware-Ordner nichts, und kein Schlüssel (V, Eintrags-, Entsperr-SE-Schlüssel) wird überschrieben.
            if s.vernichtung != nil { ergebnis += try storePruefen(s, datei, inhalt: o.content) }
            // Notfallweg mit Entsiegeln (wie recover); danach Stufe 1 und alles offen
            do {
                var r = try VaultStore.unsealed(try VaultCrypto.openWithRecovery(f, r: s.r), r: s.r)
                var c = r.content
                try c.resetAfterRecovery()
                r = OpenedVault(file: r.file, dek: r.dek, content: c)
                _ = try PayloadCodec.encode(r.content)
                ergebnis += "|rec:ok"
            } catch let x as SiegelError {
                guard case .corruptFile = x else { throw Fund("fehlertyp", "Notfallweg: " + fehlerCode(x)) }
                ergebnis += "|rec:" + fehlerCode(x)
            }
        } catch let x as SiegelError {
            switch x {
            case .corruptFile(let c):
                // Vom Kopf abhängig (direkt nicht prüfbar): Stufe, Längen, Schlüssel-Kennungen der Selbstvernichtung.
                if direkt != nil, c != "payload.level", c != "payload.length", c != "file.length", c != "payload.destruction" {
                    throw Fund("konsistenz", "direktes Lesen gelingt, Dateiweg meldet " + fehlerCode(x))
                }
            default:
                throw Fund("fehlertyp", "Dateiweg: " + fehlerCode(x))
            }
            ergebnis += "|datei:" + fehlerCode(x)
        }
        return ergebnis
    }

    /// Tresorordner der Saat mit dieser Tresordatei, echtes Entsperren über den Store; prüft den Hardware-Ordner.
    private func storePruefen(_ s: TresorSaat, _ datei: [UInt8], inhalt: VaultContent) throws -> String {
        guard let vs = s.vernichtung, let wurzel else { return "" }
        zaehler += 1
        let basis = wurzel.appendingPathComponent("e\(zaehler)", isDirectory: true)
        let ordner = basis.appendingPathComponent("Siegel", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: basis) }
        for (rel, bytes) in vs.dateien {
            let u = ordner.appendingPathComponent(rel)
            try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(rel == VaultStore.vaultFileName ? datei : bytes).write(to: u)
        }
        let hw = ordner.appendingPathComponent(VaultStore.hardwareFolderName, isDirectory: true)
        func dateien() -> [String: [UInt8]] {
            var out: [String: [UInt8]] = [:]
            for n in (try? FileManager.default.contentsOfDirectory(atPath: hw.path)) ?? [] {
                out[n.lowercased()] = try? FileIO.read(hw.appendingPathComponent(n), maxSize: 1 << 20)
            }
            return out
        }
        func name(_ id: UUID?) -> String? { id.map { SaatWerte.hwName($0).lowercased() } }
        let vorher = dateien()
        let store = VaultStore(directory: ordner, rollbackGuard: InMemoryRollbackGuard(), testKDF: true)
        var ergebnis: String
        do {
            let o = try TestHooks.$now.withValue(SaatWerte.zeitpunkt.addingTimeInterval(60)) {
                try store.unlock(masterPassword: s.passwort, factors: s.faktoren)
            }
            switch o {
            case let .unlocked(v), let .rollbackSuspected(v, _, _): v.lock()
            }
            ergebnis = "|store:ok"
        } catch let x as SiegelError {
            guard case .corruptFile = x else { throw Fund("fehlertyp", "Store-Entsperren: " + fehlerCode(x)) }
            ergebnis = "|store:" + fehlerCode(x)
        }
        let nachher = dateien()
        let zustand = DestructionState.fileName
        let ablage = name(inhalt.destruction?.duress?.fileID)
        let altAblage = name(vs.zustand.flatMap { try? DestructionState.decode($0) }?.duressFileID)
        let geschuetzt = Set([vs.plan.vKeyID, s.inhalt?.entryFactors.secureEnclave?.keyID, s.header.factorFields.seKeyID,
                              inhalt.destruction?.vKey?.keyID, inhalt.entryFactors.secureEnclave?.keyID]
                                .compactMap { name($0) })
        for n in geschuetzt.sorted() where vorher[n] != nil && nachher[n] != vorher[n] {
            throw Fund("inhalt", "echtes Entsperren mit diesem Inhalt " + (nachher[n] == nil ? "löscht" : "überschreibt")
                       + " die Schlüssel-Datei \(n) (Ablage des Inhalts: \(ablage ?? "-"), alte Ablage: \(altAblage ?? "-"))")
        }
        for (n, b) in nachher.sorted(by: { $0.key < $1.key }) where n != zustand && n != ablage && vorher[n] != b {
            throw Fund("inhalt", "echtes Entsperren schreibt eine fremde Datei im Hardware-Ordner: \(n)")
        }
        for n in vorher.keys.sorted() where nachher[n] == nil && n != zustand && n != altAblage {
            throw Fund("inhalt", "echtes Entsperren löscht eine Datei, die keine alte Ablage ist: \(n)")
        }
        return ergebnis
    }
}

/// Aufdecken synchron (der Fuzzer läuft auf einem eigenen Thread) mit den Faktor-Werten der Saat-Tresore.
enum Aufdecken {
    final class Kasten: @unchecked Sendable {
        var ergebnis: Result<EntrySecrets, Error>?
    }

    /// Kennungen der Vernichtungsschlüssel V aller Vernichtungs-Saaten.
    static let vKeyIDs = Set(SaatErzeugung.plaene.compactMap { $0.vernichtung?.vKeyID })

    struct Anbieter: EntryFactorProvider {
        /// V der Saat noch da (bei schon vernichteten Saaten nicht: dann wie ein fehlender SE-Blob).
        var vVorhanden = true

        func secureEnclaveSharedSecret(keyID: UUID, ephemeralPublicKey: Data) async throws -> FactorSecret {
            if Aufdecken.vKeyIDs.contains(keyID) {
                guard vVorhanden else { throw SiegelError.factorUnavailable(.secureEnclave) }
            }
            guard let roh = SaatWerte.rohSchluessel(keyID) else { throw SiegelError.factorUnavailable(.secureEnclave) }
            let k = try P256.KeyAgreement.PrivateKey(rawRepresentation: roh)
            let s = try k.sharedSecretFromKeyAgreement(with: try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey))
            return try s.withUnsafeBytes { try FactorSecret(copying: Array($0)) }
        }
        func cardSecret() async throws -> FactorSecret { SaatWerte.q }
        func securityKeyOutput(credentialID: Data, salt: Data) async throws -> FactorSecret { SaatWerte.fidoEintrag }
    }

    static func synchron(_ v: UnlockedVault, id: UUID, vVorhanden: Bool = true) throws -> EntrySecrets {
        let kasten = Kasten()
        let fertig = DispatchSemaphore(value: 0)
        Task.detached {
            do {
                kasten.ergebnis = .success(try await v.revealSecrets(id: id, factors: Anbieter(vVorhanden: vVorhanden)))
            } catch {
                kasten.ergebnis = .failure(error)
            }
            fertig.signal()
        }
        fertig.wait()
        guard let r = kasten.ergebnis else { throw SiegelError.io("fuzz.aufdecken") }
        return try r.get()
    }
}
#endif
