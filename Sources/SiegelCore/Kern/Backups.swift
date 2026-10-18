import Foundation

/// Namensschema und Ausdünnung der Sicherungen (SPEC §4).
///   lokal:  Sicherungen/<vaultID>/<UTC JJJJMMTT-hhmmss>-g<generation>-<4 Zufallshex>[-vor-<anlass>].siegel
///   extern: Siegel-<vaultID 8 hex>-<UTC JJJJMMTT-hhmmss>.siegel
///   beschädigt: Sicherungen/beschaedigt-<UTC JJJJMMTT-hhmmss>[-<4 hex>].siegel
enum BackupNaming {
    static let fileExtension = "siegel"
    static let quarantinePrefix = "beschaedigt-"
    static let externalPrefix = "Siegel-"

    /// Anlässe angehefteter Sicherungen.
    enum Reason: String, Sendable {
        case importCSV = "import"
        case passwordChange = "passwortwechsel"
        case recovery = "notfall"
        case newKit = "neues-kit"
        case migration = "migration"
        /// Letzter Stand im Format v1 vor dem ersten Schreiben in Format v2 (SPEC §13.2).
        case migrationV1 = "migration-v1"
        case restore = "wiederherstellung"
        /// Vor einem Wechsel der Sicherheitsstufe (Zugangswechsel, SPEC §13).
        case levelChange = "stufenwechsel"
    }

    private static let utc: TimeZone = TimeZone(identifier: "UTC") ?? TimeZone(secondsFromGMT: 0) ?? .current

    private static var calendar: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = utc
        return c
    }

    /// "JJJJMMTT-hhmmss" in UTC.
    static func timestamp(_ date: Date) -> String {
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        func pad(_ v: Int?, _ w: Int) -> String {
            let s = String(v ?? 0)
            return String(repeating: "0", count: max(0, w - s.count)) + s
        }
        return pad(c.year, 4) + pad(c.month, 2) + pad(c.day, 2) + "-" + pad(c.hour, 2) + pad(c.minute, 2) + pad(c.second, 2)
    }

    static func parseTimestamp(_ day: Substring, _ time: Substring) -> Date? {
        guard day.count == 8, time.count == 6, day.allSatisfy(\.isASCIIDigit), time.allSatisfy(\.isASCIIDigit),
              let y = Int(day.prefix(4)), let mo = Int(day.dropFirst(4).prefix(2)), let d = Int(day.suffix(2)),
              let h = Int(time.prefix(2)), let mi = Int(time.dropFirst(2).prefix(2)), let s = Int(time.suffix(2)) else {
            return nil
        }
        var dc = DateComponents()
        dc.year = y; dc.month = mo; dc.day = d; dc.hour = h; dc.minute = mi; dc.second = s
        dc.timeZone = utc
        return calendar.date(from: dc)
    }

    static func randomHex4() -> String { hexString(randomBytes(2)) }

    static func localName(date: Date, generation: UInt64, reason: String?) -> String {
        var name = timestamp(date) + "-g" + String(generation) + "-" + randomHex4()
        if let reason { name += "-vor-" + reason }
        return name + "." + fileExtension
    }

    struct LocalName: Equatable {
        let date: Date
        let generation: UInt64
        let reason: String?
    }

    /// Zerlegt einen lokalen Sicherungsnamen; nil, wenn er nicht dem Schema folgt.
    static func parseLocal(_ fileName: String) -> LocalName? {
        guard fileName.hasSuffix("." + fileExtension) else { return nil }
        let stem = fileName.dropLast(fileExtension.count + 1)
        let parts = stem.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count >= 4, let date = parseTimestamp(parts[0], parts[1]),
              parts[2].hasPrefix("g"), let gen = UInt64(parts[2].dropFirst()),
              parts[3].count == 4, parts[3].allSatisfy(\.isHexDigit) else { return nil }
        var reason: String?
        if parts.count > 4 {
            guard parts[4] == "vor", parts.count > 5 else { return nil }
            reason = parts[5...].joined(separator: "-")
        }
        return LocalName(date: date, generation: gen, reason: reason)
    }

    static func externalPrefix(vaultID: UUID) -> String {
        externalPrefix + String(hexString(VaultHeader.bytes(of: vaultID)).prefix(8)) + "-"
    }

    static func externalName(vaultID: UUID, date: Date) -> String {
        externalPrefix(vaultID: vaultID) + timestamp(date) + "." + fileExtension
    }

    /// Zeit aus einem externen Namen (nur für das passende Präfix).
    static func parseExternal(_ fileName: String, prefix: String) -> Date? {
        guard fileName.hasPrefix(prefix), fileName.hasSuffix("." + fileExtension) else { return nil }
        let middle = fileName.dropFirst(prefix.count).dropLast(fileExtension.count + 1)
        let parts = middle.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        return parseTimestamp(parts[0], parts[1])
    }

    /// Externe Namen beliebiger Tresore: "Siegel-<8 hex>-JJJJMMTT-hhmmss.siegel".
    static func parseAnyExternal(_ fileName: String) -> Date? {
        guard fileName.hasPrefix(externalPrefix) else { return nil }
        let rest = fileName.dropFirst(externalPrefix.count)
        guard rest.count > 9, rest.prefix(8).allSatisfy(\.isHexDigit), rest.dropFirst(8).first == "-" else { return nil }
        return parseExternal(fileName, prefix: externalPrefix + String(rest.prefix(8)) + "-")
    }

    static func quarantineName(date: Date, suffix: String?) -> String {
        quarantinePrefix + timestamp(date) + (suffix.map { "-" + $0 } ?? "") + "." + fileExtension
    }
}

private extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}

/// Zeitliche Ausdünnung pro vaultID (SPEC §4): alles aus den letzten 48 h (max. 50), danach je die neueste pro
/// Tag für 30 Tage, pro Woche für 26 Wochen, pro Monat für 24 Monate. Nie gelöscht: angeheftete und die älteste.
enum BackupThinning {
    struct Item: Sendable {
        let url: URL
        let date: Date
        let pinned: Bool
    }

    static let recentWindow: TimeInterval = 48 * 3600
    static let recentMax = 50

    static func selectForDeletion(_ items: [Item], now: Date) -> [URL] {
        guard let oldest = items.min(by: { $0.date < $1.date }) else { return [] }
        var keep = Set<URL>([oldest.url])
        let unpinned = items.filter { !$0.pinned }.sorted { $0.date > $1.date }

        var recentKept = 0
        for it in unpinned where now.timeIntervalSince(it.date) <= recentWindow {
            if recentKept < recentMax {
                keep.insert(it.url)
                recentKept += 1
            }
        }

        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC") ?? TimeZone(secondsFromGMT: 0) ?? .current
        func keepNewestPerBucket(since start: Date, bucket: (Date) -> Int) {
            var seen = Set<Int>()
            for it in unpinned where it.date >= start {
                if seen.insert(bucket(it.date)).inserted { keep.insert(it.url) }
            }
        }
        let day: (Date) -> Int = { Int((floor($0.timeIntervalSince1970 / 86_400))) }
        // Wochen ab Montag (1970-01-01 war ein Donnerstag)
        let week: (Date) -> Int = { Int(floor(($0.timeIntervalSince1970 / 86_400 + 3) / 7)) }
        let month: (Date) -> Int = { d in
            let c = cal.dateComponents([.year, .month], from: d)
            return (c.year ?? 0) * 12 + (c.month ?? 0)
        }
        keepNewestPerBucket(since: now.addingTimeInterval(-30 * 86_400), bucket: day)
        keepNewestPerBucket(since: now.addingTimeInterval(-26 * 7 * 86_400), bucket: week)
        let monthStart = cal.date(byAdding: .month, value: -24, to: now) ?? now.addingTimeInterval(-730 * 86_400)
        keepNewestPerBucket(since: monthStart, bucket: month)

        return unpinned.filter { !keep.contains($0.url) }.map(\.url)
    }
}
