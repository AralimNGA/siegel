import Darwin
import Foundation
import IOKit
import IOKit.hid

/// CTAPHID über IOHIDManager/IOHIDDevice (FIDO-Usage-Page 0xF1D0, Usage 0x01, Berichte je 64 Byte).
///
/// Ehrlich: mit echter Hardware ungetestet (siehe `SecurityKeyFactor.testedWithHardware`). Eingabeberichte kommen
/// über eine Dispatch-Queue (IOHIDDeviceSetDispatchQueue/Activate/Cancel); Ausgabe per IOHIDDeviceSetReport ohne
/// Report-ID. In der Sandbox braucht die App das Entitlement `com.apple.security.device.usb`.
final class HIDDeviceTransport: CTAPHIDTransport, @unchecked Sendable {
    static let fidoUsagePage = 0xF1D0
    static let fidoUsage = 0x01
    /// Höchstzahl wartender Berichte (ein Gerät, das flutet, füllt nicht den Speicher).
    static let maxQueuedReports = 256

    private let device: IOHIDDevice
    private let queue = DispatchQueue(label: "siegel.fido.hid")
    private let buffer: UnsafeMutablePointer<UInt8>
    private let condition = NSCondition()
    private var reports: [[UInt8]] = []
    private var removed = false
    private var closed = false
    private let cancelled = DispatchSemaphore(value: 0)

    private init(device: IOHIDDevice) {
        self.device = device
        buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: CTAPHID.reportSize)
        buffer.initialize(repeating: 0, count: CTAPHID.reportSize)
    }

    deinit {
        _ = memset_s(buffer, CTAPHID.reportSize, 0, CTAPHID.reportSize)
        buffer.deallocate()
    }

    // MARK: Aufzählen

    /// Alle angeschlossenen FIDO-HID-Geräte mit 64-Byte-Berichten.
    static func enumerate() -> [SecurityKeyDevice] {
        fidoDevices().map(\.0)
    }

    private static func fidoDevices() -> [(SecurityKeyDevice, IOHIDDevice)] {
        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        let matching: [String: Any] = [kIOHIDDeviceUsagePageKey: fidoUsagePage, kIOHIDDeviceUsageKey: fidoUsage]
        IOHIDManagerSetDeviceMatching(manager, matching as CFDictionary)
        guard let set = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else { return [] }
        var out: [(SecurityKeyDevice, IOHIDDevice)] = []
        for device in set where isFIDO(device) {
            out.append((SecurityKeyDevice(name: displayName(device), registryID: registryID(device)), device))
        }
        return out.sorted { $0.0.registryID < $1.0.registryID }
    }

    static func isFIDO(_ device: IOHIDDevice) -> Bool {
        let page: Int? = property(device, kIOHIDPrimaryUsagePageKey)
        let usage: Int? = property(device, kIOHIDPrimaryUsageKey)
        let input: Int? = property(device, kIOHIDMaxInputReportSizeKey)
        let output: Int? = property(device, kIOHIDMaxOutputReportSizeKey)
        return page == fidoUsagePage && usage == fidoUsage && input == CTAPHID.reportSize && output == CTAPHID.reportSize
    }

    static func displayName(_ device: IOHIDDevice) -> String {
        let manufacturer: String = (property(device, kIOHIDManufacturerKey) ?? "").trimmingCharacters(in: .whitespaces)
        let product: String = (property(device, kIOHIDProductKey) ?? "").trimmingCharacters(in: .whitespaces)
        let name: String
        if product.isEmpty {
            name = manufacturer
        } else if manufacturer.isEmpty || product.localizedCaseInsensitiveContains(manufacturer) {
            name = product
        } else {
            name = "\(manufacturer) \(product)"
        }
        let trimmed = String(name.prefix(80))
        return trimmed.isEmpty ? "Sicherheitsschlüssel" : trimmed
    }

    private static func registryID(_ device: IOHIDDevice) -> UInt64 {
        var id: UInt64 = 0
        IORegistryEntryGetRegistryEntryID(IOHIDDeviceGetService(device), &id)
        return id
    }

    private static func property<T>(_ device: IOHIDDevice, _ key: String) -> T? {
        IOHIDDeviceGetProperty(device, key as CFString) as? T
    }

    // MARK: Öffnen

    static func open(_ wanted: SecurityKeyDevice) throws(FIDOError) -> HIDDeviceTransport {
        let candidates = fidoDevices()
        let match = wanted.registryID != 0
            ? candidates.first { $0.0.registryID == wanted.registryID }
            : candidates.first { $0.0.name == wanted.name }
        guard let (_, device) = match else { throw .transport }
        guard IOHIDDeviceOpen(device, IOOptionBits(kIOHIDOptionsTypeNone)) == kIOReturnSuccess else { throw .transport }
        let transport = HIDDeviceTransport(device: device)
        transport.activate()
        return transport
    }

    private func activate() {
        IOHIDDeviceSetDispatchQueue(device, queue)
        // Der Kontext hält das Objekt, bis der Abbruch-Handler gelaufen ist.
        let context = Unmanaged.passRetained(self).toOpaque()
        IOHIDDeviceRegisterInputReportCallback(device, buffer, CTAPHID.reportSize, { context, result, _, _, _, report, length in
            guard let context else { return }
            let me = Unmanaged<HIDDeviceTransport>.fromOpaque(context).takeUnretainedValue()
            me.enqueue(result == kIOReturnSuccess ? Array(UnsafeBufferPointer(start: report, count: max(0, length))) : nil)
        }, context)
        IOHIDDeviceRegisterRemovalCallback(device, { context, _, _ in
            guard let context else { return }
            Unmanaged<HIDDeviceTransport>.fromOpaque(context).takeUnretainedValue().markRemoved()
        }, context)
        let bits = UInt(bitPattern: context)
        let done = cancelled
        IOHIDDeviceSetCancelHandler(device) {
            if let pointer = UnsafeMutableRawPointer(bitPattern: bits) {
                Unmanaged<HIDDeviceTransport>.fromOpaque(pointer).release()
            }
            done.signal()
        }
        IOHIDDeviceActivate(device)
    }

    private func enqueue(_ report: [UInt8]?) {
        condition.lock()
        if let report, reports.count < Self.maxQueuedReports { reports.append(report) }
        condition.broadcast()
        condition.unlock()
    }

    private func markRemoved() {
        condition.lock()
        removed = true
        condition.broadcast()
        condition.unlock()
    }

    // MARK: CTAPHIDTransport

    func send(report: [UInt8]) throws {
        guard report.count == CTAPHID.reportSize else { throw FIDOError.hid("hid.report") }
        condition.lock()
        let unusable = removed || closed
        condition.unlock()
        guard !unusable else { throw FIDOError.transport }
        let result = report.withUnsafeBufferPointer { buf -> IOReturn in
            guard let base = buf.baseAddress else { return kIOReturnBadArgument }
            return IOHIDDeviceSetReport(device, kIOHIDReportTypeOutput, 0, base, buf.count)
        }
        guard result == kIOReturnSuccess else { throw FIDOError.transport }
    }

    func receive(timeout: Duration) throws -> [UInt8]? {
        let deadline = Date().addingTimeInterval(CTAPHIDChannel.seconds(timeout))
        condition.lock()
        defer { condition.unlock() }
        while reports.isEmpty, !removed, !closed {
            if !condition.wait(until: deadline) { break }
        }
        if !reports.isEmpty { return reports.removeFirst() }
        if removed || closed { throw FIDOError.transport }
        return nil
    }

    func close() {
        condition.lock()
        let already = closed
        closed = true
        reports.removeAll()
        condition.broadcast()
        condition.unlock()
        guard !already else { return }
        IOHIDDeviceCancel(device)
        _ = cancelled.wait(timeout: .now() + 2)
        IOHIDDeviceClose(device, IOOptionBits(kIOHIDOptionsTypeNone))
        _ = memset_s(buffer, CTAPHID.reportSize, 0, CTAPHID.reportSize)
    }
}
