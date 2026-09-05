import Foundation
import AppKit
import UserNotifications

/// Tails the daemon's JSONL log.
///
/// Polling rather than a DispatchSource: the daemon rotates the file, and a
/// vnode source attached to a replaced inode goes silent without saying so.
/// Re-stat'ing each tick survives rotation for free.
@MainActor
final class EventStore: ObservableObject {
    @Published private(set) var events: [AgentEvent] = []
    @Published var notifyOnSign: Bool = UserDefaults.standard.bool(forKey: "notifyOnSign") {
        didSet { UserDefaults.standard.set(notifyOnSign, forKey: "notifyOnSign") }
    }

    private let url: URL
    private var offset: UInt64 = 0
    private var inode: UInt64 = 0
    private var timer: Timer?
    private var primed = false

    static let maxEvents = 5000

    init(url: URL = EventStore.defaultLogURL) {
        self.url = url
    }

    nonisolated static var defaultLogURL: URL {
        FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Keyward/events.jsonl")
    }

    func start() {
        requestNotificationAuthorization()
        tick()
        primed = true
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    private func requestNotificationAuthorization() {
        guard Bundle.main.bundleIdentifier != nil else { return }
        UNUserNotificationCenter.current()
            .requestAuthorization(options: [.alert]) { _, _ in }
    }

    private func tick() {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: url.path),
              let size = (attrs[.size] as? NSNumber)?.uint64Value,
              let ino = (attrs[.systemFileNumber] as? NSNumber)?.uint64Value
        else { return }

        // Rotated or truncated: start over from the top of the new file.
        if ino != inode || size < offset {
            inode = ino
            offset = 0
            events.removeAll()
        }
        guard size > offset else { return }

        guard let fh = try? FileHandle(forReadingFrom: url) else { return }
        defer { try? fh.close() }
        try? fh.seek(toOffset: offset)
        guard let data = try? fh.readToEnd(), !data.isEmpty else { return }
        offset = size

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase

        var fresh: [AgentEvent] = []
        for line in data.split(separator: UInt8(ascii: "\n")) where !line.isEmpty {
            if let ev = try? decoder.decode(AgentEvent.self, from: Data(line)) {
                fresh.append(ev)
            }
        }
        guard !fresh.isEmpty else { return }

        events.append(contentsOf: fresh)
        if events.count > Self.maxEvents {
            events.removeFirst(events.count - Self.maxEvents)
        }
        if primed && notifyOnSign {
            for ev in fresh where ev.kind == .sign { notify(ev) }
        }
    }

    private func notify(_ ev: AgentEvent) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        content.title = "\(ev.appName) signed with your key"
        var parts: [String] = []
        if let d = ev.who.destination { parts.append(d) }
        if let c = ev.keyComment { parts.append(c) }
        if let u = ev.upstream { parts.append("via \(u)") }
        content.body = parts.joined(separator: " · ")
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }

    // MARK: - Derived

    var signEvents: [AgentEvent] { events.filter { $0.kind == .sign } }

    func appIcon(for event: AgentEvent) -> NSImage? {
        guard let path = event.who.app?.bundlePath else { return nil }
        return NSWorkspace.shared.icon(forFile: path)
    }

    /// Signature counts per app, most active first.
    var signatureLeaderboard: [(name: String, count: Int)] {
        var counts: [String: Int] = [:]
        for e in signEvents { counts[e.appName, default: 0] += 1 }
        return counts.sorted { $0.value > $1.value }.map { (name: $0.key, count: $0.value) }
    }
}
