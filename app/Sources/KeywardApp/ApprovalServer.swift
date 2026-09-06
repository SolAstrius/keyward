import Foundation
import Darwin

/// Listens for the daemon's "a signature is happening" messages.
///
/// The app is the server so the daemon can simply fail to connect when the app
/// is not running, and sign anyway — the card is context, never a gate. If it
/// were a gate, quitting the UI would break SSH.
final class ApprovalServer {
    static let shared = ApprovalServer()
    private var fd: Int32 = -1

    static var socketPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Keyward/ui.sock").path
    }

    func start() {
        let path = Self.socketPath
        try? FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true)
        unlink(path)

        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)

        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
        }
        guard ok == 0, listen(fd, 8) == 0 else { close(fd); fd = -1; return }
        chmod(path, 0o600)

        Thread.detachNewThread { [weak self] in self?.acceptLoop() }
    }

    private func acceptLoop() {
        while true {
            let c = accept(fd, nil, nil)
            if c < 0 { if errno == EINTR { continue }; return }
            Thread.detachNewThread { [weak self] in self?.serve(c) }
        }
    }

    private func serve(_ c: Int32) {
        defer {
            close(c)
            // A dropped connection must not strand the card on screen.
            Task { @MainActor in ApprovalPanel.shared.hide() }
        }
        var buf = [UInt8](repeating: 0, count: 8192)
        var acc = Data()
        while true {
            let n = read(c, &buf, buf.count)
            if n <= 0 { return }
            acc.append(contentsOf: buf[0..<n])
            while let i = acc.firstIndex(of: UInt8(ascii: "\n")) {
                let line = acc[acc.startIndex..<i]
                acc = acc[acc.index(after: i)...]
                handle(Data(line), reply: c)
            }
        }
    }

    private func handle(_ line: Data, reply c: Int32) {
        let dec = JSONDecoder()
        dec.keyDecodingStrategy = .convertFromSnakeCase
        guard let env = try? dec.decode(Envelope.self, from: line) else { return }
        switch env.type {
        case "show":
            if let ctx = try? dec.decode(PendingSignature.self, from: line) {
                Task { @MainActor in ApprovalPanel.shared.show(ctx) }
            }
            // Tell the daemon the card is up, so the sheet lands on top of it
            // rather than in front of nothing.
            var ack = Array(#"{"type":"shown"}"#.utf8); ack.append(UInt8(ascii: "\n"))
            _ = ack.withUnsafeBufferPointer { write(c, $0.baseAddress, $0.count) }
        case "done":
            Task { @MainActor in ApprovalPanel.shared.hide() }
        default:
            break
        }
    }

    private struct Envelope: Codable { let type: String }
}
