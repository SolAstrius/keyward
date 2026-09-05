import Foundation
import Darwin

/// Asks the agent socket for its identity list, with a hard timeout.
///
/// This is the check launchd cannot do. `KeepAlive.Crashed` only notices a
/// process that died; the failure that actually broke SSH was a process that
/// stayed alive, kept accepting connections, and answered none of them.
enum AgentHealth {
    enum Status: Equatable {
        case healthy(keys: Int)
        case unreachable(String)
        case unresponsive

        var isHealthy: Bool { if case .healthy = self { return true }; return false }

        var label: String {
            switch self {
            case .healthy(let n): return "Agent healthy · \(n) key\(n == 1 ? "" : "s")"
            case .unreachable(let why): return "Agent unreachable — \(why)"
            case .unresponsive: return "Agent wedged — accepting but not answering"
            }
        }
    }

    static var socketPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/keyward.sock").path
    }

    static func check(path: String = socketPath, timeout: TimeInterval = 5) -> Status {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return .unreachable("no socket") }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            return .unreachable("path too long")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
        }
        guard rc == 0 else { return .unreachable(String(cString: strerror(errno))) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // SSH_AGENTC_REQUEST_IDENTITIES, length-prefixed.
        var req: [UInt8] = [0, 0, 0, 1, 11]
        guard write(fd, &req, req.count) == req.count else { return .unresponsive }

        var lenBuf = [UInt8](repeating: 0, count: 4)
        guard readFully(fd, &lenBuf, 4) else { return .unresponsive }
        let n = (UInt32(lenBuf[0]) << 24) | (UInt32(lenBuf[1]) << 16)
              | (UInt32(lenBuf[2]) << 8) | UInt32(lenBuf[3])
        guard n >= 5, n < 1 << 20 else { return .unresponsive }

        var body = [UInt8](repeating: 0, count: Int(n))
        guard readFully(fd, &body, Int(n)) else { return .unresponsive }
        guard body[0] == 12 else { return .unresponsive }  // IDENTITIES_ANSWER
        let count = (UInt32(body[1]) << 24) | (UInt32(body[2]) << 16)
                  | (UInt32(body[3]) << 8) | UInt32(body[4])
        return .healthy(keys: Int(count))
    }

    private static func readFully(_ fd: Int32, _ buf: inout [UInt8], _ want: Int) -> Bool {
        var got = 0
        while got < want {
            let n = buf.withUnsafeMutableBytes { raw -> Int in
                read(fd, raw.baseAddress!.advanced(by: got), want - got)
            }
            if n <= 0 { return false }
            got += n
        }
        return true
    }
}
