import Foundation
import CryptoKit
import LocalAuthentication
import Security

// Irreducibly Swift: Apple exposes Secure Enclave key persistence only through
// CryptoKit's dataRepresentation. Everything else lives in Rust.

private func store(_ data: Data, _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    if data.count > cap { return -2 }
    data.copyBytes(to: buf, count: data.count)
    return data.count
}

/// policy: 0 = no auth, 1 = user presence, 2 = current biometry set
private func accessControl(_ policy: Int32) -> SecAccessControl? {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if policy == 1 { flags.insert(.userPresence) }
    if policy == 2 { flags.insert(.biometryCurrentSet) }
    return SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)
}

/// A reuse window only has effect within a single LAContext — a fresh context
/// per signature always re-authenticates. Holding one for the length of the
/// window is what actually turns "once per host" into "once per window".
private final class ContextCache {
    static let shared = ContextCache()
    private let lock = NSLock()
    private var ctx: LAContext?
    private var born = Date.distantPast

    func take(reuse: Double) -> LAContext {
        lock.lock()
        defer { lock.unlock() }
        if reuse > 0, let c = ctx, Date().timeIntervalSince(born) < reuse {
            return c
        }
        let c = LAContext()
        if reuse > 0 {
            c.touchIDAuthenticationAllowableReuseDuration =
                min(reuse, LATouchIDAuthenticationMaximumAllowableReuseDuration)
            ctx = c
            born = Date()
        } else {
            ctx = nil
        }
        return c
    }
}

@_cdecl("kwse_available")
public func kwse_available() -> Int32 { SecureEnclave.isAvailable ? 1 : 0 }

@_cdecl("kwse_generate")
public func kwse_generate(_ policy: Int32, _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    guard let ac = accessControl(policy) else { return -1 }
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey(accessControl: ac) else { return -1 }
    return store(k.dataRepresentation, buf, cap)
}

@_cdecl("kwse_public")
public func kwse_public(_ blob: UnsafePointer<UInt8>, _ blobLen: Int,
                        _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let d = Data(bytes: blob, count: blobLen)
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: d) else { return -1 }
    return store(k.publicKey.x963Representation, buf, cap)
}

@_cdecl("kwse_sign")
public func kwse_sign(_ blob: UnsafePointer<UInt8>, _ blobLen: Int,
                      _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
                      _ reason: UnsafePointer<CChar>?,
                      _ reuseSeconds: Double,
                      _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let d = Data(bytes: blob, count: blobLen)
    // Consecutive signatures within the window share one authentication, so a
    // loop over the fleet asks once rather than once per host.
    let ctx = ContextCache.shared.take(reuse: reuseSeconds)
    if let reason, let text = String(validatingUTF8: reason), !text.isEmpty {
        // This is the whole point: Keyward writes the Touch ID prompt, so it can
        // name the commit or the host instead of saying "a request from launchd".
        ctx.localizedReason = text
    }
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: d, authenticationContext: ctx) else { return -1 }
    guard let sig = try? k.signature(for: Data(bytes: msg, count: msgLen)) else { return -3 }
    return store(sig.rawRepresentation, buf, cap)   // r||s, 64 bytes
}
