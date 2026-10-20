// Touch ID via the Secure Enclave (BRIEF §6.3, M6.1). CryptoKit is Swift-only,
// so this file is compiled into a static library by build.rs and called from
// src/secure_enclave.rs through the C functions below. Imports are limited to
// Foundation, CryptoKit, LocalAuthentication and Security (surface check).
//
// The Secure Enclave key never leaves the chip. Its `dataRepresentation` is an
// opaque, chip-bound blob that only this Mac's Secure Enclave can use, and the
// chip itself demands a current fingerprint (biometryCurrentSet: adding or
// removing a finger invalidates the key).
//
// Status codes: 0 ok, 1 unavailable, 2 failed, 3 cancelled, 4 lockout,
// 5 key invalid (fingerprints changed or blob from another Mac).

import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let info = Data("lockbox/v1/touch-id".utf8)

private func status(for error: Error) -> Int32 {
    let ns = error as NSError
    if ns.domain == LAError.errorDomain {
        switch LAError.Code(rawValue: ns.code) {
        case .userCancel, .systemCancel, .appCancel, .userFallback: return 3
        case .biometryLockout: return 4
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet: return 1
        default: return 2
        }
    }
    if error is CryptoKitError { return 5 }
    return 2
}

/// The wrapping key both sides derive: HKDF-SHA256 over the ECDH secret,
/// salted with the ephemeral public key.
private func derive(_ secret: SharedSecret, ephemeral: Data, into out: UnsafeMutablePointer<UInt8>) {
    let key = secret.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: ephemeral, sharedInfo: info, outputByteCount: 32)
    key.withUnsafeBytes { raw in
        out.update(from: raw.bindMemory(to: UInt8.self).baseAddress!, count: 32)
    }
}

@_cdecl("lockbox_se_available")
public func lockboxSeAvailable() -> Bool {
    var error: NSError?
    return SecureEnclave.isAvailable
        && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
}

/// Creates a fingerprint-gated Secure Enclave key. Writes its chip-bound blob
/// (malloc'd; free with lockbox_se_free) and its 65-byte X9.63 public key.
@_cdecl("lockbox_se_create")
public func lockboxSeCreate(
    _ outBlob: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outBlobLen: UnsafeMutablePointer<Int>,
    _ outPublic: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return 1 }
    var cfError: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &cfError)
    else { return 2 }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let blob = key.dataRepresentation
        let buffer = malloc(blob.count)!.assumingMemoryBound(to: UInt8.self)
        blob.copyBytes(to: buffer, count: blob.count)
        outBlob.pointee = buffer
        outBlobLen.pointee = blob.count
        let pub = key.publicKey.x963Representation
        pub.copyBytes(to: outPublic, count: 65)
        return 0
    } catch {
        return status(for: error)
    }
}

/// Wrapping side (no fingerprint needed): a fresh ephemeral key agrees with
/// the Secure Enclave key's public half. Writes the ephemeral public key (65)
/// and the derived wrapping key (32).
@_cdecl("lockbox_se_wrap_key")
public func lockboxSeWrapKey(
    _ sePublic: UnsafePointer<UInt8>,
    _ outEphemeral: UnsafeMutablePointer<UInt8>,
    _ outKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: Data(bytes: sePublic, count: 65))
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralPublic = ephemeral.publicKey.x963Representation
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: peer)
        ephemeralPublic.copyBytes(to: outEphemeral, count: 65)
        derive(secret, ephemeral: ephemeralPublic, into: outKey)
        return 0
    } catch {
        return status(for: error)
    }
}

/// Unwrapping side: the Secure Enclave key agrees with the stored ephemeral
/// public key. This is where Touch ID is asked for, with `reason` shown in
/// the system prompt. Blocks until the user answers; never call on the main
/// thread.
@_cdecl("lockbox_se_unwrap_key")
public func lockboxSeUnwrapKey(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ ephemeral: UnsafePointer<UInt8>,
    _ reason: UnsafePointer<CChar>,
    _ outKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: blobLen), authenticationContext: context)
        let ephemeralData = Data(bytes: ephemeral, count: 65)
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralData)
        let secret = try key.sharedSecretFromKeyAgreement(with: peer)
        derive(secret, ephemeral: ephemeralData, into: outKey)
        return 0
    } catch {
        return status(for: error)
    }
}

@_cdecl("lockbox_se_free")
public func lockboxSeFree(_ pointer: UnsafeMutablePointer<UInt8>?) {
    free(pointer)
}
