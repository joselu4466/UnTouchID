import Foundation
import os.log

/// Orchestrates the iOS side of challenge-response:
/// decrypt challenge → prompt biometric → sign nonce → encrypt response → send via BLE.
public final class ChallengeHandler: @unchecked Sendable {
    private let logger = Logger(subsystem: "dev.touchbridge", category: "ChallengeHandler")

    private let signingProvider: SigningProvider
    private let localAuth: LocalAuthManager
    private let signingKeyTag: String

    /// Session crypto for the current BLE connection (set after ECDH).
    public var sessionCrypto: SessionCryptoWrapper?

    /// Callback to send the signed response back over BLE.
    public var sendResponse: ((Data) -> Bool)?

    public init(
        signingProvider: SigningProvider,
        localAuth: LocalAuthManager,
        signingKeyTag: String = "dev.touchbridge.signing"
    ) {
        self.signingProvider = signingProvider
        self.localAuth = localAuth
        self.signingKeyTag = signingKeyTag
    }

    /// Handle an incoming encrypted challenge from the Mac.
    ///
    /// Flow:
    /// 1. Decrypt with session key
    /// 2. Parse ChallengeIssuedMessage
    /// 3. Prompt biometric via LocalAuthManager
    /// 4. Sign nonce with Secure Enclave key
    /// 5. Build ChallengeResponseMessage
    /// 6. Encrypt with session key
    /// 7. Send via BLE
    @MainActor
    public func handleChallenge(encryptedData: Data, deviceID: String) async -> ChallengeHandlerResult {
        // 1. Decrypt
        guard let session = sessionCrypto else {
            logger.error("No session crypto — ECDH not yet completed")
            return .failed(.noSession)
        }

        // 2. Parse — the challenge arrives as wire format [version, type] + plain JSON.
        // Strip the 2-byte header before JSON-decoding. The nonce inside is separately encrypted.
        guard encryptedData.count > 2 else {
            logger.error("Challenge data too short: \(encryptedData.count) bytes")
            return .failed(.parseFailed)
        }
        let jsonPayload = encryptedData.dropFirst(2)
        let challengeMsg: ChallengeIssuedMessageCompanion
        do {
            challengeMsg = try JSONDecoder().decode(ChallengeIssuedMessageCompanion.self, from: jsonPayload)
        } catch {
            logger.error("Failed to parse challenge: \(error.localizedDescription)")
            return .failed(.parseFailed)
        }

        // Decrypt the nonce — only the nonce field is AES-GCM encrypted, not the whole message.
        let decryptedNonce: Data
        do {
            decryptedNonce = try session.decrypt(ciphertext: challengeMsg.encryptedNonce)
        } catch {
            logger.error("Failed to decrypt nonce: \(error.localizedDescription)")
            return .failed(.decryptionFailed)
        }

        // Check expiry
        let expiryDate = Date(timeIntervalSince1970: TimeInterval(challengeMsg.expiryUnix))
        guard Date() < expiryDate else {
            logger.warning("Challenge expired before biometric prompt")
            return .failed(.expired)
        }

        // 3. Prompt biometric
        let reason = "TouchBridge: \(challengeMsg.reason)"
        do {
            let authenticated = try await localAuth.authenticateUser(reason: reason)
            guard authenticated else {
                logger.info("Biometric authentication returned false")
                return .failed(.biometricDenied)
            }
        } catch {
            logger.info("Biometric authentication failed: \(error.localizedDescription)")
            return .failed(.biometricDenied)
        }

        // 4. Sign the decrypted nonce — daemon verifies against the plaintext nonce it stored.
        let signature: Data
        do {
            signature = try signingProvider.sign(data: decryptedNonce, keyTag: signingKeyTag)
        } catch SecureEnclaveError.keyInvalidated {
            logger.error("Signing key invalidated — biometric enrollment changed since pairing")
            // Notify the Mac immediately so it fails fast instead of waiting for timeout.
            sendKeyInvalidatedError(challengeID: challengeMsg.challengeID, deviceID: deviceID, session: session)
            return .failed(.keyInvalidated)
        } catch {
            logger.error("Signing failed: \(error.localizedDescription)")
            return .failed(.signingFailed)
        }

        // 5. Build response
        let response = ChallengeResponseCompanion(
            challengeID: challengeMsg.challengeID,
            signature: signature,
            deviceID: deviceID
        )

        // 6. Encode — daemon expects wire format: [version=1][type=4(challengeResponse)] + JSON
        let responseData: Data
        do {
            let jsonData = try JSONEncoder().encode(response)
            var wire = Data([1, 4]) // protocolVersion=1, MessageType.challengeResponse=4
            wire.append(jsonData)
            responseData = wire
        } catch {
            logger.error("Failed to encode response: \(error.localizedDescription)")
            return .failed(.encodingFailed)
        }

        // 7. Send
        if let send = sendResponse {
            let sent = send(responseData)
            if !sent {
                logger.warning("Failed to send response over BLE")
                return .failed(.sendFailed)
            }
        }

        logger.info("Challenge \(challengeMsg.challengeID) handled successfully")
        return .success(challengeID: challengeMsg.challengeID)
    }
}

// MARK: - Supporting Types

/// Result of handling a challenge.
public enum ChallengeHandlerResult: Sendable {
    case success(challengeID: String)
    case failed(ChallengeHandlerError)
}

public enum ChallengeHandlerError: Sendable, CustomStringConvertible {
    public var description: String {
        switch self {
        case .noSession: return "no_session"
        case .decryptionFailed: return "decryption_failed"
        case .parseFailed: return "parse_failed"
        case .expired: return "expired"
        case .biometricDenied: return "biometric_denied"
        case .signingFailed: return "signing_failed"
        case .keyInvalidated: return "key_invalidated"
        case .encodingFailed: return "encoding_failed"
        case .sendFailed: return "send_failed"
        }
    }

    case noSession
    case decryptionFailed
    case parseFailed
    case expired
    case biometricDenied
    case signingFailed
    /// Secure Enclave key was invalidated — biometric enrollment changed. User must re-pair.
    case keyInvalidated
    case encodingFailed
    case sendFailed
}

/// Wrapper around SessionCrypto operations for the companion side.
/// Avoids importing CryptoKit directly in the handler.
public final class SessionCryptoWrapper: @unchecked Sendable {
    private let encryptFn: (Data) throws -> Data
    private let decryptFn: (Data) throws -> Data

    public init(encrypt: @escaping (Data) throws -> Data, decrypt: @escaping (Data) throws -> Data) {
        self.encryptFn = encrypt
        self.decryptFn = decrypt
    }

    public func encrypt(plaintext: Data) throws -> Data {
        try encryptFn(plaintext)
    }

    public func decrypt(ciphertext: Data) throws -> Data {
        try decryptFn(ciphertext)
    }
}

// MARK: - Private helpers

extension ChallengeHandler {
    /// Send a key-invalidated error to the Mac so it can fail the auth immediately
    /// rather than waiting for the 15-second timeout.
    ///
    /// Wire format: [version=1][type=5(error)] + JSON payload
    /// Matches the daemon's ErrorMessage type.
    private func sendKeyInvalidatedError(
        challengeID: String,
        deviceID: String,
        session: SessionCryptoWrapper
    ) {
        // Build the error payload. The daemon's ErrorMessage struct expects:
        //   { "code": 1001, "description": "key_invalidated", "challengeID": "..." }
        // We encrypt it with the session key so it matches the security model.
        struct ErrorPayload: Codable {
            let code: UInt16
            let description: String
            let challengeID: String?
        }

        guard let payloadData = try? JSONEncoder().encode(
            ErrorPayload(code: 1001, description: "key_invalidated", challengeID: challengeID)
        ) else {
            logger.error("Failed to encode key-invalidated error payload")
            return
        }

        // Wire format: [protocolVersion=1][messageType=5(error)] + encrypted payload
        guard let encryptedPayload = try? session.encrypt(plaintext: payloadData) else {
            logger.error("Failed to encrypt key-invalidated error payload")
            return
        }

        var wireData = Data([1, 5]) // version=1, type=error(5)
        wireData.append(encryptedPayload)

        _ = sendResponse?(wireData)
        logger.info("Sent key-invalidated error to Mac for challenge \(challengeID)")
    }
}

/// Local copies of message types for the companion app (avoids cross-package dependency).
struct ChallengeIssuedMessageCompanion: Codable {
    let challengeID: String
    let encryptedNonce: Data
    let reason: String
    let expiryUnix: UInt64

    enum CodingKeys: String, CodingKey {
        case challengeID = "challengeID"
        case encryptedNonce
        case reason
        case expiryUnix
    }
}

struct ChallengeResponseCompanion: Codable {
    let challengeID: String
    let signature: Data
    let deviceID: String
}
