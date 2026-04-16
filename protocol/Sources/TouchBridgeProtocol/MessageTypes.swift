import Foundation

/// Wire message type identifier — first byte of every message.
public enum MessageType: UInt8, Codable, Sendable {
    case pairRequest = 1
    case pairResponse = 2
    case challengeIssued = 3
    case challengeResponse = 4
    case error = 5
    /// Sent by companion after ECDH to identify itself on reconnect (no pairing required).
    case identify = 6
}

// MARK: - Message Payloads

public struct PairRequestMessage: Codable, Sendable {
    public let deviceName: String
    public let publicKey: Data

    public init(deviceName: String, publicKey: Data) {
        self.deviceName = deviceName
        self.publicKey = publicKey
    }
}

public struct PairResponseMessage: Codable, Sendable {
    public let deviceID: String
    public let publicKey: Data
    public let accepted: Bool

    public init(deviceID: String, publicKey: Data, accepted: Bool) {
        self.deviceID = deviceID
        self.publicKey = publicKey
        self.accepted = accepted
    }
}

public struct ChallengeIssuedMessage: Codable, Sendable {
    public let challengeID: String
    public let encryptedNonce: Data
    public let reason: String
    public let expiryUnix: UInt64

    public init(challengeID: String, encryptedNonce: Data, reason: String, expiryUnix: UInt64) {
        self.challengeID = challengeID
        self.encryptedNonce = encryptedNonce
        self.reason = reason
        self.expiryUnix = expiryUnix
    }
}

public struct ChallengeResponseMessage: Codable, Sendable {
    public let challengeID: String
    public let signature: Data
    public let deviceID: String

    public init(challengeID: String, signature: Data, deviceID: String) {
        self.challengeID = challengeID
        self.signature = signature
        self.deviceID = deviceID
    }
}

public struct ErrorMessage: Codable, Sendable {
    public let code: UInt16
    public let description: String
    /// Challenge this error relates to — allows daemon to resolve a pending auth immediately.
    public let challengeID: String?

    public init(code: UInt16, description: String, challengeID: String? = nil) {
        self.code = code
        self.description = description
        self.challengeID = challengeID
    }
}

/// Sent by companion after ECDH to identify itself without going through full pairing.
/// Allows the daemon to recognise a previously-paired device that reconnected.
public struct IdentifyMessage: Codable, Sendable {
    public let deviceID: String
    public let deviceName: String

    public init(deviceID: String, deviceName: String) {
        self.deviceID = deviceID
        self.deviceName = deviceName
    }
}

/// Well-known error codes sent from companion to daemon.
public enum ErrorCode: UInt16, Sendable {
    /// Secure Enclave key was invalidated — biometric enrollment changed since pairing.
    case keyInvalidated = 1001
}
