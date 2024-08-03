//
//  SwiftPollManager.swift
//  calmdocs
//
//  Created by Iain McLaren on 25/3/2024.
//

import Foundation
import SwiftUI
import SwiftProcessManager
import SwiftKeyExchange

/// PollManagerError error.
public enum PollManagerError: Error {
    case urlError
    case publishFailure

    case timestampInvalidFormat
    case timestampExpired
    case timestampInPastError
    case timestampInFutureError
}

///  Function to create a new KeyExchangeStore.  Alternatively, create a similar function using a custom KeyExchangeStore().
public var KeyExchange_Curve25519_SHA256_HKDF_AESGCM = { return try! KeyExchange_Curve25519_SHA256_HKDF_AESGCM_Store("") }
public var KeyExchange_Curve25519_SHA384_HKDF_AESGCM = { return try! KeyExchange_Curve25519_SHA384_HKDF_AESGCM_Store("") }
public var KeyExchange_Curve25519_SHA512_HKDF_AESGCM = { return try! KeyExchange_Curve25519_SHA512_HKDF_AESGCM_Store("") }

/// PollManager is an ObservableObject used for long polling
public class PollManager: ObservableObject {
    
    // Bearer token.  Defaults to self.kes.LocalPublicKey() unless we manually change it
    public var bearerToken: String = ""

    // ProcessManager
    public var processManager = ProcessManager()
    public var timer: Timer?
    public var pingCount: Int = 0
    
    // KeyExchangeStore
    public var keyExchangeStoreFunction: () -> KeyExchangeStore
    public var kes: KeyExchangeStore = KeyExchangeStore()
    public var timestamp = KeyExchangeCurrentTimestamp() // Int64 current time since 1970 in milliseconds.
   
    /// Set ping count to 0
    public func pong() {
        self.pingCount = 0
    }
    
    /// Get the current time since 1970 in milliseconds.
    /// - Returns: Data timestamp (utf8 encoded).
    public func keyExchangeCurrentTimestampData() -> Data {
        return KeyExchangeCurrentTimestampData()
    }
    
    #if os(macOS)
    
    /// Get a random open port in the range (e.g. RandomOpenPort(8001..<9000))
    public func randomOpenPort(_ range: Range<Int>) -> Int {
        return RandomOpenPort(range)
    }
    
    /// Terminate the running executable if another copy of the executable is already running.
    public func exitAppIfAlreadyOpen() {
        ExitAppIfAlreadyOpen()
    }
    
    #endif
    
    /// Return the macOS system architecture.
    /// - Returns: The system architecture as a string (e.g. "arm64").
    public func systemArchitecture() -> String {
        return SystemArchitecture()
    }
    
    /// Converts an Encodeable object to a string
    /// - Parameter value: Object to encode.
    /// - Returns: encoded string.
    public func objectAsString<T>(_ value: T) throws -> String where T : Encodable {
        return String(data: try JSONEncoder().encode(value), encoding: .utf8)!
    }
    
    /// Authenticate using an additionalData String timestamp (tracking the current time as an Int64 since 1970 in milliseconds).
    /// - Parameter additionalData: The additionalData string
    /// - Returns: Authentication success or failure Bool.
    public func authTimestamp(_ additionalData: String) -> Bool {
        do {
            try authTimestampThrows(additionalData)
            return true
        } catch {
            print("authTimestamp error:", error)
            return false
        } 
    }

    public func authTimestampThrows(_ additionalData: String) throws {
    
        // Only process new messages
        guard let t = KeyExchangeTimestamp(additionalData) else {
            throw PollManagerError.timestampInvalidFormat
        }
        if t <= self.timestamp {
            throw PollManagerError.timestampExpired
        }
        
        // Allow up to 50 milliseconds of jitter
        let delta = KeyExchangeCurrentTimestamp()-t
        if delta < 0 {
            throw PollManagerError.timestampInPastError
        }
        if delta > 20 {
            throw PollManagerError.timestampInFutureError
        }
        self.timestamp = t
    }
    
    /// Decrypt data and decode JSON
    ///
    /// - Parameters:
    ///   - data: The URLSessionWebSocketTask.Message.
    ///   - kes: The KeyExchangeStore used to decrypt the data.
    ///   - auth: Function that validates whether the KeyExchangeStore additionalData is valid.
    /// - Throws: KeyExchangeError.invalidFormat
    /// - Returns: The decoded JSON.
    public func decryptAndDecodeJSON<T: Decodable>(
        data: Data,
        kes: KeyExchangeStore,
        auth: @escaping (String) throws -> Bool = { _ in return true }
    ) throws -> T {
        try _ = kes.ExternalPublicKey() // throws if no key
        let aeadStore = try JSONDecoder().decode(KeyExchangeAEADStore.self, from: data)
        let decryptedData = try kes.decryptAEADStore(aeadStore)
        let message = try JSONDecoder().decode(T.self, from: decryptedData)
        if try !auth(aeadStore.additionalData) {
            throw KeyExchangeError.invalidAdditionalData
        }
        return message
    }
    
    /// Publishes an Encodeable object to the localhost (i.e. http://127.0.0.1)
    /// - Parameters:
    ///   - value: Encodeable object to publish.
    ///   - port: URL port.
    ///   - path: URL path.
    ///   - bearerToken: Bearer token (defaults to none).
    /// - Returns: The server response as Data.
    public func publishLocal<T>(_ value: T, port: Int, path: String, bearerToken: String = "") async throws -> Data where T : Encodable {
        var components = URLComponents()
        components.scheme = "http"
        components.host = "127.0.0.1"
        components.port = port
        components.path = path
        guard let url = components.url else {
            throw PollManagerError.urlError
        }
        return try await publishWithURL(
            value,
            url: url,
            bearerToken: bearerToken
        )
    }
    
    /// Publishes an Encodeable object to tthe provided URL.
    /// - Parameters:
    ///   - value: Encodeable object to publish.
    ///   - url: The URL.
    ///   - bearerToken: Bearer token (defaults to none).
    /// - Returns: The server response as Data.
    public func publishWithURL<T>(_ value: T, url: URL, bearerToken: String = "") async throws -> Data where T : Encodable {

        // No timeout - long polling
        var request = URLRequest(url: url, timeoutInterval: 0.00)
        if bearerToken != "" {
            request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        }
        
        request.httpMethod = "POST"
        request.httpBody = try! JSONEncoder().encode(value)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: request)
        if (response as! HTTPURLResponse).statusCode != 200 {
            throw PollManagerError.publishFailure
        }
        return data
    }

    /// Start a the binary and optionally watch for public key Strings in the Privacy-Enhanced Mail (PEM) format
    /// - Parameters:
    ///   - binURL: URL of the binary to run
    ///   - withRetry: If true, restarts the binary if it exits.
    ///   - withPEMWatcher: Watch binary output for a public key String in the Privacy-Enhanced Mail (PEM) format, and update the KeyExchangeStore external public key using this PEM.
    ///   - pingTimeLimit: Time before the function calls pingTimeLimit - messages received will act as a pong() as will calling self.pong().
    ///   - pingTimeout: Triggers when pingTimeLimit is reached without any pongs.  Never triggered if pingTimeLimit <= 0.
    ///   - standardOutput: Send the binary standard output to the provided function.
    ///   - taskExitNotification: Send an Error? to the provided function each time the binary exits.
    public func subscribeWithBinary(
        binURL: URL,
        withRetry: Bool = false,
        withPEMWatcher: Bool = false,
        pingTimeLimit: TimeInterval = 0,
        pingTimeout: @escaping () -> Void = {},
        standardOutput: @escaping (String) -> Void  = { _ in },
        taskExitNotification: @escaping (Error?) -> Void  = { _ in }
    ) async {
        
        // Ping with timeout.
        if pingTimeLimit > 0 {
            self.timer = Timer.scheduledTimer(
                withTimeInterval: pingTimeLimit / 5,
                repeats: true
            ) { timer in
                self.pingCount += 1
                if self.pingCount >= 5 {
                    self.pingCount = 0
                    pingTimeout()
                }
            }
        }

        // Run the binary and connect to the websocket server.
        await self.processManager.RunProces(
            binURL: binURL,
            withRetry: withRetry,
            standardOutput: { result in
                standardOutput(result)
                DispatchQueue.main.async {
                    self.pong()
                }
                if withPEMWatcher {
                    guard let publicKey = PEMSearchString(result) else {
                        return
                    }
                    do {
                        try self.kes.setExternalPublicKey(publicKey)
                    } catch {
                        print("pem search parse error - reset:", error)
                        self.processManager.terminateCurrentTask()
                    }
                }
            },
            taskExitNotification: taskExitNotification
        )
    }
    
    public init(_ keyExchangeStoreFunction: @escaping () -> KeyExchangeStore = KeyExchange_Curve25519_SHA256_HKDF_AESGCM) {
        
        // Initiate keyExchangeStore
        self.keyExchangeStoreFunction = keyExchangeStoreFunction
        self.kes = self.keyExchangeStoreFunction()
        self.bearerToken = self.kes.LocalPublicKey()
    }
}
