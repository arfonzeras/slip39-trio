// SPDX-License-Identifier: Apache-2.0
// slip39-trio-mac — seal / reveal share A with age + age-plugin-se (Secure Enclave, Touch ID).
//
// EXPERIMENTAL, UNAUDITED. See docs/THREAT_MODEL.md.
//
// Usage:
//   slip39-trio-mac init                     generate the Secure Enclave identity (Touch ID bound)
//   slip39-trio-mac seal                     read share A from the terminal (no echo), encrypt it
//   slip39-trio-mac reveal                   decrypt share A (Touch ID) and print it
//
// Requirements: `brew install age age-plugin-se`

import Foundation
import Network
import Darwin

// MARK: - Configuration

let home = FileManager.default.homeDirectoryForCurrentUser
let stateDir = home.appendingPathComponent(".slip39-trio", isDirectory: true)
let identityFile = stateDir.appendingPathComponent("identity.txt")   // SE key stub, useless off this Mac
let recipientFile = stateDir.appendingPathComponent("recipient.txt")
let shareFile = stateDir.appendingPathComponent("share-a.age")

/// Only these absolute locations are trusted (Apple Silicon and Intel Homebrew).
/// We never resolve binaries through $PATH, which malware can hijack.
let trustedBinDirs = ["/opt/homebrew/bin", "/usr/local/bin"]

func trustedBinary(_ name: String) -> URL {
    for dir in trustedBinDirs {
        let path = "\(dir)/\(name)"
        if FileManager.default.isExecutableFile(atPath: path) { return URL(fileURLWithPath: path) }
    }
    fail("\(name) not found in \(trustedBinDirs). Install with: brew install age age-plugin-se")
}

// MARK: - Helpers

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("error: \(msg)\n".utf8))
    exit(1)
}

/// Offline gate. Hygiene control only (THREAT_MODEL L2): it blocks live exfiltration
/// during the sensitive window, not malware that waits for the network to come back.
/// Thread-safe holder for the first path status reported by NWPathMonitor.
final class PathStatusBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: NWPath.Status?
    func set(_ s: NWPath.Status) { lock.lock(); if value == nil { value = s }; lock.unlock() }
    func get() -> NWPath.Status? { lock.lock(); defer { lock.unlock() }; return value }
}

func requireOffline() {
    let monitor = NWPathMonitor()
    let sem = DispatchSemaphore(value: 0)
    let box = PathStatusBox()
    monitor.pathUpdateHandler = { path in
        box.set(path.status)
        sem.signal()
    }
    monitor.start(queue: DispatchQueue(label: "slip39-trio.offline"))
    _ = sem.wait(timeout: .now() + 3)
    monitor.cancel()
    // No answer within 3 s counts as "online": fail closed.
    guard box.get() == .unsatisfied else {
        fail("network path detected. Turn off Wi-Fi, unplug Ethernet and disable other interfaces, then retry.")
    }
}

/// Reads a line from the terminal without echo (uses readpassphrase(3)).
func readSecret(prompt: String) -> [UInt8] {
    var buf = [CChar](repeating: 0, count: 1024)
    guard readpassphrase(prompt, &buf, buf.count, RPP_REQUIRE_TTY) != nil else { fail("could not read from terminal") }
    let len = strlen(buf)
    let bytes = buf.prefix(len).map { UInt8(bitPattern: $0) }
    memset_s(&buf, buf.count, 0, buf.count)   // wipe our copy (best effort, THREAT_MODEL L4)
    return bytes
}

/// Runs a binary without a shell. Secrets go through stdin only, never through arguments.
@discardableResult
func run(_ exe: URL, _ args: [String], stdin: [UInt8]? = nil) -> Data {
    let p = Process()
    p.executableURL = exe
    p.arguments = args
    // Keep the user's environment (HOME etc.) but force PATH to the trusted dirs,
    // so `age` can only find the age-plugin-se binary there.
    var env = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("DYLD_") }  // no injected dylibs
    env["PATH"] = trustedBinDirs.joined(separator: ":")
    p.environment = env
    let inPipe = Pipe(), outPipe = Pipe()
    p.standardInput = inPipe
    p.standardOutput = outPipe
    p.standardError = FileHandle.standardError
    do { try p.run() } catch { fail("cannot start \(exe.path): \(error)") }
    if let s = stdin { inPipe.fileHandleForWriting.write(Data(s)) }
    try? inPipe.fileHandleForWriting.close()
    let out = outPipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    guard p.terminationStatus == 0 else { fail("\(exe.lastPathComponent) exited with \(p.terminationStatus)") }
    return out
}

func ensureStateDir() {
    try? FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true,
                                             attributes: [.posixPermissions: 0o700])
}

// MARK: - Commands

func cmdInit() {
    ensureStateDir()
    guard !FileManager.default.fileExists(atPath: identityFile.path) else { fail("identity already exists at \(identityFile.path)") }
    run(trustedBinary("age-plugin-se"), ["keygen", "--access-control=any-biometry", "-o", identityFile.path])
    let recipient = run(trustedBinary("age-plugin-se"), ["recipients", "-i", identityFile.path])
    try? recipient.write(to: recipientFile, options: .atomic)
    print("Secure Enclave identity created. Decrypting share A will require Touch ID on this Mac.")
}

func cmdSeal() {
    requireOffline()
    guard let recipient = try? String(contentsOf: recipientFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
          recipient.hasPrefix("age1se1") else { fail("no Secure Enclave recipient found. Run `init` first.") }
    guard !FileManager.default.fileExists(atPath: shareFile.path) else { fail("share A already sealed at \(shareFile.path)") }
    var secret = readSecret(prompt: "Share A words (input hidden): ")
    defer { secret.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
    guard !secret.isEmpty else { fail("empty input") }
    run(trustedBinary("age"), ["-r", recipient, "-o", shareFile.path], stdin: secret)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: shareFile.path)
    print("Share A sealed to the Secure Enclave: \(shareFile.path)")
}

func cmdReveal() {
    requireOffline()
    guard FileManager.default.fileExists(atPath: shareFile.path) else { fail("no sealed share A at \(shareFile.path)") }
    print("Touch ID will be requested by age-plugin-se. Approve it only because YOU just ran this command.")
    var plain = run(trustedBinary("age"), ["--decrypt", "-i", identityFile.path, shareFile.path])
    requireOffline()   // re-check before displaying anything
    FileHandle.standardOutput.write(plain)
    plain.resetBytes(in: 0..<plain.count)
    print("\nClear your terminal scrollback when done (THREAT_MODEL L5).")
}

// MARK: - Entry point

switch CommandLine.arguments.dropFirst().first {
case "init":   cmdInit()
case "seal":   cmdSeal()
case "reveal": cmdReveal()
default:
    print("usage: slip39-trio-mac init | seal | reveal")
    exit(2)
}
