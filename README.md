# slip39-trio

**Back up a BIP39 seed as three SLIP-39 shares on things you already own — a Mac, an Android phone and a sheet of paper. Any two shares recover it.**

One share alone reveals nothing about the seed, so an infostealer that copies what is stored on one device gets nothing usable. Shares on the Mac and the phone are encrypted with hardware keys (Secure Enclave, Android Keystore) that need your fingerprint for every use.

> **Status: experimental, unaudited.** Do not protect real funds with this until it has passed an external review. See [SECURITY.md](SECURITY.md).

## Why this exists

Two common attack paths make "encrypted storage" of a seed phrase much weaker than it looks:

1. **macOS infostealers** (e.g. the Atomic Stealer / AMOS family) show a fake system password dialog via `osascript`, use the captured login password to unlock `login.keychain-db`, and exfiltrate it along with browser data and wallet files.
2. **Session hijacking**: a stolen browser session cookie lets an attacker into an account — including an end-to-end encrypted mailbox — without the password or the second factor. End-to-end encryption protects you from the provider, not from someone who *is* you.

If a seed lives in one place that a single compromise can reach, it is gone. slip39-trio makes sure no single place holds enough to reconstruct it.

## How it works

- **2-of-3 Shamir secret sharing** ([SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)) over the **BIP39 entropy**. Recovery outputs the same standard BIP39 mnemonic, which any wallet can import.
- **Share A — Mac**: encrypted with [age](https://age-encryption.org) to a **Secure Enclave** key via [age-plugin-se](https://github.com/remko/age-plugin-se). The private key cannot leave the chip, and every decryption requires Touch ID.
- **Share B — Android**: AES-256-GCM with an **Android Keystore** key (StrongBox when available). Strong biometrics are required on every use, and the key is invalidated if a new fingerprint is enrolled.
- **Share C — paper**: written by hand, stored physically elsewhere.
- **Offline gate + biometrics**: every operation that touches a share refuses to run while the device has a network path, and requires biometric authentication.
- **Optional SLIP-39 passphrase**: adds a knowledge factor on top of the 2-of-3 split. A wrong passphrase does not fail: it silently recovers a *different* valid wallet (see THREAT_MODEL L9).

Any one source (Mac, phone or paper) reveals **zero information** about the seed. This is a mathematical property of Shamir's scheme, not an implementation detail.

The SLIP-39 code is not home-grown: it is vendored from [Drongo](https://github.com/sparrowwallet/drongo), Sparrow Wallet's Java library (Apache-2.0), and checked against Trezor's **official test vectors** on every test run.

## What it does NOT protect against

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before using it. In short:

- Malware on the device where you **reconstruct** the seed, at the moment you reconstruct it.
- An attacker who controls **two of the three** sources.
- You approving a biometric prompt you did not initiate.
- The **setup ceremony** running on an already-compromised device.

**slip39-trio is a backup and recovery tool, not a daily-use wallet.** For funds you move regularly, use a hardware wallet or on-chain multisig.

## Running the tests

The crypto core is plain JVM code, so it runs on any machine with JDK 17+ (no Android SDK needed):

```
./android/gradlew -p android/core test
```

This runs all 45 official SLIP-39 vectors and 24 official BIP39 vectors, plus the 2-of-3 ceremony properties (any two shares recover, one share alone is rejected, corrupted shares are rejected, error messages never contain seed words).

## Continuous integration

Every push runs three workflows:

| Workflow | What it checks |
|---|---|
| `core-tests` | Official vectors and ceremony tests; vendored code, word lists and vectors match the hashes pinned in `android/third_party/SHA256SUMS`; the Gradle wrapper is genuine. |
| `android-build` | The app compiles (debug and release) and passes Android lint; the **merged** manifest has no `INTERNET` permission, no backups, no unguarded exported components, and the release build is not debuggable. |
| `macos-build` | The Mac CLI compiles on Apple Silicon, and `reveal` refuses to run while the machine is online. |

Dependabot proposes updates for GitHub Actions and Gradle dependencies weekly.

## Repository layout

```
docs/
  THREAT_MODEL.md        assets, adversaries, guarantees, explicit limits
  ARCHITECTURE.md        ceremonies, crypto parameters, design decisions
macos/                   Swift CLI: seal / reveal share A (age + age-plugin-se)
android/
  core/                  pure-JVM crypto: BIP39, SLIP-39 adapter, Slip39Trio ceremonies, tests
    src/main/java/com/sparrowwallet/drongo/   vendored SLIP-39 (see third_party/)
  app/                   Android: Keystore vault, offline gate (UI on the roadmap)
  scripts/               check-manifest.py, the merged-manifest security guard
  third_party/           licenses, NOTICE files and pinned hashes (SHA256SUMS)
.github/workflows/       CI: core tests, Android build, macOS build
SECURITY.md              status, release gate, how to report vulnerabilities
```

## Roadmap

- [x] SLIP-39 backend passing the official Trezor test vectors (JVM)
- [x] BIP39 entropy ⇄ mnemonic conversion with checksum validation, passing the official vectors
- [ ] Run the same vectors **on a real Android device** (instrumented test): the crypto provider and the record/stream desugaring differ from the desktop JVM
- [ ] Android setup and recovery UI (`FLAG_SECURE`, no clipboard)
- [x] CI: compile Android and macOS, manifest and supply-chain guards
- [ ] macOS CLI hardening (signed, notarized build)
- [ ] QR transfer of share A, so it is never typed
- [ ] Bluetooth / NFC checks in the offline gate
- [ ] External security review

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions: the vendored SLIP-39 code from Drongo (Apache-2.0) and Trezor's test vectors and word list (MIT) keep their own licenses, in `android/third_party/`.
