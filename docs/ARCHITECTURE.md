# Architecture

## Components

```
            ┌──────────────── setup ceremony (Android, offline) ────────────────┐
 BIP39      │  mnemonic ──► entropy ──► SLIP-39 split (2-of-3, optional pass)   │
 mnemonic ──┤                                  │          │          │         │
            │                              share A    share B    share C       │
            └──────────────────────────────────┼──────────┼──────────┼─────────┘
                                               ▼          ▼          ▼
                                     Mac: age → SE   Keystore    paper
                                     (Touch ID)      AES-GCM     (handwritten)
                                                     (biometric)
```

Recovery is the reverse: any two shares → SLIP-39 combine → entropy → BIP39 mnemonic.

## Why the ceremonies run on Android

The Mac is the device with the documented infostealer history in our threat model (AMOS-class malware). Android's app sandbox, a non-exportable Keystore and `FLAG_SECURE` make it the better place for the moment when the full secret exists in memory. Recommended practice: run setup on a phone that was **factory-reset**, has **no other apps** installed, and is in **airplane mode**.

The Mac only ever sees share A.

## Crypto parameters

| Item | Choice | Notes |
|---|---|---|
| Secret sharing | SLIP-0039, 1 group, 2-of-3 | Backend: SLIP-39 code vendored from Drongo (Sparrow Wallet), validated against all 45 official Trezor vectors. Extendable flag on and iteration exponent 1, matching the reference implementation's defaults. |
| Secret | BIP39 entropy (16–32 bytes, any BIP39 length) | Own Kotlin BIP39 conversion (no seed derivation), validated against the 24 official English vectors. Recovery returns the original BIP39 mnemonic. |
| Share size | 20 words (128-bit seed), 33 words (256-bit seed) | |
| Share A at rest | age, recipient `age1se1…` (age-plugin-se) | Key generated with `--access-control=any-biometry`. |
| Share B at rest | AES-256-GCM, 96-bit random IV, 128-bit tag | Keystore key: `setUserAuthenticationRequired(true)`, `AUTH_BIOMETRIC_STRONG`, timeout 0 (auth per use), `setInvalidatedByBiometricEnrollment(true)`, StrongBox when available. |
| Share C | SLIP-39 words on paper | Never photographed, never typed into a networked device. |

## Offline gate

| Platform | Check | Blocks if |
|---|---|---|
| macOS | `NWPathMonitor` current path | status is not `.unsatisfied` |
| Android | `ConnectivityManager.allNetworks` + airplane-mode setting | any network exists, or airplane mode is off |

The gate runs **before** biometrics and **again after** decryption, before displaying anything. See THREAT_MODEL limit L2 for what it does not guarantee.

## Moving share A between devices

1. During setup, Android shows share A words on screen (`FLAG_SECURE`, so no screenshots).
2. You type them into `slip39-trio-mac seal` on the Mac, offline.
3. Planned: a QR transfer so share A is never typed (roadmap).

## Code layout on Android

- `android/core` — pure JVM, no Android dependency: `Bip39`, the `Slip39` interface with its `DrongoSlip39` adapter, and `Slip39Trio` (split / recover). Standalone Gradle build so the vectors run anywhere; the app pulls it in with `includeBuild("core")`.
- `android/app` — Android-only pieces: `KeystoreVault` (share B), `OfflineGate`, and the UI (roadmap).

The adapter normalizes input (case, whitespace), rejects unknown words before they reach Drongo, and builds error messages from word **positions only**, so a crash report never contains seed or share words. `Slip39Trio.Shares.toString()` is redacted for the same reason.

## Design decisions

- **No custom crypto.** Only age, CryptoKit (via age-plugin-se), Android Keystore and an audited SLIP-39 library.
- **No network permission** in the Android manifest: the app cannot open sockets itself. The offline gate is about *other* processes on the device.
- **No backups** of app data (`allowBackup=false`, data in `noBackupFilesDir`), so share B never reaches Google cloud backup.
- **Absolute binary paths** on macOS, no shell, plaintext only over stdin pipes, never in arguments (arguments are visible in `ps`).
