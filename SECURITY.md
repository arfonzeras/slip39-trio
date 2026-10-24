# Security policy

## Status

**Experimental and unaudited.** Do not protect real funds with slip39-trio yet.

Release gate (all required before a 1.0):

1. ✅ SLIP-39 and BIP39 code pass the official Trezor test vectors on the JVM (`gradle -p android/core test`).
2. ⬜ The same vectors pass in an instrumented test on a real Android device.
3. ⬜ Reproducible, signed builds for the macOS CLI and the Android APK.
4. ⬜ Independent security review of the code and of the ceremonies.

## Third-party code

The SLIP-39 implementation is vendored from Drongo (Sparrow Wallet), Apache-2.0. See `android/third_party/drongo-slip39/NOTICE` for the exact commit and the two small modifications. Updates must be re-vendored deliberately and must keep passing the official vectors; never edit the vendored files beyond what the NOTICE lists.

The SHA-256 of every vendored file, word list and vector file is pinned in `android/third_party/SHA256SUMS`, and CI fails if any of them changes. A pull request that touches those hashes deserves a line-by-line review.

## Automated guards

- The Android app must never gain network access: CI fails if the merged manifest requests `INTERNET` or any permission outside a short allowlist (`android/scripts/check-manifest.py`).
- Backups stay off and release builds are never debuggable (same script).
- The Mac CLI's offline gate is exercised on every push: `reveal` must refuse to run on the (online) CI runner.

## Reporting a vulnerability

Please report privately via GitHub Security Advisories on this repository ("Report a vulnerability"). Do not open a public issue for security problems.

## Never

- Never paste a real seed, share or mnemonic into an issue, a PR, a log or a chat (including AI assistants).
- Never use a real seed in tests. The test suite generates throwaway random seeds and uses the published vectors only.
- Never approve a Touch ID or fingerprint prompt you did not start yourself.
