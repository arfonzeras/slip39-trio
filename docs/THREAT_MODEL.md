# Threat model

## Asset

The **BIP39 entropy** (128 or 256 bits) behind a wallet mnemonic. Anyone who obtains it controls the funds.

## Sources

| Share | Lives on | Protected by |
|---|---|---|
| A | Mac | age encryption to a Secure Enclave P-256 key; Touch ID per decryption; offline gate |
| B | Android | AES-256-GCM, Android Keystore key (StrongBox if present); strong biometric per use; key invalidated on new biometric enrollment; offline gate |
| C | Paper | Physical custody, stored apart from both devices |

Threshold: any **2 of 3** reconstruct the secret. One share alone carries no information about it (Shamir).

## Adversaries and outcomes

| ID | Adversary | Gets | Outcome |
|---|---|---|---|
| A1 | Mac infostealer with the login password, a copy of the keychain and file grabbing (AMOS-like) | The encrypted share A file and the identity stub | **Nothing usable.** The Secure Enclave key is not exportable, so the ciphertext cannot be decrypted off-device. |
| A2 | Session hijack of email or cloud accounts | Whatever is stored there | **Nothing.** No share is ever stored in email or cloud. |
| A3 | Android malware without root | App-private files are not readable; the Keystore key is not exportable | **Nothing usable**, assuming no root exploit. |
| A4 | Theft of one device | One encrypted share | **Nothing.** Biometrics plus one share is still below the threshold. |
| A5 | Someone finds the paper | Share C | **Nothing** on its own. |
| A6 | Malware on Mac **and** Android | Potentially both shares, if the user unlocks both | **Compromise.** This exceeds the threshold. |
| A7 | Malware on the device performing **recovery** or **setup** | The full secret in memory | **Compromise.** See limit L1. |

## Explicit limits

**L1 — The reconstruction moment.** During setup (split) and recovery (combine), the full secret exists in the memory of one device. Malware on that device at that moment wins. Mitigations: perform both ceremonies on a freshly reset device, offline, and only rarely. Use the recovered mnemonic to set up a hardware wallet or multisig, not to sit on a laptop.

**L2 — The offline gate is a hygiene control, not a security boundary.** It prevents *live* exfiltration and remote-control sessions during the sensitive window, and it forces a deliberate ritual. It does **not** stop malware that records the secret and sends it after the device reconnects. A process running as your user could also tamper with the check itself. Do not treat "it was offline" as proof that nothing leaked.

**L3 — Biometric prompt approval.** Malware running as the user may trigger a legitimate Touch ID or BiometricPrompt request. If you approve a prompt you did not initiate, the share is decrypted. Rule: **never approve a biometric prompt you did not start yourself.**

**L4 — Memory hygiene is best effort.** Swift strings and JVM objects can be copied by the runtime. The code wipes buffers it controls, but it cannot guarantee that no copy remains in RAM.

**L5 — Terminal and display.** Revealing share A on the Mac prints it to the terminal (scrollback). Screen recorders or malicious accessibility apps can capture anything displayed.

**L6 — Supply chain.** A compromised build of slip39-trio, `age` or `age-plugin-se`, or a hijacked `PATH`, defeats everything. The macOS CLI calls binaries by absolute path and drops `DYLD_*` variables; vendored code is hash-pinned and checked in CI; releases must still be made reproducible and signed. CI checks catch accidental regressions, not a malicious maintainer.

**L7 — Biometric re-enrollment.** Adding a fingerprint on Android invalidates the share B key by design. Share B is then lost, and you fall back to A + C. Keep that in mind before changing biometrics.

**L8 — Side channels in SLIP-39.** The vendored SLIP-39 code (from Drongo) does its finite-field arithmetic with lookup tables, as Trezor's Python reference does, and is not hardened against timing or cache side channels. The reference implementation explicitly warns about this. The risk is reduced, not removed, by running the ceremonies rarely, offline, on a freshly reset phone with no other apps.

**L9 — Wrong passphrase gives a different wallet, not an error.** By SLIP-39 design, combining valid shares with a wrong passphrase yields another valid seed. Mitigation: at setup, write down the wallet's first receiving address next to share C; after recovery, check that the recovered wallet shows the same address before moving funds.

**L10 — Same seed, several splits.** Splitting the same seed twice produces two unrelated share sets. Shares from different sets cannot be mixed, but any two shares of the *old* set still recover the seed. If you re-split, destroy every share of the old set.

## Non-goals

- Protecting a hot wallet used daily.
- Defending against a state-level adversary with physical access and hardware attacks against the Secure Enclave or StrongBox.
- Replacing on-chain multisig, which protects funds even when a full key leaks.
