# Offline Signer App (OnePlus tablet) — Phase 2 plan

**Status (2026-11-02):** the Rust core (`crates/signer-core`) and the Kotlin bridge (`crates/signer-ffi`, UniFFI) are built and tested. The Android app (screens) is not built yet. **No signing yet**: signing comes later in Phase 2, on testnets first.

Design references: ARCHITECTURE-MOBILE.md §2, §4, §5.1a; ARCHITECTURE.md §6, §7 ⑦.

## What exists now

| Part | Status | Tests |
|---|---|---|
| Seed creation: OS randomness + ≥ 99 dice rolls (SHA-256 mix), 24 words | ✅ | dice parsing, mixing depends on both inputs |
| Restore from 12/24 words (checksum checked) | ✅ | wrong word rejected |
| Word check ("type words #3, #11, #17, #22") | ✅ | |
| Passphrase + master fingerprint (catches a mistyped passphrase) | ✅ | BIP-39 "TREZOR" reference vector |
| Public data: BTC zpub (`m/84'/0'/0'`), ETH and TRON addresses | ✅ | BIP-84 zpub, first BTC/ETH addresses, fingerprint `73c5da0a` |
| Encrypted vault per stored wallet (Argon2id 256 MiB + XChaCha20-Poly1305); Vault tier refused (stateless) | ✅ | wrong password, wrong passphrase, nothing readable |
| Watch-only export `WWX1:…#checksum` for the PC (QR) | ✅ | damage, tampering, smuggled fields rejected |
| Kotlin bindings (UniFFI) | ✅ generated | end-to-end test through the FFI layer |
| No network code in the signer's dependency tree | ✅ | checked with `cargo tree` |

## The Android app (next)

**Technology:** Kotlin + Jetpack Compose screens; all logic in Rust via the generated bindings. No WebView.

**Manifest and security settings (ARCHITECTURE-MOBILE.md §5.1):**
- **No `INTERNET` permission** (Android then blocks all network access for the app).
- `android:allowBackup="false"`, excluded from device-to-device transfer.
- `FLAG_SECURE` on every screen (no screenshots, screen recording or recent-apps preview).
- Secrets typed only on the app's own in-app keyboard.
- Start-up checks refuse to continue unless: airplane mode on, no network connected, no SIM, USB debugging off, no accessibility service or overlay active, verified boot green (key attestation), no screen recording/casting. Reports whether keys are StrongBox- or TEE-backed.
- Vault files in app-private storage; the vault key can additionally be wrapped with Android Keystore.

**Screens, first version (no signing):**
1. Start-up checks.
2. Create wallet: tier, id, label → dice entry → 24 words shown once → word check → passphrase (Savings/Vault) → vault password (Spending/Savings) or SeedQR card (Vault).
3. Wallet list (public data only).
4. Show watch-only export as QR (for the PC app).
5. Verify address: show the BTC receive address #n, or the ETH/TRON address, for comparison with the PC Receive page.
6. Restore wallet from words (recovery test).

**Also needed on the PC side:** "Add wallet from signer": scan the export QR with the PC webcam (or paste the export text), validated by the same rules as `export::decode`.

## First Android build (testnet) — what's in it

Built by `.github/workflows/android.yml` (decision: Option A, GitHub Actions).

- Screens: safety checks → wallet list → create (dice, 24 words, word check, passphrase, vault password) / restore from words → wallet detail → export QR for the PC, verify Bitcoin/Ethereum/TRON address (QR + text with bold ends).
- Guard in CI: the build fails if the APK requests `INTERNET` permission.
- **Known limits of this first build (to fix before real funds):**
  - Debug-signed: GitHub's runner creates a new debug key each run, so installing a newer build means **uninstalling the old one, which deletes the test wallets** on the tablet (restore them from their words). A fixed release signing key comes later.
  - Passwords, passphrases and words typed in the app pass through Kotlin strings, which the JVM can't wipe from memory (the Rust side wipes its copies).
  - The system keyboard is used (with suggestions off); the in-app keyboard is still to do.
  - Not yet checked at start-up: verified-boot state (key attestation) and screen recording.

## Installing a test build on the tablet

1. On GitHub: **Actions → "Android signer (testnet)" → latest green run → Artifacts**, download `wallet-signer-testnet-<commit>`. It contains the APK and a `.sha256` file.
2. On the PC, check the hash (PowerShell): `Get-FileHash .\wallet-signer-testnet-XXXXXXX.apk -Algorithm SHA256`, and compare with the `.sha256` file and the value shown in the GitHub run log.
3. On the tablet (still before any real seed exists): enable Developer options → USB debugging, connect the cable, run `adb install wallet-signer-testnet-XXXXXXX.apk` from the PC.
4. Turn USB debugging and Developer options **off**, unplug, keep airplane mode on. The app's safety checks won't let you continue otherwise.

## How the APK gets built

This development environment can't download Google's Android SDK, so the APK must be built elsewhere:

| Option | How | Notes |
|---|---|---|
| **A. GitHub Actions (recommended)** | A workflow builds the Rust core for `aarch64-linux-android`, generates the bindings, runs Gradle and uploads the APK plus its SHA-256 as a build artifact | GitHub's runners include the Android SDK/NDK. Builds are reproducible from the reviewed commit. The APK is installed on the tablet with a USB cable (`adb install`) after checking the hash, as in §5.1a |
| B. Android Studio on the owner's PC | Install Android Studio (~10 GB) + NDK; `cargo install cargo-ndk`; build locally | More setup; the development PC becomes part of the build chain (T21) |

Either way, the release APK is signed with a key kept off the development machine, and the signer checks its own signing-certificate fingerprint on first start (§5.1a step 11).
