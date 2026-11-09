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

**PC side (built):** Wallets page → "Add a wallet from the signer tablet". The webcam reads the export QR (jsQR, in the app window); the text goes to Rust, which decodes it with the same shared code as the tablet (`crates/watch-export`) and re-checks every field. The PC then shows the fingerprint, Bitcoin receive address #0 (derived on the PC), Ethereum and TRON addresses; the user compares them with the tablet screen and ticks a box before **Add this wallet** is enabled. The add step checks the export again from scratch. Imported wallets are marked "From the signer tablet · fingerprint …". The camera runs only while the scan panel is open.

## First Android build (testnet) — what's in it

Built by `.github/workflows/android.yml` (decision: Option A, GitHub Actions).

- Screens: safety checks → wallet list → create (dice, 24 words, word check, passphrase, vault password) / restore from words → wallet detail → export QR for the PC, verify Bitcoin/Ethereum/TRON address (QR + text with bold ends).
- Restore from words: 12 or 24 numbered boxes, one word each. Words are hidden except the box being typed in (or the one whose **Show** was tapped), so only one word is readable at a time. Errors name the problem exactly: wrong word count, an empty box, word #n not in the BIP-39 list, or a checksum mismatch (a wrong valid word or two words swapped). The word itself is never shown in an error. The write-down check also names which word numbers don't match.
- Guard in CI: the build fails if the APK requests `INTERNET` permission.
- **Known limits of this first build (to fix before real funds):**
  - Debug-signed: GitHub's runner creates a new debug key each run, so installing a newer build means **uninstalling the old one, which deletes the test wallets** on the tablet (restore them from their words). A fixed release signing key comes later.
  - Passwords, passphrases and words typed in the app pass through Kotlin strings, which the JVM can't wipe from memory (the Rust side wipes its copies).

## Test network screens (Phase 2)

TRON Nile (USDT): wallet → **Test network** → unlock → **Sign a TRON test payment (Nile USDT)**: scan the PC's `WTR1` QR, check, type the recipient's last 6 characters (case-sensitive), sign, show the `WTS1` QR. See docs/phase2-tron-testnet.md.


Wallet → **Test network (signet)** (Spending/Savings wallets): unlock with the vault password (and passphrase), then:
- **Show test export QR**: the `m/84'/1'/0'` test key for the PC's Test send page.
- **Sign a test payment**: the camera reads the PC's payment QR (CameraX + ZXing, offline). The tablet shows network, recipient (grouped, bold ends), amount, fee, change and the transaction ID start, all worked out on the tablet. You type the recipient's **last 6 characters from your paper**; then it signs and shows the signed QR for the PC.
- The wallet locks again (key material wiped) when you leave the screen.
- Permissions: **CAMERA** is added (QR reading only). The build fails if the APK requests INTERNET or any permission not on the reviewed list.

## Hardening (built)

| Item | What it does |
|---|---|
| App keyboard | Seed words (a–z only), passwords and passphrases (letters, Shift, digits, symbols), dice (1–6) and the approval characters are typed on the app's own keyboard, docked at the bottom. The system keyboard never opens for them, so nothing is learned, suggested or sent. Wallet ID and label (not secret) still use the system keyboard. |
| Screen recording / casting | Android 15's screen-recording callback (`DETECT_SCREEN_RECORDING` permission) and a presentation-display listener: while recorded or cast, every screen is hidden. `FLAG_SECURE` already blanks screenshots and recordings. |
| Tamper check (verified boot) | Start-up check (critical): the secure hardware creates a throw-away key with a fresh challenge; the certificate chain must verify up to one of Google's pinned attestation roots (RSA root and "Key Attestation CA1", from github.com/android/keyattestation `roots.json`); the Rust core reads the root of trust: bootloader **locked** and verified boot **Verified** are required. Tested against real attestations from Google's test data (a locked Pixel passes, an unlocked one fails). Limit: attestation-key revocation can't be checked offline. |
| Fixed signing key | When the repository has the secrets `SIGNER_KEYSTORE_B64`, `SIGNER_KEYSTORE_PASSWORD` and `SIGNER_KEY_ALIAS`, CI builds a **release** APK (not debuggable) signed with that key, so updates install with `adb install -r` and keep the wallets. Without them, a debug build as before. Still to do once the key exists: the app checks its own signing-certificate fingerprint at start. |

## Allowlist, limits and signing log

Test networks → (unlock) → **Allowlist, limits and signing log**. The tablet signs only to addresses on this wallet's own list, after a waiting period (10 minutes on test networks, 24 hours on real ones), and only up to the daily limits, whatever the PC asks. Type addresses from the paper address book or scan them from the recipient's own device, never from the PC. Every signature is logged (hash-chained) before it is shown, and its log number goes to the PC, which warns if numbers were skipped. Details: docs/phase2-tron-testnet.md.

**After updating the app:** add your test recipients to the allowlist and wait 10 minutes before the next test payment.

## Restore: confirm the fingerprint

After a restore (and the passphrase, for Savings/Vault), the tablet shows the wallet's **fingerprint** and its TRON and Ethereum addresses and asks whether they match your paper or the PC's Wallets page. A mistyped passphrase (typed the same way twice) is otherwise silently accepted and opens a different, empty wallet. "Doesn't match" goes back to the passphrase (or the words). Write each wallet's fingerprint on its paper when you create it.

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
