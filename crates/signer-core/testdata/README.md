Key attestation extensions (OID 1.3.6.1.4.1.11129.2.1.17) taken from the leaf
certificates of real attestation chains in Google's `android/keyattestation`
repository (Apache License 2.0), `testdata/`:

- `attest_unlocked_pixel.der`: `akita/sdk34/TEE_EC_NONE.pem` (bootloader
  unlocked, verified boot "Unverified").
- `attest_locked_pixel.der`: `caiman/sdk36/TEE_EC_RKP.pem` (locked, verified
  boot "Verified").
