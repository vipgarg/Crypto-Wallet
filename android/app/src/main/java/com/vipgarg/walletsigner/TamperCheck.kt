package com.vipgarg.walletsigner

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import uniffi.signer_ffi.checkAttestation

/**
 * Tamper check (verified boot) with Android key attestation: the secure
 * hardware creates a throw-away key and certifies the device's boot state.
 * The certificate chain must lead to one of Google's attestation roots
 * (pinned below); the Rust core then reads the boot state. Offline: the
 * revocation list can't be checked.
 */
object TamperCheck {
    /**
     * SHA-256 of the SubjectPublicKeyInfo of Google's hardware attestation
     * roots, from github.com/android/keyattestation `roots.json`: the RSA
     * root (serialNumber f92009e853b6b045) and the EC "Key Attestation CA1"
     * (2025).
     */
    private val GOOGLE_ROOTS = setOf(
        "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
        "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
    )
    private const val OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val ALIAS = "tamper-check"

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /** (passed, explanation) */
    fun run(): Pair<Boolean, String> = try {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setAttestationChallenge(challenge)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()
        val chain = ks.getCertificateChain(ALIAS)?.map { it as X509Certificate }.orEmpty()
        ks.deleteEntry(ALIAS)
        if (chain.size < 2) {
            false to "The tablet gave no attestation certificate chain."
        } else {
            for (i in 0 until chain.size - 1) chain[i].verify(chain[i + 1].publicKey)
            val root = chain.last()
            root.verify(root.publicKey)
            val rootHash = hex(MessageDigest.getInstance("SHA-256").digest(root.publicKey.encoded))
            if (rootHash !in GOOGLE_ROOTS) {
                false to "The attestation doesn't lead to Google's attestation root (root ${rootHash.take(16)}…). The device's report can't be trusted."
            } else {
                val ext = chain[0].getExtensionValue(OID)
                if (ext == null) {
                    false to "The attestation certificate has no device report."
                } else {
                    val r = checkAttestation(ext, challenge)
                    r.passed to r.detail
                }
            }
        }
    } catch (e: Exception) {
        false to "The tamper check couldn't run: ${e.message ?: e.javaClass.simpleName}."
    }
}
