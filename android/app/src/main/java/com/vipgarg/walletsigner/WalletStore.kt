package com.vipgarg.walletsigner

import org.json.JSONObject
import uniffi.signer_ffi.WalletPublicRecord
import java.io.File

/** Public record of a wallet on the signer (no secrets). */
data class WalletEntry(
    val id: String,
    val label: String,
    /** "spending", "savings" or "vault". */
    val tier: String,
    val usesPassphrase: Boolean,
    val public: WalletPublicRecord,
    /** Made by a real-networks build: signs real money only (sealed in its vault too). */
    val real: Boolean = BuildConfig.REAL_NETWORKS,
) {
    val tierName: String
        get() = when (tier) {
            "vault" -> "T-0 Vault"
            "savings" -> "T-1 Savings"
            "spending" -> "T-2 Spending"
            else -> tier
        }

    /** Vault-tier seeds are never stored on the tablet (stateless). */
    val stateless: Boolean get() = tier == "vault"
}

/**
 * App-private storage (never backed up or transferred):
 * - wallets/<id>.json: public record
 * - wallets/<id>.vault: encrypted seed (Spending and Savings only)
 * - wallets/<id>.policy: allowlist, limits and signing log (sealed)
 */
class WalletStore(filesDir: File) {
    private val dir = File(filesDir, "wallets").apply { mkdirs() }

    fun list(): List<WalletEntry> =
        dir.listFiles { f -> f.name.endsWith(".json") }
            ?.mapNotNull { runCatching { parse(JSONObject(it.readText())) }.getOrNull() }
            ?.sortedBy { it.id }
            ?: emptyList()

    fun exists(id: String): Boolean = File(dir, "$id.json").exists()

    fun save(entry: WalletEntry, vault: ByteArray?) {
        if (vault != null) atomicWrite(File(dir, "${entry.id}.vault"), vault)
        val json = JSONObject()
            .put("id", entry.id)
            .put("label", entry.label)
            .put("tier", entry.tier)
            .put("uses_passphrase", entry.usesPassphrase)
            .put("fingerprint", entry.public.fingerprint)
            .put("btc_zpub", entry.public.btcZpub)
            .put("eth", entry.public.eth)
            .put("tron", entry.public.tron)
            .put("real", entry.real)
        atomicWrite(File(dir, "${entry.id}.json"), json.toString(2).toByteArray())
    }

    fun vault(id: String): ByteArray? = File(dir, "$id.vault").takeIf { it.exists() }?.readBytes()

    /**
     * The wallet's signing policy (allowlist, limits, signing log), sealed
     * by Rust with a key from the seed; null before the first change.
     */
    fun policy(id: String): ByteArray? = File(dir, "$id.policy").takeIf { it.exists() }?.readBytes()

    fun savePolicy(id: String, bytes: ByteArray) = atomicWrite(File(dir, "$id.policy"), bytes)

    fun deletePolicy(id: String) {
        File(dir, "$id.policy").delete()
    }

    private fun parse(o: JSONObject) = WalletEntry(
        id = o.getString("id"),
        label = o.getString("label"),
        tier = o.getString("tier"),
        usesPassphrase = o.getBoolean("uses_passphrase"),
        public = WalletPublicRecord(
            fingerprint = o.getString("fingerprint"),
            btcZpub = o.getString("btc_zpub"),
            eth = o.getString("eth"),
            tron = o.getString("tron"),
        ),
        real = o.optBoolean("real", false),
    )

    /** Write a temp file, then rename, so a crash can't leave half a file. */
    private fun atomicWrite(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.outputStream().use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            target.delete()
            check(tmp.renameTo(target)) { "could not save ${target.name}" }
        }
    }
}
