package com.vipgarg.walletsigner

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import uniffi.signer_ffi.PolicyRecord
import uniffi.signer_ffi.UnlockedWallet
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private sealed interface PolicyStep {
    data object Main : PolicyStep
    data class Add(val net: String, val netName: String) : PolicyStep
    data class ScanAddress(val net: String, val netName: String) : PolicyStep
    data class ConfirmAdd(val net: String, val netName: String, val address: String) : PolicyStep
    data class Limit(val asset: String, val name: String, val unit: String, val daily: String) : PolicyStep
    data object Log : PolicyStep
    data object Wait : PolicyStep
}

internal fun now(): ULong = System.currentTimeMillis().toULong()

internal fun waitText(minutes: ULong): String = when {
    minutes >= 60uL && minutes % 60uL == 0uL -> "${minutes / 60uL} hour" + if (minutes == 60uL) "" else "s"
    else -> "$minutes minute" + if (minutes == 1uL) "" else "s"
}

private fun time(ms: ULong): String =
    SimpleDateFormat("d MMM yyyy, HH:mm", Locale.getDefault()).format(Date(ms.toLong()))

/** "tron:T…?amount=1" or "ethereum:0x…@11155111" → the bare address. */
private fun bareAddress(scanned: String): String =
    scanned.trim()
        .substringAfter(':')
        .substringBefore('?')
        .substringBefore('@')
        .substringBefore('/')
        .trim()

/**
 * This wallet's signing policy: the tablet's own allowlist of recipients,
 * daily limits, and the log of everything signed. Changes need the wallet
 * unlocked (the policy is sealed with a key from its seed).
 */
@Composable
fun PolicyScreen(w: UnlockedWallet, entry: WalletEntry, store: WalletStore, onBack: () -> Unit) {
    var step by remember { mutableStateOf<PolicyStep>(PolicyStep.Main) }
    var error by remember { mutableStateOf<String?>(null) }
    var view by remember { mutableStateOf<PolicyRecord?>(null) }

    fun reload() {
        runCatching { w.policyView(store.policy(entry.id), now()) }
            .onSuccess { view = it; error = null }
            .onFailure { view = null; error = it.message }
    }

    /** Apply a change: the new file is saved before anything else happens. */
    fun change(f: (ByteArray?) -> ByteArray): Boolean =
        runCatching { store.savePolicy(entry.id, f(store.policy(entry.id))) }
            .onSuccess { reload() }
            .onFailure { error = it.message }
            .isSuccess

    if (view == null && error == null) reload()

    Title("Allowlist and limits: ${entry.label}")
    error?.let { Hint(it, BAD) }
    val v = view
    if (v == null) {
        Hint("This wallet's policy file can't be used. Nothing can be signed with this wallet until it is reset. Resetting gives an empty allowlist (addresses you add again must wait before use).", WARN)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Button(onClick = { store.deletePolicy(entry.id); error = null; reload() }) { Text("Reset policy") }
        }
        return
    }

    when (val s = step) {
        PolicyStep.Main -> {
            Hint("The tablet signs only to addresses on this list, and only up to the daily limits, whatever the PC asks. New addresses and higher limits take effect after this wallet's waiting period.")
            Card {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Waiting period: ${waitText(v.waitMinutes)}", fontWeight = FontWeight.SemiBold)
                    v.pendingWaitMinutes?.let { Hint("Shortening to ${waitText(it)} from ${time(v.pendingWaitFromMs)}", WARN) }
                    OutlinedButton(onClick = { error = null; step = PolicyStep.Wait }) { Text("Change") }
                }
            }
            Text("Allowlist", fontWeight = FontWeight.SemiBold)
            if (v.addresses.isEmpty()) Hint("No addresses yet: nothing can be signed.")
            v.addresses.forEach { a ->
                Card {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("${a.label}: ${a.netName}", fontWeight = FontWeight.SemiBold)
                        GroupedAddress(a.address)
                        if (a.usableFromMs == 0uL) Hint("Usable", OK)
                        else Hint("Waiting: usable from ${time(a.usableFromMs)}", WARN)
                        OutlinedButton(onClick = {
                            change { w.policyRemoveAddress(it, a.net, a.address, now()) }
                        }) { Text("Remove") }
                    }
                }
            }
            Text("Add an address", fontWeight = FontWeight.SemiBold)
            w.policyNetworks().forEach { n ->
                OutlinedButton(onClick = { error = null; step = PolicyStep.Add(n.code, n.name) }) { Text("Add ${n.name} address") }
            }
            Text("Daily limits (rolling 24 hours)", fontWeight = FontWeight.SemiBold)
            v.limits.forEach { l ->
                Card {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(l.name, fontWeight = FontWeight.SemiBold)
                        Text("Limit ${l.daily} ${l.unit}; signed in the last 24 hours: ${l.usedDay} ${l.unit}")
                        l.pending?.let { Hint("Raising to $it ${l.unit} from ${time(l.pendingFromMs)}", WARN) }
                        OutlinedButton(onClick = {
                            error = null
                            step = PolicyStep.Limit(l.asset, l.name, l.unit, l.daily)
                        }) { Text("Change") }
                    }
                }
            }
            Text("Signing log: ${v.signedTotal} signature(s)", fontWeight = FontWeight.SemiBold)
            if (v.head.isNotEmpty()) Hint("Log head: ${v.head.take(16)}…")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onBack) { Text("Back") }
                OutlinedButton(onClick = { step = PolicyStep.Log }) { Text("Show signing log") }
            }
        }

        is PolicyStep.Add -> {
            var address by remember(s) { mutableStateOf("") }
            Hint("Type the address from your PAPER address book, or scan it from the recipient's own device. Never copy it from the PC: the allowlist must not depend on the PC.")
            SecureInput(
                key = "allow-address",
                value = address,
                onChange = { address = it.filter { c -> c.isLetterOrDigit() }.take(90) },
                label = "${s.netName} address",
                layout = KeyLayout.TEXT,
                masked = false,
                maxLength = 90,
            )
            val focus = LocalSecureFocus.current
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { step = PolicyStep.Main }) { Text("Cancel") }
                OutlinedButton(onClick = { focus.close(); step = PolicyStep.ScanAddress(s.net, s.netName) }) { Text("Scan") }
                Button(enabled = address.length >= 20, onClick = {
                    focus.close()
                    step = PolicyStep.ConfirmAdd(s.net, s.netName, address)
                }) { Text("Next") }
            }
        }

        is PolicyStep.ScanAddress -> {
            Hint("Scan the address QR on the recipient's own device (not the PC).")
            QrScanner(
                prefix = "",
                wrongHint = "",
                onResult = { step = PolicyStep.ConfirmAdd(s.net, s.netName, bareAddress(it)) },
                onCancel = { step = PolicyStep.Add(s.net, s.netName) },
            )
        }

        is PolicyStep.ConfirmAdd -> {
            var label by remember(s) { mutableStateOf("") }
            Text("Check the whole address against your paper", fontWeight = FontWeight.SemiBold)
            Hint(s.netName)
            GroupedAddress(s.address)
            SecureInput(
                key = "allow-label",
                value = label,
                onChange = { label = it.take(40) },
                label = "Name (e.g. \"Shop\", \"My savings wallet\")",
                layout = KeyLayout.TEXT,
                masked = false,
                maxLength = 40,
            )
            error?.let { Hint(it, BAD) }
            val focus = LocalSecureFocus.current
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { error = null; step = PolicyStep.Main }) { Text("Cancel") }
                Button(enabled = label.isNotBlank(), onClick = {
                    focus.close()
                    if (change { w.policyAddAddress(it, s.net, s.address, label, now()) }) step = PolicyStep.Main
                }) { Text("Add (usable after the wait)") }
            }
        }

        is PolicyStep.Limit -> {
            var amount by remember(s) { mutableStateOf("") }
            Text(s.name, fontWeight = FontWeight.SemiBold)
            Hint("Now ${s.daily} ${s.unit} per 24 hours. Lowering applies at once; raising applies after the waiting period.")
            SecureInput(
                key = "limit",
                value = amount,
                onChange = { amount = it.filter { c -> c.isDigit() || c == '.' }.take(20) },
                label = "New daily limit (${s.unit})",
                layout = KeyLayout.TEXT,
                masked = false,
                maxLength = 20,
            )
            error?.let { Hint(it, BAD) }
            val focus = LocalSecureFocus.current
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { error = null; step = PolicyStep.Main }) { Text("Cancel") }
                Button(enabled = amount.isNotEmpty(), onClick = {
                    focus.close()
                    if (change { w.policySetLimit(it, s.asset, amount, now()) }) step = PolicyStep.Main
                }) { Text("Save") }
            }
        }

        PolicyStep.Wait -> {
            Text("Waiting period", fontWeight = FontWeight.SemiBold)
            Hint("How long a new address (or a higher daily limit) waits before it can be used. Now: ${waitText(v.waitMinutes)}. A longer wait applies at once. A shorter one applies only after the current wait has passed, so someone who learns your vault password can't remove it.")
            val choices = if (entry.real) listOf(10uL, 60uL, 360uL, 1440uL) else listOf(1uL, 10uL, 60uL, 1440uL)
            choices.forEach { m ->
                OutlinedButton(onClick = {
                    if (change { w.policySetWait(it, m, now()) }) step = PolicyStep.Main
                }) { Text(waitText(m) + if (m == v.waitMinutes) " (current)" else "") }
            }
            error?.let { Hint(it, BAD) }
            OutlinedButton(onClick = { error = null; step = PolicyStep.Main }) { Text("Cancel") }
        }

        PolicyStep.Log -> {
            Text("Signing log (newest first)", fontWeight = FontWeight.SemiBold)
            Hint("Everything this tablet signed with this wallet, including payments that were never sent. The PC is told each signature's number, so it notices signatures it didn't see.")
            if (v.recent.isEmpty()) Hint("Nothing signed yet.")
            v.recent.forEach { e ->
                Card {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("#${e.seq} · ${time(e.timeMs)}", fontWeight = FontWeight.SemiBold)
                        Text("${e.amount} ${e.unit}: ${e.asset}")
                        Text("To ${e.recipient}", fontFamily = FontFamily.Monospace)
                        Text("Transaction ${e.txid.take(16)}…", fontFamily = FontFamily.Monospace)
                    }
                }
            }
            OutlinedButton(onClick = { step = PolicyStep.Main }) { Text("Back") }
        }
    }
}
