package com.vipgarg.walletsigner

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.signer_ffi.BtcReviewRecord
import uniffi.signer_ffi.TronReviewRecord
import uniffi.signer_ffi.UnlockedWallet
import uniffi.signer_ffi.unlockVault

private sealed interface TestStep {
    data object Menu : TestStep
    data class ShowExport(val text: String) : TestStep
    data object Scan : TestStep
    data class Review(val request: String, val review: BtcReviewRecord) : TestStep
    data class Signed(val text: String, val review: BtcReviewRecord) : TestStep
    data object TronScan : TestStep
    data class TronReview(val request: String, val review: TronReviewRecord) : TestStep
    data class TronSigned(val text: String, val review: TronReviewRecord) : TestStep
}

private fun sats(v: ULong): String {
    val s = v.toString().padStart(9, '0')
    val whole = s.dropLast(8).trimStart('0').ifEmpty { "0" }
    val frac = s.takeLast(8).trimEnd('0')
    val btc = if (frac.isEmpty()) whole else "$whole.$frac"
    return "$btc sBTC (${"%,d".format(v.toLong())} sats)"
}

/**
 * Test network (Bitcoin signet): unlock the stored wallet, export its test
 * key to the PC, and sign test payments scanned from the PC. Coins on
 * signet have no value. The wallet is locked again (key material wiped)
 * when this screen is left.
 */
@Composable
fun TestNetScreen(entry: WalletEntry, store: WalletStore, onBack: () -> Unit) {
    var wallet by remember { mutableStateOf<UnlockedWallet?>(null) }
    var step by remember { mutableStateOf<TestStep>(TestStep.Menu) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    DisposableEffect(Unit) { onDispose { wallet?.close() } }

    Title("Test networks: ${entry.label}")
    Hint("TRON Nile and Bitcoin signet: test coins with no value. Practise here before any real signing exists.", WARN)
    error?.let { Hint(it, BAD) }
    busy?.let { Hint(it) }

    val w = wallet
    if (w == null) {
        var password by remember { mutableStateOf("") }
        var passphrase by remember { mutableStateOf("") }
        Hint("Unlock this wallet for this screen only. It locks again when you leave.")
        SecretField(password, { password = it }, "Vault password")
        if (entry.usesPassphrase) SecretField(passphrase, { passphrase = it }, "Passphrase")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Button(enabled = busy == null && password.isNotEmpty(), onClick = {
                val bytes = store.vault(entry.id)
                if (bytes == null) {
                    error = "No stored seed for this wallet."
                    return@Button
                }
                busy = "Unlocking (this takes a few seconds)…"
                error = null
                scope.launch {
                    val r = withContext(Dispatchers.Default) {
                        runCatching { unlockVault(bytes, password, passphrase) }
                    }
                    busy = null
                    r.onSuccess {
                        wallet = it
                        password = ""
                        passphrase = ""
                    }.onFailure { error = it.message }
                }
            }) { Text("Unlock") }
        }
        return
    }

    when (val s = step) {
        TestStep.Menu -> {
            Button(onClick = {
                runCatching { w.testExportString() }
                    .onSuccess { step = TestStep.ShowExport(it) }
                    .onFailure { error = it.message }
            }) { Text("Show test export QR (for the PC)") }
            Button(onClick = { error = null; step = TestStep.TronScan }) { Text("Sign a TRON test payment (Nile USDT)") }
            OutlinedButton(onClick = { error = null; step = TestStep.Scan }) { Text("Sign a Bitcoin test payment (signet)") }
            OutlinedButton(onClick = onBack) { Text("Lock and go back") }
        }

        is TestStep.ShowExport -> {
            Hint("On the PC: Test send → Add test wallet (scan the tablet). Public data only (test-network key).")
            QrImage(s.text)
            OutlinedButton(onClick = { step = TestStep.Menu }) { Text("Done") }
        }

        TestStep.Scan -> {
            Hint("On the PC: Test send → Build payment. Then scan the QR it shows.")
            QrScanner(
                prefix = "WPS1:",
                wrongHint = "That isn't a payment request from the PC (it should start with WPS1).",
                onResult = { text ->
                    busy = "Checking the payment…"
                    scope.launch {
                        val r = withContext(Dispatchers.Default) { runCatching { w.reviewBtc(text) } }
                        busy = null
                        r.onSuccess { step = TestStep.Review(text, it) }
                            .onFailure { error = it.message; step = TestStep.Menu }
                    }
                },
                onCancel = { step = TestStep.Menu },
            )
        }

        is TestStep.Review -> {
            var typed by remember(s) { mutableStateOf("") }
            val r = s.review
            Text("Check every line against the PC and your paper", fontWeight = FontWeight.SemiBold)
            Card {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(r.network)
                    Text("Recipient", fontWeight = FontWeight.SemiBold)
                    GroupedAddress(r.recipient)
                    Text("Amount: ${sats(r.amountSats)}", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Text("Fee: ${sats(r.feeSats)} (about ${r.feeRate} sat/vB)")
                    Text(
                        if (r.changeSats > 0uL) "Change back to this wallet: ${sats(r.changeSats)} (change address #${r.changeIndex})"
                        else "No change",
                    )
                    Text("Coins used: ${r.inputs}")
                    Text("Transaction ID starts with: ${r.txid.take(8)}", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                }
            }
            HorizontalDivider()
            Hint("To approve, type the LAST 6 characters of the recipient address from your PAPER address book (not from either screen).")
            SecureInput(
                key = "last6",
                value = typed,
                onChange = { typed = it.filter { c -> c.isLetterOrDigit() }.take(6) },
                label = "Last 6 characters",
                layout = KeyLayout.TEXT,
                masked = false,
                maxLength = 6,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { step = TestStep.Menu }) { Text("Reject") }
                Button(enabled = typed.length == 6 && busy == null, onClick = {
                    busy = "Signing…"
                    scope.launch {
                        val res = withContext(Dispatchers.Default) {
                            runCatching { w.signBtc(s.request, r.txid, typed) }
                        }
                        busy = null
                        res.onSuccess { step = TestStep.Signed(it, r) }
                            .onFailure { error = it.message }
                    }
                }) { Text("Approve and sign") }
            }
        }

        TestStep.TronScan -> {
            Hint("On the PC: Test send → USDT on TRON Nile → Build payment. Then scan the QR it shows.")
            QrScanner(
                prefix = "WTR1:",
                wrongHint = "That isn't a TRON payment request from the PC (it should start with WTR1).",
                onResult = { text ->
                    busy = "Checking the payment…"
                    scope.launch {
                        val r = withContext(Dispatchers.Default) {
                            runCatching { w.reviewTron(text, System.currentTimeMillis().toULong()) }
                        }
                        busy = null
                        r.onSuccess { step = TestStep.TronReview(text, it) }
                            .onFailure { error = it.message; step = TestStep.Menu }
                    }
                },
                onCancel = { step = TestStep.Menu },
            )
        }

        is TestStep.TronReview -> {
            var typed by remember(s) { mutableStateOf("") }
            val r = s.review
            Text("Check every line against the PC and your paper", fontWeight = FontWeight.SemiBold)
            Card {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(r.network)
                    Text("Token: test USDT (TRC-20)")
                    Text("Recipient", fontWeight = FontWeight.SemiBold)
                    GroupedAddress(r.recipient)
                    Text("Amount: ${r.amountUsdt} test USDT", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Text("Fee limit: up to ${r.feeLimitTrx} test TRX")
                    Text("From this wallet: ${r.from}", fontFamily = FontFamily.Monospace)
                    Text("Transaction ID starts with: ${r.txid.take(8)}", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                }
            }
            HorizontalDivider()
            Hint("To approve, type the LAST 6 characters of the recipient address from your PAPER address book. TRON addresses are case-sensitive (capital and small letters must match).")
            SecureInput(
                key = "last6",
                value = typed,
                onChange = { typed = it.filter { c -> c.isLetterOrDigit() }.take(6) },
                label = "Last 6 characters",
                layout = KeyLayout.TEXT,
                masked = false,
                maxLength = 6,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { step = TestStep.Menu }) { Text("Reject") }
                Button(enabled = typed.length == 6 && busy == null, onClick = {
                    busy = "Signing…"
                    scope.launch {
                        val res = withContext(Dispatchers.Default) {
                            runCatching { w.signTron(s.request, r.txid, typed, System.currentTimeMillis().toULong()) }
                        }
                        busy = null
                        res.onSuccess { step = TestStep.TronSigned(it, r) }
                            .onFailure { error = it.message }
                    }
                }) { Text("Approve and sign") }
            }
        }

        is TestStep.TronSigned -> {
            Text("Signed", fontWeight = FontWeight.SemiBold, color = OK)
            Hint("On the PC: Scan the signed QR from the tablet. Transaction ID starts with ${s.review.txid.take(8)}.")
            QrImage(s.text)
            OutlinedButton(onClick = { step = TestStep.Menu }) { Text("Done") }
        }

        is TestStep.Signed -> {
            Text("Signed", fontWeight = FontWeight.SemiBold, color = OK)
            Hint("On the PC: Scan the signed QR from the tablet. Transaction ID starts with ${s.review.txid.take(8)}.")
            QrImage(s.text)
            OutlinedButton(onClick = { step = TestStep.Menu }) { Text("Done") }
        }
    }
}
