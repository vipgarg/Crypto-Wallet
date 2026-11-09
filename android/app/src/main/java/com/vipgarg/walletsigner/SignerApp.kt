package com.vipgarg.walletsigner

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.signer_ffi.Seed
import uniffi.signer_ffi.btcReceiveAddress
import uniffi.signer_ffi.checkDice
import uniffi.signer_ffi.exportString
import uniffi.signer_ffi.newSeed
import uniffi.signer_ffi.qrCode
import uniffi.signer_ffi.restoreSeed

internal val BAD = Color(0xFFB3261E)
internal val OK = Color(0xFF1D6B3A)
internal val WARN = Color(0xFF7A5600)

private sealed interface Screen {
    data object Checks : Screen
    data object Home : Screen
    data class Create(val restore: Boolean) : Screen
    data class Detail(val entry: WalletEntry) : Screen
    data class ShowQr(val title: String, val text: String, val note: String) : Screen
    data class TestNet(val entry: WalletEntry) : Screen
}

@Composable
fun SignerApp(store: WalletStore) {
    var screen by remember { mutableStateOf<Screen>(Screen.Checks) }
    val secureFocus = remember { SecureFocus() }
    MaterialTheme {
        CompositionLocalProvider(LocalSecureFocus provides secureFocus) {
        Surface(modifier = Modifier.fillMaxSize()) {
          Column(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (Safety.blocked) {
                    // Hide everything (secrets included) while recorded or cast.
                    LaunchedEffect(Unit) { secureFocus.close() }
                    Title("Stopped: the screen may be recorded or shown elsewhere")
                    Hint(
                        if (Safety.screenRecorded) {
                            "Screen recording of this app was detected. Stop the recording to continue."
                        } else {
                            "The screen is being cast or mirrored to another display. Stop casting to continue."
                        },
                        BAD,
                    )
                    Hint("Nothing is shown while this lasts. This tablet should never record or cast its screen.")
                } else when (val s = screen) {
                    Screen.Checks -> ChecksScreen(onPassed = { screen = Screen.Home })
                    Screen.Home -> HomeScreen(
                        store = store,
                        onCreate = { screen = Screen.Create(restore = false) },
                        onRestore = { screen = Screen.Create(restore = true) },
                        onOpen = { screen = Screen.Detail(it) },
                    )
                    is Screen.Create -> CreateWallet(
                        store = store,
                        restore = s.restore,
                        onDone = { screen = Screen.Detail(it) },
                        onCancel = { screen = Screen.Home },
                    )
                    is Screen.Detail -> DetailScreen(
                        entry = s.entry,
                        onBack = { screen = Screen.Home },
                        onShowQr = { title, text, note -> screen = Screen.ShowQr(title, text, note) },
                        onTestNet = { screen = Screen.TestNet(s.entry) },
                    )
                    is Screen.TestNet -> TestNetScreen(
                        entry = s.entry,
                        store = store,
                        onBack = { screen = Screen.Detail(s.entry) },
                    )
                    is Screen.ShowQr -> QrScreen(s.title, s.text, s.note, onBack = { screen = Screen.Home })
                }
            }
            SecureKeyboardHost()
          }
        }
        }
    }
}

@Composable
internal fun Title(text: String) {
    Text(text, fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
}

@Composable
internal fun Hint(text: String, color: Color = Color.Unspecified) {
    Text(text, fontSize = 14.sp, color = color)
}

// ---------------------------------------------------------------------------
// Start-up checks
// ---------------------------------------------------------------------------

@Composable
private fun ChecksScreen(onPassed: () -> Unit) {
    val context = LocalContext.current
    var checks by remember { mutableStateOf(runChecks(context)) }
    val blocked = checks.any { it.critical && !it.ok }
    Title("Safety checks")
    Hint("This tablet must stay offline. Testnet build: do not use with real funds.", WARN)
    checks.forEach { c ->
        Row(verticalAlignment = Alignment.Top) {
            Text(
                if (c.ok) "✓" else if (c.critical) "✗" else "!",
                color = if (c.ok) OK else if (c.critical) BAD else WARN,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(end = 10.dp),
            )
            Column {
                Text(c.title, fontWeight = FontWeight.SemiBold)
                Hint(c.detail)
            }
        }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = { checks = runChecks(context) }) { Text("Check again") }
        Button(onClick = onPassed, enabled = !blocked) { Text("Continue") }
    }
    if (blocked) Hint("Fix the items marked ✗ to continue.", BAD)
}

// ---------------------------------------------------------------------------
// Wallet list
// ---------------------------------------------------------------------------

@Composable
private fun HomeScreen(
    store: WalletStore,
    onCreate: () -> Unit,
    onRestore: () -> Unit,
    onOpen: (WalletEntry) -> Unit,
) {
    val wallets = remember { store.list() }
    Title("Wallets")
    if (wallets.isEmpty()) Hint("No wallets yet.")
    wallets.forEach { w ->
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(w.label, fontWeight = FontWeight.SemiBold)
                Hint("${w.id} · ${w.tierName} · fingerprint ${w.public.fingerprint}")
                Spacer(Modifier.height(6.dp))
                OutlinedButton(onClick = { onOpen(w) }) { Text("Open") }
            }
        }
    }
    HorizontalDivider()
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = onCreate) { Text("Create new wallet") }
        OutlinedButton(onClick = onRestore) { Text("Restore from words") }
    }
}

// ---------------------------------------------------------------------------
// Create / restore
// ---------------------------------------------------------------------------

private enum class Step { BASICS, DICE, RESTORE_WORDS, SHOW_WORDS, WORD_CHECK, PASSPHRASE, PASSWORD, SAVING }

private val ID_RULE = Regex("^[a-z][a-z0-9-]{0,31}$")

@Composable
private fun CreateWallet(
    store: WalletStore,
    restore: Boolean,
    onDone: (WalletEntry) -> Unit,
    onCancel: () -> Unit,
) {
    var step by remember { mutableStateOf(Step.BASICS) }
    var id by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var tier by remember { mutableStateOf("savings") }
    var seed by remember { mutableStateOf<Seed?>(null) }
    var positions by remember { mutableStateOf<List<UInt>>(emptyList()) }
    var passphrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    // Free the seed in Rust (which wipes it) when leaving this flow.
    DisposableEffect(Unit) { onDispose { seed?.close() } }

    val needsPassphrase = tier != "spending"
    val stored = tier != "vault"

    Title(if (restore) "Restore wallet" else "Create wallet")
    error?.let { Hint(it, BAD) }

    when (step) {
        Step.BASICS -> {
            OutlinedTextField(id, { id = it.trim().lowercase() }, label = { Text("ID (e.g. savings-01)") }, singleLine = true)
            OutlinedTextField(label, { label = it.take(40) }, label = { Text("Label") }, singleLine = true)
            Text("Tier", fontWeight = FontWeight.SemiBold)
            listOf(
                "spending" to "T-2 Spending (stored, small balance)",
                "savings" to "T-1 Savings (stored, passphrase required)",
                "vault" to "T-0 Vault (seed NOT stored on this tablet)",
            ).forEach { (value, text) ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = tier == value, onClick = { tier = value })
                    Text(text)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onCancel) { Text("Cancel") }
                Button(onClick = {
                    error = when {
                        !ID_RULE.matches(id) -> "ID: 1-32 characters, a-z, 0-9 and '-', starting with a letter."
                        store.exists(id) -> "A wallet with this ID already exists."
                        label.isBlank() -> "Enter a label."
                        else -> null
                    }
                    if (error == null) step = if (restore) Step.RESTORE_WORDS else Step.DICE
                }) { Text("Next") }
            }
        }

        Step.DICE -> {
            var rolls by remember { mutableStateOf("") }
            val count = rolls.count { it in '1'..'6' }
            Hint("Roll a normal six-sided die at least 99 times and type each result (1-6). Spaces are fine.")
            SecureInput(
                key = "dice",
                value = rolls,
                onChange = { rolls = it.filter { c -> c in '1'..'6' || c == ' ' } },
                label = "Dice rolls ($count of 99)",
                layout = KeyLayout.DICE,
                masked = false,
                maxLength = 400,
            )
            Button(onClick = {
                try {
                    checkDice(rolls)
                    seed = newSeed(rolls)
                    rolls = ""
                    error = null
                    step = Step.SHOW_WORDS
                } catch (e: Exception) {
                    error = e.message
                }
            }) { Text("Create seed") }
        }

        Step.RESTORE_WORDS -> {
            var count by remember { mutableStateOf(24) }
            val words = remember { mutableStateListOf(*Array(24) { "" }) }
            // Only one word is readable at a time: the box being typed in, or
            // the one whose "Show" was tapped.
            var visible by remember { mutableStateOf(-1) }
            var restoreError by remember { mutableStateOf<String?>(null) }
            Hint("Type one word in each box, in the same order as on your paper (#1 first).")
            Row(verticalAlignment = Alignment.CenterVertically) {
                listOf(12, 24).forEach { n ->
                    RadioButton(selected = count == n, onClick = { count = n; restoreError = null })
                    Text("$n words", modifier = Modifier.padding(end = 16.dp))
                }
            }
            (0 until count).chunked(2).forEach { pair ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    pair.forEach { i ->
                        val focusKey = "w$i"
                        val activeKey = LocalSecureFocus.current.activeKey
                        val typingWord = activeKey?.startsWith("w") == true
                        val focus = LocalSecureFocus.current
                        Row(modifier = Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                            SecureInput(
                                key = focusKey,
                                value = words[i],
                                onChange = { v -> words[i] = v; restoreError = null },
                                label = "#${i + 1}",
                                layout = KeyLayout.WORD,
                                // Readable only while typed in, or after "Show" (one at a time).
                                // While typing, only the box being typed in; otherwise
                                // only the one whose "Show" was tapped.
                                masked = if (typingWord) activeKey != focusKey else visible != i,
                                maxLength = 12,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = {
                                focus.close()
                                visible = if (visible == i) -1 else i
                            }) {
                                Text(if (visible == i && !typingWord) "Hide" else "Show")
                            }
                        }
                    }
                    if (pair.size == 1) Spacer(Modifier.weight(1f))
                }
            }
            restoreError?.let { Hint(it, BAD) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    for (i in words.indices) words[i] = ""
                    visible = -1
                    restoreError = null
                }) { Text("Clear all") }
                Button(onClick = {
                    try {
                        seed = restoreSeed(words.take(count))
                        for (i in words.indices) words[i] = ""
                        restoreError = null
                        error = null
                        step = if (needsPassphrase) Step.PASSPHRASE else Step.PASSWORD
                    } catch (e: Exception) {
                        restoreError = "Can't restore: " + (e.message ?: "unknown error")
                    }
                }) { Text("Next") }
            }
        }

        Step.SHOW_WORDS -> {
            val words = remember { seed?.words().orEmpty() }
            Hint(
                "Write these 24 words on paper, in order. Never photograph them or type them anywhere else. " +
                    "They are the only way to recover this wallet.",
                BAD,
            )
            words.chunked(4).forEachIndexed { row, group ->
                Text(
                    group.mapIndexed { i, w -> "${row * 4 + i + 1}. $w" }.joinToString("    "),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 17.sp,
                )
            }
            Button(onClick = {
                positions = seed?.wordCheckPositions(4u).orEmpty()
                error = null
                step = Step.WORD_CHECK
            }) { Text("I wrote them down") }
        }

        Step.WORD_CHECK -> {
            val answers = remember(positions) { positions.map { mutableStateOf("") } }
            Hint("Type these words from your paper to check it.")
            positions.forEachIndexed { i, p ->
                SecureInput(
                    key = "check$i",
                    value = answers[i].value,
                    onChange = { answers[i].value = it },
                    label = "Word #$p",
                    layout = KeyLayout.WORD,
                    masked = false,
                    maxLength = 12,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { step = Step.SHOW_WORDS }) { Text("Show words again") }
                Button(onClick = {
                    val wrong = positions.indices
                        .filter { seed?.checkWords(listOf(positions[it]), listOf(answers[it].value)) != true }
                        .map { "#${positions[it]}" }
                    if (wrong.isEmpty()) {
                        error = null
                        step = if (needsPassphrase) Step.PASSPHRASE else Step.PASSWORD
                    } else {
                        error = "Word ${wrong.joinToString(", ")} doesn't match. Check your paper."
                    }
                }) { Text("Check") }
            }
        }

        Step.PASSPHRASE -> {
            var again by remember { mutableStateOf("") }
            Hint(
                "Passphrase (\"25th word\"): required for Savings and Vault. Write it on separate paper, kept in a " +
                    "different place from the 24 words. If you forget it, the funds are lost.",
            )
            SecretField(passphrase, { passphrase = it }, "Passphrase")
            SecretField(again, { again = it }, "Passphrase again")
            Button(onClick = {
                error = when {
                    passphrase.isEmpty() -> "Enter a passphrase."
                    passphrase != again -> "The two passphrases don't match."
                    else -> null
                }
                if (error == null) {
                    if (stored) {
                        step = Step.PASSWORD
                    } else {
                        // Vault tier: nothing secret is stored.
                        val s = seed ?: return@Button
                        step = Step.SAVING
                        scope.launch {
                            val result = runCatching {
                                withContext(Dispatchers.Default) {
                                    val public = s.derivePublic(passphrase)
                                    val entry = WalletEntry(id, label, tier, true, public)
                                    store.save(entry, vault = null)
                                    entry
                                }
                            }
                            passphrase = ""
                            result.onSuccess(onDone).onFailure { error = it.message; step = Step.PASSPHRASE }
                        }
                    }
                }
            }) { Text("Next") }
        }

        Step.PASSWORD -> {
            var password by remember { mutableStateOf("") }
            var again by remember { mutableStateOf("") }
            Hint("Vault password for this wallet only (at least 12 characters). It encrypts the seed on this tablet.")
            SecretField(password, { password = it }, "Vault password")
            SecretField(again, { again = it }, "Vault password again")
            Button(onClick = {
                error = when {
                    password.length < 12 -> "Use at least 12 characters."
                    password != again -> "The two passwords don't match."
                    else -> null
                }
                val s = seed
                if (error == null && s != null) {
                    step = Step.SAVING
                    val pw = password
                    password = ""
                    again = ""
                    scope.launch {
                        val result = runCatching {
                            withContext(Dispatchers.Default) {
                                val pass = if (needsPassphrase) passphrase else ""
                                val public = s.derivePublic(pass)
                                val vault = s.sealVault(id, label, tier, public, needsPassphrase, pw)
                                val entry = WalletEntry(id, label, tier, needsPassphrase, public)
                                store.save(entry, vault)
                                entry
                            }
                        }
                        passphrase = ""
                        result.onSuccess(onDone).onFailure { error = it.message; step = Step.PASSWORD }
                    }
                }
            }) { Text("Encrypt and save") }
        }

        Step.SAVING -> Hint("Encrypting… this takes a few seconds.")
    }
}

@Composable
internal fun SecretField(value: String, onChange: (String) -> Unit, label: String) {
    // Typed on the app's own keyboard only; shown as dots.
    SecureInput(
        key = "secret:$label",
        value = value,
        onChange = onChange,
        label = label,
        layout = KeyLayout.TEXT,
        masked = true,
    )
}

// ---------------------------------------------------------------------------
// Wallet detail, export and address verification
// ---------------------------------------------------------------------------

@Composable
private fun DetailScreen(
    entry: WalletEntry,
    onBack: () -> Unit,
    onShowQr: (String, String, String) -> Unit,
    onTestNet: () -> Unit,
) {
    var btcIndex by remember { mutableStateOf("0") }
    var error by remember { mutableStateOf<String?>(null) }
    Title(entry.label)
    Hint("${entry.id} · ${entry.tierName} · fingerprint ${entry.public.fingerprint}")
    if (entry.stateless) {
        Hint("Vault tier: the seed is not stored on this tablet. Keep the paper words (and later the SeedQR card) safe.", WARN)
    }
    error?.let { Hint(it, BAD) }

    Button(onClick = {
        runCatching { exportString(entry.id, entry.label, entry.tier, entry.public) }
            .onSuccess {
                onShowQr(
                    "Add to the PC app",
                    it,
                    "Scan this with the PC app. It contains public data only (addresses and the Bitcoin account key).",
                )
            }
            .onFailure { error = it.message }
    }) { Text("Show export QR for the PC") }

    HorizontalDivider()
    Text("Verify an address", fontWeight = FontWeight.SemiBold)
    Hint("Compare with the PC app's Receive page. Every character must match.")
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            btcIndex,
            { btcIndex = it.filter(Char::isDigit).take(4) },
            label = { Text("Bitcoin receive #") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.width(180.dp),
        )
        OutlinedButton(onClick = {
            val i = btcIndex.toUIntOrNull() ?: 0u
            runCatching { btcReceiveAddress(entry.public, i) }
                .onSuccess { onShowQr("Bitcoin receive #$i", it, "Bitcoin address of ${entry.label}.") }
                .onFailure { error = it.message }
        }) { Text("Show Bitcoin") }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = { onShowQr("Ethereum address", entry.public.eth, "USDT (ERC-20) and ETH of ${entry.label}.") }) {
            Text("Show Ethereum")
        }
        OutlinedButton(onClick = { onShowQr("TRON address", entry.public.tron, "USDT (TRC-20) and TRX of ${entry.label}.") }) {
            Text("Show TRON")
        }
    }
    HorizontalDivider()
    Text("Test networks (TRON Nile, Bitcoin signet)", fontWeight = FontWeight.SemiBold)
    if (entry.stateless) {
        Hint("Not available for Vault-tier wallets (their seed isn't stored here). Use a Spending test wallet.")
    } else {
        Hint("Practise signing with test coins that have no value: export the test wallet to the PC, then sign test payments.")
        OutlinedButton(onClick = onTestNet) { Text("Test network") }
    }
    HorizontalDivider()
    OutlinedButton(onClick = onBack) { Text("Back to wallets") }
}

/** A QR code drawn on a white square; larger codes get a larger square. */
@Composable
internal fun QrImage(text: String) {
    val qr = remember(text) { runCatching { qrCode(text) }.getOrNull() }
    if (qr == null) {
        Hint("This is too large for one QR code.", BAD)
        return
    }
    val n = qr.size.toInt()
    val side = if (n > 45) 520.dp else 300.dp
    Canvas(modifier = Modifier.size(side)) {
        val quiet = 4
        val cell = size.width / (n + quiet * 2)
        drawRect(Color.White, size = size)
        for (y in 0 until n) {
            for (x in 0 until n) {
                if (qr.modules[y * n + x]) {
                    drawRect(
                        Color.Black,
                        topLeft = Offset((x + quiet) * cell, (y + quiet) * cell),
                        size = Size(cell, cell),
                    )
                }
            }
        }
    }
}

/** Address in groups of 4, with the first and last 6 characters in bold. */
@Composable
internal fun GroupedAddress(text: String) {
    Text(
        buildAnnotatedString {
            text.forEachIndexed { i, c ->
                if (i > 0 && i % 4 == 0) append(' ')
                if (i < 6 || i >= text.length - 6) {
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { append(c) }
                } else {
                    append(c)
                }
            }
        },
        fontFamily = FontFamily.Monospace,
        fontSize = 19.sp,
    )
}

@Composable
private fun QrScreen(title: String, text: String, note: String, onBack: () -> Unit) {
    Title(title)
    Hint(note)
    QrImage(text)
    if (text.length <= 64) GroupedAddress(text)
    OutlinedButton(onClick = onBack) { Text("Done") }
}
