package com.vipgarg.walletsigner

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The app's own keyboard for secrets (ARCHITECTURE-MOBILE.md §5.1): seed
 * words, passwords, passphrases, dice rolls and the approval characters are
 * never typed on the system keyboard, which could learn, store, suggest or
 * send what is typed. This keyboard keeps nothing and has no suggestions.
 */
enum class KeyLayout {
    /** Letters (with Shift), digits and symbols: passwords, passphrases, last-6. */
    TEXT,
    /** Lowercase a-z only: recovery words. */
    WORD,
    /** 1-6 and space: dice rolls. */
    DICE,
}

/** The field the keyboard is typing into (updated on every recomposition). */
class SecureTarget(
    val key: String,
    val layout: KeyLayout,
    val value: String,
    val maxLength: Int,
    val onChange: (String) -> Unit,
)

class SecureFocus {
    var activeKey by mutableStateOf<String?>(null)
    var target by mutableStateOf<SecureTarget?>(null)

    fun close() {
        activeKey = null
        target = null
    }
}

val LocalSecureFocus = staticCompositionLocalOf { SecureFocus() }

/**
 * A text field typed only with [SecureKeyboardHost]. Tapping it opens the
 * app's keyboard at the bottom of the screen; the system keyboard never
 * appears. With [masked], the text is shown as dots.
 */
@Composable
fun SecureInput(
    key: String,
    value: String,
    onChange: (String) -> Unit,
    label: String,
    layout: KeyLayout,
    masked: Boolean,
    maxLength: Int = 200,
    modifier: Modifier = Modifier.fillMaxWidth(),
) {
    val focus = LocalSecureFocus.current
    val active = focus.activeKey == key
    if (active) {
        SideEffect { focus.target = SecureTarget(key, layout, value, maxLength, onChange) }
    }
    DisposableEffect(key) {
        onDispose { if (focus.activeKey == key) focus.close() }
    }
    val shown = if (masked) "•".repeat(value.length) else value
    Column(
        modifier = modifier
            .border(
                BorderStroke(if (active) 2.dp else 1.dp, if (active) MaterialTheme.colorScheme.primary else Color.Gray),
                RoundedCornerShape(6.dp),
            )
            .clickable { focus.activeKey = key }
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(label, fontSize = 12.sp, color = Color.Gray)
        Text(
            if (shown.isEmpty()) " " else shown + if (active) "▏" else "",
            fontFamily = FontFamily.Monospace,
            fontSize = 18.sp,
        )
    }
}

private const val LETTERS = "qwertyuiop|asdfghjkl|zxcvbnm"
private const val SYMBOLS = "1234567890|-_.,:;!?@#|$%&*+=/()'\""

/** Docked at the bottom of the screen; shows only while a secure field is active. */
@Composable
fun SecureKeyboardHost() {
    val focus = LocalSecureFocus.current
    val t = focus.target ?: return
    if (focus.activeKey != t.key) return
    var shift by remember { mutableStateOf(false) }
    var symbols by remember { mutableStateOf(false) }

    fun type(c: String) {
        if (t.value.length < t.maxLength) t.onChange(t.value + c)
        if (shift) shift = false
    }

    fun back() {
        if (t.value.isNotEmpty()) t.onChange(t.value.dropLast(1))
    }

    @Composable
    fun KeyRow(keys: List<Pair<String, () -> Unit>>) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            keys.forEach { (label, action) ->
                Box(
                    modifier = Modifier
                        .weight(if (label.length > 1) 1.6f else 1f)
                        .height(48.dp)
                        .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(6.dp))
                        .clickable { action() },
                    contentAlignment = Alignment.Center,
                ) { Text(label, fontSize = 18.sp) }
            }
        }
    }

    Surface(tonalElevation = 6.dp, shadowElevation = 6.dp) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("App keyboard (nothing is stored or suggested)", fontSize = 12.sp, color = Color.Gray, modifier = Modifier.weight(1f))
                TextButton(onClick = { focus.close() }) { Text("Done") }
            }
            when (t.layout) {
                KeyLayout.DICE -> {
                    KeyRow(listOf("1", "2", "3").map { c -> c to { type(c) } })
                    KeyRow(listOf("4", "5", "6").map { c -> c to { type(c) } })
                    KeyRow(listOf("space" to { type(" ") }, "⌫" to { back() }))
                }
                KeyLayout.WORD -> {
                    LETTERS.split('|').forEach { row ->
                        KeyRow(row.map { c -> c.toString() to { type(c.toString()) } })
                    }
                    KeyRow(listOf("⌫" to { back() }))
                }
                KeyLayout.TEXT -> {
                    if (symbols) {
                        SYMBOLS.split('|').forEach { row ->
                            KeyRow(row.map { c -> c.toString() to { type(c.toString()) } })
                        }
                    } else {
                        LETTERS.split('|').forEach { row ->
                            KeyRow(row.map { c ->
                                val s = if (shift) c.uppercase() else c.toString()
                                s to { type(s) }
                            })
                        }
                    }
                    KeyRow(
                        listOf(
                            (if (shift) "⇧ ON" else "⇧") to { shift = !shift; symbols = false },
                            (if (symbols) "abc" else "123#") to { symbols = !symbols },
                            "space" to { type(" ") },
                            "⌫" to { back() },
                        ),
                    )
                }
            }
        }
    }
}
