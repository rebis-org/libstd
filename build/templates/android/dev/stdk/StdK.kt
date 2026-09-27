package dev.stdk

import java.io.ByteArrayOutputStream

/*
 * Kotlin facade over the Java bindings. The JNI surface stays in [StdK], and
 * this file adds the idiomatic entry points: block-scoped sessions and a pump
 * that loops until the session reports finished.
 */

/** Opens an unbounded session for a published pair and closes it after [block]. */
public inline fun <R> useSession(
    component: String,
    verb: String,
    block: (StdK.Session) -> R,
): R = StdK.open(component, verb).use(block)

/** Opens a bounded session for untrusted input and closes it after [block]. */
public inline fun <R> useBoundedSession(
    component: String,
    verb: String,
    maxEncoded: Long = -1,
    maxDecoded: Long = -1,
    maxWork: Long = -1,
    maxEntries: Long = -1,
    block: (StdK.Session) -> R,
): R = StdK.openBounded(component, verb, maxEncoded, maxDecoded, maxWork, maxEntries).use(block)

/**
 * Pumps [input] through the session until it reports finished and returns the produced bytes.
 * Throws [StdK.StdKException] on failure with the driver detail.
 */
public fun StdK.Session.pumpAll(
    input: ByteArray,
    endOfInput: Boolean = true,
    bufferSize: Int = 64 * 1024,
): ByteArray {
    require(bufferSize > 0) { "bufferSize must be positive" }
    val collected = ByteArrayOutputStream()
    var offset = 0
    val buffer = ByteArray(bufferSize)
    while (true) {
        val chunk =
            when {
                offset < input.size ->
                    input.copyOfRange(offset, minOf(offset + bufferSize, input.size))
                else -> null
            }
        val last = endOfInput && (chunk == null || offset + chunk.size >= input.size)
        val result = step(chunk, buffer, last)
        collected.write(buffer, 0, result.produced.toInt())
        offset += result.consumed.toInt()
        if (result.finished) {
            return collected.toByteArray()
        }
        if (result.consumed == 0L && result.produced == 0L) {
            throw StdK.StdKException(
                "Session made no progress; the input may be incomplete.",
                StdK.INVALID_DATA,
            )
        }
    }
}
