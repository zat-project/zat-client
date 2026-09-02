package zat.manager.vpn

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.time.Instant

/**
 * Are ALL SIX bootstrap channels actually serving a fresh snapshot right now?
 *
 * ## Why this exists
 *
 * The client tries the channels IN ORDER and stops at the first success, so on a healthy run
 * channels 2..6 are never fetched at all. A channel can rot for weeks and no client, no log and no
 * test will say so — the run simply succeeds on channel 1. This project has already paid for that
 * exact blind spot: signed artifacts once sat for nine days while **four of the six channels were
 * dead**, and what made it survivable was luck about which two were alive.
 *
 * It is also the R19 shape one layer up. The publisher logs `[Bitbucket] Publish succeeded` — that is
 * the WRITE side. Nothing checked the READ side, and a publish can succeed onto a URL that then
 * serves a 404, a login page, or last week's copy from a CDN edge.
 *
 * ## Why it goes through the client's own code
 *
 * The URLs are XOR-obfuscated in the binary. Re-deriving them in a shell script would risk probing
 * URLs the client does not actually use — a checker that tests something adjacent to the thing it
 * claims to test, which is worse than no checker. So this asks [StealthConfig] for the real list, the
 * same call `BootstrapResolver` makes.
 *
 * ## Opt-in
 *
 * The live sweep reaches the public internet, so it is skipped unless `ZAT_LIVE=1`; run it via
 * `scripts/channel-health-check.sh`. Run that BEFORE an in-country test — a dead channel of OUR
 * making would come back as a censorship report — but it is deliberately a separate command from
 * `pretest-check.sh`, which stays a fast GO/NO-GO. (An earlier draft of this comment claimed
 * `pretest-check.sh` called it. It did not. A comment that describes an intent nothing implements is
 * exactly what R19 was.)
 *
 * The failure-path test below needs no network and runs always, so this file is never wholly skipped.
 */
class ChannelHealthLiveTest {

    /** A channel is stale to a client once the snapshot's own ttl has passed; warn well before that. */
    private val freshEnoughSeconds = 1_800L

    @Test
    fun `every bootstrap channel serves a fresh snapshot`() {
        assumeTrue(System.getenv("ZAT_LIVE") == "1", "live network test; set ZAT_LIVE=1")

        val urls = StealthConfig.getChannelUrls()
        val results = urls.mapIndexed { i, url -> probe(i + 1, url) }

        // Written to a FILE, not just printed. The whole table is the useful artifact — which channel
        // and how it failed — and a failure message alone loses the healthy ones. Gradle swallows a
        // test's stdout, so a println here would leave the wrapper script reporting a verdict with no
        // evidence, which is a checker you cannot act on.
        val table = buildString {
            appendLine("channel health - ${results.size} channel(s)")
            results.forEach { appendLine("  " + it.render()) }
        }
        print(table)
        runCatching {
            val out = java.io.File(System.getenv("ZAT_CHANNEL_REPORT") ?: "build/channel-health.txt")
            out.parentFile?.mkdirs()
            out.writeText(table)
        }

        val bad = results.filter { !it.ok }
        check(bad.isEmpty()) {
            "channel(s) ${bad.joinToString(", ") { it.number.toString() }} are not serving a fresh " +
                "snapshot. A client only notices when the ones ABOVE them fail too, which is how " +
                "four of six once stayed dead for nine days:\n" +
                bad.joinToString("\n") { "  " + it.render() }
        }
    }

    /**
     * The other direction, and it runs WITHOUT the network so it can never be skipped.
     *
     * A checker that has only ever been seen saying "ok" is not a checker. `.invalid` is reserved by
     * RFC 2606 and resolves nowhere, so this exercises the failure path on every ordinary test run —
     * including in an offline CI where the live probe above is skipped and would otherwise leave the
     * whole file unexecuted.
     */
    @Test
    fun `a dead channel is reported as a failure, not skipped`() {
        val bad = probe(9, "https://zat-channel-that-does-not-exist.invalid/snapshot.json")
        check(!bad.ok) { "an unresolvable channel must FAIL, got: ${bad.render()}" }
        check(bad.render().contains("channel 9")) { bad.render() }
    }

    private data class Probe(
        val number: Int,
        val ok: Boolean,
        val detail: String,
    ) {
        fun render(): String = "channel $number: ${if (ok) "ok" else "FAIL"} - $detail"
    }

    /**
     * Fetch a channel the way the CLIENT does, decode included.
     *
     * The first version of this used `HttpURLConnection` and decoded only gzip, while advertising
     * `gzip, deflate, br` like the client. Two channels answered in brotli, it read the compressed
     * bytes, and it reported "not JSON (1333 bytes) — a login or error page?" about channels that
     * were perfectly healthy. The give-away was the size: 1333 against 3551 uncompressed is a
     * compression ratio, not an error page.
     *
     * So this calls [BootstrapResolver.decodeBody] — the client's own decoder, the one
     * `release-check.sh` guards as "the fixed decode path (4 of 6 channels need it)". Reimplementing
     * it here is how the checker came to disagree with the thing it checks.
     */
    private fun probe(number: Int, url: String): Probe {
        return try {
            val http = okhttp3.OkHttpClient.Builder()
                .connectTimeout(java.time.Duration.ofSeconds(15))
                .readTimeout(java.time.Duration.ofSeconds(15))
                .build()
            val request = okhttp3.Request.Builder()
                .url(url)
                // The full browser Accept-Encoding the client advertises. A channel that only breaks
                // for a compression-capable client would otherwise pass here and fail in the field —
                // which is the failure this whole check exists to notice.
                .header("Accept-Encoding", "gzip, deflate, br")
                .header("User-Agent", "Mozilla/5.0")
                .get()
                .build()

            val resp = http.newCall(request).execute()
            val body: String? = resp.use { r ->
                if (!r.isSuccessful) return Probe(number, false, "http ${r.code}")
                BootstrapResolver.decodeBody(r, "channel-$number")
            }
            if (body.isNullOrBlank()) return Probe(number, false, "empty body after decode")
            val raw = body.toByteArray(Charsets.UTF_8)

            val obj = runCatching { Json.parseToJsonElement(body) as JsonObject }.getOrNull()
                ?: return Probe(number, false, "not JSON (${body.length} bytes) - a login or error page?")

            val generatedAt = obj["generated_at"]?.jsonPrimitive?.content
                ?: return Probe(number, false, "no generated_at - not a snapshot")
            val ageSeconds = (System.currentTimeMillis() - Instant.parse(generatedAt).toEpochMilli()) / 1000

            // A signed body served from a stale CDN edge is the failure that looks most like success.
            if (ageSeconds > freshEnoughSeconds) {
                Probe(number, false, "STALE by ${ageSeconds}s (generated_at=$generatedAt)")
            } else {
                Probe(number, true, "${raw.size} bytes, ${ageSeconds}s old")
            }
        } catch (e: Exception) {
            // The class, not the message: the message carries the host, and this output is meant to
            // be safe to paste (`RunDiagnostics` holds the same line).
            Probe(number, false, e.javaClass.simpleName)
        }
    }
}
