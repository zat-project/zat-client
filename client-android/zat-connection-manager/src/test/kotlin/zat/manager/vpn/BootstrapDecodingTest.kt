package zat.manager.vpn

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * The bootstrap resolver must decode every Content-Encoding it advertises.
 *
 * This exists because it once did not: the browser profiles set `Accept-Encoding` by hand, and OkHttp
 * only decompresses transparently for the header IT adds. Compressed bodies were therefore read as
 * UTF-8 garbage, failed the `startsWith("{")` check, and were logged as "channel may be
 * challenged/blocked" — FOUR of the six bootstrap channels were dead that way (Cloudflare, jsDelivr
 * and Bitbucket serve `br`; raw.githubusercontent serves `gzip`), and the log blamed the censor for
 * our own bug.
 *
 * The fixtures are compressed by Node's zlib — a DIFFERENT implementation from the Java decoders
 * under test — so this is a genuine cross-implementation check, not a round-trip against ourselves.
 */
class BootstrapDecodingTest {

    private val plain = """{"schema_version":1,"servers":[{"host":"x"}]}"""

    private fun responseWith(encoding: String?, bodyB64: String): Response {
        val builder = Response.Builder()
            .request(Request.Builder().url("https://example.invalid/snapshot.json").build())
            .protocol(Protocol.HTTP_1_1)
            .code(200)
            .message("OK")
            .body(Base64.getDecoder().decode(bodyB64).toResponseBody("application/json".toMediaType()))
        if (encoding != null) builder.header("Content-Encoding", encoding)
        return builder.build()
    }

    private fun decode(encoding: String?, bodyB64: String): String? =
        BootstrapResolver.decodeBody(responseWith(encoding, bodyB64), "test-channel")

    @Test
    fun `brotli is decoded — the encoding that killed three channels`() {
        assertEquals(plain, decode("br", "CxaAeyJzY2hlbWFfdmVyc2lvbiI6MSwic2VydmVycyI6W3siaG9zdCI6IngifV19Aw=="))
    }

    @Test
    fun `gzip is decoded — the encoding that killed raw githubusercontent`() {
        assertEquals(plain, decode("gzip", "H4sIAAAAAAAACqtWKk7OSM1NjC9LLSrOzM9TsjLUUSpOLQJxlayiq5Uy8otLlKyUKpRqY2sBdbPOby0AAAA="))
    }

    @Test
    fun `zlib-wrapped and raw deflate are both decoded — both occur in the wild`() {
        assertEquals(plain, decode("deflate", "eJyrVipOzkjNTYwvSy0qzszPU7Iy1FEqTi0CcZWsoquVMvKLS5SslCqUamNrAXYPD9o="))
        assertEquals(plain, decode("deflate", "q1YqTs5IzU2ML0stKs7Mz1OyMtRRKk4tAnGVrKKrlTLyi0uUrJQqlGpjawE="))
    }

    @Test
    fun `an identity body is passed through, header present or absent`() {
        val b64 = Base64.getEncoder().encodeToString(plain.toByteArray())
        assertEquals(plain, decode(null, b64))
        assertEquals(plain, decode("identity", b64))
    }

    @Test
    fun `an encoding we cannot decode yields null rather than garbage`() {
        // zstd is the live example: Chrome 123+ advertises it, we deliberately do not, because
        // claiming an encoding we cannot read is exactly the bug this test guards. If a server ever
        // sends one anyway, the channel must fail cleanly — never surface as unreadable "text".
        assertNull(decode("zstd", Base64.getEncoder().encodeToString(byteArrayOf(0x28, 0xB5.toByte(), 0x2F, 0xFD.toByte()))))
    }

    @Test
    fun `a corrupt compressed body fails cleanly instead of throwing`() {
        assertNull(decode("br", Base64.getEncoder().encodeToString("not actually brotli".toByteArray())))
    }
}
