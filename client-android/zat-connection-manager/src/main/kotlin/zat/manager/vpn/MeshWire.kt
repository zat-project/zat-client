package zat.manager.vpn

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Pure client mirrors of the broker's mesh derivations (B1a.1) — byte-exact ports of
 * `broker/src/rendezvous/mesh-buckets.ts` + `mesh-record.ts`, so the client's VOPRF
 * inputs and record decryption match the broker. No Android deps → JVM-unit-testable
 * (base64/HTTP live in [MeshRendezvousClient]).
 */
object MeshWire {

    /** Unit separator (0x1f) — the broker's `\x1f` join char. Built from the code point so
     *  no raw control char or fragile escape lives in the source. */
    private val US = 0x1F.toChar().toString()

    /** `zat:mesh:<purpose>\x1f<part>\x1f<part>…` (UTF-8) — the cross-language wire contract. */
    /**
     * A short, non-invertible fingerprint of a derived key, for comparing the two ends of a seal.
     *
     * 32 bits of SHA-256 over the key — enough to tell "the same key" from "a different key" in a
     * log, far too little to be the key. The volunteer prints the identical value for the same
     * bucket (`mesh_seal::key_fingerprint`), which is the point: a count told us a record would not
     * open; a fingerprint tells us whether the reader and the writer agree on what the key IS (R21).
     */
    fun keyFingerprint(key: ByteArray): String {
        val d = java.security.MessageDigest.getInstance("SHA-256").digest(key)
        return "%02x%02x%02x%02x".format(d[0], d[1], d[2], d[3])
    }

    fun meshTag(purpose: String, vararg parts: Any): ByteArray =
        ("zat:mesh:$purpose" + US + parts.joinToString(US)).toByteArray(Charsets.UTF_8)

    /** First 6 bytes big-endian, mod N (mirrors `indexFromDigest`). */
    fun indexFromDigest(digest: ByteArray, n: Int): Int {
        var v = 0L
        for (i in 0 until 6) v = (v shl 8) or (digest[i].toLong() and 0xFF)
        return (v % n).toInt()
    }

    /** `SHA-256("zat:mesh:sr\x1f"+epoch)` hex, first 32 chars (mirrors `sharedRandomFor`). */
    fun sharedRandomFor(epoch: Long): String {
        val h = MessageDigest.getInstance("SHA-256")
            .digest(("zat:mesh:sr" + US + epoch).toByteArray(Charsets.UTF_8))
        return h.joinToString("") { "%02x".format(it) }.substring(0, 32)
    }

    /** inputs blob = u16(count) || ( u16(len) || tag )*count (what `MeshOprf.blind` parses). */
    fun buildInputsBlob(tags: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, tags.size)
        for (t in tags) {
            writeU16(out, t.size)
            out.write(t)
        }
        return out.toByteArray()
    }

    /** Split `MeshOprf.finalizeEval` output = u16(count) || out(elemLen)*count. */
    fun parseOutputs(blob: ByteArray, elemLen: Int): List<ByteArray> {
        val count = readU16(blob, 0)
        val out = ArrayList<ByteArray>(count)
        var off = 2
        repeat(count) {
            out.add(blob.copyOfRange(off, off + elemLen))
            off += elemLen
        }
        return out
    }

    /**
     * Open a mesh record sealed as `iv(12) || tag(16) || ct` (raw bytes; the base64url
     * decode happens in the caller). `key` is the 32-byte AES-256-GCM key (the first 32
     * bytes of the 64-byte VOPRF output). Returns the plaintext, or null if the key is
     * wrong / the bytes were tampered.
     */
    fun aesGcmOpen(key: ByteArray, sealed: ByteArray): ByteArray? {
        if (key.size != 32 || sealed.size < 12 + 16) return null
        return try {
            val iv = sealed.copyOfRange(0, 12)
            val tag = sealed.copyOfRange(12, 28)
            val ct = sealed.copyOfRange(28, sealed.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            cipher.doFinal(ct + tag) // JCA expects ciphertext||tag
        } catch (e: Exception) {
            null
        }
    }

    private fun writeU16(out: ByteArrayOutputStream, n: Int) {
        out.write((n ushr 8) and 0xFF)
        out.write(n and 0xFF)
    }

    private fun readU16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
}
