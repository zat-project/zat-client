package cloud.zat.meshoprf

/**
 * Kotlin binding for the Rust mesh VOPRF (`libmeshoprf.so`, B1a.1). One instance per
 * oblivious round: `create` → `blind` (→ request to the broker) → `finalizeEval`
 * (← the broker's evaluation, whose batched DLEQ proof is verified in Rust).
 *
 * `AutoCloseable`: `close()` frees the native object — use `MeshOprf.create(pk).use { … }`.
 * Not thread-safe; use one instance from one thread. Wire bytes are byte-identical to the
 * broker's `@cloudflare/voprf-ts` (ristretto255-SHA512); Rust does the framing + verify.
 */
class MeshOprf private constructor(private var handle: Long) : AutoCloseable {

    /** Blind a length-prefixed batch of tags → the voprf-ts-framed request bytes. */
    fun blind(inputsBlob: ByteArray): ByteArray {
        check(handle != 0L) { "MeshOprf is closed" }
        return nativeBlind(handle, inputsBlob)
    }

    /** Finalize the broker's evaluation (verifies the batched DLEQ proof) → outputs. */
    fun finalizeEval(evaluation: ByteArray): ByteArray {
        check(handle != 0L) { "MeshOprf is closed" }
        return nativeFinalize(handle, evaluation)
    }

    override fun close() {
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0L
        }
    }

    companion object {
        init {
            System.loadLibrary("meshoprf")
        }

        /** Create a round bound to the broker's mesh public key (32-byte compressed). */
        fun create(publicKey: ByteArray): MeshOprf = MeshOprf(nativeNew(publicKey))

        /** On-device smoke test: a full local VOPRF round inside the native lib (no broker).
         *  Confirms `libmeshoprf.so` loaded + the ristretto255 crypto works on this ABI.
         *  Returns an OK string; throws on failure. */
        fun selfTest(): String = nativeSelfTest()

        /**
         * B2a threshold coordinator, round 1: combine the committee's Round1 messages (framed as
         * `u16 count || (u16 len || blob)*count`) over the `blind` `request` → the between-rounds
         * `pending` bytes, whose FIRST 32 bytes are the challenge `c` to broadcast to the committee.
         * `publicKey` = the broker's mesh key `K` (same value used in `create`).
         */
        fun thrRound1(publicKey: ByteArray, request: ByteArray, round1s: ByteArray): ByteArray =
            nativeThrRound1(publicKey, request, round1s)

        /**
         * B2a threshold coordinator, round 2: combine the committee's Round2 messages → the
         * voprf-ts `evaluation` bytes that `finalizeEval` consumes UNCHANGED.
         */
        fun thrRound2(publicKey: ByteArray, pending: ByteArray, round2s: ByteArray): ByteArray =
            nativeThrRound2(publicKey, pending, round2s)

        @JvmStatic
        private external fun nativeNew(publicKey: ByteArray): Long

        @JvmStatic
        private external fun nativeBlind(handle: Long, inputsBlob: ByteArray): ByteArray

        @JvmStatic
        private external fun nativeFinalize(handle: Long, evaluation: ByteArray): ByteArray

        @JvmStatic
        private external fun nativeDestroy(handle: Long)

        @JvmStatic
        private external fun nativeSelfTest(): String

        @JvmStatic
        private external fun nativeThrRound1(
            publicKey: ByteArray,
            request: ByteArray,
            round1s: ByteArray,
        ): ByteArray

        @JvmStatic
        private external fun nativeThrRound2(
            publicKey: ByteArray,
            pending: ByteArray,
            round2s: ByteArray,
        ): ByteArray
    }
}
