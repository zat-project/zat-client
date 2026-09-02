package zat.manager.vpn

/**
 * StealthConfig — Phase 13 (Anti-Censorship Hardening)
 *
 * Encrypted URL vault for bootstrap channel discovery. All channel URLs
 * (and decoy URLs) are stored using a custom 3-layer encryption scheme
 * so they cannot be extracted by static analysis tools (strings, jadx,
 * apktool, etc.).
 *
 * Encryption layers:
 *   1. XOR with a per-byte rotating key derived from scattered constants.
 *   2. Fisher-Yates byte-position shuffle with a seeded deterministic PRNG.
 *   3. Storage as IntArray literals (not Base64 strings).
 *
 * The vault contains 14 encrypted entries: 6 real bootstrap channels and
 * 8 realistic VPN-related decoy URLs, interleaved in non-sequential order.
 * Only the real channels are selected at runtime via an obfuscated index
 * array. An analyst who decrypts the vault still cannot easily determine
 * which entries are real and which are decoys without tracing the runtime
 * selection logic through obfuscated code.
 *
 * Privacy rules:
 *   - No user identity, Telegram data, or device info is stored here.
 *   - The vault contains only public endpoint URLs.
 */
internal object StealthConfig {

    // --- Key material (scattered to resist grep) ---
    private const val _p1 = "net.tele"
    private const val _p2 = "gram.zat"

    // Cryptographic constants (golden ratio fractional bits, SHA-256 IV)
    private const val _gr = 0x9E3779B9.toInt() // -1640531527
    private const val _ss = 0x6A09E667         // 1779033703

    // --- PRNG state (Linear Congruential Generator) ---
    // Using Numerical Recipes LCG parameters for full-period 31-bit PRNG.
    private var _ps = 0

    private fun prngInit(seed: Int) {
        _ps = seed
    }

    private fun prngNext(): Int {
        _ps = (_ps * 1664525 + 1013904223) and 0x7FFFFFFF
        return _ps
    }

    private fun prngNextInt(bound: Int): Int {
        return prngNext() % bound
    }

    // --- Real channel indices (ordered: Direct, GitHub, GitLab, R2, jsDelivr, Bitbucket) ---
    private val _ri = intArrayOf(2, 4, 6, 9, 11, 13)

    // --- Encrypted URL vault (14 entries: 6 real + 8 decoy, interleaved) ---
    private val _vault = arrayOf(
        intArrayOf(111, 203, 211, 208, 249, 88, 152, 163, 57, 238, 68, 27, 132, 34, 214, 11, 246, 139, 231, 46, 83, 61, 9, 150, 104, 255, 46, 50, 12, 190, 33, 67, 167, 197, 35),
        intArrayOf(115, 67, 74, 3, 57, 87, 83, 88, 251, 86, 244, 33, 197, 246, 104, 214, 79, 61, 222, 231, 42, 188, 181, 38, 132, 9, 5, 20, 110, 152, 197, 79, 193, 70, 146, 208, 69, 83, 171, 233, 198, 143, 249, 176, 36, 33, 126, 211, 184, 120, 210, 27, 168, 107, 190, 98, 195, 127, 229, 164, 128, 49, 26, 186, 150, 123, 211, 212, 59, 183, 253, 235, 92, 9, 150, 251, 186, 85, 120, 137),
        intArrayOf(246, 31, 9, 65, 157, 212, 190, 120, 44, 237, 209, 166, 131, 250, 193, 90, 208, 238, 231, 109, 27, 34, 97, 155, 77, 67, 152, 179, 200, 104, 48, 236, 154, 91, 137, 90, 169, 170, 39, 40, 81, 76, 126, 6, 197, 57, 249, 83, 50),
        intArrayOf(141, 133, 73, 110, 111, 9, 36, 33, 197, 75, 57, 105, 181, 59, 55, 70, 190, 121, 64, 208, 125, 123, 163, 207, 115, 178, 227, 17, 83, 73, 146, 212, 255, 197, 155, 87, 76, 180, 156, 5, 181, 252, 246, 152, 222, 7, 146, 32, 67, 92, 244, 231, 150, 24, 85, 152, 202, 205, 64, 244),
        intArrayOf(87, 48, 122, 57, 251, 190, 245, 234, 208, 172, 180, 212, 211, 181, 33, 86, 69, 193, 32, 110, 197, 247, 146, 32, 104, 121, 67, 91, 83, 36, 150, 216, 9, 49, 252, 244, 213, 103, 106, 88, 135, 191, 143, 83, 152, 8, 78, 219, 126, 27, 77, 173, 246, 64, 64, 211, 115, 85, 162, 182, 193, 40, 143, 152, 231, 123, 68, 127, 214, 168, 19, 233),
        intArrayOf(125, 208, 179, 118, 64, 6, 245, 174, 98, 42, 58, 154, 62, 31, 1, 212, 105, 31, 231, 54, 144, 134, 190, 154, 49, 225, 186, 98, 9, 57, 206, 34, 234, 30, 126, 10, 246, 75, 22, 202, 169, 193, 221, 182, 152, 153, 83, 182, 83, 228, 97, 150, 21, 14, 214, 171, 235, 120, 77, 55, 78, 160, 197, 1, 166, 74, 193),
        intArrayOf(246, 231, 141, 86, 51, 48, 31, 169, 51, 236, 235, 187, 210, 202, 152, 118, 208, 245, 81, 255, 118, 4, 143, 121, 179, 120, 49, 131, 197, 111, 89, 194, 224, 57, 223, 189, 139, 149, 174, 186, 83, 27, 97, 153, 79, 1, 9, 106, 35, 222, 86, 225, 33, 249, 2, 18, 42, 199, 73, 71, 190, 83, 108, 176, 158),
        intArrayOf(152, 197, 83, 79, 146, 197, 166, 67, 57, 124, 33, 123, 124, 211, 69, 246, 86, 27, 193, 106, 110, 175, 168, 115, 2, 246, 49, 134, 104, 253, 150, 212, 181, 211, 150, 71, 241, 85, 190, 178, 162, 77, 126, 201, 91, 233, 179, 55, 0, 231, 126, 21, 244, 3, 83, 251, 198, 49, 251, 103, 143, 36, 9, 214, 140, 92),
        intArrayOf(246, 165, 231, 143, 197, 85, 36, 104, 92, 58, 182, 36, 138, 181, 27, 123, 193, 156, 211, 202, 57, 249, 139, 167, 233, 110, 98, 210, 83, 197, 152, 188, 211, 193, 251, 23, 44, 163, 126, 109, 168, 91, 168, 33, 172, 72, 83, 21, 9, 56, 211, 188, 247, 7, 100, 124, 51, 111, 104, 194, 146, 94, 69, 115, 49, 72, 244, 234, 190, 105, 248, 67, 155, 150, 1, 86, 180, 153, 214, 80, 187, 87, 70),
        intArrayOf(246, 231, 221, 75, 126, 101, 3, 242, 124, 236, 165, 224, 202, 155, 152, 118, 198, 172, 81, 236, 106, 71, 146, 121, 173, 36, 38, 200, 197, 101, 68, 136, 187, 57, 143, 189, 136, 149, 177, 178, 6, 27, 60, 195, 74, 64, 9, 106, 35, 134, 29, 225, 105, 249, 89, 8, 122, 199, 73, 66, 190, 83, 105, 176, 146),
        intArrayOf(156, 152, 83, 215, 204, 237, 12, 233, 190, 44, 165, 29, 57, 87, 43, 156, 109, 50, 234, 117, 221, 74, 136, 213, 44, 139, 189, 98, 83, 234, 197, 210, 60, 228, 123, 77, 232, 231, 2, 124, 38, 238, 119, 214, 56, 246, 0, 182, 53, 58, 254, 38, 241, 232, 189, 88, 97, 202, 100, 19, 190, 196, 67, 128, 48, 95, 165, 9, 127, 129, 83, 181, 206, 29),
        intArrayOf(152, 197, 83, 64, 136, 213, 146, 67, 57, 82, 44, 98, 18, 209, 10, 211, 87, 29, 221, 43, 117, 189, 233, 50, 2, 246, 28, 182, 35, 220, 150, 208, 190, 202, 151, 12, 246, 88, 190, 160, 226, 105, 126, 150, 41, 234, 177, 106, 54, 231, 123, 58, 228, 9, 93, 243, 165, 60, 232, 37, 196, 53, 9, 209, 170, 67),
        intArrayOf(152, 141, 208, 231, 118, 182, 4, 195, 127, 249, 131, 71, 246, 165, 57, 60, 243, 27, 134, 147, 52, 44, 246, 236, 37, 214, 31, 71, 104, 15, 209, 190, 156, 52, 122, 16, 230, 52, 152, 38, 9, 151, 235, 236, 83, 74, 98, 212, 3, 248, 40, 178, 153, 8, 197, 70, 22, 234, 247, 87, 205, 90, 124),
        intArrayOf(246, 231, 135, 11, 61, 58, 88, 171, 51, 236, 235, 161, 210, 198, 152, 118, 208, 183, 81, 255, 118, 4, 143, 121, 243, 114, 52, 144, 197, 96, 19, 213, 162, 57, 145, 189, 141, 149, 235, 249, 71, 27, 122, 152, 79, 15, 9, 106, 35, 156, 87, 225, 109, 249, 14, 76, 44, 199, 73, 77, 190, 83, 108, 176, 158)
    )

    // --- Encrypted Ed25519 signing public key (raw 32-byte key, Base64-encoded then encrypted) ---
    // Rotated 2026-06-17: the prior key had been inside the Drive-synced tree. The matching
    // private key exists only in the broker's .env (SNAPSHOT_SIGNING_PRIVATE_KEY) and was
    // generated off-session by the operator.
    private val _sigPubKey = intArrayOf(102, 223, 161, 53, 93, 137, 223, 163, 92, 176, 94, 45, 214, 44, 55, 172, 136, 96, 171, 213, 126, 5, 106, 240, 0, 206, 151, 167, 115, 217, 94, 117, 56, 252, 189, 238, 177, 27, 233, 165, 16, 240, 3, 108)

    // --- B2b.4: the committee's threshold snapshot-signing group key P_snap (SECONDARY pinned key) ---
    // Accepted during the trust-anchor rollover overlap (see docs/B2b_TRUST_ANCHOR_v0.1.md): once the
    // broker serves the committee (threshold) signature under ZAT_MESH_SNAPSHOT_FLIP, this key verifies
    // it while the primary single-key signature still works. EMPTY ⇒ dormant (primary only), so behaviour
    // is identical to today until a real P_snap (from a committee DKG) is captured + stealth-encoded here.
    private val _snapPubKey = intArrayOf(98,246,160,110,85,152,209,163,29,176,122,126,192,60,20,160,156,22,206,207,87,54,110,230,121,238,173,137,118,200,88,81,48,238,163,175,142,63,225,191,21,182,49,51)

    /**
     * Returns the ordered list of real bootstrap channel URLs.
     * URLs are decrypted on-the-fly and the complete string exists in
     * memory only briefly during the HTTP request lifecycle.
     */
    fun getChannelUrls(): List<String> {
        return _ri.map { idx -> decrypt(_vault[idx]) }
    }

    /**
     * The broker's old Ed25519 snapshot-signing public key — **RETIRED at A3 rung 5 (2026-07-28)**
     * and no longer consulted by anything.
     *
     * Deliberately left here rather than deleted, as the record of what was dropped. Calling it again
     * would re-admit a key we hold, which is exactly the thread rung 5 cut: after this, no key of ours
     * can produce a snapshot or a revocation any client will accept. Verification goes through
     * [getSnapshotThresholdPublicKey] — the committee's `P_snap` — and nothing else.
     */
    @Deprecated(
        "Retired at A3 rung 5 — verify against getSnapshotThresholdPublicKey() (P_snap) instead.",
        level = DeprecationLevel.WARNING,
    )
    fun getSigningPublicKey(): ByteArray {
        val base64Str = decrypt(_sigPubKey)
        return android.util.Base64.decode(base64Str, android.util.Base64.NO_WRAP)
    }

    /**
     * B2b.4: the committee threshold group key `P_snap` (raw 32 bytes), or `null` when unset
     * (dormant — the snapshot verifier then pins only the primary key, exactly as today). Decoded
     * on-the-fly like the primary key once a real `P_snap` is stealth-encoded into `_snapPubKey`.
     */
    fun getSnapshotThresholdPublicKey(): ByteArray? {
        if (_snapPubKey.isEmpty()) return null
        val base64Str = decrypt(_snapPubKey)
        return android.util.Base64.decode(base64Str, android.util.Base64.NO_WRAP)
    }

    // ================================================================
    // Decryption engine — reverses the 3-layer encryption.
    // Layer order is reversed: unshuffle first, then XOR.
    // ================================================================

    /**
     * Decrypts an IntArray-encoded ciphertext back to plaintext.
     *
     * @param data Encrypted byte values stored as IntArray.
     * @return The original plaintext string.
     */
    private fun decrypt(data: IntArray): String {
        val n = data.size
        val bytes = ByteArray(n) { data[it].toByte() }
        val baseKey = ("zat" + _p1 + _p2).hashCode()

        // Reverse Layer 2: Collect Fisher-Yates swap pairs, apply in reverse.
        prngInit(_ss)
        val swaps = mutableListOf<Pair<Int, Int>>()
        for (i in n - 1 downTo 1) {
            swaps.add(Pair(i, prngNextInt(i + 1)))
        }
        for ((i, j) in swaps.asReversed()) {
            val tmp = bytes[i]
            bytes[i] = bytes[j]
            bytes[j] = tmp
        }

        // Reverse Layer 1: XOR with rotating key (self-inverse).
        for (i in 0 until n) {
            val rotKey = (baseKey xor (i * _gr)) and 0xFF
            bytes[i] = (bytes[i].toInt() xor rotKey).toByte()
        }

        return String(bytes, Charsets.UTF_8)
    }
}
