# mesh-oprf-rs — the Android client mesh VOPRF (B1a.1)

Rust `cdylib` that wraps the [`voprf`](https://crates.io/crates/voprf) crate
(**ristretto255-SHA512**, RFC 9497) and exposes it to Kotlin over JNI as
`cloud.zat.meshoprf.MeshOprf`. It derives a token's oblivious mesh bucket set + record
keys against the broker's `@cloudflare/voprf-ts` — **validated wire-compatible**
(cross-lib gate: Rust `finalize` == voprf-ts `evaluate`, DLEQ proof verified).

**Why Rust, not gomobile/CIRCL:** the app already embeds libbox (a gomobile Go
runtime). Two gomobile `.aar`s cannot coexist in one process (duplicate Go runtime →
crashes). Rust has no global runtime, so `libmeshoprf.so` loads alongside libbox
cleanly. The `voprf` crate implements only ristretto255, so the whole mesh uses
ristretto255-SHA512.

## API (JNI → Kotlin)
One `MeshOprf` per oblivious round (a handle to a heap-boxed native object):

```
nativeNew(pubKey: ByteArray) -> long          // broker mesh pubkey (32B compressed)
nativeBlind(handle, inputsBlob) -> ByteArray  // -> POST /mesh/blind-evaluate {request}
nativeFinalize(handle, evaluation) -> ByteArray // verifies the batched DLEQ proof
nativeDestroy(handle)
```

Wire formats (big-endian), byte-identical to voprf-ts:
- inputs blob: `u16(count) || ( u16(len) || tag )*count`
- request:     `u16(count) || elem(32)*count`
- evaluation:  `u16(count) || elem(32)*count || mode(1) || proof(64)`
- outputs:     `u16(count) || out(64)*count`  (SHA-512, Nh=64; take `out[..32]` for the AES-256-GCM key)

Batching matters: the broker returns ONE batched DLEQ proof, so the client uses
`batch_finalize` to verify it over all elements at once.

## Build
`./build.sh` (see it for one-time setup). Outputs `jniLibs/<abi>/libmeshoprf.so` for
arm64-v8a, armeabi-v7a, x86, x86_64. Host unit tests: `cargo test`.
