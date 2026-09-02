//! ZAT mesh VOPRF — the Android JNI wrapper (B1a.1 + B2a).
//!
//! The OPRF client-side crypto (blind/finalize + the B2a threshold coordinator) lives in the
//! shared `zat-oprf-client` crate, used by BOTH the mobile client here and the volunteer's B2a
//! record seal. This crate is only the thin Android layer: it re-exports that core and adds the
//! JNI bridge (`jni.rs`), building as the `libmeshoprf.so` the Kotlin app loads via cargo-ndk.
//! Kept as its own crate so the `.so` build + the app's jniLibs wiring stay unchanged.

pub use zat_oprf_client::*;

#[cfg(target_os = "android")]
mod jni;
