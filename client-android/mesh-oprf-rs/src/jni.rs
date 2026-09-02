//! JNI bridge for `cloud.zat.meshoprf.MeshOprf` (Android only).
//!
//! A `MeshOprf` round is a heap-boxed native object referenced from Kotlin by an
//! opaque `long` handle: `nativeNew` allocates it, `nativeBlind`/`nativeFinalize`
//! operate on it, `nativeDestroy` frees it. The Kotlin wrapper is `AutoCloseable`
//! and uses one instance per oblivious round from a single thread, so no `Send`/
//! locking is needed. Errors surface as Java `RuntimeException`s.

use crate::MeshOprf;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jlong, jstring};
use jni::JNIEnv;

#[no_mangle]
pub extern "system" fn Java_cloud_zat_meshoprf_MeshOprf_nativeSelfTest<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match crate::self_test() {
        Ok(s) => env
            .new_string(s)
            .map(|j| j.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_cloud_zat_meshoprf_MeshOprf_nativeNew<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pub_key: JByteArray<'local>,
) -> jlong {
    let bytes = match env.convert_byte_array(&pub_key) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    match MeshOprf::new(&bytes) {
        Ok(m) => Box::into_raw(Box::new(m)) as jlong,
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_cloud_zat_meshoprf_MeshOprf_nativeBlind<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    inputs_blob: JByteArray<'local>,
) -> jbyteArray {
    let bytes = match env.convert_byte_array(&inputs_blob) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    // SAFETY: `handle` is a live pointer from nativeNew, used single-threaded.
    let m = unsafe { &mut *(handle as *mut MeshOprf) };
    match m.blind(&bytes) {
        Ok(out) => env
            .byte_array_from_slice(&out)
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_cloud_zat_meshoprf_MeshOprf_nativeFinalize<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    evaluation: JByteArray<'local>,
) -> jbyteArray {
    let bytes = match env.convert_byte_array(&evaluation) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    // SAFETY: `handle` is a live pointer from nativeNew, used single-threaded.
    let m = unsafe { &*(handle as *const MeshOprf) };
    match m.finalize(&bytes) {
        Ok(out) => env
            .byte_array_from_slice(&out)
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

/// B2a threshold coordinator, round 1 (static — no per-round handle needed): combine the
/// committee's Round1 messages → the between-rounds `Pending` bytes (its first 32 bytes are the
/// challenge `c` to broadcast). Args: `pk`, the `blind` request, the framed Round1 list.
#[no_mangle]
pub extern "system" fn Java_cloud_zat_meshoprf_MeshOprf_nativeThrRound1<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pk: JByteArray<'local>,
    request: JByteArray<'local>,
    round1s: JByteArray<'local>,
) -> jbyteArray {
    let (pk, request, round1s) = match (
        env.convert_byte_array(&pk),
        env.convert_byte_array(&request),
        env.convert_byte_array(&round1s),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return std::ptr::null_mut(),
    };
    match crate::thr_round1(&pk, &request, &round1s) {
        Ok(out) => env
            .byte_array_from_slice(&out)
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

/// B2a threshold coordinator, round 2: combine the committee's Round2 messages → the voprf-ts
/// `evaluation` blob that `nativeFinalize` consumes unchanged. Args: `pk`, the round-1 `pending`
/// bytes, the framed Round2 list.
#[no_mangle]
pub extern "system" fn Java_cloud_zat_meshoprf_MeshOprf_nativeThrRound2<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pk: JByteArray<'local>,
    pending: JByteArray<'local>,
    round2s: JByteArray<'local>,
) -> jbyteArray {
    let (pk, pending, round2s) = match (
        env.convert_byte_array(&pk),
        env.convert_byte_array(&pending),
        env.convert_byte_array(&round2s),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return std::ptr::null_mut(),
    };
    match crate::thr_round2(&pk, &pending, &round2s) {
        Ok(out) => env
            .byte_array_from_slice(&out)
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_cloud_zat_meshoprf_MeshOprf_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: `handle` came from Box::into_raw in nativeNew and is freed once.
        unsafe { drop(Box::from_raw(handle as *mut MeshOprf)) };
    }
}
