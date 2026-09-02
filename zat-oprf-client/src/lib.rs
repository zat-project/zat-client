//! ZAT mesh OPRF — the client-side crypto (ristretto255-SHA512, RFC 9497).
//!
//! Wraps the `voprf` crate and frames its protocol messages byte-compatible with the broker's
//! `@cloudflare/voprf-ts` (validated cross-lib: Rust `finalize` == voprf-ts `evaluate`, DLEQ
//! verified). SHARED by both OPRF clients in the mesh: the Android mobile client (via the
//! `mesh-oprf-rs` JNI wrapper, which re-exports this) for its oblivious READ, and the volunteer
//! for its record SEAL (B2a P3 — the volunteer derives its seal keys from the same committee).
//! Pure Rust (no global runtime), so it coexists with libbox's Go runtime in the Android process.
//!
//! Wire formats (big-endian), matching voprf-ts exactly:
//!   - inputs blob (caller → blind):  u16(count) || ( u16(len) || tag )*count
//!   - request     (blind → issuer):  u16(count) || elem(32)*count
//!   - evaluation  (issuer → finalize): u16(count) || elem(32)*count || mode(1) || proof(64)
//!   - outputs     (finalize → caller): u16(count) || out(64)*count   (SHA-512, Nh=64)

use rand::rngs::OsRng;
use voprf::{CipherSuite, EvaluationElement, Group, Proof, VoprfClient};
use zat_threshold_oprf::{Coordinator, Pending, Round1, Round2};

/// ristretto255-SHA512 (the only suite the `voprf` crate implements; the whole mesh
/// uses it). The ID must match voprf-ts's suite identifier for the context strings
/// to agree (cross-lib gate confirmed it).
pub struct Ristretto255Suite;
impl CipherSuite for Ristretto255Suite {
    const ID: &'static str = "ristretto255-SHA512";
    type Group = voprf::Ristretto255;
    type Hash = sha2::Sha512;
}

type Cs = Ristretto255Suite;
type Elem = <<Cs as CipherSuite>::Group as Group>::Elem;

const ELEM_LEN: usize = 32; // ristretto255 compressed element
const PROOF_LEN: usize = 64; // two ristretto255 scalars (c‖s)

/// One oblivious round: `new` → `blind` (→ request to broker) → `finalize`
/// (← evaluation from broker). Holds the per-round client state between the two calls.
pub struct MeshOprf {
    pk: Elem,
    clients: Vec<VoprfClient<Cs>>,
    inputs: Vec<Vec<u8>>,
}

impl MeshOprf {
    /// Build from the broker's mesh public key (raw 32-byte compressed ristretto point
    /// from `GET /mesh/params`, base64-decoded by the caller).
    pub fn new(pub_key: &[u8]) -> Result<Self, String> {
        let pk = <Cs as CipherSuite>::Group::deserialize_elem(pub_key)
            .map_err(|e| format!("bad public key: {e:?}"))?;
        Ok(Self {
            pk,
            clients: Vec::new(),
            inputs: Vec::new(),
        })
    }

    /// Blind a length-prefixed batch of tags; returns the voprf-ts-framed request and
    /// stores the client state for the matching `finalize`.
    pub fn blind(&mut self, inputs_blob: &[u8]) -> Result<Vec<u8>, String> {
        let inputs = parse_inputs_blob(inputs_blob)?;
        let mut rng = OsRng;
        let mut out = Vec::with_capacity(2 + inputs.len() * ELEM_LEN);
        out.extend_from_slice(&(inputs.len() as u16).to_be_bytes());
        for input in inputs {
            let res =
                VoprfClient::<Cs>::blind(&input, &mut rng).map_err(|e| format!("blind: {e:?}"))?;
            out.extend_from_slice(res.message.serialize().as_ref());
            self.clients.push(res.state);
            self.inputs.push(input);
        }
        Ok(out)
    }

    /// Parse the broker's voprf-ts-framed evaluation, verify the batched DLEQ proof,
    /// and return the length-prefixed 64-byte outputs. Must follow a matching `blind`.
    pub fn finalize(&self, evaluation: &[u8]) -> Result<Vec<u8>, String> {
        if self.clients.is_empty() {
            return Err("finalize before blind".into());
        }
        if evaluation.len() < 2 {
            return Err("short evaluation".into());
        }
        let count = u16::from_be_bytes([evaluation[0], evaluation[1]]) as usize;
        if count != self.clients.len() {
            return Err(format!("count {count} != blinded {}", self.clients.len()));
        }
        let mut off = 2usize;
        let mut eval_elems = Vec::with_capacity(count);
        for _ in 0..count {
            let end = off + ELEM_LEN;
            if end > evaluation.len() {
                return Err("truncated evaluation element".into());
            }
            eval_elems.push(
                EvaluationElement::<Cs>::deserialize(&evaluation[off..end])
                    .map_err(|e| format!("eval elem: {e:?}"))?,
            );
            off = end;
        }
        off += 1; // skip the voprf-ts mode byte
        let end = off + PROOF_LEN;
        if end > evaluation.len() {
            return Err("truncated proof".into());
        }
        let proof =
            Proof::<Cs>::deserialize(&evaluation[off..end]).map_err(|e| format!("proof: {e:?}"))?;

        let outputs =
            VoprfClient::batch_finalize(&self.inputs, &self.clients, &eval_elems, &proof, self.pk)
                .map_err(|e| format!("batch_finalize (DLEQ verify): {e:?}"))?;

        let mut out = Vec::new();
        out.extend_from_slice(&(count as u16).to_be_bytes());
        for o in outputs {
            let o = o.map_err(|e| format!("output: {e:?}"))?;
            out.extend_from_slice(o.as_ref());
        }
        Ok(out)
    }
}

// ---- B2a threshold coordinator (Kotlin owns the HTTP to the committee; this owns the crypto) ----
//
// The client blinds a batch exactly as for the single-key broker, but instead of one broker
// `blindEvaluate` it drives `t` committee nodes: POST the blinded batch to each `/threshold/commit`
// (round 1), combine → a challenge `c`, broadcast `c` to each `/threshold/respond` (round 2),
// combine → the SAME voprf-ts `evaluation` blob `finalize` already consumes. So `blind` + `finalize`
// are UNCHANGED; only how the evaluation is obtained differs. `curve25519-dalek` stays out of here —
// everything crosses the `zat-threshold-oprf` byte seam.

/// A list of committee messages framed like the inputs blob: `u16(count) || (u16(len) || blob)*count`.
fn parse_message_list(b: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    parse_inputs_blob(b) // identical framing (count of length-prefixed byte strings)
}

/// The `t` blinded points from a `blind`-produced request (`u16(count) || elem(32)*count`).
fn parse_request_blinded(request: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if request.len() < 2 {
        return Err("short request".into());
    }
    let count = u16::from_be_bytes([request[0], request[1]]) as usize;
    if request.len() != 2 + count * ELEM_LEN {
        return Err("request length mismatch".into());
    }
    let mut out = Vec::with_capacity(count);
    let mut off = 2;
    for _ in 0..count {
        let mut e = [0u8; 32];
        e.copy_from_slice(&request[off..off + ELEM_LEN]);
        out.push(e);
        off += ELEM_LEN;
    }
    Ok(out)
}

fn to32(b: &[u8]) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(b).map_err(|_| "expected 32 bytes".to_string())
}

/// Coordinator round 1: combine the committee's `Round1` messages over the blinded batch → the
/// between-rounds `Pending` state. Its FIRST 32 bytes are the challenge `c` the caller broadcasts to
/// the committee for round 2 (the rest is opaque). `round1s` = the framed list of node Round1 blobs;
/// `pk` = the group key `K` (32-byte compressed ristretto from `/mesh/params`).
pub fn thr_round1(pk: &[u8], request: &[u8], round1s: &[u8]) -> Result<Vec<u8>, String> {
    let coord = Coordinator::from_pk_bytes(&to32(pk)?)?;
    let blinded = parse_request_blinded(request)?;
    let msgs = parse_message_list(round1s)?
        .iter()
        .map(|b| Round1::from_bytes(b))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(coord.round1(&blinded, &msgs)?.to_bytes())
}

/// Coordinator round 2: combine the committee's `Round2` messages → the voprf-ts-framed
/// `evaluation` blob (`u16 count || E*count || mode(0x01) || proof(64)`) that `MeshOprf::finalize`
/// consumes UNCHANGED. `pending` is the round-1 output; `round2s` the framed list of Round2 blobs.
pub fn thr_round2(pk: &[u8], pending: &[u8], round2s: &[u8]) -> Result<Vec<u8>, String> {
    let coord = Coordinator::from_pk_bytes(&to32(pk)?)?;
    let pending = Pending::from_bytes(pending)?;
    let msgs = parse_message_list(round2s)?
        .iter()
        .map(|b| Round2::from_bytes(b))
        .collect::<Result<Vec<_>, _>>()?;
    let (evals, proof) = coord.round2(&pending, &msgs)?;
    let mut out = Vec::with_capacity(2 + evals.len() * ELEM_LEN + 1 + PROOF_LEN);
    out.extend_from_slice(&(evals.len() as u16).to_be_bytes());
    for e in &evals {
        out.extend_from_slice(e);
    }
    out.push(0x01); // voprf-ts VOPRF mode byte
    out.extend_from_slice(&proof);
    Ok(out)
}

/// inputs blob = u16(count) || ( u16(len) || tag )*count
fn parse_inputs_blob(b: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if b.len() < 2 {
        return Err("short inputs blob".into());
    }
    let count = u16::from_be_bytes([b[0], b[1]]) as usize;
    let mut off = 2usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if off + 2 > b.len() {
            return Err("truncated inputs blob".into());
        }
        let n = u16::from_be_bytes([b[off], b[off + 1]]) as usize;
        off += 2;
        if off + n > b.len() {
            return Err("truncated input".into());
        }
        out.push(b[off..off + n].to_vec());
        off += n;
    }
    Ok(out)
}

/// E2 stub: without the `self-test` feature (the SHIPPED release build) the diagnostic and its
/// server-side `VoprfServer` are excluded entirely, so the client binary carries no server OPRF.
/// Returns Ok (a benign "disabled" status, NOT an error) so the caller's diagnostic log stays
/// harmless — `jni.rs` throws only on Err.
#[cfg(not(feature = "self-test"))]
pub fn self_test() -> Result<String, String> {
    Ok("self-test diagnostic not built into this (release) binary".to_string())
}

/// On-device smoke test: runs a FULL local VOPRF round (client blind → a local server
/// batch-evaluate → client finalize, batched DLEQ verified) entirely in-process, needing
/// no broker. Proves `libmeshoprf.so` loaded and the ristretto255 crypto works on the
/// target ABI — and, when called from the :vpn process, that it coexists with libbox's Go
/// runtime (the whole reason for Rust). Returns a human-readable OK string, or an error.
///
/// NOTE: pulls in `VoprfServer` (server side) purely for the self-check, so it is feature-gated
/// behind `self-test` (OFF by default) — the SHIPPED release build gets the stub above and carries
/// no server-side OPRF (E2); a dev/diagnostic build (`--features self-test`) runs the real round.
#[cfg(feature = "self-test")]
pub fn self_test() -> Result<String, String> {
    use voprf::{BlindedElement, VoprfServer};
    let mut rng = OsRng;
    let server = VoprfServer::<Cs>::new(&mut rng).map_err(|e| format!("server: {e:?}"))?;
    let pk_bytes = <Cs as CipherSuite>::Group::serialize_elem(server.get_public_key());
    let mut m = MeshOprf::new(pk_bytes.as_ref())?;

    let input: &[u8] = b"zat-mesh-selftest";
    let mut blob = 1u16.to_be_bytes().to_vec();
    blob.extend_from_slice(&(input.len() as u16).to_be_bytes());
    blob.extend_from_slice(input);
    let req = m.blind(&blob)?;

    let count = u16::from_be_bytes([req[0], req[1]]) as usize;
    let mut blinded = Vec::with_capacity(count);
    let mut off = 2usize;
    for _ in 0..count {
        blinded.push(
            BlindedElement::<Cs>::deserialize(&req[off..off + ELEM_LEN])
                .map_err(|e| format!("blinded: {e:?}"))?,
        );
        off += ELEM_LEN;
    }
    let result = server
        .batch_blind_evaluate(&mut rng, &blinded)
        .map_err(|e| format!("evaluate: {e:?}"))?;

    let mut eval = (count as u16).to_be_bytes().to_vec();
    for e in &result.messages {
        eval.extend_from_slice(e.serialize().as_ref());
    }
    eval.push(0x01); // voprf-ts VOPRF mode byte
    eval.extend_from_slice(result.proof.serialize().as_ref());

    let out = m.finalize(&eval)?;
    let want = server.evaluate(input).map_err(|e| format!("direct: {e:?}"))?;
    if out.len() == 2 + 64 && out[2..] == want[..] {
        Ok(format!("self-test OK ({}): ristretto255 round + DLEQ verified", std::env::consts::ARCH))
    } else {
        Err("self-test FAILED: output mismatch".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voprf::{BlindedElement, VoprfServer};

    fn inputs_blob(inputs: &[&[u8]]) -> Vec<u8> {
        let mut out = (inputs.len() as u16).to_be_bytes().to_vec();
        for i in inputs {
            out.extend_from_slice(&(i.len() as u16).to_be_bytes());
            out.extend_from_slice(i);
        }
        out
    }

    // Drives MeshOprf through a real VoprfServer that mimics voprf-ts's framing (the
    // cross-lib BYTE compatibility with voprf-ts is proven separately in the interop
    // harness). Batched oblivious round-trip, DLEQ-verified, output == server.evaluate.
    #[test]
    fn batch_round_trip() {
        let mut rng = OsRng;
        let server = VoprfServer::<Cs>::new(&mut rng).unwrap();
        let pk_bytes = <Cs as CipherSuite>::Group::serialize_elem(server.get_public_key());

        let mut m = MeshOprf::new(pk_bytes.as_ref()).unwrap();
        let inputs: [&[u8]; 2] = [
            b"zat:mesh:rbkt\x1ftoken\x1f42\x1f0",
            b"zat:mesh:rkey\x1fsr\x1f7",
        ];
        let req = m.blind(&inputs_blob(&inputs)).unwrap();

        // server side: parse request → blinded elements, batch-evaluate, re-frame.
        let count = u16::from_be_bytes([req[0], req[1]]) as usize;
        assert_eq!(count, 2);
        let mut blinded = Vec::new();
        let mut off = 2;
        for _ in 0..count {
            blinded.push(BlindedElement::<Cs>::deserialize(&req[off..off + ELEM_LEN]).unwrap());
            off += ELEM_LEN;
        }
        let result = server.batch_blind_evaluate(&mut rng, &blinded).unwrap();

        let mut eval = (count as u16).to_be_bytes().to_vec();
        for e in &result.messages {
            eval.extend_from_slice(e.serialize().as_ref());
        }
        eval.push(0x01); // voprf-ts VOPRF mode byte
        eval.extend_from_slice(result.proof.serialize().as_ref());

        let out_blob = m.finalize(&eval).unwrap();
        let oc = u16::from_be_bytes([out_blob[0], out_blob[1]]) as usize;
        assert_eq!(oc, 2);
        let mut off = 2;
        for input in inputs {
            let got = &out_blob[off..off + 64];
            let want = server.evaluate(input).unwrap();
            assert_eq!(got, &want[..], "batch output mismatch");
            off += 64;
        }
    }

    #[test]
    fn finalize_before_blind_errs() {
        let mut rng = OsRng;
        let server = VoprfServer::<Cs>::new(&mut rng).unwrap();
        let pk_bytes = <Cs as CipherSuite>::Group::serialize_elem(server.get_public_key());
        let m = MeshOprf::new(pk_bytes.as_ref()).unwrap();
        assert!(m.finalize(&[0, 0]).is_err());
    }

    // E2: the diagnostic is only compiled with the `self-test` feature, so its test runs only then
    // (`cargo test --features self-test`). The same client crypto is covered feature-independently by
    // the round-trip tests above (against a local `VoprfServer` stub, which is fine in test code).
    #[cfg(feature = "self-test")]
    #[test]
    fn self_test_passes() {
        let r = self_test();
        assert!(r.is_ok(), "{r:?}");
    }

    /// The FULL client threshold path with a local `t`-of-`n` committee: the client blinds a batch,
    /// drives the committee's two rounds through the coordinator (`thr_round1`/`thr_round2`), and its
    /// UNCHANGED `finalize` accepts the resulting evaluation (DLEQ-verified against K). Proves the
    /// client coordinator produces a proof byte-identical to a single-key issuer — no broker.
    #[test]
    fn threshold_round_trip_finalizes() {
        use zat_threshold_oprf::{deal_shares, Node};

        fn list_blob(blobs: &[Vec<u8>]) -> Vec<u8> {
            let mut out = (blobs.len() as u16).to_be_bytes().to_vec();
            for b in blobs {
                out.extend_from_slice(&(b.len() as u16).to_be_bytes());
                out.extend_from_slice(b);
            }
            out
        }

        let mut rng = OsRng;
        let (shares, pk) = deal_shares(2, 3, &mut rng);
        let pk_bytes = pk.compress().to_bytes();
        let mut nodes: Vec<Node> = shares
            .iter()
            .take(2)
            .map(|(id, s)| Node::from_share_bytes(*id, &s.to_bytes()).unwrap())
            .collect();

        // Client blinds a batch — the exact request the coordinator drives.
        let mut m = MeshOprf::new(&pk_bytes).unwrap();
        let inputs: [&[u8]; 2] = [b"zat:mesh:rbkt\x1ftok\x1f0", b"zat:mesh:rkey\x1fsr\x1f9"];
        let request = m.blind(&inputs_blob(&inputs)).unwrap();
        let blinded = parse_request_blinded(&request).unwrap();

        // Committee round 1: each node commits over the batch.
        let mut sessions = Vec::new();
        let mut r1 = Vec::new();
        for n in nodes.iter_mut() {
            let (s, msg) = n.commit(&blinded, &mut rng).unwrap();
            sessions.push(s);
            r1.push(msg.to_bytes());
        }
        let pending = thr_round1(&pk_bytes, &request, &list_blob(&r1)).unwrap();
        let c: [u8; 32] = pending[0..32].try_into().unwrap(); // the challenge to broadcast

        // Committee round 2: each node responds to c.
        let mut r2 = Vec::new();
        for (n, s) in nodes.iter_mut().zip(&sessions) {
            r2.push(n.respond_bytes(*s, &c).unwrap().to_bytes().to_vec());
        }
        let evaluation = thr_round2(&pk_bytes, &pending, &list_blob(&r2)).unwrap();

        // The client's UNCHANGED finalize accepts it + verifies the batched DLEQ against K.
        let out = m.finalize(&evaluation).unwrap();
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 2);
        assert_eq!(out.len(), 2 + 2 * 64, "two 64-byte VOPRF outputs");
    }
}
