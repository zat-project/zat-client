//! ZAT B2a — a verifiable **THRESHOLD** VOPRF over ristretto255-SHA512 whose evaluation +
//! DLEQ proof the **UNMODIFIED `voprf` 0.5 client accepts**, byte-identical to a single-key
//! server. This dissolves the broker's OPRF issuer key: `k` is Shamir-shared across a
//! committee and **no party ever reconstructs it**. See `docs/ISSUER_DISSOLUTION_B2_v0.1.md`
//! (design) + `docs/B2a_THRESHOLD_WIRING_v0.1.md` (the network-wiring plan).
//!
//! THE TRICK (breaks the "voprf 0.5 is a black box" wall — it exposes no threshold API and its
//! `Proof` is opaque+mandatory): use the crate's PUBLIC `serialize`/`deserialize` as the seam
//! and do the raw math on `curve25519-dalek`. Pull each blinded point `B_j` out of the client's
//! `BlindedElement`, compute the per-element threshold eval `E_j = Σ λ_i·(k_i·B_j)`, produce the
//! RFC-9497 BATCHED DLEQ threshold-style (threshold Chaum-Pedersen over the two bases `G` and the
//! batch composite `M = Σ_j d_j·B_j`: shared nonce `r = Σ λ_i·r_i`, `s = Σ λ_i·s_i`), serialize the
//! `E_j` + `(c,s)` back to bytes, and feed them to the stock `VoprfClient::batch_finalize`. The
//! eval algebra is free (group linearity); the only real crypto is the threshold DLEQ, which must
//! reproduce RFC 9497 §4.3 byte-for-byte — the test locks that against the real crate.
//!
//! This spike simulates all committee nodes in one process (no network) to prove the crypto: each
//! `Node` holds ONE Shamir share and runs a 2-message nonce-commit/respond round over a BATCH of
//! blinded elements (one batched DLEQ, matching the client's batched read), and the shares come
//! from a **real FROST DKG** (RFC 9591, `frost_ristretto255`) so `k` is never assembled at any
//! party — not even by a trusted dealer. `Round1`/`Round2` carry byte wire-formats (opaque blobs
//! the transport ships; the crypto is FFI/HTTP-ready). The remaining B2a work is wiring these
//! nodes onto the network (behind the `Rendezvous` seam), not the crypto.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::CompressedRistretto,
    ristretto::RistrettoPoint, scalar::Scalar, traits::Identity,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

/// RFC 9497 CreateContextString(modeVOPRF=0x01, "ristretto255-SHA512").
const CONTEXT: &[u8] = b"OPRFV1-\x01-ristretto255-SHA512";

fn i2osp2(n: usize) -> [u8; 2] {
    (n as u16).to_be_bytes()
}

/// RFC 9380 `expand_message_xmd` with SHA-512. Only the one-block case (`len <= 64`) is needed —
/// HashToScalar asks for exactly 64 bytes.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 64 && dst.len() < 256);
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);
    // b_0 = H(Z_pad(s_in_bytes=128) || msg || I2OSP(len,2) || I2OSP(0,1) || DST_prime)
    let mut h = Sha512::new();
    h.update([0u8; 128]);
    h.update(msg);
    h.update(i2osp2(len));
    h.update([0u8]);
    h.update(&dst_prime);
    let b0 = h.finalize();
    // b_1 = H(b_0 || I2OSP(1,1) || DST_prime)
    let mut h = Sha512::new();
    h.update(b0);
    h.update([1u8]);
    h.update(&dst_prime);
    h.finalize()[..len].to_vec()
}

/// RFC 9497 §4.1 HashToScalar for ristretto255-SHA512: expand 64 bytes with DST
/// `"HashToScalar-" || contextString`, interpret little-endian, reduce mod the group order.
fn hash_to_scalar(msg: &[u8]) -> Scalar {
    let mut dst = b"HashToScalar-".to_vec();
    dst.extend_from_slice(CONTEXT);
    let ub = expand_message_xmd(msg, &dst, 64);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&ub);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn ser_elem(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// A field element serialized RFC-9497-style, then a two-byte length prefix, appended to `t`.
fn push_lp(t: &mut Vec<u8>, bytes: &[u8]) {
    t.extend_from_slice(&i2osp2(bytes.len()));
    t.extend_from_slice(bytes);
}

fn decompress(bytes: &[u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or_else(|| "non-canonical ristretto point".into())
}

fn scalar_from(bytes: &[u8; 32]) -> Result<Scalar, String> {
    Option::from(Scalar::from_canonical_bytes(*bytes)).ok_or_else(|| "non-canonical scalar".into())
}

/// RFC 9497 ComputeCompositesFast for a batch of `m`: for each `j`,
/// `d_j = HashToScalar(seed ‖ I2OSP(j,2) ‖ LP(C_j) ‖ LP(D_j) ‖ "Composite")`, then
/// `M = Σ_j d_j·C_j` and `Z = Σ_j d_j·D_j` (= `k·M`, since `D_j = k·C_j`). Returns `(M, Z, [d_j])`
/// — the coordinator also needs the `d_j` to weight the per-element nonce commitments into `t3`.
fn compute_composites(
    pk_ser: &[u8; 32],
    blinded: &[RistrettoPoint],
    evals: &[RistrettoPoint],
) -> (RistrettoPoint, RistrettoPoint, Vec<Scalar>) {
    let mut seed_dst = b"Seed-".to_vec();
    seed_dst.extend_from_slice(CONTEXT);
    let seed = {
        let mut t = Vec::new();
        push_lp(&mut t, pk_ser);
        push_lp(&mut t, &seed_dst);
        Sha512::digest(&t)
    };
    let mut m = RistrettoPoint::identity();
    let mut z = RistrettoPoint::identity();
    let mut ds = Vec::with_capacity(blinded.len());
    for (i, (c_i, d_i)) in blinded.iter().zip(evals).enumerate() {
        let d = {
            let mut t = Vec::new();
            push_lp(&mut t, &seed);
            t.extend_from_slice(&i2osp2(i)); // I2OSP(i, 2)
            push_lp(&mut t, &ser_elem(c_i)); // C[i] = blinded
            push_lp(&mut t, &ser_elem(d_i)); // D[i] = eval
            t.extend_from_slice(b"Composite");
            hash_to_scalar(&t)
        };
        m += d * c_i;
        z += d * d_i;
        ds.push(d);
    }
    (m, z, ds)
}

/// RFC 9497 challenge `c = HashToScalar( LP(pk) || LP(M) || LP(Z) || LP(t2) || LP(t3) || "Challenge" )`.
fn challenge_scalar(
    pk_ser: &[u8; 32],
    m: &RistrettoPoint,
    z: &RistrettoPoint,
    t2: &RistrettoPoint,
    t3: &RistrettoPoint,
) -> Scalar {
    let (a0, a1, a2, a3) = (ser_elem(m), ser_elem(z), ser_elem(t2), ser_elem(t3));
    let mut t = Vec::new();
    for x in [&pk_ser[..], &a0[..], &a1[..], &a2[..], &a3[..]] {
        push_lp(&mut t, x);
    }
    t.extend_from_slice(b"Challenge");
    hash_to_scalar(&t)
}

/// Shamir-share `k` over the scalar field: returns `(id, f(id))` for `id = 1..=n`, degree `t-1`.
fn shamir_share<R: RngCore + CryptoRng>(
    k: &Scalar,
    t: usize,
    n: usize,
    rng: &mut R,
) -> Vec<(u64, Scalar)> {
    let mut coeffs = vec![*k];
    for _ in 1..t {
        coeffs.push(Scalar::random(rng));
    }
    (1..=n as u64)
        .map(|id| {
            let x = Scalar::from(id);
            let mut y = Scalar::ZERO; // Horner
            for c in coeffs.iter().rev() {
                y = y * x + c;
            }
            (id, y)
        })
        .collect()
}

/// Lagrange coefficient for participant `id` within subset `ids`, evaluated at 0:
/// `λ = Π_{j≠i} x_j / (x_j - x_i)`.
fn lagrange_at_zero(ids: &[u64], id: u64) -> Scalar {
    let xi = Scalar::from(id);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in ids {
        if j == id {
            continue;
        }
        let xj = Scalar::from(j);
        num *= xj;
        den *= xj - xi;
    }
    num * den.invert()
}

// ---- Distributed 2-message protocol over a BATCH of blinded elements --------------------------
//
// Each node holds ONE share; no in-process combining. The client blinds `m` tags at once and
// expects ONE batched RFC-9497 DLEQ, so the protocol runs over the whole batch with a SINGLE fresh
// nonce per node per session.
//
// Round 1 (per node, one fresh nonce r_i): partial evals k_i·B_j for every j, plus the nonce
//   commitments r_i·G and, per j, r_i·B_j.
// Coordinator: E_j = Σ λ_i·(k_i·B_j); composite M = Σ_j d_j·B_j, Z, d_j; t2 = Σ λ_i·(r_i·G) = r·G;
//   t3 = Σ_j d_j·(Σ λ_i·(r_i·B_j)) = Σ_j d_j·(r·B_j) = r·M (so no node ever sees M); challenge c.
// Round 2 (per node): s_i = r_i − c·k_i, CONSUMING the nonce. Coordinator: s = Σ λ_i·s_i; proof (c,s).
//
// Security: fresh per-eval nonces used immediately + single-use = the classic secure interactive
// threshold Schnorr/Chaum-Pedersen (no nonce reuse ⇒ no Drijvers/ROS window). FROST's binding
// factor is the extra step that makes it safe to PRE-COMPUTE nonces (round-latency optimization) —
// tracked as a concurrency-hardening refinement, not needed for correctness here.
//
// `session` is a NODE-LOCAL nonce handle (returned from `commit`, echoed by the client in `respond`)
// and is deliberately NOT part of the crypto wire blob — the coordinator only ever needs `id` +
// points. So `Round1`/`Round2` serialize exactly what the coordinator combines.

/// A committee node's round-1 message — the crypto the coordinator combines. Wire layout:
/// `id(8, BE) ‖ m(2, BE) ‖ a_g(32) ‖ [ e_j(32) ‖ a_b_j(32) ] × m`.
pub struct Round1 {
    pub id: u64,
    pub a_g: [u8; 32],     // r_i·G
    pub e: Vec<[u8; 32]>,  // k_i·B_j for each j
    pub a_b: Vec<[u8; 32]>, // r_i·B_j for each j
}

impl Round1 {
    pub fn to_bytes(&self) -> Vec<u8> {
        let m = self.e.len();
        let mut out = Vec::with_capacity(10 + 32 + 64 * m);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&(m as u16).to_be_bytes());
        out.extend_from_slice(&self.a_g);
        for j in 0..m {
            out.extend_from_slice(&self.e[j]);
            out.extend_from_slice(&self.a_b[j]);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 42 {
            return Err("round1 too short".into());
        }
        let id = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let m = u16::from_be_bytes(bytes[8..10].try_into().unwrap()) as usize;
        if bytes.len() != 10 + 32 + 64 * m {
            return Err("round1 length mismatch".into());
        }
        let mut a_g = [0u8; 32];
        a_g.copy_from_slice(&bytes[10..42]);
        let mut e = Vec::with_capacity(m);
        let mut a_b = Vec::with_capacity(m);
        let mut off = 42;
        for _ in 0..m {
            let mut ej = [0u8; 32];
            ej.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            let mut aj = [0u8; 32];
            aj.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
            e.push(ej);
            a_b.push(aj);
        }
        Ok(Round1 { id, a_g, e, a_b })
    }
}

/// A committee node's round-2 message. Wire layout: `id(8, BE) ‖ s_i(32)`.
pub struct Round2 {
    pub id: u64,
    pub s_i: [u8; 32],
}

impl Round2 {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..8].copy_from_slice(&self.id.to_be_bytes());
        out[8..40].copy_from_slice(&self.s_i);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 40 {
            return Err("round2 must be 40 bytes".into());
        }
        let id = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let mut s_i = [0u8; 32];
        s_i.copy_from_slice(&bytes[8..40]);
        Ok(Round2 { id, s_i })
    }
}

/// Upper bound on a node's concurrently-pending nonces. A client that commits but never responds
/// would otherwise leak a nonce entry per abandoned session; at the cap the oldest is evicted
/// (its session simply fails to respond later — a benign, bounded outcome vs. unbounded memory).
const MAX_PENDING_NONCES: usize = 2048;

/// One committee node — holds a SINGLE Shamir share of `k`, never learns `k` or the composite `M`,
/// and enforces single-use nonces.
pub struct Node {
    pub id: u64,
    share: Scalar,
    nonces: HashMap<u64, Scalar>,
    next: u64,
}

impl Node {
    pub fn new(id: u64, share: Scalar) -> Self {
        Self {
            id,
            share,
            nonces: HashMap::new(),
            next: 1,
        }
    }

    /// Build a node from a committee share serialized as 32-byte little-endian (RFC 9497) — the
    /// exact bytes the broker's `MeshThreshold.shareFor` delivers. The byte seam keeps
    /// `curve25519-dalek` out of the transport/host code.
    pub fn from_share_bytes(id: u64, share: &[u8; 32]) -> Result<Self, String> {
        Ok(Node::new(id, scalar_from(share)?))
    }

    /// Round 1 over a batch: partial evals `k_i·B_j` + a fresh single-use nonce committed over `G`
    /// and each `B_j`. Returns the node-local `session` handle (echoed back in `respond`) and the
    /// crypto message. Errors if any blinded element is non-canonical.
    pub fn commit<R: RngCore + CryptoRng>(
        &mut self,
        blinded: &[[u8; 32]],
        rng: &mut R,
    ) -> Result<(u64, Round1), String> {
        let bs: Vec<RistrettoPoint> = blinded
            .iter()
            .map(decompress)
            .collect::<Result<_, _>>()?;
        let r = Scalar::random(rng);
        let session = self.next;
        self.next += 1;
        // Bound memory: at the cap, drop the oldest (lowest-session) pending nonce.
        if self.nonces.len() >= MAX_PENDING_NONCES {
            if let Some(&oldest) = self.nonces.keys().min() {
                self.nonces.remove(&oldest);
            }
        }
        self.nonces.insert(session, r);
        let e = bs.iter().map(|b| ser_elem(&(self.share * b))).collect();
        let a_b = bs.iter().map(|b| ser_elem(&(r * b))).collect();
        Ok((
            session,
            Round1 {
                id: self.id,
                a_g: ser_elem(&(r * G)),
                e,
                a_b,
            },
        ))
    }

    /// Round 2: `s_i = r_i − c·k_i`, CONSUMING the nonce. A second response for the same session
    /// is refused — two challenges on one nonce would leak `k_i = (s − s')/(c' − c)`.
    pub fn respond(&mut self, session: u64, c: &Scalar) -> Result<Round2, String> {
        let r = self
            .nonces
            .remove(&session)
            .ok_or("unknown or already-used session (single-use nonce)")?;
        Ok(Round2 {
            id: self.id,
            s_i: (r - c * self.share).to_bytes(),
        })
    }

    /// Round 2 with the challenge as 32-byte canonical little-endian bytes (the transport form),
    /// so the HTTP/FFI host never touches `curve25519-dalek`.
    pub fn respond_bytes(&mut self, session: u64, c: &[u8; 32]) -> Result<Round2, String> {
        self.respond(session, &scalar_from(c)?)
    }
}

/// State the coordinator carries between the two rounds.
pub struct Pending {
    /// The challenge to broadcast to the nodes for round 2.
    pub c: Scalar,
    e: Vec<RistrettoPoint>,
}

impl Pending {
    /// Serialize for the FFI/transport boundary (the client coordinator runs across a JNI hop
    /// between the two rounds): `c(32) ‖ count(2, BE) ‖ E_j(32) × count`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34 + 32 * self.e.len());
        out.extend_from_slice(&self.c.to_bytes());
        out.extend_from_slice(&(self.e.len() as u16).to_be_bytes());
        for e in &self.e {
            out.extend_from_slice(&ser_elem(e));
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Pending, String> {
        if b.len() < 34 {
            return Err("pending too short".into());
        }
        let mut cb = [0u8; 32];
        cb.copy_from_slice(&b[0..32]);
        let c = scalar_from(&cb)?;
        let count = u16::from_be_bytes([b[32], b[33]]) as usize;
        if b.len() != 34 + 32 * count {
            return Err("pending length mismatch".into());
        }
        let mut e = Vec::with_capacity(count);
        let mut off = 34;
        for _ in 0..count {
            let mut eb = [0u8; 32];
            eb.copy_from_slice(&b[off..off + 32]);
            e.push(decompress(&eb)?);
            off += 32;
        }
        Ok(Pending { c, e })
    }
}

/// The coordinator (the requesting client, or any node): PUBLIC Lagrange combination only. A
/// malicious coordinator can only cause a rejected proof, never forge or extract a share.
pub struct Coordinator {
    pub pk: RistrettoPoint,
}

impl Coordinator {
    pub fn new(pk: RistrettoPoint) -> Self {
        Self { pk }
    }

    /// Build from the group public key `K` as 32-byte compressed ristretto (the transport form —
    /// the client reads it from the broker's `/mesh/params`), so the host never touches
    /// `curve25519-dalek`.
    pub fn from_pk_bytes(pk: &[u8; 32]) -> Result<Self, String> {
        Ok(Self::new(decompress(pk)?))
    }

    /// Combine round-1 messages over the batch → `E_j`, the composite, `t2,t3`, and the challenge.
    pub fn round1(&self, blinded: &[[u8; 32]], msgs: &[Round1]) -> Result<Pending, String> {
        let bs: Vec<RistrettoPoint> = blinded
            .iter()
            .map(decompress)
            .collect::<Result<_, _>>()?;
        let m = bs.len();
        if msgs.is_empty() {
            return Err("no round1 messages".into());
        }
        let ids: Vec<u64> = msgs.iter().map(|x| x.id).collect();
        let mut e = vec![RistrettoPoint::identity(); m];
        let mut a_b = vec![RistrettoPoint::identity(); m];
        let mut a_g = RistrettoPoint::identity();
        for msg in msgs {
            if msg.e.len() != m || msg.a_b.len() != m {
                return Err("round1 batch size mismatch".into());
            }
            let lam = lagrange_at_zero(&ids, msg.id);
            a_g += lam * decompress(&msg.a_g)?;
            for j in 0..m {
                e[j] += lam * decompress(&msg.e[j])?;
                a_b[j] += lam * decompress(&msg.a_b[j])?;
            }
        }
        let pk_ser = ser_elem(&self.pk);
        let (mm, z, ds) = compute_composites(&pk_ser, &bs, &e);
        let t2 = a_g; // r·G
        // t3 = Σ_j d_j·(r·B_j) = r·(Σ_j d_j·B_j) = r·M
        let mut t3 = RistrettoPoint::identity();
        for j in 0..m {
            t3 += ds[j] * a_b[j];
        }
        let c = challenge_scalar(&pk_ser, &mm, &z, &t2, &t3);
        Ok(Pending { c, e })
    }

    /// Combine round-2 shares → `([E_j bytes], proof_bytes)` for the stock `batch_finalize`.
    pub fn round2(
        &self,
        pending: &Pending,
        msgs: &[Round2],
    ) -> Result<(Vec<[u8; 32]>, [u8; 64]), String> {
        let ids: Vec<u64> = msgs.iter().map(|x| x.id).collect();
        let mut s = Scalar::ZERO;
        for msg in msgs {
            s += lagrange_at_zero(&ids, msg.id) * scalar_from(&msg.s_i)?;
        }
        let mut proof = [0u8; 64];
        proof[..32].copy_from_slice(&pending.c.to_bytes());
        proof[32..].copy_from_slice(&s.to_bytes());
        let es = pending.e.iter().map(ser_elem).collect();
        Ok((es, proof))
    }
}

/// DKG stand-in for the distributed tests: deal `(t, n)` shares of a fresh `k` + return `k·G`.
/// (Real B2a replaces this with a FROST-style DKG so `k` is never assembled anywhere.)
pub fn deal_shares<R: RngCore + CryptoRng>(
    t: usize,
    n: usize,
    rng: &mut R,
) -> (Vec<(u64, Scalar)>, RistrettoPoint) {
    let k = Scalar::random(rng);
    (shamir_share(&k, t, n, rng), k * G)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voprf::{CipherSuite, EvaluationElement, Group, Proof, VoprfClient};

    struct Cs;
    impl CipherSuite for Cs {
        const ID: &'static str = "ristretto255-SHA512";
        type Group = voprf::Ristretto255;
        type Hash = sha2::Sha512;
    }

    /// Test helper: run the full distributed 2-round protocol over `shares` for a BATCH of `inputs`
    /// and return the stock client's finalized outputs — panics if the client rejects. Every
    /// Round1/Round2 is round-tripped through its byte wire-format before the coordinator sees it,
    /// so this also exercises the wire in every acceptance test. Shared by the trusted-dealer and
    /// the real-DKG tests so both exercise the exact same acceptance path.
    fn threshold_finalize(
        shares: Vec<(u64, Scalar)>,
        pk: RistrettoPoint,
        inputs: &[&[u8]],
    ) -> Vec<Vec<u8>> {
        let mut rng = rand::rngs::OsRng;
        let mut nodes: Vec<Node> = shares.into_iter().map(|(id, s)| Node::new(id, s)).collect();
        let coord = Coordinator::new(pk);

        // Blind each input with the stock client; keep the states for finalize.
        let mut blinded: Vec<[u8; 32]> = Vec::new();
        let mut states = Vec::new();
        for inp in inputs {
            let b = VoprfClient::<Cs>::blind(inp, &mut rng).unwrap();
            let mut a = [0u8; 32];
            a.copy_from_slice(&b.message.serialize());
            blinded.push(a);
            states.push(b.state);
        }

        // Round 1: every node commits over the batch; the coordinator derives the challenge.
        let mut sessions = Vec::new();
        let mut r1 = Vec::new();
        for n in nodes.iter_mut() {
            let (session, msg) = n.commit(&blinded, &mut rng).unwrap();
            sessions.push(session);
            r1.push(Round1::from_bytes(&msg.to_bytes()).unwrap()); // through the wire
        }
        let pending = coord.round1(&blinded, &r1).unwrap();
        // Round 2: broadcast c; each node responds for ITS session.
        let r2: Vec<Round2> = nodes
            .iter_mut()
            .zip(&sessions)
            .map(|(n, s)| {
                let msg = n.respond(*s, &pending.c).unwrap();
                Round2::from_bytes(&msg.to_bytes()).unwrap() // through the wire
            })
            .collect();
        let (e_bytes, proof_bytes) = coord.round2(&pending, &r2).unwrap();

        let evals: Vec<_> = e_bytes
            .iter()
            .map(|e| EvaluationElement::<Cs>::deserialize(e).unwrap())
            .collect();
        let proof = Proof::<Cs>::deserialize(&proof_bytes).unwrap();
        let pkc = <Cs as CipherSuite>::Group::deserialize_elem(&pk.compress().to_bytes()).unwrap();
        let input_vecs: Vec<Vec<u8>> = inputs.iter().map(|i| i.to_vec()).collect();
        let outputs = VoprfClient::batch_finalize(&input_vecs, &states, &evals, &proof, pkc)
            .expect("the stock voprf client must ACCEPT the batched threshold proof");
        outputs.map(|o| o.unwrap().to_vec()).collect()
    }

    /// THE de-risk: a t-of-n committee (no party holds k) produces a BATCH of (E_j, one proof) that
    /// the UNMODIFIED voprf client accepts + finalizes — i.e. our batched threshold DLEQ is
    /// byte-exact RFC 9497, so every output is identical to a single-key issuer.
    #[test]
    fn distributed_batch_accepted_by_stock_client() {
        let (shares, pk) = deal_shares(3, 5, &mut rand::rngs::OsRng);
        let inputs: [&[u8]; 3] = [
            b"zat:mesh:rbkt\x1ftoken\x1f42\x1f0",
            b"zat:mesh:rbkt\x1ftoken\x1f42\x1f1",
            b"zat:mesh:rkey\x1fsr\x1f1893",
        ];
        let outs = threshold_finalize(shares.into_iter().take(3).collect(), pk, &inputs);
        assert_eq!(outs.len(), 3);
        for o in &outs {
            assert_eq!(o.len(), 64, "ristretto255-SHA512 VOPRF output is 64 bytes");
        }
    }

    /// The threshold eval element is BYTE-IDENTICAL to a single-key `k·B` (group linearity), so the
    /// finalized output above is identical to a single-key issuer's — this locks the Shamir/Lagrange
    /// mechanics that the acceptance test relies on.
    #[test]
    fn threshold_eval_equals_single_key() {
        let mut rng = rand::rngs::OsRng;
        let k = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng) * G; // any point stands in for a blinded element
        let e_single = k * b;

        let shares: Vec<(u64, Scalar)> =
            shamir_share(&k, 3, 5, &mut rng).into_iter().take(3).collect();
        let ids: Vec<u64> = shares.iter().map(|(id, _)| *id).collect();
        let e_thr: RistrettoPoint = shares
            .iter()
            .map(|(id, ki)| lagrange_at_zero(&ids, *id) * (ki * b))
            .sum();

        assert_eq!(
            e_single.compress().to_bytes(),
            e_thr.compress().to_bytes(),
            "Σ λ_i·(k_i·B) must equal k·B byte-for-byte"
        );
    }

    /// The single-use nonce guard: a second response for a consumed session is refused — two
    /// challenges on one nonce would leak `k_i = (s − s')/(c' − c)`.
    #[test]
    fn nonce_is_single_use() {
        let mut rng = rand::rngs::OsRng;
        let (shares, _pk) = deal_shares(2, 3, &mut rng);
        let mut node = Node::new(shares[0].0, shares[0].1);
        let blinded = [ser_elem(&(Scalar::random(&mut rng) * G))];
        let (session, _r1) = node.commit(&blinded, &mut rng).unwrap();
        let c = Scalar::random(&mut rng);
        assert!(node.respond(session, &c).is_ok());
        assert!(
            node.respond(session, &c).is_err(),
            "a consumed session's nonce must never be reusable"
        );
    }

    /// The byte-oriented node seam (`from_share_bytes` + `respond_bytes`) — exactly what the
    /// volunteer's HTTP server uses (share + challenge arrive as bytes) — yields an accepted proof.
    #[test]
    fn byte_api_node_accepted_by_stock_client() {
        let mut rng = rand::rngs::OsRng;
        let (shares, pk) = deal_shares(2, 3, &mut rng);
        let mut nodes: Vec<Node> = shares
            .iter()
            .take(2)
            .map(|(id, s)| Node::from_share_bytes(*id, &s.to_bytes()).unwrap())
            .collect();
        let coord = Coordinator::new(pk);

        let input: &[u8] = b"zat:mesh:bytes";
        let blind = VoprfClient::<Cs>::blind(input, &mut rng).unwrap();
        let mut b = [0u8; 32];
        b.copy_from_slice(&blind.message.serialize());
        let batch = [b];

        let mut sessions = Vec::new();
        let mut r1 = Vec::new();
        for n in nodes.iter_mut() {
            let (s, m) = n.commit(&batch, &mut rng).unwrap();
            sessions.push(s);
            r1.push(m);
        }
        let pending = coord.round1(&batch, &r1).unwrap();
        let c_bytes = pending.c.to_bytes(); // the transport form of the challenge
        let r2: Vec<Round2> = nodes
            .iter_mut()
            .zip(&sessions)
            .map(|(n, s)| n.respond_bytes(*s, &c_bytes).unwrap())
            .collect();
        let (e_bytes, proof_bytes) = coord.round2(&pending, &r2).unwrap();

        let eval = EvaluationElement::<Cs>::deserialize(&e_bytes[0]).unwrap();
        let proof = Proof::<Cs>::deserialize(&proof_bytes).unwrap();
        let pkc = <Cs as CipherSuite>::Group::deserialize_elem(&pk.compress().to_bytes()).unwrap();
        let inputs = [input.to_vec()];
        let states = [blind.state];
        let evals = [eval];
        let mut out = VoprfClient::batch_finalize(&inputs, &states, &evals, &proof, pkc).unwrap();
        assert_eq!(out.next().unwrap().unwrap().len(), 64);
    }

    /// Pending nonces are bounded: past the cap the oldest session is evicted (so an abandoned
    /// commit can't grow memory without bound), and that evicted session can no longer respond.
    #[test]
    fn pending_nonces_are_bounded() {
        let mut rng = rand::rngs::OsRng;
        let (shares, _pk) = deal_shares(2, 3, &mut rng);
        let mut node = Node::new(shares[0].0, shares[0].1);
        // An EMPTY batch keeps each commit to a single r·G (only the nonce bookkeeping is under
        // test), so filling past the cap stays fast even in a debug build.
        let empty: [[u8; 32]; 0] = [];
        let (first_session, _) = node.commit(&empty, &mut rng).unwrap();
        for _ in 0..MAX_PENDING_NONCES {
            node.commit(&empty, &mut rng).unwrap();
        }
        assert!(
            node.respond(first_session, &Scalar::random(&mut rng)).is_err(),
            "the oldest pending nonce must be evicted at the cap"
        );
    }

    /// The coordinator byte seam — build from the pk BYTES (the `/mesh/params` form) and round-trip
    /// the `Pending` state through its FFI bytes (the client coordinator crosses a JNI hop between
    /// the two rounds) — still yields a proof the stock client accepts.
    #[test]
    fn coordinator_byte_seam_accepted_by_stock_client() {
        let mut rng = rand::rngs::OsRng;
        let (shares, pk) = deal_shares(2, 3, &mut rng);
        let mut nodes: Vec<Node> = shares
            .iter()
            .take(2)
            .map(|(id, s)| Node::from_share_bytes(*id, &s.to_bytes()).unwrap())
            .collect();
        let coord = Coordinator::from_pk_bytes(&pk.compress().to_bytes()).unwrap();

        let input: &[u8] = b"zat:mesh:coord-bytes";
        let blind = VoprfClient::<Cs>::blind(input, &mut rng).unwrap();
        let mut b = [0u8; 32];
        b.copy_from_slice(&blind.message.serialize());
        let batch = [b];

        let mut sessions = Vec::new();
        let mut r1 = Vec::new();
        for n in nodes.iter_mut() {
            let (s, m) = n.commit(&batch, &mut rng).unwrap();
            sessions.push(s);
            r1.push(m);
        }
        let pending = coord.round1(&batch, &r1).unwrap();
        // Cross the FFI boundary: serialize + reparse the pending state between the rounds.
        let pending = Pending::from_bytes(&pending.to_bytes()).unwrap();
        let c_bytes = pending.c.to_bytes();
        let r2: Vec<Round2> = nodes
            .iter_mut()
            .zip(&sessions)
            .map(|(n, s)| n.respond_bytes(*s, &c_bytes).unwrap())
            .collect();
        let (e_bytes, proof_bytes) = coord.round2(&pending, &r2).unwrap();

        let eval = EvaluationElement::<Cs>::deserialize(&e_bytes[0]).unwrap();
        let proof = Proof::<Cs>::deserialize(&proof_bytes).unwrap();
        let pkc = <Cs as CipherSuite>::Group::deserialize_elem(&pk.compress().to_bytes()).unwrap();
        let inputs = [input.to_vec()];
        let states = [blind.state];
        let evals = [eval];
        let mut out = VoprfClient::batch_finalize(&inputs, &states, &evals, &proof, pkc).unwrap();
        assert_eq!(out.next().unwrap().unwrap().len(), 64);
    }

    /// The Round1/Round2 byte wire-format round-trips exactly (the coordinator reconstructs the same
    /// crypto from `from_bytes(to_bytes(..))`), and the sizes are as documented.
    #[test]
    fn wire_format_roundtrips() {
        let mut rng = rand::rngs::OsRng;
        let (shares, _pk) = deal_shares(2, 3, &mut rng);
        let mut node = Node::new(shares[0].0, shares[0].1);
        let blinded = [
            ser_elem(&(Scalar::random(&mut rng) * G)),
            ser_elem(&(Scalar::random(&mut rng) * G)),
        ];
        let (session, r1) = node.commit(&blinded, &mut rng).unwrap();
        let r1_bytes = r1.to_bytes();
        assert_eq!(r1_bytes.len(), 10 + 32 + 64 * 2);
        let r1b = Round1::from_bytes(&r1_bytes).unwrap();
        assert_eq!((r1b.id, r1b.a_g, r1b.e, r1b.a_b), (r1.id, r1.a_g, r1.e, r1.a_b));

        let r2 = node.respond(session, &Scalar::random(&mut rng)).unwrap();
        let r2_bytes = r2.to_bytes();
        assert_eq!(r2_bytes.len(), 40);
        let r2b = Round2::from_bytes(&r2_bytes).unwrap();
        assert_eq!((r2b.id, r2b.s_i), (r2.id, r2.s_i));

        // Corrupt lengths are rejected.
        assert!(Round1::from_bytes(&r1_bytes[..r1_bytes.len() - 1]).is_err());
        assert!(Round2::from_bytes(&r2_bytes[..39]).is_err());
    }

    /// THE DISSOLUTION MILESTONE: a **real FROST DKG** (RFC 9591 — no trusted dealer, `k` is never
    /// assembled at any party) produces shares that drive the distributed BATCH threshold eval to a
    /// proof the UNMODIFIED voprf client accepts. Proves the whole "no node holds k" issuer.
    #[test]
    fn frost_dkg_output_accepted_by_stock_client() {
        let (shares, pk) = frost_dkg(3, 5, &mut rand::rngs::OsRng);
        let inputs: [&[u8]; 2] = [b"zat:mesh:frost\x1f0", b"zat:mesh:frost\x1f1"];
        let outs = threshold_finalize(shares.into_iter().take(3).collect(), pk, &inputs);
        assert_eq!(outs.len(), 2);
        assert!(outs.iter().all(|o| o.len() == 64), "FROST-DKG batch must finalize");
    }

    /// Run the RFC-9591 FROST DKG for all `n` participants in-process and return each participant's
    /// `(identifier, signing-share scalar)` plus the group public key `k·G` — bridged into
    /// curve25519-dalek through the crate's canonical byte serialization (same ristretto255 group,
    /// so this is version-independent, exactly like the voprf byte seam).
    fn frost_dkg<R: RngCore + CryptoRng>(
        t: u16,
        n: u16,
        rng: &mut R,
    ) -> (Vec<(u64, Scalar)>, RistrettoPoint) {
        use frost_ristretto255::{self as frost, keys::dkg};
        use std::collections::BTreeMap;

        let ids: Vec<frost::Identifier> = (1..=n)
            .map(|i| frost::Identifier::try_from(i).unwrap())
            .collect();

        // Round 1: each participant broadcasts a commitment package.
        let mut r1_secrets = BTreeMap::new();
        let mut r1_pkgs = BTreeMap::new();
        for id in &ids {
            let (sec, pkg) = dkg::part1(*id, n, t, &mut *rng).unwrap();
            r1_secrets.insert(*id, sec);
            r1_pkgs.insert(*id, pkg);
        }

        // Round 2: each participant produces a per-recipient package from the others' round-1 set.
        let mut r2_secrets = BTreeMap::new();
        let mut r2_sent: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, dkg::round2::Package>> =
            BTreeMap::new();
        for id in &ids {
            let recv_r1: BTreeMap<_, _> = r1_pkgs
                .iter()
                .filter(|&(k, _)| k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let (sec, pkgs) = dkg::part2(r1_secrets.remove(id).unwrap(), &recv_r1).unwrap();
            r2_secrets.insert(*id, sec);
            r2_sent.insert(*id, pkgs);
        }

        // Round 3: each participant assembles its key package + the shared group public key.
        let mut shares = Vec::new();
        let mut group_key = None;
        for (idx, id) in ids.iter().enumerate() {
            let recv_r1: BTreeMap<_, _> = r1_pkgs
                .iter()
                .filter(|&(k, _)| k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let recv_r2: BTreeMap<_, _> = r2_sent
                .iter()
                .filter(|&(k, _)| k != id)
                .map(|(k, sent)| (*k, sent[id].clone()))
                .collect();
            let (key_pkg, pub_pkg) = dkg::part3(&r2_secrets[id], &recv_r1, &recv_r2).unwrap();

            // FROST identifier n is the scalar n (RFC 9591) — assert it so our u64 Lagrange
            // x-coordinates line up with the DKG's Shamir x-coordinates.
            let mut ib = [0u8; 32];
            ib.copy_from_slice(&id.serialize());
            let want = idx as u64 + 1;
            assert_eq!(
                scalar_from(&ib).unwrap(),
                Scalar::from(want),
                "FROST identifier must equal its scalar for the u64 Lagrange bridge"
            );

            let mut sb = [0u8; 32];
            sb.copy_from_slice(&key_pkg.signing_share().serialize());
            shares.push((want, scalar_from(&sb).unwrap()));

            if group_key.is_none() {
                let mut vb = [0u8; 32];
                vb.copy_from_slice(&pub_pkg.verifying_key().serialize().unwrap());
                group_key = Some(decompress(&vb).unwrap());
            }
        }
        (shares, group_key.unwrap())
    }
}
