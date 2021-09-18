#![no_std]
#[macro_use]
extern crate slice_as_array;
#[macro_use]
extern crate alloc;

pub mod gm;
pub mod tests;
pub mod utils;

use crate::gm::CombinedPubkey;
use alloc::vec::Vec;
use bbs::sign;
use bbs::USK;
use bls12_381::Gt;
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use gm::OpenShare;
use group::{Curve, GroupEncoding};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use utils::gen_rand_scalar;

#[derive(Serialize, Deserialize)]
pub struct PairingCurve {
    pub g1: G1Projective,
    pub g2: G2Projective,
}

impl PairingCurve {
    pub fn new() -> Self {
        PairingCurve {
            g1: G1Projective::generator(),
            g2: G2Projective::generator(),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct PartialGSK {
    pub gamma: Scalar,
    pub xi: Scalar,
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct PartialGPK {
    pub h: G1Projective,
    pub omega: G2Projective,
}

pub type PartialUSK = USK;

#[derive(Serialize, Deserialize, Clone)]
pub struct CombinedUSK {
    pub partials: Vec<PartialUSK>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CombinedGPK {
    pub h: G1Projective,
    pub u: G1Projective,
    pub v: G1Projective,
    pub w: G1Projective,
    pub partical_gpks: Vec<PartialGPK>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Signature {
    pub t1: G1Projective,
    pub t2: G1Projective,
    pub t3: G1Projective,
    pub t4: Vec<G1Projective>,
    pub hash: Scalar,
    pub sa: Scalar,
    pub sb: Scalar,
    pub sc: Scalar,
    pub sx: Vec<Scalar>,
    pub s_delta1: Scalar,
    pub s_delta2: Scalar,
    pub s_delta3: Scalar,
}

impl CombinedGPK {
    pub fn new(
        partical_gpks: &[PartialGPK],
        u: &CombinedPubkey,
        v: &CombinedPubkey,
        w: &CombinedPubkey,
        h: &CombinedPubkey,
    ) -> Self {
        Self {
            partical_gpks: partical_gpks.to_vec(),
            u: *u,
            v: *v,
            w: *w,
            h: *h,
        }
    }
}

impl CombinedUSK {
    pub fn new(partials: &[PartialUSK]) -> Self {
        Self {
            partials: partials.to_vec(),
        }
    }
}

pub struct SignCredBeforeHashing {
    pub t1: G1Projective,
    pub t2: G1Projective,
    pub t3: G1Projective,
    pub t4: G1Projective,
    pub r4: Gt,
    pub a: bbs::sign::SignCredBeforeHashing,
    pub b: bbs::sign::SignCredBeforeHashing,
    pub c: bbs::sign::SignCredBeforeHashing,
    pub rx: Scalar,
}

pub struct SignCredAfterHashing {
    pub s_a: bbs::sign::SignCredAfterHashing,
    pub s_b: bbs::sign::SignCredAfterHashing,
    pub s_c: bbs::sign::SignCredAfterHashing,
}

pub fn process_sign_before_hash(
    msg: &[u8],
    partial_usk: &PartialUSK,
    partial_gpk: &PartialGPK,
    combined_usk: &CombinedUSK,
    gpk: &CombinedGPK,
    rng: &mut impl RngCore,
) -> SignCredBeforeHashing {
    let PairingCurve { g1: _, g2 } = PairingCurve::new();
    let i = 0;

    let CombinedGPK {
        h,
        u,
        v,
        w,
        partical_gpks,
    } = gpk;

    let rx = gen_rand_scalar(rng);

    let a = bbs::sign::process_sign_before_hash(&partial_usk.x, &rx, u, rng);
    let b = bbs::sign::process_sign_before_hash(&partial_usk.x, &rx, v, rng);
    let c = bbs::sign::process_sign_before_hash(&partial_usk.x, &rx, w, rng);

    let t4 = partial_usk.a + h * (a.y + b.y + c.y);
    let a3 = pairing(&h.to_affine(), &g2.to_affine());

    let a1 = pairing(&t4.to_affine(), &g2.to_affine());
    let a2 = pairing(&h.to_affine(), &partial_gpk.omega.to_affine());

    let r4 = a1 * rx + a2 * (-a.r - b.r - c.r) + a3 * (-a.r_delta - b.r_delta - c.r_delta);

    SignCredBeforeHashing {
        t1: a.t,
        t2: b.t,
        t3: c.t,
        t4,
        r4,
        a,
        b,
        c,
        rx,
    }
}

pub fn process_sign_after_hash(
    x: &Scalar,
    rx: &Scalar,
    cred: &SignCredBeforeHashing,
    hash: &Scalar,
) -> SignCredAfterHashing {
    let s_a = bbs::sign::process_sign_after_hash(&cred.a, hash);
    let s_b = bbs::sign::process_sign_after_hash(&cred.b, hash);
    let s_c = bbs::sign::process_sign_after_hash(&cred.c, hash);

    

    SignCredAfterHashing { s_a, s_b, s_c }
}

pub fn sign(msg: &[u8], usk: &CombinedUSK, gpk: &CombinedGPK, rng: &mut impl RngCore) -> Signature {
    let mut hash: Vec<u8> = vec![];

    let cred =
        process_sign_before_hash(msg, &usk.partials[0], &gpk.partical_gpks[0], &usk, gpk, rng);
    let SignCredBeforeHashing {
        t1,
        t2,
        t3,
        t4,
        r4,
        a,
        b,
        c,
        rx,
    } = cred;

    hash.append(&mut msg.to_vec());
    hash.append(&mut a.t.to_bytes().as_ref().to_vec());
    hash.append(&mut b.t.to_bytes().as_ref().to_vec());
    hash.append(&mut c.t.to_bytes().as_ref().to_vec());
    hash.append(&mut a.r_first.to_bytes().as_ref().to_vec());
    hash.append(&mut b.r_first.to_bytes().as_ref().to_vec());
    hash.append(&mut c.r_first.to_bytes().as_ref().to_vec());
    hash.append(&mut a.r_second.to_bytes().as_ref().to_vec());
    hash.append(&mut b.r_second.to_bytes().as_ref().to_vec());
    hash.append(&mut c.r_second.to_bytes().as_ref().to_vec());

    hash.append(&mut r4.to_bytes().as_ref().to_vec());

    let hash = utils::calc_sha256_scalar(&hash);

    let SignCredAfterHashing { s_a, s_b, s_c } =
        process_sign_after_hash(&usk.partials[0].x, &rx, &cred, &hash);

    Signature {
        t1: a.t,
        t2: b.t,
        t3: c.t,
        t4: vec![t4],
        hash,
        sa: s_a.s,
        sb: s_b.s,
        sc: s_c.s,
        sx,
        s_delta1: s_a.s_delta,
        s_delta2: s_b.s_delta,
        s_delta3: s_c.s_delta,
    }
}

pub fn verify(msg: &[u8], signature: &Signature, gpk: &CombinedGPK) -> Result<(), ()> {
    let PairingCurve { g1, g2 } = PairingCurve::new();

    let Signature {
        t1,
        t2,
        t3,
        t4,
        hash,
        sa,
        sb,
        sc,
        sx,
        s_delta1,
        s_delta2,
        s_delta3,
    } = signature;

    let CombinedGPK {
        h,
        u,
        v,
        w,
        partical_gpks,
    } = gpk;

    let r1_v = u * sa + t1 * -hash;
    let r2_v = v * sb + t2 * -hash;
    let r3_v = w * sc + t3 * -hash;

    let mut r4_v: Vec<Gt> = vec![];
    let a3_v = pairing(&h.to_affine(), &g2.to_affine());
    let a5_v = pairing(&g1.to_affine(), &g2.to_affine());

    // for i in 0..3 {
    let i = 0;
    let a1_v = pairing(&t4[i].to_affine(), &g2.to_affine());
    let a2_v = pairing(&h.to_affine(), &partical_gpks[i].omega.to_affine());
    let a4_v = pairing(&t4[i].to_affine(), &partical_gpks[i].omega.to_affine());

    let r4_v_content = a1_v * sx[i]
        + a2_v * (-sa - sb - sc)
        + a3_v * (-s_delta1 - s_delta2 - s_delta3)
        + (a4_v - a5_v) * hash;

    r4_v.push(r4_v_content);
    // }

    let r5_v = t1 * sx[0] + u * -s_delta1;
    let r6_v = t2 * sx[1] + v * -s_delta2;
    let r7_v = t3 * sx[2] + w * -s_delta3;

    let mut hash_v: Vec<u8> = vec![];
    hash_v.append(&mut msg.to_vec());
    hash_v.append(&mut t1.to_bytes().as_ref().to_vec());
    hash_v.append(&mut t2.to_bytes().as_ref().to_vec());
    hash_v.append(&mut t3.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r1_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r2_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r3_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r5_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r6_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r7_v.to_bytes().as_ref().to_vec());

    hash_v.append(&mut r4_v[0].to_bytes().as_ref().to_vec());
    // for i in 0..3 {
    // }

    let hash_v = utils::calc_sha256_scalar(&hash_v);

    if hash_v == *hash {
        Ok(())
    } else {
        Err(())
    }
}

pub fn open_combain(
    usk: &PartialUSK,
    signature: &Signature,
    index: usize,
    share1: &OpenShare,
    share2: &OpenShare,
    share3: &OpenShare,
) -> bool {
    let a_v = signature.t4[index] - (share1 + share2 + share3);
    usk.a == a_v
}
