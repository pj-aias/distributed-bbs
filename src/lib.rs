// #![no_std]
#[macro_use]
extern crate slice_as_array;
#[macro_use]
extern crate alloc;

pub mod gm;
pub mod tests;
pub mod utils;

// use crate::gm::Share;
use alloc::vec::Vec;
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

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct PartialUSK {
    pub x: Scalar,
    pub a: G1Projective,
}

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

#[derive(Serialize, Deserialize)]
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
    pub s_delta1: Vec<Scalar>,
    pub s_delta2: Vec<Scalar>,
    pub s_delta3: Vec<Scalar>,
}

pub fn sign(msg: &[u8], usk: &CombinedUSK, gpk: &CombinedGPK, rng: &mut impl RngCore) -> Signature {
    let PairingCurve { g1: _, g2 } = PairingCurve::new();

    let CombinedGPK {
        h,
        u,
        v,
        w,
        partical_gpks,
    } = gpk;

    let a = gen_rand_scalar(rng);
    let b = gen_rand_scalar(rng);
    let c = gen_rand_scalar(rng);

    let ra = gen_rand_scalar(rng);
    let rb = gen_rand_scalar(rng);
    let rc = gen_rand_scalar(rng);
    let rx = gen_rand_scalar(rng);

    let r_delta1 = gen_rand_scalar(rng);
    let r_delta2 = gen_rand_scalar(rng);
    let r_delta3 = gen_rand_scalar(rng);

    let t1 = u * a;
    let t2 = v * b;
    let t3 = w * c;

    let partical_usk = usk.partials.as_ref();

    let t4: Vec<G1Projective> = utils::map(partical_usk, |partical| partical.a + h * (a + b + c));

    let delta1: Vec<Scalar> = utils::map(partical_usk, |partical| a * partical.x);
    let delta2: Vec<Scalar> = utils::map(partical_usk, |partical| b * partical.x);
    let delta3: Vec<Scalar> = utils::map(partical_usk, |partical| c * partical.x);

    let r1 = u * ra;
    let r2 = v * rb;
    let r3 = w * rc;

    let a3 = pairing(&h.to_affine(), &g2.to_affine());

    let mut r4: Vec<Gt> = vec![];
    for i in 0..3 {
        let a1 = pairing(&t4[i].to_affine(), &g2.to_affine());
        let a2 = pairing(&h.to_affine(), &partical_gpks[i].omega.to_affine());

        let r4_content = a1 * rx + a2 * (-ra - rb - rc) + a3 * (-r_delta1 - r_delta2 - r_delta3);
        r4.push(r4_content);
    }

    let r5 = t1 * rx + u * -r_delta1;
    let r6 = t2 * rx + v * -r_delta2;
    let r7 = t3 * rx + w * -r_delta3;

    let mut hash: Vec<u8> = vec![];
    hash.append(&mut msg.to_vec());
    hash.append(&mut t1.to_bytes().as_ref().to_vec());
    hash.append(&mut t2.to_bytes().as_ref().to_vec());
    hash.append(&mut t3.to_bytes().as_ref().to_vec());
    hash.append(&mut r1.to_bytes().as_ref().to_vec());
    hash.append(&mut r2.to_bytes().as_ref().to_vec());
    hash.append(&mut r3.to_bytes().as_ref().to_vec());

    for i in 0..3 {
        hash.append(&mut r4[i].to_bytes().as_ref().to_vec());
        hash.append(&mut r5.to_bytes().as_ref().to_vec());
        hash.append(&mut r6.to_bytes().as_ref().to_vec());
        hash.append(&mut r7.to_bytes().as_ref().to_vec());
    }

    let hash = utils::calc_sha256_scalar(&hash);

    let sa = ra + hash * a;
    let sb = rb + hash * b;
    let sc = rc + hash * c;

    let sx: Vec<Scalar> = utils::map(&partical_usk, |partical| rx + hash * partical.x);

    let s_delta1: Vec<Scalar> = utils::map(&delta1, |delta1| r_delta1 + hash * delta1);
    let s_delta2: Vec<Scalar> = utils::map(&delta2, |delta2| r_delta2 + hash * delta2);
    let s_delta3: Vec<Scalar> = utils::map(&delta3, |delta3| r_delta3 + hash * delta3);

    Signature {
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

    for i in 0..3 {
        let a1_v = pairing(&t4[i].to_affine(), &g2.to_affine());
        let a2_v = pairing(&h.to_affine(), &partical_gpks[i].omega.to_affine());
        let a4_v = pairing(&t4[i].to_affine(), &partical_gpks[i].omega.to_affine());

        let r4_v_content = a1_v * sx[i]
            + a2_v * (-sa - sb - sc)
            + a3_v * (-s_delta1[i] - s_delta2[i] - s_delta3[i])
            + (a4_v - a5_v) * hash;
        r4_v.push(r4_v_content);
    }

    let mut r5_v = vec![];
    let mut r6_v = vec![];
    let mut r7_v = vec![];

    for i in 0..3 {
        r5_v.push(t1 * sx[i] + u * -s_delta1[i]);
        r6_v.push(t2 * sx[i] + v * -s_delta2[i]);
        r7_v.push(t3 * sx[i] + w * -s_delta3[i]);
    }

    let mut hash_v: Vec<u8> = vec![];
    hash_v.append(&mut msg.to_vec());
    hash_v.append(&mut t1.to_bytes().as_ref().to_vec());
    hash_v.append(&mut t2.to_bytes().as_ref().to_vec());
    hash_v.append(&mut t3.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r1_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r2_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r3_v.to_bytes().as_ref().to_vec());

    for i in 0..3 {
        hash_v.append(&mut r4_v[i].to_bytes().as_ref().to_vec());
        hash_v.append(&mut r5_v[i].to_bytes().as_ref().to_vec());
        hash_v.append(&mut r6_v[i].to_bytes().as_ref().to_vec());
        hash_v.append(&mut r7_v[i].to_bytes().as_ref().to_vec());
    }

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
