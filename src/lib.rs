#![no_std]
#[macro_use]
extern crate slice_as_array;
#[macro_use]
extern crate alloc;

pub mod issuer;
pub mod opener;
pub mod tests;
pub mod utils;

use alloc::vec::Vec;
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
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
pub struct ISK {
    pub gamma: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct OSK {
    pub xi: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct OPK {
    pub pubkey: G1Projective,
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct IPK {
    pub w: G2Projective,
}

#[derive(Serialize, Deserialize)]
pub struct USK {
    pub x: Scalar,
    pub a_i: G1Projective,
}

#[derive(Serialize, Deserialize)]
pub struct GPK {
    pub h: G1Projective,
    pub u: G1Projective,
    pub v: G1Projective,
    pub z: G1Projective,
    pub ipk: IPK,
}

#[derive(Serialize, Deserialize)]
pub struct Signature {
    pub t1: G1Projective,
    pub t2: G1Projective,
    pub t3: G1Projective,
    pub t4: G1Projective,
    pub hash: Scalar,
    pub sa: Scalar,
    pub sb: Scalar,
    pub sc: Scalar,
    pub sx: Scalar,
    pub s_delta1: Scalar,
    pub s_delta2: Scalar,
    pub s_delta3: Scalar,
}

impl GPK {
    pub fn new(
        u: G1Projective,
        v: G1Projective,
        z: G1Projective,
        h: G1Projective,
        ipk: IPK,
    ) -> Self {
        Self { u, v, z, h, ipk }
    }
}

pub fn sign(usk: &USK, gpk: &GPK, rng: &mut impl RngCore) -> Signature {
    let PairingCurve { g1: _, g2 } = PairingCurve::new();

    let USK { a_i, x } = usk;
    let GPK { h, u, v, z, ipk } = gpk;
    let IPK { w } = ipk;

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
    let t3 = z * c;

    let t4 = a_i + h * (a + b + c);

    let delta1 = a * x;
    let delta2 = b * x;
    let delta3 = c * x;

    let r1 = u * ra;
    let r2 = v * rb;
    let r3 = z * rc;

    let a1 = pairing(&t4.to_affine(), &g2.to_affine());
    let a2 = pairing(&h.to_affine(), &w.to_affine());
    let a3 = pairing(&h.to_affine(), &g2.to_affine());

    let r4 = a1 * rx + a2 * (-ra - rb - rc) + a3 * (-r_delta1 - r_delta2 - r_delta3);

    let r5 = t1 * rx + u * -r_delta1;
    let r6 = t2 * rx + v * -r_delta2;
    let r7 = t3 * rx + z * -r_delta3;

    let mut hash: Vec<u8> = vec![];
    hash.append(&mut t1.to_bytes().as_ref().to_vec());
    hash.append(&mut t2.to_bytes().as_ref().to_vec());
    hash.append(&mut t3.to_bytes().as_ref().to_vec());
    hash.append(&mut r1.to_bytes().as_ref().to_vec());
    hash.append(&mut r2.to_bytes().as_ref().to_vec());
    hash.append(&mut r3.to_bytes().as_ref().to_vec());
    hash.append(&mut r4.to_bytes().as_ref().to_vec());
    hash.append(&mut r5.to_bytes().as_ref().to_vec());
    hash.append(&mut r6.to_bytes().as_ref().to_vec());
    hash.append(&mut r7.to_bytes().as_ref().to_vec());

    let hash = utils::calc_sha256_scalar(&hash);

    let sa = ra + hash * a;
    let sb = rb + hash * b;
    let sc = rc + hash * c;
    let sx = rx + hash * x;
    let s_delta1 = r_delta1 + hash * delta1;
    let s_delta2 = r_delta2 + hash * delta2;
    let s_delta3 = r_delta3 + hash * delta3;

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

pub fn verify(signature: &Signature, gpk: &GPK) -> Result<(), ()> {
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

    let GPK { h, u, v, z, ipk } = gpk;
    let IPK { w } = ipk;

    let r1_v = u * sa + t1 * -hash;
    let r2_v = v * sb + t2 * -hash;
    let r3_v = z * sc + t3 * -hash;

    let a1_v = pairing(&t4.to_affine(), &g2.to_affine());
    let a2_v = pairing(&h.to_affine(), &w.to_affine());
    let a3_v = pairing(&h.to_affine(), &g2.to_affine());
    let a4_v = pairing(&t4.to_affine(), &w.to_affine());
    let a5_v = pairing(&g1.to_affine(), &g2.to_affine());

    let r4_v = a1_v * sx
        + a2_v * (-sa - sb - sc)
        + a3_v * (-s_delta1 - s_delta2 - s_delta3)
        + (a4_v - a5_v) * hash;

    let r5_v = t1 * sx + u * -s_delta1;
    let r6_v = t2 * sx + v * -s_delta2;
    let r7_v = t3 * sx + z * -s_delta3;

    let mut hash_v: Vec<u8> = vec![];
    hash_v.append(&mut t1.to_bytes().as_ref().to_vec());
    hash_v.append(&mut t2.to_bytes().as_ref().to_vec());
    hash_v.append(&mut t3.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r1_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r2_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r3_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r4_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r5_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r6_v.to_bytes().as_ref().to_vec());
    hash_v.append(&mut r7_v.to_bytes().as_ref().to_vec());

    let hash_v = utils::calc_sha256_scalar(&hash_v);

    if hash_v == *hash {
        Ok(())
    } else {
        Err(())
    }
}
