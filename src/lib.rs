#![no_std]
#[macro_use]
extern crate slice_as_array;
#[macro_use]
extern crate alloc;

use alloc::vec::Vec;
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use byteorder::{BigEndian, ByteOrder};
use ff::Field;
use group::{Curve, Group, GroupEncoding};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
pub struct GSK {
    pub xi_1: Scalar,
    pub xi_2: Scalar,
    pub xi_3: Scalar,
    pub gamma: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct GPK {
    pub h: G1Projective,
    pub u: G1Projective,
    pub v: G1Projective,
    pub z: G1Projective,
    pub w: G2Projective,
    pub g1: G1Projective,
    pub g2: G2Projective,
}

pub struct SetUpResult {
    pub gpk: GPK,
    pub gsk: GSK,
}

#[derive(Serialize, Deserialize)]
pub struct ISK {
    pub x: Scalar,
    pub a_i: G1Projective,
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

pub fn setup(rng: &mut impl RngCore) -> SetUpResult {
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let xi_1 = gen_rand_scalar(rng);
    let xi_2 = gen_rand_scalar(rng);
    let xi_3 = gen_rand_scalar(rng);

    let tmp = gen_rand_g1(rng);

    let u = tmp * xi_1;
    let v = tmp * xi_2;
    let z = tmp * xi_3;

    let h = u * xi_2 * xi_3;

    let gamma = gen_rand_scalar(rng);
    let w = g2 * gamma;

    let gsk = GSK {
        xi_1,
        xi_2,
        xi_3,
        gamma,
    };
    let gpk = GPK {
        h,
        u,
        v,
        w,
        z,
        g1,
        g2,
    };

    SetUpResult { gsk, gpk }
}

pub fn issue(gsk: &GSK, gpk: &GPK, rng: &mut impl RngCore) -> ISK {
    let x = gen_rand_scalar(rng);
    let tmp = (gsk.gamma + x).invert().unwrap();
    let a_i = gpk.g1 * tmp;

    ISK { a_i, x }
}

pub fn sign(isk: &ISK, gpk: &GPK, rng: &mut impl RngCore) -> Signature {
    let ISK { a_i, x } = isk;
    let GPK {
        h,
        u,
        v,
        w,
        z,
        g1: _,
        g2,
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

    let hash = calc_sha256_scalar(&hash);

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

    let GPK {
        h,
        u,
        v,
        w,
        z,
        g1,
        g2,
    } = gpk;

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

    let hash_v = calc_sha256_scalar(&hash_v);

    if hash_v == *hash {
        Ok(())
    } else {
        Err(())
    }
}

pub fn is_signed_member(isk: &ISK, signature: &Signature, gsk: &GSK) -> bool {
    let a_v = signature.t3 - (signature.t1 * gsk.xi_2 + signature.t2 * gsk.xi_1);

    isk.a_i == a_v
}

fn calc_sha256_scalar(vec: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(vec);
    let hashed = hasher.finalize().to_vec();

    let mut schalar: Vec<u64> = vec![0; hashed.len() / 8];
    BigEndian::read_u64_into(&hashed, &mut schalar);
    let schalar = slice_as_array!(&schalar, [u64; 4]).unwrap();

    Scalar::from_raw(*schalar)
}

fn gen_rand_scalar(rng: &mut impl RngCore) -> Scalar {
    Scalar::random(rng)
}

fn gen_rand_g1(rng: &mut impl RngCore) -> G1Projective {
    G1Projective::random(rng)
}

#[test]
fn test_all() {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let SetUpResult { gsk, gpk } = setup(&mut rng);
    let isk = issue(&gsk, &gpk, &mut rng);
    let sig = sign(&isk, &gpk, &mut rng);
    verify(&sig, &gpk).unwrap();

    // assert!(is_signed_member(&isk, &sig, &gsk));
}
