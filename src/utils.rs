use alloc::vec::Vec;
use bls12_381::Scalar;
use byteorder::{BigEndian, ByteOrder};
use ff::Field;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub(crate) fn calc_sha256_scalar(vec: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(vec);
    let hashed = hasher.finalize().to_vec();

    let mut schalar: Vec<u64> = vec![0; hashed.len() / 8];
    BigEndian::read_u64_into(&hashed, &mut schalar);
    let schalar = slice_as_array!(&schalar, [u64; 4]).unwrap();

    Scalar::from_raw(*schalar)
}

pub(crate) fn gen_rand_scalar(rng: &mut impl RngCore) -> Scalar {
    Scalar::random(rng)
}

pub(crate) fn map<T, F, R>(v: &[T], f: F) -> Vec<R>
where
    F: Fn(&T) -> R,
{
    v.iter().map(&f).collect()
}

pub(crate) fn enumurate<T, F, R>(v: &[T], f: F) -> Vec<R>
where
    F: Fn((usize, &T)) -> R,
{
    v.iter().enumerate().map(&f).collect()
