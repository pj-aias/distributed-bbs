use crate::utils::gen_rand_scalar;
use crate::Signature;
use crate::{OPK, OSK};
use bls12_381::{G1Projective, Scalar};
use rand::RngCore;

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum OpenerId {
    One,
    Two,
    Three,
}

pub struct Opener {
    pub id: OpenerId,
    pub opk: OPK,
    pub osk: OSK,
}

impl Opener {
    pub fn new(id: OpenerId, xi: &Scalar) -> Self {
        let privkey = OSK { xi: *xi };
        let pubkey = G1Projective::generator() * xi;
        let pubkey = OPK { pubkey: pubkey };

        Self {
            id: id,
            osk: privkey,
            opk: pubkey,
        }
    }

    pub fn random(id: OpenerId, rng: &mut impl RngCore) -> Self {
        let xi = gen_rand_scalar(rng);

        Self::new(id, &xi)
    }

    pub fn gen_pubkey(&self, pk: &OPK) -> G1Projective {
        pk.pubkey * self.osk.xi
    }

    pub fn open_share(&self, signature: &Signature) -> G1Projective {
        let id = self.id as u8;

        if id == (OpenerId::One as u8) {
            signature.t2 * self.osk.xi
        } else if id == (OpenerId::Two as u8) {
            signature.t3 * self.osk.xi
        } else {
            signature.t1 * self.osk.xi
        }
    }
}
