use crate::utils::gen_rand_scalar;
use crate::{OPK, OSK};
use bls12_381::{G1Projective, Scalar};
use rand::RngCore;

pub struct Opener {
    pub opk: OPK,
    pub osk: OSK,
}

impl Opener {
    pub fn new(xi: &Scalar) -> Self {
        let privkey = OSK { xi: *xi };
        let pubkey = G1Projective::generator() * xi;
        let pubkey = OPK { pubkey: pubkey };

        Self {
            osk: privkey,
            opk: pubkey,
        }
    }

    pub fn random(rng: &mut impl RngCore) -> Self {
        let xi = gen_rand_scalar(rng);

        Self::new(&xi)
    }

    pub fn gen_pubkey(&self, pk: &OPK) -> G1Projective {
        pk.pubkey * self.osk.xi
    }
}
