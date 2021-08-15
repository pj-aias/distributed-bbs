use crate::utils::{gen_rand_g1, gen_rand_scalar};
use crate::{PairingCurve, IPK, ISK, OPK, OSK, USK};
use bls12_381::{G1Projective, G2Projective, Scalar};
use rand::RngCore;

pub struct Opener {
    pub opk: OPK,
    pub osk: OSK,
}

#[derive(Copy, Clone)]
pub struct Issuer {
    pub ipk: IPK,
    pub isk: ISK,
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

impl Issuer {
    pub fn new(gamma: &Scalar) -> Self {
        let PairingCurve { g1, g2 } = PairingCurve::new();
        let w = g2 * gamma;

        let isk = ISK { gamma: *gamma };
        let ipk = IPK { w };

        Issuer { isk, ipk }
    }

    pub fn random(rng: &mut impl RngCore) -> Self {
        let gamma = gen_rand_scalar(rng);

        Self::new(&gamma)
    }

    pub fn issue(&self, rng: &mut impl RngCore) -> USK {
        let PairingCurve { g1, g2 } = PairingCurve::new();

        let x = gen_rand_scalar(rng);
        let tmp = (self.isk.gamma + x).invert().unwrap();
        let a_i = g1 * tmp;

        USK { a_i, x }
    }
}

impl PairingCurve {
    pub fn new() -> Self {
        PairingCurve {
            g1: G1Projective::generator(),
            g2: G2Projective::generator(),
        }
    }
}
