use crate::utils::gen_rand_scalar;
use crate::PairingCurve;
use crate::PartialGPK;
use crate::PartialGSK;
use crate::PartialUSK;
use crate::Signature;
use bls12_381::G2Projective;
use bls12_381::{G1Projective, Scalar};
use rand::RngCore;

#[derive(Copy, Clone)]
pub enum GMId {
    One,
    Two,
    Three,
}

pub struct GM {
    pub id: GMId,
    pub gpk: PartialGPK,
    pub gsk: PartialGSK,
}

pub type CombainedPubkey = G1Projective;
pub type OpenShare = G1Projective;

impl GM {
    pub fn new(id: GMId, xi: &Scalar, gamma: &Scalar) -> Self {
        let privkey = PartialGSK {
            xi: *xi,
            gamma: *gamma,
        };
        let h = G1Projective::generator() * xi;
        let omega = G2Projective::generator() * gamma;

        let pubkey = PartialGPK { h, omega };

        Self {
            id: id,
            gsk: privkey,
            gpk: pubkey,
        }
    }

    pub fn random(id: GMId, rng: &mut impl RngCore) -> Self {
        let xi = gen_rand_scalar(rng);
        let gamma = gen_rand_scalar(rng);

        Self::new(id, &xi, &gamma)
    }

    pub fn gen_combined_pubkey(&self, h: &CombainedPubkey) -> CombainedPubkey {
        h * self.gsk.xi
    }

    pub fn open_share(&self, signature: &Signature) -> OpenShare {
        match self.id {
            GMId::One => signature.t2 * self.gsk.xi,
            GMId::Two => signature.t3 * self.gsk.xi,
            GMId::Three => signature.t1 * self.gsk.xi,
        }
    }

    pub fn issue_member(&self, rng: &mut impl RngCore) -> PartialUSK {
        let PairingCurve { g1, g2: _ } = PairingCurve::new();

        let x = gen_rand_scalar(rng);
        let tmp = (self.gsk.gamma + x).invert().unwrap();
        let a = g1 * tmp;

        PartialUSK { a, x }
    }
}
