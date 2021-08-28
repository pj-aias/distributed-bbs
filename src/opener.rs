use crate::utils::gen_rand_scalar;
use crate::PairingCurve;
use crate::ParticalUSK;
use crate::Signature;
use crate::{OPK, OSK};
use bls12_381::G2Projective;
use bls12_381::{G1Projective, Scalar};
use rand::RngCore;

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

pub type CombainedPubkey = G1Projective;
pub type Share = G1Projective;

impl Opener {
    pub fn new(id: OpenerId, xi: &Scalar, gamma: &Scalar) -> Self {
        let privkey = OSK {
            xi: *xi,
            gamma: *gamma,
        };
        let h = G1Projective::generator() * xi;
        let omega = G2Projective::generator() * gamma;

        let pubkey = OPK { h, omega };

        Self {
            id: id,
            osk: privkey,
            opk: pubkey,
        }
    }

    pub fn random(id: OpenerId, rng: &mut impl RngCore) -> Self {
        let xi = gen_rand_scalar(rng);
        let gamma = gen_rand_scalar(rng);

        Self::new(id, &xi, &gamma)
    }

    pub fn gen_combined_pubkey(&self, h: &CombainedPubkey) -> CombainedPubkey {
        h * self.osk.xi
    }

    pub fn open_share(&self, signature: &Signature) -> Share {
        match self.id {
            OpenerId::One => signature.t2 * self.osk.xi,
            OpenerId::Two => signature.t3 * self.osk.xi,
            OpenerId::Three => signature.t1 * self.osk.xi,
        }
    }

    pub fn issue_member(&self, rng: &mut impl RngCore) -> ParticalUSK {
        let PairingCurve { g1, g2: _ } = PairingCurve::new();

        let x = gen_rand_scalar(rng);
        let tmp = (self.osk.gamma + x).invert().unwrap();
        let a = g1 * tmp;

        ParticalUSK { a, x }
    }
}
