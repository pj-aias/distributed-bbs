// use crate::utils::gen_rand_scalar;
// use crate::{PairingCurve, IPK, ISK, USK};
// use bls12_381::Scalar;
// use rand::RngCore;

// #[derive(Copy, Clone)]
// pub struct Issuer {
//     pub ipk: IPK,
//     pub isk: ISK,
// }

// impl Issuer {
//     pub fn new(gamma: &Scalar) -> Self {
//         let PairingCurve { g1: _, g2 } = PairingCurve::new();
//         let omega = g2 * gamma;

//         let isk = ISK { gamma: *gamma };
//         let ipk = IPK { omega };

//         Issuer { isk, ipk }
//     }

//     pub fn random(rng: &mut impl RngCore) -> Self {
//         let gamma = gen_rand_scalar(rng);

//         Self::new(&gamma)
//     }

//     pub fn issue(&self, rng: &mut impl RngCore) -> USK {
//         let PairingCurve { g1, g2: _ } = PairingCurve::new();

//         let x = gen_rand_scalar(rng);
//         let tmp = (self.isk.gamma + x).invert().unwrap();
//         let a_i = g1 * tmp;

//         USK { a_i, x }
//     }
// }
