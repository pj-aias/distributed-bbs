#[test]
fn test_all() {
    use rand::thread_rng;
    let mut rng = thread_rng();

    use crate::issuer::Issuer;
    use crate::opener::Opener;

    use crate::{is_signed_member, sign, verify, GPK, OPK};

    let issuer = Issuer::random(&mut rng);

    let opener1 = Opener::random(&mut rng);
    let opener2 = Opener::random(&mut rng);
    let opener3 = Opener::random(&mut rng);

    let u = opener1.gen_pubkey(&opener2.opk);
    let v = opener2.gen_pubkey(&opener3.opk);
    let z = opener3.gen_pubkey(&opener1.opk);

    let tmp = OPK { pubkey: u };
    let h = opener3.gen_pubkey(&tmp);

    let gpk = GPK::new(u, v, z, h, issuer.ipk);
    let usk = issuer.issue(&mut rng);

    let sig = sign(&usk, &gpk, &mut rng);
    verify(&sig, &gpk).unwrap();

    assert!(is_signed_member(
        &usk,
        &sig,
        &opener1.osk,
        &opener2.osk,
        &opener3.osk
    ));
}
