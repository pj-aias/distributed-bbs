#[test]
fn test_all() {
    use alloc::vec::Vec;
    use rand::thread_rng;

    use crate::gm::{GMId, GM};

    use crate::{open_combain, sign, verify, CombinedGPK, CombinedUSK};

    let msg: Vec<u8> = vec![1, 3, 4, 5];
    let msg2: Vec<u8> = vec![1, 3, 4, 5, 5];

    let mut rng = thread_rng();

    let gm1 = GM::random(GMId::One, &mut rng);
    let gm2 = GM::random(GMId::Two, &mut rng);
    let gm3 = GM::random(GMId::Three, &mut rng);

    let u = gm1.gen_combined_pubkey(&gm2.gpk.h);
    let v = gm2.gen_combined_pubkey(&gm3.gpk.h);
    let w = gm3.gen_combined_pubkey(&gm1.gpk.h);

    let h = gm3.gen_combined_pubkey(&u);

    let partials = vec![
        gm1.issue_member(&mut rng),
        gm2.issue_member(&mut rng),
        gm3.issue_member(&mut rng),
    ];

    let partical_gpks = vec![gm1.gpk, gm2.gpk, gm3.gpk];

    let usk = CombinedUSK { partials };
    let gpk = CombinedGPK {
        h,
        u,
        v,
        w,
        partical_gpks,
    };

    let sig = sign(&msg, &usk, &gpk, &mut rng);
    verify(&msg, &sig, &gpk).unwrap();

    match verify(&msg2, &sig, &gpk) {
        Ok(_) => {}
        Err(_) => {
            assert!(true);
        }
    };

    let s1 = gm1.open_share(&sig);
    let s2 = gm2.open_share(&sig);
    let s3 = gm3.open_share(&sig);

    for i in 0..3 {
        assert!(open_combain(&usk.partials[i], &sig, i, &s1, &s2, &s3));
    }
}
