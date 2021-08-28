#[test]
fn test_all() {
    use alloc::vec::Vec;
    use rand::thread_rng;

    use crate::opener::{Opener, OpenerId};

    use crate::{open_combain, sign, verify, GPK, USK};

    let msg: Vec<u8> = vec![1, 3, 4, 5];
    let msg2: Vec<u8> = vec![1, 3, 4, 5, 5];

    let mut rng = thread_rng();

    let opener1 = Opener::random(OpenerId::One, &mut rng);
    let opener2 = Opener::random(OpenerId::Two, &mut rng);
    let opener3 = Opener::random(OpenerId::Three, &mut rng);

    let u = opener1.gen_combined_pubkey(&opener2.opk.h);
    let v = opener2.gen_combined_pubkey(&opener3.opk.h);
    let w = opener3.gen_combined_pubkey(&opener1.opk.h);

    let h = opener3.gen_combined_pubkey(&u);

    let particals = vec![
        opener1.issue_member(&mut rng),
        opener2.issue_member(&mut rng),
        opener3.issue_member(&mut rng),
    ];

    let opks = vec![opener1.opk, opener2.opk, opener3.opk];

    let usk = USK { particals };
    let gpk = GPK { h, u, v, w, opks };

    let sig = sign(&msg, &usk, &gpk, &mut rng);
    verify(&msg, &sig, &gpk).unwrap();

    match verify(&msg2, &sig, &gpk) {
        Ok(_) => {}
        Err(_) => {
            assert!(true);
        }
    };

    let s1 = opener1.open_share(&sig);
    let s2 = opener2.open_share(&sig);
    let s3 = opener3.open_share(&sig);

    assert!(open_combain(&usk, &sig, 0, &s1, &s2, &s3));
    assert!(open_combain(&usk, &sig, 1, &s1, &s2, &s3));
    assert!(open_combain(&usk, &sig, 2, &s1, &s2, &s3));
}
