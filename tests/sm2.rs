#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use libsm_js::sm2::{Exchange2Keypair, Keypair, SM2ExchangeA, SM2ExchangeB, SM2};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn key_exchange() {
    let ctx = SM2::new();

    let keypair_a = ctx.new_keypair().into_serde::<Keypair>().unwrap();
    let keypair_b = ctx.new_keypair().into_serde::<Keypair>().unwrap();

    let pk_a = keypair_a.pk;
    let sk_a = keypair_a.sk;
    let pk_b = keypair_b.pk;
    let sk_b = keypair_b.sk;

    let id_a = "0000";
    let id_b = "9999";

    let mut ctx1 = SM2ExchangeA::new(16, id_a, id_b, &pk_a, &pk_b, &sk_a);
    let mut ctx2 = SM2ExchangeB::new(16, id_a, id_b, &pk_a, &pk_b, &sk_b);

    let r_a = ctx1.exchange1();
    let exchange2_keypair = ctx2
        .exchange2(&r_a)
        .into_serde::<Exchange2Keypair>()
        .unwrap();
    let r_b = exchange2_keypair.r_b;
    let s_b = exchange2_keypair.s_b;

    let s_a = ctx1.exchange3(&r_b, &s_b);
    let succ = ctx2.exchange4(&r_a, &s_a);

    assert!(succ);
    assert_eq!(ctx1.get_key(), ctx2.get_key());
}
