#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use libsm_js::sm4::SM4;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn encrypt() {
    // the key length must be 16.
    let key = "0123456789abcdef".as_bytes();
    let message = "hello world".as_bytes();
    let sm4 = SM4::new(key);
    let encrypt = sm4.encrypt(message);

    let hex = "F8858D9DBE5EA2DA4D63411D2EDAC01E";
    let hex = hex::decode(hex).unwrap();

    assert_eq!(encrypt, hex);
}

#[wasm_bindgen_test]
fn decrypt() {
    // the key length must be 16.
    let key = "0123456789abcdef".as_bytes();
    let message = "国密算法 SM4".as_bytes();
    let sm4 = SM4::new(key);
    let encrypt = sm4.encrypt(message);
    let decrypt = sm4.decrypt(&encrypt);

    assert_eq!(decrypt, message);
}
