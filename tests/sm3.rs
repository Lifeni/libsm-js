//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use libsm_js::sm3::SM3;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn get_hash() {
    let message = "hello world".as_bytes();
    let sm3 = SM3::new(message);
    let hash = sm3.get_hash();

    let hex = "44F0061E69FA6FDFC290C494654A05DC0C053DA7E5C52B84EF93A9D67D3FFF88";
    let hex = hex::decode(hex).unwrap();

    assert_eq!(hash, hex);
}
