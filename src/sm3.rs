use libsm::sm3::hash::Sm3Hash;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct SM3 {
    buffer: Vec<u8>,
}

#[wasm_bindgen]
impl SM3 {
    #[wasm_bindgen(constructor)]
    pub fn new(buffer: &[u8]) -> SM3 {
        let buffer = buffer.to_vec();
        SM3 { buffer }
    }

    pub fn get_hash(&self) -> Vec<u8> {
        let mut hash = Sm3Hash::new(&self.buffer);
        let digest: [u8; 32] = hash.get_hash();
        let digest = digest.to_vec();
        digest
    }
}
