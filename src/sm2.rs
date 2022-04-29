use libsm::sm2::encrypt::{DecryptCtx, EncryptCtx};
use libsm::sm2::signature::{SigCtx, Signature};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
struct Keypair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[wasm_bindgen]
pub struct SM2 {
    ctx: SigCtx,
}

#[wasm_bindgen]
impl SM2 {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SM2 {
        SM2 { ctx: SigCtx::new() }
    }

    pub fn new_keypair(&self) -> JsValue {
        let (pk, sk) = self.ctx.new_keypair();
        let pk = self.ctx.serialize_pubkey(&pk, true);
        let sk = self.ctx.serialize_seckey(&sk);
        let keypair = Keypair { pk, sk };
        JsValue::from_serde(&keypair).unwrap()
    }

    pub fn pk_from_sk(&self, sk: &[u8]) -> Vec<u8> {
        let sk = self.ctx.load_seckey(sk).unwrap();
        let pk = self.ctx.pk_from_sk(&sk);
        self.ctx.serialize_pubkey(&pk, true)
    }

    pub fn sign(&self, buffer: &[u8], sk: &[u8], pk: &[u8]) -> Vec<u8> {
        let pk = self.ctx.load_pubkey(&pk).unwrap();
        let sk = self.ctx.load_seckey(&sk).unwrap();
        let signature = self.ctx.sign(buffer, &sk, &pk);
        signature.der_encode()
    }

    pub fn verify(&self, buffer: &[u8], pk: &[u8], signature: &[u8]) -> bool {
        let pk = self.ctx.load_pubkey(&pk).unwrap();
        let signature = Signature::der_decode(signature).unwrap();
        self.ctx.verify(buffer, &pk, &signature)
    }

    pub fn encrypt(&self, buffer: &[u8], pk: &[u8]) -> Vec<u8> {
        let pk = self.ctx.load_pubkey(&pk).unwrap();
        let klen = buffer.len();
        let encrypt_ctx = EncryptCtx::new(klen, pk);
        encrypt_ctx.encrypt(buffer)
    }

    pub fn decrypt(&self, buffer: &[u8], sk: &[u8]) -> Vec<u8> {
        let sk = self.ctx.load_seckey(&sk).unwrap();
        let klen = buffer.len();
        let decrypt_ctx = DecryptCtx::new(klen, sk);
        decrypt_ctx.decrypt(buffer)
    }
}
