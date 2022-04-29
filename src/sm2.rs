use libsm::sm2::encrypt::{DecryptCtx, EncryptCtx};
use libsm::sm2::exchange::{ExchangeCtxA, ExchangeCtxB};
use libsm::sm2::signature::{SigCtx, Signature};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct Keypair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Exchange2Keypair {
    pub r_b: Vec<u8>,
    pub s_b: Vec<u8>,
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
}

#[wasm_bindgen]
pub struct SM2Encrypt {
    encrypt_ctx: EncryptCtx,
}

#[wasm_bindgen]
impl SM2Encrypt {
    #[wasm_bindgen(constructor)]
    pub fn new(pk: &[u8]) -> SM2Encrypt {
        let ctx = SigCtx::new();
        let pk = ctx.load_pubkey(pk).unwrap();
        let klen: usize = 128;
        let encrypt_ctx = EncryptCtx::new(klen, pk);
        SM2Encrypt { encrypt_ctx }
    }

    pub fn encrypt(&self, buffer: &[u8]) -> Vec<u8> {
        self.encrypt_ctx.encrypt(buffer)
    }
}

#[wasm_bindgen]
pub struct SM2Decrypt {
    decrypt_ctx: DecryptCtx,
}

#[wasm_bindgen]
impl SM2Decrypt {
    #[wasm_bindgen(constructor)]
    pub fn new(sk: &[u8]) -> SM2Decrypt {
        let ctx = SigCtx::new();
        let sk = ctx.load_seckey(sk).unwrap();
        let klen: usize = 128;
        let decrypt_ctx = DecryptCtx::new(klen, sk);
        SM2Decrypt { decrypt_ctx }
    }

    pub fn decrypt(&self, buffer: &[u8]) -> Vec<u8> {
        self.decrypt_ctx.decrypt(buffer)
    }
}

#[wasm_bindgen]
pub struct SM2ExchangeA {
    ctx: SigCtx,
    exchange_ctx: ExchangeCtxA,
}

#[wasm_bindgen]
impl SM2ExchangeA {
    #[wasm_bindgen(constructor)]
    pub fn new(id_a: &str, id_b: &str, pk_a: &[u8], pk_b: &[u8], sk_a: &[u8]) -> SM2ExchangeA {
        let ctx = SigCtx::new();
        let pk_a = ctx.load_pubkey(pk_a).unwrap();
        let pk_b = ctx.load_pubkey(pk_b).unwrap();
        let sk_a = ctx.load_seckey(sk_a).unwrap();
        let klen: usize = 128;
        let exchange_ctx = ExchangeCtxA::new(klen, id_a, id_b, pk_a, pk_b, sk_a);
        SM2ExchangeA { ctx, exchange_ctx }
    }

    pub fn exchange1(&mut self) -> Vec<u8> {
        let r_a = self.exchange_ctx.exchange1();
        let r_a = self.ctx.serialize_pubkey(&r_a, true);
        r_a
    }

    pub fn exchange3(&mut self, r_b: &[u8], s_b: &[u8]) -> Vec<u8> {
        let r_b = self.ctx.load_pubkey(r_b).unwrap();
        let mut arr: [u8; 32] = [0; 32];
        arr.copy_from_slice(s_b);
        let s_a = self.exchange_ctx.exchange3(&r_b, arr);
        s_a.to_vec()
    }

    pub fn get_key(&self) -> Vec<u8> {
        self.exchange_ctx.get_key().unwrap()
    }
}

#[wasm_bindgen]
pub struct SM2ExchangeB {
    ctx: SigCtx,
    exchange_ctx: ExchangeCtxB,
}

#[wasm_bindgen]
impl SM2ExchangeB {
    #[wasm_bindgen(constructor)]
    pub fn new(id_a: &str, id_b: &str, pk_a: &[u8], pk_b: &[u8], sk_b: &[u8]) -> SM2ExchangeB {
        let ctx = SigCtx::new();
        let pk_a = ctx.load_pubkey(pk_a).unwrap();
        let pk_b = ctx.load_pubkey(pk_b).unwrap();
        let sk_b = ctx.load_seckey(sk_b).unwrap();
        let klen: usize = 128;
        let exchange_ctx = ExchangeCtxB::new(klen, id_a, id_b, pk_a, pk_b, sk_b);
        SM2ExchangeB { ctx, exchange_ctx }
    }

    pub fn exchange2(&mut self, r_a: &[u8]) -> JsValue {
        let r_a = self.ctx.load_pubkey(r_a).unwrap();
        let (r_b, s_b) = self.exchange_ctx.exchange2(&r_a);
        let r_b = self.ctx.serialize_pubkey(&r_b, true);
        let s_b = s_b.to_vec();
        let keypair = Exchange2Keypair { r_b, s_b };
        JsValue::from_serde(&keypair).unwrap()
    }

    pub fn exchange4(&mut self, r_a: &[u8], s_a: &[u8]) -> bool {
        let r_a = self.ctx.load_pubkey(r_a).unwrap();
        let mut arr: [u8; 32] = [0; 32];
        arr.copy_from_slice(s_a);
        let succ = self.exchange_ctx.exchange4(arr, &r_a);
        succ
    }

    pub fn get_key(&self) -> Vec<u8> {
        self.exchange_ctx.get_key().unwrap()
    }
}
