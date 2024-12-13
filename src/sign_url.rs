use std::ops::Add;
use std::time::{Duration, SystemTime};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::debug;

#[derive(Debug)]
pub struct SignUrlContainer {
    pub payload: String,  // 任意のjson変換可能なデータを公開鍵で暗号化したものをbase64エンコードしたデータ
    pub expires: u64,  // url有効期間のunixタイム時間
    pub signature: String,  // ?payload=<payload>&expires=<expires> の文字列を秘密鍵で暗号化したものをsha256でハッシュしたもの
}

impl SignUrlContainer {
    pub fn make<S: Serialize>(data: S, expires: u64, private_key: &RsaPrivateKey) -> Result<Self, Box<dyn std::error::Error>> {
        let nonce: u32 = rand::random();
        let serialize = format!("{}.nonce={:X>08}", serde_json::to_string(&data)?, nonce);
        debug!("payload serialize with nonce: {:?}", serialize);

        let private_key = RsaPrivateKey::from_components(
            private_key.n().clone(), private_key.e().clone(), private_key.d().clone(), Vec::from(private_key.primes())
        ).unwrap();
        let public_key = RsaPublicKey::from(private_key.clone());
        let encrypt = public_key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, serialize.as_bytes())?;
        debug!("encrypt serialized payload: {:?}", encrypt);

        let payload = BASE64_URL_SAFE_NO_PAD.encode(encrypt);
        debug!("base64 encoded encrypt payload: {:?}", payload);

        let expires = SystemTime::now()
          .add(Duration::from_millis(expires))
          .duration_since(SystemTime::UNIX_EPOCH)?
          .as_secs();
        let param = format!("?payload={}&expires={}", payload, expires);
        let mut hasher = Sha256::new();
        hasher.update(param.as_bytes());
        let hash = hasher.finalize();
        debug!("hash: {:?}", hash);

        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
        let sign = signing_key.try_sign(&hash).unwrap().to_bytes();
        debug!("sign: {:?}", sign);

        let signature = BASE64_URL_SAFE_NO_PAD.encode(sign);
        debug!("base64 encoded sign: {:?}", signature);

        Ok(SignUrlContainer {
            payload,
            expires,
            signature,
        })
    }

    pub fn verify(&self, private_key: &RsaPrivateKey) -> Result<String, Box<dyn std::error::Error>> {
        // 動作順序
        // 1. 改ざんチェック
        // 2. 期限チェック
        // 3. データ複合化

        // signatureをみて改ざんされていないことを確認する
        debug!("base64 encoded signature: {:?}", &self.signature);
        let sign = BASE64_URL_SAFE_NO_PAD.decode(&self.signature)?;
        debug!("decode signature: {:?}", sign);
        let signature = Signature::try_from(sign.as_slice())?;
        let private_key = RsaPrivateKey::from_components(
            private_key.n().clone(), private_key.e().clone(), private_key.d().clone(), Vec::from(private_key.primes())
        )?;
        let public_key = RsaPublicKey::from(private_key.clone());
        let param = format!("?payload={}&expires={}", &self.payload, self.expires);
        let mut hasher = Sha256::new();
        hasher.update(param.as_bytes());
        let hash = hasher.finalize();
        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);
        verifying_key.verify(&hash, &signature)?;

        // expiresをみて期限が切れてないことを確認する
        let expires =  Duration::from_secs(self.expires);
        let now = SystemTime::now()
          .duration_since(SystemTime::UNIX_EPOCH)
          .unwrap();
        debug!("expires: {}, now: {}", expires.as_secs(), now.as_secs());
        if now > expires { return Err(Box::from("Expired")); }

        // データ複合化
        debug!("base64 encoded payload: {:?}", &self.payload);
        let encrypt_raw_data = BASE64_URL_SAFE_NO_PAD.decode(&self.payload)?;
        debug!("encrypt raw data: {:?}", encrypt_raw_data);
        let raw_string = String::from_utf8(private_key.decrypt(Pkcs1v15Encrypt, encrypt_raw_data.as_slice())?)?;
        debug!("decrypt raw data: {:?}", raw_string);
        let split_raw = raw_string.split(".nonce=").collect::<Vec<&str>>();
        let serialized = split_raw[..split_raw.len()-1].join("").to_string();
        debug!("serialized: {:?}", serialized);

        Ok(serialized)
    }
}
