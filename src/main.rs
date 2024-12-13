use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString,
        PasswordHash, PasswordVerifier
    },
    Argon2
};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info};
use tracing_subscriber;
use url::Url;
use warp::Filter;
use warp::host::Authority;

#[derive(Deserialize, Serialize, Debug)]
struct Account {
    username: String,
    password: String,
}

impl Account {
    fn validate(&self) -> Result<(), String> {
        if self.username.len() > 256 { return Err("username must be 256 characters or less".to_string()); }
        if !self.username.is_ascii() { return Err("username must be ascii characters".to_string()); }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateQuery {
    expires: Option<u64>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SignUrlContainer {
    payload: String,  // username+argon2hashed passwordを公開鍵で暗号化したものをbase64エンコードしたデータ
    expires: u64,  // url有効期間のunixタイム時間
    signature: String,  // ?payload=<payload>&expires=<expires> の文字列を秘密鍵で暗号化したものをsha512でハッシュしたもの
}

impl SignUrlContainer {
    fn make(account: Account, expires: u64, private_key: Arc<RsaPrivateKey>) -> Result<Self, Box<dyn std::error::Error>> {
        // let user = Account {
        //     username: account.username,
        //     password: hash(account.password.as_bytes()),
        // };
        account.validate()?;
        let user = (account.username, hash(account.password.as_bytes()));
        debug!("account: {:?}", user);
        let private_key = RsaPrivateKey::from_components(
            private_key.n().clone(), private_key.e().clone(), private_key.d().clone(), Vec::from(private_key.primes())
        ).unwrap();
        let public_key = RsaPublicKey::from(private_key.clone());
        let serialize = serde_json::to_string(&user)?;
        debug!("account serialize: {:?}", serialize);
        let encrypt = public_key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, serialize.as_bytes())?;
        debug!("encrypt serialized account: {:?}", encrypt);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(encrypt);
        debug!("base64 encoded encrypt: {:?}", payload);
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
}



#[derive(Deserialize, Serialize, Debug)]
struct CreateResponse {
    sign_url: String,  // ?payload=...&expires=...&signature=...
}

impl CreateResponse {
    fn new(base: String, sign: &SignUrlContainer) -> Self {
        let mut url = Url::parse(&base).unwrap().join("verify").unwrap();
        url.set_query(Some(
            &format!("payload={}&expires={}&signature={}",
                 urlencoding::encode(sign.payload.as_str()).to_string(),
                 sign.expires,
                 urlencoding::encode(sign.signature.as_str()).to_string()
            )
        ));
        let sign_url = url.to_string();
        CreateResponse {
            sign_url
        }
    }
}

fn hash(s: &[u8]) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(s, &salt).unwrap().to_string()
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifyQuery {
    payload: String,
    expires: u64,
    signature: String,
}

fn verify(payload: String, expires: u64, signature: String, private_key: Arc<RsaPrivateKey>) -> Result<String, Box<dyn std::error::Error>> {
    // 動作順序
    // 1. 改ざんチェック
    // 2. 期限チェック
    // 3. データ複合化

    // signatureをみて改ざんされていないことを確認する
    debug!("base64 encoded signature: {:?}", signature);
    let sign = BASE64_URL_SAFE_NO_PAD.decode(signature)?;
    debug!("decode signature: {:?}", sign);
    let signature = Signature::try_from(sign.as_slice())?;
    let private_key = RsaPrivateKey::from_components(
        private_key.n().clone(), private_key.e().clone(), private_key.d().clone(), Vec::from(private_key.primes())
    )?;
    let public_key = RsaPublicKey::from(private_key.clone());
    let param = format!("?payload={}&expires={}", payload, expires);
    let mut hasher = Sha256::new();
    hasher.update(param.as_bytes());
    let hash = hasher.finalize();
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);
    verifying_key.verify(&hash, &signature)?;

    // expiresをみて期限が切れてないことを確認する
    let expires =  Duration::from_secs(expires);
    let now = SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .unwrap();
    debug!("expires: {}, now: {}", expires.as_secs(), now.as_secs());
    if now > expires { return Err(Box::from("Expired")); }

    // データ複合化
    debug!("base64 encoded payload: {:?}", payload);
    let encrypt_raw_data = BASE64_URL_SAFE_NO_PAD.decode(payload)?;
    debug!("encrypt raw data: {:?}", encrypt_raw_data);
    let user_raw_string = String::from_utf8(private_key.decrypt(Pkcs1v15Encrypt, encrypt_raw_data.as_slice()).unwrap())?;
    debug!("decrypt raw data: {:?}", user_raw_string);
    let user_raw: (String, String) = serde_json::from_str(&user_raw_string)?;
    debug!("raw data: {:?}", user_raw);
    let user = Account {
        username: user_raw.0,
        password: user_raw.1,
    };
    debug!("account: {:?}", user);
    Ok(format!("Hello, {}!", user.username))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,warp=debug".to_owned());
    tracing_subscriber::fmt()
      .with_env_filter(filter)
      .init();

    // 2048bit = 512byte まで暗号化可能
    // password: 97byte 固定
    // padding: 11byte 固定
    // username = 512-97-11 = 408文字 (255文字の制限を付けるならこれでOK 1023文字なら鍵長が8192bit必要)
    info!("start create encrypt key...");
    let private_key = Arc::new(RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap());
    info!("finish create encrypt key");

    /*
    post /create?expires=number username,password
     -> res signedurl
    get /verify?payload=...&expires=...&signature=... → 冪等性 アカウント登録完了

    get /health-check
    post /login username,password
    post /logout
    get /protected
    */

    // GET /health-check
    let health_check = warp::path::path("health-check")
      .and(warp::get())
      .map(|| "Hello, World!");

    // POST /create?expires=number
    let create = {
        let private_key = private_key.clone();
        warp::path("create")
          .and(warp::post())
          .and(warp::query::<CreateQuery>())
          .and(warp::body::json())
          .and(warp::host::optional())
          .map(move |query: CreateQuery, body: Account, authority: Option<Authority>| {
              let host = match authority {
                  Some(a) => {
                      if let Some(port) = a.port() {
                          if port.as_u16() == 3030 {
                              format!("http://{}", a.as_str())
                          } else {
                              format!("https://{}", a.as_str())
                          }
                      } else {
                          format!("http://{}", a.as_str())
                      }
                  },
                  None => "http://localhost:3030/".to_string(),
              };
              let expires = query.expires.unwrap_or_else(|| 600000u64);
              debug!("host: {:?}, expires: {:?}", host, expires);
              match SignUrlContainer::make(body, expires, private_key.to_owned()) {
                  Ok(sign) => {
                      let res = CreateResponse::new(host, &sign);
                      warp::reply::json(&res)
                  },
                  Err(e) => {
                      info!("{:?}", e);
                      warp::reply::json(&"error".to_string())
                  }
              }
          })
    };

    // GET /verify?signature~~~
    let verify = {
        let private_key = private_key.clone();
        warp::path!("verify")
          .and(warp::get())
          .and(warp::query::<VerifyQuery>())
          .map(move |query: VerifyQuery| {
              verify(query.payload, query.expires, query.signature, private_key.to_owned()).unwrap_or_else(|err| {
                  info!("{:?}", err);
                  if err.to_string() == "Expired" { return "Expired".to_string(); }
                  "Invalid".to_string()
              })
          })
    };

    let routes = health_check
      .or(create)
      .or(verify)
    ;

    let non_tls_server = warp::serve(routes.clone().with(warp::trace::request()))
      .run(([0, 0, 0, 0], 3030));

    let tls_server = warp::serve(routes.with(warp::trace::request()))
      .tls()
      .cert_path("./credential/server.crt")
      .key_path("./credential/server.key")
      .run(([0, 0, 0, 0], 3031));

    // non tls server
    let handle = tokio::spawn(non_tls_server);

    // use tls
    tls_server.await;

    handle.abort();
    Ok(())
}
