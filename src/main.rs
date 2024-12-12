use std::collections::HashMap;
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
use base64::prelude::BASE64_STANDARD;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info};
use tracing_subscriber;
use url::Url;
use warp::Filter;

#[derive(Deserialize, Serialize, Debug)]
struct Account {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateQuery {
    expires: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifyQuery {
    payload: String,
    expires: u64,
    signature: String,
}


#[derive(Deserialize, Serialize, Debug)]
struct Signature {
    payload: String,  // username+argon2hashed passwordを公開鍵で暗号化したものをbase64エンコードしたデータ
    expires: u64,  // url有効期間のunixタイム時間
    signature: String,  // ?payload=<payload>&expires=<expires> の文字列を秘密鍵で暗号化したものをsha512でハッシュしたもの
}

impl Signature {
    fn make(account: Account, expires: u64, private_key: Arc<RsaPrivateKey>) -> Self {
        // let user = Account {
        //     username: account.username,
        //     password: hash(account.password.as_bytes()),
        // };
        let user = (account.username, hash(account.password.as_bytes()));
        debug!("account: {:?}", user);
        let private_key = RsaPrivateKey::from_components(
            private_key.n().clone(), private_key.e().clone(), private_key.d().clone(), Vec::from(private_key.primes())
        ).unwrap();
        let public_key = RsaPublicKey::from(private_key.clone());
        let serialize = serde_json::to_string(&user).unwrap();
        debug!("account serialize: {:?}", serialize);
        let encrypt = public_key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, serialize.as_bytes()).unwrap();
        debug!("encrypt serialized account: {:?}", encrypt);
        let payload = BASE64_STANDARD.encode(encrypt);
        debug!("base64 encoded encrypt: {:?}", payload);
        let expires = SystemTime::now()
          .add(Duration::from_millis(expires))
          .duration_since(SystemTime::UNIX_EPOCH)
          .unwrap()
          .as_secs();
        let param = format!("?payload={}&expires={}", payload, expires);
        let mut hasher = Sha256::new();
        hasher.update(param.as_bytes());
        let hash = hasher.finalize();
        debug!("hash: {:?}", hash);
        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
        let sign = signing_key.try_sign(&hash).unwrap().to_bytes();
        debug!("sign: {:?}", sign);
        let signature = BASE64_STANDARD.encode(sign);
        debug!("base64 encoded sign: {:?}", signature);
        Signature {
            payload,
            expires,
            signature,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct CreateResponse {
    sign_url: String,  // ?payload=...&expires=...&signature=...
}

impl CreateResponse {
    fn new(base: String, sign: &Signature) -> Self {
        let mut url = Url::parse(&base).unwrap().join("verify").unwrap();
        url.set_query(Some(&format!("payload={}&expires={}&signature={}", sign.payload, sign.expires, sign.signature)));
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
    let create = warp::path("create")
      .and(warp::post())
      .and(warp::query::<CreateQuery>())
      .and(warp::body::json())
      .map(move |query: CreateQuery, body: Account| {
          let expires = match query.expires {
              Some(exp) => exp,
              None => 600000u64,
          };
          let sign = Signature::make(body, expires, private_key.clone());
          // let host = warp::header::<String>("host");
          let host = "http://localhost:3030/".to_string();
          let res = CreateResponse::new(host, &sign);
          warp::reply::json(&res)
      });

    // GET /verify?signature~~~
    let verify = warp::path!("verify")
      .and(warp::get())
      .and(warp::query::<VerifyQuery>())
      .map(|query: VerifyQuery| {
          let expires =  Duration::from_secs(query.expires);
          let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
          if now > expires { return format!("Expired"); }

          let payload = query.payload;
          let signature = query.signature;
          println!("payload: {:?}", payload);
          println!("signature: {:?}", signature);
          format!("Hello, {:?}!", signature)
      });

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
