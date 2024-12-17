mod sign_url;
mod account;
mod store;

use std::collections::HashMap;
use std::ops::Add;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};
use rsa::RsaPrivateKey;
use serde_derive::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{debug, info};
use tracing_subscriber;
use url::Url;
use uuid::Uuid;
use warp::Filter;
use warp::host::Authority;
use warp::http::Response;
use crate::sign_url::SignUrlContainer;
use crate::account::Account;
use crate::store::DataStore;

#[derive(Deserialize, Serialize, Debug)]
struct CreateQuery {
    expires: Option<u64>,
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

#[derive(Serialize, Deserialize, Debug)]
struct VerifyQuery {
    payload: String,
    expires: u64,
    signature: String,
}

struct ServerSession {
    id: Uuid,
    expires: u64,
}

impl ServerSession {
    fn new(expires: u64) -> Self {
        let expires = SystemTime::now()
          .add(Duration::from_secs(expires))
          .duration_since(SystemTime::UNIX_EPOCH)
          .unwrap()
          .as_secs();
        ServerSession {
            id: Uuid::new_v4(),
            expires
        }
    }

    fn refresh(&mut self, expires: u64) {
        let expires = SystemTime::now()
          .add(Duration::from_secs(expires))
          .duration_since(SystemTime::UNIX_EPOCH)
          .unwrap()
          .as_secs();
        self.expires = expires;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,warp=debug".to_owned());
    tracing_subscriber::fmt()
      .with_env_filter(filter)
      .init();

    const DEFAULT_RSA_BIT_SIZE: usize = 2048;
    const DEFAULT_DATABASE_CONNECTION: u32 = 1024;
    const DEFAULT_CONTENT_LENGTH_LIMIT: u64 = 1024 * 16;
    const DEFAULT_COOKIE_EXPIRES: u64 = 2592000;  // 2592000秒 = 30日
    const DEFAULT_VERIFY_EXPIRES: u64 = 600000;  // 600000ミリ秒 = 10分

    // 2048bit = 512byte まで暗号化可能
    // password: 97byte 固定
    // padding: 11byte 固定
    // username = 512-97-11 = 408文字 (255文字の制限を付けるならこれでOK 1023文字なら鍵長が8192bit必要)
    info!("start create encrypt key...");
    let private_key = Arc::new(RsaPrivateKey::new(&mut rand::thread_rng(), DEFAULT_RSA_BIT_SIZE)?);
    info!("finish create encrypt key");

    info!("start setup datastore...");
    let datastore = Arc::new(DataStore::setup(DEFAULT_DATABASE_CONNECTION).await?);
    info!("finish setup datastore...");

    let session = Arc::new(RwLock::new(HashMap::<Uuid, Arc<RwLock<ServerSession>>>::new()));

    /*
    post /create?expires=number username,password
     -> res signedurl
    get /verify?payload=...&expires=...&signature=... → 冪等性 アカウント登録完了

    get /health-check
    post /login username,password
    get /logout
    get /protected
    */

    // GET /health-check
    let health_check = warp::path::path("health-check")
      .and(warp::get())
      .map(|| "Hello, World!");

    // GET /
    let index = {
        let path = warp::path::end()
          .and(warp::get());
        #[cfg(debug_assertions)]
        let api = path.and(warp::fs::file("./asset/index.html"));
        #[cfg(not(debug_assertions))]
        let api = path.map(|| warp::reply::html(include_str!("../asset/index.html")));
        api
    };

    // POST /login
    let login = {
        let datastore = datastore.clone();
        let session = session.clone();
        warp::path::path("login")
          .and(warp::post())
          .and(warp::body::content_length_limit(DEFAULT_CONTENT_LENGTH_LIMIT))
          .and(warp::body::json())
          .then(move |body: Account| {
              let datastore = datastore.to_owned();
              let session = session.to_owned();
              async move {
                  match datastore.select_account(&body.username).await {
                      Err(_account) => {
                          return Response::builder()
                            .body("user not found".to_string());
                      },
                      Ok(account) => {
                          if let Err(_) = account.verify(&body.password) {
                              return  Response::builder()
                                  .body("incorrect password".to_string());
                          }
                          let username = account.username.clone();

                          let new_session = ServerSession::new(DEFAULT_COOKIE_EXPIRES);
                          let session_id = new_session.id;
                          session.write().unwrap().insert(session_id, Arc::new(RwLock::new(new_session)));

                          Response::builder()
                            // .header("Set-Cookie", format!("token={}; Secure; HttpOnly; SameSite=Lax; Max-Age={}", session_id.to_string(), DEFAULT_COOKIE_EXPIRES))
                            .header("Set-Cookie", format!("token={}; HttpOnly; SameSite=Lax; Max-Age={}", session_id.to_string(), DEFAULT_COOKIE_EXPIRES))
                            .body(format!("Hello, {}!", username))
                      }
                  }
              }
          })
    };

    // GET /logout
    let logout = {
        let session = session.clone();
        warp::path::path("logout")
          .and(warp::get())
          .and(warp::filters::cookie::optional("token"))
          .then(move |cookie: Option<String>| {
              let session = session.to_owned();
              async move {
                  if let Some(cookie) = cookie {
                      if let Ok(cookie) = Uuid::from_str(&cookie) {
                          if session.read().unwrap().contains_key(&cookie) {
                              session.write().unwrap().remove(&cookie);
                          }
                      }
                  }
                  "logout".to_string()
              }
          })
    };

    // GET /protected
    let protected = {
        let session = session.clone();
        warp::path::path("protected")
          .and(warp::get())
          .and(warp::filters::cookie::optional("token"))
          .then(move |cookie: Option<String>| {
              let session = session.to_owned();
              async move {
                  if let Some(cookie) = cookie {
                      if let Ok(cookie) = Uuid::from_str(&cookie) {
                          if let Some(session) = session.read().unwrap().get(&cookie) {
                              if session.clone().read().unwrap().expires > SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() {
                                  let session_id = session.clone().read().unwrap().id;
                                  session.clone().write().unwrap().refresh(DEFAULT_COOKIE_EXPIRES);

                                  return Response::builder()
                                    // .header("Set-Cookie", format!("token={}; Secure; HttpOnly; SameSite=Lax; Max-Age={}", session_id.to_string(), DEFAULT_COOKIE_EXPIRES))
                                    .header("Set-Cookie", format!("token={}; HttpOnly; SameSite=Lax; Max-Age={}", session_id.to_string(), DEFAULT_COOKIE_EXPIRES))
                                    .body("authorized".to_string());
                              }
                          }
                      }
                  }
                  Response::builder()
                    .body("unauthorized".to_string())
              }
          })
    };

    // POST /create?expires=number
    let create = {
        let private_key = private_key.clone();
        let datastore = datastore.clone();
        warp::path("create")
          .and(warp::post())
          .and(warp::query::<CreateQuery>())
          .and(warp::body::content_length_limit(DEFAULT_CONTENT_LENGTH_LIMIT))
          .and(warp::body::json())
          .and(warp::host::optional())
          .then(move |query: CreateQuery, body: Account, authority: Option<Authority>| {
              let private_key = private_key.to_owned();
              let datastore = datastore.to_owned();
              async move {
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
                  let expires = query.expires.unwrap_or_else(|| DEFAULT_VERIFY_EXPIRES);
                  debug!("host: {:?}, expires: {:?}", host, expires);

                  if let Ok(_account) = datastore.select_account(&body.username).await {
                      return warp::reply::json(&"user already exist".to_string());
                  }

                  let account = {
                      let handle = thread::spawn(move || body.hash());
                      while !handle.is_finished() {
                          // Interval magic number from tokio
                          // see also: https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html#method.global_queue_interval
                          sleep(Duration::from_millis(31)).await;
                      }
                      match handle.join() {
                          Ok(a) => a,
                          Err(e) => {
                              info!("{:?}", e);
                              return warp::reply::json(&"error".to_string());
                          },
                      }
                  };

                  if let Err(e) = account.validate() {
                      info!("{:?}", e);
                      return warp::reply::json(&"error".to_string());
                  }
                  let compressed = account.compress();
                  match SignUrlContainer::make(compressed, expires, private_key.as_ref()) {
                      Ok(sign) => {
                          let res = CreateResponse::new(host, &sign);
                          warp::reply::json(&res)
                      },
                      Err(e) => {
                          info!("{:?}", e);
                          warp::reply::json(&"error".to_string())
                      }
                  }
              }
          })
    };

    // GET /verify?signature~~~
    let verify = {
        let private_key = private_key.clone();
        let datastore = datastore.clone();
        let session = session.clone();
        warp::path!("verify")
          .and(warp::get())
          .and(warp::query::<VerifyQuery>())
          .then(move |query: VerifyQuery| {
              let private_key = private_key.to_owned();
              let datastore = datastore.to_owned();
              let session = session.to_owned();
              async move {
                  let container = SignUrlContainer {
                      payload: query.payload,
                      expires: query.expires,
                      signature: query.signature,
                  };
                  let (user, response) = {
                      let v = container.verify(private_key.as_ref());
                      match v {
                          Ok(raw) => {
                              match serde_json::from_str(&raw) {
                                  Ok(value) => {
                                      let user = Account::decompress(value);
                                      debug!("account: {:?}", user);
                                      let username = user.username.clone();
                                      (Some(user), format!("Hello, {}!", username))
                                  },
                                  Err(err) => {
                                      info!("{:?}", err);
                                      if err.to_string() == "Expired" {
                                          return Response::builder()
                                            .body("Expired".to_string());
                                      }
                                      (None, "Invalid".to_string())
                                  }
                              }
                          },
                          Err(err) => {
                              info!("{:?}", err);
                              if err.to_string() == "Expired" {
                                  return Response::builder()
                                    .body("Expired".to_string());
                              }
                              (None, "Invalid".to_string())
                          }
                      }
                  };

                  match user {
                      Some(user) => {
                          if let Ok(_account) = datastore.select_account(&user.username).await {
                              return Response::builder()
                                .body("user already exist".to_string());
                          }
                          datastore.insert_account(&user.username, &user.password).await.unwrap();
                          let new_session = ServerSession::new(DEFAULT_COOKIE_EXPIRES);
                          let session_id = new_session.id;
                          session.write().unwrap().insert(session_id, Arc::new(RwLock::new(new_session)));

                          Response::builder()
                            // .header("Set-Cookie", format!("token={}; Secure; HttpOnly; SameSite=Lax; Max-Age={}", session_id.to_string(), DEFAULT_COOKIE_EXPIRES))
                            .header("Set-Cookie", format!("token={}; HttpOnly; SameSite=Lax; Max-Age={}", session_id.to_string(), DEFAULT_COOKIE_EXPIRES))
                            .body(response)
                      },
                      None => {
                          Response::builder()
                            .body("Invalid".to_string())
                      }
                  }
              }
          })
    };

    let routes = health_check
      .or(index)
      .or(create)
      .or(verify)
      .or(login)
      .or(logout)
      .or(protected)
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
