mod sign_url;
mod account;
mod store;

use std::sync::Arc;
use std::thread;
use std::time::Duration;
use rsa::RsaPrivateKey;
use serde_derive::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{debug, info};
use tracing_subscriber;
use url::Url;
use warp::Filter;
use warp::host::Authority;
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

#[tokio::main(flavor = "current_thread")]
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
    let private_key = Arc::new(RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?);
    info!("finish create encrypt key");

    info!("start setup datastore...");
    let datastore = Arc::new(DataStore::setup(1024).await?);
    info!("finish setup datastore...");

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
        let datastore = datastore.clone();
        warp::path("create")
          .and(warp::post())
          .and(warp::query::<CreateQuery>())
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
                  let expires = query.expires.unwrap_or_else(|| 600000u64);
                  debug!("host: {:?}, expires: {:?}", host, expires);

                  if let Ok(_account) = datastore.select_account(&body.username).await {
                      return warp::reply::json(&"user already exist".to_string());
                  }

                  let account = {
                      let handle = thread::spawn(move || body.hash());
                      while !handle.is_finished() {
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
        warp::path!("verify")
          .and(warp::get())
          .and(warp::query::<VerifyQuery>())
          .then(move |query: VerifyQuery| {
              let private_key = private_key.to_owned();
              let datastore = datastore.to_owned();
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
                                      if err.to_string() == "Expired" { return "Expired".to_string(); }
                                      (None, "Invalid".to_string())
                                  }
                              }
                          },
                          Err(err) => {
                              info!("{:?}", err);
                              if err.to_string() == "Expired" { return "Expired".to_string(); }
                              (None, "Invalid".to_string())
                          }
                      }
                  };

                  match user {
                      Some(user) => {
                          if let Ok(_account) = datastore.select_account(&user.username).await {
                              return "user already exist".to_string();
                          }
                          datastore.insert_account(&user.username, &user.password).await.unwrap();
                          response
                      },
                      None => "Invalid".to_string()
                  }
              }
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
