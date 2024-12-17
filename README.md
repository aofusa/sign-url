Sign URL
=====


署名付きURLを生成するAPIサーバの実装

アカウント作成すると一時アカウントを発行する
一時アカウントはRSAによって暗号化され、署名付きURLに埋め込まれる
署名付きURLにアクセスすることで一時アカウントの正当性検証を行うサンプル


実行環境構築
-----
```sh
RUST_LOG=debug cargo run
```

http://localhost:3030 と https://localhost:3031 で起動

上記にアクセスすることで検証用htmlが返ってくる


APIエントリポイント
- GET /
- GET /health-check
- POST /create
- GET /verify
- POST /login
- POST /logout
- GET /protected

テスト
-----

```sh
# 仮アカウントの発行
curl -X POST -H 'Content-type: application/json' -d '{"username":"user","password":"user"}' localhost:3030/create?expires=60000
# 以下のようなレスポンスが返ってくるのでアクセスするとアカウントが発行される
# {"sign_url": "http://localhost:3030/verify?payload=~~~"}
curl localhost:3030/verify?payload=~~~

# ログイン
curl -X POST -H 'Content-Type: application/json' -d '{"username":"user","password":"user"}' localhost:3030/login -v
# ログイン時に取得したcookieを渡してアクセスする
# ログイン状態であれば authorized と表示、そうでなければ unauthorized と表示
curl -H 'Cookie: ~~~' localhost:8080/protected -v
```

docker build
```sh
tar -ch $(ls -A) | docker build -t dev.local/signurl:latest -
docker run --rm -it --publish 3030:3030 --publish 3031:3031 dev.local/signurl:latest
```

