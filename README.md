Sign URL
=====

以下のAPIを持つ署名付きURLを生成するAPIサーバの実装
- POST /create
- GET /verify
- GET /health-check
- POST /login
- POST /logout
- GET /protected

実行環境構築
```sh
cargo run
```

テスト
```sh
curl -X POST -H 'Content-type: application/json' -d '{"username":"user","password":"user"}' https://localhost:3031/create -k

curl -X POST -H 'Content-Type: application/json' -d '{"username":"user","password":"user"}' localhost:8080/login -v
curl -H 'Cookie: ~~~' localhost:8080/protected -v
```

