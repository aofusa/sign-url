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

http://localhost:3030 と https://localhost:3031 で起動する  


APIエントリポイント
- GET /health-check
- POST /create
- GET /verify

テスト
-----
```sh
curl -X POST -H 'Content-type: application/json' -d '{"username":"user","password":"user"}' https://localhost:3031/create?expires=10000 -k
curl https://localhost:3031/verify?payload=~~~ -k
```

