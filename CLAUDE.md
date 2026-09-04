# ctflib の開発規約

## docstring の Example

`ctflib.__all__` に載る名前の docstring には、`Example:` 見出しを置き、その中身を doctest 形式で書きます。例は読み物ではなく、テストとして実行されます。

- 免除は3種類です。定数とインスタンス、本体側に例がある別名、`ctflib._meta.no_example` を付けたものです。`ServerRequest` のように本体が `ctflib.__all__` の外にある再エクスポートは、本体側の docstring に例を書きます。
- `ELLIPSIS` と `NORMALIZE_WHITESPACE` を有効にしています。`...` は長い repr を畳むためのもので、期待値を書く手間を省く用途では使いません。
- `# doctest: +SKIP` は `reverse_shell` だけに許可します。HTTP を伴う例は `tests/test_docstrings.py` が注入する `URL` に向け、`listen` と `wait_hit` は `background=True` と短いタイムアウトで実行できる形にします。
- `__all__` 外の公開メソッドに例を書くことは推奨しますが、必須ではありません。

## 検査の範囲

`ctflib.__all__` の全エントリが検査対象です。モジュールを追加した場合も、そこから公開する名前は同じ規約に従います。

## テストの実行

```
python3 -m unittest tests.test_docstrings
```
