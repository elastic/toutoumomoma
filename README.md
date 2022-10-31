# `toutoumomoma` [![go.dev reference](https://pkg.go.dev/badge/github.com/elastic/toutoumomoma)](https://pkg.go.dev/github.com/elastic/toutoumomoma)

`toutoumomoma` provides functions that may help you to answer the question of an executable, “[是偷偷摸摸吗？](https://translate.google.com.au/?sl=zh-CN&tl=en&text=%E6%98%AF%E5%81%B7%E5%81%B7%E6%91%B8%E6%91%B8%E5%90%97%EF%BC%9F&op=translate)”

- `Stripped`: scan files that may be executable and report whether they are a Go executable that has had its symbols stripped.
- `ImportHash`: calculate the [imphash](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html) of an executable with dynamic imports.
- `GoSymbolHash`: calculate an imphash analogue for Go executables compiled by the gc-compiler.

    The `GoSymbolHash` algorithm is analogous to the algorithm described for `ImportHash` with the exception that Go's static symbols are used in place of the dynamic import symbols used by `ImportHash`.

    The list of symbols referenced by the executable is obtained and the MD5 hash of the ordered list of symbols, separated by commas, is calculated.
    The fully qualified import path of each symbol is included and while symbols used by `ImportHash` are canonicalised to lowercase, `GoSymbolHash` retains the case of the original symbol. `GoSymbolHash` may be calculated including or excluding standard library imports.
- `Sections`: provide section size and entropy statistics for an executable.
