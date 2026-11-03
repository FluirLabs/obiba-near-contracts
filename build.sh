#!/bin/sh
set -eu
cd "$(dirname "$0")"
RUSTC_VERSION=1.96.0
WASM_OPT_VERSION=133
rustc --version | grep -q "^rustc $RUSTC_VERSION " || { echo "build.sh: need rustc $RUSTC_VERSION for reproducible hashes, found $(rustc --version)" >&2; exit 1; }
wasm-opt --version | grep -q "version $WASM_OPT_VERSION\b" || { echo "build.sh: need wasm-opt $WASM_OPT_VERSION for reproducible hashes, found $(wasm-opt --version)" >&2; exit 1; }
for crate in "${@:-obiba-account obiba-pay}"; do
  for c in $crate; do
    name=$(echo "$c" | tr - _)
    cargo build --release --locked --target wasm32v1-none -p "$c"
    mkdir -p "target/near/$name"
    wasm-opt -Oz --converge --mvp-features --strip-debug --strip-producers --strip-target-features \
      -o "target/near/$name/$name.wasm" "target/wasm32v1-none/release/$name.wasm"
    printf '%s %s bytes sha256 %s\n' "$name" "$(wc -c < "target/near/$name/$name.wasm" | tr -d ' ')" "$(shasum -a 256 "target/near/$name/$name.wasm" | cut -d' ' -f1)"
  done
done
