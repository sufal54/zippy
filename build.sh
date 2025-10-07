#!/bin/bash
set -e

targets=(
  x86_64-unknown-linux-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-gnu
)

for target in "${targets[@]}"; do
    rustup target add "$target"
    cargo build --release --target "$target"
done
