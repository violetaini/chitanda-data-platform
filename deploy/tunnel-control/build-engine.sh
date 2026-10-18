#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
core="$root/tmp/chitanda-tunnel-core"
mkdir -p "$root/tmp"
if [[ ! -d "$core/.git" ]]; then
  git clone https://github.com/chitanda-project/chitanda.git "$core"
fi
git -C "$core" checkout 2926cf2c41c85d2177536a4ba2d9931f1ec675f9
for patch in "$root"/patches/*.patch; do
  if ! git -C "$core" apply --reverse --check "$patch" 2>/dev/null; then
    git -C "$core" apply --check "$patch"
    git -C "$core" apply "$patch"
  fi
done
mkdir -p "$core/cmd/chitanda-transit"
cp "$root"/deploy/tunnel-control/engine/*.go "$core/cmd/chitanda-transit/"
cd "$core"
GOOS="${GOOS:-linux}" GOARCH="${GOARCH:-amd64}" CGO_ENABLED=0 \
  go build -mod=mod -trimpath -ldflags='-s -w' -o "$root/tmp/chitanda-transit" ./cmd/chitanda-transit
