#!/usr/bin/env bash
# Rebuild from a freshly extracted Mozilla source archive.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$root"
# shellcheck disable=SC1091
source ./wallet-build-env.sh
arch=$(uname -m)
case "$arch" in
    aarch64) node_arch=arm64; protoc_arch=aarch_64 ;;
    x86_64) node_arch=x64; protoc_arch=x86_64 ;;
    *) echo "Expected a Linux ARM64 or x86_64 reviewer environment" >&2; exit 1 ;;
esac

work="$root/.review-build"
mkdir -m 700 "$work"
cd "$work"
download() {
    local url=$1 filename=$2
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 \
        --output "$filename" "$url"
    awk -v name="$filename" '$2 == name {print; found++} END {exit (found != 1)}' \
        "$root/review-tools.sha256" | sha256sum --strict --check -
}

node_archive="node-v${REVIEW_NODE}-linux-${node_arch}.tar.xz"
download "https://nodejs.org/dist/v${REVIEW_NODE}/${node_archive}" "$node_archive"
mkdir node
tar -xJf "$node_archive" --strip-components=1 -C node
node_bin="$work/node/bin"

protoc_archive="protoc-${REVIEW_PROTOC}-linux-${protoc_arch}.zip"
download "https://github.com/protocolbuffers/protobuf/releases/download/v${REVIEW_PROTOC}/${protoc_archive}" "$protoc_archive"
unzip -q "$protoc_archive" -d protoc
test -r protoc/include/google/protobuf/descriptor.proto

export CARGO_HOME="$work/cargo" RUSTUP_HOME="$work/rustup"
rustup_version=1.29.3
rustup_binary="rustup-init-${rustup_version}-${arch}"
download "https://static.rust-lang.org/rustup/archive/${rustup_version}/${arch}-unknown-linux-gnu/rustup-init" "$rustup_binary"
mv "$rustup_binary" rustup-init
chmod u+x rustup-init
./rustup-init -y --no-modify-path --profile minimal --default-toolchain 1.100.0

export PATH="$work/protoc/bin:$node_bin:$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR="$work/target" CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export NX_DAEMON=false NX_PARALLEL=2
python3 "$root/rebuild.py" restore
ln -s "$root/epix-wallet/.yarn/releases/yarn-${REVIEW_YARN}.cjs" "$node_bin/yarn"
test "$(protoc --version)" = "libprotoc $REVIEW_PROTOC"
test "$(node --version)" = "v$REVIEW_NODE"
test "$(yarn --version)" = "$REVIEW_YARN"
printf 'Building with Node %s, npm %s, Yarn %s, %s and %s\n' \
    "$(node --version)" "$(npm --version)" "$(yarn --version)" "$(protoc --version)" "$(rustc --version)"

cd "$root/epix-wallet"
yarn install --immutable
yarn build:libs
yarn workspace @keplr-wallet/extension build
export EPIX_WALLET_DIST="$PWD/apps/extension/build/firefox"
python3 "$root/rebuild.py" verify-wallet "$EPIX_WALLET_DIST"

cd "$root/EpixNet"
cargo build --locked -p epix-browser --no-default-features
"$CARGO_TARGET_DIR/debug/epix-browser" --export-wallet "$work/runtime.xpi"
python3 "$root/rebuild.py" verify-final "$work/runtime.xpi" --output "$root/rebuilt.xpi"
