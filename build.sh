#!/bin/sh
# Builds the helper binary from source.
#   sh build.sh [macos-aarch64|linux-aarch64|linux-x86_64] [output]
# Defaults to this machine and bin/rex-paste. Needs Zig 0.17.0 ($ZIG), and on macOS
# Xcode command line tools plus Homebrew libpng and webp, which are linked statically.
set -eu
cd "$(dirname "$0")"
: "${ZIG:=zig}"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
[ "$os" = darwin ] && os=macos
arch=$(uname -m)
[ "$arch" = arm64 ] && arch=aarch64
target=${1:-$os-$arch}
out=${2:-bin/rex-paste}
[ "$("$ZIG" version)" = 0.17.0 ] || { echo 'build.sh: Zig 0.17.0 required' >&2; exit 1; }
mkdir -p "$(dirname "$out")" .zig-cache
case $target in
linux-aarch64 | linux-x86_64)
  "$ZIG" build-exe src/main.zig -O ReleaseFast -target "${target#linux-}-linux-musl" \
    -lc -static -fstrip -femit-bin="$out"
  ;;
macos-aarch64)
  # Zig compiles main.zig; the Apple linker handles the current SDK's TBD format.
  "$ZIG" build-obj src/main.zig -O ReleaseFast -target aarch64-macos.26.0 -lc -fcompiler-rt \
    -femit-bin=.zig-cache/rex-paste.o
  brew=${HOMEBREW_PREFIX:-/opt/homebrew}/opt
  xcrun clang -O3 -fobjc-arc -mmacosx-version-min=26.0 .zig-cache/rex-paste.o src/mac.m src/codec.c \
    -I"$brew/libpng/include" -I"$brew/webp/include" \
    "$brew/libpng/lib/libpng16.a" "$brew/webp/lib/libwebpmux.a" \
    "$brew/webp/lib/libwebp.a" "$brew/webp/lib/libsharpyuv.a" -lz \
    -framework AppKit -framework Accelerate -framework ImageIO -framework CoreGraphics \
    -framework CoreFoundation -framework UniformTypeIdentifiers -Wl,-dead_strip -o "$out"
  ;;
*)
  echo "build.sh: unsupported target $target" >&2
  exit 1
  ;;
esac
