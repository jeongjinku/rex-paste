#!/bin/sh
# Builds and runs test/clipboard_test.m against bin/rex-paste (macOS; run `sh build.sh` first).
set -eu
cd "$(dirname "$0")/.."
b=$(brew --prefix)/opt
mkdir -p .zig-cache
xcrun clang -fobjc-arc -Wno-deprecated-declarations test/clipboard_test.m \
  -I"$b/libpng/include" -I"$b/webp/include" \
  "$b/libpng/lib/libpng16.a" "$b/webp/lib/libwebpmux.a" "$b/webp/lib/libwebp.a" "$b/webp/lib/libsharpyuv.a" -lz \
  -framework AppKit -framework Accelerate -framework ImageIO -framework UniformTypeIdentifiers \
  -o .zig-cache/clipboard_test
.zig-cache/clipboard_test "$PWD/bin/rex-paste"
