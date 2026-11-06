#!/bin/sh
# Packages the release assets that install.sh downloads:
#   sh .github/package.sh <version> <binary dir> <output dir>
# Each rex-paste-<os>-<arch> binary becomes rex-paste-<os>-<arch>.tar.gz holding the plugin
# directory; install.sh gets the version, and SHA256SUMS covers everything. The tar flags
# keep macOS metadata out when packaging locally.
set -eu
version=$1 bins=$2 out=$3
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/rex-paste/bin"
(cd "$root" && cp init.lua worker.lua notice.lua README.md LICENSE THIRD_PARTY_NOTICES.md "$stage/rex-paste/")
echo "$version" >"$stage/rex-paste/VERSION"
for bin in "$bins"/rex-paste-*; do
  cp "$bin" "$stage/rex-paste/bin/rex-paste"
  chmod 755 "$stage/rex-paste/bin/rex-paste"
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "$out/$(basename "$bin").tar.gz" -C "$stage" rex-paste
done
sed "s/^release=.*/release=$version/" "$root/install.sh" >"$out/install.sh"
if command -v sha256sum >/dev/null; then sum=sha256sum; else sum="shasum -a 256"; fi
(cd "$out" && $sum rex-paste-*.tar.gz install.sh >SHA256SUMS)
