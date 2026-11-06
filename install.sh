#!/bin/sh
# Installs or updates rex-paste in ~/.config/rex/rex-paste. Run the same command on the Mac
# and on every Rex server host:
#   curl -fsSL https://github.com/jeongjinku/rex-paste/releases/latest/download/install.sh | sh
# Each release's install.sh installs that release. The download is checked against the
# release's SHA256SUMS. It adds the plugin to ~/.config/rex/init.lua if missing, then reloads
# the Rex config. To run a source checkout instead, use `sh build.sh` in it.
# `sh -s uninstall` (or `sh install.sh uninstall`) removes the plugin and the lines it added.
set -eu
config=$HOME/.config/rex
dest=$config/rex-paste
init=$config/init.lua

reload() {
  rex=$(command -v rex || echo "$HOME/.local/bin/rex")
  if "$rex" --autostart=false config reload >/dev/null 2>&1; then
    echo "Reloaded the Rex config."
  else
    echo "Run 'rex config reload' to $1."
  fi
}

if [ "${1:-}" = uninstall ]; then
  [ ! -e "$dest/.git" ] || { echo "install.sh: $dest is a git checkout; remove it yourself" >&2; exit 1; }
  if [ -f "$init" ]; then
    kept=$(mktemp "$config/.rex-paste-init.XXXXXX")
    trap 'rm -f "$kept"' EXIT
    grep -vxF -e '-- Added by rex-paste install.sh' -e 'require("rex-paste").setup()' \
      -e 'rex.bind("cmd+shift+v", "rex_paste")' "$init" >"$kept" || true
    # Lines the installer didn't write would fail the config load once the plugin is gone.
    if grep 'rex-paste\|rex_paste' "$kept" >&2; then
      echo "install.sh: remove the lines above from $init, then run uninstall again" >&2
      exit 1
    fi
    cat "$kept" >"$init" # keeps the file's mode and any symlink
    echo "Removed rex-paste from $init"
  fi
  rm -rf "$dest"
  echo "Removed $dest. Pasted files stay in ~/.cache/rex-paste until you delete it."
  reload "unload it"
  exit 0
fi

release= # set by .github/package.sh
[ -n "$release" ] || { echo "install.sh: run the install.sh from a release, or 'sh build.sh' in a checkout" >&2; exit 1; }
url=https://github.com/jeongjinku/rex-paste/releases/download/$release
os=$(uname -s | tr '[:upper:]' '[:lower:]')
[ "$os" = darwin ] && os=macos
arch=$(uname -m)
[ "$arch" = arm64 ] && arch=aarch64
asset=rex-paste-$os-$arch.tar.gz
[ ! -e "$dest/.git" ] || { echo "install.sh: $dest is a git checkout; update it with git and 'sh build.sh'" >&2; exit 1; }

mkdir -p "$config"
# Staged next to the destination so the final move is a rename.
tmp=$(mktemp -d "$config/.rex-paste-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
echo "Downloading rex-paste $release for $os-$arch"
curl -fsSL -o "$tmp/$asset" "$url/$asset" || { echo "install.sh: no $asset in release $release" >&2; exit 1; }
curl -fsSL -o "$tmp/SHA256SUMS" "$url/SHA256SUMS"
grep " $asset\$" "$tmp/SHA256SUMS" >"$tmp/expected" || { echo "install.sh: $asset missing from SHA256SUMS" >&2; exit 1; }
if command -v sha256sum >/dev/null; then sum=sha256sum; else sum="shasum -a 256"; fi
(cd "$tmp" && $sum -c expected >/dev/null 2>&1) || { echo "install.sh: checksum mismatch for $asset" >&2; exit 1; }
tar -xzf "$tmp/$asset" -C "$tmp"

previous=$(cat "$dest/VERSION" 2>/dev/null || true)
[ ! -e "$dest" ] || mv "$dest" "$tmp/previous"
mv "$tmp/rex-paste" "$dest"
echo "Installed rex-paste $release in $dest${previous:+ (was $previous)}"

# First install: load the plugin from init.lua, and on the Mac bind its key unless taken.
if ! grep -Eq "require[[:space:](]*[\"']rex-paste[\"']" "$init" 2>/dev/null; then
  [ ! -s "$init" ] || [ -z "$(tail -c 1 "$init")" ] || echo >>"$init"
  printf '%s\n' '-- Added by rex-paste install.sh' 'require("rex-paste").setup()' >>"$init"
  if [ "$os" = macos ]; then
    if grep -q 'cmd+shift+v' "$init"; then
      echo "install.sh: cmd+shift+v is already bound in $init; bind a key to rex_paste yourself" >&2
    else
      echo 'rex.bind("cmd+shift+v", "rex_paste")' >>"$init"
    fi
  fi
  echo "Added rex-paste to $init"
fi
reload "load it"
