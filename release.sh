#!/bin/sh
# Build and package a release DMG.
#
# Ad-hoc signed, because Gatekeeper only trusts a Developer ID certificate plus
# notarisation and both need the paid Apple Developer Program. Anyone opening
# this on another Mac has to clear the quarantine attribute first; building from
# source avoids that entirely and needs the same Xcode toolchain either way.
set -e
root="$(cd "$(dirname "$0")" && pwd)"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/daemon/Cargo.toml" | head -1)"
arch="$(uname -m)"
stage="$root/dist/.dmg"
dmg="$root/dist/Keyward-$version-$arch.dmg"

"$root/build.sh"

echo "==> packaging $dmg"
rm -rf "$stage" "$dmg"
mkdir -p "$stage"
cp -R "$root/dist/Keyward.app" "$stage/Keyward.app"
ln -s /Applications "$stage/Applications"   # conventional drag-to-install layout

hdiutil create -quiet -volname "Keyward $version" -srcfolder "$stage" \
  -ov -format UDZO -imagekey zlib-level=9 "$dmg"
rm -rf "$stage"

echo "==> done"
shasum -a 256 "$dmg"
