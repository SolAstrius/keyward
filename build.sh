#!/bin/sh
# Build the daemon, the app, and assemble Keyward.app into ./dist.
set -e
root="$(cd "$(dirname "$0")" && pwd)"
dist="$root/dist"
app="$dist/Keyward.app"

echo "==> daemon (rust)"
cargo build --release --manifest-path "$root/daemon/Cargo.toml"

echo "==> app (swift)"
(cd "$root/app" && swift build -c release)

echo "==> assembling $app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$root/app/.build/release/KeywardApp" "$app/Contents/MacOS/Keyward"

# The daemon ships *inside* the bundle. That makes the app the whole product:
# one thing to move, one path for launchd to exec, and no dependency on a
# checkout that could be cleaned or relocated out from under SSH.
#
# Replace by rename, never in place. Overwriting a running binary's file keeps
# the inode, so the kernel finds pages that no longer match the cached
# signature and kills it with CODESIGNING/"Invalid Page" — taking every later
# exec of that path with it.
cp "$root/daemon/target/release/keywardd" "$app/Contents/MacOS/.keywardd.new"
mv -f "$app/Contents/MacOS/.keywardd.new" "$app/Contents/MacOS/keywardd"

# A convenience handle for the CLI (--health, --pubkey), same binary.
ln -sfn "$app/Contents/MacOS/keywardd" "$dist/keywardd"

cp "$root/assets/AppIcon.icns" "$app/Contents/Resources/AppIcon.icns"

cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Keyward</string>
  <key>CFBundleDisplayName</key><string>Keyward</string>
  <key>CFBundleIdentifier</key><string>dev.danielsol.keyward</string>
  <key>CFBundleExecutable</key><string>Keyward</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
PLIST

# Sign the nested binary first, then the bundle that contains it.
codesign --force --sign - --timestamp=none "$app/Contents/MacOS/keywardd" >/dev/null 2>&1
codesign --force --sign - --timestamp=none "$app" >/dev/null 2>&1 || \
  echo "    (codesign failed; app still runs, notifications may not)"

echo "==> done"
echo "    app:    $app  (daemon embedded)"
echo "    run ./install.sh to place it in /Applications and register its agents"
