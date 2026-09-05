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

# Replace the daemon by rename, never in place. Overwriting a running binary's
# file keeps the inode, so the kernel finds pages that no longer match the
# cached signature and kills it with CODESIGNING/"Invalid Page" — taking every
# later exec of that path with it. Write beside it, sign, then swap.
cp "$root/daemon/target/release/keywardd" "$dist/.keywardd.new"
codesign --force --sign - "$dist/.keywardd.new" >/dev/null 2>&1 || \
  echo "    (codesign failed for keywardd)"
mv -f "$dist/.keywardd.new" "$dist/keywardd"

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

# Ad-hoc signature: enough for a stable bundle identity and notifications.
codesign --force --sign - --timestamp=none "$app" >/dev/null 2>&1 || \
  echo "    (codesign failed; app still runs, notifications may not)"

echo "==> done"
echo "    app:    $app"
echo "    daemon: $dist/keywardd"
