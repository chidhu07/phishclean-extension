#!/usr/bin/env bash
# Build PhishClean extension packages for Chrome, Firefox, and Edge
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
EXT="$ROOT/extension"
DIST="$ROOT/dist"

# Read version from Chrome manifest
VERSION=$(grep -o '"version": "[^"]*"' "$EXT/manifest.json" | head -1 | cut -d'"' -f4)
echo "Building PhishClean v${VERSION}"
echo "================================"

# Clean dist
rm -rf "$DIST"
mkdir -p "$DIST/chrome" "$DIST/firefox" "$DIST/edge"

# Files to include in every build (relative to extension/)
FILES=(
  background.js
  contentScript.js
  linkTooltip.js
  riskEngine.js
  secretScanner.js
  networkHook.js
  lib/publicSuffix.js
  popup/popup.html
  popup/popup.js
  popup/popup.css
  popup/pdfReport.js
  options/options.html
  options/options.js
  options/options.css
  icons/icon16.png
  icons/icon48.png
  icons/icon128.png
  icons/logo.svg
  lib/jspdf.umd.min.js
  lib/logoData.js
)

copy_files() {
  local dest="$1"
  for f in "${FILES[@]}"; do
    mkdir -p "$dest/$(dirname "$f")"
    cp "$EXT/$f" "$dest/$f"
  done
}

validate_package() {
  local dest="$1"
  local manifest="$dest/manifest.json"

  py -c "
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
missing = []

for script in manifest.get('background', {}).values():
    if isinstance(script, str) and not (root / script).exists():
        missing.append(script)

for entry in manifest.get('content_scripts', []):
    for script in entry.get('js', []):
        if not (root / script).exists():
            missing.append(script)

for group in manifest.get('web_accessible_resources', []):
    for resource in group.get('resources', []):
        if not (root / resource).exists():
            missing.append(resource)

if missing:
    raise SystemExit('Missing packaged files: ' + ', '.join(sorted(set(missing))))
" "$dest"
}

# Create zip with forward-slash paths (required by Firefox/AMO)
make_zip() {
  local src_dir="$1"
  local zip_path="$2"

  if command -v zip &>/dev/null; then
    (cd "$src_dir" && zip -rq "$zip_path" .)
  else
    # Python ensures forward slashes on Windows (PowerShell uses backslashes which AMO rejects)
    local abs_src abs_zip
    abs_src=$(cd "$src_dir" && pwd)
    abs_zip=$(cd "$(dirname "$zip_path")" && pwd)/$(basename "$zip_path")
    py -c "
import zipfile, os, sys
src = sys.argv[1].replace('\\\\', '/')
out = sys.argv[2].replace('\\\\', '/')
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(src):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, src).replace('\\\\', '/')
            zf.write(full, arc)
" "$abs_src" "$abs_zip"
  fi
}

# ── Chrome ──
echo ""
echo ">> Chrome"
copy_files "$DIST/chrome"
cp "$EXT/manifest.json" "$DIST/chrome/manifest.json"
validate_package "$DIST/chrome"
make_zip "$DIST/chrome" "$DIST/phishclean-chrome-v${VERSION}.zip"
echo "   Created dist/phishclean-chrome-v${VERSION}.zip"

# ── Firefox ──
echo ""
echo ">> Firefox"
copy_files "$DIST/firefox"
cp "$EXT/manifest.firefox.json" "$DIST/firefox/manifest.json"
validate_package "$DIST/firefox"
make_zip "$DIST/firefox" "$DIST/phishclean-firefox-v${VERSION}.zip"
echo "   Created dist/phishclean-firefox-v${VERSION}.zip"

# ── Edge (identical to Chrome) ──
echo ""
echo ">> Edge"
cp "$DIST/phishclean-chrome-v${VERSION}.zip" "$DIST/phishclean-edge-v${VERSION}.zip"
echo "   Created dist/phishclean-edge-v${VERSION}.zip (same as Chrome)"

# ── Summary ──
echo ""
echo "================================"
echo "Packages:"
echo ""
for f in "$DIST"/phishclean-*.zip; do
  SIZE=$(wc -c < "$f" | tr -d ' ')
  NAME=$(basename "$f")
  echo "  $NAME  (${SIZE} bytes)"
  if command -v sha256sum &>/dev/null; then
    HASH=$(sha256sum "$f" | cut -d' ' -f1)
    echo "    SHA256: $HASH"
  fi
done

echo ""
echo "Done. Upload these to the respective stores:"
echo "  Chrome:  https://chrome.google.com/webstore/devconsole"
echo "  Firefox: https://addons.mozilla.org/developers/"
echo "  Edge:    https://partner.microsoft.com/dashboard/microsoftedge"
