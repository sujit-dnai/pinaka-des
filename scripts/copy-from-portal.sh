#!/bin/sh
# Copy the app from the skd-portal repo into this store project, then sync both platforms.
#   sh scripts/copy-from-portal.sh ../skd-portal
set -e
PORTAL="${1:-../skd-portal}"
sed -e 's#href="/pinaka/manifest.webmanifest"#href="manifest.json"#' \
    -e 's#href="/pinaka/icon-192.png"#href="icon-192.png"#g' \
    "$PORTAL/pinaka.html" > www/index.html
cp "$PORTAL/pinaka-eagle.png" www/eagle.png
cp "$PORTAL/pinaka-icon-192.png" www/icon-192.png
npx cap sync
echo "Copied and synced. Now raise the version and build."
