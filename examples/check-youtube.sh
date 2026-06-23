#!/usr/bin/env bash
# Check uBO's YouTube rules against adblock-rust and print a markdown report.
#
# Run from anywhere inside the repo:
#   examples/check-youtube.sh                  # markdown report to stdout
#   examples/check-youtube.sh > youtube.md     # save it
#   examples/check-youtube.sh --json           # override output format
set -euo pipefail

UBO="https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt"
DOMAINS="youtube.com,youtu.be,youtube-nocookie.com,ytimg.com,googlevideo.com,ggpht.com,www.youtube.com,m.youtube.com,music.youtube.com,gaming.youtube.com,tv.youtube.com,studio.youtube.com,kids.youtube.com,www.youtube-nocookie.com,i.ytimg.com,s.ytimg.com,yt3.ggpht.com"

echo ">> Building & running (first run compiles dependencies; can take a few minutes)..." >&2
cargo run --release --locked -- \
  --url "$UBO" \
  --domains "$DOMAINS" \
  --markdown "$@"
