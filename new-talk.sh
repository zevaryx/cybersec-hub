#!/bin/sh
# Start a new talk from template/.
# usage: ./new-talk.sh <slug> "<Title>" ["<FOOTER LABEL>"]
#   e.g. ./new-talk.sh how-https-works "How HTTPS Really Works" "HTTPS"
set -eu
cd "$(dirname "$0")"

slug=${1:-}; title=${2:-}; footer=${3:-}
if [ -z "$slug" ] || [ -z "$title" ]; then
  echo "usage: $0 <slug> \"<Title>\" [\"<FOOTER LABEL>\"]" >&2; exit 1
fi
case "$slug" in
  *[!a-z0-9-]*) echo "slug must be lowercase letters, digits and hyphens" >&2; exit 1 ;;
esac
[ -n "$footer" ] || footer=$(printf '%s' "$title" | tr '[:lower:]' '[:upper:]')

dest="docs/talks/$slug"
if [ -e "$dest" ]; then echo "$dest already exists" >&2; exit 1; fi

mkdir -p "$dest"
cp template/index.html template/app.js template/talk.css template/qr-discussions.svg "$dest/"
# escape characters that are special in sed replacements
esc() { printf '%s' "$1" | sed -e 's/[\/&|]/\\&/g'; }
sed -i -e "s|{{SLUG}}|$(esc "$slug")|g" -e "s|{{TITLE}}|$(esc "$title")|g" -e "s|{{FOOTER}}|$(esc "$footer")|g" "$dest/index.html"

echo "Created $dest"
echo "Next:"
echo "  1. Write the slides in $dest/index.html and demos in $dest/app.js"
echo "  2. Add a card for it to its track in docs/index.html (copy a <li class=\"talk\">), in the order to take them"
echo "  3. Add the talk to the list in README.md"
