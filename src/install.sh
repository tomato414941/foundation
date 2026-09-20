#!/bin/sh
# Installs the Foundation runtime CLI for the server that served this script.
set -eu
ORIGIN='__ORIGIN__'
DIR="${FOUNDATION_CLI_DIR:-$HOME/.local/share/foundation}"
BIN="${FOUNDATION_BIN_DIR:-$HOME/.local/bin}"
command -v node >/dev/null 2>&1 || { echo 'Node.js 24 or later is required.' >&2; exit 1; }
MAJOR=$(node -p 'process.versions.node.split(".")[0]')
[ "$MAJOR" -ge 24 ] || { echo "Node.js 24 or later is required (found $(node -v))." >&2; exit 1; }
mkdir -p "$DIR" "$BIN"
for f in __FILES__; do
  curl -fsSL "$ORIGIN/cli/$f" -o "$DIR/$f.tmp"
  mv "$DIR/$f.tmp" "$DIR/$f"
done
{
  echo '#!/bin/sh'
  echo "export FOUNDATION_URL=\"\${FOUNDATION_URL:-$ORIGIN}\""
  echo "exec node \"$DIR/runtime.mjs\" \"\$@\""
} > "$BIN/foundation"
chmod +x "$BIN/foundation"
echo "Installed $BIN/foundation for $ORIGIN"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Add $BIN to PATH, or call $BIN/foundation directly." ;; esac
echo "Next: foundation --help"
