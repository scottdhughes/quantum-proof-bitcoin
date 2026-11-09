#!/bin/sh
# Launch the local browser console from Terminal or Finder.
set -eu
PATH="$PATH:/opt/homebrew/bin:/usr/local/bin"
export PATH
cd -- "$(dirname -- "$0")"
exec python3 ./app.py "$@"
