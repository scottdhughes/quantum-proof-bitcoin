#!/bin/sh
# Dedicated public-test launcher; the offline app keeps its own state and port.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/public_app.py" "$@"
