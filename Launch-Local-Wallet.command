#!/bin/sh
# Double-click in Finder to start Docker and resume the local test wallet.
set -eu
cd -- "$(dirname -- "$0")"
exec ./contrib/ml-dsa-console/launch.command "$@"
