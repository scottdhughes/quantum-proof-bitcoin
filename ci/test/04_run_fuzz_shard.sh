#!/usr/bin/env bash
#
# Copyright (c) 2026-present The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

set -ex

export HOST=${HOST:-$("${BASE_ROOT_DIR}/depends/config.guess")}
export DIR_FUZZ_IN=${DIR_QA_ASSETS}/fuzz_corpora/

if [ ! -x "${BASE_BUILD_DIR}/bin/fuzz" ]; then
  echo "Missing fuzz binary at ${BASE_BUILD_DIR}/bin/fuzz"
  exit 1
fi

if [ ! -d "${DIR_FUZZ_IN}" ]; then
  ${CI_RETRY_EXE} git clone --depth=1 https://github.com/bitcoin-core/qa-assets "${DIR_QA_ASSETS}"
fi
(
  cd "${DIR_QA_ASSETS}"
  echo "Using qa-assets repo from commit ..."
  git log -1
)

LD_LIBRARY_PATH="${DEPENDS_DIR}/${HOST}/lib" \
python3 "${BASE_ROOT_DIR}/ci/test/fuzz_shard.py" run \
  --fuzz-bin "${BASE_BUILD_DIR}/bin/fuzz" \
  --source-dir "${BASE_ROOT_DIR}" \
  --corpus-dir "${DIR_FUZZ_IN}" \
  --shard-index "${FUZZ_SHARD_INDEX}" \
  --shard-count "${FUZZ_SHARD_COUNT}" \
  --par "$(nproc)" \
  --empty-min-time 60 \
  --loglevel DEBUG
