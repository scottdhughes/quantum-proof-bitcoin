#!/usr/bin/env bash
#
# Copyright (c) 2026-present The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_pq_tranche
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export PACKAGES="python3-zmq libevent-dev libboost-dev libsqlite3-dev"
export NO_DEPENDS=1
export GOAL="install"
export RUN_GATEKEEPER=false
export RUN_PQSIG_FUZZ_SMOKE=false
export BITCOIN_CONFIG="\
 -DBUILD_GUI=OFF -DBUILD_GUI_TESTS=OFF \
 -DENABLE_IPC=OFF -DENABLE_EXTERNAL_SIGNER=OFF \
 -DWITH_ZMQ=OFF -DWITH_USDT=OFF \
"
