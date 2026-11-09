#!/usr/bin/env bash
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
export LC_ALL=C
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export OPENSSL_CONF=/dev/null OPENSSL_MODULES=/nonexistent PYTHONDONTWRITEBYTECODE=1
case "$COMPILER" in
  gcc) cc=gcc; cxx=g++ ;;
  clang) cc=clang; cxx=clang++ ;;
  *) echo 'Unsupported build compiler' >&2; exit 1 ;;
esac
source_dir=/tmp/mldsa-demo-source
build_dir=/tmp/mldsa-demo-build
evidence=/opt/pqbtc-runtime/evidence
mkdir -p "$evidence"
step_log="$evidence/openssl-build.log"
report_build_failure() {
  local exit_code=$?
  echo "Source build failed; last step log: $step_log" >&2
  if test -f "$step_log"; then
    tail -n 80 "$step_log" >&2
  fi
  exit "$exit_code"
}
trap report_build_failure ERR
test "$(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse HEAD)" = "$EXPECTED_HEAD"
test "$(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse 'HEAD^{tree}')" = "$EXPECTED_TREE"
test -z "$(git -c safe.directory="$source_dir" -C "$source_dir" status --porcelain)"
chown 1000:1000 /tmp/pqbtc-openssl-3.6.5.tar.gz
echo "Building checksum-pinned OpenSSL 3.6.5 with $cc"
runuser -u signer -- env CC="$cc" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  bash "$source_dir/contrib/ml-dsa-wallet-backup/build_openssl.sh" \
  /tmp/pqbtc-openssl-3.6.5.tar.gz /tmp/mldsa-openssl > "$evidence/openssl-build.log" 2>&1
step_log="$evidence/native-integration.json"
echo "Testing native transaction/ML-DSA integration with $cc"
runuser -u signer -- env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory \
  GIT_CONFIG_VALUE_0="$source_dir" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  python3 "$source_dir/contrib/ml-dsa-integration/run_native_tests.py" \
  --cc "$cc" --cxx "$cxx" --expect-head "$EXPECTED_HEAD" > "$evidence/native-integration.json"
step_log="$evidence/signer.json"
echo "Building and testing the isolated signer with $cc"
runuser -u signer -- env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory \
  GIT_CONFIG_VALUE_0="$source_dir" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  python3 "$source_dir/contrib/ml-dsa-signer/run_signer_tests.py" \
  --cc "$cc" --cxx "$cxx" --expect-head "$EXPECTED_HEAD" \
  --openssl-prefix /tmp/mldsa-openssl --build-dir /tmp/demo-signer-bin > "$evidence/signer.json"
mkdir "$build_dir"
chown 1001:1000 "$build_dir"
step_log="$evidence/node-configure.log"
echo "Configuring the experimental node with $cc"
runuser -u node -- env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory \
  GIT_CONFIG_VALUE_0="$source_dir" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  cmake -S "$source_dir" -B "$build_dir" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
  -DENABLE_EXPERIMENTAL_MLDSA44=ON -DENABLE_WALLET=OFF -DBUILD_GUI=OFF \
  -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DWITH_USDT=OFF -DBUILD_TESTS=ON \
  -DWITH_CCACHE=OFF -DBUILD_BENCH=OFF > "$evidence/node-configure.log" 2>&1
step_log="$evidence/node-build.log"
echo "Compiling daemon, CLI, public ML-DSA client and node tests with $cc"
runuser -u node -- env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory \
  GIT_CONFIG_VALUE_0="$source_dir" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  cmake --build "$build_dir" --parallel 2 --target pqbtcd pqbtc-cli test_pqbtc pqbtc-mldsa-client \
  > "$evidence/node-build.log" 2>&1
step_log="$evidence/node-unit.log"
echo "Running actual-node ML-DSA unit tests"
runuser -u node -- "$build_dir/bin/test_pqbtc" --run_test=mldsa44_node_tests --report_level=short \
  > "$evidence/node-unit.log" 2>&1
step_log="$evidence/node-functional.log"
echo "Running two real nodes with malformed-witness and activation controls"
runuser -u node -- python3 "$source_dir/test/functional/feature_mldsa44_demo.py" \
  --binary "$build_dir/bin/pqbtcd" --validation-only --timeout-factor 4 \
  > "$evidence/node-functional.log" 2>&1
grep -qx MLDSA_DEMO_VALIDATION_TERMINAL_EXIT_0 "$evidence/node-functional.log"
test -z "$(git -c safe.directory="$source_dir" -C "$source_dir" status --porcelain)"
mkdir -p /opt/pqbtc-runtime/seed/mldsa-demo-build /opt/pqbtc-runtime/seed/demo-signer-bin
cp -a "$source_dir" /opt/pqbtc-runtime/seed/mldsa-demo-source
cp -a "$build_dir/bin" /opt/pqbtc-runtime/seed/mldsa-demo-build/bin
cp -a /tmp/demo-signer-bin/pilot-signer /opt/pqbtc-runtime/seed/demo-signer-bin/pilot-signer
echo "Recording source, binary, compiler and dependency identities"
python3 - <<'PY'
import hashlib,json,os,pathlib,platform,subprocess
base=pathlib.Path('/opt/pqbtc-runtime')
paths=[
 '/tmp/mldsa-demo-build/bin/pqbtcd','/tmp/mldsa-demo-build/bin/pqbtc-cli',
 '/tmp/mldsa-demo-build/bin/pqbtc-mldsa-client','/tmp/mldsa-demo-build/bin/test_pqbtc',
 '/tmp/demo-signer-bin/pilot-signer',
 '/tmp/mldsa-demo-source/docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md',
 '/tmp/mldsa-demo-source/contrib/ml-dsa-signer/node_wallet.py']
native=json.loads((base/'evidence/native-integration.json').read_text())
signer=json.loads((base/'evidence/signer.json').read_text())
if native.get('result')!='PASS' or signer.get('result')!='PASS':
 raise ValueError('Native tests did not report PASS')
compiler=os.environ['COMPILER']
toolchain={name:subprocess.check_output([name,'--version'],text=True).splitlines()[0]
 for name in (compiler,'g++' if compiler=='gcc' else 'clang++','cmake','ninja','git')}
manifest={'schema':'PQBTC-MLDSA44-SOURCE-BUILD-1','source_head':os.environ['EXPECTED_HEAD'],
 'source_tree':os.environ['EXPECTED_TREE'],'compiler':compiler,'architecture':platform.machine(),
 'sha256':{p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths},
 'toolchain':toolchain,'base_image':'debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc',
 'source_date_epoch':int(os.environ['SOURCE_DATE_EPOCH']),
 'openssl_source_sha256':'a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98',
 'checks':{'native_integration':'PASS','signer':'PASS','mldsa44_node_tests':'PASS','node_functional_validation':'PASS'},
 'evidence_sha256':{str(p.relative_to(base/'evidence')):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in sorted((base/'evidence').iterdir()) if p.is_file()},
 'packages':subprocess.check_output(['dpkg-query','-W','-f=${Package}\t${Version}\n'],text=True).splitlines(),
 'reproducibility_scope':'exact source/dependency/toolchain and binary receipts; bit-for-bit cross-build equality not asserted'}
(base/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n')
os.chmod(base/'manifest.json',0o644)
PY
echo "Removing generated build/test state from the runtime image's temporary filesystem"
python3 - <<'PY'
from pathlib import Path
import shutil
import stat

# This executes only in the disposable Linux build image, after its immutable
# seed/evidence have been published under /opt. Do not copy test records or
# build leftovers into a new user's Docker data volume through volume copy-up.
base = Path('/opt/pqbtc-runtime')
if not (base / 'manifest.json').is_file() or not (base / 'seed').is_dir():
    raise ValueError('Immutable runtime seed must exist before build cleanup')
temporary = Path('/tmp')
for entry in temporary.iterdir():
    mode = entry.lstat().st_mode
    if stat.S_ISDIR(mode):
        shutil.rmtree(entry)
    else:
        entry.unlink()
if any(temporary.iterdir()):
    raise ValueError('Runtime image temporary filesystem is not empty')
PY
