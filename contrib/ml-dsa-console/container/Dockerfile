# The multi-architecture base is pinned; toolchain/package versions are retained
# in the build manifest rather than represented as bit-for-bit reproducibility.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential clang-16 libclang-rt-16-dev cmake ninja-build pkgconf python3 git binutils perl \
    ca-certificates curl libevent-dev libboost-dev util-linux passwd \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/bin/clang-16 /usr/local/bin/clang \
    && ln -s /usr/bin/clang++-16 /usr/local/bin/clang++ \
    && groupadd --gid 1000 pqbtc \
    && useradd --uid 1000 --gid 1000 --no-create-home signer \
    && useradd --uid 1001 --gid 1000 --no-create-home node

ARG COMPILER=gcc
ARG EXPECTED_HEAD
ARG EXPECTED_TREE
ARG SOURCE_DATE_EPOCH
ENV PYTHONDONTWRITEBYTECODE=1 LC_ALL=C.UTF-8 LANG=C.UTF-8
COPY source/ /tmp/mldsa-demo-source/
COPY build_native.sh /opt/pqbtc-build/build_native.sh
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      https://github.com/openssl/openssl/releases/download/openssl-3.6.5/openssl-3.6.5.tar.gz \
      -o /tmp/pqbtc-openssl-3.6.5.tar.gz \
    && echo 'a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98  /tmp/pqbtc-openssl-3.6.5.tar.gz' | sha256sum --check
RUN --network=none bash /opt/pqbtc-build/build_native.sh
LABEL org.pqbtc.console.build="source-1"
CMD ["sleep", "infinity"]
