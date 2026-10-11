#!/bin/sh
# Build NCP2 against zstd 1.5.7 (https://github.com/facebook/zstd/releases/tag/v1.5.7).
set -eu
ZSTD=${ZSTD:-./zstd-1.5.7}
make -C "$ZSTD/lib" -j4 libzstd
g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -I"$ZSTD/lib" ncp.cpp -L"$ZSTD/lib" -Wl,-rpath,"$ZSTD/lib" \
  -lzstd -lcrypto -pthread -o ncp
./ncp --version
