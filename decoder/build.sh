#!/bin/sh
# Build the native receiver helper. No interpreter is needed by the result.
set -eu
cd "$(dirname "$0")/.."
output=$1
shift
cxx=${CXX:-c++}
if [ "$(uname)" = Darwin ]; then
    openssl_prefix=${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}
    "$cxx" -std=c++11 -O2 -Wall -Wextra -Werror "$@" -I"$openssl_prefix/include" \
        decoder/NativeDecoder.cpp decoder/worker.cpp -L"$openssl_prefix/lib" -lcrypto -o "$output"
else
    "$cxx" -std=c++11 -O2 -Wall -Wextra -Werror "$@" \
        decoder/NativeDecoder.cpp decoder/worker.cpp -lcrypto -o "$output"
fi
