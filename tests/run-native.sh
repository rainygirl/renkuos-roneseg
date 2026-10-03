#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d /tmp/roneseg-native-tests.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cxx=${CXX:-c++}
if [ "$(uname)" = Darwin ]; then
    openssl_prefix=${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}
    "$cxx" -std=c++11 -O1 -g -Wall -Wextra -Werror "$@" \
        -Idecoder -I"$openssl_prefix/include" decoder/NativeDecoder.cpp tests/native_decoder_test.cpp \
        -L"$openssl_prefix/lib" -lcrypto -o "$work/test"
else
    "$cxx" -std=c++11 -O2 -Wall -Wextra -Werror "$@" \
        -Idecoder decoder/NativeDecoder.cpp tests/native_decoder_test.cpp -lcrypto -o "$work/test"
fi
"$work/test" tests/fixtures
