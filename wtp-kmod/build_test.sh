#!/bin/bash
# Build wtp_test for ARM/IPQ6018
QSDK="${QSDK:-/workdir3/qsdk}"
TC="$QSDK/staging_dir/toolchain-arm"
SYSROOT="$QSDK/staging_dir/target-arm"
CC="$TC/bin/arm-openwrt-linux-muslgnueabi-gcc"
export STAGING_DIR="$QSDK/staging_dir"

$CC -O2 -Wall \
    --sysroot="$SYSROOT" \
    -I. \
    -I"$SYSROOT/usr/include" \
    -I"$SYSROOT/usr/include/libnl3" \
    wtp_test.c \
    -L"$SYSROOT/usr/lib" \
    -lnl-3 -lnl-genl-3 \
    -o wtp_test
echo "built: wtp_test"
file wtp_test
