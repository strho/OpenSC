#! /bin/sh

OPENSC_PATH="$(pwd)/../src/pkcs11/.libs/opensc-pkcs11.so"

echo "Current directory: $(pwd)"
echo "Testing PKCS#11 implementation on Yubico"

if ! test -x $OPENSC_PATH; then
    echo "OpenSC PKCS#11 library is not on path '$OPENSC_PATH'"
    exit 77
fi

./test_card.sh -m  $OPENSC_PATH -t PIV