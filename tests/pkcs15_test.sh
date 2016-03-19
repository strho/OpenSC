#! /bin/sh

OPENSC_PATH="$(pwd)/../src/pkcs11/.libs/opensc-pkcs11.so"
PKCS15_INIT_PATH="$(pwd)/../src/tools/pkcs15-init"
PKCS11_TOOL_PATH="$(pwd)/../src/tools/pkcs11-tool"



echo "Current directory: $(pwd)"
echo "Testing PKCS#11 implementation on PKCS#15 cards"

if ! test -x ${OPENSC_PATH}; then
    echo "OpenSC PKCS#11 library is not on path '$OPENSC_PATH'"
    exit 77
fi

./test_card.sh -m  ${OPENSC_PATH} -t PKCS15 -s 00000000 -r ${PKCS15_INIT_PATH} -p ${PKCS11_TOOL_PATH}