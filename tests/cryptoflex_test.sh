#! /bin/sh

. ./common_functions.sh

if ! is_card_connected; then
    exit 77
fi

ALLOWED_ATRS=("3b:95:18:40:ff:62:04:01:01:05")

if ! is_card_allowed "${ALLOWED_ATRS[@]}"; then
    echo "Card is not supported"
    exit 77
fi;

echo "Current directory: $(pwd)"
echo "Testing PKCS#11 implementation on PKCS#15 cards"

if ! test -x ${OPENSC_PATH}; then
    echo "OpenSC PKCS#11 library is not on path '$OPENSC_PATH'"
    exit 77
fi

./test_card.sh -m  ${OPENSC_PATH} -t PKCS15 -s 00000000 -r ${PKCS15_INIT_PATH} -p ${PKCS11_TOOL_PATH}