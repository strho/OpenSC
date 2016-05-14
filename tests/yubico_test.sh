#! /bin/sh

. ./common_functions.sh

if ! is_card_connected; then
    exit 77
fi

ALLOWED_ATRS=("3b:fa:13:00:00:81:31:fe:15:59:75:62:69:6B:65:79:4e:45:4f:a6")

if ! is_card_allowed "${ALLOWED_ATRS[@]}"; then
    echo "Card is not supported"
    exit 77
fi;


echo "Current directory: $(pwd)"
echo "Testing PKCS#11 implementation on Yubico"

if ! test -x ${OPENSC_PATH}; then
    echo "OpenSC PKCS#11 library is not on path '$OPENSC_PATH'"
    exit 77
fi

./test_card.sh -m  ${OPENSC_PATH} -t PIV