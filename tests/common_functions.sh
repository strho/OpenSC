#! /bin/sh

OPENSC_PATH="$(pwd)/../src/pkcs11/.libs/opensc-pkcs11.so"
PKCS15_INIT_PATH="$(pwd)/../src/tools/pkcs15-init"
PKCS11_TOOL_PATH="$(pwd)/../src/tools/pkcs11-tool"
OPENSC_TOOL_PATH="$(pwd)/../src/tools/opensc-tool"


is_card_connected() {

    if ! $(${PKCS11_TOOL_PATH} -IL > /dev/null 2>&1);
    then
        echo "Card is not connected"
        return 1
    fi;

    return 0

}

is_card_allowed() {

    local CARD_ATR=$(${OPENSC_TOOL_PATH} -a 2> /dev/null)
    local ALLOWED_ATRS=("$@")

    for atr in "${ALLOWED_ATRS[@]}";
    do
        if test "$atr" == "$CARD_ATR"; then
            return 0
        fi
    done;

    return 1
}
