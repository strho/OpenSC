#! /bin/sh

# Copyright (C) 2016 Martin Strhársky <strharsky.martin@gmail.com>,
#
# This test suite is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
#
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


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
