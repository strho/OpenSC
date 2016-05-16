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