/* Copyright (C) 2016 Martin Strhársky <strharsky.martin@gmail.com>,
 *
 * This test suite is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef SMARTCARDTESTSUIT_COMMON_H
#define SMARTCARDTESTSUIT_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "libs/pkcs11.h"

#ifdef NDEBUG
    #define debug_print(fmt, ...) \
                do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#else
    #define debug_print(fmt, ...)
#endif

#define RANDOM_DATA_SIZE    64
#define BUFFER_SIZE       4096
#define MAX_DIGEST          64
#define MD5_HASH_LENGTH     16
#define SHA1_HASH_LENGTH    20

#define SHORT_MESSAGE_TO_HASH "This is test message for digest.\n"
#define LONG_MESSAGE_TO_HASH_PATH "./resources/message_to_hash.txt"

#define SHORT_MESSAGE_TO_SIGN "Simple message for signing & verifying.\n"
#define SHORT_MESSAGE_SIGNATURE_PATH "./resources/message_to_sign.signature"

#define DECRYPTED_MESSAGE "Simple message for encrypton & decryption.\n"
#define ENCRYPTED_MESSAGE_PATH "./resources/message_to_decrypt.dec"

#define CERTIFICATE_SUBJECT_HEX "306E310B300906035504061302435A3117301506035504080C0E437A6563682052657075626C6963310D300B06035504070C0442726E6F311C301A060355040A0C1344656661756C7420436F6D70616E79204C74643119301706035504030C104D617274696E20537472686172736B79"
#define CERTIFICATE_SERIAL_NUMBER "020900FA0A2360CCA513F9"

#define SEED_DATA "e2be987ee3123a84899fabe8382f5f53da6aac4a9bfe5378424e1705e32abcb2f97fea6178dff10283f7393c8e22a90339c63f792370eac6a2cb1026ec7e8a51"
#define EMPTY_ARRAY "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

#define PRIVATE_KEY_DER_PATH "./resources/private_key.key"
#define PRIVATE_KEY_PROPERTIES "--id a1 --label \"My Private Key\" --usage-sign --usage-decrypt"


#define PUBLIC_KEY_DER_PATH "./resources/public_key.key"
#define PUBLIC_KEY_PROPERTIES "--id a1 --label \"My Public Key\" --usage-sign --usage-decrypt"

#define CERTIFICATE_DER_PATH "./resources/cert.der"

typedef enum {
    PKCS15,
    PIV,
} card_type;

typedef struct {
    card_type type;
    CK_UTF8CHAR* pin;
    CK_UTF8CHAR* so_pin;
    CK_UTF8CHAR* change_pin;

    CK_BYTE id[1];

    size_t pin_length;
    size_t id_length;
    size_t so_pin_length;

    char* pkcs11_tool_path;
    char* pkcs15_tool_path;
} card_info_t;
card_info_t card_info;

typedef struct {
    CK_FLAGS flags;
} supported_mechanisms_t;

typedef struct {
    CK_FUNCTION_LIST_PTR function_pointer;
    CK_SLOT_ID slot_id;
    CK_SESSION_HANDLE session_handle;
    supported_mechanisms_t supported;

} token_info_t;

void display_usage();
int set_card_info();
void clear_card_info();
int path_exists(const char* name);

#endif //SMARTCARDTESTSUIT_COMMON_H
