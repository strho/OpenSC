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


#include "loader.h"

int get_slot_with_card(token_info_t * info);

int load_pkcs11_module(token_info_t * info, const char* path_to_pkcs11_library) {

    if(strlen(path_to_pkcs11_library) == 0) {
        fprintf(stderr, "You have to specify path to PKCS#11 library.");
        return 1;
    }

    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR) = 0;
    pkcs11_so = dlopen(path_to_pkcs11_library, RTLD_NOW);

    if (!pkcs11_so) {
        fprintf(stderr, "Error loading pkcs#11 so: %s\n", dlerror());
        return 1;
    }

    C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(pkcs11_so, "C_GetFunctionList");

    if (!C_GetFunctionList) {
        fprintf(stderr, "Could not get function list: %s\n", dlerror());
        return 1;
    }

    CK_RV rv = C_GetFunctionList(&info->function_pointer);
    if (CKR_OK != rv) {
        fprintf(stderr, "C_GetFunctionList call failed: 0x%.8lX", rv);
        return 1;
    }

    rv = info->function_pointer->C_Initialize(NULL_PTR);

    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize: Error = 0x%.8X\n", rv);
        return 1;
    }

    if(get_slot_with_card(info)) {
        fprintf(stderr, "There is no card present in reader.\n");
        info->function_pointer->C_Finalize(NULL_PTR);
        return 1;
    }

    info->function_pointer->C_Finalize(NULL_PTR);
    return 0;
}

int get_slot_with_card(token_info_t * info)
{
    CK_SLOT_ID_PTR slot_list;
    CK_SLOT_ID slot_id;
    CK_ULONG slot_count = 0;
    CK_RV rv;
    int error = 0;

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    /* Get slot list for memory allocation */
    rv = function_pointer->C_GetSlotList(0, NULL_PTR, &slot_count);

    if ((rv == CKR_OK) && (slot_count > 0)) {
        slot_list = malloc(slot_count * sizeof (CK_SLOT_ID));

        if (slot_list == NULL) {
            fprintf(stderr, "System error: unable to allocate memory\n");
            return 1;
        }

        /* Get the slot list for processing */
        rv = function_pointer->C_GetSlotList(0, slot_list, &slot_count);
        if (rv != CKR_OK) {
            fprintf(stderr, "GetSlotList failed: unable to get slot count.\n");
            error = 1;
            goto cleanup;
        }
    } else {
        fprintf(stderr, "GetSlotList failed: unable to get slot list.\n");
        return 1;
    }

    /* Find a slot capable of specified mechanism */
    for (size_t i = 0; i < slot_count; i++) {
        CK_SLOT_INFO slot_info;
        slot_id = slot_list[i];

        rv = function_pointer->C_GetSlotInfo(slot_id, &slot_info);

        if(rv == CKR_OK && (slot_info.flags & CKF_TOKEN_PRESENT)){
            info->slot_id = slot_id;
            break;
        }
    }

    cleanup:
    if (slot_list) {
        free(slot_list);
    }

    return error;
}

void close_pkcs11_module() {
    if(pkcs11_so)
        dlclose(pkcs11_so);
}

void get_supported_mechanisms(supported_mechanisms_t *supported, CK_MECHANISM_INFO mechanism_info, CK_MECHANISM_TYPE mechanism_type) {

    if (mechanism_info.flags & CKF_GENERATE_KEY_PAIR) {
        SET_GENERATE_KEY_PAIR(supported->flags);
    }

    if (mechanism_info.flags & CKF_VERIFY) {
        SET_VERIFY(supported->flags);
    }

    if (mechanism_info.flags & CKF_SIGN) {
        SET_SIGN(supported->flags);
    }

    if (mechanism_info.flags & CKF_ENCRYPT) {
        SET_ENCRYPT(supported->flags);
    }

    if (mechanism_info.flags & CKF_DECRYPT) {
        SET_DECRYPT(supported->flags);
    }

    if (mechanism_info.flags & CKF_DIGEST && mechanism_type == CKM_SHA_1) {
        SET_DIGEST_SHA1(supported->flags);
    }

    if (mechanism_info.flags & CKF_DIGEST && mechanism_type == CKM_MD5) {
        SET_DIGEST_MD5(supported->flags);
    }

    if (mechanism_info.flags & CKF_GENERATE) {
        SET_GENERATE(supported->flags);
    }

    if(mechanism_type == CKM_EC_KEY_PAIR_GEN) {
        SET_EC_SUPPORT(supported->flags);
    }


}