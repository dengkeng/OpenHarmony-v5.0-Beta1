/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCF_KEY_H
#define HCF_KEY_H

#include "blob.h"
#include "result.h"
#include "object_base.h"

typedef enum {
    DSA_P_BN = 101,
    DSA_Q_BN = 102,
    DSA_G_BN = 103,
    DSA_SK_BN = 104,
    DSA_PK_BN = 105,

    ECC_FP_P_BN = 201,
    ECC_A_BN = 202,
    ECC_B_BN = 203,
    ECC_G_X_BN = 204,
    ECC_G_Y_BN = 205,
    ECC_N_BN = 206,
    ECC_H_INT = 207,  // warning: ECC_H_NUM in JS
    ECC_SK_BN = 208,
    ECC_PK_X_BN = 209,
    ECC_PK_Y_BN = 210,
    ECC_FIELD_TYPE_STR = 211,
    ECC_FIELD_SIZE_INT = 212,  // warning: ECC_FIELD_SIZE_NUM in JS
    ECC_CURVE_NAME_STR = 213,

    RSA_N_BN = 301,
    RSA_SK_BN = 302,
    RSA_PK_BN = 303,

    DH_P_BN = 401,
    DH_G_BN = 402,
    DH_L_NUM = 403,
    DH_SK_BN = 404,
    DH_PK_BN = 405,

    ED25519_SK_BN = 501,
    ED25519_PK_BN = 502,
    X25519_SK_BN = 601,
    X25519_PK_BN = 602,
} AsyKeySpecItem;

typedef struct HcfKey HcfKey;

struct HcfKey {
    HcfObjectBase base;

    const char *(*getAlgorithm)(HcfKey *self);

    HcfResult (*getEncoded)(HcfKey *self, HcfBlob *returnBlob);

    HcfResult (*getEncodedPem)(HcfKey *self, const char *format, char **returnString);

    const char *(*getFormat)(HcfKey *self);
};

#endif
