/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "mac.h"

#include <securec.h>

#include "mac_spi.h"
#include "mac_openssl.h"

#include "log.h"
#include "config.h"
#include "memory.h"
#include "utils.h"

typedef HcfResult (*HcfMacSpiCreateFunc)(const char *, HcfMacSpi **);

typedef struct {
    HcfMac base;

    HcfMacSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfMacImpl;

typedef struct {
    char *algoName;

    HcfMacSpiCreateFunc createSpiFunc;
} HcfMacAbility;

static const HcfMacAbility MAC_ABILITY_SET[] = {
    { "SHA1", OpensslMacSpiCreate },
    { "SHA224", OpensslMacSpiCreate },
    { "SHA256", OpensslMacSpiCreate },
    { "SHA384", OpensslMacSpiCreate },
    { "SHA512", OpensslMacSpiCreate },
    { "SM3", OpensslMacSpiCreate },
    { "MD5", OpensslMacSpiCreate },
};

static const char *GetMacClass(void)
{
    return "HMAC";
}

static HcfMacSpiCreateFunc FindAbility(const char *algoName)
{
    for (uint32_t i = 0; i < (sizeof(MAC_ABILITY_SET) / sizeof(MAC_ABILITY_SET[0])); i++) {
        if (strcmp(MAC_ABILITY_SET[i].algoName, algoName) == 0) {
            return MAC_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %s", algoName);
    return NULL;
}

static HcfResult Init(HcfMac *self, const HcfSymKey *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("The input self ptr or key is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMacImpl *)self)->spiObj->engineInitMac(
        ((HcfMacImpl *)self)->spiObj, key);
}

static HcfResult Update(HcfMac *self, HcfBlob *input)
{
    if ((self == NULL) || (!IsBlobValid(input))) {
        LOGE("The input self ptr or dataBlob is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMacImpl *)self)->spiObj->engineUpdateMac(
        ((HcfMacImpl *)self)->spiObj, input);
}

static HcfResult DoFinal(HcfMac *self, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("The input self ptr or dataBlob is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    return ((HcfMacImpl *)self)->spiObj->engineDoFinalMac(
        ((HcfMacImpl *)self)->spiObj, output);
}

static uint32_t GetMacLength(HcfMac *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return 0;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return 0;
    }
    return ((HcfMacImpl *)self)->spiObj->engineGetMacLength(
        ((HcfMacImpl *)self)->spiObj);
}

static const char *GetAlgoName(HcfMac *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfMacImpl *)self)->algoName;
}

static void MacDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetMacClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfMacImpl *impl = (HcfMacImpl *)self;
    HcfObjDestroy(impl->spiObj);
    HcfFree(impl);
}

HcfResult HcfMacCreate(const char *algoName, HcfMac **mac)
{
    if (!IsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN) || (mac == NULL)) {
        LOGE("Invalid input params while creating mac!");
        return HCF_INVALID_PARAMS;
    }
    HcfMacSpiCreateFunc createSpiFunc = FindAbility(algoName);
    if (createSpiFunc == NULL) {
        LOGE("Algo name is error!");
        return HCF_INVALID_PARAMS;
    }
    HcfMacImpl *returnMacApi = (HcfMacImpl *)HcfMalloc(sizeof(HcfMacImpl), 0);
    if (returnMacApi == NULL) {
        LOGE("Failed to allocate Mac Obj memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnMacApi->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnMacApi);
        return HCF_INVALID_PARAMS;
    }
    HcfMacSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(algoName, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnMacApi);
        return res;
    }
    returnMacApi->base.base.getClass = GetMacClass;
    returnMacApi->base.base.destroy = MacDestroy;
    returnMacApi->base.init = Init;
    returnMacApi->base.update = Update;
    returnMacApi->base.doFinal = DoFinal;
    returnMacApi->base.getMacLength = GetMacLength;
    returnMacApi->base.getAlgoName = GetAlgoName;
    returnMacApi->spiObj = spiObj;
    *mac = (HcfMac *)returnMacApi;
    return HCF_SUCCESS;
}