/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "rand_openssl.h"

#include "openssl_adapter.h"
#include "openssl_common.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

typedef struct {
    HcfRandSpi base;
} HcfRandSpiImpl;

static const char *GetRandOpenSSLClass(void)
{
    return "RandOpenssl";
}

static HcfResult OpensslGenerateRandom(HcfRandSpi *self, int32_t numBytes, HcfBlob *random)
{
    if ((self == NULL) || (random == NULL)) {
        LOGE("Invalid params!");
        return HCF_INVALID_PARAMS;
    }
    if (numBytes <= 0) {
        LOGE("Invalid numBytes!");
        return HCF_INVALID_PARAMS;
    }
    random->data = (uint8_t *)HcfMalloc(numBytes, 0);
    if (random->data == NULL) {
        LOGE("Failed to allocate random->data memory!");
        return HCF_ERR_MALLOC;
    }
    int32_t ret = OpensslRandPrivBytes(random->data, numBytes);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] RAND_bytes return error!");
        HcfFree(random->data);
        random->data = NULL;
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    random->len = numBytes;
    return HCF_SUCCESS;
}

static const char *GetRandAlgoName(HcfRandSpi *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetRandOpenSSLClass())) {
        LOGE("Class is not match.");
        return NULL;
    }

    return OPENSSL_RAND_ALGORITHM;
}

static void OpensslSetSeed(HcfRandSpi *self, HcfBlob *seed)
{
    OpensslRandSeed(seed->data, seed->len);
}

static void DestroyRandOpenssl(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL!");
        return;
    }
    if (!IsClassMatch(self, GetRandOpenSSLClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfFree(self);
}

HcfResult HcfRandSpiCreate(HcfRandSpi **spiObj)
{
    if (spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfRandSpiImpl *returnSpiImpl = (HcfRandSpiImpl *)HcfMalloc(sizeof(HcfRandSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->base.base.getClass = GetRandOpenSSLClass;
    returnSpiImpl->base.base.destroy = DestroyRandOpenssl;
    returnSpiImpl->base.engineGenerateRandom = OpensslGenerateRandom;
    returnSpiImpl->base.engineSetSeed = OpensslSetSeed;
    returnSpiImpl->base.engineGetAlgoName = GetRandAlgoName;
    *spiObj = (HcfRandSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}