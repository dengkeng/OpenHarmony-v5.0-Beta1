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

#include "mac_openssl.h"

#include "openssl_adapter.h"
#include "sym_common_defines.h"
#include "openssl_common.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "config.h"
#include "utils.h"

typedef struct {
    HcfMacSpi base;

    HMAC_CTX *ctx;

    char opensslAlgoName[HCF_MAX_ALGO_NAME_LEN];
} HcfMacSpiImpl;

static const char *OpensslGetMacClass(void)
{
    return "OpensslMac";
}

static HMAC_CTX *OpensslGetMacCtx(HcfMacSpi *self)
{
    if (!IsClassMatch((HcfObjectBase *)self, OpensslGetMacClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfMacSpiImpl *)self)->ctx;
}

static const EVP_MD *OpensslGetMacAlgoFromString(const char *mdName)
{
    if (strcmp(mdName, "SHA1") == 0) {
        return OpensslEvpSha1();
    } else if (strcmp(mdName, "SHA224") == 0) {
        return OpensslEvpSha224();
    } else if (strcmp(mdName, "SHA256") == 0) {
        return OpensslEvpSha256();
    } else if (strcmp(mdName, "SHA384") == 0) {
        return OpensslEvpSha384();
    } else if (strcmp(mdName, "SHA512") == 0) {
        return OpensslEvpSha512();
    } else if (strcmp(mdName, "SM3") == 0) {
        return OpensslEvpSm3();
    } else if (strcmp(mdName, "MD5") == 0) {
        return OpensslEvpMd5();
    }
    return NULL;
}

static HcfResult OpensslEngineInitMac(HcfMacSpi *self, const HcfSymKey *key)
{
    if (OpensslGetMacCtx(self) == NULL) {
        LOGD("[error] The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (!IsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OpensslGetMacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfBlob keyBlob = ((SymKeyImpl *)key)->keyMaterial;
    if (!IsBlobValid(&keyBlob)) {
        LOGE("Invalid keyMaterial");
        return HCF_INVALID_PARAMS;
    }
    const EVP_MD *mdfunc = OpensslGetMacAlgoFromString(((HcfMacSpiImpl *)self)->opensslAlgoName);
    int32_t ret = OpensslHmacInitEx(OpensslGetMacCtx(self), keyBlob.data, keyBlob.len, mdfunc, NULL);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] HMAC_Init_ex return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineUpdateMac(HcfMacSpi *self, HcfBlob *input)
{
    if (OpensslGetMacCtx(self) == NULL) {
        LOGD("[error] The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (HMAC_Update(OpensslGetMacCtx(self), input->data, input->len) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] HMAC_Update return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineDoFinalMac(HcfMacSpi *self, HcfBlob *output)
{
    if (OpensslGetMacCtx(self) == NULL) {
        LOGD("[error] The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    unsigned char outputBuf[EVP_MAX_MD_SIZE];
    uint32_t outputLen;
    int32_t ret = OpensslHmacFinal(OpensslGetMacCtx(self), outputBuf, &outputLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] HMAC_Final return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = (uint8_t *)HcfMalloc(outputLen, 0);
    if (output->data == NULL) {
        LOGE("Failed to allocate output->data memory!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(output->data, outputLen, outputBuf, outputLen);
    output->len = outputLen;
    return HCF_SUCCESS;
}

static uint32_t OpensslEngineGetMacLength(HcfMacSpi *self)
{
    if (OpensslGetMacCtx(self) == NULL) {
        LOGD("[error] The CTX is NULL!");
        return HCF_OPENSSL_INVALID_MAC_LEN;
    }
    return OpensslHmacSize(OpensslGetMacCtx(self));
}

static void OpensslDestroyMac(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL");
        return;
    }
    if (!IsClassMatch(self, OpensslGetMacClass())) {
        LOGE("Class is not match.");
        return;
    }
    if (OpensslGetMacCtx((HcfMacSpi *)self) != NULL) {
        OpensslHmacCtxFree(OpensslGetMacCtx((HcfMacSpi *)self));
    }
    HcfFree(self);
}

HcfResult OpensslMacSpiCreate(const char *opensslAlgoName, HcfMacSpi **spiObj)
{
    if (spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfMacSpiImpl *returnSpiImpl = (HcfMacSpiImpl *)HcfMalloc(sizeof(HcfMacSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnSpiImpl->opensslAlgoName, HCF_MAX_ALGO_NAME_LEN, opensslAlgoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnSpiImpl);
        return HCF_INVALID_PARAMS;
    }
    returnSpiImpl->ctx = OpensslHmacCtxNew();
    if (returnSpiImpl->ctx == NULL) {
        LOGD("[error] Failed to create ctx!");
        HcfFree(returnSpiImpl);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSpiImpl->base.base.getClass = OpensslGetMacClass;
    returnSpiImpl->base.base.destroy = OpensslDestroyMac;
    returnSpiImpl->base.engineInitMac = OpensslEngineInitMac;
    returnSpiImpl->base.engineUpdateMac = OpensslEngineUpdateMac;
    returnSpiImpl->base.engineDoFinalMac = OpensslEngineDoFinalMac;
    returnSpiImpl->base.engineGetMacLength = OpensslEngineGetMacLength;
    *spiObj = (HcfMacSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}