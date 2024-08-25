/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "md_openssl.h"

#include "openssl_adapter.h"
#include "openssl_common.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "config.h"
#include "utils.h"

typedef struct {
    HcfMdSpi base;

    EVP_MD_CTX *ctx;

    char opensslAlgoName[HCF_MAX_ALGO_NAME_LEN];
} OpensslMdSpiImpl;

static const char *OpensslGetMdClass(void)
{
    return "OpensslMd";
}

static EVP_MD_CTX *OpensslGetMdCtx(HcfMdSpi *self)
{
    if (!IsClassMatch((HcfObjectBase *)self, OpensslGetMdClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((OpensslMdSpiImpl *)self)->ctx;
}

static const EVP_MD *OpensslGetMdAlgoFromString(const char *mdName)
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
    } else if (strcmp(mdName, "MD5") == 0) {
        return OpensslEvpMd5();
    } else if (strcmp(mdName, "SM3") == 0) {
        return OpensslEvpSm3();
    }
    return NULL;
}

static HcfResult OpensslEngineUpdateMd(HcfMdSpi *self, HcfBlob *input)
{
    if (OpensslGetMdCtx(self) == NULL) {
        LOGD("[error] The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (EVP_DigestUpdate(OpensslGetMdCtx(self), input->data, input->len) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] EVP_DigestUpdate return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineDoFinalMd(HcfMdSpi *self, HcfBlob *output)
{
    EVP_MD_CTX *localCtx = OpensslGetMdCtx(self);
    if (localCtx == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    unsigned char outputBuf[EVP_MAX_MD_SIZE];
    uint32_t outputLen;
    int32_t ret = OpensslEvpDigestFinalEx(localCtx, outputBuf, &outputLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] EVP_DigestFinal_ex return error!");
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

static uint32_t OpensslEngineGetMdLength(HcfMdSpi *self)
{
    if (OpensslGetMdCtx(self) == NULL) {
        LOGD("[error] The CTX is NULL!");
        return HCF_OPENSSL_INVALID_MD_LEN;
    }
    int32_t size = OpensslEvpMdCtxSize(OpensslGetMdCtx(self));
    if (size < 0) {
        LOGD("[error] Get the overflow path length in openssl!");
        return HCF_OPENSSL_INVALID_MD_LEN;
    }
    return size;
}

static void OpensslDestroyMd(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL!");
        return;
    }
    if (!IsClassMatch(self, OpensslGetMdClass())) {
        LOGE("Class is not match.");
        return;
    }
    if (OpensslGetMdCtx((HcfMdSpi *)self) != NULL) {
        OpensslEvpMdCtxFree(OpensslGetMdCtx((HcfMdSpi *)self));
    }
    HcfFree(self);
}

HcfResult OpensslMdSpiCreate(const char *opensslAlgoName, HcfMdSpi **spiObj)
{
    if (spiObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    OpensslMdSpiImpl *returnSpiImpl = (OpensslMdSpiImpl *)HcfMalloc(sizeof(OpensslMdSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->ctx = OpensslEvpMdCtxNew();
    if (returnSpiImpl->ctx == NULL) {
        LOGE("Failed to create ctx!");
        HcfFree(returnSpiImpl);
        return HCF_ERR_MALLOC;
    }
    const EVP_MD *mdfunc = OpensslGetMdAlgoFromString(opensslAlgoName);
    int32_t ret = OpensslEvpDigestInitEx(returnSpiImpl->ctx, mdfunc, NULL);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Failed to init MD!");
        OpensslEvpMdCtxFree(returnSpiImpl->ctx);
        HcfFree(returnSpiImpl);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSpiImpl->base.base.getClass = OpensslGetMdClass;
    returnSpiImpl->base.base.destroy = OpensslDestroyMd;
    returnSpiImpl->base.engineUpdateMd = OpensslEngineUpdateMd;
    returnSpiImpl->base.engineDoFinalMd = OpensslEngineDoFinalMd;
    returnSpiImpl->base.engineGetMdLength = OpensslEngineGetMdLength;
    *spiObj = (HcfMdSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}