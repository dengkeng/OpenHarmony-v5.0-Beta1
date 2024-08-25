/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "sm4_openssl.h"
#include "securec.h"
#include "blob.h"
#include "log.h"
#include "memory.h"
#include "result.h"
#include "utils.h"
#include "aes_openssl_common.h"
#include "sym_common_defines.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "openssl_class.h"

#define MAX_AAD_LEN 2048
#define SM4_BLOCK_SIZE 16
#define SM4_SIZE_128 16

typedef struct {
    HcfCipherGeneratorSpi base;
    CipherAttr attr;
    CipherData *cipherData;
} HcfCipherSm4GeneratorSpiOpensslImpl;

static const char *GetSm4GeneratorClass(void)
{
    return OPENSSL_SM4_CIPHER_CLASS;
}

static const EVP_CIPHER *CipherEcbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Ecb();
        default:
            break;
    }
    return NULL;
}

static const EVP_CIPHER *CipherCbcType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Cbc();
        default:
            break;
    }
    return NULL;
}

static const EVP_CIPHER *CipherCtrType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Ctr();
        default:
            break;
    }
    return NULL;
}

static const EVP_CIPHER *CipherOfbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Ofb();
        default:
            break;
    }
    return NULL;
}

static const EVP_CIPHER *CipherCfbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Cfb();
        default:
            break;
    }
    return NULL;
}

static const EVP_CIPHER *CipherCfb128Type(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case SM4_SIZE_128:
            return OpensslEvpSm4Cfb128();
        default:
            break;
    }
    return NULL;
}

static const EVP_CIPHER *DefaultCipherType(SymKeyImpl *symKey)
{
    return CipherEcbType(symKey);
}

static const EVP_CIPHER *GetCipherType(HcfCipherSm4GeneratorSpiOpensslImpl *impl, SymKeyImpl *symKey)
{
    switch (impl->attr.mode) {
        case HCF_ALG_MODE_ECB:
            return CipherEcbType(symKey);
        case HCF_ALG_MODE_CBC:
            return CipherCbcType(symKey);
        case HCF_ALG_MODE_CTR:
            return CipherCtrType(symKey);
        case HCF_ALG_MODE_OFB:
            return CipherOfbType(symKey);
        case HCF_ALG_MODE_CFB:
            return CipherCfbType(symKey);
        case HCF_ALG_MODE_CFB128:
            return CipherCfb128Type(symKey);
        default:
            break;
    }
    return DefaultCipherType(symKey);
}

static HcfResult InitCipherData(enum HcfCryptoMode opMode, CipherData **cipherData)
{
    HcfResult ret = HCF_ERR_MALLOC;
    if (cipherData == NULL) {
        LOGE("invalid cipher data");
        return HCF_INVALID_PARAMS;
    }

    CipherData *data = (CipherData *)HcfMalloc(sizeof(CipherData), 0);
    if (data == NULL) {
        LOGE("malloc failed.");
        return HCF_ERR_MALLOC;
    }

    data->enc = opMode;
    data->ctx = OpensslEvpCipherCtxNew();
    if (data->ctx != NULL) {
        *cipherData = data;
        ret = HCF_SUCCESS;
    } else {
        HcfPrintOpensslError();
        HcfFree(data);
        LOGD("[error] Failed to allocate ctx memroy.");
    }
    return ret;
}

static HcfResult GetPaddingMode(HcfCipherSm4GeneratorSpiOpensslImpl* cipherImpl)
{
    switch (cipherImpl->attr.paddingMode) {
        case HCF_ALG_NOPADDING:
            break;
        case HCF_ALG_PADDING_PKCS5:
            return EVP_PADDING_PKCS7;
        case HCF_ALG_PADDING_PKCS7:
            return EVP_PADDING_PKCS7;
        default:
            LOGE("No Params!");
            break;
    }
    return HCF_SUCCESS;
}

static HcfResult CheckParam(HcfCipherGeneratorSpi* self, enum HcfCryptoMode opMode, HcfKey* key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS)) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (opMode != ENCRYPT_MODE && opMode != DECRYPT_MODE) {
        LOGE("Invalid opMode %d", opMode);
        return HCF_INVALID_PARAMS;
    }
    SymKeyImpl* keyImpl = (SymKeyImpl*)key;
    if (keyImpl->keyMaterial.len < SM4_SIZE_128) {
        LOGE("Init failed, the input key size is smaller than keySize specified in cipher.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    if (cipherImpl->attr.paddingMode != HCF_ALG_NOPADDING && cipherImpl->attr.paddingMode != HCF_ALG_PADDING_PKCS5
        && cipherImpl->attr.paddingMode != HCF_ALG_PADDING_PKCS7) {
        LOGE("Invalid padding mode %u", cipherImpl->attr.paddingMode);
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi* self, enum HcfCryptoMode opMode,
    HcfKey* key, HcfParamsSpec* params)
{
    if (CheckParam(self, opMode, key) != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    CipherData* data = NULL;
    if (InitCipherData(opMode, &data) != HCF_SUCCESS) {
        LOGE("InitCipherData failed");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    int32_t enc = (opMode == ENCRYPT_MODE) ? 1 : 0;
    SymKeyImpl* keyImpl = (SymKeyImpl*)key;
    if (OpensslEvpCipherInit(data->ctx, GetCipherType(cipherImpl, keyImpl), keyImpl->keyMaterial.data,
        GetIv(params), enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error] Cipher init key and iv failed.");
        FreeCipherData(&data);
        return ret;
    }
    if (OpensslEvpCipherCtxSetPadding(data->ctx, GetPaddingMode(cipherImpl)) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error] Set padding failed.");
        FreeCipherData(&data);
        return ret;
    }
    cipherImpl->cipherData = data;
    return HCF_SUCCESS;
}

static HcfResult AllocateOutput(HcfBlob* input, HcfBlob* output)
{
    uint32_t outLen = SM4_BLOCK_SIZE;
    if (IsBlobValid(input)) {
        outLen += input->len;
    }
    output->data = (uint8_t*)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("Malloc output failed.");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult EngineUpdate(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (input == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfCipherSm4GeneratorSpiOpensslImpl *cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    CipherData *data = cipherImpl->cipherData;
    if (data == NULL) {
        LOGE("cipherData is null!");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    if (AllocateOutput(input, output) == HCF_SUCCESS) {
        if (OpensslEvpCipherUpdate(data->ctx, output->data, (int*)&output->len,
            input->data, input->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGD("[error] Cipher update failed.");
        } else {
            ret = HCF_SUCCESS;
        }
    }
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(output);
        FreeCipherData(&(cipherImpl->cipherData));
    } else {
        FreeRedundantOutput(output);
    }
    return ret;
}

static HcfResult SM4DoFinal(CipherData* data, HcfBlob* input, HcfBlob* output)
{
    int32_t ret;
    uint32_t len = 0;

    if (IsBlobValid(input)) {
        ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int*)&output->len,
            input->data, input->len);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGD("[error] Cipher update failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        len += output->len;
    }
    ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int*)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error] Cipher final filed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += len;
    return HCF_SUCCESS;
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi* self, HcfBlob* input, HcfBlob* output)
{
    if ((self == NULL) || (output == NULL)) { /* input maybe is null */
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase*)self, self->base.getClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl* cipherImpl = (HcfCipherSm4GeneratorSpiOpensslImpl*)self;
    if (cipherImpl->cipherData == NULL) {
        LOGE("CipherData is null.");
        return HCF_INVALID_PARAMS;
    }

    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    if (AllocateOutput(input, output) == HCF_SUCCESS) {
        ret = SM4DoFinal(cipherImpl->cipherData, input, output);
        if (ret != HCF_SUCCESS) {
            LOGD("[error] DesDoFinal failed.");
        }
    }
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(output);
    } else {
        FreeRedundantOutput(output);
    }
    FreeCipherData(&(cipherImpl->cipherData));
    return ret;
}

static void EngineSm4GeneratorDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, self->getClass())) {
        LOGE("Class is not match.");
        return;
    }

    HcfCipherSm4GeneratorSpiOpensslImpl *impl = (HcfCipherSm4GeneratorSpiOpensslImpl *)self;
    FreeCipherData(&(impl->cipherData));
    HcfFree(impl);
}

static HcfResult GetSm4CipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetSm4CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    return HCF_NOT_SUPPORT;
}

static HcfResult SetSm4CipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

HcfResult HcfCipherSm4GeneratorSpiCreate(CipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if (attr == NULL || generator == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherSm4GeneratorSpiOpensslImpl *returnImpl = (HcfCipherSm4GeneratorSpiOpensslImpl *)HcfMalloc(
        sizeof(HcfCipherSm4GeneratorSpiOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), attr, sizeof(CipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetSm4CipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetSm4CipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetSm4CipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineSm4GeneratorDestroy;
    returnImpl->base.base.getClass = GetSm4GeneratorClass;

    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
