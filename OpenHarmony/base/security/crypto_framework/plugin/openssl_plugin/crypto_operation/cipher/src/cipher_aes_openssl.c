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

#define CCM_AAD_MAX_LEN 2048
#define GCM_IV_MIN_LEN 1
#define GCM_IV_MAX_LEN 128
#define CCM_IV_MIN_LEN 7
#define CCM_IV_MAX_LEN 13
#define CBC_CTR_OFB_CFB_IV_LEN 16
#define AES_BLOCK_SIZE 16
#define GCM_TAG_SIZE 16
#define CCM_TAG_SIZE 12
#define AES_SIZE_128 16
#define AES_SIZE_192 24
#define AES_SIZE_256 32

typedef struct {
    HcfCipherGeneratorSpi base;
    CipherAttr attr;
    CipherData *cipherData;
} HcfCipherAesGeneratorSpiOpensslImpl;

static const char *GetAesGeneratorClass(void)
{
    return OPENSSL_AES_CIPHER_CLASS;
}

static const EVP_CIPHER *CipherEcbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Ecb();
        case AES_SIZE_192:
            return OpensslEvpAes192Ecb();
        case AES_SIZE_256:
            return OpensslEvpAes256Ecb();
        default:
            break;
    }
    return OpensslEvpAes128Ecb();
}

static const EVP_CIPHER *CipherCbcType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Cbc();
        case AES_SIZE_192:
            return OpensslEvpAes192Cbc();
        case AES_SIZE_256:
            return OpensslEvpAes256Cbc();
        default:
            break;
    }
    return OpensslEvpAes128Cbc();
}

static const EVP_CIPHER *CipherCtrType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Ctr();
        case AES_SIZE_192:
            return OpensslEvpAes192Ctr();
        case AES_SIZE_256:
            return OpensslEvpAes256Ctr();
        default:
            break;
    }
    return OpensslEvpAes128Ctr();
}

static const EVP_CIPHER *CipherOfbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Ofb();
        case AES_SIZE_192:
            return OpensslEvpAes192Ofb();
        case AES_SIZE_256:
            return OpensslEvpAes256Ofb();
        default:
            break;
    }
    return OpensslEvpAes128Ofb();
}

static const EVP_CIPHER *CipherCfbType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Cfb();
        case AES_SIZE_192:
            return OpensslEvpAes192Cfb();
        case AES_SIZE_256:
            return OpensslEvpAes256Cfb();
        default:
            break;
    }
    return OpensslEvpAes128Cfb();
}

static const EVP_CIPHER *CipherCfb1Type(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Cfb1();
        case AES_SIZE_192:
            return OpensslEvpAes192Cfb1();
        case AES_SIZE_256:
            return OpensslEvpAes256Cfb1();
        default:
            break;
    }
    return OpensslEvpAes128Cfb1();
}

static const EVP_CIPHER *CipherCfb128Type(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Cfb128();
        case AES_SIZE_192:
            return OpensslEvpAes192Cfb128();
        case AES_SIZE_256:
            return OpensslEvpAes256Cfb128();
        default:
            break;
    }
    return OpensslEvpAes128Cfb128();
}

static const EVP_CIPHER *CipherCfb8Type(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Cfb8();
        case AES_SIZE_192:
            return OpensslEvpAes192Cfb8();
        case AES_SIZE_256:
            return OpensslEvpAes256Cfb8();
        default:
            break;
    }
    return OpensslEvpAes128Cfb8();
}


static const EVP_CIPHER *CipherCcmType(SymKeyImpl *symKey)
{
    switch (symKey->keyMaterial.len) {
        case AES_SIZE_128:
            return OpensslEvpAes128Ccm();
        case AES_SIZE_192:
            return OpensslEvpAes192Ccm();
        case AES_SIZE_256:
            return OpensslEvpAes256Ccm();
        default:
            break;
    }
    return OpensslEvpAes128Ccm();
}

static const EVP_CIPHER *CipherGcmType(SymKeyImpl *symKey)
{
    if (symKey->keyMaterial.len == AES_SIZE_192) {
        return OpensslEvpAes192Gcm();
    } else if (symKey->keyMaterial.len == AES_SIZE_256) {
        return OpensslEvpAes256Gcm();
    } else {
        return OpensslEvpAes128Gcm();
    }
}

static const EVP_CIPHER *DefaultCiherType(SymKeyImpl *symKey)
{
    return CipherEcbType(symKey);
}

static const EVP_CIPHER *GetCipherType(HcfCipherAesGeneratorSpiOpensslImpl *impl, SymKeyImpl *symKey)
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
        case HCF_ALG_MODE_CFB1:
            return CipherCfb1Type(symKey);
        case HCF_ALG_MODE_CFB8:
            return CipherCfb8Type(symKey);
        case HCF_ALG_MODE_CFB128:
            return CipherCfb128Type(symKey);
        case HCF_ALG_MODE_CCM:
            return CipherCcmType(symKey);
        case HCF_ALG_MODE_GCM:
            return CipherGcmType(symKey);
        default:
            break;
    }
    return DefaultCiherType(symKey);
}

static bool IsGcmParamsValid(HcfGcmParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if ((params->iv.data == NULL) || (params->iv.len < GCM_IV_MIN_LEN) || (params->iv.len > GCM_IV_MAX_LEN)) {
        LOGE("iv is invalid!");
        return false;
    }
    if ((params->tag.data == NULL) || (params->tag.len == 0)) {
        LOGE("tag is invalid!");
        return false;
    }
    return true;
}

static bool IsCcmParamsValid(HcfCcmParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return false;
    }
    if ((params->aad.data == NULL) || (params->aad.len == 0) || (params->aad.len > CCM_AAD_MAX_LEN)) {
        LOGE("aad is invalid!");
        return false;
    }
    if ((params->iv.data == NULL) || (params->iv.len < CCM_IV_MIN_LEN) || (params->iv.len > CCM_IV_MAX_LEN)) {
        LOGE("iv is invalid!");
        return false;
    }
    if ((params->tag.data == NULL) || (params->tag.len == 0)) {
        LOGE("tag is invalid!");
        return false;
    }
    return true;
}

static HcfResult IsIvParamsValid(HcfIvParamsSpec *params)
{
    if (params == NULL) {
        LOGE("params is null!");
        return HCF_INVALID_PARAMS;
    }
    if ((params->iv.data == NULL) || (params->iv.len != CBC_CTR_OFB_CFB_IV_LEN)) {
        LOGE("iv is invalid!");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult InitAadAndTagFromGcmParams(enum HcfCryptoMode opMode, HcfGcmParamsSpec *params, CipherData *data)
{
    if (!IsGcmParamsValid(params)) {
        LOGE("gcm params is invalid!");
        return HCF_INVALID_PARAMS;
    }

    if (params->aad.data != NULL && params->aad.len != 0) {
        data->aad = (uint8_t *)HcfMalloc(params->aad.len, 0);
        if (data->aad == NULL) {
            LOGE("aad malloc failed!");
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(data->aad, params->aad.len, params->aad.data, params->aad.len);
        data->aadLen = params->aad.len;
        data->aead = true;
    } else {
        data->aad = NULL;
        data->aadLen = 0;
        data->aead = false;
    }
    data->tagLen = params->tag.len;
    if (opMode == ENCRYPT_MODE) {
        return HCF_SUCCESS;
    }
    data->tag = (uint8_t *)HcfMalloc(params->tag.len, 0);
    if (data->tag == NULL) {
        HcfFree(data->aad);
        data->aad = NULL;
        LOGE("tag malloc failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(data->tag, params->tag.len, params->tag.data, params->tag.len);
    return HCF_SUCCESS;
}

static HcfResult InitAadAndTagFromCcmParams(enum HcfCryptoMode opMode, HcfCcmParamsSpec *params, CipherData *data)
{
    if (!IsCcmParamsValid(params)) {
        LOGE("gcm params is invalid!");
        return HCF_INVALID_PARAMS;
    }

    data->aad = (uint8_t *)HcfMalloc(params->aad.len, 0);
    if (data->aad == NULL) {
        LOGE("aad malloc failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(data->aad, params->aad.len, params->aad.data, params->aad.len);
    data->aadLen = params->aad.len;
    data->aead = true;

    data->tagLen = params->tag.len;
    if (opMode == ENCRYPT_MODE) {
        return HCF_SUCCESS;
    }
    data->tag = (uint8_t *)HcfMalloc(params->tag.len, 0);
    if (data->tag == NULL) {
        HcfFree(data->aad);
        data->aad = NULL;
        LOGE("tag malloc failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(data->tag, params->tag.len, params->tag.data, params->tag.len);
    return HCF_SUCCESS;
}

static HcfResult InitCipherData(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfParamsSpec *params, CipherData **cipherData)
{
    HcfResult ret = HCF_ERR_MALLOC;
    *cipherData = (CipherData *)HcfMalloc(sizeof(CipherData), 0);
    if (*cipherData == NULL) {
        LOGE("malloc is failed!");
        return ret;
    }
    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    HcfAlgParaValue mode = cipherImpl->attr.mode;

    (*cipherData)->enc = opMode;
    (*cipherData)->ctx = OpensslEvpCipherCtxNew();
    if ((*cipherData)->ctx == NULL) {
        HcfPrintOpensslError();
        LOGD("[error] Failed to allocate ctx memory!");
        goto clearup;
    }

    ret = HCF_SUCCESS;
    switch (mode) {
        case HCF_ALG_MODE_CBC:
        case HCF_ALG_MODE_CTR:
        case HCF_ALG_MODE_OFB:
        case HCF_ALG_MODE_CFB:
        case HCF_ALG_MODE_CFB1:
        case HCF_ALG_MODE_CFB8:
        case HCF_ALG_MODE_CFB128:
            ret = IsIvParamsValid((HcfIvParamsSpec *)params);
            break;
        case HCF_ALG_MODE_CCM:
            ret = InitAadAndTagFromCcmParams(opMode, (HcfCcmParamsSpec *)params, *cipherData);
            break;
        case HCF_ALG_MODE_GCM:
            ret = InitAadAndTagFromGcmParams(opMode, (HcfGcmParamsSpec *)params, *cipherData);
            break;
        default:
            break;
    }
    if (ret != HCF_SUCCESS) {
        LOGE("gcm or ccm or iv init failed!");
        goto clearup;
    }
    return ret;
clearup:
    FreeCipherData(cipherData);
    return ret;
}

static bool SetCipherAttribute(HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl, SymKeyImpl *keyImpl,
    int enc, HcfParamsSpec *params)
{
    CipherData *data = cipherImpl->cipherData;
    HcfAlgParaValue mode = cipherImpl->attr.mode;
    if (mode != HCF_ALG_MODE_GCM) {
        if (OpensslEvpCipherInit(data->ctx, GetCipherType(cipherImpl, keyImpl), keyImpl->keyMaterial.data,
            GetIv(params), enc) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGD("[error] EVP_CipherInit failed!");
            return false;
        }
        return true;
    }
    if (OpensslEvpCipherInit(data->ctx, GetCipherType(cipherImpl, keyImpl),
        NULL, NULL, enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error] EVP_CipherInit failed!");
        return false;
    }
    if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_IVLEN,
        GetIvLen(params), NULL) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]EVP_Cipher set iv len failed!");
        return false;
    }
    if (OpensslEvpCipherInit(data->ctx, NULL, keyImpl->keyMaterial.data,
        GetIv(params), enc) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]EVP_CipherInit failed!");
        return false;
    }
    return true;
}

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    // params spec may be null, do not check
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if ((!IsClassMatch((const HcfObjectBase *)self, GetAesGeneratorClass())) ||
        (!IsClassMatch((const HcfObjectBase *)key, OPENSSL_SYM_KEY_CLASS))) {
        return HCF_INVALID_PARAMS;
    }
    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    SymKeyImpl *keyImpl = (SymKeyImpl *)key;
    int enc = (opMode == ENCRYPT_MODE) ? 1 : 0;
    cipherImpl->attr.keySize = keyImpl->keyMaterial.len;
    if (InitCipherData(self, opMode, params, &(cipherImpl->cipherData)) != HCF_SUCCESS) {
        LOGE("InitCipherData failed!");
        return HCF_INVALID_PARAMS;
    }

    CipherData *data = cipherImpl->cipherData;
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    if (!SetCipherAttribute(cipherImpl, keyImpl, enc, params)) {
        LOGD("[error]Set cipher attribute failed!");
        goto clearup;
    }

    int32_t padding = (cipherImpl->attr.paddingMode == HCF_ALG_NOPADDING) ? 0 : EVP_PADDING_PKCS7;

    if (OpensslEvpCipherCtxSetPadding(data->ctx, padding) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]set padding failed!");
        goto clearup;
    }

    if (opMode == ENCRYPT_MODE || cipherImpl->attr.mode != HCF_ALG_MODE_CCM) {
        return HCF_SUCCESS;
    }
    /* ccm decrypt need set tag */
    if (OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, GetCcmTagLen(params),
        GetCcmTag(params)) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]set AuthTag failed!");
        goto clearup;
    }
    return HCF_SUCCESS;
clearup:
    FreeCipherData(&(cipherImpl->cipherData));
    return ret;
}

static HcfResult CommonUpdate(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    int32_t ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len,
        input->data, input->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult AeadUpdate(CipherData *data, HcfAlgParaValue mode, HcfBlob *input, HcfBlob *output)
{
    if (mode == HCF_ALG_MODE_CCM) {
        if (OpensslEvpCipherUpdate(data->ctx, NULL, (int *)&output->len, NULL, input->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGD("[error]ccm cipher update failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    int32_t ret = OpensslEvpCipherUpdate(data->ctx, NULL, (int *)&output->len, data->aad, data->aadLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]aad cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int *)&output->len, input->data, input->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]gcm cipher update failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult AllocateOutput(HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    if (IsBlobValid(input)) {
        outLen += input->len;
        *isUpdateInput = true;
    }
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
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
    if (!IsClassMatch((const HcfObjectBase *)self, GetAesGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    CipherData *data = cipherImpl->cipherData;
    if (data == NULL) {
        LOGE("cipherData is null!");
        return HCF_INVALID_PARAMS;
    }
    bool isUpdateInput = false;
    HcfResult ret = AllocateOutput(input, output, &isUpdateInput);
    if (ret != HCF_SUCCESS) {
        LOGE("AllocateOutput failed!");
        return ret;
    }

    if (!data->aead) {
        ret = CommonUpdate(data, input, output);
    } else {
        ret = AeadUpdate(data, cipherImpl->attr.mode, input, output);
    }
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(output);
        FreeCipherData(&(cipherImpl->cipherData));
    }
    data->aead = false;
    FreeRedundantOutput(output);
    return ret;
}

static HcfResult CommonDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    int32_t ret;
    uint32_t len = 0;
    bool isUpdateInput = false;
    HcfResult res = AllocateOutput(input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("AllocateOutput failed!");
        return res;
    }
    if (isUpdateInput) {
        ret = OpensslEvpCipherUpdate(data->ctx, output->data, (int32_t *)&len, input->data, input->len);
        if (ret != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGD("[error]EVP_CipherUpdate failed!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]EVP_CipherFinal_ex failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += len;
    return HCF_SUCCESS;
}

static HcfResult AllocateCcmOutput(CipherData *data, HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = 0;
    if (IsBlobValid(input)) {
        outLen += input->len;
        *isUpdateInput = true;
    }
    uint32_t authTagLen = data->enc == ENCRYPT_MODE ? CCM_TAG_SIZE : 0;
    outLen += authTagLen + AES_BLOCK_SIZE;
    if (outLen == 0) {
        LOGE("output size is invaild!");
        return HCF_INVALID_PARAMS;
    }
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult CcmDecryptDoFinal(HcfBlob *output, bool isUpdateInput)
{
    if (isUpdateInput) { /* DecryptFinal this does not occur in CCM mode */
        return HCF_SUCCESS;
    }
    if (output->data != NULL) {
        HcfBlobDataFree(output);
    }
    return HCF_SUCCESS;
}

static HcfResult CcmEncryptDoFinal(CipherData *data, HcfBlob *output, uint32_t len)
{
    int32_t ret = OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_GET_TAG, data->tagLen, output->data + len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]get AuthTag failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len = data->tagLen + len;
    return HCF_SUCCESS;
}

static HcfResult CcmDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    bool isUpdateInput = false;
    uint32_t len = 0;
    HcfResult res = AllocateCcmOutput(data, input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("AllocateCcmOutput failed!");
        return res;
    }
    if (isUpdateInput) {
        HcfResult result = AeadUpdate(data, HCF_ALG_MODE_CCM, input, output);
        if (result != HCF_SUCCESS) {
            LOGE("AeadUpdate failed!");
            return result;
        }
        len = output->len;
    }
    if (data->enc == ENCRYPT_MODE) {
        return CcmEncryptDoFinal(data, output, len);
    } else if (data->enc == DECRYPT_MODE) {
        return CcmDecryptDoFinal(output, isUpdateInput);
    } else {
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult GcmDecryptDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output, uint32_t len)
{
    if (data->tag == NULL) {
        LOGE("gcm decrypt has not AuthTag!");
        return HCF_INVALID_PARAMS;
    }
    int32_t ret = OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_SET_TAG, data->tagLen, (void *)data->tag);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]gcm decrypt set AuthTag failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]EVP_CipherFinal_ex failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len = output->len + len;
    return HCF_SUCCESS;
}

static HcfResult GcmEncryptDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output, uint32_t len)
{
    int32_t ret = OpensslEvpCipherFinalEx(data->ctx, output->data + len, (int *)&output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]EVP_CipherFinal_ex failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += len;
    ret = OpensslEvpCipherCtxCtrl(data->ctx, EVP_CTRL_AEAD_GET_TAG, data->tagLen,
        output->data + output->len);
    if (ret != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        LOGD("[error]get AuthTag failed!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len += data->tagLen;
    return HCF_SUCCESS;
}

static HcfResult AllocateGcmOutput(CipherData *data, HcfBlob *input, HcfBlob *output, bool *isUpdateInput)
{
    uint32_t outLen = 0;
    if (IsBlobValid(input)) {
        outLen += input->len;
        *isUpdateInput = true;
    }
    uint32_t authTagLen = data->enc == ENCRYPT_MODE ? GCM_TAG_SIZE : 0;
    outLen += data->updateLen + authTagLen + AES_BLOCK_SIZE;
    if (outLen == 0) {
        LOGE("output size is invaild!");
        return HCF_INVALID_PARAMS;
    }
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult GcmDoFinal(CipherData *data, HcfBlob *input, HcfBlob *output)
{
    uint32_t len = 0;
    bool isUpdateInput = false;
    HcfResult res = AllocateGcmOutput(data, input, output, &isUpdateInput);
    if (res != HCF_SUCCESS) {
        LOGE("AllocateGcmOutput failed!");
        return res;
    }

    if (isUpdateInput) {
        if (data->aad != NULL && data->aadLen != 0) {
            HcfResult result = AeadUpdate(data, HCF_ALG_MODE_GCM, input, output);
            if (result != HCF_SUCCESS) {
                LOGD("[error]AeadUpdate failed!");
                return result;
            }
        } else {
            HcfResult result = CommonUpdate(data, input, output);
            if (result != HCF_SUCCESS) {
                LOGD("[error]No aad update failed!");
                return result;
            }
        }
        len = output->len;
    }
    if (data->enc == ENCRYPT_MODE) {
        return GcmEncryptDoFinal(data, input, output, len);
    } else if (data->enc == DECRYPT_MODE) {
        return GcmDecryptDoFinal(data, input, output, len);
    } else {
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) { /* input maybe is null */
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((const HcfObjectBase *)self, GetAesGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    HcfCipherAesGeneratorSpiOpensslImpl *cipherImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    CipherData *data = cipherImpl->cipherData;
    HcfAlgParaValue mode = cipherImpl->attr.mode;
    if (data == NULL) {
        LOGE("cipherData is null!");
        return HCF_INVALID_PARAMS;
    }

    if (mode == HCF_ALG_MODE_CCM) {
        ret = CcmDoFinal(data, input, output);
    } else if (mode == HCF_ALG_MODE_GCM) {
        ret = GcmDoFinal(data, input, output);
    } else { /* only ECB CBC CTR CFB OFB support */
        ret = CommonDoFinal(data, input, output);
    }

    FreeCipherData(&(cipherImpl->cipherData));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataFree(output);
    }
    FreeRedundantOutput(output);
    return ret;
}

static void EngineAesGeneratorDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetAesGeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }

    HcfCipherAesGeneratorSpiOpensslImpl *impl = (HcfCipherAesGeneratorSpiOpensslImpl *)self;
    FreeCipherData(&(impl->cipherData));
    HcfFree(impl);
}

static HcfResult GetAesCipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetAesCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    return HCF_NOT_SUPPORT;
}

static HcfResult SetAesCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

HcfResult HcfCipherAesGeneratorSpiCreate(CipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    HcfCipherAesGeneratorSpiOpensslImpl *returnImpl = (HcfCipherAesGeneratorSpiOpensslImpl *)HcfMalloc(
        sizeof(HcfCipherAesGeneratorSpiOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(CipherAttr), attr, sizeof(CipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetAesCipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetAesCipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetAesCipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineAesGeneratorDestroy;
    returnImpl->base.base.getClass = GetAesGeneratorClass;

    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
