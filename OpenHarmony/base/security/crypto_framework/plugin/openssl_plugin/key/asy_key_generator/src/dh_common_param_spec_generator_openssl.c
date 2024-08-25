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

#include "dh_common_param_spec_generator_openssl.h"
#include "dh_openssl_common.h"
#include "securec.h"

#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

#define PARAMS_NUM_TWO 2
#define PARAMS_NUM_THREE 3

static HcfResult GenerateDhUnknownGroupEvpKey(int32_t pLen, EVP_PKEY **ppkey)
{
    EVP_PKEY_CTX *paramsCtx = OpensslEvpPkeyCtxNewId(EVP_PKEY_DH, NULL);
    if (paramsCtx == NULL) {
        HcfPrintOpensslError();
        LOGD("[error] Create params ctx failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    do {
        if (OpensslEvpPkeyParamGenInit(paramsCtx) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGD("[error] Params ctx paramgen init failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyCtxSetDhParamgenPrimeLen(paramsCtx, pLen) <= 0) {
            HcfPrintOpensslError();
            LOGD("[error] Set prime length of bits to params ctx failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyParamGen(paramsCtx, ppkey) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGD("[error] Generate params pkey failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    OpensslEvpPkeyCtxFree(paramsCtx);
    return ret;
}

static HcfResult GenerateDhKnownGroupEvpKey(int32_t skLen, char *nidName, EVP_PKEY **ppkey)
{
    HcfResult ret = HCF_SUCCESS;
    EVP_PKEY_CTX *paramsCtx = NULL;
    OSSL_PARAM params[PARAMS_NUM_THREE];

    params[0] = OpensslOsslParamConstructUtf8String("group", nidName, 0);
    if (skLen != 0) {
        params[1] = OpensslOsslParamConstructInt("priv_len", &skLen);
        params[PARAMS_NUM_TWO] = OpensslOsslParamConstructEnd();
    } else {
        params[1] = OpensslOsslParamConstructEnd();
    }
    do {
        paramsCtx = OpensslEvpPkeyCtxNewFromName(NULL, "DH", NULL);
        if (paramsCtx == NULL) {
            LOGD("[error] New paramsCtx from name failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyKeyGenInit(paramsCtx) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Pkey keygen init failed.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyCtxSetParams(paramsCtx, params) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Set paramsCtx failed.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (OpensslEvpPkeyGenerate(paramsCtx, ppkey) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Generate pKey failed.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    if (paramsCtx != NULL) {
        OpensslEvpPkeyCtxFree(paramsCtx);
    }
    return ret;
}

static HcfResult BuildCommonParam(EVP_PKEY *dhKey, HcfDhCommParamsSpecSpi *returnCommonParamSpec)
{
    DH *sk = OpensslEvpPkeyGet1Dh(dhKey);
    if (sk == NULL) {
        LOGD("[error] Get dh private key from pkey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(OpensslDhGet0P(sk), &(returnCommonParamSpec->paramsSpec.p)) != HCF_SUCCESS) {
        LOGD("[error] BuildCommonParamPrime failed.");
        OpensslDhFree(sk);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(OpensslDhGet0G(sk), &(returnCommonParamSpec->paramsSpec.g)) != HCF_SUCCESS) {
        LOGD("[error] BuildCommonParamGenerator failed.");
        OpensslDhFree(sk);
        HcfFree(returnCommonParamSpec->paramsSpec.p.data);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    OpensslDhFree(sk);
    return HCF_SUCCESS;
}

static HcfResult SetAlgName(const char *algName, char **returnAlgName)
{
    size_t srcAlgNameLen = HcfStrlen(algName);
    if (!srcAlgNameLen) {
        LOGE("AlgName is empty!");
        return HCF_INVALID_PARAMS;
    }
    *returnAlgName = (char *)HcfMalloc(srcAlgNameLen + 1, 0);
    if (*returnAlgName == NULL) {
        LOGE("Failed to malloc algName memory.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(*returnAlgName, srcAlgNameLen, algName, srcAlgNameLen) != EOK) {
        LOGD("[error] Failed to memcpy algName.");
        HcfFree(*returnAlgName);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult HcfDhCommonParamSpecCreate(int32_t pLen, int32_t skLen, HcfDhCommParamsSpecSpi **returnCommonParamSpec)
{
    if (returnCommonParamSpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    EVP_PKEY *dhKey = NULL;
    char *nidName = GetNidNameByDhPLen(pLen);
    if (nidName == NULL) {
        if (GenerateDhUnknownGroupEvpKey(pLen, &dhKey) != HCF_SUCCESS) {
            LOGD("[error] Generate dh unknown group evpKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        if (GenerateDhKnownGroupEvpKey(skLen, nidName, &dhKey) != HCF_SUCCESS) {
            LOGD("[error] Generate dh known group evpKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    HcfDhCommParamsSpecSpi *object = (HcfDhCommParamsSpecSpi*)HcfMalloc(sizeof(HcfDhCommParamsSpecSpi), 0);
    if (object == NULL) {
        LOGE("Build dh common params object failed.");
        OpensslEvpPkeyFree(dhKey);
        return HCF_ERR_MALLOC;
    }
    const char *algName = "DH";
    object->paramsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    object->paramsSpec.length = skLen;
    if (SetAlgName(algName, &(object->paramsSpec.base.algName)) != HCF_SUCCESS) {
        LOGE("Set algName parameter failed.");
        HcfFree(object);
        OpensslEvpPkeyFree(dhKey);
        return HCF_INVALID_PARAMS;
    }
    if (BuildCommonParam(dhKey, object)!= HCF_SUCCESS) {
        LOGD("[error] Get common params failed.");
        HcfFree(object->paramsSpec.base.algName);
        HcfFree(object);
        OpensslEvpPkeyFree(dhKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnCommonParamSpec = object;
    OpensslEvpPkeyFree(dhKey);
    return HCF_SUCCESS;
}
