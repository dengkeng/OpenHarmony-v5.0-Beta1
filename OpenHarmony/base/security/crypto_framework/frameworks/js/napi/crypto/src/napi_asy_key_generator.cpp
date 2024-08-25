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

#include "napi_asy_key_generator.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"

namespace OHOS {
namespace CryptoFramework {
struct GenKeyPairCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

struct ConvertKeyCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;
    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

struct ConvertPemKeyCtx {
    napi_env env = nullptr;

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;
    std::string pubKey = "";
    std::string priKey = "";

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

thread_local napi_ref NapiAsyKeyGenerator::classRef_ = nullptr;

static void FreeGenKeyPairCtx(napi_env env, GenKeyPairCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
        ctx->callback = nullptr;
    }

    if (ctx->generatorRef != nullptr) {
        napi_delete_reference(env, ctx->generatorRef);
        ctx->generatorRef = nullptr;
    }

    HcfFree(ctx);
}

static void FreeConvertKeyCtx(napi_env env, ConvertKeyCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
        ctx->callback = nullptr;
    }

    if (ctx->generatorRef != nullptr) {
        napi_delete_reference(env, ctx->generatorRef);
        ctx->generatorRef = nullptr;
    }

    HcfBlobDataFree(ctx->pubKey);
    HcfFree(ctx->pubKey);
    HcfBlobDataFree(ctx->priKey);
    HcfFree(ctx->priKey);
    HcfFree(ctx);
}

static void FreeConvertPemKeyCtx(napi_env env, ConvertPemKeyCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }
    if (ctx->generatorRef != nullptr) {
        napi_delete_reference(env, ctx->generatorRef);
        ctx->generatorRef = nullptr;
    }

    ctx->errMsg = nullptr;
    ctx->pubKey = "";
    ctx->priKey = "";
    HcfFree(ctx);
    ctx = nullptr;
}

static bool BuildGenKeyPairCtx(napi_env env, napi_callback_info info, GenKeyPairCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[0], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiAsyKeyGenerator *napiGenerator;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }

    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = nullptr;

    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed generator key pair!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool GetPkAndSkBlobFromNapiValueIfInput(napi_env env, napi_value pkValue, napi_value skValue,
    HcfBlob **returnPubKey, HcfBlob **returnPriKey)
{
    napi_valuetype valueType;
    napi_typeof(env, pkValue, &valueType);
    HcfBlob *pubKey = nullptr;
    if (valueType != napi_null) {
        pubKey = GetBlobFromNapiDataBlob(env, pkValue);
        if (pubKey == nullptr) {
            LOGE("failed to get pubKey.");
            return false;
        }
    }

    napi_typeof(env, skValue, &valueType);
    HcfBlob *priKey = nullptr;
    if (valueType != napi_null) {
        priKey = GetBlobFromNapiDataBlob(env, skValue);
        if (priKey == nullptr) {
            // if the prikey get func fails, the return pointer will not take the ownership of pubkey and not free it.
            HcfBlobDataFree(pubKey);
            HcfFree(pubKey);
            LOGE("failed to get priKey.");
            return false;
        }
    }

    *returnPubKey = pubKey;
    *returnPriKey = priKey;
    return true;
}

static bool GetPkAndSkStringFromNapiValueIfInput(napi_env env, napi_value pkValue, napi_value skValue,
    std::string &returnPubKey, std::string &returnPriKey)
{
    size_t length = 0;
    napi_valuetype valueTypePk;
    napi_valuetype valueTypeSk;
    napi_typeof(env, pkValue, &valueTypePk);
    napi_typeof(env, skValue, &valueTypeSk);
    if (valueTypePk == napi_null && valueTypeSk == napi_null) {
        LOGE("valueTypePk and valueTypeSk is all null.");
        return false;
    }
    if (valueTypePk != napi_null) {
        if (valueTypePk != napi_string) {
            LOGE("valueTypePk wrong argument type, expect string type.");
            return false;
        }
        if (napi_get_value_string_utf8(env, pkValue, nullptr, 0, &length) != napi_ok) {
            LOGE("pkValue can not get string length.");
            return false;
        }
        returnPubKey.reserve(length + 1);
        returnPubKey.resize(length);
        if (napi_get_value_string_utf8(env, pkValue, returnPubKey.data(), (length + 1), &length) != napi_ok) {
            LOGE("pkValue can not get string value.");
            return false;
        }
    }
    if (valueTypeSk != napi_null) {
        if (valueTypeSk != napi_string) {
            LOGE("valueTypeSk wrong argument type. expect string type.");
            return false;
        }
        if (napi_get_value_string_utf8(env, skValue, nullptr, 0, &length) != napi_ok) {
            LOGE("skValue can not get string length.");
            return false;
        }
        returnPriKey.reserve(length + 1);
        returnPriKey.resize(length);
        if (napi_get_value_string_utf8(env, skValue, returnPriKey.data(), (length + 1), &length) != napi_ok) {
            LOGE("skValue can not get string value.");
            return false;
        }
    }
    return true;
}

static bool BuildConvertKeyCtx(napi_env env, napi_callback_info info, ConvertKeyCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiAsyKeyGenerator *napiGenerator;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }

    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;
    if (!GetPkAndSkBlobFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], &pubKey, &priKey)) {
        return false;
    }

    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = nullptr;
    ctx->pubKey = pubKey;
    ctx->priKey = priKey;

    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed when convert asym key!");
        return false;
    }

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool BuildConvertPemKeyCtx(napi_env env, napi_callback_info info, ConvertPemKeyCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        LOGE("wrong argument num. require %zu arguments. [Argc]: %zu!", expectedArgc, argc);
        return false;
    }
    NapiAsyKeyGenerator *napiGenerator;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }
    std::string pubKey = "";
    std::string priKey = "";
    if (!GetPkAndSkStringFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], pubKey, priKey)) {
        LOGE("GetPkAndSkStringFromNapiValueIfInput failed.");
        return false;
    }
    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = nullptr;
    ctx->pubKey = pubKey;
    ctx->priKey = priKey;
    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed when convert pem asym key!");
        return false;
    }
    napi_create_promise(env, &ctx->deferred, &ctx->promise);
    return true;
}

static void ReturnGenKeyPairCallbackResult(napi_env env, GenKeyPairCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnGenKeyPairPromiseResult(napi_env env, GenKeyPairCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnConvertKeyCallbackResult(napi_env env, ConvertKeyCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnConvertKeyPromiseResult(napi_env env, ConvertKeyCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnConvertPemKeyPromiseResult(napi_env env, ConvertPemKeyCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void GenKeyPairAsyncWorkProcess(napi_env env, void *data)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(data);

    ctx->errCode = ctx->generator->generateKeyPair(ctx->generator, ctx->params, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGD("[error] generate key pair fail.");
        ctx->errMsg = "generate key pair fail.";
    }
}

static void GenKeyPairAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi key pair failed!"));
            LOGE("new napi key pair failed");
            FreeGenKeyPairCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                NapiKeyPair *keyPair = static_cast<NapiKeyPair *>(data);
                delete keyPair;
                return;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            delete napiKeyPair;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnGenKeyPairCallbackResult(env, ctx, instance);
    } else {
        ReturnGenKeyPairPromiseResult(env, ctx, instance);
    }
    FreeGenKeyPairCtx(env, ctx);
}

static void ConvertKeyAsyncWorkProcess(napi_env env, void *data)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(data);

    ctx->errCode = ctx->generator->convertKey(ctx->generator, ctx->params,
        ctx->pubKey, ctx->priKey, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGD("[error] convert key fail.");
        ctx->errMsg = "convert key fail.";
    }
}

static void ConvertPemKeyAsyncWorkProcess(napi_env env, void *data)
{
    ConvertPemKeyCtx *ctx = static_cast<ConvertPemKeyCtx *>(data);
    ctx->errCode = ctx->generator->convertPemKey(ctx->generator, ctx->params,
            ctx->pubKey.c_str(), ctx->priKey.c_str(), &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("ConvertPemKey fail.");
        ctx->errMsg = "ConvertPemKey fail.";
    }
}

static void ConvertKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi key pair failed!"));
            LOGE("new napi key pair failed");
            FreeConvertKeyCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                NapiKeyPair *keyPair = static_cast<NapiKeyPair *>(data);
                delete keyPair;
                return;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            delete napiKeyPair;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnConvertKeyCallbackResult(env, ctx, instance);
    } else {
        ReturnConvertKeyPromiseResult(env, ctx, instance);
    }
    FreeConvertKeyCtx(env, ctx);
}

static void ConvertPemKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    ConvertPemKeyCtx *ctx = static_cast<ConvertPemKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            LOGE("new napi key pair failed.");
            napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi key pair failed!"));
            HcfObjDestroy(ctx->returnKeyPair);
            ctx->returnKeyPair = nullptr;
            FreeConvertPemKeyCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                NapiKeyPair *keyPair = static_cast<NapiKeyPair *>(data);
                delete keyPair;
                return;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            HcfObjDestroy(ctx->returnKeyPair);
            ctx->returnKeyPair = nullptr;
            delete napiKeyPair;
        }
    }

    ReturnConvertPemKeyPromiseResult(env, ctx, instance);
    FreeConvertPemKeyCtx(env, ctx);
}

static napi_value NewGenKeyPairAsyncWork(napi_env env, GenKeyPairCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generatorKeyPair", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            GenKeyPairAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            GenKeyPairAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewConvertKeyAsyncWork(napi_env env, ConvertKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "convertKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ConvertKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            ConvertKeyAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewConvertPemKeyAsyncWork(napi_env env, ConvertPemKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "convertPemKey", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ConvertPemKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            ConvertPemKeyAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

NapiAsyKeyGenerator::NapiAsyKeyGenerator(HcfAsyKeyGenerator *generator)
{
    this->generator_ = generator;
}

NapiAsyKeyGenerator::~NapiAsyKeyGenerator()
{
    HcfObjDestroy(this->generator_);
}

HcfAsyKeyGenerator *NapiAsyKeyGenerator::GetAsyKeyGenerator()
{
    return this->generator_;
}

napi_value NapiAsyKeyGenerator::JsGenerateKeyPair(napi_env env, napi_callback_info info)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(HcfMalloc(sizeof(GenKeyPairCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc ctx fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildGenKeyPairCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeGenKeyPairCtx(env, ctx);
        return nullptr;
    }

    return NewGenKeyPairAsyncWork(env, ctx);
}

static bool GetHcfKeyPairInstance(napi_env env, HcfKeyPair *returnKeyPair, napi_value *instance)
{
    NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(returnKeyPair);
    if (napiKeyPair == nullptr) {
        HcfObjDestroy(returnKeyPair);
        LOGE("new napi key pair failed");
        return false;
    }

    *instance = napiKeyPair->ConvertToJsKeyPair(env);
    napi_status ret = napi_wrap(
        env, *instance, napiKeyPair,
        [](napi_env env, void *data, void *hint) {
            NapiKeyPair *keyPair = static_cast<NapiKeyPair *>(data);
            delete keyPair;
            return;
        }, nullptr, nullptr);
    if (ret != napi_ok) {
        LOGE("failed to wrap napiKeyPair obj!");
        delete napiKeyPair;
        return false;
    }

    return true;
}

napi_value NapiAsyKeyGenerator::JsGenerateKeyPairSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj."));
        return nullptr;
    }

    HcfAsyKeyGenerator *generator = napiGenerator->GetAsyKeyGenerator();
    if (generator == nullptr) {
        LOGE("get generator fail.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get generator fail!"));
        return nullptr;
    }

    HcfParamsSpec *params = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
    HcfResult errCode = generator->generateKeyPair(generator, params, &returnKeyPair);
    if (errCode != HCF_SUCCESS) {
        LOGE("generate key pair fail.");
        napi_throw(env, GenerateBusinessError(env, errCode, "generate key pair fail."));
        return nullptr;
    }

    napi_value instance = nullptr;
    if (!GetHcfKeyPairInstance(env, returnKeyPair, &instance)) {
        LOGE("failed to get generate key pair instance!");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "failed to get generate key pair instance!"));
        return nullptr;
    }

    return instance;
}

napi_value NapiAsyKeyGenerator::JsConvertKey(napi_env env, napi_callback_info info)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(HcfMalloc(sizeof(ConvertKeyCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail!"));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildConvertKeyCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeConvertKeyCtx(env, ctx);
        return nullptr;
    }

    return NewConvertKeyAsyncWork(env, ctx);
}

static void HcfFreePubKeyAndPriKey(HcfBlob *pubKey, HcfBlob *priKey)
{
    HcfBlobDataFree(pubKey);
    HcfFree(pubKey);
    HcfBlobDataFree(priKey);
    HcfFree(priKey);
}

napi_value NapiAsyKeyGenerator::JsConvertKeySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = PARAMS_NUM_TWO;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != PARAMS_NUM_TWO) {
        LOGE("wrong argument num. require %d arguments. [Argc]: %zu!", PARAMS_NUM_TWO, argc);
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "wrong argument num."));
        return nullptr;
    }

    NapiAsyKeyGenerator *napiGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj."));
        return nullptr;
    }

    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;
    if (!GetPkAndSkBlobFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], &pubKey, &priKey)) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj."));
        return nullptr;
    }

    HcfAsyKeyGenerator *generator = napiGenerator->GetAsyKeyGenerator();
    if (generator == nullptr) {
        HcfFreePubKeyAndPriKey(pubKey, priKey);
        LOGE("get generator fail.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get generator fail!"));
        return nullptr;
    }

    HcfParamsSpec *params = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
    HcfResult errCode = generator->convertKey(generator, params, pubKey, priKey, &(returnKeyPair));
    HcfFreePubKeyAndPriKey(pubKey, priKey);
    if (errCode != HCF_SUCCESS) {
        LOGE("convert key fail.");
        napi_throw(env, GenerateBusinessError(env, errCode, "convert key fail."));
        return nullptr;
    }

    napi_value instance = nullptr;
    if (!GetHcfKeyPairInstance(env, returnKeyPair, &instance)) {
        LOGE("failed to get convert key instance!");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "failed to get convert key instance!"));
        return nullptr;
    }

    return instance;
}

napi_value NapiAsyKeyGenerator::JsConvertPemKey(napi_env env, napi_callback_info info)
{
    ConvertPemKeyCtx *ctx = static_cast<ConvertPemKeyCtx *>(HcfMalloc(sizeof(ConvertPemKeyCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail!"));
        return nullptr;
    }
    if (!BuildConvertPemKeyCtx(env, info, ctx)) {
        LOGE("build context fail.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        FreeConvertPemKeyCtx(env, ctx);
        return nullptr;
    }
    return NewConvertPemKeyAsyncWork(env, ctx);
}

static HcfResult ConvertPemKeySync(std::string &pubKey,  std::string &priKey, HcfAsyKeyGenerator *generator,
    HcfKeyPair **returnKeyPair)
{
    HcfResult errCode = generator->convertPemKey(generator, nullptr,
           pubKey.c_str(), priKey.c_str(), returnKeyPair);
    if (errCode != HCF_SUCCESS) {
        LOGE("convertPemKey error!");
        return errCode;
    }
    return HCF_SUCCESS;
}

napi_value NapiAsyKeyGenerator::JsConvertPemKeySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        LOGE("wrong argument num. require %zu arguments. [Argc]: %zu!", expectedArgc, argc);
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "invalid parameters."));
        return nullptr;
    }

    NapiAsyKeyGenerator *napiGenerator;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napi asyKeyGenerator obj."));
        return nullptr;
    }

    std::string pubKey = "";
    std::string priKey = "";
    if (!GetPkAndSkStringFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], pubKey, priKey)) {
        LOGE("GetPkAndSkStringFromNapiValueIfInput failed.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "GetPkAndSkStringFromNapiValueIfInput failed."));
        return nullptr;
    }

    HcfAsyKeyGenerator *generator = napiGenerator->GetAsyKeyGenerator();
    if (generator == nullptr) {
        LOGE("GetAsyKeyGenerator failed!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "GetAsyKeyGenerator failed!"));
        return nullptr;
    }

    HcfKeyPair *returnKeyPair = nullptr;
    HcfResult errCode = ConvertPemKeySync(pubKey, priKey, generator, &(returnKeyPair));
    if (errCode != HCF_SUCCESS) {
        LOGE("ConvertPemKeySync error!");
        napi_throw(env, GenerateBusinessError(env, errCode, "ConvertPemKeySync error!"));
        return nullptr;
    }

    NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(returnKeyPair);
    if (napiKeyPair == nullptr) {
        LOGE("new napi key pair failed");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc context failed."));
        HcfObjDestroy(returnKeyPair);
        returnKeyPair = nullptr;
        return nullptr;
    }

    napi_value instance = nullptr;
    instance = napiKeyPair->ConvertToJsKeyPair(env);
    return instance;
}

napi_value NapiAsyKeyGenerator::AsyKeyGeneratorConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapAsyKeyGen(napi_env env, napi_value instance, NapiAsyKeyGenerator *napiAsyKeyGenerator)
{
    napi_status status = napi_wrap(
        env, instance, napiAsyKeyGenerator,
        [](napi_env env, void *data, void *hint) {
            NapiAsyKeyGenerator *napiAsyKeyGenerator = static_cast<NapiAsyKeyGenerator *>(data);
            delete napiAsyKeyGenerator;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to wrap napiAsyKeyGenerator obj!"));
        delete napiAsyKeyGenerator;
        napiAsyKeyGenerator = nullptr;
        LOGE("failed to wrap napiAsyKeyGenerator obj!");
        return nullptr;
    }
    return instance;
}

napi_value NapiAsyKeyGenerator::CreateJsAsyKeyGenerator(napi_env env, napi_callback_info info)
{
    LOGD("Enter CreateJsAsyKeyGenerator...");
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        LOGE("The input args num is invalid.");
        return NapiGetNull(env);
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get algoName."));
        LOGE("failed to get algoName.");
        return NapiGetNull(env);
    }

    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create c generator fail."));
        LOGE("create c generator fail.");
        return NapiGetNull(env);
    }

    NapiAsyKeyGenerator *napiAsyKeyGenerator = new (std::nothrow) NapiAsyKeyGenerator(generator);
    if (napiAsyKeyGenerator == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi asy key napi generator failed!"));
        LOGE("new napi asy key napi generator failed");
        HcfObjDestroy(generator);
        return NapiGetNull(env);
    }

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    return NapiWrapAsyKeyGen(env, instance, napiAsyKeyGenerator);
}

void NapiAsyKeyGenerator::DefineAsyKeyGeneratorJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createAsyKeyGenerator", NapiAsyKeyGenerator::CreateJsAsyKeyGenerator),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateKeyPair", NapiAsyKeyGenerator::JsGenerateKeyPair),
        DECLARE_NAPI_FUNCTION("generateKeyPairSync", NapiAsyKeyGenerator::JsGenerateKeyPairSync),
        DECLARE_NAPI_FUNCTION("convertKey", NapiAsyKeyGenerator::JsConvertKey),
        DECLARE_NAPI_FUNCTION("convertKeySync", NapiAsyKeyGenerator::JsConvertKeySync),
        DECLARE_NAPI_FUNCTION("convertPemKey", NapiAsyKeyGenerator::JsConvertPemKey),
        DECLARE_NAPI_FUNCTION("convertPemKeySync", NapiAsyKeyGenerator::JsConvertPemKeySync),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "AsyKeyGenerator", NAPI_AUTO_LENGTH, NapiAsyKeyGenerator::AsyKeyGeneratorConstructor,
        nullptr, sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
