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

#include "napi_mac.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_sym_key.h"
#include "napi_utils.h"
#include "napi_crypto_framework_defines.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiMac::classRef_ = nullptr;

struct MacCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref macRef = nullptr;
    napi_ref symKeyRef = nullptr;

    std::string algoName = "";
    HcfSymKey *symKey = nullptr;
    HcfBlob *inBlob = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfBlob *outBlob = nullptr;
    HcfMac *mac = nullptr;
};

static void FreeCryptoFwkCtx(napi_env env, MacCtx *context)
{
    if (context == nullptr) {
        return;
    }
    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
        context->asyncWork = nullptr;
    }
    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
        context->callback = nullptr;
    }
    if (context->macRef != nullptr) {
        napi_delete_reference(env, context->macRef);
        context->macRef = nullptr;
    }
    if (context->symKeyRef != nullptr) {
        napi_delete_reference(env, context->symKeyRef);
        context->symKeyRef = nullptr;
    }
    context->symKey = nullptr;
    if (context->inBlob != nullptr) {
        HcfFree(context->inBlob->data);
        context->inBlob->data = nullptr;
        context->inBlob->len = 0;
        HcfFree(context->inBlob);
        context->inBlob = nullptr;
    }
    if (context->outBlob != nullptr) {
        HcfFree(context->outBlob->data);
        context->outBlob->data = nullptr;
        context->outBlob->len = 0;
        HcfFree(context->outBlob);
        context->outBlob = nullptr;
    }
    context->errMsg = nullptr;
    context->mac = nullptr;
    HcfFree(context);
    context = nullptr;
}

static void ReturnCallbackResult(napi_env env, MacCtx *context, napi_value result)
{
    napi_value businessError = nullptr;
    if (context->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, context->errCode, context->errMsg);
    }
    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, context->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnPromiseResult(napi_env env, MacCtx *context, napi_value result)
{
    if (context->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            GenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void MacInitExecute(napi_env env, void *data)
{
    MacCtx *context = static_cast<MacCtx *>(data);
    HcfMac *macObj = context->mac;
    HcfSymKey *symKey = context->symKey;
    context->errCode = macObj->init(macObj, symKey);
    if (context->errCode != HCF_SUCCESS) {
        LOGD("[error] init failed!");
        context->errMsg = "init failed";
    }
}

static void MacInitComplete(napi_env env, napi_status status, void *data)
{
    MacCtx *context = static_cast<MacCtx *>(data);
    napi_value nullInstance = nullptr;
    napi_get_null(env, &nullInstance);
    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, nullInstance);
    } else {
        ReturnPromiseResult(env, context, nullInstance);
    }
    FreeCryptoFwkCtx(env, context);
}

static void MacUpdateExecute(napi_env env, void *data)
{
    MacCtx *context = static_cast<MacCtx *>(data);
    HcfMac *macObj = context->mac;
    HcfBlob *inBlob = reinterpret_cast<HcfBlob *>(context->inBlob);
    context->errCode = macObj->update(macObj, inBlob);
    if (context->errCode != HCF_SUCCESS) {
        LOGD("[error] update failed!");
        context->errMsg = "update failed";
    }
}

static void MacUpdateComplete(napi_env env, napi_status status, void *data)
{
    MacCtx *context = static_cast<MacCtx *>(data);
    napi_value nullInstance = nullptr;
    napi_get_null(env, &nullInstance);
    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, nullInstance);
    } else {
        ReturnPromiseResult(env, context, nullInstance);
    }
    FreeCryptoFwkCtx(env, context);
}

static void MacDoFinalExecute(napi_env env, void *data)
{
    MacCtx *context = static_cast<MacCtx *>(data);
    HcfMac *macObj = context->mac;
    HcfBlob *outBlob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (outBlob == nullptr) {
        LOGD("[error] outBlob is null!");
        context->errCode = HCF_ERR_MALLOC;
        context->errMsg = "malloc data blob failed";
        return;
    }
    context->errCode = macObj->doFinal(macObj, outBlob);
    if (context->errCode != HCF_SUCCESS) {
        HcfFree(outBlob);
        LOGE("doFinal failed!");
        context->errMsg = "doFinal failed";
        return;
    }
    context->outBlob = outBlob;
}

static void MacDoFinalComplete(napi_env env, napi_status status, void *data)
{
    MacCtx *context = static_cast<MacCtx *>(data);
    napi_value returnOutBlob = ConvertBlobToNapiValue(env, context->outBlob);
    if (returnOutBlob == nullptr) {
        LOGE("returnOutBlob is nullptr!");
        returnOutBlob = NapiGetNull(env);
    }
    if (context->asyncType == ASYNC_CALLBACK) {
        ReturnCallbackResult(env, context, returnOutBlob);
    } else {
        ReturnPromiseResult(env, context, returnOutBlob);
    }
    FreeCryptoFwkCtx(env, context);
}

static bool BuildMacJsInitCtx(napi_env env, napi_callback_info info, MacCtx *context)
{
    napi_value thisVar = nullptr;
    NapiMac *napiMac = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_TWO;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return false;
    }

    context->asyncType = isCallback(env, argv[expectedArgsCount - 1], argc, expectedArgsCount) ?
        ASYNC_CALLBACK : ASYNC_PROMISE;
    NapiSymKey *symKey = nullptr;
    napi_status status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&symKey));
    if (status != napi_ok || symKey == nullptr) {
        LOGE("symKey is null!");
        return false;
    }
    context->symKey = symKey->GetSymKey();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMac));
    if (status != napi_ok || napiMac == nullptr) {
        LOGE("failed to unwrap napiMac obj!");
        return false;
    }

    context->mac = napiMac->GetMac();

    if (napi_create_reference(env, thisVar, 1, &context->macRef) != napi_ok) {
        LOGE("create mac ref failed when do mac init!");
        return false;
    }

    if (napi_create_reference(env, argv[PARAM0], 1, &context->symKeyRef) != napi_ok) {
        LOGE("create sym key ref failed when do mac init!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[PARAM1], &context->callback);
    }
}

static bool BuildMacJsUpdateCtx(napi_env env, napi_callback_info info, MacCtx *context)
{
    napi_value thisVar = nullptr;
    NapiMac *napiMac = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_TWO;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return false;
    }

    context->asyncType = isCallback(env, argv[expectedArgsCount - 1], argc, expectedArgsCount) ?
        ASYNC_CALLBACK : ASYNC_PROMISE;
    context->inBlob = GetBlobFromNapiDataBlob(env, argv[PARAM0]);
    if (context->inBlob == nullptr) {
        LOGE("inBlob is null!");
        return false;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMac));
    if (status != napi_ok || napiMac == nullptr) {
        LOGE("failed to unwrap napiMac obj!");
        return false;
    }

    context->mac = napiMac->GetMac();

    if (napi_create_reference(env, thisVar, 1, &context->macRef) != napi_ok) {
        LOGE("create mac ref failed when do mac update!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[PARAM1], &context->callback);
    }
}

static bool BuildMacJsDoFinalCtx(napi_env env, napi_callback_info info, MacCtx *context)
{
    napi_value thisVar = nullptr;
    NapiMac *napiMac = nullptr;
    size_t expectedArgsCount = ARGS_SIZE_ONE;
    size_t argc = expectedArgsCount;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        return false;
    }

    context->asyncType = isCallback(env, argv[expectedArgsCount - 1], argc, expectedArgsCount) ?
        ASYNC_CALLBACK : ASYNC_PROMISE;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMac));
    if (status != napi_ok || napiMac == nullptr) {
        LOGE("failed to unwrap napiMac obj!");
        return false;
    }

    context->mac = napiMac->GetMac();

    if (napi_create_reference(env, thisVar, 1, &context->macRef) != napi_ok) {
        LOGE("create mac ref failed when do mac final!");
        return false;
    }

    if (context->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &context->deferred, &context->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[PARAM0], &context->callback);
    }
}

static napi_value NewMacJsInitAsyncWork(napi_env env, MacCtx *context)
{
    napi_create_async_work(
        env, nullptr, GetResourceName(env, "MacInit"),
        [](napi_env env, void *data) {
            MacInitExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            MacInitComplete(env, status, data);
            return;
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewMacJsUpdateAsyncWork(napi_env env, MacCtx *context)
{
    napi_create_async_work(
        env, nullptr, GetResourceName(env, "MacUpdate"),
        [](napi_env env, void *data) {
            MacUpdateExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            MacUpdateComplete(env, status, data);
            return;
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewMacJsDoFinalAsyncWork(napi_env env, MacCtx *context)
{
    napi_create_async_work(
        env, nullptr, GetResourceName(env, "MacDoFinal"),
        [](napi_env env, void *data) {
            MacDoFinalExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            MacDoFinalComplete(env, status, data);
            return;
        },
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}


NapiMac::NapiMac(HcfMac *macObj)
{
    this->macObj_ = macObj;
}

NapiMac::~NapiMac()
{
    HcfObjDestroy(this->macObj_);
}

HcfMac *NapiMac::GetMac()
{
    return this->macObj_;
}

napi_value NapiMac::JsMacInit(napi_env env, napi_callback_info info)
{
    MacCtx *context = static_cast<MacCtx *>(HcfMalloc(sizeof(MacCtx), 0));
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc context failed"));
        LOGE("malloc context failed!");
        return nullptr;
    }

    if (!BuildMacJsInitCtx(env, info, context)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    return NewMacJsInitAsyncWork(env, context);
}

napi_value NapiMac::JsMacInitSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiMac *napiMac = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        LOGE("The input args num is invalid.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        return nullptr;
    }
    NapiSymKey *napiSysKey = nullptr;
    napi_status status = napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiSysKey));
    if (status != napi_ok || napiSysKey == nullptr) {
        LOGE("napiSysKey is null!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "napiSysKey is null!"));
        return nullptr;
    }
    HcfSymKey *symKey = napiSysKey->GetSymKey();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMac));
    if (status != napi_ok || napiMac == nullptr) {
        LOGE("failed to unwrap napiMac obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiMac obj!"));
        return nullptr;
    }
    HcfMac *mac = napiMac->GetMac();
    if (mac == nullptr) {
        LOGE("mac is nullptr!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "mac is nullptr!"));
        return nullptr;
    }
    HcfResult errCode = mac->init(mac, symKey);
    if (errCode != HCF_SUCCESS) {
        LOGE("mac init failed!");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_CRYPTO_OPERATION, "mac init failed!"));
        return nullptr;
    }
    napi_value nullInstance = nullptr;
    napi_get_null(env, &nullInstance);
    return nullInstance;
}

napi_value NapiMac::JsMacUpdate(napi_env env, napi_callback_info info)
{
    MacCtx *context = static_cast<MacCtx *>(HcfMalloc(sizeof(MacCtx), 0));
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc context failed"));
        LOGE("malloc context failed!");
        return nullptr;
    }

    if (!BuildMacJsUpdateCtx(env, info, context)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    return NewMacJsUpdateAsyncWork(env, context);
}

napi_value NapiMac::JsMacUpdateSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiMac *napiMac = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        LOGE("The input args num is invalid.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMac));
    if (status != napi_ok || napiMac == nullptr) {
        LOGE("failed to unwrap napiMac obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiMac obj!"));
        return nullptr;
    }

    HcfBlob *inBlob = GetBlobFromNapiDataBlob(env, argv[PARAM0]);
    if (inBlob == nullptr) {
        LOGE("inBlob is null!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "inBlob is null!"));
        return nullptr;
    }

    HcfMac *mac = napiMac->GetMac();
    if (mac == nullptr) {
        LOGE("mac is nullptr!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "mac is nullptr!"));
        HcfBlobDataClearAndFree(inBlob);
        HcfFree(inBlob);
        return nullptr;
    }
    HcfResult errCode = mac->update(mac, inBlob);
    HcfBlobDataClearAndFree(inBlob);
    HcfFree(inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("mac update failed!");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_CRYPTO_OPERATION, "mac update failed!"));
        return nullptr;
    }
    napi_value nullInstance = nullptr;
    napi_get_null(env, &nullInstance);
    return nullInstance;
}

napi_value NapiMac::JsMacDoFinal(napi_env env, napi_callback_info info)
{
    MacCtx *context = static_cast<MacCtx *>(HcfMalloc(sizeof(MacCtx), 0));
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc context failed"));
        LOGE("malloc context failed!");
        return nullptr;
    }

    if (!BuildMacJsDoFinalCtx(env, info, context)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    return NewMacJsDoFinalAsyncWork(env, context);
}

napi_value NapiMac::JsMacDoFinalSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiMac *napiMac = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMac));
    if (status != napi_ok || napiMac == nullptr) {
        LOGE("failed to unwrap napiMac obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_NAPI, "failed to unwrap napiMac obj."));
        return nullptr;
    }
    HcfMac *mac = napiMac->GetMac();
    if (mac == nullptr) {
        LOGE("mac is nullptr!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "mac is nullptr!"));
        return nullptr;
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = mac->doFinal(mac, &outBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("mac doFinal failed!");
        napi_throw(env, GenerateBusinessError(env, errCode, "mac doFinal failed!"));
        HcfBlobDataClearAndFree(&outBlob);
        return nullptr;
    }

    napi_value returnOutBlob = nullptr;
    errCode = ConvertDataBlobToNapiValue(env, &outBlob, &returnOutBlob);
    HcfBlobDataClearAndFree(&outBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("mac convert dataBlob to napi_value failed!");
        napi_throw(env, GenerateBusinessError(env, errCode, "mac convert dataBlob to napi_value failed!"));
        return nullptr;
    }

    return returnOutBlob;
}

napi_value NapiMac::JsGetMacLength(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiMac *napiMac = nullptr;

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiMac));
    if (status != napi_ok || napiMac == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiMac obj!"));
        LOGE("failed to unwrap napiMac obj!");
        return nullptr;
    }

    HcfMac *mac = napiMac->GetMac();
    if (mac == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "fail to get mac obj!"));
        LOGE("fail to get mac obj!");
        return nullptr;
    }

    uint32_t retLen = mac->getMacLength(mac);
    napi_value napiLen = nullptr;
    napi_create_uint32(env, retLen, &napiLen);
    return napiLen;
}

napi_value NapiMac::MacConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapMac(napi_env env, napi_value instance, NapiMac *macNapiObj)
{
    napi_status status = napi_wrap(
        env, instance, macNapiObj,
        [](napi_env env, void *data, void *hint) {
            NapiMac *mac = static_cast<NapiMac *>(data);
            delete mac;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to wrap NapiMac obj!"));
        delete macNapiObj;
        macNapiObj = nullptr;
        LOGE("failed to wrap NapiMac obj!");
        return nullptr;
    }
    return instance;
}

napi_value NapiMac::CreateMac(napi_env env, napi_callback_info info)
{
    LOGD("Enter CreateMac...");
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        LOGE("The input args num is invalid.");
        return nullptr;
    }
    std::string algoName;
    if (!GetStringFromJSParams(env, argv[PARAM0], algoName)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "Failed to get algorithm."));
        LOGE("Failed to get algorithm.");
        return nullptr;
    }
    HcfMac *macObj = nullptr;
    HcfResult res = HcfMacCreate(algoName.c_str(), &macObj);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "create C obj failed."));
        LOGE("create c macObj failed.");
        return nullptr;
    }
    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algoName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_value instance = nullptr;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);
    NapiMac *macNapiObj = new (std::nothrow) NapiMac(macObj);
    if (macNapiObj == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new mac napi obj failed."));
        HcfObjDestroy(macObj);
        LOGE("create napi obj failed");
        return nullptr;
    }

    return NapiWrapMac(env, instance, macNapiObj);
}

void NapiMac::DefineMacJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createMac", NapiMac::CreateMac),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("init", NapiMac::JsMacInit),
        DECLARE_NAPI_FUNCTION("initSync", NapiMac::JsMacInitSync),
        DECLARE_NAPI_FUNCTION("update", NapiMac::JsMacUpdate),
        DECLARE_NAPI_FUNCTION("updateSync", NapiMac::JsMacUpdateSync),
        DECLARE_NAPI_FUNCTION("doFinal", NapiMac::JsMacDoFinal),
        DECLARE_NAPI_FUNCTION("doFinalSync", NapiMac::JsMacDoFinalSync),
        DECLARE_NAPI_FUNCTION("getMacLength", NapiMac::JsGetMacLength),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Mac", NAPI_AUTO_LENGTH, MacConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS