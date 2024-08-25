/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NAPITUTORIALS_JAVASCRIPTAPI_H
#define NAPITUTORIALS_JAVASCRIPTAPI_H

#include "common.h"

#include "hilog/log.h"
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0x3200
#define LOG_TAG "[javascriptapi_property]"
#define OH_LOG_INFO(type, ...) ((void)OH_LOG_Print((type), LOG_INFO, LOG_DOMAIN, LOG_TAG, __VA_ARGS__))

napi_value jsPropertyInit(napi_env env, napi_value exports);
napi_value testNapiGetPropertyNames(napi_env env, napi_callback_info info);
napi_value testNapiSetProperty(napi_env env, napi_callback_info info);
napi_value testNapiGetProperty(napi_env env, napi_callback_info info);
napi_value testNapiHasProperty(napi_env env, napi_callback_info info);
napi_value testNapiDeleteProperty(napi_env env, napi_callback_info info);
bool validateObjectProperty(napi_env &env, napi_value &obj, napi_value &propName, const char *tag);
napi_value testNapiSetNamedProperty(napi_env env, napi_callback_info info);
napi_value testNapiGetNamedProperty(napi_env env, napi_callback_info info);
napi_value testNapiHasNamedProperty(napi_env env, napi_callback_info info);
bool validateArrayObjProperty(napi_env &env, napi_value &obj, napi_value &propName, const char *tag);
napi_value testNapiSetElement(napi_env env, napi_callback_info info);
napi_value testNapiGetElement(napi_env env, napi_callback_info info);
napi_value testNapiHasElement(napi_env env, napi_callback_info info);
napi_value testNapiDeleteElement(napi_env env, napi_callback_info info);

napi_value testNapiCoerceToBool(napi_env env, napi_callback_info info);
napi_value testNapiCoerceToNumber(napi_env env, napi_callback_info info);
napi_value testNapiCoerceToObject(napi_env env, napi_callback_info info);
napi_value testNapiCoerceToString(napi_env env, napi_callback_info info);
napi_value testNapiTypeof(napi_env env, napi_callback_info info);

void jsAbstractOpsInit(napi_property_descriptor **origDescPtr, size_t *len);

napi_value jsValuesInit(napi_env env, napi_value exports);
napi_value testNapiCreateInt32(napi_env env, napi_callback_info info);
napi_value testNapiCreateUInt32(napi_env env, napi_callback_info info);
napi_value testNapiCreateInt64(napi_env env, napi_callback_info info);

#endif //NAPITUTORIALS_JAVASCRIPTAPI_H
