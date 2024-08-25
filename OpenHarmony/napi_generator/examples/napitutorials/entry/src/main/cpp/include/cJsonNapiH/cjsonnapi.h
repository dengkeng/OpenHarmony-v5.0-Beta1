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

#ifndef NAPITUTORIALS_CJSONNAPI_H
#define NAPITUTORIALS_CJSONNAPI_H

#include "cjsoncommon.h"

/* [NAPI_GEN]:对应cJSON.h中：cJSON_Parse的napi方法，
 * 输入：value: const char *;
 * 输出：cJSON *
 */
napi_value KH418_CJSON_Parse(napi_env env, napi_callback_info info);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_GetArraySize的napi方法，
 * 输入：array: const cJSON *;
 * 输出：int
 */
napi_value KH373_cJSON_GetArraySize(napi_env env, napi_callback_info info);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_Print的napi方法，
 * 输入：item: const cJSON *;
 * 输出：char *
 */
napi_value KH735_cJSON_Print(napi_env env, napi_callback_info info);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_CreateObject的napi方法，
 * 输入：void
 * 输出：cJSON *
 */
napi_value KH361_cJSON_CreateObject(napi_env env, napi_callback_info info);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_CreateString的napi方法，
 * 输入：string: const char *;
 * 输出：cJSON *
 */
napi_value KH515_cJSON_CreateString(napi_env env, napi_callback_info info);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_AddStringToObject的napi方法，
 * 输入：object: cJSON * const; name: const char * const; string: const char * const;
 * 输出：cJSON *
 */
napi_value KH526_cJSON_AddStringToObject(napi_env env, napi_callback_info info);
/* [NAPI_GEN]:对应cJSON.h中：cJSON_AddNumberToObject的napi方法，
 * 输入：object: cJSON * const; name: const char * const; number: const double;
 * 输出：cJSON *
 */
napi_value KH206_cJSON_AddNumberToObject(napi_env env, napi_callback_info info);
/* [NAPI_GEN]:对应cJSON.h中：cJSON_AddFalseToObject的napi方法，
 * 输入：object: cJSON * const; name: const char * const;
 * 输出：cJSON *
 */
napi_value KH545_cJSON_AddFalseToObject(napi_env env, napi_callback_info info);

/* 将C++ cJSON对象返回js层
 * 输入：待返回的js对象，c++ cJSON对象
 * 输出：返回js的对象
 */
napi_value getAdditemtoobjChildOut(napi_env env, napi_value cJSON_AddItemToObjectOut, cJSON *jsonObj);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_AddItemToObject的napi方法，
 * 输入：object: cJSON *; string: const char *; item: cJSON *;
 * 输出：int
 */
napi_value KH180_cJSON_AddItemToObject(napi_env env, napi_callback_info info);

/* 将C++ cJSON对象返回js层
 * 输入：待返回的js对象，c++ cJSON对象
 * 输出：返回js的对象
 */
napi_value getAdditemtoarrChildOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonObj);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_CreateArray的napi方法，
 * 输入：void
 * 输出：cJSON *
 */
napi_value KH386_cJSON_CreateArray(napi_env env, napi_callback_info info);
/* [NAPI_GEN]:对应cJSON.h中：cJSON_CreateIntArray的napi方法，
 * 输入：numbers: const int *; count: int;
 * 输出：cJSON *
 */
napi_value KH203_cJSON_CreateIntArray(napi_env env, napi_callback_info info);

/* [NAPI_GEN]:对应cJSON.h中：cJSON_AddItemToArray的napi方法，
 * 输入：array: cJSON *; item: cJSON *;
 * 输出：int
 */
napi_value KH802_cJSON_AddItemToArray(napi_env env, napi_callback_info info);

#endif // NAPITUTORIALS_CJSONNAPI_H