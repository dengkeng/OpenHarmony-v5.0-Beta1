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

#ifndef NAPITUTORIALS_CJSONCOMMON_H
#define NAPITUTORIALS_CJSONCOMMON_H

#include <js_native_api.h>
#include <js_native_api_types.h>
#include <string>
#include <stdio.h>
#include <vector>
#include "hilog/log.h"
#include "napi/native_api.h"
#include "cjson/cJSON.h"

#define GLOBAL_RESMGR (0xFFEE)
const unsigned int LOG_PRINT_DOMAIN = 0xFF00;

constexpr int32_t STR_MAX_SIZES = 200;
constexpr int32_t LONG_STR_MAX_SIZES = 1024;

constexpr uint8_t PARAMS0 = 0;
constexpr uint8_t PARAMS1 = 1;
constexpr uint8_t PARAMS2 = 2;
constexpr uint8_t PARAMS3 = 3;
constexpr uint8_t PARAMS4 = 4;
constexpr uint8_t PARAMS5 = 5;
constexpr uint8_t PARAMS6 = 6;
constexpr uint8_t PARAMS7 = 7;
constexpr uint8_t PARAMS8 = 8;
constexpr uint8_t PARAMS9 = 9;
constexpr uint8_t PARAMS10 = 10;
constexpr uint8_t PARAMS11 = 11;
constexpr uint8_t PARAMS12 = 12;
constexpr uint8_t PARAMS100 = 100;

void getErrMessage(napi_status &status, napi_env &env, const napi_extended_error_info *&extended_error_info,
    const char *info, const char *tag);

/* 去除字符串中的换行符，便于查找打印, 公共方法
 * str: 待去除\n的字符串
 */
void RemoveNewlines(std::string &str);

/* 检查JavaScript对象是否为空（不含自己的属性），公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * obj: 类型是napi_object
 * tag: 日志打印标识符
 */
bool IsEmptyObject(napi_env env, napi_value obj, const char *tag);

/* 在native初始化js传递的对象， 公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象
 * jsonObj: 待初始化的native层cJSON对象
 * tag: 日志打印标识符
 */
cJSON *initCJSON_Object(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag);

/* 在native初始化js传递的对象， 公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象,该对象表示一个数组,如：[{"name":"ann"},{"name":"john"}]
 * jsonObj: 待初始化的native层cJSON对象
 * tag: 日志打印标识符
 * flag: true表示判断是普通array,如：[2,-3,6];false表示判断数组元素是否是对象，如：[{"name":"ann"},{"name":"john"}]
 * return cJSON: 返回c++ cJSON对象
 */
cJSON *initCJSON_ArrayObj(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag, bool flag);

/* 在native初始化js传递的对象， 公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象,该对象表示一个基本类型的数组，如[9,-2,7]
 * jsonObj: 待初始化的native层cJSON对象
 * tag: 日志打印标识符
 * flag: true表示判断是普通array,如：[2,-3,6];false表示判断数组元素是否是对象，如：[{"name":"ann"},{"name":"john"}]
 * return cJSON: 返回c++ cJSON对象
 */
cJSON *initCJSON_Array(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag, bool flag);

/* 判断是单纯对象还是arrObj或objArr
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象
 * tag: 日志打印标识
 * return 布尔值：若对象是array object或者object array返回true,如[{"name":"john"}]或{"testArr":[9,8,7]}
 */
bool isArrObject(napi_env env, napi_value cjsonObj, const char *tag);

#endif // NAPITUTORIALS_CJSONCOMMON_H