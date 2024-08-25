/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NAPITUTORIALS_COMMON_H
#define NAPITUTORIALS_COMMON_H

#include <string>
#include <stdio.h>
#include <js_native_api.h>
#include <js_native_api_types.h>
#include <vector>
#include "hilog/log.h"
#include "napi/native_api.h"
#include "rawfile/raw_file_manager.h"
#include "rawfile/raw_file.h"
#include "rawfile/raw_dir.h"

#define GLOBAL_RESMGR (0xFFEE)
constexpr int32_t RGB_565 = 2;
constexpr int32_t RGBA_8888 = 3;

constexpr int32_t STR_MAX_SIZE = 200;
constexpr int32_t LONG_STR_MAX_SIZE = 1024;
constexpr int32_t ERR_OK = 0;
constexpr int8_t NO_ERROR = 0;
constexpr int8_t ERROR = -1;
constexpr uint8_t PARAM0 = 0;
constexpr uint8_t PARAM1 = 1;
constexpr uint8_t PARAM2 = 2;
constexpr uint8_t PARAM3 = 3;
constexpr uint8_t PARAM4 = 4;
constexpr uint8_t PARAM5 = 5;
constexpr uint8_t PARAM6 = 6;
constexpr uint8_t PARAM7 = 7;
constexpr uint8_t PARAM8 = 8;
constexpr uint8_t PARAM9 = 9;
constexpr uint8_t PARAM10 = 10;
constexpr uint8_t PARAM11 = 11;
constexpr uint8_t PARAM12 = 12;
constexpr uint8_t PARAM60 = 60;
constexpr uint8_t PARAM100 = 100;
constexpr uint16_t PARAM1000 = 1000;
constexpr uint32_t PARAM100W = 1000000;

constexpr int32_t ARGS_ONE = 1;
constexpr int32_t ARGS_TWO = 2;
constexpr int32_t ONLY_CALLBACK_MAX_PARA = 1;
constexpr int32_t ONLY_CALLBACK_MIN_PARA = 0;

enum TestCaseTypes {
    TCT_BASE = 1,
    TCT_NADATATYPE,
    TCT_NAENVLCAPI,
    TCT_JSABSTARCTOPS,
    TCT_JSPREOPERTY,
    TCT_JSVALUES,
    TCT_CJSON,
    TCT_FFMPEG,
    TCT_OPENCV
};

struct CallbackPromiseInfo {
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    bool isCallback = false;
    int32_t errorCode = 0;
};

template <typename T> void FreeMemory(T *p)
{
    if (p == nullptr) {
        return;
    }
    delete p;
    p = nullptr;
}

template <typename T> void FreeMemoryArray(T *p)
{
    if (p == nullptr) {
        return;
    }
    delete[] p;
    p = nullptr;
}
#define NAPI_RETVAL_NOTHING

extern bool CreateArrayBuffer(napi_env env, uint8_t *src, size_t srcLen, napi_value *res);
extern napi_value NapiGetUndefined(napi_env env);
extern napi_value GetCallbackErrorValue(napi_env env, int32_t errCode);
extern napi_value NapiGetBoolean(napi_env env, const bool &isValue);

extern void SetCallback(const napi_env &env, const napi_ref &callbackIn, const int32_t &errorCode,
                        const napi_value &result);
extern void SetPromise(const napi_env &env, const napi_deferred &deferred, const int32_t &errorCode,
                       const napi_value &result);
extern void ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result);
extern napi_value JSParaError(const napi_env &env, const napi_ref &callback);
extern void PaddingCallbackPromiseInfo(const napi_env &env, const napi_ref &callback, CallbackPromiseInfo &info,
                                       napi_value &promise);

void getErrMsg(napi_status &status, napi_env &env, const napi_extended_error_info *&extended_error_info,
               const char *info, const char *tag);
napi_status napiValueType2Str(const napi_env &env, const napi_valuetype type, napi_value *result);

#endif //NAPITUTORIALS_COMMON_H
