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

#include "cJsonNapiH/cjsonnapi.h"

char *getCjsonPrintRes(napi_env env, napi_value obj)
{
    const char *tag = "[KH735_cJSON_Print]";
    // 创建一个JSON对象
    cJSON *jsonObject = cJSON_CreateObject();
    jsonObject = initCJSON_Object(env, obj, jsonObject, tag);
    char *genResString1 = cJSON_Print(jsonObject);
    char *resultStr = genResString1;
    bool isNullObj = false;
    if (genResString1 != NULL) {
        std::string genResStringPrint = genResString1;
        RemoveNewlines(genResStringPrint);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "KH735_cJSON_Print", "genResString1: %s",
            genResStringPrint.c_str());
        if (genResStringPrint == "{}") {
            isNullObj = true;
        }
    }

    bool isArrNull = false;
    cJSON *jsonArray = cJSON_CreateArray();
    jsonArray = initCJSON_Array(env, obj, jsonArray, tag, false);
    char *genResString2 = cJSON_Print(jsonArray);
    if (genResString2 != NULL) {
        std::string genResStringPrint = genResString2;
        RemoveNewlines(genResStringPrint);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "KH735_cJSON_Print", "genResString2: %s",
            genResStringPrint.c_str());
        if (genResStringPrint == "[]") {
            isArrNull = true;
        }
    }

    bool isArrObjNull = false;
    cJSON *jsonArrayObj = cJSON_CreateArray();
    jsonArrayObj = initCJSON_ArrayObj(env, obj, jsonArrayObj, tag, true);
    char *genResString3 = cJSON_Print(jsonArrayObj);
    if (genResString3 != NULL) {
        std::string genResStringPrint = genResString3;
        RemoveNewlines(genResStringPrint);
        if (genResStringPrint == "[]") {
            isArrObjNull = true;
        }
    }
    bool isArrayObject = isArrObject(env, obj, tag);
    if (!isArrObjNull && isArrayObject) {
        resultStr = genResString3;
    } else if (!isArrNull) {
        resultStr = genResString2;
    }
    // 清理cJSON对象
    cJSON_Delete(jsonObject);
    return resultStr;
}

/* [NAPI_GEN]:对应cJSON.h中: CJSON_PUBLIC(char *) cJSON_Print(const cJSON *item);的napi方法，
 * 输入一个cJSON对象
 * 输出该对象序列化之后的字符串
 */
napi_value KH735_cJSON_Print(napi_env env, napi_callback_info info)
{
    napi_status status;
    /* [NAPI_GEN]: Node.js在其N-API中用来提供错误的扩展信息的结构体,结构体包含以下字段
     * error_message: 一个指向错误详细字符串的指针，提供了关于错误的文本描述
     * engin_reserved: 一个保留给Js引擎使用的指针
     * error_code: 错误码，指示了错误的种类，比如napi_pending_exception表示有一个JavaScript异常未被清理。
     * engine_error_code：一个引擎特定的错误码，为引擎实现保留，具体含义依赖于使用的JavaScript引擎。
     * error_message_len：错误消息字符串的长度。
     */
    const napi_extended_error_info *extended_error_info;
    /* [NAPI_GEN]: tag: 日志打印标签*/
    const char *tag = "[KH735_cJSON_Print]";
    /* [NAPI_GEN]: get function param in*/
    /* [NAPI_GEN]: argc：js传入的参数个数 */
    size_t argc = PARAMS1;
    /* [NAPI_GEN]: args: 一个数组,保存js传入的参数 */
    napi_value args[PARAMS1] = {nullptr};
    /* [NAPI_GEN]: napi_get_cb_info用于获取JS调用该函数时所传递的参数、接收参数的个数以及'this'的值
     * env: 当前环境的句柄，代表当前的Node.js环境
     * info: 回调信息句柄，代表当前回调的上下文
     * argc: 指向size_t的指针，最初应包含可接受的最大参数数量，函数返回时，它将包含实际传递的参数数量
     * args: 一个足够大的数组，用于接收传递给回调函数的所有js参数。数组的大小应至少与argc传入的值一样大。
     * this_arg: 如果不是NULL,则返回js回调中this的值
     * data: 如果不是NULL,则返回与回调函数关联的任何可选数据。通常用于传递在创建函数时指定的静态数据
     */
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_get_cb_info", tag);
        return NULL;
    }
  
    // Todo: add business logic. 在这之前代码为框架所生成
    char *resultStr = getCjsonPrintRes(env, args[PARAMS0]);
    
    /* [NAPI_GEN]: function return value*/
    napi_value cJSON_PrintOut;
    /* [NAPI_GEN]:
     * 返回值是字符串时，napi_create_string_utf8用于在原生代码中创建一个新的js字符串。这个函数会根据提供的UTF-8编码的字符串创建一个等价的js字符串
     * env: 当前环境的句柄
     * str: 指向以null结尾的UTF-8编码的C字符串的指针，这里以cJSON_Print举例，用户可根据需求修改
     * length:
     * 字符串的长度，可以是具体的字节数，或者使用特殊的值NAPI_AUTO_LENGTH来让函数自己计算长度(假定字符串以null结尾)
     * result: 指向napi_value的指针，函数执行成功后这个指针将指向新创建的js字符串
     */
    status = napi_create_string_utf8(env, resultStr, NAPI_AUTO_LENGTH, &cJSON_PrintOut);
    if (status != napi_ok) {
        /*错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_create_string_utf8", tag);
        return NULL;
    }

    return cJSON_PrintOut;
}
