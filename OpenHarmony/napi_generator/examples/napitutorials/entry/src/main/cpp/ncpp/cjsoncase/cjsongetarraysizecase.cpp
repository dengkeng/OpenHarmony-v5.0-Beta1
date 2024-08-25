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

/* [NAPI_GEN]:对应cJSON.h中: CJSON_PUBLIC(int) cJSON_GetArraySize(const cJSON *array);的napi方法，
 * 输入一个cJSON数组
 * 输出数组长度
 */
napi_value KH373_cJSON_GetArraySize(napi_env env, napi_callback_info info)
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
    const char *tag = "[KH373_cJSON_GetArraySize]";
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
        return nullptr;
    }
    /* [NAPI_GEN]: 从args数组中获取入参 */
    // Todo: add business logic. 在这前后代码为框架所生成
    // js传入的是一个cJSON对象， 如何拿到数组？数组保存在valuestring里面？
    napi_value arrayStringObj;
    status = napi_get_named_property(env, args[0], "valuestring", &arrayStringObj); // 读取属性
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get named property", tag);
        return NULL;
    }
    size_t strSize0 = 0;
    /* [NAPI_GEN]: napi_get_value_string_utf8用于将Js字符串转换为UTF-8编码的C字符串
     * env: N-API环境的句柄，表示当前的上下文
     * value: 要转换的JavaScript字符串
     * buf: 用于存储结果的字符数组的指针
     * bufsize: 缓冲区大小，以字节为单位
     * result: 转换后的字符串的字节长度(不包括空终止符)。若干buf是NULL,则返回所需的缓冲区大小(包括空终止符)
     */
    /* [NAPI_GEN]: buf参数是NULL时，用于获取所需缓冲区大小*/
    status = napi_get_value_string_utf8(env, arrayStringObj, NULL, 0, &strSize0);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        return nullptr;
    }
    char *stringArrayIn = new char[strSize0 + 1];
    /* [NAPI_GEN]: 用于获取字符串*/
    status = napi_get_value_string_utf8(env, arrayStringObj, stringArrayIn, strSize0 + 1, &strSize0);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        delete[] stringArrayIn;
        return nullptr;
    }
    
    cJSON *stringArray = cJSON_Parse(stringArrayIn);
    int32_t arrayLenOut = cJSON_GetArraySize(stringArray);
    
    delete[] stringArrayIn;
    cJSON_Delete(stringArray);
    /* [NAPI_GEN]: function return value*/
    napi_value cJSON_GetArraySizeOut;
    /* [NAPI_GEN]: 返回值是int32_t类型时，napi_create_int32 创建一个包含32位整数(int32_t)的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要准换成js数值的int32_t的值,这里以传入1为例,用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_int32(env, arrayLenOut, &cJSON_GetArraySizeOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32", tag);
        return nullptr;
    }

    return cJSON_GetArraySizeOut;
}
