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
#include <bits/alltypes.h>

napi_value getCreateintarrTypeOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value typeOut;
    /* [NAPI_GEN]: 返回值是int32_t类型时，napi_create_int32 创建一个包含32位整数(int32_t)的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要准换成js数值的int32_t的值,这里以传入1为例,用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_int32(env, jsonObj == NULL ? 0 : jsonObj->type, &typeOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32", tag);
        return NULL;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "type", typeOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

napi_value getCreateintarrValuesintOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value valueintOut;
    /* [NAPI_GEN]: 返回值是int32_t类型时，napi_create_int32 创建一个包含32位整数(int32_t)的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要准换成js数值的int32_t的值,这里以传入1为例,用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_int32(env, jsonObj == NULL ? 0 : jsonObj->valueint, &valueintOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32", tag);
        return NULL;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "valueint", valueintOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

napi_value getCreateintarrValuesdoubleOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value valuedoubleOut;
    /* [NAPI_GEN]: 返回值是double类型时，napi_create_double 创建一个包含双精度浮点数的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要传递给js的双精度浮点数值,这里以传入1.0为例，用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_double(env, jsonObj == NULL ? 0 : jsonObj->valuedouble, &valuedoubleOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_double", tag);
        return NULL;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "valuedouble", valuedoubleOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

napi_value getCreateintarrValuestringOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value valuestringOut;
    /* [NAPI_GEN]:
     * 返回值是字符串时，napi_create_string_utf8用于在原生代码中创建一个新的js字符串。这个函数会根据提供的UTF-8编码的字符串创建一个等价的js字符串
     * env: 当前环境的句柄
     * str: 指向以null结尾的UTF-8编码的C字符串的指针，这里以valuestring举例，用户可根据需求修改
     * length:
     * 字符串的长度，可以是具体的字节数，或者使用特殊的值NAPI_AUTO_LENGTH来让函数自己计算长度(假定字符串以null结尾)
     * result: 指向napi_value的指针，函数执行成功后这个指针将指向新创建的js字符串
     */
    status = napi_create_string_utf8(env, jsonOut->valuestring == nullptr ? "" : jsonOut->valuestring, NAPI_AUTO_LENGTH,
                                     &valuestringOut);
    if (status != napi_ok) {
        /*错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_create_string_utf8", tag);
        return NULL;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "valuestring", valuestringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

napi_value getCreateintarrStringOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value stringOut;
    /* [NAPI_GEN]:
     * 返回值是字符串时，napi_create_string_utf8用于在原生代码中创建一个新的js字符串。这个函数会根据提供的UTF-8编码的字符串创建一个等价的js字符串
     * env: 当前环境的句柄
     * str: 指向以null结尾的UTF-8编码的C字符串的指针，这里以string举例，用户可根据需求修改
     * length:
     * 字符串的长度，可以是具体的字节数，或者使用特殊的值NAPI_AUTO_LENGTH来让函数自己计算长度(假定字符串以null结尾)
     * result: 指向napi_value的指针，函数执行成功后这个指针将指向新创建的js字符串
     */
    status =
        napi_create_string_utf8(env, jsonOut->string == nullptr ? "" : jsonOut->string, NAPI_AUTO_LENGTH, &stringOut);
    if (status != napi_ok) {
        /*错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_create_string_utf8", tag);
        return NULL;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "string", stringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

napi_value getCreateintarrNextOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value nextOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &nextOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return NULL;
    }
    // 给jsonObj->next赋值
    if (jsonObj == NULL) {
        return NULL;
    }
    if (jsonObj->next != NULL) {
        nextOut = getCreateintarrTypeOut(env, nextOut, jsonObj->next);
        nextOut = getCreateintarrValuesdoubleOut(env, nextOut, jsonObj->next);
        nextOut = getCreateintarrValuesintOut(env, nextOut, jsonObj->next);
        nextOut = getCreateintarrValuestringOut(env, nextOut, jsonObj->next);
        nextOut = getCreateintarrStringOut(env, nextOut, jsonObj->next);
        if (jsonObj->next->next != NULL) {
            cJSON *nextNext = jsonObj->next->next;
            if (nextNext != NULL) {
                nextOut = getCreateintarrNextOut(env, nextOut, jsonObj->next);
            }
        }
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "next", nextOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

napi_value getJsonobjitemChildOut(napi_env env, napi_value childOut, cJSON *jsonObj)
{
    if (jsonObj->child != NULL) {
        childOut = getCreateintarrTypeOut(env, childOut, jsonObj->child);
        childOut = getCreateintarrValuesdoubleOut(env, childOut, jsonObj->child);
        childOut = getCreateintarrValuesintOut(env, childOut, jsonObj->child);
        childOut = getCreateintarrValuestringOut(env, childOut, jsonObj->child);
        childOut = getCreateintarrStringOut(env, childOut, jsonObj->child);
        if (jsonObj->child->next != NULL) {
            cJSON *childNext = jsonObj->child->next;
            if (childNext != NULL) {
                childOut = getCreateintarrNextOut(env, childOut, jsonObj->child);
            }
        }
    }
    return childOut;
}

napi_value getCreateintarrChildOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value childOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &childOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return NULL;
    }
    // 给jsonObj->child赋值
    if (jsonObj != NULL) {
        childOut = getJsonobjitemChildOut(env, childOut, jsonObj);
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "child", childOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

napi_value getCreateintarrPrevOut(napi_env env, napi_value cJSON_CreateIntArrayOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    napi_value prevOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &prevOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return NULL;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_CreateIntArrayOut, "prev", prevOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return NULL;
    }
    return cJSON_CreateIntArrayOut;
}

uint32_t getCjsonObjArrayLen(napi_env env, napi_value param)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    // 确保传递的是一个数组
    bool isArray = false;
    status = napi_is_array(env, param, &isArray);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_is_array", tag);
        return status;
    }
    if (!isArray) {
        return NULL;
    }
    // 获取数组长度
    uint32_t outerLen = 0;
    status = napi_get_array_length(env, param, &outerLen);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_get_array_length", tag);
        return NULL;
    }
    return outerLen;
}

napi_status GetCjsonCreateArrayParams1(napi_env env, napi_value param, int **outArrayNumbers, uint32_t *outLen)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    uint32_t outerLen = getCjsonObjArrayLen(env, param);
    // 分配内存给输出数组前的校验
    if (outerLen == 0 || outerLen > (UINT_MAX / sizeof(int))) {
        // outerLen 为0或者乘以sizeof(int)后超过了最大可分配的内存块大小
        return napi_generic_failure;
    }
    int *tempArrayNumbers = (int *)malloc(sizeof(int) * outerLen);
    if (tempArrayNumbers == NULL) {
        // 内存分配失败，处理错误
        return napi_generic_failure;
    }
    // 如果校验和分配都成功，设置输出参数指向新分配的内存
    *outArrayNumbers = tempArrayNumbers;
    // 遍历数组
    for (uint32_t i = 0; i < outerLen; i++) {
        napi_value v;
        status = napi_get_element(env, param, i, &v);
        if (status != napi_ok) {
            free(*outArrayNumbers);
            getErrMessage(status, env, extended_error_info, "napi_get_array_length", tag);
            return status;
        }
        // 确保数组中的元素是数字
        napi_valuetype valuetypeNumber;
        status = napi_typeof(env, v, &valuetypeNumber);
        if (status != napi_ok) {
            free(*outArrayNumbers);
            getErrMessage(status, env, extended_error_info, "napi_typeof", tag);
            return status;
        }
        if (valuetypeNumber == napi_number) {
            int32_t num;
            status = napi_get_value_int32(env, v, &num);
            if (status != napi_ok) {
                free(*outArrayNumbers);
                getErrMessage(status, env, extended_error_info, "napi_get_array_length", tag);
                return status;
            }
            (*outArrayNumbers)[i] = num;
        } else {
            free(*outArrayNumbers);
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH203_cJSON_CreateIntArray", "get params fail");
            return napi_number_expected;
        }
    }
    // 设置输出数组长度
    *outLen = outerLen;
    return napi_ok;
}

int32_t GetCjsonCreateArrayParams2(napi_env env, napi_value param)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH203_cJSON_CreateIntArray]";

    napi_valuetype valuetypecount;
    /* [NAPI_GEN]: 获取入参类型，第1个入参
     * env: N-API环境的句柄，表示当前的上下文
     * value: 要检查类型的js值
     * result: 是一个指针，指向napi_valuetype枚举的值，函数会将结果存储在这里
     */
    status = napi_typeof(env, param, &valuetypecount);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_typeof", tag);
        return NULL;
    }
    int32_t countIn = 0;
    /* [NAPI_GEN]: napi_get_value_int32将一个 napi_value 类型的 js 数值转换成一个 C 语言的 int32_t 类型的数值
     * env: N-API环境的句柄，表示当前的上下文
     * value：要转换的JavaScript值
     * result：指向 int32_t 类型的指针，在这里函数将存储转换后的整数值
     */
    status = napi_get_value_int32(env, param, &countIn);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_get_value_int32", tag);
        return NULL;
    }
    return countIn;
}

/* [NAPI_GEN]:对应cJSON.h中: CJSON_PUBLIC(cJSON *) cJSON_CreateIntArray(const int *numbers, int count); 的napi方法
 * 输入：一个number数组，number数组中元素的数量
 * 输出：创建的cJSON数组
 */
napi_value KH203_cJSON_CreateIntArray(napi_env env, napi_callback_info info)
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
    const char *tag = "[KH203_cJSON_CreateIntArray]";
    /* [NAPI_GEN]: get function param in*/
    /* [NAPI_GEN]: argc：js传入的参数个数 */
    size_t argc = PARAMS2;
    /* [NAPI_GEN]: args: 一个数组,保存js传入的参数 */
    napi_value args[PARAMS2] = {nullptr};
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
    
    int *arrayNumbers = NULL;
    uint32_t arrayLength = 0;
    status = GetCjsonCreateArrayParams1(env, args[PARAMS0], &arrayNumbers, &arrayLength);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_get_cb_info", tag);
        return NULL;
    }
    uint32_t countIn = GetCjsonCreateArrayParams2(env, args[PARAMS1]);
    
    // Todo: add business logic. 在这前后代码为框架所生成
    cJSON *arrayRes = NULL;
    arrayRes = cJSON_CreateIntArray(arrayNumbers, countIn);
    free(arrayNumbers);
    // 打印arrayRes2
    char *arrayString2 = cJSON_Print(arrayRes);
    if (arrayString2 == NULL) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH203_cJSON_CreateIntArray", "cJSON_Print failed");
        cJSON_free(arrayString2); // 释放 cJSON_Print 分配的内存
        return NULL;
    } else {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "KH203_cJSON_CreateIntArray", "arrayString2: %s",
            arrayString2);
        cJSON_free(arrayString2); // 释放 cJSON_Print 分配的内存
    }

    /* [NAPI_GEN]: function return value*/
    napi_value cJSON_CreateIntArrayOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &cJSON_CreateIntArrayOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return NULL;
    }
    
    cJSON_CreateIntArrayOut = getCreateintarrChildOut(env, cJSON_CreateIntArrayOut, arrayRes);
    cJSON_CreateIntArrayOut = getCreateintarrNextOut(env, cJSON_CreateIntArrayOut, arrayRes);
    cJSON_CreateIntArrayOut = getCreateintarrPrevOut(env, cJSON_CreateIntArrayOut, arrayRes);
    cJSON_CreateIntArrayOut = getCreateintarrTypeOut(env, cJSON_CreateIntArrayOut, arrayRes);
    cJSON_CreateIntArrayOut = getCreateintarrValuesdoubleOut(env, cJSON_CreateIntArrayOut, arrayRes);
    cJSON_CreateIntArrayOut = getCreateintarrValuesintOut(env, cJSON_CreateIntArrayOut, arrayRes);
    cJSON_CreateIntArrayOut = getCreateintarrValuestringOut(env, cJSON_CreateIntArrayOut, arrayRes);
    cJSON_CreateIntArrayOut = getCreateintarrStringOut(env, cJSON_CreateIntArrayOut, arrayRes);

    return cJSON_CreateIntArrayOut;
}
