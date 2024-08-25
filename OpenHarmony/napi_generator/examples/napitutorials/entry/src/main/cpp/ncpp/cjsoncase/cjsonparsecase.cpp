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

napi_value getCjsonChildOut2(napi_env env, napi_value childOut, cJSON *jsonChild)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    napi_value childTypeOut;
    status = napi_create_int32(env, jsonChild->type, &childTypeOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32 jsonChild->type", tag);
        return nullptr;
    }
    status = napi_set_named_property(env, childOut, "type", childTypeOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonChild->type", tag);
        return nullptr;
    }
    napi_value childValueintOut;
    status = napi_create_int32(env, jsonChild->valueint, &childValueintOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32 jsonChild->valueint", tag);
        return nullptr;
    }
    status = napi_set_named_property(env, childOut, "valueint", childValueintOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonChild->valueint", tag);
        return nullptr;
    }
    napi_value childValuedoubleOut;
    status = napi_create_double(env, jsonChild->valuedouble, &childValuedoubleOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_double jsonChild->valuedouble", tag);
        return nullptr;
    }
    status = napi_set_named_property(env, childOut, "valuedouble", childValuedoubleOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonChild->valuedouble", tag);
        return nullptr;
    }
    return childOut;
}

napi_value getCjsonChildOut(napi_env env, napi_value childOut, cJSON *jsonChild)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    // 将数据塞入child
    if (jsonChild != nullptr) {
        napi_value childValuestringOut;
        status = napi_create_string_utf8(env, jsonChild->valuestring == nullptr ? "" : jsonChild->valuestring,
                                         NAPI_AUTO_LENGTH, &childValuestringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_create_string_utf8 jsonChild->valuestring", tag);
            return nullptr;
        }
        status = napi_set_named_property(env, childOut, "valuestring", childValuestringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonChild->valuestring", tag);
            return nullptr;
        }
        napi_value childStringOut;
        status = napi_create_string_utf8(env, jsonChild->string == nullptr ? "" : jsonChild->string, NAPI_AUTO_LENGTH,
                                         &childStringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_create_string_utf8 jsonChild->string", tag);
            return nullptr;
        }
        status = napi_set_named_property(env, childOut, "string", childStringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonChild->string", tag);
            return nullptr;
        }
        childOut = getCjsonChildOut2(env, childOut, jsonChild);
    }
    return childOut;
}

napi_value getCjsonNextOut2(napi_env env, napi_value nextOut, cJSON *jsonNext)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    napi_value nextTypeOut;
    status = napi_create_int32(env, jsonNext->type, &nextTypeOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32 jsonNext->type", tag);
        return nullptr;
    }
    status = napi_set_named_property(env, nextOut, "type", nextTypeOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonNext->type", tag);
        return nullptr;
    }
    napi_value nextValueintOut;
    status = napi_create_int32(env, jsonNext->valueint, &nextValueintOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32 jsonNext->valueint", tag);
        return nullptr;
    }
    status = napi_set_named_property(env, nextOut, "valueint", nextValueintOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonNext->valueint", tag);
        return nullptr;
    }
    napi_value nextValuedoubleOut;
    status = napi_create_double(env, jsonNext->valuedouble, &nextValuedoubleOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_double jsonNext->valuedouble", tag);
        return nullptr;
    }
    status = napi_set_named_property(env, nextOut, "valuedouble", nextValuedoubleOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonNext->valuedouble", tag);
        return nullptr;
    }
    return nextOut;
}

napi_value getCjsonNextOut(napi_env env, napi_value nextOut, cJSON *jsonNext)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    // 将数据塞入next
    if (jsonNext != nullptr) {
        napi_value nextValuestringOut;
        status = napi_create_string_utf8(env, jsonNext->valuestring == nullptr ? "" : jsonNext->valuestring,
                                         NAPI_AUTO_LENGTH, &nextValuestringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_create_string_utf8 jsonNext->valuestring", tag);
            return nullptr;
        }
        status = napi_set_named_property(env, nextOut, "valuestring", nextValuestringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonNext->valuestring", tag);
            return nullptr;
        }
        napi_value nextStringOut;
        status = napi_create_string_utf8(env, jsonNext->string == nullptr ? "" : jsonNext->string, NAPI_AUTO_LENGTH,
                                         &nextStringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_create_string_utf8 jsonNext->string", tag);
            return nullptr;
        }
        status = napi_set_named_property(env, nextOut, "string", nextStringOut);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "napi_set_named_property jsonNext->string", tag);
            return nullptr;
        }
        nextOut = getCjsonNextOut2(env, nextOut, jsonNext);
    }
    return nextOut;
}

char *getCjsonparseInfo(napi_env env, napi_value objIn)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    /* [NAPI_GEN]: 从args数组中获取入参 */
    napi_valuetype valuetypevalue;
    /* [NAPI_GEN]: 获取入参类型，第0个入参
     * env: N-API环境的句柄，表示当前的上下文
     * value: 要检查类型的js值
     * result: 是一个指针，指向napi_valuetype枚举的值，函数会将结果存储在这里
     */
    status = napi_typeof(env, objIn, &valuetypevalue);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_typeof", tag);
        return nullptr;
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
    status = napi_get_value_string_utf8(env, objIn, NULL, 0, &strSize0);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        return nullptr;
    }
    char *valueIn = new char[strSize0 + 1];
    /* [NAPI_GEN]: 用于获取字符串*/
    status = napi_get_value_string_utf8(env, objIn, valueIn, strSize0 + 1, &strSize0);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        delete[] valueIn;
        return nullptr;
    }
    return valueIn;
}

napi_value getCjsonparseOut1(napi_env env, cJSON *jsonNext, napi_value cJSON_ParseOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    napi_value nextOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &nextOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return nullptr;
    }
    nextOut = getCjsonNextOut(env, nextOut, jsonNext);
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "next", nextOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    napi_value prevOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &prevOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "prev", prevOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_ParseOut;
}

napi_value getCjsonparseOut2(napi_env env, cJSON *json, cJSON *jsonChild, napi_value cJSON_ParseOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    napi_value childOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &childOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return nullptr;
    }
    childOut = getCjsonChildOut(env, childOut, jsonChild);
    /* [NAPI_GEN]:
     * 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js env:
     * 当前环境的句柄 object: 要设置属性的js对象，该对象是由上文napi_create_object创建的 utf8name:
     * 属性的名称，是一个以UTF-8编码的字符串 value:
     * 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "child", childOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    napi_value typeOut;
    /* [NAPI_GEN]: 返回值是int32_t类型时，napi_create_int32 创建一个包含32位整数(int32_t)的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要准换成js数值的int32_t的值,这里以传入1为例,用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_int32(env, json == nullptr ? 0 : json->type, &typeOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32", tag);
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "type", typeOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_ParseOut;
}

napi_value getCjsonparseOut3(napi_env env, cJSON *json, napi_value cJSON_ParseOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    napi_value valuestringOut;
    /* [NAPI_GEN]:
     * 返回值是字符串时，napi_create_string_utf8用于在原生代码中创建一个新的js字符串。这个函数会根据提供的UTF-8编码的字符串创建一个等价的js字符串
     * env: 当前环境的句柄
     * str: 指向以null结尾的UTF-8编码的C字符串的指针，这里以valuestring举例，用户可根据需求修改
     * length:
     * 字符串的长度，可以是具体的字节数，或者使用特殊的值NAPI_AUTO_LENGTH来让函数自己计算长度(假定字符串以null结尾)
     * result: 指向napi_value的指针，函数执行成功后这个指针将指向新创建的js字符串
     */
    status =
        napi_create_string_utf8(env, json == nullptr ? "" : (json->valuestring == nullptr ? "" : json->valuestring),
                                NAPI_AUTO_LENGTH, &valuestringOut);
    if (status != napi_ok) {
        /*错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_create_string_utf8", tag);
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "valuestring", valuestringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    napi_value valueintOut;
    /* [NAPI_GEN]: 返回值是int32_t类型时，napi_create_int32 创建一个包含32位整数(int32_t)的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要准换成js数值的int32_t的值,这里以传入1为例,用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_int32(env, json == nullptr ? 0 : json->valueint, &valueintOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_int32", tag);
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "valueint", valueintOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_ParseOut;
}

napi_value getCjsonparseOut4(napi_env env, cJSON *json, napi_value cJSON_ParseOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH418_CJSON_Parse]";
    napi_value valuedoubleOut;
    /* [NAPI_GEN]: 返回值是double类型时，napi_create_double 创建一个包含双精度浮点数的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要传递给js的双精度浮点数值,这里以传入1.0为例，用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_double(env, json == nullptr ? 0 : json->valuedouble, &valuedoubleOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_double", tag);
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "valuedouble", valuedoubleOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    napi_value stringOut;
    /* [NAPI_GEN]:
     * 返回值是字符串时，napi_create_string_utf8用于在原生代码中创建一个新的js字符串。这个函数会根据提供的UTF-8编码的字符串创建一个等价的js字符串
     * env: 当前环境的句柄
     * str: 指向以null结尾的UTF-8编码的C字符串的指针，这里以string举例，用户可根据需求修改
     * length:
     * 字符串的长度，可以是具体的字节数，或者使用特殊的值NAPI_AUTO_LENGTH来让函数自己计算长度(假定字符串以null结尾)
     * result: 指向napi_value的指针，函数执行成功后这个指针将指向新创建的js字符串
     */
    status = napi_create_string_utf8(env, json == nullptr ? "" : (json->string == nullptr ? "" : json->string),
                                     NAPI_AUTO_LENGTH, &stringOut);
    if (status != napi_ok) {
        /*错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_create_string_utf8", tag);
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_ParseOut, "string", stringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_ParseOut;
}

/* [NAPI_GEN]: 对应cJSON.h中: CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value);的napi方法，
 * param: name: string; type: const char * 输入一个待转换的字符串
 * out: 输出cJSON序列化之后的字符串
 */
napi_value KH418_CJSON_Parse(napi_env env, napi_callback_info info)
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
    const char *tag = "[KH418_CJSON_Parse]";
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
    napi_value obj = args[0];
    char *valueIn = getCjsonparseInfo(env, obj);
    // Todo: add business logic. 在这前后代码为框架所生成
    cJSON *json = cJSON_Parse(valueIn);
    if (json == nullptr) {
        return nullptr;
    }
    cJSON *jsonChild = nullptr;
    if (json != nullptr) {
        jsonChild = json->child;
    }
    cJSON *jsonNext = nullptr;
    if (jsonChild != nullptr) {
        jsonNext = jsonChild->next;
    }

    delete[] valueIn;
    /* [NAPI_GEN]: function return value*/
    napi_value cJSON_ParseOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &cJSON_ParseOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return nullptr;
    }

    cJSON_ParseOut = getCjsonparseOut1(env, jsonNext, cJSON_ParseOut);
    cJSON_ParseOut = getCjsonparseOut2(env, json, jsonChild, cJSON_ParseOut);
    cJSON_ParseOut = getCjsonparseOut3(env, json, cJSON_ParseOut);
    cJSON_ParseOut = getCjsonparseOut4(env, json, cJSON_ParseOut);

    cJSON_Delete(json);
    return cJSON_ParseOut;
}
