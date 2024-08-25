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

napi_value getAddfalsetoobjTypeOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
    napi_value typeOut;
    /* [NAPI_GEN]: 返回值是int32_t类型时，napi_create_int32 创建一个包含32位整数(int32_t)的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要准换成js数值的int32_t的值,这里以传入1为例,用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_int32(env, jsonOut->type, &typeOut);
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
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "type", typeOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddFalseToObjectOut;
}

napi_value getAddfalsetoobjValuesintOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";

    napi_value valueintOut;
    /* [NAPI_GEN]: 返回值是int32_t类型时，napi_create_int32 创建一个包含32位整数(int32_t)的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要准换成js数值的int32_t的值,这里以传入1为例,用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_int32(env, jsonOut->valueint, &valueintOut);
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
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "valueint", valueintOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }

    return cJSON_AddFalseToObjectOut;
}

napi_value getAddfalsetoobjValuesdoubleOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
    napi_value valuedoubleOut;
    /* [NAPI_GEN]: 返回值是double类型时，napi_create_double 创建一个包含双精度浮点数的js数值（Number）对象
     * env: 当前环境的句柄
     * value: 要传递给js的双精度浮点数值,这里以传入1.0为例，用例新增业务代码时可根据自身需求修改
     * result: 指向napi_value的指针，这个指针会被设置为新创建的js数值对象
     */
    status = napi_create_double(env, jsonOut->valuedouble, &valuedoubleOut);
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
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "valuedouble", valuedoubleOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddFalseToObjectOut;
}

napi_value getAddfalsetoobjValuestringOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
    napi_value valuestringOut;
    /* [NAPI_GEN]:
     * 返回值是字符串时，napi_create_string_utf8用于在原生代码中创建一个新的js字符串。这个函数会根据提供的UTF-8编码的字符串创建一个等价的js字符串
     * env: 当前环境的句柄
     * str: 指向以null结尾的UTF-8编码的C字符串的指针，这里以valuestring举例，用户可根据需求修改
     * length:
     * 字符串的长度，可以是具体的字节数，或者使用特殊的值NAPI_AUTO_LENGTH来让函数自己计算长度(假定字符串以null结尾)
     * result: 指向napi_value的指针，函数执行成功后这个指针将指向新创建的js字符串
     */
    status = napi_create_string_utf8(env, jsonObj->valuestring == NULL ? "" : jsonObj->valuestring,
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
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "valuestring", valuestringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddFalseToObjectOut;
}

napi_value getAddfalsetoobjStringOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonOut)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
    napi_value stringOut;
    /* [NAPI_GEN]:
     * 返回值是字符串时，napi_create_string_utf8用于在原生代码中创建一个新的js字符串。这个函数会根据提供的UTF-8编码的字符串创建一个等价的js字符串
     * env: 当前环境的句柄
     * str: 指向以null结尾的UTF-8编码的C字符串的指针，这里以string举例，用户可根据需求修改
     * length:
     * 字符串的长度，可以是具体的字节数，或者使用特殊的值NAPI_AUTO_LENGTH来让函数自己计算长度(假定字符串以null结尾)
     * result: 指向napi_value的指针，函数执行成功后这个指针将指向新创建的js字符串
     */
    status = napi_create_string_utf8(env, jsonOut->string == NULL ? "" : jsonOut->string, NAPI_AUTO_LENGTH, &stringOut);
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
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "string", stringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddFalseToObjectOut;
}

napi_value getAddfalsetoobjNextOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
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
    
    // 给jsonObj->next赋值
    if (jsonObj == NULL) {
        return NULL;
    }
    if (jsonObj->next != NULL) {
        nextOut = getAddfalsetoobjTypeOut(env, nextOut, jsonObj->next);
        nextOut = getAddfalsetoobjValuesdoubleOut(env, nextOut, jsonObj->next);
        nextOut = getAddfalsetoobjValuesintOut(env, nextOut, jsonObj->next);
        nextOut = getAddfalsetoobjValuestringOut(env, nextOut, jsonObj->next);
        nextOut = getAddfalsetoobjStringOut(env, nextOut, jsonObj->next);
        if (jsonObj->next->next != NULL) {
            cJSON *nextNext = jsonObj->next->next;
            if (nextNext != NULL) {
                nextOut = getAddfalsetoobjNextOut(env, nextOut, jsonObj->next);
            }
        }
    }

    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "next", nextOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddFalseToObjectOut;
}

napi_value getJsonobjfalseChildOut(napi_env env, napi_value childOut, cJSON *jsonObj)
{
    if (jsonObj->child != NULL) {
        childOut = getAddfalsetoobjTypeOut(env, childOut, jsonObj->child);
        childOut = getAddfalsetoobjValuesdoubleOut(env, childOut, jsonObj->child);
        childOut = getAddfalsetoobjValuesintOut(env, childOut, jsonObj->child);
        childOut = getAddfalsetoobjValuestringOut(env, childOut, jsonObj->child);
        childOut = getAddfalsetoobjStringOut(env, childOut, jsonObj->child);
        if (jsonObj->child->next != NULL) {
            cJSON *childNext = jsonObj->child->next;
            if (childNext != NULL) {
                childOut = getAddfalsetoobjNextOut(env, childOut, jsonObj->child);
            }
        }
    }
    return childOut;
}

napi_value getAddfalsetoobjChildOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
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
    // 给jsonObj->child赋值
    if (jsonObj != NULL) {
        childOut = getJsonobjfalseChildOut(env, childOut, jsonObj);
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "child", childOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddFalseToObjectOut;
}

napi_value getAddfalsetoobjPrevOut(napi_env env, napi_value cJSON_AddFalseToObjectOut, cJSON *jsonObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
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
    status = napi_set_named_property(env, cJSON_AddFalseToObjectOut, "prev", prevOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddFalseToObjectOut;
}

char *getAddfalsetoobjInfo(napi_env env, napi_value paramIn)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
    /* [NAPI_GEN]: 从args数组中获取入参 */
    napi_valuetype valuetypename;
    /* [NAPI_GEN]: 获取入参类型，第1个入参
     * env: N-API环境的句柄，表示当前的上下文
     * value: 要检查类型的js值
     * result: 是一个指针，指向napi_valuetype枚举的值，函数会将结果存储在这里
     */
    status = napi_typeof(env, paramIn, &valuetypename);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_typeof", tag);
        return nullptr;
    }
    size_t strSize1 = 0;
    /* [NAPI_GEN]: napi_get_value_string_utf8用于将Js字符串转换为UTF-8编码的C字符串
     * env: N-API环境的句柄，表示当前的上下文
     * value: 要转换的JavaScript字符串
     * buf: 用于存储结果的字符数组的指针
     * bufsize: 缓冲区大小，以字节为单位
     * result: 转换后的字符串的字节长度(不包括空终止符)。若干buf是NULL,则返回所需的缓冲区大小(包括空终止符)
     */
    /* [NAPI_GEN]: buf参数是NULL时，用于获取所需缓冲区大小*/
    status = napi_get_value_string_utf8(env, paramIn, NULL, 0, &strSize1);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        return nullptr;
    }
    char *nameIn = new char[strSize1 + 1];
    /* [NAPI_GEN]: 用于获取字符串*/
    status = napi_get_value_string_utf8(env, paramIn, nameIn, strSize1 + 1, &strSize1);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        delete[] nameIn;
        return nullptr;
    }
    
    return nameIn;
}

/* [NAPI_GEN]:对应cJSON.h中: CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name);
 * 的napi方法，
 * 输入：一个cJSON对象，需要添加的item名字（字符串）
 * 输出：添加item后的cJSON对象
 */
napi_value KH545_cJSON_AddFalseToObject(napi_env env, napi_callback_info info)
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
    const char *tag = "[KH545_cJSON_AddFalseToObject]";
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
        return nullptr;
    }
    napi_value paramIn = args[PARAMS1];
    char *nameIn = getAddfalsetoobjInfo(env, paramIn);

    // Todo: add business logic. 在这前后代码为框架所生成
    cJSON *jsonOut = nullptr;
    cJSON *jsonObj = cJSON_CreateObject();
    // init 传入的obj 初始化
    napi_value cjsonObj = args[PARAMS0];
    jsonObj = initCJSON_Object(env, cjsonObj, jsonObj, tag);
    // add false to jsonObj
    jsonOut = cJSON_AddFalseToObject(jsonObj, nameIn);
    // 打印 jsonObj 值
    char *jsonResStr = cJSON_Print(jsonOut);
    if (jsonResStr != NULL) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "KH545_cJSON_AddFalseToObject", "jsonResStr: %s", jsonResStr);
    }

    delete[] nameIn;
    /* [NAPI_GEN]: function return value*/
    napi_value cJSON_AddFalseToObjectOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &cJSON_AddFalseToObjectOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return nullptr;
    }

    cJSON_AddFalseToObjectOut = getAddfalsetoobjChildOut(env, cJSON_AddFalseToObjectOut, jsonObj);
    cJSON_AddFalseToObjectOut = getAddfalsetoobjNextOut(env, cJSON_AddFalseToObjectOut, jsonObj);
    cJSON_AddFalseToObjectOut = getAddfalsetoobjPrevOut(env, cJSON_AddFalseToObjectOut, jsonObj);
    cJSON_AddFalseToObjectOut = getAddfalsetoobjTypeOut(env, cJSON_AddFalseToObjectOut, jsonObj);
    cJSON_AddFalseToObjectOut = getAddfalsetoobjValuesdoubleOut(env, cJSON_AddFalseToObjectOut, jsonObj);
    cJSON_AddFalseToObjectOut = getAddfalsetoobjValuesintOut(env, cJSON_AddFalseToObjectOut, jsonObj);
    cJSON_AddFalseToObjectOut = getAddfalsetoobjValuestringOut(env, cJSON_AddFalseToObjectOut, jsonObj);
    cJSON_AddFalseToObjectOut = getAddfalsetoobjStringOut(env, cJSON_AddFalseToObjectOut, jsonObj);

    cJSON_Delete(jsonObj);
    return cJSON_AddFalseToObjectOut;
}
