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

double getAdditemtoarrInfoNum(napi_env env, napi_value itemObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH802_cJSON_AddItemToArray]";
    napi_value paramValuedoubleIn;
    status = napi_get_named_property(env, itemObj, "valuedouble", &paramValuedoubleIn); // 读取属性值
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get named property", tag);
        return NULL;
    }
   
    // 从 cJSON *item中取出值
    double arrayItemValuedoubleIn = 0;
    status = napi_get_value_double(env, paramValuedoubleIn, &arrayItemValuedoubleIn);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_get_value_double", tag);
        return NULL;
    }
    
    return arrayItemValuedoubleIn;
}

char *getAdditemtoarrInfoStr(napi_env env, napi_value itemObj)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    const char *tag = "[KH802_cJSON_AddItemToArray]";
    napi_value paramValuestringIn;
    status = napi_get_named_property(env, itemObj, "valuestring", &paramValuestringIn); // 读取属性值
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get named property", tag);
        return NULL;
    }
    size_t strSize = 0;
    /* [NAPI_GEN]: napi_get_value_string_utf8用于将Js字符串转换为UTF-8编码的C字符串
     * env: N-API环境的句柄，表示当前的上下文
     * value: 要转换的JavaScript字符串
     * buf: 用于存储结果的字符数组的指针
     * bufsize: 缓冲区大小，以字节为单位
     * result: 转换后的字符串的字节长度(不包括空终止符)。若干buf是NULL,则返回所需的缓冲区大小(包括空终止符)
     */
    /* [NAPI_GEN]: buf参数是NULL时，用于获取所需缓冲区大小*/
    status = napi_get_value_string_utf8(env, paramValuestringIn, NULL, 0, &strSize);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        return nullptr;
    }
    char *arrayItemValuestringIn = new char[strSize + 1];
    /* [NAPI_GEN]: 用于获取字符串*/
    status = napi_get_value_string_utf8(env, paramValuestringIn, arrayItemValuestringIn, strSize + 1, &strSize);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "get value string", tag);
        delete[] arrayItemValuestringIn;
        return nullptr;
    }
    return arrayItemValuestringIn;
}

cJSON_bool addItemToArray(double arrayItemValuedoubleIn, char *arrayItemValuestringIn)
{
    // 创建一个空的 JSON 数组
    cJSON *jsonArray = cJSON_CreateArray();
    // 检查是否创建成功
    if (jsonArray == NULL) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray", "cJSON_CreateArray failed.");
        return NULL;
    }
    // 创建一个要添加到数组的 JSON 对象，例如一个数字,一个布尔值，一个字符串
    cJSON *numberItem = cJSON_CreateNumber(arrayItemValuedoubleIn);
    cJSON *booleanItem = cJSON_CreateTrue();
    cJSON *stringItem = cJSON_CreateString(arrayItemValuestringIn);
    // 检查是否创建成功
    if (numberItem == NULL) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray", "cJSON_CreatNumber failed.");
        return NULL;
    }
    if (booleanItem == NULL) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray", "cJSON_CreateTrue failed.");
        return NULL;
    }
    if (stringItem == NULL) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray", "cJSON_CreateString failed.");
        return NULL;
    }
    // 将创建的数字对象添加到数组中
    cJSON_bool success = cJSON_AddItemToArray(jsonArray, numberItem);
    if (!success) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray",
            "cJSON add numberItem to array failed.");
        return NULL;
    }
    success = cJSON_AddItemToArray(jsonArray, booleanItem);
    if (!success) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray",
            "cJSON add booleanItem to array failed.");
        return NULL;
    }
    success = cJSON_AddItemToArray(jsonArray, stringItem);
    if (!success) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray",
            "cJSON add stringItem to array failed.");
        return NULL;
    }
    // 打印数组
    char *jsonResStr = cJSON_Print(jsonArray);
    if (jsonResStr != NULL) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray", "jsonResStr: %s", jsonResStr);
    }
    // 最后，不要忘记删除 cJSON 对象以防内存泄露
    cJSON_Delete(jsonArray);
    return success;
}

napi_value getAdditemtoarrTypeOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonObj)
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
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "type", typeOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

napi_value getAdditemtoarrValuesintOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonObj)
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
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "valueint", valueintOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

napi_value getAdditemtoarrValuesdoubleOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonObj)
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
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "valuedouble", valuedoubleOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

napi_value getAdditemtoarrValuestringOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonOut)
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
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "valuestring", valuestringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

napi_value getAdditemtoarrStringOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonOut)
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
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "string", stringOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

napi_value getAdditemtoarrNextOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonObj)
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
        return nullptr;
    }
    // 给jsonObj->next赋值
    if (jsonObj == NULL) {
        return NULL;
    }
    if (jsonObj->next != NULL) {
        nextOut = getAdditemtoarrTypeOut(env, nextOut, jsonObj->next);
        nextOut = getAdditemtoarrValuesdoubleOut(env, nextOut, jsonObj->next);
        nextOut = getAdditemtoarrValuesintOut(env, nextOut, jsonObj->next);
        nextOut = getAdditemtoarrValuestringOut(env, nextOut, jsonObj->next);
        nextOut = getAdditemtoarrStringOut(env, nextOut, jsonObj->next);
        if (jsonObj->next->next != NULL) {
            cJSON *nextNext = jsonObj->next->next;
            if (nextNext != NULL) {
                nextOut = getAdditemtoarrNextOut(env, nextOut, jsonObj->next);
            }
        }
        if (jsonObj->next->child != NULL) {
            cJSON *nextChild = jsonObj->next->child;
            if (nextChild != NULL) {
                nextOut = getAdditemtoarrChildOut(env, nextOut, jsonObj->next);
            }
        }
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "next", nextOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

napi_value getJsonarrayitemChildOut(napi_env env, napi_value childOut, cJSON *jsonObj)
{
    if (jsonObj->child != NULL) {
        childOut = getAdditemtoarrTypeOut(env, childOut, jsonObj->child);
        childOut = getAdditemtoarrValuesdoubleOut(env, childOut, jsonObj->child);
        childOut = getAdditemtoarrValuesintOut(env, childOut, jsonObj->child);
        childOut = getAdditemtoarrValuestringOut(env, childOut, jsonObj->child);
        childOut = getAdditemtoarrStringOut(env, childOut, jsonObj->child);
        if (jsonObj->child->child != NULL) {
            cJSON *childChild = jsonObj->child->child;
            if (childChild != NULL) {
                childOut = getAdditemtoarrChildOut(env, childOut, jsonObj->child);
            }
        }
        if (jsonObj->child->next != NULL) {
            cJSON *childNext = jsonObj->child->next;
            if (childNext != NULL) {
                childOut = getAdditemtoarrNextOut(env, childOut, jsonObj->child);
            }
        }
    }
    return childOut;
}

/* 将C++ cJSON对象返回js层
 * 输入：待返回的js对象，c++ cJSON对象
 * 输出：返回js的对象
 */
napi_value getAdditemtoarrChildOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonObj)
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
        return nullptr;
    }
    // 给jsonObj->child赋值
    if (jsonObj != NULL) {
        childOut = getJsonarrayitemChildOut(env, childOut, jsonObj);
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "child", childOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

napi_value getAdditemtoarrPrevOut(napi_env env, napi_value cJSON_AddItemToArrayOut, cJSON *jsonObj)
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
        return nullptr;
    }
    /* [NAPI_GEN]: 返回值是对象时，将native侧的对象的属性和值依次塞入napi_create_object创建出的对象，最终将该对象返回js
     * env: 当前环境的句柄
     * object: 要设置属性的js对象，该对象是由上文napi_create_object创建的
     * utf8name: 属性的名称，是一个以UTF-8编码的字符串
     * value: 与属性名称关联的值，这个值可以是任何js类型（如一个数值、字符串、另一个对象等）
     */
    status = napi_set_named_property(env, cJSON_AddItemToArrayOut, "prev", prevOut);
    if (status != napi_ok) {
        /* [NAPI_GEN]: 错误处理*/
        getErrMessage(status, env, extended_error_info, "napi_set_named_property", tag);
        return nullptr;
    }
    return cJSON_AddItemToArrayOut;
}

cJSON *getCjsonAddItemToArrRes(napi_env env, napi_value cjsonObj, napi_value cjsonArrobj)
{
    const char *tag = "[KH802_cJSON_AddItemToArray]";
    cJSON *jsonArray = cJSON_CreateArray();
    // init传入的obj: 初始化数组
    jsonArray = initCJSON_ArrayObj(env, cjsonObj, jsonArray, tag, true);
    cJSON *jsonArrayItem = cJSON_CreateArray();
    jsonArrayItem = initCJSON_Array(env, cjsonArrobj, jsonArrayItem, tag, false);
    char *arrayString0 = cJSON_Print(jsonArrayItem);
    bool jsonArrNull = false;
    if (arrayString0 == NULL) {
        cJSON_free(arrayString0); // 释放 cJSON_Print 分配的内存
        return NULL;
    } else {
        std::string printRootStr = arrayString0;
        RemoveNewlines(printRootStr);
        if (printRootStr == "[]") {
            jsonArrNull = true;
        }
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray", "arrayString1: %s",
            printRootStr.c_str());
        cJSON_free(arrayString0); // 释放 cJSON_Print 分配的内存
    }

    cJSON *jsonObject = cJSON_CreateObject();
    jsonObject = initCJSON_Object(env, cjsonArrobj, jsonObject, tag);
    bool jsonObjectNull = false;
    char *arrayString2 = cJSON_Print(jsonObject);
    if (arrayString2 != NULL) {
        std::string printRootStr = arrayString2;
        RemoveNewlines(printRootStr);
        if (printRootStr == "{}") {
            jsonObjectNull = true;
        }
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "KH802_cJSON_AddItemToArray", "arrayString2: %s",
            printRootStr.c_str());
    } else {
        cJSON_free(arrayString2); // 释放 cJSON_Print 分配的内存
        return NULL;
    }

    if (!jsonObjectNull) {
        cJSON *objItem = cJSON_CreateObject();
        cJSON_AddItemToArray(jsonArray, objItem);
        objItem = initCJSON_Object(env, cjsonArrobj, objItem, tag);
    } else if (!jsonArrNull) {
        cJSON_AddItemToArray(jsonArray, jsonArrayItem);
    }
    
    return jsonArray;
}

/* [NAPI_GEN]:对应cJSON.h中: CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item); 的napi方法
 * 输入：一个cJSON数组对象，想要添加到cJSON数组中的cJSON元素
 * 输出：添加item后的cJSON对象
 */
napi_value KH802_cJSON_AddItemToArray(napi_env env, napi_callback_info info)
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
    const char *tag = "[KH802_cJSON_AddItemToArray]";
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
    
    // Todo: add business logic. 在这前后代码为框架所生成
    cJSON *jsonArray = NULL;
    jsonArray = getCjsonAddItemToArrRes(env, args[PARAMS0], args[PARAMS1]);

    /* [NAPI_GEN]: function return value*/
    napi_value cJSON_AddItemToArrayOut;
    /* [NAPI_GEN]: 返回值是对象时，需要使用napi_create_object创建一个js的对象与js代码交互
     * env: 当前环境的句柄
     * result: 一个napi_value的指针，该指针将被设置为新创建的js对象
     */
    status = napi_create_object(env, &cJSON_AddItemToArrayOut);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "napi_create_object", tag);
        return nullptr;
    }

    cJSON_AddItemToArrayOut = getAdditemtoarrChildOut(env, cJSON_AddItemToArrayOut, jsonArray);
    cJSON_AddItemToArrayOut = getAdditemtoarrNextOut(env, cJSON_AddItemToArrayOut, jsonArray);
    cJSON_AddItemToArrayOut = getAdditemtoarrPrevOut(env, cJSON_AddItemToArrayOut, jsonArray);
    cJSON_AddItemToArrayOut = getAdditemtoarrTypeOut(env, cJSON_AddItemToArrayOut, jsonArray);
    cJSON_AddItemToArrayOut = getAdditemtoarrValuesdoubleOut(env, cJSON_AddItemToArrayOut, jsonArray);
    cJSON_AddItemToArrayOut = getAdditemtoarrValuesintOut(env, cJSON_AddItemToArrayOut, jsonArray);
    cJSON_AddItemToArrayOut = getAdditemtoarrValuestringOut(env, cJSON_AddItemToArrayOut, jsonArray);
    cJSON_AddItemToArrayOut = getAdditemtoarrStringOut(env, cJSON_AddItemToArrayOut, jsonArray);
    
    cJSON_Delete(jsonArray);
    return cJSON_AddItemToArrayOut;
}
