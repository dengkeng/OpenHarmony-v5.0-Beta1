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

#include "cJsonNapiH/cjsoncommon.h"

constexpr uint8_t TYPE1 = 1;
constexpr uint8_t TYPE2 = 2;

/*[NAPI_GEN]:错误处理,获取错误详细信息*/
void getErrMessage(napi_status &status, napi_env &env, const napi_extended_error_info *&extended_error_info,
    const char *info, const char *tag)
{
    status = napi_get_last_error_info(env, &extended_error_info);
    if (status == napi_ok && extended_error_info != NULL) {
        const char *errorMessage =
            extended_error_info->error_message != NULL ? extended_error_info->error_message : "Unknown error";
        OH_LOG_Print(LOG_APP, LOG_ERROR, GLOBAL_RESMGR, tag, "errmsg %{public}s!, engine_err_code %{public}d!.",
                     std::to_string(extended_error_info->engine_error_code).c_str(), extended_error_info->error_code);
        std::string myInfo = info;
        std::string res = "Failed to " + myInfo + " em = " + errorMessage +
                          ", eec = " + std::to_string(extended_error_info->engine_error_code) +
                          ", ec = " + std::to_string(extended_error_info->error_code);
        napi_throw_error(env, NULL, res.c_str());
    }
}

/* 去除字符串中的换行符，便于查找打印, 公共方法
 * str: 待去除\n的字符串
 */
void RemoveNewlines(std::string &str)
{
    // 删除换行符、制表符和空格
    str.erase(std::remove_if(str.begin(), str.end(), [](char c) { return c == '\n' || c == '\t' || c == ' '; }),
              str.end());
}

/* 检查JavaScript对象是否为空（不含自己的属性），公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * obj: 类型是napi_object
 * tag: 日志打印标识符
 */
bool IsEmptyObject(napi_env env, napi_value obj, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    bool isEmpty = true; // 默认对象为空
    // 首先检查传入的参数是否是对象
    napi_valuetype valuetype;
    status = napi_typeof(env, obj, &valuetype);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "IsEmptyObject: napi_typeof obj", tag);
        return NULL;
    }
    if (valuetype == napi_object) {
        // 创建一个属性名数组
        uint32_t propertyCount;
        napi_value propertyNames;
        status = napi_get_property_names(env, obj, &propertyNames);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "IsEmptyObject: napi_get_property_names obj", tag);
            return NULL;
        }
        // 计算属性的个数
        status = napi_get_array_length(env, propertyNames, &propertyCount);
        if (status != napi_ok) {
            getErrMessage(status, env, extended_error_info, "IsEmptyObject: napi_get_array_length propertyNames", tag);
            return NULL;
        }
        // 如果属性个数大于0，对象不为空
        if (propertyCount > 0) {
            isEmpty = false;
        }
    } else {
        napi_throw_type_error(env, NULL, "Argument must be an object");
        return NULL;
    }

    return isEmpty;
}

char *getNapiCjsonString(napi_env env, napi_value cjsonObj, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 获取string
    napi_value napiPropStr;
    status = napi_get_named_property(env, cjsonObj, "string", &napiPropStr);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property 1", tag);
        return NULL;
    }
    size_t strSize1 = 0;
    status = napi_get_value_string_utf8(env, napiPropStr, NULL, 0, &strSize1);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: get value string", tag);
        return NULL;
    }
    char *objStrIn = new char[strSize1 + 1];
    /* [NAPI_GEN]: 用于获取字符串*/
    status = napi_get_value_string_utf8(env, napiPropStr, objStrIn, strSize1 + 1, &strSize1);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: get value string", tag);
        delete[] objStrIn;
        return NULL;
    }
    return objStrIn;
}

char *getNapiCjsonValuestring(napi_env env, napi_value cjsonObj, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 获取valuestring
    napi_value napiPropValueStr;
    status = napi_get_named_property(env, cjsonObj, "valuestring", &napiPropValueStr);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property", tag);
        return NULL;
    }
    size_t strSize2 = 0;
    status = napi_get_value_string_utf8(env, napiPropValueStr, NULL, 0, &strSize2);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: get value string", tag);
        return NULL;
    }
    char *objValueStrIn = new char[strSize2 + 1];
    /* [NAPI_GEN]: 用于获取字符串*/
    status = napi_get_value_string_utf8(env, napiPropValueStr, objValueStrIn, strSize2 + 1, &strSize2);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: get value string", tag);
        delete[] objValueStrIn;
        return NULL;
    }
    return objValueStrIn;
}

double getNapiCjsonValuedouble(napi_env env, napi_value cjsonObj, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 获取valuedouble 并加入obj
    napi_value napiPropValueDouble;
    status = napi_get_named_property(env, cjsonObj, "valuedouble", &napiPropValueDouble);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property 2", tag);
        return NULL;
    }
    double objValueDoubleIn = 0;
    status = napi_get_value_double(env, napiPropValueDouble, &objValueDoubleIn);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_value_double", tag);
        return NULL;
    }
    return objValueDoubleIn;
}

int getNapiCjsonType(napi_env env, napi_value cjsonObj, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 获取cjson bool 并加入obj
    napi_value napiPropValueBoolean;
    status = napi_get_named_property(env, cjsonObj, "type", &napiPropValueBoolean);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property 3", tag);
        return NULL;
    }

    int objValueTypeIn = 0;
    status = napi_get_value_int32(env, napiPropValueBoolean, &objValueTypeIn);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_value_int32", tag);
        return NULL;
    }
    return objValueTypeIn;
}

cJSON *getNapiCjsonChild(napi_env env, napi_value cjsonObj, cJSON *jsonObj, char *objStr, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历child
    napi_value napiChildObj;
    status = napi_get_named_property(env, cjsonObj, "child", &napiChildObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property", tag);
        return NULL;
    }
    if (objStr[0] != '\0') {
        return jsonObj;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, napiChildObj, &valuetype);
    if (valuetype == napi_object) {
        if (!IsEmptyObject(env, napiChildObj, tag)) {
            jsonObj = initCJSON_Object(env, napiChildObj, jsonObj, tag);
        }
    }
    return jsonObj;
}

cJSON *getNapiCjsonNext(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历next
    napi_value napiNextObj;
    status = napi_get_named_property(env, cjsonObj, "next", &napiNextObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property", tag);
        return NULL;
    }
    napi_valuetype valuetypeNext;
    status = napi_typeof(env, napiNextObj, &valuetypeNext);
    if (valuetypeNext == napi_object) {
        if (!IsEmptyObject(env, napiNextObj, tag)) {
            jsonObj = initCJSON_Object(env, napiNextObj, jsonObj, tag);
        }
    }
    return jsonObj;
}

cJSON *getNapiCjsonPrev(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历prev
    napi_value napiPrevObj;
    status = napi_get_named_property(env, cjsonObj, "prev", &napiPrevObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property", tag);
        return NULL;
    }
    napi_valuetype valuetypePrev;
    status = napi_typeof(env, napiPrevObj, &valuetypePrev);
    if (valuetypePrev == napi_object) {
        if (!IsEmptyObject(env, napiPrevObj, tag)) {
            jsonObj = initCJSON_Object(env, napiPrevObj, jsonObj, tag);
        }
    }
    return jsonObj;
}

cJSON *getNapiCjsonChildArrObj(napi_env env, napi_value cjsonObj, cJSON *jsonObj, char *objStrIn, const char *tag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历child 确认child是否是数组
    napi_value napiChildObj;
    status = napi_get_named_property(env, cjsonObj, "child", &napiChildObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Object: napi_get_named_property", tag);
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, napiChildObj, &valuetype);
    if (valuetype == napi_object) {
        if (!IsEmptyObject(env, napiChildObj, tag)) {
            char *objChildStrIn = getNapiCjsonString(env, napiChildObj, tag);
            char *objChildValstrIn = getNapiCjsonValuestring(env, napiChildObj, tag);
            if (objChildStrIn[0] == '\0' && objChildValstrIn[0] == '\0') {
                cJSON *jsonArray = cJSON_CreateArray();
                jsonArray = initCJSON_Array(env, napiChildObj, jsonArray, tag, false);
                cJSON_AddItemToObject(jsonObj, objStrIn, jsonArray);
            }  else if (objChildStrIn[0] != '\0') {
                cJSON *jsonObject = cJSON_CreateObject();
                jsonObject = initCJSON_Object(env, napiChildObj, jsonObject, tag);
                cJSON_AddItemToObject(jsonObj, objStrIn, jsonObject);
            }
        }
    }
    return jsonObj;
}

/* 在native初始化js传递的对象， 公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象
 * jsonObj: 待初始化的native层cJSON对象
 * tag: 日志打印标识符
 */
cJSON *initCJSON_Object(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag)
{
    cJSON *jsonOut = nullptr;
    char *objStrIn = getNapiCjsonString(env, cjsonObj, tag);
    if (objStrIn != NULL && objStrIn[0] != '\0') {
        char *objValueStrIn = getNapiCjsonValuestring(env, cjsonObj, tag);
        if (objValueStrIn != NULL && objValueStrIn[0] != '\0') {
            jsonOut = cJSON_AddStringToObject(jsonObj, objStrIn, objValueStrIn);
        }
        double objValueDoubleIn = getNapiCjsonValuedouble(env, cjsonObj, tag);
        if (objValueDoubleIn != 0) {
            jsonOut = cJSON_AddNumberToObject(jsonObj, objStrIn, objValueDoubleIn);
        }
        int objValueTypeIn = getNapiCjsonType(env, cjsonObj, tag);
        if (objValueTypeIn == TYPE1) {
            jsonOut = cJSON_AddFalseToObject(jsonObj, objStrIn);
        } else if (objValueTypeIn == TYPE2) {
            jsonOut = cJSON_AddTrueToObject(jsonObj, objStrIn);
        }
        // 判断 child是否是数组或者对象：例如{"test":[1,2,3]} 或者 {"test":{"name","john"}}
        jsonObj = getNapiCjsonChildArrObj(env, cjsonObj, jsonObj, objStrIn, tag);
    }

    // {"name":"Ann","age":18,"isStudent":true}类型字符串的解析
    jsonObj = getNapiCjsonChild(env, cjsonObj, jsonObj, objStrIn, tag);
    jsonObj = getNapiCjsonNext(env, cjsonObj, jsonObj, tag);
    jsonObj = getNapiCjsonPrev(env, cjsonObj, jsonObj, tag);
    
    return jsonObj;
}

cJSON *getNapiCjsonArrayChild(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag, bool flag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历child
    napi_value napiChildObj;
    status = napi_get_named_property(env, cjsonObj, "child", &napiChildObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Array: napi_get_named_property", tag);
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, napiChildObj, &valuetype);
    if (valuetype == napi_object) {
        if (!IsEmptyObject(env, napiChildObj, tag)) {
            if (flag) {
                jsonObj = initCJSON_ArrayObj(env, napiChildObj, jsonObj, tag, true);
            } else {
                jsonObj = initCJSON_Array(env, napiChildObj, jsonObj, tag, false);
            }
        }
    }
    return jsonObj;
}

cJSON *getNapiCjsonArrayNext(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag, bool flag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历next
    napi_value napiNextObj;
    status = napi_get_named_property(env, cjsonObj, "next", &napiNextObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Array: napi_get_named_property", tag);
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, napiNextObj, &valuetype);
    if (valuetype == napi_object) {
        if (!IsEmptyObject(env, napiNextObj, tag)) {
            if (flag) {
                jsonObj = initCJSON_ArrayObj(env, napiNextObj, jsonObj, tag, true);
            } else {
                jsonObj = initCJSON_Array(env, napiNextObj, jsonObj, tag, false);
            }
        }
    }
    return jsonObj;
}

cJSON *getNapiCjsonArrayPrev(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag, bool flag)
{
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历prev
    napi_value napiPrevObj;
    status = napi_get_named_property(env, cjsonObj, "prev", &napiPrevObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Array: napi_get_named_property", tag);
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, napiPrevObj, &valuetype);
    if (valuetype == napi_object) {
        if (!IsEmptyObject(env, napiPrevObj, tag)) {
            if (flag) {
                jsonObj = initCJSON_ArrayObj(env, napiPrevObj, jsonObj, tag, true);
            } else {
                jsonObj = initCJSON_Array(env, napiPrevObj, jsonObj, tag, false);
            }
        }
    }
    return jsonObj;
}

/* 在native初始化js传递的对象， 公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象,该对象表示一个基本类型的数组，如[9,-2,7]
 * jsonObj: 待初始化的native层cJSON对象
 * tag: 日志打印标识符
 * flag: true表示判断是普通array,如：[2,-3,6];false表示判断数组元素是否是对象，如：[{"name":"ann"},{"name":"john"}]
 * return cJSON: 返回c++ cJSON对象
 */
cJSON *initCJSON_Array(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag, bool flag)
{
    char *objStrIn = getNapiCjsonString(env, cjsonObj, tag);
    if (objStrIn[0] == '\0') {
        int objValueTypeIn = getNapiCjsonType(env, cjsonObj, tag);
        if (objValueTypeIn != cJSON_NULL && objValueTypeIn != cJSON_Invalid) {
            double objValueDoubleIn = getNapiCjsonValuedouble(env, cjsonObj, tag);
            // 打印出来objValueDoubleIn
            if (objValueDoubleIn != 0) {
                cJSON_AddItemToArray(jsonObj, cJSON_CreateNumber(objValueDoubleIn));
            }
        }
    }

    jsonObj = getNapiCjsonArrayChild(env, cjsonObj, jsonObj, tag, flag);
    jsonObj = getNapiCjsonArrayNext(env, cjsonObj, jsonObj, tag, flag);
    jsonObj = getNapiCjsonArrayPrev(env, cjsonObj, jsonObj, tag, flag);

    return jsonObj;
}

/* 在native初始化js传递的对象， 公共方法
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象,该对象表示一个数组,如：[{"name":"ann"},{"name":"john"}]
 * jsonObj: 待初始化的native层cJSON对象
 * tag: 日志打印标识符
 * flag: true表示判断是普通array,如：[2,-3,6];false表示判断数组元素是否是对象，如：[{"name":"ann"},{"name":"john"}]
 * return cJSON: 返回c++ cJSON对象
 */
cJSON *initCJSON_ArrayObj(napi_env env, napi_value cjsonObj, cJSON *jsonObj, const char *tag, bool flag)
{
    char *objStrIn = getNapiCjsonString(env, cjsonObj, tag);
    if (objStrIn[0] != '\0') {
        cJSON *arrObj = cJSON_CreateObject();
        arrObj = initCJSON_Object(env, cjsonObj, arrObj, tag);
        char *rootString1 = cJSON_Print(arrObj);
        bool isObjNull = false;
        if (rootString1 != NULL) {
            // 需要去掉字符串中的\n 这样方便查找打印出的字符串
            std::string printRootStr = rootString1;
            RemoveNewlines(printRootStr);
            if (printRootStr == "{}") {
                isObjNull = true;
            }
        }
        if (!isObjNull) {
            cJSON *objItem = cJSON_CreateObject();
            cJSON_AddItemToArray(jsonObj, objItem);
            objItem = initCJSON_Object(env, cjsonObj, objItem, tag);
            char *rootString2 = cJSON_Print(jsonObj);
            if (rootString2 != NULL) {
                // 需要去掉字符串中的\n 这样方便查找打印出的字符串
                std::string printRootStr = rootString2;
                RemoveNewlines(printRootStr);
            }
            return jsonObj;
        }
    }

    jsonObj = getNapiCjsonArrayChild(env, cjsonObj, jsonObj, tag, flag);
    jsonObj = getNapiCjsonArrayNext(env, cjsonObj, jsonObj, tag, flag);
    jsonObj = getNapiCjsonArrayPrev(env, cjsonObj, jsonObj, tag, flag);

    return jsonObj;
}

/* 判断是单纯对象还是arrObj或objArr
 * env: 当前环境的句柄，代表当前的Node.js环境
 * cjsonObj: 从js传递的cJSON对象
 * tag: 日志打印标识
 * return 布尔值：若对象是array object或者object array返回true,如[{"name":"john"}]或{"testArr":[9,8,7]}
 */
bool isArrObject(napi_env env, napi_value cjsonObj, const char *tag)
{
    // 判断 root->child-string有没有值,有值则认为是普通object,没有值则认为是arrayObject
    napi_status status;
    const napi_extended_error_info *extended_error_info;
    // 遍历child
    napi_value napiChildObj;
    status = napi_get_named_property(env, cjsonObj, "child", &napiChildObj);
    if (status != napi_ok) {
        getErrMessage(status, env, extended_error_info, "initCJSON_Array: napi_get_named_property", tag);
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, napiChildObj, &valuetype);
    if (valuetype == napi_object) {
        if (!IsEmptyObject(env, napiChildObj, tag)) {
            char *objStrIn = getNapiCjsonString(env, napiChildObj, tag);
            if (objStrIn[0] == '\0') {
                return true;
            } else {
                bool isTrue = isArrObject(env, napiChildObj, tag);
                return isTrue;
            }
        } else {
            return false;
        }
    }
    return false;
}