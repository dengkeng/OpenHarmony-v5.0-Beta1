/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
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
const { writeFile } = require("../tools/FileRW");
const re = require("../tools/re");

let xNapiToolH = `\
#ifndef CC_TOOL_H
#define CC_TOOL_H

#include <node_api.h>
#include <string>
#include <memory>
#include <map>
#include <any>
#include <optional>
#include <vector>
#include <cmath>

using DataPtr = struct DumyData*;

struct CallFunc {
    napi_env env_;
    napi_ref funcRef_;
    napi_ref thisVarRef_;
};
struct ThreadsafeFunc {
    napi_env env_;    
    napi_ref thisVarRef_;
    napi_threadsafe_function threadsafefunc_;
};
class XNapiTool {
public:
    static const int ZERO = 0;
    static const int ONE = 1;
    static const int TWO = 2;
    static const int THREE = 3;
    static const int FOUE = 4;
    static const int FIVE = 5;
    static const int SIX = 6;
    static const int SEVEN = 7;
    static const int EIGHT = 8;
    static const int NINE = 9;
    void RegistOnOffFunc(std::string name, napi_value func);
    void UnregistOnOffFunc(std::string name);
    void RegistThreadsafeFunc(std::string name, napi_threadsafe_function thraedsafeFunc);
    static void CallSyncFunc(CallFunc *pSyncFuncs, napi_value ret);
    static void CallAsyncFunc(CallFunc *pAsyncFuncs, napi_value ret);
    static void CallThreadSafeFunc(std::string eventName);

    using CallbackFunction = void (*)(XNapiTool *pxt, DataPtr data);
    using RELEASE_INSTANCE = void (*)(DataPtr p);
    static napi_value UndefinedValue(napi_env env);
    const uint32_t DEFAULT_ARG_COUNT = 8;
    napi_value UndefinedValue();

    napi_value CreateSubObject(napi_value parent, const char *name);
    void DefineFunction(const char *funcName, napi_callback callback, napi_value dest = nullptr);
    void DefineClass(const char *className, napi_callback constructorFunc,
        std::map<const char *, std::map<const char *, napi_callback>> &valueList, std::map<const char *,
        napi_callback> &funcList, napi_value dest = nullptr);

    void SetEnumProperty(napi_value dstObj, const char *propName, const std::any objValue);
    void CreateEnumObject(const char *enumName, std::map<const char *, std::any> enumMap);

    XNapiTool(napi_env env, napi_callback_info info);
    XNapiTool(napi_env env, napi_value exports);
    ~XNapiTool();

    bool SwapJs2CBool(napi_value value);
    int32_t SwapJs2CInt32(napi_value value);
    uint32_t SwapJs2CUint32(napi_value value);
    int64_t SwapJs2CInt64(napi_value value);
    double_t SwapJs2CDouble(napi_value value);
    size_t SwapJs2CUtf8(napi_value value, std::string &str);

    napi_value SwapC2JsBool(bool value);
    napi_value SwapC2JsInt32(int32_t value);
    napi_value SwapC2JsUint32(uint32_t value);
    napi_value SwapC2JsInt64(int64_t value);
    napi_value SwapC2JsDouble(double_t value);
    napi_value SwapC2JsUtf8(const char *value);

    napi_value GetArgv(uint32_t p);
    uint32_t GetArgc();

    bool GetProperty(napi_value value, const char *propertyName);
    napi_value GetValueProperty(napi_value value, const char *propertyName);
    napi_value SetValueProperty(napi_value &value, const char *propertyName, napi_value property);

    napi_value CreateArray(napi_value &value);
    uint32_t GetArrayLength(napi_value value);
    napi_value GetArrayElement(napi_value value, uint32_t p);
    napi_value SetArrayElement(napi_value &value, uint32_t p, napi_value ele);
    
    uint32_t GetMapLength(napi_value value);
    napi_value GetMapElementName(napi_value value, uint32_t p);
    napi_value GetMapElementValue(napi_value value, const char *p);
    napi_value SetMapElement(napi_value &value, const char *ele_key, napi_value ele_value);

    std::string GetUnionType(napi_value object);

    std::string GetAnyType(napi_value object);
    std::string GetAnyArrayType(napi_value object);
    /**
     * @brief Get any type when function param is any and any type is Array<map<string, string/number/boolean>>.
     *
     * @param object Indicates data to be parsed.
     * @return Returns specific return value type if this function is successfully called such as arr_map_string.
     */
    std::string GetAnyTypeArrMap(napi_value object);
    /**
     * @brief Get any type when function param is any and any type is map<string, Array<string/number/boolean>>.
     *
     * @param object Indicates data to be parsed.
     * @return Returns specific return value type if this function is successfully called such as map_arr_string.
     */
    std::string GetAnyTypeMapArr(napi_value object);
    /**
     * @brief Set any value when function param is any and any type is Array<map<string, string/number/boolean>>.
     *
     * @param any_type Indicates the type of the param any.
     * @param argv Indicates data to be parsed.
     * @param any Indicates parsed data of the param any.
     * @param len Indicates the length of Array.
     */
    void SetAnyValueArrMap(std::string &any_type, napi_value argv, std::any &any, uint32_t len);
    /**
     * @brief Set any value when function param is any and any type is map<string, Array<string/number/boolean>>.
     *
     * @param any_type Indicates the type of the param any.
     * @param argv Indicates data to be parsed.
     * @param any Indicates parsed data of the param any.
     * @param len Indicates the length of map.
     */
    void SetAnyValueMapArr(std::string &any_type, napi_value argv, std::any &any, uint32_t len);
    void SetAnyValue(std::string &any_type, napi_value argv, std::any &any);
    /**
     * @brief Get any value when function param is any and any type is Array<map<string, string/number/boolean>>.
     *
     * @param any_type Indicates the type of the param any.
    * @param result Indicates parsed data of the param any.
    * @param any Indicates data to be parsed.
     */
    void GetAnyValueArrMap(std::string any_type, napi_value &result, std::any any);
    /**
     * @brief Get any value when function param is any and any type is map<string, Array<string/number/boolean>>.
     *
     * @param any_type Indicates the type of the param any.
     * @param result Indicates parsed data of the param any.
     * @param any Indicates data to be parsed.
     */
    void GetAnyValueMapArr(std::string any_type, napi_value &result, std::any any);
    void GetAnyValue(std::string any_type, napi_value &result, std::any any);
    void GetObjectValVecUint32(std::any &anyVal, napi_value &tnv2);
    void GetObjectValVecInt32(std::any &anyVal, napi_value &tnv2);
    void GetObjectValVecInt64(std::any &anyVal, napi_value &tnv2);
    void GetObjectValVecDouble(std::any &anyVal, napi_value &tnv2);
    void GetObjectValVecBool(std::any &anyVal, napi_value &tnv2);
    void GetObjectValVecConstchar(std::any &anyVal, napi_value &tnv2);
    void GetObjectValMapString(std::any &anyVal, napi_value &tnv2);
    void GetObjectValMapUint32(std::any &anyVal, napi_value &tnv2);
    void GetObjectValMapInt32(std::any &anyVal, napi_value &tnv2);
    void GetObjectValMapInt64(std::any &anyVal, napi_value &tnv2);
    void GetObjectValMapDouble(std::any &anyVal, napi_value &tnv2);
    void GetObjectValMapBool(std::any &anyVal, napi_value &tnv2);
    void GetObjectValMapAny(std::any &anyVal, napi_value &tnv2);
    void GetObjectValue(napi_value &result, std::map<std::string, std::any> valueIn);

    napi_value SyncCallBack(napi_value func, size_t argc, napi_value *args);

    napi_value StartAsync(CallbackFunction pe, DataPtr data, CallbackFunction pc, napi_value func = nullptr);
    void FinishAsync(size_t argc, napi_value *args);

    bool IsFailed()
    {
        return bFailed_;
    }
    napi_value GetError()
    {
        return error_;
    }
    napi_env GetEnv()
    {
        return env_;
    }

    napi_value tmp_value;

    // create code related class
public:
    static void WrapFinalize(napi_env env, XNapiTool *data, DataPtr hint);
    static std::map<std::string, CallFunc> callFuncs_;
    static std::map<std::string, ThreadsafeFunc> threadsafeCallFuncs_;
    void ReleaseInstance();
    napi_value WrapInstance(DataPtr instance, RELEASE_INSTANCE ri);
    DataPtr UnWarpInstance();
    
    void SetAsyncInstance(DataPtr p);
    void* GetAsyncInstance();

private:
    napi_env env_;
    napi_value exports_;

    // analyze params
    napi_value argv_[8];
    size_t argc_size;
    napi_value thisVar_;
    void *data_;

    // error message
    napi_value error_;
    bool bFailed_;
    bool CheckFailed(bool b, const char *errStr);
    bool CheckValueType(napi_value value, napi_valuetype type);

    // asynchronous call related code
    static void AsyncExecute(napi_env env, XNapiTool *p);
    void AsyncExecuteFunction();
    static void AsyncComplete(napi_env env, napi_status status, XNapiTool *p);
    void AsyncCompleteFunction();
    napi_ref callbackFunc_;
    napi_ref asyncThisVar_;
    napi_async_work work_;
    bool asyncNeedRelease_;
    CallbackFunction executeFunction_;
    CallbackFunction completeFunction_;
    DataPtr valueData_;
    napi_deferred deferred_;
    enum class AsyncMode {
        NONE,
        CALLBACK,
        PROMISE,
    };
    AsyncMode asyncMode_;

private:
    napi_ref wrapper_;
    DataPtr pInstance_;
    RELEASE_INSTANCE releaseInstance_;
    DataPtr asyncInstance_;
};

#endif
`

let xNapiToolCpp = `

#include "tool_utility.h"
#include <cassert>
#include <cstring>
#include <uv.h>

#define CC_ASSERT(btrue) \\
    if (!(btrue)) {      \\
                         \\
    }                    \\
    assert(btrue)

XNapiTool::XNapiTool(napi_env env, napi_callback_info info)
{
    env_ = env;
    bFailed_ = false;
    executeFunction_ = nullptr;
    completeFunction_ = nullptr;
    valueData_ = nullptr;
    asyncNeedRelease_ = false;
    asyncMode_ = AsyncMode::NONE;
    pInstance_ = nullptr;
    releaseInstance_ = nullptr;
    wrapper_ = nullptr;

    argc_size = DEFAULT_ARG_COUNT;

    napi_status result_status = napi_get_cb_info(env, info, &argc_size, argv_, &thisVar_, &data_);
    CheckFailed(result_status == napi_ok, "get args fail");
}

XNapiTool::XNapiTool(napi_env env, napi_value exports)
{
    env_ = env;
    exports_ = exports;

    asyncMode_ = AsyncMode::NONE;
    wrapper_ = nullptr;
}

XNapiTool::~XNapiTool()
{
    if (asyncMode_ == AsyncMode::PROMISE) {
        napi_status result_status = napi_delete_async_work(env_, work_);
        CC_ASSERT(result_status == napi_ok);
    }
    if (asyncMode_ == AsyncMode::CALLBACK) {
        napi_status result_status = napi_delete_reference(env_, callbackFunc_);
        CC_ASSERT(result_status == napi_ok);
        napi_delete_reference(env_, asyncThisVar_);
        result_status = napi_delete_async_work(env_, work_);
        CC_ASSERT(result_status == napi_ok);
    }
    if (wrapper_ != nullptr) {
        napi_status result_status = napi_delete_reference(env_, wrapper_);
        CC_ASSERT(result_status == napi_ok);
    }
}

bool XNapiTool::SwapJs2CBool(napi_value value)
{
    bool result;
    napi_status result_status = napi_get_value_bool(env_, value, &result);
    if (CheckFailed(result_status == napi_ok, "swap_js_2_c_bool fail"))
        return -1;
    return result;
}

napi_value XNapiTool::GetArgv(uint32_t p)
{
    if (CheckFailed(p < argc_size, "GetArgv失败"))
        return error_;

    return argv_[p];
}

uint32_t XNapiTool::GetArgc()
{
    return argc_size;
}

bool XNapiTool::GetProperty(napi_value value, const char *propertyName)
{
    napi_value result;
    bool hasProperty = false;
    bool isNull = false; 
    bool isUndefined = false;
    napi_has_named_property(env_, value, propertyName, &hasProperty);
    if (hasProperty) {
        napi_get_named_property(env_, value, propertyName, &result);
        napi_strict_equals(env_, result, nullptr, &isNull);
        napi_strict_equals(env_, result, nullptr, &isUndefined);
        if (isNull || isUndefined) {
            return false;
        } else {
            return true;
        }
    } else {
        return false;
    }
}

napi_value XNapiTool::GetValueProperty(napi_value value, const char *propertyName)
{
    napi_value result;
    napi_status result_status = napi_get_named_property(env_, value, propertyName, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SetValueProperty(napi_value &value, const char *propertyName, napi_value property)
{
    napi_status result_status;
    if (value == nullptr) {
        result_status = napi_create_object(env_, &value);
        CC_ASSERT(result_status == napi_ok);
    }
    result_status = napi_set_named_property(env_, value, propertyName, property);
    CC_ASSERT(result_status == napi_ok);
    return value;
}

napi_value XNapiTool::CreateArray(napi_value &value)
{
    if (value == nullptr) {
        napi_status result_status = napi_create_array(env_, &value);
        CC_ASSERT(result_status == napi_ok);
    }
    return value;
}

uint32_t XNapiTool::GetArrayLength(napi_value value)
{
    uint32_t ret;
    napi_status result_status = napi_get_array_length(env_, value, &ret);
    CC_ASSERT(result_status == napi_ok);
    return ret;
}

napi_value XNapiTool::GetArrayElement(napi_value value, uint32_t p)
{
    napi_value result;
    napi_status result_status = napi_get_element(env_, value, p, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SetArrayElement(napi_value &value, uint32_t p, napi_value ele)
{
    napi_status result_status;
    if (value == nullptr) {
        result_status = napi_create_array(env_, &value);
        CC_ASSERT(result_status == napi_ok);
    }
    result_status = napi_set_element(env_, value, p, ele);
    CC_ASSERT(result_status == napi_ok);
    return value;
}

uint32_t XNapiTool::GetMapLength(napi_value value)
{
    napi_value name_result;
    napi_get_property_names(env_, value, &name_result);
    uint32_t ret;
    napi_status result_status = napi_get_array_length(env_, name_result, &ret);
    CC_ASSERT(result_status == napi_ok);
    return ret;
}

napi_value XNapiTool::GetMapElementName(napi_value value, uint32_t p)
{
    napi_value name_result;
    napi_get_property_names(env_, value, &name_result);
    napi_value result;
    napi_status result_status = napi_get_element(env_, name_result, p, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::GetMapElementValue(napi_value value, const char *utf8Name)
{
    napi_value result;
    napi_status result_status = napi_get_named_property(env_, value, utf8Name, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SetMapElement(napi_value &value, const char *ele_key, napi_value ele_value)
{
    napi_status result_status;
    if (value == nullptr) {
        result_status = napi_create_object(env_, &value);
        CC_ASSERT(result_status == napi_ok);
    }
    result_status = napi_set_named_property(env_, value, ele_key, ele_value);
    CC_ASSERT(result_status == napi_ok);
    return value;
}

std::string XNapiTool::GetAnyType(napi_value object)
{
    napi_valuetype result;
    napi_typeof(env_, object, &result);
    if (result == napi_string) {
        return "string";
    } else if (result == napi_number) {
        return "number";
    } else if (result == napi_boolean) {
        return "boolean";
    } else if (result == napi_object) {
        bool is_array;
        napi_is_array(env_, object, &is_array);
        if (is_array) {
            napi_value arr_value_result;
            napi_valuetype arr_type_result;
            napi_get_element (env_, object, 0, &arr_value_result);
            napi_typeof(env_, arr_value_result, &arr_type_result);
            if (arr_type_result == napi_string) {
                return "arr_string";
            } else if (arr_type_result == napi_number) {
                return "arr_number";
            } else if (arr_type_result == napi_boolean) {
                return "arr_boolean";
            } else if (arr_type_result == napi_object) {
                return GetAnyTypeArrMap(arr_value_result);
            } else {
                return nullptr;
            }
        }
        napi_value obj_name_value;
        napi_value obj_name_result;
        napi_valuetype obj_name_type;
        std::string obj_name_string;
        napi_get_property_names (env_, object, &obj_name_value);
        napi_get_element (env_, obj_name_value, 0, &obj_name_result);
        napi_typeof(env_, obj_name_result, &obj_name_type);
        if (obj_name_type == napi_string) {
            napi_value obj_value;
            napi_valuetype obj_value_type;
            SwapJs2CUtf8(obj_name_result, obj_name_string);
            napi_get_named_property (env_, object, obj_name_string.c_str(), &obj_value);
            napi_typeof(env_, obj_value, &obj_value_type);
            if (obj_value_type == napi_string) {
                return "map_string";
            } else if (obj_value_type == napi_number) {
                return "map_number";
            } else if (obj_value_type == napi_boolean) {
                return "map_boolean";
            } else if (obj_value_type == napi_object) {
                return GetAnyTypeMapArr(obj_value);
            } else {
                return nullptr;
            }
        }
        return nullptr;
    } else {
        return nullptr;
    }
}

std::string XNapiTool::GetAnyArrayType(napi_value object)
{
    napi_valuetype result;
    napi_typeof(env_, object, &result);
    if (result == napi_object) {
        bool is_array;
        napi_is_array(env_, object, &is_array);
        if (is_array) {
            napi_value arr_value_result;
            napi_valuetype arr_type_result;
            napi_get_element (env_, object, 0, &arr_value_result);
            napi_typeof(env_, arr_value_result, &arr_type_result);
            if (arr_type_result == napi_string) {
                return "arr_string";
            } else if (arr_type_result == napi_number) {
                return "arr_number";
            } else if (arr_type_result == napi_boolean) {
                return "arr_boolean";
            } else {
                return nullptr;
            }
        }
        return nullptr;
    }
    return nullptr;
}

std::string XNapiTool::GetAnyTypeArrMap(napi_value object) {
    napi_value obj_name_value;
    napi_value obj_name_result;
    napi_valuetype obj_name_type;
    std::string obj_name_string;
    napi_get_property_names (env_, object, &obj_name_value);
    napi_get_element (env_, obj_name_value, 0, &obj_name_result);
    napi_typeof(env_, obj_name_result, &obj_name_type);
    if (obj_name_type == napi_string) {
        napi_value obj_value;
        napi_valuetype obj_value_type;
        SwapJs2CUtf8(obj_name_result, obj_name_string);
        napi_get_named_property (env_, object, obj_name_string.c_str(), &obj_value);
        napi_typeof(env_, obj_value, &obj_value_type);
        if (obj_value_type == napi_string) {
            return "arr_map_string";
        } else if (obj_value_type == napi_number) {
            return "arr_map_number";
        } else if (obj_value_type == napi_boolean) {
            return "arr_map_boolean";
        } else {
            return nullptr;
        }
    }
    return nullptr;
}

std::string XNapiTool::GetAnyTypeMapArr(napi_value object) {
    bool is_map_array;
    napi_is_array(env_, object, &is_map_array);
    if (is_map_array) {
        napi_value map_arr_value_result;
        napi_valuetype map_arr_type_result;
        napi_get_element (env_, object, 0, &map_arr_value_result);
        napi_typeof(env_, map_arr_value_result, &map_arr_type_result);
        if (map_arr_type_result == napi_string) {
            return "map_arr_string";
        } else if (map_arr_type_result == napi_number) {
            return "map_arr_number";
        } else if (map_arr_type_result == napi_boolean) {
            return "map_arr_boolean";
        } else {
            return nullptr;
        }
    }
    return nullptr;
}

void XNapiTool::SetAnyValueArrMap(std::string &any_type, napi_value argv, std::any &any, uint32_t len)
{
    if (any_type == "arr_map_string") {
        std::vector<std::map<std::string, std::string>> any_arr_map_string;
        for (uint32_t i = 0; i < len; i++) {
            std::map<std::string, std::string> arr_map_string;
            uint32_t len2 = GetMapLength(GetArrayElement(argv, i));
            for (uint32_t j = 0; j < len2; j++) {
                std::string tt1;
                std::string tt2;
                SwapJs2CUtf8(GetMapElementName(GetArrayElement(argv, i), j), tt1);
                SwapJs2CUtf8(GetMapElementValue(GetArrayElement(argv, i), tt1.c_str()), tt2);
                arr_map_string.insert(std::make_pair(tt1, tt2));
            }
            any_arr_map_string.push_back(arr_map_string);
        }
        any = any_arr_map_string;
    } else if (any_type == "arr_map_number") {
        std::vector<std::map<std::string, std::uint32_t>> any_arr_map_number;
        for (uint32_t i = 0; i < len; i++) {
            std::map<std::string, std::uint32_t> arr_map_number;
            uint32_t len2 = GetMapLength(GetArrayElement(argv, i));
            for (uint32_t j = 0; j < len2; j++) {
                std::string tt1;
                uint32_t tt2;
                SwapJs2CUtf8(GetMapElementName(GetArrayElement(argv, i), i), tt1);
                tt2 = SwapJs2CInt32(GetMapElementValue(GetArrayElement(argv, i), tt1.c_str()));
                arr_map_number.insert(std::make_pair(tt1, tt2));
            }
            any_arr_map_number.push_back(arr_map_number);
        }
        any = any_arr_map_number;
    } else if (any_type == "arr_map_boolean") {
        std::vector<std::map<std::string, bool>> any_arr_map_bool;
        for (uint32_t i = 0; i < len; i++) {
            std::map<std::string, bool> arr_map_bool;
            uint32_t len2 = GetMapLength(GetArrayElement(argv, i));
            for (uint32_t j = 0; j < len2; j++) {
                std::string tt1;
                bool tt2;
                SwapJs2CUtf8(GetMapElementName(GetArrayElement(argv, i), i), tt1);
                tt2 = SwapJs2CBool(GetMapElementValue(GetArrayElement(argv, i), tt1.c_str()));
                arr_map_bool.insert(std::make_pair(tt1, tt2));
            }
            any_arr_map_bool.push_back(arr_map_bool);
        }
        any = any_arr_map_bool;
    } 
    return;
}

void XNapiTool::SetAnyValueMapArr(std::string &any_type, napi_value argv, std::any &any, uint32_t len)
{
    if (any_type == "map_arr_string") {
        std::map<std::string, std::vector<std::string>> any_map_arr_string;
        for (uint32_t i = 0; i < len; i++) {
            std::string tt1;
            std::vector<std::string> map_arr_string;
            SwapJs2CUtf8(GetMapElementName(argv, i), tt1);
            uint32_t len2 = GetArrayLength(GetMapElementValue(argv, tt1.c_str()));
            for (uint32_t j = 0; j < len2; j++) {
                std::string tt;
                SwapJs2CUtf8(GetArrayElement(GetMapElementValue(argv, tt1.c_str()), j), tt);
                map_arr_string.push_back(tt);
            }
            any_map_arr_string.insert(std::make_pair(tt1, map_arr_string));
        }
        any = any_map_arr_string;
        return;
    } else if (any_type == "map_arr_number") {
        std::map<std::string, std::vector<std::uint32_t>> any_map_arr_number;
        for (uint32_t i = 0; i < len; i++) {
            std::string tt1;
            std::vector<std::uint32_t> map_arr_number;
            SwapJs2CUtf8(GetMapElementName(argv, i), tt1);
            uint32_t len2 = GetArrayLength(GetMapElementValue(argv, tt1.c_str()));
            for (uint32_t j = 0; j < len2; j++) {
                uint32_t tt;
                tt = SwapJs2CInt32(GetArrayElement(GetMapElementValue(argv, tt1.c_str()), j));
                map_arr_number.push_back(tt);
            }
            any_map_arr_number.insert(std::make_pair(tt1, map_arr_number));
        }
        any = any_map_arr_number;
        return;
    } else if (any_type == "map_arr_boolean") {
        std::map<std::string, std::vector<bool>> any_map_arr_bool;
        for (uint32_t i = 0; i < len; i++) {
            std::string tt1;
            std::vector<bool> map_arr_bool;
            SwapJs2CUtf8(GetMapElementName(argv, i), tt1);
            uint32_t len2 = GetArrayLength(GetMapElementValue(argv, tt1.c_str()));
            for (uint32_t j = 0; j < len2; j++) {
                bool tt;
                tt = SwapJs2CBool(GetArrayElement(GetMapElementValue(argv, tt1.c_str()), j));
                map_arr_bool.push_back(tt);
            }
            any_map_arr_bool.insert(std::make_pair(tt1, map_arr_bool));
        }
        any = any_map_arr_bool;
        return;
    }
    return;
}

void XNapiTool::SetAnyValue(std::string &any_type, napi_value argv, std::any &any)
{
    std::string get_any_type = any_type.substr(0, 3);
    if (any_type == "string") {
        std::string any_string;
        SwapJs2CUtf8(argv, any_string);
        any = any_string;
        return;
    } else if (any_type == "boolean") {
        bool any_bool;
        any_bool = SwapJs2CBool(argv);
        any = any_bool;
        return;
    } else if (any_type == "number") {
        std::uint32_t any_number;
        any_number = SwapJs2CInt32(argv);
        any = any_number;
        return;
    } else if (get_any_type == "arr") {
        uint32_t len = GetArrayLength(argv);
        if (any_type == "arr_string") {
            std::vector<std::string> any_arr_string;
            for (uint32_t i = 0; i < len; i++) {
                std::string tt;
                SwapJs2CUtf8(GetArrayElement(argv, i), tt);
                any_arr_string.push_back(tt);
            }
            any = any_arr_string;
            return;
        } else if (any_type == "arr_number") {
            std::vector<std::uint32_t> any_arr_number;
            for (uint32_t i = 0; i < len; i++) {
                uint32_t tt;
                tt = SwapJs2CInt32(GetArrayElement(argv, i));
                any_arr_number.push_back(tt);
            }
            any = any_arr_number;
            return;
        } else if (any_type == "arr_boolean") {
            std::vector<bool> any_arr_boolean;
            for (uint32_t i = 0; i < len; i++) {
                bool tt;
                tt = SwapJs2CBool(GetArrayElement(argv, i));
                any_arr_boolean.push_back(tt);
            }
            any = any_arr_boolean;
            return;
        } else if (any_type.substr(0, 7) == "arr_map") {
            SetAnyValueArrMap(any_type, argv, any, len);
            return;
        }  
        return;   
    }  else if (get_any_type == "map") {
        uint32_t len = GetMapLength(argv);
        if (any_type == "map_string") {
            std::map<std::string, std::string> any_map_string;
            for (uint32_t i = 0; i < len; i++) {
                std::string tt1;
                std::string tt2;
                SwapJs2CUtf8(GetMapElementName(argv, i), tt1);
                SwapJs2CUtf8(GetMapElementValue(argv, tt1.c_str()), tt2);
                any_map_string.insert(std::make_pair(tt1, tt2));
            }
            any = any_map_string;
            return;
        } else if (any_type == "map_number") {
            std::map<std::string, std::uint32_t> any_map_number;
            for (uint32_t i = 0; i < len; i++) {
                std::string tt1;
                uint32_t tt2;
                SwapJs2CUtf8(GetMapElementName(argv, i), tt1);
                tt2 = SwapJs2CInt32(GetMapElementValue(argv, tt1.c_str()));
                any_map_number.insert(std::make_pair(tt1, tt2));
            }
            any = any_map_number;
            return;
        } else if (any_type == "map_boolean") {
            std::map<std::string, bool> any_map_boolean;
            for (uint32_t i = 0; i < len; i++) {
                std::string tt1;
                bool tt2;
                SwapJs2CUtf8(GetMapElementName(argv, i), tt1);
                tt2 = SwapJs2CBool(GetMapElementValue(argv, tt1.c_str()));
                any_map_boolean.insert(std::make_pair(tt1, tt2));
            }
            any = any_map_boolean;
            return;
        } else if (any_type.substr(0, 7) == "map_arr") {
            SetAnyValueMapArr(any_type, argv, any, len);
            return;
        } 
        return;
    }
    return;
}

void XNapiTool::GetAnyValueArrMap (std::string any_type, napi_value &result, std::any any)
{
    if (any_type == "arr_map_number") {
        std::vector<std::map<std::string, std::uint32_t>> any_arr_map_number =
        std::any_cast<std::vector<std::map<std::string, std::uint32_t>>>(any);
        uint32_t len = any_arr_map_number.size();
        for (uint32_t i = 0; i < len; i++) {
            napi_value tnv = nullptr;
            std::map<std::string, std::uint32_t> any_map_number = any_arr_map_number[i];
            for (auto j = any_map_number.begin(); j != any_map_number.end(); j++) {
                const char *tnv1;
                napi_value tnv2 = nullptr;
                tnv1 = (j->first).c_str();
                if (typeid(j->second) == typeid(int32_t)) {
                    tnv2 = SwapC2JsInt32(j->second);
                } else if (typeid(j->second) == typeid(uint32_t)) {
                    tnv2 = SwapC2JsUint32(j->second);
                } else if (typeid(j->second) == typeid(int64_t)) {
                    tnv2 = SwapC2JsInt64(j->second);
                } else if (typeid(j->second) == typeid(double_t)) {
                    tnv2 = SwapC2JsDouble(j->second);
                }
                SetMapElement(tnv, tnv1, tnv2);
            }
            SetArrayElement(result, i, tnv);
        }
        return;
    } else if (any_type == "arr_map_string") {
        std::vector<std::map<std::string, std::string>> any_arr_map_string =
        std::any_cast<std::vector<std::map<std::string, std::string>>>(any);
        uint32_t len = any_arr_map_string.size();
        for (uint32_t i = 0; i < len; i++) {
            napi_value tnv = nullptr;
            std::map<std::string, std::string> any_map_string = any_arr_map_string[i];
            for (auto j = any_map_string.begin(); j != any_map_string.end(); j++) {
                const char *tnv1;
                napi_value tnv2 = nullptr;
                tnv1 = (j->first).c_str();
                tnv2 = SwapC2JsUtf8(j->second.c_str());
                SetMapElement(tnv, tnv1, tnv2);
            }
            SetArrayElement(result, i, tnv);
        }
        return;
    } else if (any_type == "arr_map_boolean") {
        std::vector<std::map<std::string, bool>> any_arr_map_bool =
        std::any_cast<std::vector<std::map<std::string, bool>>>(any);
        uint32_t len = any_arr_map_bool.size();
        for (uint32_t i = 0; i < len; i++) {
            napi_value tnv = nullptr;
            std::map<std::string, bool> any_map_bool= any_arr_map_bool[i];
            for (auto j = any_map_bool.begin(); j != any_map_bool.end(); j++) {
                const char *tnv1;
                napi_value tnv2 = nullptr;
                tnv1 = (j->first).c_str();
                tnv2 = SwapC2JsBool(j->second);
                SetMapElement(tnv, tnv1, tnv2);
            }
            SetArrayElement(result, i, tnv);
        }
        return;
    } 
    return;
}

void XNapiTool::GetAnyValueMapArr (std::string any_type, napi_value &result, std::any any)
{
    if (any_type == "map_arr_string") {
        std::map<std::string, std::vector<std::string>> any_map_arr_string =
        std::any_cast<std::map<std::string, std::vector<std::string>>>(any);
        for (auto i = any_map_arr_string.begin(); i != any_map_arr_string.end(); i++) {
            const char *tnv1;
            napi_value tnv2 = nullptr;
            tnv1 = (i->first).c_str();
            std::vector<std::string> map_arr_string = i->second;
            uint32_t len2 = map_arr_string.size();
            for (uint32_t j = 0; j < len2; j++) {
                napi_value tnv = nullptr;
                tnv = SwapC2JsUtf8(map_arr_string[j].c_str());
                SetArrayElement(tnv2, j, tnv);
            }
            SetMapElement(result, tnv1, tnv2);
        }
        return;
    } else if (any_type == "map_arr_number") {
        std::map<std::string, std::vector<std::uint32_t>> any_map_arr_number =
        std::any_cast<std::map<std::string, std::vector<std::uint32_t>>>(any);
        for (auto i = any_map_arr_number.begin(); i != any_map_arr_number.end(); i++) {
            const char *tnv1;
            napi_value tnv2 = nullptr;
            tnv1 = (i->first).c_str();
            std::vector<std::uint32_t> map_arr_number = i->second;
            uint32_t len2 = map_arr_number.size();
            for (uint32_t j = 0; j < len2; j++) {
                napi_value tnv = nullptr;
                if (typeid(map_arr_number[j]) == typeid(int32_t)) {
                    tnv = SwapC2JsInt32(map_arr_number[j]);
                } else if (typeid(map_arr_number[j]) == typeid(uint32_t)) {
                    tnv = SwapC2JsUint32(map_arr_number[j]);
                } else if (typeid(map_arr_number[j]) == typeid(int64_t)) {
                    tnv = SwapC2JsInt64(map_arr_number[j]);
                } else if (typeid(map_arr_number[j]) == typeid(double_t)) {
                    tnv = SwapC2JsDouble(map_arr_number[j]);
                }
                SetArrayElement(tnv2, j, tnv);
            }
            SetMapElement(result, tnv1, tnv2);
        }
        return;
    } else if (any_type == "map_arr_boolean") {
        std::map<std::string, std::vector<bool>> any_map_arr_bool =
        std::any_cast<std::map<std::string, std::vector<bool>>>(any);
        for (auto i = any_map_arr_bool.begin(); i != any_map_arr_bool.end(); i++) {
            const char *tnv1;
            napi_value tnv2 = nullptr;
            tnv1 = (i->first).c_str();
            std::vector<bool> map_arr_bool = i->second;
            uint32_t len2 = map_arr_bool.size();
            for (uint32_t j = 0; j < len2; j++) {
                napi_value tnv = nullptr;
                tnv = SwapC2JsBool(map_arr_bool[j]);
                SetArrayElement(result, j, tnv);
            }
            SetMapElement(result, tnv1, tnv2);
        }
        return;
    }
    return;
}

void XNapiTool::GetAnyValue (std::string any_type, napi_value &result, std::any any)
{
    result = nullptr;
    std::string get_any_type = any_type.substr(0, 3);
    if (any_type == "string") {
        std::string any_string = std::any_cast<std::string>(any);
        result = SwapC2JsUtf8(any_string.c_str());
        return;
    } else if (any_type == "boolean") {
        bool any_bool = std::any_cast<bool>(any);
        result = SwapC2JsBool(any_bool);
        return;
    } else if (any_type == "number") {
        std::uint32_t any_number = std::any_cast<std::uint32_t>(any);
        if (typeid(any_number) == typeid(int32_t))
            result = SwapC2JsInt32(any_number);
        else if (typeid(any_number) == typeid(uint32_t))
            result = SwapC2JsUint32(any_number);
        else if (typeid(any_number) == typeid(int64_t))
            result = SwapC2JsInt64(any_number);
        else if (typeid(any_number) == typeid(double_t))
            result = SwapC2JsDouble(any_number);
        return;
    } else if (get_any_type == "arr") {
        result = nullptr;
        if (any_type == "arr_string") {
            std::vector<std::string> any_arr_string = std::any_cast<std::vector<std::string>>(any);
            uint32_t len = any_arr_string.size();
            for (uint32_t i = 0; i < len; i++) {
                napi_value tnv = nullptr;
                tnv = SwapC2JsUtf8(any_arr_string[i].c_str());
                SetArrayElement(result, i, tnv);
            }
            return;
        } else if (any_type == "arr_number") {
            std::vector<std::uint32_t> any_arr_number = std::any_cast<std::vector<std::uint32_t>>(any);
            uint32_t len = any_arr_number.size();
            for (uint32_t i = 0; i < len; i++) {
                napi_value tnv = nullptr;
                if (typeid(any_arr_number[i]) == typeid(int32_t)) {
                    tnv = SwapC2JsInt32(any_arr_number[i]);
                } else if (typeid(any_arr_number[i]) == typeid(uint32_t)) {
                    tnv = SwapC2JsUint32(any_arr_number[i]);
                } else if (typeid(any_arr_number[i]) == typeid(int64_t)) {
                    tnv = SwapC2JsInt64(any_arr_number[i]);
                } else if (typeid(any_arr_number[i]) == typeid(double_t)) {
                    tnv = SwapC2JsDouble(any_arr_number[i]);
                }
                SetArrayElement(result, i, tnv);
            }
            return;
        } else if (any_type == "arr_boolean") {
            std::vector<bool> any_arr_boolean = std::any_cast<std::vector<bool>>(any);
            uint32_t len = any_arr_boolean.size();
            for (uint32_t i = 0; i < len; i++) {
                napi_value tnv = nullptr;
                tnv = SwapC2JsBool(any_arr_boolean[i]);
                SetArrayElement(result, i, tnv);
            }
            return;
        } else if (any_type.substr(0, 7) == "arr_map") {
            GetAnyValueArrMap(any_type, result, any);
            return;
        }
        return;
    } else if (get_any_type == "map") {
        if (any_type == "map_string") {
            std::map<std::string, std::string> any_map_string =
            std::any_cast<std::map<std::string, std::string>>(any);
            for (auto i = any_map_string.begin(); i != any_map_string.end(); i++) {
                const char *tnv1;
                napi_value tnv2 = nullptr;
                tnv1 = (i->first).c_str();
                tnv2 = SwapC2JsUtf8(i->second.c_str());
                SetMapElement(result, tnv1, tnv2);
            }
            return;
        } else if (any_type == "map_number") {
            std::map<std::string, std::uint32_t> any_map_number =
            std::any_cast<std::map<std::string, std::uint32_t>>(any);
            for (auto i = any_map_number.begin(); i != any_map_number.end(); i++) {
                const char *tnv1;
                napi_value tnv2 = nullptr;
                tnv1 = (i->first).c_str();
                if (typeid(i->second) == typeid(int32_t)) {
                    tnv2 = SwapC2JsInt32(i->second);
                } else if (typeid(i->second) == typeid(uint32_t)) {
                    tnv2 = SwapC2JsUint32(i->second);
                } else if (typeid(i->second) == typeid(int64_t)) {
                    tnv2 = SwapC2JsInt64(i->second);
                } else if (typeid(i->second) == typeid(double_t)) {
                    tnv2 = SwapC2JsDouble(i->second);
                }
                SetMapElement(result, tnv1, tnv2);
            }
            return;
        } else if (any_type == "map_boolean") {
            std::map<std::string, bool> any_map_boolean = std::any_cast<std::map<std::string, bool>>(any);
            for (auto i = any_map_boolean.begin(); i != any_map_boolean.end(); i++) {
                const char *tnv1;
                napi_value tnv2 = nullptr;
                tnv1 = (i->first).c_str();
                tnv2 = SwapC2JsBool(i->second);
                SetMapElement(result, tnv1, tnv2);
            }
            return;
        } else if (any_type.substr(0, 7) == "map_arr") {
            GetAnyValueMapArr(any_type, result, any);
            return;
        }
        return;
    }
    return;
}

std::string XNapiTool::GetUnionType(napi_value object)
{
    napi_valuetype result;
    napi_typeof(env_, object, &result);
    if (result == napi_string) {
        return "string";
    } else if (result == napi_number) {
        return "number";
    } else if (result == napi_boolean) {
        return "boolean";
    } else {
        return nullptr;
    }
}

void XNapiTool::GetObjectValVecUint32 (std::any &anyVal, napi_value &tnv2)
{
    std::vector<uint32_t> arr = std::any_cast<std::vector<uint32_t>>(anyVal);
    for (size_t j = 0; j < arr.size(); j++) {
        uint32_t tt = arr[j] ;
        napi_value tnv3 = SwapC2JsUint32(tt);
        SetArrayElement(tnv2, j, tnv3);
    }
}

void XNapiTool::GetObjectValVecInt32 (std::any &anyVal, napi_value &tnv2)
{
    std::vector<int32_t> arr = std::any_cast<std::vector<int32_t>>(anyVal);
    for (size_t j = 0; j < arr.size(); j++) {
        int32_t tt = arr[j] ;
        napi_value tnv3 = SwapC2JsInt32(tt);
        SetArrayElement(tnv2, j, tnv3);
    }
}

void XNapiTool::GetObjectValVecInt64 (std::any &anyVal, napi_value &tnv2)
{
    std::vector<int64_t> arr = std::any_cast<std::vector<int64_t>>(anyVal);
    for (size_t j = 0; j < arr.size(); j++) {
        int64_t tt = arr[j] ;
        napi_value tnv3 = SwapC2JsInt64(tt);
        SetArrayElement(tnv2, j, tnv3);
    }
}

void XNapiTool::GetObjectValVecDouble (std::any &anyVal, napi_value &tnv2)
{
    std::vector<double_t> arr = std::any_cast<std::vector<double_t>>(anyVal);
    for (size_t j = 0; j < arr.size(); j++) {
        double_t tt = arr[j] ;
        napi_value tnv3 = SwapC2JsDouble(tt);
        SetArrayElement(tnv2, j, tnv3);
    }
}

void XNapiTool::GetObjectValVecBool (std::any &anyVal, napi_value &tnv2)
{
    std::vector<bool> arr = std::any_cast<std::vector<bool>>(anyVal);
    for (size_t j = 0; j < arr.size(); j++) {
        bool tt = arr[j] ;
        napi_value tnv3 = SwapC2JsBool(tt);
        SetArrayElement(tnv2, j, tnv3);
    }
}

void XNapiTool::GetObjectValVecConstchar (std::any &anyVal, napi_value &tnv2)
{
    std::vector<const char *> arr = std::any_cast<std::vector<const char *>>(anyVal);
    for (size_t j = 0; j < arr.size(); j++) {
        const char *tt = arr[j] ;
        napi_value tnv3 = SwapC2JsUtf8(tt);
        SetArrayElement(tnv2, j, tnv3);
    }
}

void XNapiTool::GetObjectValMapString (std::any &anyVal, napi_value &tnv2)
{
    std::map<std::string, std::string> a = std::any_cast<std::map<std::string, std::string>>(anyVal);
    std::map<std::string, std::string>::iterator iter;
    for (iter = a.begin(); iter != a.end(); iter++) {
        const char *key = iter->first.c_str();
        napi_value value = SwapC2JsUtf8(iter->second.c_str());
        SetMapElement(tnv2, key, value);
    }
}

void XNapiTool::GetObjectValMapUint32 (std::any &anyVal, napi_value &tnv2)
{
    std::map<std::string, uint32_t> a = std::any_cast<std::map<std::string, uint32_t>>(anyVal);
    std::map<std::string, uint32_t>::iterator iter;
    for (iter = a.begin(); iter != a.end(); iter++) {
        const char *key = iter->first.c_str();
        napi_value value =  SwapC2JsUint32(iter->second);
        SetMapElement(tnv2, key, value);
    }
}

void XNapiTool::GetObjectValMapInt32 (std::any &anyVal, napi_value &tnv2)
{
    std::map<std::string, int32_t> a = std::any_cast<std::map<std::string, int32_t>>(anyVal);
    std::map<std::string, int32_t>::iterator iter;
    for (iter = a.begin(); iter != a.end(); iter++) {
        const char *key = iter->first.c_str();
        napi_value value =  SwapC2JsInt32(iter->second);
        SetMapElement(tnv2, key, value);
    }
}

void XNapiTool::GetObjectValMapInt64 (std::any &anyVal, napi_value &tnv2)
{
    std::map<std::string, int64_t> a = std::any_cast<std::map<std::string, int64_t>>(anyVal);
    std::map<std::string, int64_t>::iterator iter;
    for (iter = a.begin(); iter != a.end(); iter++) {
        const char *key = iter->first.c_str();
        napi_value value =  SwapC2JsInt64(iter->second);
        SetMapElement(tnv2, key, value);
    }
}

void XNapiTool::GetObjectValMapDouble (std::any &anyVal, napi_value &tnv2)
{
    std::map<std::string, double_t> a = std::any_cast<std::map<std::string, double_t>>(anyVal);
    std::map<std::string, double_t>::iterator iter;
    for (iter = a.begin(); iter != a.end(); iter++) {
        const char *key = iter->first.c_str();
        napi_value value =  SwapC2JsDouble(iter->second);
        SetMapElement(tnv2, key, value);
    }
}

void XNapiTool::GetObjectValMapBool (std::any &anyVal, napi_value &tnv2)
{
    std::map<std::string, bool> a = std::any_cast<std::map<std::string, bool>>(anyVal);
    std::map<std::string, bool>::iterator iter;
    for (iter = a.begin(); iter != a.end(); iter++) {
        const char *key = iter->first.c_str();
        napi_value value = SwapC2JsBool(iter->second);  
        SetMapElement(tnv2, key, value);
    }
}

void XNapiTool::GetObjectValMapAny (std::any &anyVal, napi_value &tnv2)
{
    std::map<std::string, std::any> a = std::any_cast<std::map<std::string, std::any>>(anyVal);
    std::map<std::string, std::any>::iterator iter;
    for (iter = a.begin(); iter != a.end(); iter++) {
        auto c = iter->second;
        if (c.type() == typeid(uint32_t)) {
            const char *key = iter->first.c_str();     
            uint32_t val = std::any_cast<uint32_t>(iter->second);
            napi_value value = SwapC2JsUint32(val);
            SetMapElement(tnv2, key, value); 
        } else if (c.type() == typeid(int32_t)) {
            const char *key = iter->first.c_str();     
            int32_t val = std::any_cast<int32_t>(iter->second);
            napi_value value = SwapC2JsInt32(val);
            SetMapElement(tnv2, key, value);
        } else if (c.type() == typeid(int64_t)) {
            const char *key = iter->first.c_str();     
            int64_t val = std::any_cast<int64_t>(iter->second);
            napi_value value = SwapC2JsInt64(val);
            SetMapElement(tnv2, key, value);
        } else if (c.type() == typeid(double_t)) {
            const char *key = iter->first.c_str();     
            double_t val = std::any_cast<double_t>(iter->second);
            napi_value value = SwapC2JsDouble(val);
            SetMapElement(tnv2, key, value);
        } else if (c.type() == typeid(const char *)) {
            const char *key = iter->first.c_str();
            const char *val = std::any_cast<const char *>(iter->second);
            napi_value value = SwapC2JsUtf8(val);
            SetMapElement(tnv2, key, value);
        } else if (c.type() == typeid(bool)) {
            const char *key = iter->first.c_str();
            bool val = std::any_cast<bool>(iter->second);
            napi_value value = SwapC2JsBool(val);
            SetMapElement(tnv2, key, value);
        }         
    }
}

void XNapiTool::GetObjectValue(napi_value &result, std::map<std::string, std::any> valueIn)
{
    napi_create_object(env_, &result);

    for (auto i = valueIn.begin(); i != valueIn.end(); i++) {
        const char *tnv1;
        std::any anyValue;
        napi_value tnv2 = nullptr;
        tnv1 = (i->first).c_str();
        auto temp = i->second;
        if (temp.type() == typeid(int32_t)) {
            tnv2 = SwapC2JsInt32(std::any_cast<int32_t>(temp));
        } else if (temp.type() == typeid(uint32_t)) {
            tnv2 = SwapC2JsUint32(std::any_cast<uint32_t>(temp));
        } else if (temp.type() == typeid(int64_t)) {
            tnv2 = SwapC2JsInt64(std::any_cast<int64_t>(temp));
        } else if (temp.type() == typeid(double_t)) {
            tnv2 = SwapC2JsDouble(std::any_cast<double_t>(temp));
        } else if (temp.type() == typeid(const char *)) {
            tnv2 = SwapC2JsUtf8(std::any_cast<const char *>(temp));
        } else if (temp.type() == typeid(bool)) {
            tnv2 = SwapC2JsBool(std::any_cast<bool>(temp));
        } else if (temp.type() == typeid(std::vector<uint32_t>)) {
            GetObjectValVecUint32(i->second, tnv2);
        } else if (temp.type() == typeid(std::vector<int32_t>)) {
            GetObjectValVecInt32(i->second, tnv2);
        } else if (temp.type() == typeid(std::vector<int64_t>)) {
            GetObjectValVecInt64(i->second, tnv2);
        } else if (temp.type() == typeid(std::vector<double_t>)) {
            GetObjectValVecDouble(i->second, tnv2);
        } else if (temp.type() == typeid(std::vector<bool>)) {
            GetObjectValVecBool(i->second, tnv2);
        } else if (temp.type() == typeid(std::vector<const char *>)) {
            GetObjectValVecConstchar(i->second, tnv2);
        } else if (temp.type() == typeid(std::map<std::string, std::string>)) {
            GetObjectValMapString(i->second, tnv2);
        } else if (temp.type() == typeid(std::map<std::string, uint32_t>)) {
            GetObjectValMapUint32(i->second, tnv2);  
        } else if (temp.type() == typeid(std::map<std::string, int32_t>)) {
            GetObjectValMapInt32(i->second, tnv2);
        } else if (temp.type() == typeid(std::map<std::string, int64_t>)) {
            GetObjectValMapInt64(i->second, tnv2);
        } else if (temp.type() == typeid(std::map<std::string, double_t>)) {
            GetObjectValMapDouble(i->second, tnv2);  
        } else if (temp.type() == typeid(std::map<std::string, bool>)) {
            GetObjectValMapBool(i->second, tnv2);
        } else if (temp.type() == typeid(std::map<std::string, std::any>)) {
            GetObjectValMapAny(i->second, tnv2);
        }
        
        SetMapElement(result, tnv1, tnv2);
    }
    return;
}

bool XNapiTool::CheckFailed(bool b, const char *errStr)
{
    if (bFailed_) {
        return true;
    }
    if (b) {
        return false;
    }

    napi_value errCode = nullptr;
    napi_value errMessage = nullptr;

    napi_create_string_utf8(env_, "x_tool", strlen("x_tool"), &errCode);
    napi_create_string_utf8(env_, errStr, strlen(errStr), &errMessage);
    napi_create_error(env_, errCode, errMessage, &error_);
    printf("tool_utility err : %s\\n", errStr);

    bFailed_ = true;
    return true;
}

int32_t XNapiTool::SwapJs2CInt32(napi_value value)
{
    int32_t result;
    napi_status result_status = napi_get_value_int32(env_, value, &result);
    if (CheckFailed(result_status == napi_ok, "swap_js_2_c_int32 fail"))
        return -1;
    return result;
}

uint32_t XNapiTool::SwapJs2CUint32(napi_value value)
{
    uint32_t result;
    napi_status result_status = napi_get_value_uint32(env_, value, &result);
    if (CheckFailed(result_status == napi_ok, "swap_js_2_c_uint32 fail"))
        return -1;
    return result;
}

int64_t XNapiTool::SwapJs2CInt64(napi_value value)
{
    int64_t result;
    napi_status result_status = napi_get_value_int64(env_, value, &result);
    if (CheckFailed(result_status == napi_ok, "swap_js_2_c_int32 fail"))
        return -1;
    return result;
}

double_t XNapiTool::SwapJs2CDouble(napi_value value)
{
    double_t result;
    napi_status result_status = napi_get_value_double(env_, value, &result);
    if (CheckFailed(result_status == napi_ok, "swap_js_2_c_int32 fail"))
        return -1;
    return result;
}

size_t XNapiTool::SwapJs2CUtf8(napi_value value, std::string &str)
{
    char buf[1024];
    size_t result;
    napi_status result_status = napi_get_value_string_utf8(env_, value, buf, 1024, &result);
    if (CheckFailed(result_status == napi_ok, "napi_get_value_string_utf8 fail"))
        return -1;
    str = buf;
    return result;
}

napi_value XNapiTool::SwapC2JsBool(bool value)
{
    napi_value result;
    napi_status result_status = napi_get_boolean(env_, value, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SwapC2JsInt32(int32_t value)
{
    napi_value result;
    napi_status result_status = napi_create_int32(env_, value, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SwapC2JsUint32(uint32_t value)
{
    napi_value result;
    napi_status result_status = napi_create_uint32(env_, value, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SwapC2JsInt64(int64_t value)
{
    napi_value result;
    napi_status result_status = napi_create_int64(env_, value, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SwapC2JsDouble(double_t value)
{
    napi_value result;
    napi_status result_status = napi_create_double(env_, value, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

napi_value XNapiTool::SwapC2JsUtf8(const char *value)
{
    napi_value result;
    napi_status result_status = napi_create_string_utf8(env_, value, NAPI_AUTO_LENGTH, &result);
    CC_ASSERT(result_status == napi_ok);
    return result;
}

bool XNapiTool::CheckValueType(napi_value value, napi_valuetype type)
{
    napi_valuetype valueType;
    napi_status result_status = napi_typeof(env_, value, &valueType);
    CC_ASSERT(result_status == napi_ok);
    if (CheckFailed(valueType == type, "传入参数类型不是回调函数"))
        return false;
    return true;
}

napi_value XNapiTool::SyncCallBack(napi_value func, size_t argc, napi_value *args)
{
    napi_value cb_result;
    napi_status result_status = napi_call_function(env_, thisVar_, func, argc, args, &cb_result);
    CC_ASSERT(result_status == napi_ok);
    return cb_result;
}

void XNapiTool::AsyncExecuteFunction()
{
    if (executeFunction_ != nullptr) {
        executeFunction_(this, valueData_);
    }
}
void XNapiTool::AsyncExecute(napi_env env, XNapiTool *p)
{
    XNapiTool *pxt = p;
    pxt->AsyncExecuteFunction();
}
void XNapiTool::AsyncCompleteFunction()
{
    if (completeFunction_ != nullptr) {
        completeFunction_(this, valueData_);
    }
}
void XNapiTool::AsyncComplete(napi_env env, napi_status status, XNapiTool *p)
{
    XNapiTool *pxt = p;
    pxt->AsyncCompleteFunction();
    delete pxt;
}

napi_value XNapiTool::StartAsync(CallbackFunction pe, DataPtr data, CallbackFunction pc, napi_value func)
{
    napi_value result;
    napi_status result_status;

    if (func == nullptr) {
        // promise
        result_status = napi_create_promise(env_, &deferred_, &result);
        CC_ASSERT(result_status == napi_ok);
        asyncMode_ = AsyncMode::PROMISE;
    } else {
        // callback
        result_status = napi_create_reference(env_, func, 1, &callbackFunc_);
        CC_ASSERT(result_status == napi_ok);
        napi_create_reference(env_, thisVar_, 1, &asyncThisVar_);
        asyncMode_ = AsyncMode::CALLBACK;
        result = UndefinedValue(env_);
    }

    asyncNeedRelease_ = true;
    executeFunction_ = pe;
    completeFunction_ = pc;
    valueData_ = data;

    napi_value resourceName = nullptr;
    result_status = napi_create_string_utf8(env_, "tool_utility", NAPI_AUTO_LENGTH, &resourceName);
    CC_ASSERT(result_status == napi_ok);
    result_status = napi_create_async_work(env_, nullptr, resourceName,
        (napi_async_execute_callback)XNapiTool::AsyncExecute,
        (napi_async_complete_callback)XNapiTool::AsyncComplete, this, &work_);
    CC_ASSERT(result_status == napi_ok);
    result_status = napi_queue_async_work(env_, work_);
    CC_ASSERT(result_status == napi_ok);

    return result;
}

void XNapiTool::FinishAsync(size_t argc, napi_value *args)
{
    if (asyncMode_ == AsyncMode::PROMISE) {
        if (argc > 1) {
            napi_resolve_deferred(env_, deferred_, args[1]);
        } else {
            napi_reject_deferred(env_, deferred_, SwapC2JsUtf8("promise fail"));
        }
        return;
    }
    napi_value result = 0;
    napi_value cb = 0;

    napi_status result_status = napi_get_reference_value(env_, callbackFunc_, &cb);
    CC_ASSERT(result_status == napi_ok);
    napi_value asyncThis = 0;
    napi_get_reference_value(env_, asyncThisVar_, &asyncThis);
    result_status = napi_call_function(env_, asyncThis, cb, argc, args, &result);
    CC_ASSERT(result_status == napi_ok);
}

napi_value XNapiTool::UndefinedValue(napi_env env)
{
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value XNapiTool::UndefinedValue()
{
    napi_value result;
    napi_get_undefined(env_, &result);
    return result;
}

napi_value XNapiTool::CreateSubObject(napi_value parent, const char *name)
{
    napi_value result;
    napi_status result_status = napi_create_object(env_, &result);
    CC_ASSERT(result_status == napi_ok);

    result_status = napi_set_named_property(env_, parent, name, result);
    CC_ASSERT(result_status == napi_ok);

    return result;
}

void XNapiTool::DefineFunction(const char *funcName, napi_callback callback, napi_value dest)
{
    if (dest == nullptr)
        dest = exports_;
    napi_property_descriptor descriptor[] = {
        {funcName, 0, callback, 0, 0, 0, napi_default, 0}};

    napi_status result_status = napi_define_properties(env_, dest, 1, descriptor);
    CC_ASSERT(result_status == napi_ok);
}

void XNapiTool::SetEnumProperty(napi_value dstObj, const char *propName, std::any objValue)
{
    napi_value prop = nullptr;
    napi_status result_status = napi_invalid_arg;

    if (objValue.type() == typeid(int32_t)) {
        result_status = napi_create_int32(env_, std::any_cast<int32_t>(objValue), &prop);
    } else if (objValue.type() == typeid(uint32_t)) {
        result_status = napi_create_uint32(env_, std::any_cast<uint32_t>(objValue), &prop);
    } else if (objValue.type() == typeid(int64_t)) {
        result_status = napi_create_int64(env_, std::any_cast<int64_t>(objValue), &prop);
    } else if (objValue.type() == typeid(double_t)) {
        result_status = napi_create_double(env_, std::any_cast<double_t>(objValue), &prop);
    } else if (objValue.type() == typeid(const char *)) {
        result_status = napi_create_string_utf8(env_, std::any_cast<const char *>(objValue), NAPI_AUTO_LENGTH, &prop);
    }

    CC_ASSERT(result_status == napi_ok);
    result_status = napi_set_named_property(env_, dstObj, propName, prop);
    CC_ASSERT(result_status == napi_ok);
}

void XNapiTool::CreateEnumObject(const char *enumName, std::map<const char *, std::any> enumMap)
{
    napi_value enumObj = nullptr;
    napi_create_object(env_, &enumObj);

    for (auto it = enumMap.begin(); it != enumMap.end(); it++) {
        SetEnumProperty(enumObj, it->first, it->second);
    }

    napi_property_descriptor exportEnum[] = {
        {enumName, 0, 0, 0, 0, enumObj, napi_enumerable, 0}
    };
    napi_status result_status = napi_define_properties(env_, exports_, 1, exportEnum);
    CC_ASSERT(result_status == napi_ok);
}

void XNapiTool::DefineClass(const char *className, napi_callback constructorFunc,
    std::map<const char *, std::map<const char *, napi_callback>> &valueList,
    std::map<const char *, napi_callback> &funcList, napi_value dest)
{
    if (dest == nullptr)
        dest = exports_;
    napi_value tmpClass = nullptr;
    napi_property_descriptor funcs[funcList.size() + valueList.size()];

    uint32_t p = 0;
    for (auto it = valueList.begin(); it != valueList.end(); it++) {
        funcs[p++] = {it->first, 0, 0, it->second["getvalue"], it->second["setvalue"], 0, napi_default, 0}; // get,set
    }
    for (auto it = funcList.begin(); it != funcList.end(); it++) {
        funcs[p++] = {it->first, 0, it->second, 0, 0, 0, napi_default, 0};
    }

    napi_status result_status = napi_define_class(env_, className, NAPI_AUTO_LENGTH, constructorFunc,
    nullptr, p, funcs, &tmpClass);
    CC_ASSERT(result_status == napi_ok);

    result_status = napi_set_named_property(env_, dest, className, tmpClass);
    CC_ASSERT(result_status == napi_ok);
}

void XNapiTool::WrapFinalize(napi_env env, XNapiTool *data, DataPtr hint)
{
    XNapiTool *pxt = data;
    pxt->ReleaseInstance();
    delete pxt;
}

void XNapiTool::ReleaseInstance()
{
    if (releaseInstance_ != nullptr) {
        releaseInstance_(pInstance_);
    }
}

napi_value XNapiTool::WrapInstance(DataPtr instance, RELEASE_INSTANCE ri)
{
    pInstance_ = instance;
    releaseInstance_ = ri;
    napi_status result_status = napi_wrap(env_, thisVar_, this, (napi_finalize)WrapFinalize, nullptr, &wrapper_);
    CC_ASSERT(result_status == napi_ok);
    return thisVar_;
}

DataPtr XNapiTool::UnWarpInstance()
{
    XNapiTool *p;
    napi_status result_status = napi_unwrap(env_, thisVar_, (void **)&p);
    CC_ASSERT(result_status == napi_ok);
    return p->pInstance_;
}

void XNapiTool::SetAsyncInstance(DataPtr p)
{
    asyncInstance_ = p;
}

void* XNapiTool::GetAsyncInstance()
{
    return asyncInstance_;
}

std::map<std::string, CallFunc> XNapiTool::callFuncs_;
void XNapiTool::RegistOnOffFunc(std::string name, napi_value func)
{
    if (XNapiTool::callFuncs_.count(name) > 0) {
        UnregistOnOffFunc(name);
    }
    XNapiTool::callFuncs_[name].env_ = env_;
    napi_status result_status = napi_create_reference(env_, func, 1, &XNapiTool::callFuncs_[name].funcRef_);
    CC_ASSERT(result_status == napi_ok);
    result_status = napi_create_reference(env_, thisVar_, 1, &XNapiTool::callFuncs_[name].thisVarRef_);
    CC_ASSERT(result_status == napi_ok);
}

void XNapiTool::UnregistOnOffFunc(std::string name)
{
    if (XNapiTool::callFuncs_.count(name) <= 0) {
        return;
    }
    napi_status result_status = napi_delete_reference(env_, XNapiTool::callFuncs_[name].funcRef_);
    CC_ASSERT(result_status == napi_ok);
    result_status = napi_delete_reference(env_, XNapiTool::callFuncs_[name].thisVarRef_);
    CC_ASSERT(result_status == napi_ok);
    XNapiTool::callFuncs_.erase(name);
}

std::map<std::string, ThreadsafeFunc> XNapiTool::threadsafeCallFuncs_;
void XNapiTool::RegistThreadsafeFunc(std::string name, napi_threadsafe_function thraedsafeFunc)
{
    XNapiTool::threadsafeCallFuncs_[name].env_ = env_;
    XNapiTool::threadsafeCallFuncs_[name].threadsafefunc_ = thraedsafeFunc;
}

void XNapiTool::CallSyncFunc(CallFunc *pSyncFuncs, napi_value ret)
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(pSyncFuncs->env_, &scope);

    napi_value cb;
    napi_status result_status = napi_get_reference_value(pSyncFuncs->env_, pSyncFuncs->funcRef_, &cb);
    CC_ASSERT(result_status == napi_ok);

    napi_value thisvar;
    result_status = napi_get_reference_value(pSyncFuncs->env_, pSyncFuncs->thisVarRef_, &thisvar);
    CC_ASSERT(result_status == napi_ok);

    uint32_t length = 0;
    napi_value element;
    napi_get_array_length(pSyncFuncs->env_, ret, &length);
           
    const uint32_t LENGTH = length;
    std::vector<napi_value> args(LENGTH);
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(pSyncFuncs->env_, ret, i, &element);
        args[i] = element;
    }
  
    napi_value cb_result;

    result_status = napi_call_function(pSyncFuncs->env_, thisvar, cb, length, args.data(), &cb_result);
    CC_ASSERT(result_status == napi_ok);

    result_status = napi_close_handle_scope(pSyncFuncs->env_, scope);
    CC_ASSERT(result_status == napi_ok);
}

void XNapiTool::CallAsyncFunc(CallFunc *pAsyncFuncs, napi_value ret)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(pAsyncFuncs->env_, &loop);
    uv_work_t *work = new uv_work_t;

    struct AsyncCallData {
        napi_ref resultRef;
        CallFunc *p;
    };
    AsyncCallData *data = (AsyncCallData *)malloc(sizeof(AsyncCallData));
    napi_create_reference(pAsyncFuncs->env_, ret, 1, &data->resultRef);
    data->p = pAsyncFuncs;
    work->data = data;

    uv_queue_work(
        loop,
        work,
        [](uv_work_t *) {},
        [](uv_work_t *work, int status) {
            AsyncCallData *data = (AsyncCallData *)work->data;
            CallFunc *paf = data->p;
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(paf->env_, &scope);

            napi_value cb;
            napi_status result_status = napi_get_reference_value(paf->env_, paf->funcRef_, &cb);
            CC_ASSERT(result_status == napi_ok);

            napi_value thisvar;
            result_status = napi_get_reference_value(paf->env_, paf->thisVarRef_, &thisvar);
            CC_ASSERT(result_status == napi_ok);

            napi_value retValue;
            result_status = napi_get_reference_value(paf->env_, data->resultRef, &retValue);
            CC_ASSERT(result_status == napi_ok);
            uint32_t length = 0;
            napi_value element;
            napi_get_array_length(paf->env_, retValue, &length);
            const static uint32_t LENGTH = length;
            std::vector<napi_value> args(LENGTH);
            for (uint32_t i = 0; i < length; i++) {
                napi_get_element(paf->env_, retValue, i, &element);
                args[i] = element;
            }
            napi_value cb_result;
            result_status = napi_call_function(paf->env_, thisvar, cb, length, args.data(), &cb_result);
            CC_ASSERT(result_status == napi_ok);

            result_status = napi_delete_reference(paf->env_, data->resultRef);
            CC_ASSERT(result_status == napi_ok);

            napi_close_handle_scope(paf->env_, scope);
            free(data);
            delete work;
        });
}

//供业务线程调用安全函数的接口
void XNapiTool::CallThreadSafeFunc(std::string eventName) {
	if(XNapiTool::threadsafeCallFuncs_.count(eventName) <= 0) {
        return;
    }
    ThreadsafeFunc *pThreadSafeFunc = &XNapiTool::threadsafeCallFuncs_[eventName];

    auto status = napi_acquire_threadsafe_function(pThreadSafeFunc->threadsafefunc_);
    if (status != napi_ok) {
        return;
    }

    status = napi_call_threadsafe_function(
        pThreadSafeFunc->threadsafefunc_, nullptr, napi_tsfn_nonblocking);
    if (status != napi_ok) {
        return;
    }

    status = napi_release_threadsafe_function(pThreadSafeFunc->threadsafefunc_, napi_tsfn_abort);
    if (status != napi_ok) {
        return;
    }
}
`

function generateBase(destDir, license) {
    writeFile(re.pathJoin(destDir, "tool_utility.h"), null != license ? (license + "\n" + xNapiToolH) : xNapiToolH)
    writeFile(re.pathJoin(destDir, "tool_utility.cpp"), null != license ? (license + "\n" + xNapiToolCpp):xNapiToolCpp)
}

module.exports = {
    generateBase
}