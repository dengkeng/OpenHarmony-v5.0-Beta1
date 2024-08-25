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

#include "javascriptapi.h"

napi_value jsPropertyInit(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        {"testNapiGetPropertyNames", nullptr, testNapiGetPropertyNames, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"testNapiSetProperty", nullptr, testNapiSetProperty, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiGetProperty", nullptr, testNapiGetProperty, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiHasProperty", nullptr, testNapiHasProperty, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiDeleteProperty", nullptr, testNapiDeleteProperty, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiGetNamedProperty", nullptr, testNapiGetNamedProperty, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"testNapiSetNamedProperty", nullptr, testNapiSetNamedProperty, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"testNapiHasNamedProperty", nullptr, testNapiHasNamedProperty, nullptr, nullptr, nullptr, napi_default,
         nullptr},
        {"testNapiSetElement", nullptr, testNapiSetElement, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiGetElement", nullptr, testNapiGetElement, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiHasElement", nullptr, testNapiHasElement, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"testNapiDeleteElement", nullptr, testNapiDeleteElement, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc);
    return exports;
}