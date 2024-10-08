/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "frameworks/bridge/declarative_frontend/engine/js_converter.h"

#include "native_engine/impl/ark/ark_native_engine.h"
#include "native_engine/native_value.h"

#include "frameworks/bridge/declarative_frontend/engine/jsi/jsi_declarative_engine.h"
#include "frameworks/bridge/js_frontend/engine/jsi/ark_js_runtime.h"

namespace OHOS::Ace::Framework {

JsiRef<JsiValue> JsConverter::ConvertNapiValueToJsVal(napi_value napiValue)
{
    if (!napiValue || !JsiDeclarativeEngineInstance::GetCurrentRuntime()) {
        return JsiRef<JsiValue>::Make();
    }
    auto localRef = NapiValueToLocalValue(napiValue);
    JsiValue jsiValue(localRef);
    return JsiRef<JsiValue>::Make(jsiValue);
}

napi_value JsConverter::ConvertJsValToNapiValue(JSRef<JSVal> jsVal)
{
    if (jsVal->IsEmpty() || !JsiDeclarativeEngineInstance::GetCurrentRuntime()) {
        return nullptr;
    }
    return LocalValueToLocalNapiValue(jsVal->GetLocalHandle());
}
} // namespace OHOS::Ace::Framework
