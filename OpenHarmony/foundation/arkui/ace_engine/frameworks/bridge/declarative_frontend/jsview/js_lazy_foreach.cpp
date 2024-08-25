/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "frameworks/bridge/declarative_frontend/jsview/js_lazy_foreach.h"

#include <functional>
#include <set>
#include <string>

#include "base/memory/ace_type.h"
#include "base/memory/referenced.h"
#include "base/utils/utils.h"
#include "bridge/common/utils/utils.h"
#include "bridge/declarative_frontend/engine/js_object_template.h"
#include "bridge/declarative_frontend/jsview/js_lazy_foreach_actuator.h"
#include "bridge/declarative_frontend/jsview/js_lazy_foreach_builder.h"
#ifndef NG_BUILD
#include "bridge/declarative_frontend/jsview/js_lazy_foreach_component.h"
#endif
#include "bridge/declarative_frontend/jsview/js_view.h"
#include "bridge/declarative_frontend/jsview/js_view_common_def.h"
#include "bridge/declarative_frontend/jsview/models/lazy_for_each_model_impl.h"
#include "bridge/declarative_frontend/view_stack_processor.h"
#include "core/common/container.h"
#include "core/common/container_scope.h"
#include "core/components_ng/base/view_stack_model.h"
#include "core/components_ng/syntax/lazy_for_each_model.h"
#include "core/components_ng/syntax/lazy_for_each_model_ng.h"

namespace OHOS::Ace {

std::unique_ptr<LazyForEachModel> LazyForEachModel::instance_ = nullptr;
std::mutex LazyForEachModel::mutex_;

LazyForEachModel* LazyForEachModel::GetInstance()
{
    if (!instance_) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!instance_) {
#ifdef NG_BUILD
            instance_.reset(new NG::LazyForEachModelNG());
#else
            if (Container::IsCurrentUseNewPipeline()) {
                instance_.reset(new NG::LazyForEachModelNG());
            } else {
                instance_.reset(new Framework::LazyForEachModelImpl());
            }
#endif
        }
    }
    return instance_.get();
}

} // namespace OHOS::Ace

namespace OHOS::Ace::Framework {

void JSDataChangeListener::JSBind(BindingTarget globalObj)
{
    JSClass<JSDataChangeListener>::Declare("__ohos_ace_inner_JSDataChangeListener__");
    // API7 onEditChanged deprecated
    JSClass<JSDataChangeListener>::CustomMethod("onDataReloaded", &JSDataChangeListener::OnDataReloaded);
    JSClass<JSDataChangeListener>::CustomMethod("onDataReload", &JSDataChangeListener::OnDataReloaded);
    // API7 onDataAdded deprecated
    JSClass<JSDataChangeListener>::CustomMethod("onDataAdded", &JSDataChangeListener::OnDataAdded);
    JSClass<JSDataChangeListener>::CustomMethod("onDataAdd", &JSDataChangeListener::OnDataAdded);
    // API7 onDataDeleted deprecated
    JSClass<JSDataChangeListener>::CustomMethod("onDataDeleted", &JSDataChangeListener::OnDataDeleted);
    JSClass<JSDataChangeListener>::CustomMethod("onDataDelete", &JSDataChangeListener::OnDataDeleted);
    // API7 onDataChanged deprecated
    JSClass<JSDataChangeListener>::CustomMethod("onDataChanged", &JSDataChangeListener::OnDataChanged);
    JSClass<JSDataChangeListener>::CustomMethod("onDataChange", &JSDataChangeListener::OnDataChanged);
    // API7 onDataMoved deprecated
    JSClass<JSDataChangeListener>::CustomMethod("onDataMoved", &JSDataChangeListener::OnDataMoved);
    JSClass<JSDataChangeListener>::CustomMethod("onDataMove", &JSDataChangeListener::OnDataMoved);
    // temporary interface
    JSClass<JSDataChangeListener>::CustomMethod("onDataBulkAdded", &JSDataChangeListener::OnDataBulkAdded);
    JSClass<JSDataChangeListener>::CustomMethod("onDataBulkAdd", &JSDataChangeListener::OnDataBulkAdded);
    JSClass<JSDataChangeListener>::CustomMethod("onDataBulkDeleted", &JSDataChangeListener::OnDataBulkDeleted);
    JSClass<JSDataChangeListener>::CustomMethod("onDataBulkDelete", &JSDataChangeListener::OnDataBulkDeleted);
    // API12 onDatasetChange
    JSClass<JSDataChangeListener>::CustomMethod("onDatasetChange", &JSDataChangeListener::OnDatasetChange);
    JSClass<JSDataChangeListener>::Bind(
        globalObj, &JSDataChangeListener::Constructor, &JSDataChangeListener::Destructor);
}

RefPtr<JSLazyForEachActuator> CreateActuator(const std::string& viewId)
{
#ifdef NG_BUILD
    return AceType::MakeRefPtr<JSLazyForEachBuilder>();
#else
    if (Container::IsCurrentUseNewPipeline()) {
        return AceType::MakeRefPtr<JSLazyForEachBuilder>();
    } else {
        return AceType::MakeRefPtr<JSLazyForEachComponent>(viewId);
    }
#endif
}

namespace {

enum {
    PARAM_VIEW_ID = 0,
    PARAM_PARENT_VIEW,
    PARAM_DATA_SOURCE,
    PARAM_ITEM_GENERATOR,
    PARAM_KEY_GENERATOR,
    PARAM_UPDATE_CHANGEDNODE,

    MIN_PARAM_SIZE = PARAM_KEY_GENERATOR,
    MAX_PARAM_SIZE = 6,
};

bool ParseAndVerifyParams(const JSCallbackInfo& info, JSRef<JSVal> (&params)[MAX_PARAM_SIZE])
{
    if (info.Length() < MIN_PARAM_SIZE) {
        return false;
    }

    if (!info[PARAM_VIEW_ID]->IsNumber() && !info[PARAM_VIEW_ID]->IsString()) {
        return false;
    }
    if (!info[PARAM_PARENT_VIEW]->IsObject()) {
        return false;
    }
    if (!info[PARAM_DATA_SOURCE]->IsObject()) {
        return false;
    }
    if (!info[PARAM_ITEM_GENERATOR]->IsFunction()) {
        return false;
    }
    if (info.Length() > MIN_PARAM_SIZE &&
        !(info[PARAM_KEY_GENERATOR]->IsFunction() || info[PARAM_KEY_GENERATOR]->IsUndefined())) {
        return false;
    }
    if (info.Length() > MIN_PARAM_SIZE + 1 && !info[PARAM_UPDATE_CHANGEDNODE]->IsBoolean()) {
        return false;
    }

    for (int32_t idx = PARAM_VIEW_ID; idx < std::min(info.Length(), static_cast<int32_t>(MAX_PARAM_SIZE)); ++idx) {
        params[idx] = info[idx];
    }
    return true;
}

} // namespace

void JSLazyForEach::JSBind(BindingTarget globalObj)
{
    JSClass<JSLazyForEach>::Declare("LazyForEach");
    JSClass<JSLazyForEach>::StaticMethod("createInternal", &JSLazyForEach::Create);
    JSClass<JSLazyForEach>::StaticMethod("pop", &JSLazyForEach::Pop);
    JSClass<JSLazyForEach>::StaticMethod("onMove", &JSLazyForEach::OnMove);
    JSClass<JSLazyForEach>::Bind(globalObj);

    JSDataChangeListener::JSBind(globalObj);
}

void JSLazyForEach::Create(const JSCallbackInfo& info)
{
    JSRef<JSVal> params[MAX_PARAM_SIZE];
    if (!ParseAndVerifyParams(info, params)) {
        TAG_LOGW(AceLogTag::ACE_LAZY_FOREACH, "Invalid arguments for LazyForEach");
        return;
    }
    if (!params[PARAM_PARENT_VIEW]->IsObject()|| !params[PARAM_DATA_SOURCE]->IsObject()
        || !params[PARAM_ITEM_GENERATOR]->IsFunction()) {
            return;
    }
    std::string viewId = ViewStackModel::GetInstance()->ProcessViewId(params[PARAM_VIEW_ID]->ToString());

    JSRef<JSObject> parentViewObj = JSRef<JSObject>::Cast(params[PARAM_PARENT_VIEW]);
    JSRef<JSObject> dataSourceObj = JSRef<JSObject>::Cast(params[PARAM_DATA_SOURCE]);
    JSRef<JSFunc> itemGenerator = JSRef<JSFunc>::Cast(params[PARAM_ITEM_GENERATOR]);
    ItemKeyGenerator keyGenFunc;
    bool updateChangedNodeFlag = false;

    if (params[PARAM_KEY_GENERATOR]->IsUndefined()) {
        keyGenFunc = [viewId](const JSRef<JSVal>&, size_t index) { return viewId + "-" + std::to_string(index); };
    } else {
        keyGenFunc = [viewId, keyGenerator = JSRef<JSFunc>::Cast(params[PARAM_KEY_GENERATOR])](
                         const JSRef<JSVal>& jsVal, size_t index) {
            JSRef<JSVal> params[] = { jsVal, JSRef<JSVal>::Make(ToJSValue(index)) };
            auto key = keyGenerator->Call(JSRef<JSObject>(), ArraySize(params), params);
            return viewId + "-" + (key->IsString() || key->IsNumber() ? key->ToString() : std::to_string(index));
        };
    }

    if (!params[PARAM_UPDATE_CHANGEDNODE]->IsUndefined()) {
        updateChangedNodeFlag = params[PARAM_UPDATE_CHANGEDNODE]->ToBoolean();
    }

    const auto& actuator = CreateActuator(viewId);
    actuator->SetJSExecutionContext(info.GetExecutionContext());
    actuator->SetParentViewObj(parentViewObj);
    actuator->SetDataSourceObj(dataSourceObj);
    actuator->SetItemGenerator(itemGenerator, std::move(keyGenFunc));
    actuator->SetUpdateChangedNodeFlag(updateChangedNodeFlag);
    LazyForEachModel::GetInstance()->Create(actuator);
}

void JSLazyForEach::Pop()
{
    auto* stack = NG::ViewStackProcessor::GetInstance();
    if (stack->GetMainFrameNode() && stack->GetMainFrameNode()->GetTag() == V2::TABS_ETS_TAG) {
        return;
    }
    ViewStackModel::GetInstance()->PopContainer();
}

void JSLazyForEach::OnMove(const JSCallbackInfo& info)
{
    if (info[0]->IsFunction()) {
        auto onMove = [execCtx = info.GetExecutionContext(), func = JSRef<JSFunc>::Cast(info[0])]
            (int32_t from, int32_t to) {
                auto params = ConvertToJSValues(from, to);
                func->Call(JSRef<JSObject>(), params.size(), params.data());
            };
        LazyForEachModel::GetInstance()->OnMove(std::move(onMove));
    } else {
        LazyForEachModel::GetInstance()->OnMove(nullptr);
    }
}
} // namespace OHOS::Ace::Framework
