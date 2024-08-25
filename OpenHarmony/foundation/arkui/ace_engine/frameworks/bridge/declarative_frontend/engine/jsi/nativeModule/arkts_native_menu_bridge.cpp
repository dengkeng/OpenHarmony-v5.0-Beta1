/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "bridge/declarative_frontend/engine/jsi/nativeModule/arkts_native_menu_bridge.h"

#include "frameworks/bridge/declarative_frontend/engine/jsi/nativeModule/arkts_utils.h"

namespace OHOS::Ace::NG {
const std::string FORMAT_FONT = "%s|%s|%s";
const std::string DEFAULT_ERR_CODE = "-1";

ArkUINativeModuleValue MenuBridge::SetMenuFontColor(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    Local<JSValueRef> secondArg = runtimeCallInfo->GetCallArgRef(1);
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    Color color;
    if (!ArkTSUtils::ParseJsColorAlpha(vm, secondArg, color)) {
        GetArkUINodeModifiers()->getMenuModifier()->resetMenuFontColor(nativeNode);
    } else {
        GetArkUINodeModifiers()->getMenuModifier()->setMenuFontColor(nativeNode, color.GetValue());
    }

    return panda::JSValueRef::Undefined(vm);
}

ArkUINativeModuleValue MenuBridge::ResetMenuFontColor(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    GetArkUINodeModifiers()->getMenuModifier()->resetMenuFontColor(nativeNode);
    return panda::JSValueRef::Undefined(vm);
}

ArkUINativeModuleValue MenuBridge::SetFont(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    Local<JSValueRef> sizeArg = runtimeCallInfo->GetCallArgRef(1);   // 1: index of font size value
    Local<JSValueRef> weightArg = runtimeCallInfo->GetCallArgRef(2); // 2: index of font weight value
    Local<JSValueRef> familyArg = runtimeCallInfo->GetCallArgRef(3); // 3: index of font family value
    Local<JSValueRef> styleArg = runtimeCallInfo->GetCallArgRef(4);  // 4: index of font style value
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    if (sizeArg->IsUndefined() && weightArg->IsUndefined() && familyArg->IsUndefined() && styleArg->IsUndefined()) {
        GetArkUINodeModifiers()->getMenuModifier()->resetFont(nativeNode);
        return panda::JSValueRef::Undefined(vm);
    }

    CalcDimension fontSize;
    if (!ArkTSUtils::ParseJsDimensionFp(vm, sizeArg, fontSize, false)) {
        fontSize = Dimension(0.0);
    }
    std::string weight = DEFAULT_ERR_CODE;
    if (weightArg->IsNumber()) {
        weight = std::to_string(weightArg->Int32Value(vm));
    } else {
        if (!ArkTSUtils::ParseJsString(vm, weightArg, weight) || weight.empty()) {
            weight = DEFAULT_ERR_CODE;
        }
    }

    int32_t style = -1;
    if (styleArg->IsNumber()) {
        style = styleArg->Int32Value(vm);
    }

    std::string family;
    if (!ArkTSUtils::ParseJsFontFamiliesToString(vm, familyArg, family) || family.empty()) {
        family = DEFAULT_ERR_CODE;
    }
    std::string fontSizeStr = fontSize.ToString();
    std::string fontInfo =
        StringUtils::FormatString(FORMAT_FONT.c_str(), fontSizeStr.c_str(), weight.c_str(), family.c_str());

    GetArkUINodeModifiers()->getMenuModifier()->setFont(nativeNode, fontInfo.c_str(), style);
    return panda::JSValueRef::Undefined(vm);
}

ArkUINativeModuleValue MenuBridge::ResetFont(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    GetArkUINodeModifiers()->getMenuModifier()->resetFont(nativeNode);
    return panda::JSValueRef::Undefined(vm);
}

bool MenuBridge::ParseRadius(EcmaVM* vm, ArkUIRuntimeCallInfo* runtimeCallInfo, ArkUINodeHandle nativeNode,
    std::vector<ArkUI_Float32>& radiusValues, std::vector<int32_t>& radiusUnits)
{
    Local<JSValueRef> topLeftArgs = runtimeCallInfo->GetCallArgRef(1);     // 1: index of top left value
    Local<JSValueRef> topRightArgs = runtimeCallInfo->GetCallArgRef(2);    // 2: index of top right value
    Local<JSValueRef> bottomLeftArgs = runtimeCallInfo->GetCallArgRef(3);  // 3: index of bottom left value
    Local<JSValueRef> bottomRightArgs = runtimeCallInfo->GetCallArgRef(4); // 4: index of bottom right value
    Local<JSValueRef> isObjectArgs = runtimeCallInfo->GetCallArgRef(5);    // 5: check is object radius
    if (topLeftArgs->IsUndefined() && topRightArgs->IsUndefined() && bottomLeftArgs->IsUndefined() &&
        bottomRightArgs->IsUndefined()) {
        GetArkUINodeModifiers()->getMenuModifier()->resetRadius(nativeNode);
        return false;
    }

    CalcDimension topLeft;
    CalcDimension topRight;
    CalcDimension bottomLeft;
    CalcDimension bottomRight;
    if (isObjectArgs->IsBoolean() && !isObjectArgs->ToBoolean(vm)->Value()) {
        if (!ArkTSUtils::ParseJsDimensionVpNG(vm, topLeftArgs, topLeft, true)) {
            GetArkUINodeModifiers()->getMenuModifier()->resetRadius(nativeNode);
            return false;
        }
        if (LessNotEqual(topLeft.Value(), 0.0)) {
            GetArkUINodeModifiers()->getMenuModifier()->resetRadius(nativeNode);
            return false;
        }
        topRight = topLeft;
        bottomLeft = topLeft;
        bottomRight = topLeft;
    } else {
        if (!ArkTSUtils::ParseJsDimensionVpNG(vm, topLeftArgs, topLeft, true)) {
            topLeft = CalcDimension(0.0, DimensionUnit::VP);
        }

        if (!ArkTSUtils::ParseJsDimensionVpNG(vm, topRightArgs, topRight, true)) {
            topRight = CalcDimension(0.0, DimensionUnit::VP);
        }

        if (!ArkTSUtils::ParseJsDimensionVpNG(vm, bottomLeftArgs, bottomLeft, true)) {
            bottomLeft = CalcDimension(0.0, DimensionUnit::VP);
        }

        if (!ArkTSUtils::ParseJsDimensionVpNG(vm, bottomRightArgs, bottomRight, true)) {
            bottomRight = CalcDimension(0.0, DimensionUnit::VP);
        }
    }
    radiusUnits.push_back(static_cast<int32_t>(topLeft.Unit()));
    radiusUnits.push_back(static_cast<int32_t>(topRight.Unit()));
    radiusUnits.push_back(static_cast<int32_t>(bottomLeft.Unit()));
    radiusUnits.push_back(static_cast<int32_t>(bottomRight.Unit()));
    radiusValues.push_back(topLeft.Value());
    radiusValues.push_back(topRight.Value());
    radiusValues.push_back(bottomLeft.Value());
    radiusValues.push_back(bottomRight.Value());
    return true;
}

ArkUINativeModuleValue MenuBridge::SetRadius(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    std::vector<ArkUI_Float32> radiusValues;
    std::vector<int32_t> radiusUnits;
    if (!ParseRadius(vm, runtimeCallInfo, nativeNode, radiusValues, radiusUnits)) {
        return panda::JSValueRef::Undefined(vm);
    }
    GetArkUINodeModifiers()->getMenuModifier()->setRadius(nativeNode, radiusValues.data(), radiusUnits.data());
    return panda::JSValueRef::Undefined(vm);
}

ArkUINativeModuleValue MenuBridge::ResetRadius(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    GetArkUINodeModifiers()->getMenuModifier()->resetRadius(nativeNode);
    return panda::JSValueRef::Undefined(vm);
}

ArkUINativeModuleValue MenuBridge::SetWidth(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    Local<JSValueRef> widthArg = runtimeCallInfo->GetCallArgRef(1);
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    CalcDimension width;
    if (!ArkTSUtils::ParseJsDimensionVp(vm, widthArg, width, false)) {
        GetArkUINodeModifiers()->getMenuModifier()->resetMenuWidth(nativeNode);
        return panda::JSValueRef::Undefined(vm);
    }
    GetArkUINodeModifiers()->getMenuModifier()->setMenuWidth(
        nativeNode, width.Value(), static_cast<int32_t>(width.Unit()));
    return panda::JSValueRef::Undefined(vm);
}

ArkUINativeModuleValue MenuBridge::ResetWidth(ArkUIRuntimeCallInfo* runtimeCallInfo)
{
    EcmaVM* vm = runtimeCallInfo->GetVM();
    CHECK_NULL_RETURN(vm, panda::NativePointerRef::New(vm, nullptr));
    Local<JSValueRef> firstArg = runtimeCallInfo->GetCallArgRef(0);
    auto nativeNode = nodePtr(firstArg->ToNativePointer(vm)->Value());
    GetArkUINodeModifiers()->getMenuModifier()->resetMenuWidth(nativeNode);
    return panda::JSValueRef::Undefined(vm);
}
} // namespace OHOS::Ace::NG
