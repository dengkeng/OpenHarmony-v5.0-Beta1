/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "core/interfaces/native/node/custom_dialog_model.h"
#include "base/error/error_code.h"
#include "core/components_ng/pattern/dialog/custom_dialog_controller_model_ng.h"

namespace OHOS::Ace::NG::CustomDialog {
namespace {
    constexpr int32_t DEFAULT_DIALOG_ALIGNMENT = -1;
    constexpr uint32_t DEFAULT_MASK_COLOR = 0x33000000;
    constexpr uint32_t DEFAULT_DIALOG_BACKGROUND_COLOR = 0x00000000;
    constexpr int32_t ARKUI_ALIGNMENT_TOP_START_INDEX = 0;
    constexpr int32_t ARKUI_ALIGNMENT_TOP_INDEX = 1;
    constexpr int32_t ARKUI_ALIGNMENT_TOP_END_INDEX = 2;
    constexpr int32_t ARKUI_ALIGNMENT_START_INDEX = 3;
    constexpr int32_t ARKUI_ALIGNMENT_CENTER_INDEX = 4;
    constexpr int32_t ARKUI_ALIGNMENT_END_INDEX = 5;
    constexpr int32_t ARKUI_ALIGNMENT_BOTTOM_START_INDEX = 6;
    constexpr int32_t ARKUI_ALIGNMENT_BOTTOM_INDEX = 7;
    constexpr int32_t ARKUI_ALIGNMENT_BOTTOM_END_INDEX = 8;
}

ArkUIDialogHandle CreateDialog()
{
    return new _ArkUIDialog({ .dialogHandle = nullptr, .contentHandle = nullptr,
        .alignment = DEFAULT_DIALOG_ALIGNMENT, .offsetX = 0.0f,
        .offsetY = 0.0f, .isModal = true, .autoCancel = true, .maskColor = DEFAULT_MASK_COLOR, .maskRect = nullptr,
        .backgroundColor = DEFAULT_DIALOG_BACKGROUND_COLOR, .cornerRadiusRect = nullptr,
        .gridCount = -1, .enableCustomStyle = false,
        .showInSubWindow = false, .enableCustomAnimation = false, .onWillDismissCall = nullptr });
}

void DisposeDialog(ArkUIDialogHandle controllerHandler)
{
    CHECK_NULL_VOID(controllerHandler);
    auto* dialog = reinterpret_cast<FrameNode*>(controllerHandler->dialogHandle);
    if (dialog) {
        dialog->DecRefCount();
    }
    controllerHandler->dialogHandle = nullptr;
    auto* content = reinterpret_cast<FrameNode*>(controllerHandler->contentHandle);
    if (content) {
        content->DecRefCount();
    }
    controllerHandler->contentHandle = nullptr;
    auto* maskRect = controllerHandler->maskRect;
    if (maskRect) {
        delete maskRect;
    }
    auto* cornerRadiusRect = controllerHandler->cornerRadiusRect;
    if (cornerRadiusRect) {
        delete cornerRadiusRect;
    }
    controllerHandler->onWillDismissCall = nullptr;
    delete controllerHandler;
}

DialogAlignment GetDialogAlignment(int32_t alignment)
{
    switch (alignment) {
        case ARKUI_ALIGNMENT_TOP_START_INDEX:
            return DialogAlignment::TOP_START;
        case ARKUI_ALIGNMENT_TOP_INDEX:
            return DialogAlignment::TOP;
        case ARKUI_ALIGNMENT_TOP_END_INDEX:
            return DialogAlignment::TOP_END;
        case ARKUI_ALIGNMENT_START_INDEX:
            return DialogAlignment::CENTER_START;
        case ARKUI_ALIGNMENT_CENTER_INDEX:
            return DialogAlignment::CENTER;
        case ARKUI_ALIGNMENT_END_INDEX:
            return DialogAlignment::CENTER_END;
        case ARKUI_ALIGNMENT_BOTTOM_START_INDEX:
            return DialogAlignment::BOTTOM_START;
        case ARKUI_ALIGNMENT_BOTTOM_INDEX:
            return DialogAlignment::BOTTOM;
        case ARKUI_ALIGNMENT_BOTTOM_END_INDEX:
            return DialogAlignment::BOTTOM_END;
        default:
            break;
    }
    return DialogAlignment::DEFAULT;
}

void ParseDialogProperties(DialogProperties& dialogProperties, ArkUIDialogHandle controllerHandler)
{
    CHECK_NULL_VOID(controllerHandler);
    dialogProperties.autoCancel = controllerHandler->autoCancel;
    dialogProperties.alignment = GetDialogAlignment(controllerHandler->alignment);
    dialogProperties.offset = DimensionOffset(Dimension(controllerHandler->offsetX),
        Dimension(controllerHandler->offsetY));
    dialogProperties.maskColor = Color(controllerHandler->maskColor);
    if (controllerHandler->maskRect) {
        DimensionRect maskRect;
        maskRect.SetOffset(DimensionOffset(Dimension(controllerHandler->maskRect->x, DimensionUnit::VP),
            Dimension(controllerHandler->maskRect->y, DimensionUnit::VP)));
        maskRect.SetSize(DimensionSize(Dimension(controllerHandler->maskRect->width, DimensionUnit::VP),
            Dimension(controllerHandler->maskRect->height, DimensionUnit::VP)));
        dialogProperties.maskRect = maskRect;
    }
    dialogProperties.isShowInSubWindow = controllerHandler->showInSubWindow;
    dialogProperties.isModal = controllerHandler->isModal;
    dialogProperties.backgroundColor = Color(controllerHandler->backgroundColor);
    dialogProperties.customStyle = controllerHandler->enableCustomStyle;
    dialogProperties.gridCount = controllerHandler->gridCount;
    if (controllerHandler->cornerRadiusRect) {
        NG::BorderRadiusProperty radius;
        radius.radiusTopLeft = Dimension(controllerHandler->cornerRadiusRect->topLeft, DimensionUnit::VP);
        radius.radiusTopRight = Dimension(controllerHandler->cornerRadiusRect->topRight, DimensionUnit::VP);
        radius.radiusBottomLeft = Dimension(controllerHandler->cornerRadiusRect->bottomLeft, DimensionUnit::VP);
        radius.radiusBottomRight = Dimension(controllerHandler->cornerRadiusRect->bottomRight, DimensionUnit::VP);
        radius.multiValued = true;
        dialogProperties.borderRadius = radius;
    }
    if (controllerHandler->onWillDismissCall) {
        dialogProperties.onWillDismiss = [controllerHandler](int32_t reason) {
                CHECK_NULL_VOID(controllerHandler);
                CHECK_NULL_VOID(controllerHandler->onWillDismissCall);
                auto executeClose = (*(controllerHandler->onWillDismissCall))(reason);
                if (!executeClose) {
                    // todo
                }
            };
    }
    if (controllerHandler->enableCustomAnimation && !dialogProperties.openAnimation.has_value()) {
        AnimationOption animation;
        dialogProperties.openAnimation = animation;
    }
    if (controllerHandler->enableCustomAnimation && !dialogProperties.closeAnimation.has_value()) {
        AnimationOption animation;
        dialogProperties.closeAnimation = animation;
    }
}

ArkUI_Int32 SetDialogContent(ArkUIDialogHandle controllerHandler, ArkUINodeHandle contentNode)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    CHECK_NULL_RETURN(contentNode, ERROR_CODE_PARAM_INVALID);
    auto* frameNode = reinterpret_cast<FrameNode*>(contentNode);
    CHECK_NULL_RETURN(frameNode, ERROR_CODE_PARAM_INVALID);
    frameNode->IncRefCount();
    controllerHandler->contentHandle = frameNode;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 RemoveDialogContent(ArkUIDialogHandle controllerHandler)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    if (controllerHandler->contentHandle) {
        auto* frameNode = reinterpret_cast<FrameNode*>(controllerHandler->contentHandle);
        CHECK_NULL_RETURN(frameNode, ERROR_CODE_PARAM_INVALID);
        frameNode->DecRefCount();
        controllerHandler->contentHandle = nullptr;
    }
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 SetDialogContentAlignment(ArkUIDialogHandle controllerHandler,
    ArkUI_Int32 alignment, ArkUI_Float32 offsetX, ArkUI_Float32 offsetY)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    if (alignment < 0 || alignment > ARKUI_ALIGNMENT_BOTTOM_END_INDEX) {
        return ERROR_CODE_PARAM_INVALID;
    }
    controllerHandler->alignment = alignment;
    controllerHandler->offsetX = offsetX;
    controllerHandler->offsetY = offsetY;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 ResetDialogContentAlignment(ArkUIDialogHandle controllerHandler)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->alignment = DEFAULT_DIALOG_ALIGNMENT;
    controllerHandler->offsetX = 0.0f;
    controllerHandler->offsetY = 0.0f;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 SetDialogModalMode(ArkUIDialogHandle controllerHandler, bool isModal)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->isModal = isModal;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 SetDialogAutoCancel(ArkUIDialogHandle controllerHandler, bool autoCancel)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->autoCancel = autoCancel;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 SetDialogMask(ArkUIDialogHandle controllerHandler, ArkUI_Uint32 maskColor, ArkUIRect* rect)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->maskColor = maskColor;
    if (rect) {
        controllerHandler->maskRect = new ArkUIRect({ .x = rect->x, .y = rect->y,
            .width = rect->width, .height = rect->height });
    }
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 SetDialogBackgroundColor(ArkUIDialogHandle controllerHandler, ArkUI_Uint32 backgroundColor)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->backgroundColor = backgroundColor;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 SetDialogCornerRadius(ArkUIDialogHandle controllerHandler, ArkUI_Float32 topLeft,
    ArkUI_Float32 topRight, ArkUI_Float32 bottomLeft, ArkUI_Float32 bottomRight)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->cornerRadiusRect = new ArkUICornerRadius({ .topLeft = topLeft, .topRight = topRight,
    .bottomLeft = bottomLeft, .bottomRight = bottomRight });
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 SetDialogGridColumnCount(ArkUIDialogHandle controllerHandler, ArkUI_Int32 gridCount)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->gridCount = gridCount;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 EnableDialogCustomStyle(ArkUIDialogHandle controllerHandler, bool enableCustomStyle)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->enableCustomStyle = enableCustomStyle;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 EnableDialogCustomAnimation(ArkUIDialogHandle controllerHandler, bool enableCustomAnimation)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->enableCustomAnimation = enableCustomAnimation;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 ShowDialog(ArkUIDialogHandle controllerHandler, bool showInSubWindow)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->showInSubWindow = showInSubWindow;
    DialogProperties dialogProperties;
    ParseDialogProperties(dialogProperties, controllerHandler);
    auto* contentNode = reinterpret_cast<FrameNode*>(controllerHandler->contentHandle);
    CHECK_NULL_RETURN(contentNode, ERROR_CODE_PARAM_INVALID);
    auto contentPtr = AceType::Claim<FrameNode>(contentNode);
    auto dialogNode = CustomDialogControllerModelNG::SetOpenDialogWithNode(dialogProperties, contentPtr);
    if (dialogNode) {
        dialogNode->IncRefCount();
    }
    controllerHandler->dialogHandle = AceType::RawPtr(dialogNode);
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 CloseDialog(ArkUIDialogHandle controllerHandler)
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    auto* dialogNode = reinterpret_cast<FrameNode*>(controllerHandler->dialogHandle);
    CHECK_NULL_RETURN(dialogNode, ERROR_CODE_PARAM_INVALID);
    CustomDialogControllerModelNG::SetCloseDialogForNDK(dialogNode);
    if (dialogNode) {
        dialogNode->DecRefCount();
    }
    controllerHandler->dialogHandle = nullptr;
    return ERROR_CODE_NO_ERROR;
}

ArkUI_Int32 RegisterOnWillDialogDismiss(ArkUIDialogHandle controllerHandler, bool (*eventHandler)(ArkUI_Int32))
{
    CHECK_NULL_RETURN(controllerHandler, ERROR_CODE_PARAM_INVALID);
    controllerHandler->onWillDismissCall = eventHandler;
    return ERROR_CODE_NO_ERROR;
}
} // namespace OHOS::Ace::NG::ViewModel