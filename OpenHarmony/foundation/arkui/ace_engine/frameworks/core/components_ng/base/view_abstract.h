/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_BASE_VIEW_ABSTRACT_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_BASE_VIEW_ABSTRACT_H

#include <cstdint>
#include <functional>

#include "modifier.h"

#include "base/geometry/dimension.h"
#include "base/geometry/matrix4.h"
#include "base/geometry/ng/offset_t.h"
#include "base/geometry/ng/rect_t.h"
#include "base/geometry/ng/vector.h"
#include "base/memory/referenced.h"
#include "core/components/common/layout/constants.h"
#include "core/components/common/layout/grid_layout_info.h"
#include "core/components/common/layout/position_param.h"
#include "core/components/common/properties/alignment.h"
#include "core/components/common/properties/blend_mode.h"
#include "core/components/common/properties/decoration.h"
#include "core/components/common/properties/motion_path_option.h"
#include "core/components/common/properties/placement.h"
#include "core/components/common/properties/popup_param.h"
#include "core/components/common/properties/shadow.h"
#include "core/components/common/properties/shared_transition_option.h"
#include "core/components_ng/event/focus_box.h"
#include "core/components_ng/event/gesture_event_hub.h"
#include "core/components_ng/pattern/menu/menu_pattern.h"
#include "core/components_ng/property/border_property.h"
#include "core/components_ng/property/calc_length.h"
#include "core/components_ng/property/gradient_property.h"
#include "core/components_ng/property/measure_property.h"
#include "core/components_ng/property/menu_property.h"
#include "core/components_ng/property/overlay_property.h"
#include "core/components_ng/property/progress_mask_property.h"
#include "core/components_ng/property/transition_property.h"

namespace OHOS::Ace::NG {
struct OptionParam {
    std::string value;
    std::string icon;
    bool enabled = true;
    std::function<void()> action;
    std::function<void(WeakPtr<NG::FrameNode>)> symbol = nullptr;

    OptionParam() = default;
    OptionParam(const std::string &valueParam, const std::string &iconParam, const std::function<void()> &actionParam)
        : value(valueParam), icon(iconParam), enabled(true), action(actionParam)
    {}
    OptionParam(const std::string &valueParam, const std::string &iconParam, bool enabledParam,
        const std::function<void()> &actionParam)
        : value(valueParam), icon(iconParam), enabled(enabledParam), action(actionParam)
    {}
    OptionParam(const std::string &valueParam, const std::function<void()> &actionParam)
        : value(valueParam), icon(""), enabled(true), action(actionParam)
    {}
    OptionParam(const std::string& valueParam, const std::string& iconParam,
        const std::function<void()>& actionParam, const std::function<void(WeakPtr<NG::FrameNode>)> symbol)
        : value(valueParam), icon(iconParam), enabled(true), action(actionParam), symbol(symbol)
    {}
    OptionParam(const std::string& valueParam, const std::string& iconParam, bool enabledParam,
        const std::function<void()>& actionParam, const std::function<void(WeakPtr<NG::FrameNode>)> symbol)
        : value(valueParam), icon(iconParam), enabled(enabledParam), action(actionParam), symbol(symbol)
    {}

    ~OptionParam() = default;
};

enum class OverlayType {
    BUILDER = 0,
    TEXT = 1,
    RESET = 2,
};

class ACE_FORCE_EXPORT ViewAbstract {
public:
    static void SetWidth(const CalcLength &width);
    static void SetHeight(const CalcLength &height);
    static void ClearWidthOrHeight(bool isWidth);
    static void SetMinWidth(const CalcLength &minWidth);
    static void SetMinHeight(const CalcLength &minHeight);
    static void SetMaxWidth(const CalcLength &maxWidth);
    static void SetMaxHeight(const CalcLength &maxHeight);
    static void ResetMinSize(bool resetWidth);
    static void ResetMaxSize(bool resetWidth);

    static void SetAspectRatio(float ratio);
    static void ResetAspectRatio();
    static void SetLayoutWeight(float value);
    static void SetPixelRound(uint8_t value);
    static void SetLayoutDirection(TextDirection value);

    static void SetBackgroundColor(const Color &color);
    static void SetBackgroundImage(const ImageSourceInfo &src);
    static void SetBackgroundImageRepeat(const ImageRepeat &imageRepeat);
    static void SetBackgroundImageSize(const BackgroundImageSize &bgImgSize);
    static void SetBackgroundImagePosition(const BackgroundImagePosition &bgImgPosition);
    static void SetBackgroundBlurStyle(const BlurStyleOption &bgBlurStyle);
    static void SetMotionBlur(const MotionBlurOption &motionBlurOption);
    static void SetBackgroundEffect(const EffectOption &effectOption);
    static void SetBackgroundImageResizableSlice(const ImageResizableSlice& slice);
    static void SetForegroundEffect(float radius);
    static void SetForegroundBlurStyle(const BlurStyleOption &fgBlurStyle);
    static void SetSphericalEffect(double radio);
    static void SetPixelStretchEffect(PixStretchEffectOption &option);
    static void SetLightUpEffect(double radio);
    static void SetPadding(const CalcLength &value);
    static void SetPadding(const PaddingProperty &value);
    static void SetMargin(const CalcLength &value);
    static void SetMargin(const PaddingProperty &value);
    static void SetBorderRadius(const BorderRadiusProperty &value);
    static void SetBorderRadius(const Dimension &value);
    static void SetBorderColor(const Color &value);
    static void SetBorderColor(const BorderColorProperty &value);
    static void SetBorderWidth(const Dimension &value);
    static void SetBorderWidth(const BorderWidthProperty &value);
    static void SetBorderStyle(const BorderStyle &value);
    static void SetBorderStyle(const BorderStyleProperty &value);
    static void SetOpacity(double opacity);
    static void SetAllowDrop(const std::set<std::string> &allowDrop);
    static void SetDrawModifier(const RefPtr<NG::DrawModifier>& drawModifier);
    static void* GetFrameNode();
    static void SetDragPreview(const NG::DragDropInfo& info);

    static void SetBorderImage(const RefPtr<BorderImage> &borderImage);
    static void SetBorderImageSource(const std::string &bdImageSrc);

    // visual
    static void SetVisualEffect(const OHOS::Rosen::VisualEffect* visualEffect);
    static void SetBackgroundFilter(const OHOS::Rosen::Filter* backgroundFilter);
    static void SetForegroundFilter(const OHOS::Rosen::Filter* foregroundFilter);
    static void SetCompositingFilter(const OHOS::Rosen::Filter* compositingFilter);

    // outer border
    static void SetOuterBorderRadius(const BorderRadiusProperty& value);
    static void SetOuterBorderRadius(const Dimension& value);
    static void SetOuterBorderColor(const Color& value);
    static void SetOuterBorderColor(const BorderColorProperty& value);
    static void SetOuterBorderWidth(const Dimension& value);
    static void SetOuterBorderWidth(const BorderWidthProperty& value);
    static void SetOuterBorderStyle(const BorderStyle& value);
    static void SetOuterBorderStyle(const BorderStyleProperty& value);

    static void SetHasBorderImageSlice(bool tag);
    static void SetHasBorderImageWidth(bool tag);
    static void SetHasBorderImageOutset(bool tag);
    static void SetHasBorderImageRepeat(bool tag);
    static void SetBorderImageGradient(const NG::Gradient &gradient);

    // customBackground
    static void SetBackgroundAlign(const Alignment &align);

    // decoration
    static void SetBackdropBlur(const Dimension &radius, const BlurOption &blurOption);
    static void SetLinearGradientBlur(const NG::LinearGradientBlurPara& blurPara);
    static void SetDynamicLightUp(float rate, float lightUpDegree);
    static void SetBgDynamicBrightness(const BrightnessOption& brightnessOption);
    static void SetFgDynamicBrightness(const BrightnessOption& brightnessOption);
    static void SetDynamicDim(float DimDegree);
    static void SetFrontBlur(const Dimension &radius, const BlurOption &blurOption);
    static void SetBackShadow(const Shadow &shadow);
    static void SetBlendMode(BlendMode blendMode);
    static void SetBlendApplyType(BlendApplyType blendApplyType);

    // graphics
    static void SetBrightness(const Dimension &value);
    static void SetGrayScale(const Dimension &value);
    static void SetContrast(const Dimension &value);
    static void SetSaturate(const Dimension &value);
    static void SetSepia(const Dimension &value);
    static void SetInvert(const InvertVariant &value);
    static void SetHueRotate(float value);
    static void SetColorBlend(const Color &value);
    static void SetSystemBarEffect(bool systemBarEffect);

    // gradient
    static void SetLinearGradient(const NG::Gradient &gradient);
    static void SetSweepGradient(const NG::Gradient &gradient);
    static void SetRadialGradient(const NG::Gradient &gradient);

    // layout
    static void SetAlign(Alignment alignment);
    static void SetAlignRules(const std::map<AlignDirection, AlignRule> &alignRules);
    static void SetChainStyle(const ChainInfo& chainInfo);
    static void SetBias(const BiasPair& biasPair);
    static void SetVisibility(VisibleType visible);
    static void SetGrid(std::optional<int32_t> span, std::optional<int32_t> offset,
        GridSizeType type = GridSizeType::UNDEFINED);

    // position
    static void SetPosition(const OffsetT<Dimension>& value);
    static void SetOffset(const OffsetT<Dimension>& value);
    static void SetPositionEdges(const EdgesParam& value);
    static void SetOffsetEdges(const EdgesParam& value);
    static void MarkAnchor(const OffsetT<Dimension>& value);
    static void ResetPosition();

    // render position
    static void SetZIndex(int32_t value);
    // renderGroup
    static void SetRenderGroup(bool isRenderGroup);
    // renderFit, i.e. gravity
    static void SetRenderFit(RenderFit renderFit);

    // transform
    static void SetScale(const NG::VectorF &value);
    static void SetPivot(const DimensionOffset &value);
    static void SetTranslate(const NG::TranslateOptions &value);
    static void SetRotate(const NG::Vector5F &value);

    static void SetTransformMatrix(const Matrix4 &matrix);

    // event
    static void SetOnClick(GestureEventFunc &&clickEventFunc);
    static void SetOnGestureJudgeBegin(GestureJudgeFunc &&gestureJudgeFunc);
    static void SetOnTouchIntercept(TouchInterceptFunc &&touchInterceptFunc);
    static void SetOnTouch(TouchEventFunc &&touchEventFunc);
    static void SetOnMouse(OnMouseEventFunc &&onMouseEventFunc);
    static void SetOnHover(OnHoverFunc &&onHoverEventFunc);
    static void SetHoverEffect(HoverEffectType hoverEffect);
    static void SetHoverEffectAuto(HoverEffectType hoverEffect);
    static void SetEnabled(bool enabled);
    static void SetFocusable(bool focusable);
    static void SetOnFocus(OnFocusFunc &&onFocusCallback);
    static void SetOnBlur(OnBlurFunc &&onBlurCallback);
    static void SetOnKeyEvent(OnKeyCallbackFunc &&onKeyCallback);
    static void SetTabIndex(int32_t index);
    static void SetFocusOnTouch(bool isSet);
    static void SetDefaultFocus(bool isSet);
    static void SetGroupDefaultFocus(bool isSet);
    static void SetFocusBoxStyle(const NG::FocusBoxStyle& style);
    static void SetOnAppear(std::function<void()> &&onAppear);
    static void SetOnDisappear(std::function<void()> &&onDisappear);
    static void SetOnAttach(std::function<void()> &&onAttach);
    static void SetOnDetach(std::function<void()> &&onDetach);
    static void SetOnAreaChanged(std::function<void(const RectF &oldRect, const OffsetF &oldOrigin, const RectF &rect,
        const OffsetF &origin)> &&onAreaChanged);
    static void SetOnVisibleChange(std::function<void(bool, double)> &&onVisibleChange,
        const std::vector<double> &ratioList);
    static void SetOnSizeChanged(std::function<void(const RectF &oldRect, const RectF &rect)> &&onSizeChanged);
    static void SetResponseRegion(const std::vector<DimensionRect> &responseRegion);
    static void SetMouseResponseRegion(const std::vector<DimensionRect> &mouseResponseRegion);
    static void SetTouchable(bool touchable);
    static void SetHitTestMode(HitTestMode hitTestMode);
    static void SetOnTouchTestFunc(NG::OnChildTouchTestFunc&& onChildTouchTest);
    static void SetDraggable(bool draggable);
    static void SetDragPreviewOptions(const DragPreviewOption& previewOption);
    static void SetOnDragStart(
        std::function<DragDropInfo(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragStart);
    static void SetOnPreDrag(
        std::function<void(const PreDragStatus)> &&onPreDragFunc);
    static void SetOnDragEnter(
        std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragEnter);
    static void SetOnDragLeave(
        std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragLeave);
    static void SetOnDragMove(
        std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDragMove);
    static void SetOnDrop(std::function<void(const RefPtr<OHOS::Ace::DragEvent> &, const std::string &)> &&onDrop);

    static void SetOnDragEnd(std::function<void(const RefPtr<OHOS::Ace::DragEvent> &)> &&onDragEnd);
    static void SetMonopolizeEvents(bool monopolizeEvents);
    static void SetDragEventStrictReportingEnabled(bool dragEventStrictReportingEnabled);

    // flex properties
    static void SetAlignSelf(FlexAlign value);
    static void SetFlexShrink(float value);
    static void ResetFlexShrink();
    static void SetFlexGrow(float value);
    static void SetFlexBasis(const Dimension &value);
    static void SetDisplayIndex(int32_t value);
    static void SetKeyboardShortcut(const std::string &value, const std::vector<ModifierKey> &keys,
        std::function<void()> &&onKeyboardShortcutAction);
    // obscured
    static void SetObscured(const std::vector<ObscuredReasons> &reasons);
    static void SetPrivacySensitive(bool flag);

    // Bind properties
    static void BindPopup(const RefPtr<PopupParam> &param, const RefPtr<FrameNode> &targetNode,
        const RefPtr<UINode> &customNode);
    static void DismissDialog();
    static void DismissPopup();
    static void BindMenuWithItems(std::vector<OptionParam> &&params, const RefPtr<FrameNode> &targetNode,
        const NG::OffsetF &offset, const MenuParam &menuParam);
    static void BindMenuWithCustomNode(std::function<void()>&& buildFunc, const RefPtr<FrameNode>& targetNode,
        const NG::OffsetF& offset, MenuParam menuParam, std::function<void()>&& previewBuildFunc);
    static void ShowMenu(
        int32_t targetId, const NG::OffsetF& offset, bool isShowInSubWindow, bool isContextMenu = false);
    // inspector
    static void SetInspectorId(const std::string &inspectorId);
    // auto event param
    static void SetAutoEventParam(const std::string& param);
    // restore
    static void SetRestoreId(int32_t restoreId);
    // inspector debugLine
    static void SetDebugLine(const std::string &line);
    // transition
    static void SetTransition(const TransitionOptions &options);
    static void CleanTransition();
    static void SetChainedTransition(const RefPtr<NG::ChainedTransitionEffect> &effect);
    // sharedTransition
    static void SetSharedTransition(const std::string &shareId, const std::shared_ptr<SharedTransitionOption> &option);
    // geometryTransition
    static void SetGeometryTransition(const std::string &id, bool followWithoutTransition = false);
    // clip and mask
    static void SetClipShape(const RefPtr<BasicShape> &basicShape);
    static void SetClipEdge(bool isClip);
    static void SetMask(const RefPtr<BasicShape> &basicShape);
    // overlay
    static void SetOverlay(const NG::OverlayOptions &overlay);
    static void SetOverlayBuilder(std::function<void()>&& buildFunc,
        const std::optional<Alignment>& align, const std::optional<Dimension>& offsetX,
        const std::optional<Dimension>& offsetY);
    // motionPath
    static void SetMotionPath(const MotionPathOption &motionPath);
    // progress mask
    static void SetProgressMask(const RefPtr<ProgressMaskProperty> &progress);

    static void Pop();

    // Disable event
    static void DisableOnClick();
    static void DisableOnTouch();
    static void DisableOnKeyEvent();
    static void DisableOnHover();
    static void DisableOnMouse();
    static void DisableOnAppear();
    static void DisableOnDisAppear();
    static void DisableOnAttach();
    static void DisableOnDetach();
    static void DisableOnAreaChange();
    static void DisableOnFocus();
    static void DisableOnBlur();
    static void DisableOnClick(FrameNode* frameNode);
    static void DisableOnTouch(FrameNode* frameNode);
    static void DisableOnKeyEvent(FrameNode* frameNode);
    static void DisableOnHover(FrameNode* frameNode);
    static void DisableOnMouse(FrameNode* frameNode);
    static void DisableOnAppear(FrameNode* frameNode);
    static void DisableOnDisappear(FrameNode* frameNode);
    static void DisableOnAttach(FrameNode* frameNode);
    static void DisableOnDetach(FrameNode* frameNode);
    static void DisableOnFocus(FrameNode* frameNode);
    static void DisableOnBlur(FrameNode* frameNode);
    static void DisableOnAreaChange(FrameNode* frameNode);

    // useEffect
    static void SetUseEffect(bool useEffect);

    static void SetFreeze(bool freeze);

    static void SetDisallowDropForcedly(bool isDisallowDropForcedly);

    // useShadowBatching
    static void SetUseShadowBatching(bool useShadowBatching);

    // foregroundColor
    static void SetForegroundColor(const Color& color);
    static void SetForegroundColorStrategy(const ForegroundColorStrategy& strategy);

    // clickEffect
    static void SetClickEffectLevel(const ClickEffectLevel& level, float scaleValue);

    // custom animatable property
    static void CreateAnimatablePropertyFloat(
        const std::string& propertyName, float value, const std::function<void(float)>& onCallbackEvent);
    static void UpdateAnimatablePropertyFloat(const std::string& propertyName, float value);
    static void CreateAnimatableArithmeticProperty(const std::string& propertyName,
        RefPtr<CustomAnimatableArithmetic>& value,
        std::function<void(const RefPtr<CustomAnimatableArithmetic>&)>& onCallbackEvent);
    static void UpdateAnimatableArithmeticProperty(
        const std::string& propertyName, RefPtr<CustomAnimatableArithmetic>& value);
    static void UpdateSafeAreaExpandOpts(const SafeAreaExpandOpts& opts);

    // global light
    static void SetLightPosition(
        const CalcDimension& positionX, const CalcDimension& positionY, const CalcDimension& positionZ);
    static void SetLightIntensity(float value);
    static void SetLightColor(const Color& value);
    static void SetLightIlluminated(uint32_t value);
    static void SetIlluminatedBorderWidth(const Dimension& value);
    static void SetBloom(float value);

    static void SetBackgroundColor(FrameNode* frameNode, const Color& color);
    static void SetWidth(FrameNode* frameNode, const CalcLength& width);
    static void SetHeight(FrameNode* frameNode, const CalcLength& height);
    static void ClearWidthOrHeight(FrameNode* frameNode, bool isWidth);
    static void SetBorderRadius(FrameNode* frameNode, const BorderRadiusProperty& value);
    static void SetBorderRadius(FrameNode* frameNode, const Dimension& value);
    static void SetBorderWidth(FrameNode* frameNode, const BorderWidthProperty& value);
    static void SetBorderWidth(FrameNode* frameNode, const Dimension& value);
    static void SetBorderColor(FrameNode* frameNode, const BorderColorProperty& value);
    static void SetBorderColor(FrameNode* frameNode, const Color& value);
    static void SetOuterBorderColor(FrameNode* frameNode, const Color& value);
    static void SetOuterBorderColor(FrameNode* frameNode, const BorderColorProperty& value);
    static void SetOuterBorderRadius(FrameNode* frameNode, const Dimension& value);
    static void SetOuterBorderRadius(FrameNode* frameNode, const BorderRadiusProperty& value);
    static void SetOuterBorderWidth(FrameNode* frameNode, const Dimension& value);
    static void SetOuterBorderWidth(FrameNode* frameNode, const BorderWidthProperty& value);
    static void SetOuterBorderStyle(FrameNode* frameNode, const BorderStyleProperty& value);
    static void SetOuterBorderStyle(FrameNode* frameNode, const BorderStyle& value);
    static void SetBorderStyle(FrameNode* frameNode, const BorderStyle& value);
    static void SetBorderStyle(FrameNode* frameNode, const BorderStyleProperty& value);
    static void SetBackShadow(FrameNode* frameNode, const Shadow& shadow);
    static void SetPosition(FrameNode* frameNode, const OffsetT<Dimension>& value);
    static void SetPositionEdges(FrameNode* frameNode, const EdgesParam& value);
    static void ResetPosition(FrameNode* frameNode);
    static void SetTransformMatrix(FrameNode* frameNode, const Matrix4& matrix);
    static void SetHitTestMode(FrameNode* frameNode, HitTestMode hitTestMode);
    static void SetOpacity(FrameNode* frameNode, double opacity);
    static void SetZIndex(FrameNode* frameNode, int32_t value);
    static void SetAlign(FrameNode* frameNode, Alignment alignment);
    static void SetBackdropBlur(FrameNode* frameNode, const Dimension& radius, const BlurOption &blurOption);
    static void SetInvert(FrameNode* frameNode, const InvertVariant& invert);
    static void SetSepia(FrameNode* frameNode, const Dimension& sepia);
    static void SetSaturate(FrameNode* frameNode, const Dimension& saturate);
    static void SetColorBlend(FrameNode* frameNode, const Color& colorBlend);
    static void SetGrayScale(FrameNode* frameNode, const Dimension& grayScale);
    static void SetContrast(FrameNode* frameNode, const Dimension& contrast);
    static void SetBrightness(FrameNode* frameNode, const Dimension& brightness);
    static void SetFrontBlur(FrameNode* frameNode, const Dimension& radius, const BlurOption &blurOption);
    static void SetHueRotate(FrameNode* frameNode, float hueRotate);
    static void SetLinearGradient(FrameNode* frameNode, const NG::Gradient& gradient);
    static void SetSweepGradient(FrameNode* frameNode, const NG::Gradient& gradient);
    static void SetRadialGradient(FrameNode* frameNode, const NG::Gradient& gradient);
    static void SetOverlay(FrameNode* frameNode, const NG::OverlayOptions& overlay);
    static void SetBorderImage(FrameNode* frameNode, const RefPtr<BorderImage>& borderImage);
    static void SetBorderImageSource(FrameNode* frameNode, const std::string& bdImageSrc);
    static void SetHasBorderImageSlice(FrameNode* frameNode, bool tag);
    static void SetHasBorderImageWidth(FrameNode* frameNode, bool tag);
    static void SetHasBorderImageOutset(FrameNode* frameNode, bool tag);
    static void SetHasBorderImageRepeat(FrameNode* frameNode, bool tag);
    static void SetBorderImageGradient(FrameNode* frameNode, const NG::Gradient& gradient);
    static void SetForegroundBlurStyle(FrameNode* frameNode, const BlurStyleOption& fgBlurStyle);
    static void SetLinearGradientBlur(FrameNode* frameNode, const NG::LinearGradientBlurPara& blurPara);
    static void SetBackgroundBlurStyle(FrameNode* frameNode, const BlurStyleOption& bgBlurStyle);
    static void SetBackgroundImagePosition(FrameNode* frameNode, const BackgroundImagePosition& bgImgPosition);
    static void SetBackgroundImageSize(FrameNode* frameNode, const BackgroundImageSize& bgImgSize);
    static void SetBackgroundImage(FrameNode* frameNode, const ImageSourceInfo& src);
    static void SetBackgroundImageRepeat(FrameNode* frameNode, const ImageRepeat& imageRepeat);
    static void SetTranslate(FrameNode* frameNode, const NG::TranslateOptions& value);
    static void SetScale(FrameNode* frameNode, const NG::VectorF& value);
    static void SetPivot(FrameNode* frameNode, const DimensionOffset& value);
    static void SetGeometryTransition(FrameNode* frameNode, const std::string& id, bool followWithoutTransition);
    static const std::string GetGeometryTransition(FrameNode* frameNode, bool* followWithoutTransition);
    static void SetRotate(FrameNode* frameNode, const NG::Vector5F& value);
    static void SetClipEdge(FrameNode* frameNode, bool isClip);
    static void SetClipShape(FrameNode* frameNode, const RefPtr<BasicShape>& basicShape);
    static void SetPixelStretchEffect(FrameNode* frameNode, PixStretchEffectOption& option);
    static void SetLightUpEffect(FrameNode* frameNode, double radio);
    static void SetSphericalEffect(FrameNode* frameNode, double radio);
    static void SetRenderGroup(FrameNode* frameNode, bool isRenderGroup);
    static void SetRenderFit(FrameNode* frameNode, RenderFit renderFit);
    static void SetUseEffect(FrameNode* frameNode, bool useEffect);
    static void SetForegroundColor(FrameNode* frameNode, const Color& color);
    static void SetForegroundColorStrategy(FrameNode* frameNode, const ForegroundColorStrategy& strategy);
    static void SetMotionPath(FrameNode* frameNode, const MotionPathOption& motionPath);
    static void SetFocusOnTouch(FrameNode* frameNode, bool isSet);
    static void SetGroupDefaultFocus(FrameNode* frameNode, bool isSet);
    static void SetFocusable(FrameNode* frameNode, bool focusable);
    static void SetTouchable(FrameNode* frameNode, bool touchable);
    static void SetDefaultFocus(FrameNode* frameNode, bool isSet);
    static void SetDisplayIndex(FrameNode* frameNode, int32_t value);
    static void SetOffset(FrameNode* frameNode, const OffsetT<Dimension>& value);
    static void SetOffsetEdges(FrameNode* frameNode, const EdgesParam& value);
    static void MarkAnchor(FrameNode* frameNode, const OffsetT<Dimension>& value);
    static void SetVisibility(FrameNode* frameNode, VisibleType visible);
    static void SetMargin(FrameNode* frameNode, const CalcLength& value);
    static void SetMargin(FrameNode* frameNode, const PaddingProperty& value);
    static void SetPadding(FrameNode* frameNode, const CalcLength& value);
    static void SetPadding(FrameNode* frameNode, const PaddingProperty& value);
    static void SetLayoutDirection(FrameNode* frameNode, TextDirection value);
    static void UpdateSafeAreaExpandOpts(FrameNode* frameNode, const SafeAreaExpandOpts& opts);
    static void SetAspectRatio(FrameNode* frameNode, float ratio);
    static void SetAlignSelf(FrameNode* frameNode, FlexAlign value);
    static void SetFlexBasis(FrameNode* frameNode, const Dimension& value);
    static void ResetFlexShrink(FrameNode* frameNode);
    static void SetFlexShrink(FrameNode* frameNode, float value);
    static void SetFlexGrow(FrameNode* frameNode, float value);
    static void SetLayoutWeight(FrameNode* frameNode, float value);
    static void ResetMaxSize(FrameNode* frameNode, bool resetWidth);
    static void ResetMinSize(FrameNode* frameNode, bool resetWidth);
    static void SetMinWidth(FrameNode* frameNode, const CalcLength& minWidth);
    static void SetMaxWidth(FrameNode* frameNode, const CalcLength& maxWidth);
    static void SetMinHeight(FrameNode* frameNode, const CalcLength& minHeight);
    static void SetMaxHeight(FrameNode* frameNode, const CalcLength& maxHeight);
    static void SetAlignRules(FrameNode* frameNode, const std::map<AlignDirection, AlignRule>& alignRules);
    static void SetChainStyle(FrameNode* frameNode, const ChainInfo& chainInfo);
    static ChainInfo GetChainStyle(FrameNode* frameNode);
    static void ResetChainStyle(FrameNode* frameNode);
    static void SetGrid(FrameNode* frameNode, std::optional<int32_t> span, std::optional<int32_t> offset,
        GridSizeType type = GridSizeType::UNDEFINED);
    static void ResetAspectRatio(FrameNode* frameNode);
    static void SetAllowDrop(FrameNode* frameNode, const std::set<std::string>& allowDrop);
    static void SetInspectorId(FrameNode* frameNode, const std::string& inspectorId);
    static void SetRestoreId(FrameNode* frameNode, int32_t restoreId);
    static void SetTabIndex(FrameNode* frameNode, int32_t index);
    static void SetObscured(FrameNode* frameNode, const std::vector<ObscuredReasons>& reasons);
    static void SetMotionBlur(FrameNode* frameNode, const MotionBlurOption &motionBlurOption);
    static void SetForegroundEffect(FrameNode* frameNode, float radius);
    static void SetBackgroundEffect(FrameNode* frameNode, const EffectOption &effectOption);
    static void SetBackgroundImageResizableSlice(FrameNode* frameNode, const ImageResizableSlice& slice);
    static void SetDynamicLightUp(FrameNode* frameNode, float rate, float lightUpDegree);
    static void SetBgDynamicBrightness(FrameNode* frameNode, const BrightnessOption& brightnessOption);
    static void SetFgDynamicBrightness(FrameNode* frameNode, const BrightnessOption& brightnessOption);
    static void SetDragPreviewOptions(FrameNode* frameNode, const DragPreviewOption& previewOption);
    static void SetResponseRegion(FrameNode* frameNode, const std::vector<DimensionRect>& responseRegion);
    static void SetMouseResponseRegion(FrameNode* frameNode, const std::vector<DimensionRect>& mouseResponseRegion);
    static void SetSharedTransition(
        FrameNode* frameNode, const std::string& shareId, const std::shared_ptr<SharedTransitionOption>& option);
    static void SetTransition(FrameNode* frameNode, const TransitionOptions& options);
    static void CleanTransition(FrameNode* frameNode);
    static void SetChainedTransition(FrameNode* frameNode, const RefPtr<NG::ChainedTransitionEffect>& effect);
    static void SetMask(FrameNode* frameNode, const RefPtr<BasicShape>& basicShape);
    static void SetProgressMask(FrameNode* frameNode, const RefPtr<ProgressMaskProperty>& progress);
    static void SetEnabled(FrameNode* frameNode, bool enabled);
    static void SetUseShadowBatching(FrameNode* frameNode, bool useShadowBatching);
    static void SetBlendMode(FrameNode* frameNode, BlendMode blendMode);
    static void SetBlendApplyType(FrameNode* frameNode, BlendApplyType blendApplyType);
    static void SetMonopolizeEvents(FrameNode* frameNode, bool monopolizeEvents);
    static void SetDraggable(FrameNode* frameNode, bool draggable);
    static void SetHoverEffect(FrameNode* frameNode, HoverEffectType hoverEffect);
    static void SetClickEffectLevel(FrameNode* frameNode, const ClickEffectLevel& level, float scaleValue);
    static void SetKeyboardShortcut(FrameNode* frameNode, const std::string& value,
        const std::vector<ModifierKey>& keys, std::function<void()>&& onKeyboardShortcutAction);

    static void SetOnAppear(FrameNode* frameNode, std::function<void()> &&onAppear);
    static void SetOnDisappear(FrameNode* frameNode, std::function<void()> &&onDisappear);
    static void SetOnAttach(FrameNode* frameNode, std::function<void()> &&onAttach);
    static void SetOnDetach(FrameNode* frameNode, std::function<void()> &&onDetach);
    static void SetOnAreaChanged(FrameNode* frameNode, std::function<void(const RectF &oldRect,
        const OffsetF &oldOrigin, const RectF &rect, const OffsetF &origin)> &&onAreaChanged);
    static void SetOnFocus(FrameNode* frameNode, OnFocusFunc &&onFocusCallback);
    static void SetOnBlur(FrameNode* frameNode, OnBlurFunc &&onBlurCallback);
    static void SetOnClick(FrameNode* frameNode, GestureEventFunc &&clickEventFunc);
    static void SetOnTouch(FrameNode* frameNode, TouchEventFunc &&touchEventFunc);
    static void SetOnMouse(FrameNode* frameNode, OnMouseEventFunc &&onMouseEventFunc);
    static void SetOnHover(FrameNode* frameNode, OnHoverFunc &&onHoverEventFunc);
    static void SetOnKeyEvent(FrameNode* frameNode, OnKeyCallbackFunc &&onKeyCallback);
    static void SetOnGestureJudgeBegin(FrameNode* frameNode, GestureJudgeFunc&& gestureJudgeFunc);
    static void SetOnSizeChanged(
        FrameNode* frameNode, std::function<void(const RectF& oldRect, const RectF& rect)>&& onSizeChanged);

    static bool GetFocusable(FrameNode* frameNode);
    static bool GetDefaultFocus(FrameNode* frameNode);
    static std::vector<DimensionRect> GetResponseRegion(FrameNode* frameNode);
    static NG::OverlayOptions GetOverlay(FrameNode* frameNode);
    static void SetNeedFocus(FrameNode* frameNode, bool value);
    static bool GetNeedFocus(FrameNode* frameNode);
    static double GetOpacity(FrameNode* frameNode);
    static BorderWidthProperty GetBorderWidth(FrameNode* frameNode);
    static BorderWidthProperty GetLayoutBorderWidth(FrameNode* frameNode);
    static BorderRadiusProperty GetBorderRadius(FrameNode* frameNode);
    static BorderColorProperty GetBorderColor(FrameNode* frameNode);
    static BorderStyleProperty GetBorderStyle(FrameNode* frameNode);
    static int GetZIndex(FrameNode* frameNode);
    static VisibleType GetVisibility(FrameNode* frameNode);
    static bool GetClip(FrameNode* frameNode);
    static RefPtr<BasicShape> GetClipShape(FrameNode* frameNode);
    static Matrix4 GetTransform(FrameNode* frameNode);
    static HitTestMode GetHitTestBehavior(FrameNode* frameNode);
    static OffsetT<Dimension> GetPosition(FrameNode* frameNode);
    static std::optional<Shadow> GetShadow(FrameNode* frameNode);
    static NG::Gradient GetSweepGradient(FrameNode* frameNode);
    static NG::Gradient GetRadialGradient(FrameNode* frameNode);
    static RefPtr<BasicShape> GetMask(FrameNode* frameNode);
    static RefPtr<ProgressMaskProperty> GetMaskProgress(FrameNode* frameNode);
    static BlendMode GetBlendMode(FrameNode* frameNode);
    static TextDirection GetDirection(FrameNode* frameNode);
    static std::map<AlignDirection, AlignRule> GetAlignRules(FrameNode* frameNode);
    static FlexAlign GetAlignSelf(FrameNode* frameNode);
    // used in JS FrameNode
    static void SetJSFrameNodeOnClick(FrameNode* frameNode, GestureEventFunc&& clickEventFunc);
    static void SetJSFrameNodeOnTouch(FrameNode* frameNode, TouchEventFunc&& touchEventFunc);
    static void SetJSFrameNodeOnAppear(FrameNode* frameNode, std::function<void()>&& onAppear);
    static void SetJSFrameNodeOnDisappear(FrameNode* frameNode, std::function<void()>&& onDisappear);
    static void SetJSFrameNodeOnKeyCallback(FrameNode* frameNode, OnKeyCallbackFunc&& onKeyCallback);
    static void SetJSFrameNodeOnFocusCallback(FrameNode* frameNode, OnFocusFunc&& onFocusCallback);
    static void SetJSFrameNodeOnBlurCallback(FrameNode* frameNode, OnBlurFunc&& onBlurCallback);
    static void SetJSFrameNodeOnHover(FrameNode* frameNode, OnHoverFunc&& onHoverEventFunc);
    static void SetJSFrameNodeOnMouse(FrameNode* frameNode, OnMouseEventFunc&& onMouseEventFunc);
    static void SetJSFrameNodeOnSizeChange(
        FrameNode* frameNode, std::function<void(const RectF& oldRect, const RectF& rect)>&& onSizeChanged);
    static void SetJSFrameNodeOnVisibleAreaApproximateChange(FrameNode* frameNode,
        const std::function<void(bool, double)>&& jsCallback, const std::vector<double>& ratioList,
        int32_t expectedUpdateInterval = 1000);
    static void ClearJSFrameNodeOnClick(FrameNode* frameNode);
    static void ClearJSFrameNodeOnTouch(FrameNode* frameNode);
    static void ClearJSFrameNodeOnAppear(FrameNode* frameNode);
    static void ClearJSFrameNodeOnDisappear(FrameNode* frameNode);
    static void ClearJSFrameNodeOnKeyCallback(FrameNode* frameNode);
    static void ClearJSFrameNodeOnFocusCallback(FrameNode* frameNode);
    static void ClearJSFrameNodeOnBlurCallback(FrameNode* frameNode);
    static void ClearJSFrameNodeOnHover(FrameNode* frameNode);
    static void ClearJSFrameNodeOnMouse(FrameNode* frameNode);
    static void ClearJSFrameNodeOnSizeChange(FrameNode* frameNode);
    static void ClearJSFrameNodeOnVisibleAreaApproximateChange(FrameNode* frameNode);

    static float GetFlexGrow(FrameNode* frameNode);
    static float GetFlexShrink(FrameNode* frameNode);
    static Dimension GetFlexBasis(FrameNode* frameNode);
    static Dimension GetMinWidth(FrameNode* frameNode);
    static Dimension GetMaxWidth(FrameNode* frameNode);
    static Dimension GetMinHeight(FrameNode* frameNode);
    static Dimension GetMaxHeight(FrameNode* frameNode);
    static Dimension GetGrayScale(FrameNode* frameNode);
    static InvertVariant GetInvert(FrameNode* frameNode);
    static Dimension GetSepia(FrameNode* frameNode);
    static Dimension GetContrast(FrameNode* frameNode);
    static Color GetForegroundColor(FrameNode* frameNode);
    static Dimension GetFrontBlur(FrameNode* frameNode);
    static NG::Gradient GetLinearGradient(FrameNode* frameNode);
    static Alignment GetAlign(FrameNode* frameNode);
    static NG::VectorF GetScale(FrameNode* frameNode);
    static NG::Vector5F GetRotate(FrameNode* frameNode);
    static Dimension GetBrightness(FrameNode* frameNode);
    static Dimension GetSaturate(FrameNode* frameNode);
    static BackgroundImagePosition GetBackgroundImagePosition(FrameNode* frameNode);
    static Dimension GetWidth(FrameNode* frameNode);
    static Dimension GetHeight(FrameNode* frameNode);
    static Color GetBackgroundColor(FrameNode* frameNode);
    static std::string GetBackgroundImageSrc(FrameNode* frameNode);
    static ImageRepeat GetBackgroundImageRepeat(FrameNode* frameNode);
    static PaddingProperty GetPadding(FrameNode* frameNode);
    static std::optional<CalcSize> GetConfigSize(FrameNode* frameNode);
    static std::string GetKey(FrameNode* frameNode);
    static bool GetEnabled(FrameNode* frameNode);
    static MarginProperty GetMargin(FrameNode* frameNode);
    static TranslateOptions GetTranslate(FrameNode* frameNode);
    static float GetAspectRatio(FrameNode* frameNode);
    static BlendApplyType GetBlendApplyType(FrameNode* frameNode);
    static void SetOnTouchIntercept(FrameNode* frameNode, TouchInterceptFunc &&touchInterceptFunc);
    static float GetLayoutWeight(FrameNode* frameNode);
    static void SetFocusScopeId(const std::string& focusScopeId, bool isGroup);
    static void SetFocusScopePriority(const std::string& focusScopeId, const uint32_t focusPriority);
    static int32_t GetDisplayIndex(FrameNode* frameNode);
    static NG::BorderWidthProperty GetOuterBorderWidth(FrameNode* frameNode);
    static void SetBias(FrameNode* frameNode, const BiasPair& biasPair);
    static BiasPair GetBias(FrameNode* frameNode);
    static RenderFit GetRenderFit(FrameNode* frameNode);
    static BorderColorProperty GetOuterBorderColor(FrameNode* frameNode);
    static bool GetRenderGroup(FrameNode* frameNode);
    static void ResetBias(FrameNode* frameNode);
    static void ResetAlignRules(FrameNode* frameNode);
    static void SetOnVisibleChange(FrameNode* frameNode, std::function<void(bool, double)> &&onVisibleChange,
        const std::vector<double> &ratioList);
    static Color GetColorBlend(FrameNode* frameNode);
    static void ResetAreaChanged(FrameNode* frameNode);
    static void ResetVisibleChange(FrameNode* frameNode);
    static void SetLayoutRect(FrameNode* frameNode, const NG::RectF& rect);
    static void ResetLayoutRect(FrameNode* frameNode);
    static NG::RectF GetLayoutRect(FrameNode* frameNode);
    static bool GetFocusOnTouch(FrameNode* frameNode);

private:
    static void AddDragFrameNodeToManager();
};
} // namespace OHOS::Ace::NG

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_BASE_VIEW_ABSTRACT_H
