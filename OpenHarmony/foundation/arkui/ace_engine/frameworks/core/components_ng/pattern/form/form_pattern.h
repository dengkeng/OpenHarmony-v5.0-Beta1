/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERN_FORM_FORM_PATTERN_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERN_FORM_FORM_PATTERN_H

#include "transaction/rs_interfaces.h"

#include "core/common/ace_application_info.h"
#include "core/components/form/resource/form_request_data.h"
#include "core/components_ng/event/event_hub.h"
#include "core/components_ng/pattern/form/form_event_hub.h"
#include "core/components_ng/pattern/form/form_layout_property.h"
#include "core/components_ng/pattern/pattern.h"
#include "form_skeleton_params.h"

namespace OHOS {
namespace MMI {
class PointerEvent;
} // namespace MMI

namespace Ace {
class SubContainer;
class FormManagerDelegate;

namespace NG {

class FormPattern : public Pattern {
    DECLARE_ACE_TYPE(FormPattern, Pattern);

public:
    FormPattern();
    ~FormPattern() override;

    void OnActionEvent(const std::string& action);

    void OnLoadEvent();

    void HandleUnTrustForm();

    RefPtr<LayoutProperty> CreateLayoutProperty() override
    {
        return MakeRefPtr<FormLayoutProperty>();
    }

    RefPtr<EventHub> CreateEventHub() override
    {
        return MakeRefPtr<FormEventHub>();
    }

    std::unique_ptr<DrawDelegate> GetDrawDelegate();

    const RefPtr<SubContainer>& GetSubContainer() const;

    void DispatchPointerEvent(const std::shared_ptr<MMI::PointerEvent>& pointerEvent,
        SerializedGesture& serializedGesture);

    void OnSnapshot(std::shared_ptr<Media::PixelMap> pixelMap);

    void HandleOnSnapshot(std::shared_ptr<Media::PixelMap> pixelMap);

    RefPtr<RenderContext> GetExternalRenderContext()
    {
        return externalRenderContext_;
    }

    bool GetIsLoaded() const
    {
        return isLoaded_;
    }

    void SetFormLinkInfos(const std::vector<std::string>& infos)
    {
        formLinkInfos_.clear();
        formLinkInfos_ = infos;
    }

    bool IsJsCard() const
    {
        return isJsCard_;
    }

    void SetObscured(bool isObscured)
    {
        isFormObscured_ = isObscured;
    }

private:
    void OnAttachToFrameNode() override;
    bool OnDirtyLayoutWrapperSwap(const RefPtr<LayoutWrapper>& dirty, const DirtySwapConfig& config) override;
    void OnRebuildFrame() override;
    void OnVisibleChange(bool isVisible) override;
    void OnModifyDone() override;

    void InitFormManagerDelegate();
    void CreateCardContainer();
    void RemoveSubContainer();

    void FireOnAcquiredEvent(int64_t id) const;
    void FireOnRouterEvent(const std::unique_ptr<JsonValue>& action);
    void FireOnLoadEvent() const;
    void FireOnErrorEvent(const std::string& code, const std::string& msg) const;
    void FireOnUninstallEvent(int64_t id) const;
    void FireFormSurfaceNodeCallback(const std::shared_ptr<Rosen::RSSurfaceNode>& node, bool isDynamic, bool isRecover);
    void FireFormSurfaceChangeCallback(float width, float height, float borderWidth = 0.0);
    void FireFormSurfaceDetachCallback();
    void UpdateBackgroundColorWhenUnTrustForm();

    bool ISAllowUpdate() const;
    void EnableDrag();
    void UpdateConfiguration();
    void HandleFormComponent(const RequestFormInfo& info);
    void AddFormComponent(const RequestFormInfo& info);
    void UpdateFormComponent(const RequestFormInfo& info);
    void UpdateFormComponentSize(const RequestFormInfo& info);

    void HandleSnapshot(uint32_t delayTime);
    void TakeSurfaceCaptureForUI();
    void UpdateStaticCard();
    RefPtr<FrameNode> CreateImageNode();
    void UpdateImageNode();
    void RemoveFrsNode();
    void ReleaseRenderer();
    void DeleteImageNode();
    void DelayDeleteImageNode();
    void DeleteImageNodeAfterRecover();
    RefPtr<FrameNode> GetImageNode();
    void HandleStaticFormEvent(const PointF& touchPoint);

    void InitClickEvent();
    void HandleTouchDownEvent(const TouchEventInfo& event);
    void HandleTouchUpEvent(const TouchEventInfo& event);

    void LoadFormSkeleton();
    int32_t GetFormDimensionHeight(int32_t dimension);
    void RemoveFormSkeleton();
    RefPtr<FrameNode> CreateColumnNode();
    RefPtr<FrameNode> CreateRectNode(const RefPtr<FrameNode>& parent, const CalcSize& idealSize,
        const MarginProperty& margin, uint32_t fillColor, double opacity);
    void CreateSkeletonView(const RefPtr<FrameNode>& parent, const std::shared_ptr<FormSkeletonParams>& params,
        int32_t dimensionHeight);

    // used by ArkTS Card, for RSSurfaceNode from FRS,
    RefPtr<RenderContext> externalRenderContext_;

    RefPtr<SubContainer> subContainer_;
    RefPtr<FormManagerDelegate> formManagerBridge_;

    RequestFormInfo cardInfo_;
    bool isLoaded_ = false;
    bool isVisible_ = true;
    bool isBeenLayout_ = false;
    bool isUnTrust_ = false;
    bool isDynamic_ = true;
    bool isFrsNodeDetached_ = false;
    bool needSnapshotAgain_ = false;
    bool isSnapshot_ = false;
    RefPtr<PixelMap> pixelMap_ = nullptr;
    int64_t snapshotTimestamp_ = 0;
    int32_t scopeId_;
    std::string localeTag_ = AceApplicationInfo::GetInstance().GetLocaleTag();
    std::vector<std::string> formLinkInfos_;
    TimeStamp touchDownTime_;
    bool shouldResponseClick_ = false;
    Offset lastTouchLocation_;

    bool isFormObscured_ = false;
    bool isJsCard_ = true;
};

} // namespace NG
} // namespace Ace
} // namespace OHOS

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERN_FORM_FORM_PATTERN_H
