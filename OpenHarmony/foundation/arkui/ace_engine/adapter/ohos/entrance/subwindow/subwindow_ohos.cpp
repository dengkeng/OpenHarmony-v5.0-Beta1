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

#include "adapter/ohos/entrance/subwindow/subwindow_ohos.h"

#include "dm/display_manager.h"
#include "interfaces/inner_api/ace/viewport_config.h"
#include "render_service_client/core/ui/rs_surface_node.h"
#include "window.h"

#include "adapter/ohos/entrance/ace_application_info.h"
#include "base/geometry/rect.h"
#include "base/log/log_wrapper.h"
#include "core/components/root/root_element.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/base/ui_node.h"
#include "core/components_ng/property/property.h"
#include "core/components_v2/inspector/inspector_constants.h"
#include "core/pipeline_ng/pipeline_context.h"
#if defined(ENABLE_ROSEN_BACKEND) and !defined(UPLOAD_GPU_DISABLED)
#include "adapter/ohos/entrance/ace_rosen_sync_task.h"
#endif

#include "adapter/ohos/entrance/ace_container.h"
#include "adapter/ohos/entrance/ace_view_ohos.h"
#include "adapter/ohos/entrance/dialog_container.h"
#include "adapter/ohos/entrance/utils.h"
#include "base/log/frame_report.h"
#include "base/utils/system_properties.h"
#include "base/utils/utils.h"
#include "core/common/connect_server_manager.h"
#include "core/common/container_scope.h"
#include "core/common/frontend.h"
#include "core/common/hdc_register.h"
#include "core/common/text_field_manager.h"
#include "core/components/bubble/bubble_component.h"
#include "core/components/popup/popup_component.h"
#include "core/components_ng/pattern/menu/menu_view.h"
#include "core/components_ng/pattern/menu/wrapper/menu_wrapper_pattern.h"
#include "core/components_ng/pattern/overlay/overlay_manager.h"
#include "core/components_ng/render/adapter/rosen_render_context.h"
#include "core/components_ng/render/adapter/rosen_window.h"
#include "frameworks/bridge/common/utils/engine_helper.h"
#include "frameworks/bridge/declarative_frontend/declarative_frontend.h"

namespace OHOS::Ace {
namespace {
const Rect MIN_WINDOW_HOT_AREA = Rect(0.0f, 0.0f, 1.0f, 1.0f);
#ifndef NG_BUILD
constexpr int32_t PLATFORM_VERSION_TEN = 10;
#endif
} // namespace

int32_t SubwindowOhos::id_ = 0;
static std::atomic<int32_t> gToastDialogId = 0;
RefPtr<Subwindow> Subwindow::CreateSubwindow(int32_t instanceId)
{
    return AceType::MakeRefPtr<SubwindowOhos>(instanceId);
}

SubwindowOhos::SubwindowOhos(int32_t instanceId) : windowId_(id_), parentContainerId_(instanceId)
{
    SetSubwindowId(windowId_);
    id_++;
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "Create Subwindow, subwindow id %{public}d, container id %{public}d", windowId_,
        instanceId);
}

void SubwindowOhos::InitContainer()
{
    auto parentContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    CHECK_NULL_VOID(parentContainer);
    auto parentPipeline = parentContainer->GetPipelineContext();
    CHECK_NULL_VOID(parentPipeline);
    if (!window_) {
        OHOS::sptr<OHOS::Rosen::WindowOption> windowOption = new OHOS::Rosen::WindowOption();
        auto parentWindowName = parentContainer->GetWindowName();
        auto parentWindowId = parentContainer->GetWindowId();
        auto defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
        sptr<OHOS::Rosen::Window> parentWindow = parentContainer->GetUIWindow(parentContainerId_);
        CHECK_NULL_VOID(parentWindow);
        parentWindow_ = parentWindow;
        auto windowType = parentWindow->GetType();
        if (parentContainer->IsScenceBoardWindow() || windowType == Rosen::WindowType::WINDOW_TYPE_DESKTOP) {
            windowOption->SetWindowType(Rosen::WindowType::WINDOW_TYPE_SYSTEM_FLOAT);
        } else if (GetAboveApps()) {
            windowOption->SetWindowType(Rosen::WindowType::WINDOW_TYPE_TOAST);
        } else if (windowType == Rosen::WindowType::WINDOW_TYPE_UI_EXTENSION) {
            auto hostWindowId = parentPipeline->GetFocusWindowId();
            windowOption->SetExtensionTag(true);
            windowOption->SetWindowType(Rosen::WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
            windowOption->SetParentId(hostWindowId);
            SetUIExtensionHostWindowId(hostWindowId);
        } else if (windowType >= Rosen::WindowType::SYSTEM_WINDOW_BASE) {
            windowOption->SetWindowType(Rosen::WindowType::WINDOW_TYPE_SYSTEM_SUB_WINDOW);
            windowOption->SetParentId(parentWindowId);
        } else {
            windowOption->SetWindowType(Rosen::WindowType::WINDOW_TYPE_APP_SUB_WINDOW);
            windowOption->SetParentId(parentWindowId);
        }
        windowOption->SetWindowRect({ 0, 0, defaultDisplay->GetWidth(), defaultDisplay->GetHeight() });
        windowOption->SetWindowMode(Rosen::WindowMode::WINDOW_MODE_FLOATING);
        window_ = OHOS::Rosen::Window::Create("ARK_APP_SUBWINDOW_" + parentWindowName + std::to_string(windowId_),
            windowOption, parentWindow->GetContext());
        if (!window_) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Window create failed");
        }
        CHECK_NULL_VOID(window_);
    }
    std::string url = "";
    auto subSurface = window_->GetSurfaceNode();
    CHECK_NULL_VOID(subSurface);
    subSurface->SetShadowElevation(0.0f);
    window_->NapiSetUIContent(url, nullptr, nullptr, false);
    childContainerId_ = SubwindowManager::GetInstance()->GetContainerId(window_->GetWindowId());
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "Window child containerId : %{public}d", childContainerId_);
    SubwindowManager::GetInstance()->AddParentContainerId(childContainerId_, parentContainerId_);

    auto container = Platform::AceContainer::GetContainer(childContainerId_);
    if (!container) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Window get ace container failed");
    }
    CHECK_NULL_VOID(container);

    auto parentToken = parentContainer->GetToken();
    container->SetToken(parentToken);
    container->SetWindowId(window_->GetWindowId());
    container->SetParentId(parentContainerId_);
    container->GetSettings().SetUsingSharedRuntime(true);
    container->SetSharedRuntime(parentContainer->GetSharedRuntime());
    container->Initialize();
    container->SetAssetManager(parentContainer->GetAssetManager());
    container->SetResourceConfiguration(parentContainer->GetResourceConfiguration());
    container->SetPackagePathStr(parentContainer->GetPackagePathStr());
    container->SetHapPath(parentContainer->GetHapPath());
    container->SetIsSubContainer(true);
    container->InitializeSubContainer(parentContainerId_);
    ViewportConfig config;
    // create ace_view
    auto* aceView =
        Platform::AceViewOhos::CreateView(childContainerId_, false, container->GetSettings().usePlatformAsUIThread);
    Platform::AceViewOhos::SurfaceCreated(aceView, window_);

    int32_t width = static_cast<int32_t>(window_->GetRequestRect().width_);
    int32_t height = static_cast<int32_t>(window_->GetRequestRect().height_);
    auto density = parentPipeline->GetDensity();
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW,
        "UIContent Initialize: width: %{public}d, height: %{public}d, density: %{public}lf", width, height, density);

    Ace::Platform::UIEnvCallback callback = nullptr;
    // set view
    Platform::AceContainer::SetView(aceView, density, width, height, window_, callback);
    Platform::AceViewOhos::SurfaceChanged(aceView, width, height, config.Orientation());

#ifndef NG_BUILD
#ifdef ENABLE_ROSEN_BACKEND
    if (SystemProperties::GetRosenBackendEnabled()) {
        rsUiDirector = OHOS::Rosen::RSUIDirector::Create();
        if (rsUiDirector != nullptr) {
            rsUiDirector->SetRSSurfaceNode(window_->GetSurfaceNode());
            auto context = DynamicCast<PipelineContext>(container->GetPipelineContext());
            if (context != nullptr) {
                context->SetRSUIDirector(rsUiDirector);
            }
            rsUiDirector->Init();
            TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "UIContent Init Rosen Backend");
        }
    }
#endif
#endif
#ifdef NG_BUILD
    auto subPipelineContextNG = AceType::DynamicCast<NG::PipelineContext>(
        Platform::AceContainer::GetContainer(childContainerId_)->GetPipelineContext());
    CHECK_NULL_VOID(subPipelineContextNG);
    subPipelineContextNG->SetParentPipeline(parentContainer->GetPipelineContext());
    subPipelineContextNG->SetupSubRootElement();
    subPipelineContextNG->SetMinPlatformVersion(parentPipeline->GetMinPlatformVersion());
#else
    if (container->IsCurrentUseNewPipeline()) {
        auto subPipelineContextNG = AceType::DynamicCast<NG::PipelineContext>(
            Platform::AceContainer::GetContainer(childContainerId_)->GetPipelineContext());
        CHECK_NULL_VOID(subPipelineContextNG);
        subPipelineContextNG->SetParentPipeline(parentContainer->GetPipelineContext());
        subPipelineContextNG->SetupSubRootElement();
        subPipelineContextNG->SetMinPlatformVersion(parentPipeline->GetMinPlatformVersion());
        return;
    }
    auto subPipelineContext =
        DynamicCast<PipelineContext>(Platform::AceContainer::GetContainer(childContainerId_)->GetPipelineContext());
    CHECK_NULL_VOID(subPipelineContext);
    subPipelineContext->SetParentPipeline(parentContainer->GetPipelineContext());
    subPipelineContext->SetupSubRootElement();
    subPipelineContext->SetMinPlatformVersion(parentPipeline->GetMinPlatformVersion());
#endif
}

RefPtr<PipelineBase> SubwindowOhos::GetChildPipelineContext() const
{
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_RETURN(aceContainer, nullptr);
    return aceContainer->GetPipelineContext();
}

void SubwindowOhos::ResizeWindow()
{
    auto defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    CHECK_NULL_VOID(defaultDisplay);
    auto ret = window_->Resize(defaultDisplay->GetWidth(), defaultDisplay->GetHeight());
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Resize window by default display failed with errCode: %{public}d",
            static_cast<int32_t>(ret));
        return;
    }
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW,
        "SubwindowOhos window rect is resized to x: %{public}d, y: %{public}d, width: %{public}u, height: %{public}u",
        window_->GetRect().posX_, window_->GetRect().posY_, window_->GetRect().width_, window_->GetRect().height_);
}

NG::RectF SubwindowOhos::GetRect()
{
    NG::RectF rect;
    CHECK_NULL_RETURN(window_, rect);
    rect.SetRect(
        window_->GetRect().posX_, window_->GetRect().posY_, window_->GetRect().width_, window_->GetRect().height_);
    return rect;
}

void SubwindowOhos::ShowPopup(const RefPtr<Component>& newComponent, bool disableTouchEvent)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show popup enter");
#ifndef NG_BUILD
    ShowWindow();
    auto stack = GetStack();
    CHECK_NULL_VOID(stack);
    auto popup = AceType::DynamicCast<TweenComponent>(newComponent);
    CHECK_NULL_VOID(popup);
    stack->PopPopup(popup->GetId());
    stack->PushComponent(newComponent, disableTouchEvent);
    auto bubble = AceType::DynamicCast<BubbleComponent>(popup->GetChild());
    if (bubble) {
        bubble->SetWeakStack(WeakClaim(RawPtr(stack)));
    }
#endif
}

bool SubwindowOhos::CancelPopup(const std::string& id)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "cancel popup enter");
#ifndef NG_BUILD
    auto stack = GetStack();
    CHECK_NULL_RETURN(stack, false);
    stack->PopPopup(id);
    auto context = stack->GetContext().Upgrade();
    CHECK_NULL_RETURN(context, false);
    context->FlushPipelineImmediately();
    HideWindow();
#endif
    return true;
}

void SubwindowOhos::ShowPopupNG(int32_t targetId, const NG::PopupInfo& popupInfo)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show popup ng enter");
    popupTargetId_ = targetId;
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlayManager = context->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    ShowWindow(popupInfo.focusable);
    window_->SetTouchable(true);
    ResizeWindow();
    ContainerScope scope(childContainerId_);
    overlayManager->ShowPopup(targetId, popupInfo);
    window_->SetFocusable(true);
}

void SubwindowOhos::HidePopupNG(int32_t targetId)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "hide popup ng enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlayManager = context->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    auto popupInfo = overlayManager->GetPopupInfo(targetId == -1 ? popupTargetId_ : targetId);
    popupInfo.markNeedUpdate = true;
    ContainerScope scope(childContainerId_);
    overlayManager->HidePopup(targetId == -1 ? popupTargetId_ : targetId, popupInfo);
    context->FlushPipelineImmediately();
    HideEventColumn();
    HidePixelMap();
    HideFilter(false);
}

void SubwindowOhos::GetPopupInfoNG(int32_t targetId, NG::PopupInfo& popupInfo)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "get popup info ng enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlayManager = context->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    popupInfo = overlayManager->GetPopupInfo(targetId);
}

const RefPtr<NG::OverlayManager> SubwindowOhos::GetOverlayManager()
{
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_RETURN(aceContainer, nullptr);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_RETURN(context, nullptr);
    return context->GetOverlayManager();
}

void SubwindowOhos::ShowWindow(bool needFocus)
{
    CHECK_NULL_VOID(window_);
    if (isShowed_) {
        TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "subwindow id:%{public}u is on display", window_->GetWindowId());
        if (needFocus) {
            window_->SetFocusable(needFocus);
            RequestFocus();
        }
        return;
    }
    // Set min window hot area so that sub window can transparent event.
    std::vector<Rosen::Rect> hotAreas;
    Rosen::Rect rosenRect {};
    RectConverter(MIN_WINDOW_HOT_AREA, rosenRect);
    hotAreas.emplace_back(rosenRect);
    window_->SetTouchHotAreas(hotAreas);

    window_->SetNeedDefaultAnimation(false);
    auto ret = window_->SetFocusable(needFocus);
    if (ret != OHOS::Rosen::WMError::WM_OK) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW,
            "subwindow id:%{public}u set focusable %{public}d failed with WMError: %{public}d", window_->GetWindowId(),
            needFocus, static_cast<int32_t>(ret));
    }
    ret = window_->Show();
    if (ret != OHOS::Rosen::WMError::WM_OK) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Show subwindow id:%{public}u failed with WMError: %{public}d",
            window_->GetWindowId(), static_cast<int32_t>(ret));
        return;
    }
    if (needFocus) {
        RequestFocus();
    }

    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = aceContainer->GetPipelineContext();
    CHECK_NULL_VOID(context);
    AccessibilityEvent event;
    event.type = AccessibilityEventType::PAGE_CHANGE;
    event.windowId = context->GetWindowId();
    event.windowChangeTypes = WINDOW_UPDATE_ADDED;
    context->SendEventToAccessibility(event);
    isShowed_ = true;
    SubwindowManager::GetInstance()->SetCurrentSubwindow(AceType::Claim(this));
}

void SubwindowOhos::HideWindow()
{
    CHECK_NULL_VOID(window_);
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "Hide the subwindow %{public}s", window_->GetWindowName().c_str());

    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);

#ifdef NG_BUILD
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto rootNode = context->GetRootElement();
    CHECK_NULL_VOID(rootNode);
    if (!rootNode->GetChildren().empty() &&
        !(rootNode->GetChildren().size() == 1 && rootNode->GetLastChild()->GetTag() == V2::KEYBOARD_ETS_TAG)) {
        auto lastChildId = rootNode->GetLastChild()->GetId();
        auto iter = hotAreasMap_.find(lastChildId);
        if (iter != hotAreasMap_.end()) {
            auto hotAreaRect = iter->second;
            OHOS::Rosen::WMError ret = window_->SetTouchHotAreas(hotAreaRect);
            if (ret != OHOS::Rosen::WMError::WM_OK) {
                TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Set hot areas failed with errCode: %{public}d",
                    static_cast<int32_t>(ret));
            }
        }
        return;
    }
    auto focusHub = rootNode->GetFocusHub();
    CHECK_NULL_VOID(focusHub);
    focusHub->SetIsDefaultHasFocused(false);
#else
    if (Container::IsCurrentUseNewPipeline()) {
        auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
        CHECK_NULL_VOID(context);
        auto rootNode = context->GetRootElement();
        CHECK_NULL_VOID(rootNode);
        if (!rootNode->GetChildren().empty() &&
            !(rootNode->GetChildren().size() == 1 && rootNode->GetLastChild()->GetTag() == V2::KEYBOARD_ETS_TAG)) {
            auto it = hotAreasMap_.find(rootNode->GetLastChild()->GetId());
            if (it != hotAreasMap_.end()) {
                auto hotAreaRect = it->second;
                OHOS::Rosen::WMError ret = window_->SetTouchHotAreas(hotAreaRect);
                if (ret != OHOS::Rosen::WMError::WM_OK) {
                    TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Set hot areas failed with errCode: %{public}d",
                        static_cast<int32_t>(ret));
                }
            }
            return;
        }
        if (!rootNode->GetChildren().empty()) {
            return;
        }
        auto focusHub = rootNode->GetFocusHub();
        CHECK_NULL_VOID(focusHub);
        focusHub->SetIsDefaultHasFocused(false);
    } else {
        auto context = DynamicCast<PipelineContext>(aceContainer->GetPipelineContext());
        CHECK_NULL_VOID(context);
        auto rootNode = context->GetRootElement();
        CHECK_NULL_VOID(rootNode);
        rootNode->SetIsDefaultHasFocused(false);
    }
#endif
    if (!window_->IsFocused()) {
        ContainerModalUnFocus();
    }
    OHOS::Rosen::WMError ret = window_->Hide();
    auto parentContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    CHECK_NULL_VOID(parentContainer);
    if (parentContainer->IsScenceBoardWindow()) {
        window_->SetTouchable(true);
    }

    if (ret != OHOS::Rosen::WMError::WM_OK) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Hide window failed with errCode: %{public}d", static_cast<int32_t>(ret));
        return;
    }
    isShowed_ = false;
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "Hide the subwindow successfully.");
#ifndef NG_BUILD
    auto context = aceContainer->GetPipelineContext();
    CHECK_NULL_VOID(context);
#endif
    AccessibilityEvent event;
    event.type = AccessibilityEventType::PAGE_CHANGE;
    event.windowId = context->GetWindowId();
    event.windowChangeTypes = WINDOW_UPDATE_REMOVED;
    context->SendEventToAccessibility(event);
}

void SubwindowOhos::ContainerModalUnFocus()
{
    auto parentContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    CHECK_NULL_VOID(parentContainer);
    auto parentWindowName = parentContainer->GetWindowName();
    sptr<OHOS::Rosen::Window> parentWindow = OHOS::Rosen::Window::Find(parentWindowName);
    CHECK_NULL_VOID(parentWindow);
    if (parentWindow->GetFocusable() && !parentWindow->IsFocused()) {
        auto pipelineContext = parentContainer->GetPipelineContext();
        CHECK_NULL_VOID(pipelineContext);
        pipelineContext->ContainerModalUnFocus();
    }
}

void SubwindowOhos::AddMenu(const RefPtr<Component>& newComponent)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "add menu enter");
#ifndef NG_BUILD
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "Subwindow push new component start.");
    auto stack = GetStack();
    CHECK_NULL_VOID(stack);
    // Push the component
    stack->PopMenu();
    stack->PushComponent(newComponent);
    popup_ = AceType::DynamicCast<SelectPopupComponent>(newComponent);
#endif
}

void SubwindowOhos::ClearMenu()
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "clear menu enter");
    if (haveDialog_) {
        return;
    }
#ifndef NG_BUILD
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "Subwindow Clear menu start.");
    auto stack = GetStack();
    CHECK_NULL_VOID(stack);
    // Pop the component
    stack->PopMenu();
    auto context = stack->GetContext().Upgrade();
    CHECK_NULL_VOID(context);
    context->FlushPipelineImmediately();
    HideWindow();
#endif
}

bool SubwindowOhos::ShowPreviewNG()
{
    CHECK_NULL_RETURN(window_, false);
    ShowWindow(false);
    ResizeWindow();
    window_->SetTouchable(false);
    return true;
}

void SubwindowOhos::HidePreviewNG()
{
    auto overlayManager = GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    overlayManager->RemovePixelMap();
    overlayManager->RemovePreviewBadgeNode();
    overlayManager->RemoveGatherNode();
    overlayManager->RemoveEventColumn();
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto pipeline = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(pipeline);
    pipeline->FlushPipelineImmediately();
    HideSubWindowNG();
}

void SubwindowOhos::ShowMenuNG(const RefPtr<NG::FrameNode> customNode, const NG::MenuParam& menuParam,
    const RefPtr<NG::FrameNode>& targetNode, const NG::OffsetF& offset)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show menu ng enter");
    CHECK_NULL_VOID(customNode);
    CHECK_NULL_VOID(targetNode);
    ContainerScope scope(childContainerId_);
    auto container = Container::Current();
    CHECK_NULL_VOID(container);
    auto context = DynamicCast<NG::PipelineContext>(container->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    auto menuNode = customNode;
    if (customNode->GetTag() != V2::MENU_WRAPPER_ETS_TAG) {
        menuNode = NG::MenuView::Create(customNode, targetNode->GetId(), targetNode->GetTag(), menuParam, true);
        auto menuWrapperPattern = menuNode->GetPattern<NG::MenuWrapperPattern>();
        CHECK_NULL_VOID(menuWrapperPattern);
        menuWrapperPattern->RegisterMenuCallback(menuNode, menuParam);
        menuWrapperPattern->SetMenuTransitionEffect(menuNode, menuParam);
    }
    ShowWindow();
    ResizeWindow();
    window_->SetTouchable(true);
    overlay->ShowMenuInSubWindow(targetNode->GetId(), offset, menuNode);
}

void SubwindowOhos::ShowMenuNG(std::function<void()>&& buildFunc, std::function<void()>&& previewBuildFunc,
    const NG::MenuParam& menuParam, const RefPtr<NG::FrameNode>& targetNode, const NG::OffsetF& offset)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show menu ng enter");
    ContainerScope scope(childContainerId_);
    auto container = Container::Current();
    CHECK_NULL_VOID(container);
    auto context = DynamicCast<NG::PipelineContext>(container->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    ShowWindow();
    ResizeWindow();
    window_->SetTouchable(true);
    NG::ScopedViewStackProcessor builderViewStackProcessor;
    buildFunc();
    auto customNode = NG::ViewStackProcessor::GetInstance()->Finish();
    RefPtr<NG::UINode> previewCustomNode;
    if (previewBuildFunc && menuParam.previewMode == MenuPreviewMode::CUSTOM) {
        previewBuildFunc();
        previewCustomNode = NG::ViewStackProcessor::GetInstance()->Finish();
    }
    auto menuNode =
        NG::MenuView::Create(customNode, targetNode->GetId(), targetNode->GetTag(), menuParam, true, previewCustomNode);
    auto menuWrapperPattern = menuNode->GetPattern<NG::MenuWrapperPattern>();
    CHECK_NULL_VOID(menuWrapperPattern);
    menuWrapperPattern->RegisterMenuCallback(menuNode, menuParam);
    menuWrapperPattern->SetMenuTransitionEffect(menuNode, menuParam);
    overlay->ShowMenuInSubWindow(targetNode->GetId(), offset, menuNode);
}

void SubwindowOhos::HideMenuNG(bool showPreviewAnimation, bool startDrag)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "hide menu ng enter");
    if (!isShowed_) {
        return;
    }
    ContainerScope scope(childContainerId_);
    auto container = Container::Current();
    CHECK_NULL_VOID(container);
    auto context = DynamicCast<NG::PipelineContext>(container->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    overlay->HideMenuInSubWindow(showPreviewAnimation, startDrag);
    HideEventColumn();
    HidePixelMap(startDrag, 0, 0, false);
    HideFilter(false);
    HideFilter(true);
}

void SubwindowOhos::HideMenuNG(const RefPtr<NG::FrameNode>& menu, int32_t targetId)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "hide menu ng enter");
    if (!isShowed_) {
        return;
    }
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "Subwindow hide menu for target id %{public}d", targetId);
    targetId_ = targetId;
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    overlay->HideMenuInSubWindow(menu, targetId_);
    HideEventColumn();
    HidePixelMap(false, 0, 0, false);
    HideFilter(false);
    HideFilter(true);
}

void SubwindowOhos::UpdateHideMenuOffsetNG(const NG::OffsetF& offset)
{
    ContainerScope scope(childContainerId_);
    auto pipelineContext = NG::PipelineContext::GetCurrentContext();
    CHECK_NULL_VOID(pipelineContext);
    auto overlay = pipelineContext->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    if (overlay->IsContextMenuDragHideFinished()) {
        return;
    }
    overlay->UpdateContextMenuDisappearPosition(offset);
}

void SubwindowOhos::ClearMenuNG(int32_t targetId, bool inWindow, bool showAnimation)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "clear menu ng enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    if (showAnimation) {
        overlay->CleanMenuInSubWindowWithAnimation();
        HideFilter(true);
    } else {
        overlay->CleanMenuInSubWindow(targetId);
        overlay->RemoveFilter();
    }
    overlay->EraseMenuInfo(targetId);
    HideWindow();
    context->FlushPipelineImmediately();
    if (inWindow) {
        HideEventColumn();
    }
    HidePixelMap(false, 0, 0, false);
    HideFilter(false);
}

void SubwindowOhos::ClearPopupNG()
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "clear popup ng enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    overlay->CleanPopupInSubWindow();
    HideWindow();
    context->FlushPipelineImmediately();
}

void SubwindowOhos::ShowMenu(const RefPtr<Component>& newComponent)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show menu enter");
    ShowWindow();
    AddMenu(newComponent);
}

void SubwindowOhos::CloseMenu()
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "close menu enter");
#ifndef NG_BUILD
    if (!isShowed_) {
        return;
    }
    if (popup_) {
        popup_->CloseContextMenu();
    }
#endif
}

RefPtr<StackElement> SubwindowOhos::GetStack()
{
#ifndef NG_BUILD
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_RETURN(aceContainer, nullptr);

    auto context = DynamicCast<PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_RETURN(context, nullptr);
    return context->GetLastStack();
#else
    return nullptr;
#endif
}

void SubwindowOhos::DeleteHotAreas(int32_t nodeId)
{
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "delete hot area %{public}d", nodeId);
    hotAreasMap_.erase(nodeId);
    std::vector<Rosen::Rect> hotAreas;
    for (auto it = hotAreasMap_.begin(); it != hotAreasMap_.end(); it++) {
        hotAreas.insert(hotAreas.end(), it->second.begin(), it->second.end());
    }
    window_->SetTouchHotAreas(hotAreas);
}

void SubwindowOhos::SetHotAreas(const std::vector<Rect>& rects, int32_t nodeId)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "set hot areas enter");
    CHECK_NULL_VOID(window_);

    std::vector<Rosen::Rect> hotAreas;
    Rosen::Rect rosenRect {};
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "set hot area %{public}d", nodeId);
    for (const auto& rect : rects) {
        TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "set hot area rect %{public}s", rect.ToString().c_str());
        RectConverter(rect, rosenRect);
        hotAreas.emplace_back(rosenRect);
    }
    if (nodeId >= 0) {
        hotAreasMap_[nodeId] = hotAreas;
    }

    std::vector<Rosen::Rect> hotAreasNow;
    for (auto it = hotAreasMap_.begin(); it != hotAreasMap_.end(); it++) {
        hotAreasNow.insert(hotAreasNow.end(), it->second.begin(), it->second.end());
    }
    window_->SetTouchHotAreas(hotAreasNow);
}

void SubwindowOhos::RectConverter(const Rect& rect, Rosen::Rect& rosenRect)
{
    rosenRect.posX_ = static_cast<int>(rect.GetOffset().GetX());
    rosenRect.posY_ = static_cast<int>(rect.GetOffset().GetY());
    rosenRect.width_ = static_cast<uint32_t>(rect.GetSize().Width());
    rosenRect.height_ = static_cast<uint32_t>(rect.GetSize().Height());
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW,
        "Convert rect to rosenRect, x is %{public}d, y is %{public}d, width is %{public}d, height is %{public}d",
        rosenRect.posX_, rosenRect.posY_, rosenRect.width_, rosenRect.height_);
}

RefPtr<NG::FrameNode> SubwindowOhos::ShowDialogNG(
    const DialogProperties& dialogProps, std::function<void()>&& buildFunc)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show dialog ng enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_RETURN(aceContainer, nullptr);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_RETURN(context, nullptr);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_RETURN(overlay, nullptr);
    std::map<int32_t, RefPtr<NG::FrameNode>> DialogMap(overlay->GetDialogMap().begin(), overlay->GetDialogMap().end());
    int dialogMapSize = static_cast<int>(DialogMap.size());
    if (dialogMapSize == 0) {
        auto parentAceContainer = Platform::AceContainer::GetContainer(parentContainerId_);
        CHECK_NULL_RETURN(parentAceContainer, nullptr);
        auto parentcontext = DynamicCast<NG::PipelineContext>(parentAceContainer->GetPipelineContext());
        CHECK_NULL_RETURN(parentcontext, nullptr);
        auto parentOverlay = parentcontext->GetOverlayManager();
        CHECK_NULL_RETURN(parentOverlay, nullptr);
        parentOverlay->SetSubWindowId(SubwindowManager::GetInstance()->GetDialogSubwindowInstanceId(GetSubwindowId()));
    }
    SubwindowManager::GetInstance()->SetDialogSubWindowId(
        SubwindowManager::GetInstance()->GetDialogSubwindowInstanceId(GetSubwindowId()));
    ShowWindow();
    window_->SetFullScreen(true);
    window_->SetTouchable(true);
    ResizeWindow();
    ContainerScope scope(childContainerId_);
    auto dialog = overlay->ShowDialog(dialogProps, std::move(buildFunc));
    CHECK_NULL_RETURN(dialog, nullptr);
    haveDialog_ = true;
    return dialog;
}

RefPtr<NG::FrameNode> SubwindowOhos::ShowDialogNGWithNode(
    const DialogProperties& dialogProps, const RefPtr<NG::UINode>& customNode)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show dialog ng enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_RETURN(aceContainer, nullptr);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_RETURN(context, nullptr);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_RETURN(overlay, nullptr);
    std::map<int32_t, RefPtr<NG::FrameNode>> DialogMap(overlay->GetDialogMap().begin(), overlay->GetDialogMap().end());
    int dialogMapSize = static_cast<int>(DialogMap.size());
    if (dialogMapSize == 0) {
        auto parentAceContainer = Platform::AceContainer::GetContainer(parentContainerId_);
        CHECK_NULL_RETURN(parentAceContainer, nullptr);
        auto parentcontext = DynamicCast<NG::PipelineContext>(parentAceContainer->GetPipelineContext());
        CHECK_NULL_RETURN(parentcontext, nullptr);
        auto parentOverlay = parentcontext->GetOverlayManager();
        CHECK_NULL_RETURN(parentOverlay, nullptr);
        parentOverlay->SetSubWindowId(SubwindowManager::GetInstance()->GetDialogSubwindowInstanceId(GetSubwindowId()));
    }
    SubwindowManager::GetInstance()->SetDialogSubWindowId(
        SubwindowManager::GetInstance()->GetDialogSubwindowInstanceId(GetSubwindowId()));
    ShowWindow();
    window_->SetFullScreen(true);
    window_->SetTouchable(true);
    ResizeWindow();
    ContainerScope scope(childContainerId_);
    auto dialog = overlay->ShowDialogWithNode(dialogProps, customNode);
    CHECK_NULL_RETURN(dialog, nullptr);
    haveDialog_ = true;
    return dialog;
}

void SubwindowOhos::CloseDialogNG(const RefPtr<NG::FrameNode>& dialogNode)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "close dialog ng enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    ContainerScope scope(childContainerId_);
    return overlay->CloseDialog(dialogNode);
}

void SubwindowOhos::OpenCustomDialogNG(const DialogProperties& dialogProps, std::function<void(int32_t)>&& callback)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "open customDialog ng subwindow enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    std::map<int32_t, RefPtr<NG::FrameNode>> DialogMap(overlay->GetDialogMap().begin(), overlay->GetDialogMap().end());
    int dialogMapSize = static_cast<int>(DialogMap.size());
    if (dialogMapSize == 0) {
        auto parentAceContainer = Platform::AceContainer::GetContainer(parentContainerId_);
        CHECK_NULL_VOID(parentAceContainer);
        auto parentcontext = DynamicCast<NG::PipelineContext>(parentAceContainer->GetPipelineContext());
        CHECK_NULL_VOID(parentcontext);
        auto parentOverlay = parentcontext->GetOverlayManager();
        CHECK_NULL_VOID(parentOverlay);
        parentOverlay->SetSubWindowId(SubwindowManager::GetInstance()->GetDialogSubwindowInstanceId(GetSubwindowId()));
        TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "overlay in parent container %{public}d, SetSubWindowId %{public}d",
            parentContainerId_, GetSubwindowId());
    }
    SubwindowManager::GetInstance()->SetDialogSubWindowId(
        SubwindowManager::GetInstance()->GetDialogSubwindowInstanceId(GetSubwindowId()));
    ShowWindow();
    window_->SetFullScreen(true);
    window_->SetTouchable(true);
    ResizeWindow();
    ContainerScope scope(childContainerId_);
    overlay->OpenCustomDialog(dialogProps, std::move(callback));
    haveDialog_ = true;
}

void SubwindowOhos::CloseCustomDialogNG(int32_t dialogId)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "close customDialog ng subwindow enter, child container id %{public}d",
        childContainerId_);
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    ContainerScope scope(childContainerId_);
    return overlay->CloseCustomDialog(dialogId);
}

void SubwindowOhos::CloseCustomDialogNG(const WeakPtr<NG::UINode>& node, std::function<void(int32_t)>&& callback)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "close customDialog ng subwindow enter, child container id %{public}d",
        childContainerId_);
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    ContainerScope scope(childContainerId_);
    return overlay->CloseCustomDialog(node, std::move(callback));
}

void SubwindowOhos::UpdateCustomDialogNG(
    const WeakPtr<NG::UINode>& node, const DialogProperties& dialogProps, std::function<void(int32_t)>&& callback)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "update customDialog ng subwindow enter");
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    ContainerScope scope(childContainerId_);
    return overlay->UpdateCustomDialog(node, dialogProps, std::move(callback));
}

void SubwindowOhos::HideSubWindowNG()
{
    ContainerScope scope(childContainerId_);
    auto container = Container::Current();
    CHECK_NULL_VOID(container);
    if (container->IsDialogContainer()) {
        if (IsToastWindow()) {
            Platform::DialogContainer::HideWindow(Container::CurrentId());
        } else {
            Platform::DialogContainer::CloseWindow(Container::CurrentId());
            Platform::DialogContainer::DestroyContainer(Container::CurrentId());
        }
    } else {
        HideWindow();
    }
}

void SubwindowOhos::GetToastDialogWindowProperty(
    int32_t& width, int32_t& height, int32_t& posX, int32_t& posY, float& density) const
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "get toast dialog window property enter");
    auto defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (defaultDisplay) {
        posX = 0;
        posY = 0;
        width = defaultDisplay->GetWidth();
        height = defaultDisplay->GetHeight();
        density = defaultDisplay->GetVirtualPixelRatio();
    }
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW,
        "Toast posX: %{public}d, posY: %{public}d, width: %{public}d, height: %{public}d, density: %{public}f", posX,
        posY, width, height, density);
}

bool SubwindowOhos::InitToastDialogWindow(int32_t width, int32_t height, int32_t posX, int32_t posY, bool isToast)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "init toast dialog window enter");
    OHOS::sptr<OHOS::Rosen::WindowOption> windowOption = new OHOS::Rosen::WindowOption();
    if (isToast) {
        windowOption->SetWindowType(Rosen::WindowType::WINDOW_TYPE_TOAST);
    } else {
        windowOption->SetWindowType(Rosen::WindowType::WINDOW_TYPE_APP_MAIN_WINDOW);
    }
    windowOption->SetWindowRect({ posX, posY, width, height });
    windowOption->SetWindowMode(Rosen::WindowMode::WINDOW_MODE_FULLSCREEN);
    windowOption->SetFocusable(!isToast);
    int32_t dialogId = gToastDialogId.fetch_add(1, std::memory_order_relaxed);
    std::string windowName = "ARK_APP_SUBWINDOW_TOAST_DIALOG_" + std::to_string(dialogId);
    dialogWindow_ = OHOS::Rosen::Window::Create(windowName, windowOption);
    CHECK_NULL_RETURN(dialogWindow_, false);
    dialogWindow_->SetLayoutFullScreen(true);
    return true;
}

bool SubwindowOhos::InitToastDialogView(int32_t width, int32_t height, float density)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "init toast dialog view enter");
#ifndef NG_BUILD
    dialogWindow_->NapiSetUIContent("", nullptr, nullptr, false);
    childContainerId_ = SubwindowManager::GetInstance()->GetContainerId(dialogWindow_->GetWindowId());
    SubwindowManager::GetInstance()->AddParentContainerId(childContainerId_, parentContainerId_);
    ContainerScope scope(childContainerId_);

    auto container = Platform::DialogContainer::GetContainer(childContainerId_);
    CHECK_NULL_RETURN(container, false);
    // create ace_view
    auto* aceView = Platform::AceViewOhos::CreateView(childContainerId_, true, true);
    Platform::AceViewOhos::SurfaceCreated(aceView, dialogWindow_);
    // set view
    Platform::DialogContainer::SetView(aceView, density, width, height, dialogWindow_);
    Ace::Platform::DialogContainer::SetUIWindow(childContainerId_, dialogWindow_);
    ViewportConfig config(width, height, density);
    Platform::AceViewOhos::SetViewportMetrics(aceView, config);
    Platform::AceViewOhos::SurfaceChanged(aceView, width, height, 0);

#ifdef ENABLE_ROSEN_BACKEND
    if (SystemProperties::GetRosenBackendEnabled()) {
        rsUiDirector = OHOS::Rosen::RSUIDirector::Create();
        if (rsUiDirector != nullptr) {
            rsUiDirector->SetRSSurfaceNode(dialogWindow_->GetSurfaceNode());
            auto context = DynamicCast<PipelineContext>(container->GetPipelineContext());
            if (context != nullptr) {
                context->SetRSUIDirector(rsUiDirector);
            }
            rsUiDirector->Init();
        }
    }
#endif

    auto pipelineContext = container->GetPipelineContext();
    CHECK_NULL_RETURN(pipelineContext, false);
    pipelineContext->SetupRootElement();
    auto parentContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    if (parentContainer) {
        auto parentPipeline = parentContainer->GetPipelineContext();
        CHECK_NULL_RETURN(parentPipeline, false);
        pipelineContext->SetMinPlatformVersion(parentPipeline->GetMinPlatformVersion());
    } else {
        pipelineContext->SetMinPlatformVersion(PLATFORM_VERSION_TEN);
    }
    return true;
#else
    return true;
#endif
}

bool SubwindowOhos::CreateEventRunner()
{
    if (!eventLoop_) {
        eventLoop_ = AppExecFwk::EventRunner::Create("Subwindow_Toast_Dialog");
        CHECK_NULL_RETURN(eventLoop_, false);
        handler_ = std::make_shared<AppExecFwk::EventHandler>(eventLoop_);
        CHECK_NULL_RETURN(handler_, false);
    }
    return true;
}

void SubwindowOhos::ClearToast()
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "clear toast enter");
    if (!IsToastWindow()) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "default toast needs not to be clear");
        return;
    }
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlayManager = context->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);
    ContainerScope scope(childContainerId_);
    overlayManager->ClearToast();
    context->FlushPipelineImmediately();
    HideWindow();
}

void SubwindowOhos::ShowToastForAbility(const std::string& message, int32_t duration, const std::string& bottom,
    const NG::ToastShowMode& showMode, int32_t alignment, std::optional<DimensionOffset> offset)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show toast for ability enter, containerId : %{public}d", childContainerId_);
    SubwindowManager::GetInstance()->SetCurrentSubwindow(AceType::Claim(this));
    SetIsToastWindow(showMode == NG::ToastShowMode::TOP_MOST);
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    if (!aceContainer) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get container failed, child containerId : %{public}d", childContainerId_);
        return;
    }

    auto engine = EngineHelper::GetEngine(aceContainer->GetInstanceId());
    auto delegate = engine->GetFrontend();
    if (!delegate) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get frontend failed, child containerId : %{public}d", childContainerId_);
        return;
    }
    ContainerScope scope(childContainerId_);
    auto parentContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    CHECK_NULL_VOID(parentContainer);
    if (parentContainer->IsScenceBoardWindow() || showMode == NG::ToastShowMode::TOP_MOST) {
        ShowWindow(false);
        ResizeWindow();
        window_->SetTouchable(false);
    }
    delegate->ShowToast(message, duration, bottom, showMode, alignment, offset);
}

void SubwindowOhos::ShowToastForService(const std::string& message, int32_t duration, const std::string& bottom,
    const NG::ToastShowMode& showMode, int32_t alignment, std::optional<DimensionOffset> offset)
{
    bool ret = CreateEventRunner();
    if (!ret) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create event runner failed");
        return;
    }

    SubwindowManager::GetInstance()->SetCurrentDialogSubwindow(AceType::Claim(this));
    auto showDialogCallback = [message, duration, bottom]() {
        int32_t posX = 0;
        int32_t posY = 0;
        int32_t width = 0;
        int32_t height = 0;
        float density = 1.0f;
        auto subwindowOhos =
            AceType::DynamicCast<SubwindowOhos>(SubwindowManager::GetInstance()->GetCurrentDialogWindow());
        CHECK_NULL_VOID(subwindowOhos);
        subwindowOhos->GetToastDialogWindowProperty(width, height, posX, posY, density);
        auto childContainerId = subwindowOhos->GetChildContainerId();
        auto window = Platform::DialogContainer::GetUIWindow(childContainerId);
        auto dialogWindow = subwindowOhos->GetDialogWindow();
        if (!dialogWindow || !window || !subwindowOhos->IsToastWindow()) {
            bool ret = subwindowOhos->InitToastDialogWindow(width, height, posX, posY, true);
            if (!ret) {
                TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "init toast dialog window failed");
                return;
            }
            ret = subwindowOhos->InitToastDialogView(width, height, density);
            if (!ret) {
                TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "init toast dialog view failed");
                return;
            }
            subwindowOhos->SetIsToastWindow(true);
        }
        childContainerId = subwindowOhos->GetChildContainerId();
        ContainerScope scope(childContainerId);
        subwindowOhos->UpdateAceView(width, height, density, childContainerId);
        TAG_LOGD(AceLogTag::ACE_SUB_WINDOW,
            "update ace view width : %{public}d,  height : %{public}d, density : %{public}f,childContainerId : "
            "%{public}d",
            width, height, density, childContainerId);

        Platform::DialogContainer::ShowToastDialogWindow(childContainerId, posX, posY, width, height, true);
        Platform::DialogContainer::ShowToast(childContainerId, message, duration, bottom);
    };
    if (!handler_->PostTask(showDialogCallback)) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create show dialog callback failed");
        return;
    }
}

void SubwindowOhos::ShowToast(const std::string& message, int32_t duration, const std::string& bottom,
    const NG::ToastShowMode& showMode, int32_t alignment, std::optional<DimensionOffset> offset)
{
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "show toast, window parent id is %{public}d", parentContainerId_);
    if (parentContainerId_ >= MIN_PA_SERVICE_ID || parentContainerId_ < 0) {
        ShowToastForService(message, duration, bottom, showMode, alignment, offset);
    } else {
        ShowToastForAbility(message, duration, bottom, showMode, alignment, offset);
    }
}

void SubwindowOhos::ShowDialogForAbility(const std::string& title, const std::string& message,
    const std::vector<ButtonInfo>& buttons, bool autoCancel, std::function<void(int32_t, int32_t)>&& callback,
    const std::set<std::string>& callbacks)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show dialog for ability enter");
    SubwindowManager::GetInstance()->SetCurrentSubwindow(AceType::Claim(this));

    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    if (!aceContainer) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get container failed, child containerId : %{public}d", childContainerId_);
        return;
    }

    auto engine = EngineHelper::GetEngine(aceContainer->GetInstanceId());
    auto delegate = engine->GetFrontend();
    if (!delegate) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get frontend failed, child containerId : %{public}d", childContainerId_);
        return;
    }
    delegate->ShowDialog(title, message, buttons, autoCancel, std::move(callback), callbacks);
}

void SubwindowOhos::ShowDialogForService(const std::string& title, const std::string& message,
    const std::vector<ButtonInfo>& buttons, bool autoCancel, std::function<void(int32_t, int32_t)>&& callback,
    const std::set<std::string>& callbacks)
{
    bool ret = CreateEventRunner();
    if (!ret) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create event runner failed");
        return;
    }

    SubwindowManager::GetInstance()->SetCurrentDialogSubwindow(AceType::Claim(this));
    auto showDialogCallback = [title, message, &buttons, autoCancel, callbackParam = std::move(callback),
                                  &callbacks]() {
        int32_t posX = 0;
        int32_t posY = 0;
        int32_t width = 0;
        int32_t height = 0;
        float density = 1.0f;
        auto subwindowOhos =
            AceType::DynamicCast<SubwindowOhos>(SubwindowManager::GetInstance()->GetCurrentDialogWindow());
        CHECK_NULL_VOID(subwindowOhos);
        subwindowOhos->GetToastDialogWindowProperty(width, height, posX, posY, density);
        bool ret = subwindowOhos->InitToastDialogWindow(width, height, posX, posY);
        if (!ret) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "init toast dialog window failed");
            return;
        }
        ret = subwindowOhos->InitToastDialogView(width, height, density);
        if (!ret) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "init toast dialog view failed");
            return;
        }
        auto childContainerId = subwindowOhos->GetChildContainerId();
        ContainerScope scope(childContainerId);
        Platform::DialogContainer::ShowToastDialogWindow(childContainerId, posX, posY, width, height);
        Platform::DialogContainer::ShowDialog(childContainerId, title, message, buttons, autoCancel,
            std::move(const_cast<std::function<void(int32_t, int32_t)>&&>(callbackParam)), callbacks);
    };
    isToastWindow_ = false;
    if (!handler_->PostTask(showDialogCallback)) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create show dialog callback failed");
        return;
    }
}

void SubwindowOhos::ShowDialogForAbility(const PromptDialogAttr& dialogAttr, const std::vector<ButtonInfo>& buttons,
    std::function<void(int32_t, int32_t)>&& callback, const std::set<std::string>& callbacks)
{
    SubwindowManager::GetInstance()->SetCurrentSubwindow(AceType::Claim(this));

    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    if (!aceContainer) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get ace container failed");
        return;
    }

    auto engine = EngineHelper::GetEngine(aceContainer->GetInstanceId());
    auto delegate = engine->GetFrontend();
    if (!delegate) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get frontend failed");
        return;
    }
    delegate->ShowDialog(dialogAttr, buttons, std::move(callback), callbacks);
}

void SubwindowOhos::ShowDialogForService(const PromptDialogAttr& dialogAttr, const std::vector<ButtonInfo>& buttons,
    std::function<void(int32_t, int32_t)>&& callback, const std::set<std::string>& callbacks)
{
    bool ret = CreateEventRunner();
    if (!ret) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create event runner failed");
        return;
    }

    SubwindowManager::GetInstance()->SetCurrentDialogSubwindow(AceType::Claim(this));
    auto showDialogCallback = [dialogAttr, &buttons, callbackParam = std::move(callback), &callbacks]() {
        int32_t posX = 0;
        int32_t posY = 0;
        int32_t width = 0;
        int32_t height = 0;
        float density = 1.0f;
        auto subwindowOhos =
            AceType::DynamicCast<SubwindowOhos>(SubwindowManager::GetInstance()->GetCurrentDialogWindow());
        CHECK_NULL_VOID(subwindowOhos);
        subwindowOhos->GetToastDialogWindowProperty(width, height, posX, posY, density);
        bool ret = subwindowOhos->InitToastDialogWindow(width, height, posX, posY);
        if (!ret) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "init toast dialog window failed");
            return;
        }
        ret = subwindowOhos->InitToastDialogView(width, height, density);
        if (!ret) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "init toast dialog view failed");
            return;
        }
        auto childContainerId = subwindowOhos->GetChildContainerId();
        ContainerScope scope(childContainerId);
        Platform::DialogContainer::ShowToastDialogWindow(childContainerId, posX, posY, width, height);
        Platform::DialogContainer::ShowDialog(childContainerId, dialogAttr, buttons,
            std::move(const_cast<std::function<void(int32_t, int32_t)>&&>(callbackParam)), callbacks);
    };
    isToastWindow_ = false;
    if (!handler_->PostTask(showDialogCallback)) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create show dialog callback failed");
        return;
    }
}

void SubwindowOhos::ShowDialog(const std::string& title, const std::string& message,
    const std::vector<ButtonInfo>& buttons, bool autoCancel, std::function<void(int32_t, int32_t)>&& callback,
    const std::set<std::string>& callbacks)
{
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "show dialog, window parent id is %{public}d", parentContainerId_);
    if (parentContainerId_ >= MIN_PA_SERVICE_ID || parentContainerId_ < 0) {
        ShowDialogForService(title, message, buttons, autoCancel, std::move(callback), callbacks);
    } else {
        ShowDialogForAbility(title, message, buttons, autoCancel, std::move(callback), callbacks);
    }
}

void SubwindowOhos::ShowDialog(const PromptDialogAttr& dialogAttr, const std::vector<ButtonInfo>& buttons,
    std::function<void(int32_t, int32_t)>&& callback, const std::set<std::string>& callbacks)
{
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "show dialog with attr, window parent id is %{public}d", parentContainerId_);
    if (parentContainerId_ >= MIN_PA_SERVICE_ID || parentContainerId_ < 0) {
        ShowDialogForService(dialogAttr, buttons, std::move(callback), callbacks);
    } else {
        ShowDialogForAbility(dialogAttr, buttons, std::move(callback), callbacks);
    }
}

void SubwindowOhos::OpenCustomDialogForAbility(
    const PromptDialogAttr& dialogAttr, std::function<void(int32_t)>&& callback)
{
    SubwindowManager::GetInstance()->SetCurrentSubwindow(AceType::Claim(this));

    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    if (!aceContainer) {
        TAG_LOGW(
            AceLogTag::ACE_SUB_WINDOW, "open dialog fail, the container %{public}d can not find", childContainerId_);
        return;
    }

    auto engine = EngineHelper::GetEngine(aceContainer->GetInstanceId());
    auto delegate = engine->GetFrontend();
    if (!delegate) {
        return;
    }
    delegate->OpenCustomDialog(dialogAttr, std::move(callback));
}

void SubwindowOhos::OpenCustomDialogForService(
    const PromptDialogAttr& dialogAttr, std::function<void(int32_t)>&& callback)
{
    // temporary not support
    TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "temporary not support for service by promptAction with CustomBuilder");
}

void SubwindowOhos::OpenCustomDialog(const PromptDialogAttr& dialogAttr, std::function<void(int32_t)>&& callback)
{
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "open custom dialog, window parent id is %{public}d", parentContainerId_);
    if (parentContainerId_ >= MIN_PA_SERVICE_ID || parentContainerId_ < 0) {
        OpenCustomDialogForService(dialogAttr, std::move(callback));
    } else {
        OpenCustomDialogForAbility(dialogAttr, std::move(callback));
    }
}

void SubwindowOhos::CloseCustomDialog(const int32_t dialogId)
{
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    ContainerScope scope(childContainerId_);
    return overlay->CloseCustomDialog(dialogId);
}

void SubwindowOhos::CloseCustomDialog(const WeakPtr<NG::UINode>& node, std::function<void(int32_t)>&& callback)
{
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto overlay = context->GetOverlayManager();
    CHECK_NULL_VOID(overlay);
    ContainerScope scope(childContainerId_);
    return overlay->CloseCustomDialog(node, std::move(callback));
}

void SubwindowOhos::ShowActionMenuForAbility(
    const std::string& title, const std::vector<ButtonInfo>& button, std::function<void(int32_t, int32_t)>&& callback)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show action menu for ability enter");
    SubwindowManager::GetInstance()->SetCurrentSubwindow(AceType::Claim(this));

    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    if (!aceContainer) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get container failed");
        return;
    }

    auto engine = EngineHelper::GetEngine(aceContainer->GetInstanceId());
    auto delegate = engine->GetFrontend();
    if (!delegate) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "get frontend failed");
        return;
    }
    delegate->ShowActionMenu(title, button, std::move(callback));
}

void SubwindowOhos::ShowActionMenuForService(
    const std::string& title, const std::vector<ButtonInfo>& button, std::function<void(int32_t, int32_t)>&& callback)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "show action menu for service enter");
    bool ret = CreateEventRunner();
    if (!ret) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create event runner failed");
        return;
    }

    SubwindowManager::GetInstance()->SetCurrentDialogSubwindow(AceType::Claim(this));
    auto showDialogCallback = [title, &button, callbackParam = std::move(callback)]() {
        int32_t posX = 0;
        int32_t posY = 0;
        int32_t width = 0;
        int32_t height = 0;
        float density = 1.0f;
        auto subwindowOhos =
            AceType::DynamicCast<SubwindowOhos>(SubwindowManager::GetInstance()->GetCurrentDialogWindow());
        CHECK_NULL_VOID(subwindowOhos);
        subwindowOhos->GetToastDialogWindowProperty(width, height, posX, posY, density);
        bool ret = subwindowOhos->InitToastDialogWindow(width, height, posX, posY);
        if (!ret) {
            return;
        }
        ret = subwindowOhos->InitToastDialogView(width, height, density);
        if (!ret) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "init toast dialog view failed");
            return;
        }
        auto childContainerId = subwindowOhos->GetChildContainerId();
        ContainerScope scope(childContainerId);
        Platform::DialogContainer::ShowToastDialogWindow(childContainerId, posX, posY, width, height);
        Platform::DialogContainer::ShowActionMenu(childContainerId, title, button,
            std::move(const_cast<std::function<void(int32_t, int32_t)>&&>(callbackParam)));
    };
    isToastWindow_ = false;
    if (!handler_->PostTask(showDialogCallback)) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "create show dialog callback failed");
        return;
    }
}

void SubwindowOhos::CloseDialog(int32_t instanceId)
{
    TAG_LOGD(AceLogTag::ACE_SUB_WINDOW, "close dialog enter");
    Platform::DialogContainer::CloseWindow(instanceId);
}

void SubwindowOhos::UpdateAceView(int32_t width, int32_t height, float density, int32_t containerId)
{
    auto container = Platform::DialogContainer::GetContainer(containerId);
    CHECK_NULL_VOID(container);
    auto aceView = static_cast<Platform::AceViewOhos*>(container->GetView());
    CHECK_NULL_VOID(aceView);
    if (aceView->GetWidth() != width || aceView->GetHeight() != height) {
        ViewportConfig config(width, height, density);
        Platform::AceViewOhos::SetViewportMetrics(aceView, config);
        Platform::AceViewOhos::SurfaceChanged(aceView, width, height, 0);
    }
}

void SubwindowOhos::ShowActionMenu(
    const std::string& title, const std::vector<ButtonInfo>& button, std::function<void(int32_t, int32_t)>&& callback)
{
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "show custom dialog, window parent id is %{public}d", parentContainerId_);
    if (parentContainerId_ >= MIN_PA_SERVICE_ID || parentContainerId_ < 0) {
        ShowActionMenuForService(title, button, std::move(callback));
    } else {
        ShowActionMenuForAbility(title, button, std::move(callback));
    }
}

Rect SubwindowOhos::GetParentWindowRect() const
{
    Rect rect;
    CHECK_NULL_RETURN(parentWindow_, rect);
    auto parentWindowRect = parentWindow_->GetRect();
    return Rect(parentWindowRect.posX_, parentWindowRect.posY_, parentWindowRect.width_, parentWindowRect.height_);
}

Rect SubwindowOhos::GetUIExtensionHostWindowRect() const
{
    Rect rect;
    CHECK_NULL_RETURN(parentWindow_, rect);
    auto id = GetUIExtensionHostWindowId();
    auto hostWindowRect = parentWindow_->GetHostWindowRect(id);
    return Rect(hostWindowRect.posX_, hostWindowRect.posY_, hostWindowRect.width_, hostWindowRect.height_);
}

void SubwindowOhos::RequestFocus()
{
    if (window_->IsFocused()) {
        TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "subwindow id:%{public}u already focused", window_->GetWindowId());
        // already focused, no need to focus
        return;
    }
    OHOS::Rosen::WMError ret = window_->RequestFocus();
    if (ret != OHOS::Rosen::WMError::WM_OK) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "subindow id:%{public}u request focus failed with WMError: %{public}d",
            window_->GetWindowId(), static_cast<int32_t>(ret));
        return;
    }
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW, "subwindow id:%{public}u request focus successfully.", window_->GetWindowId());
}

bool SubwindowOhos::IsFocused()
{
    return window_->IsFocused();
}

void SubwindowOhos::HideFilter(bool isInSubWindow)
{
    RefPtr<Container> aceContainer = nullptr;
    if (isInSubWindow) {
        aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    } else {
        aceContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    }

    CHECK_NULL_VOID(aceContainer);
    auto pipelineContext = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(pipelineContext);
    auto overlayManager = pipelineContext->GetOverlayManager();
    CHECK_NULL_VOID(overlayManager);

    auto containerId = isInSubWindow ? childContainerId_ : parentContainerId_;
    ContainerScope scope(containerId);
    overlayManager->RemoveFilterAnimation();
}

void SubwindowOhos::HidePixelMap(bool startDrag, double x, double y, bool showAnimation)
{
    auto parentAceContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    CHECK_NULL_VOID(parentAceContainer);
    auto parentPipeline = DynamicCast<NG::PipelineContext>(parentAceContainer->GetPipelineContext());
    CHECK_NULL_VOID(parentPipeline);
    auto manager = parentPipeline->GetOverlayManager();
    CHECK_NULL_VOID(manager);
    ContainerScope scope(parentContainerId_);
    if (!startDrag) {
        manager->RemovePreviewBadgeNode();
        manager->RemoveGatherNodeWithAnimation();
    }
    if (showAnimation) {
        manager->RemovePixelMapAnimation(startDrag, x, y);
    } else {
        manager->RemovePixelMap();
    }
}

void SubwindowOhos::HideEventColumn()
{
    auto parentAceContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    CHECK_NULL_VOID(parentAceContainer);
    auto parentPipeline = DynamicCast<NG::PipelineContext>(parentAceContainer->GetPipelineContext());
    CHECK_NULL_VOID(parentPipeline);
    auto manager = parentPipeline->GetOverlayManager();
    CHECK_NULL_VOID(manager);
    ContainerScope scope(parentContainerId_);
    manager->RemoveEventColumn();
}

void SubwindowOhos::ResizeWindowForFoldStatus(int32_t parentContainerId)
{
    auto callback = []() {
        auto subwindowOhos =
            AceType::DynamicCast<SubwindowOhos>(SubwindowManager::GetInstance()->GetCurrentDialogWindow());
        CHECK_NULL_VOID(subwindowOhos);
        auto childContainerId = subwindowOhos->GetChildContainerId();
        ContainerScope scope(childContainerId);
        auto window = Platform::DialogContainer::GetUIWindow(childContainerId);
        CHECK_NULL_VOID(window);
        auto defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
        CHECK_NULL_VOID(defaultDisplay);
        auto ret = window->Resize(defaultDisplay->GetWidth(), defaultDisplay->GetHeight());
        if (ret != Rosen::WMError::WM_OK) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Resize window by default display failed with errCode: %{public}d",
                static_cast<int32_t>(ret));
            return;
        }
        auto container = Platform::DialogContainer::GetContainer(childContainerId);
        CHECK_NULL_VOID(container);
        // get ace_view
        auto aceView = static_cast<Platform::AceViewOhos*>(container->GetAceView());
        CHECK_NULL_VOID(aceView);
        Platform::AceViewOhos::SurfaceChanged(aceView, defaultDisplay->GetWidth(), defaultDisplay->GetHeight(), 0);
    };
    if (parentContainerId > 0) {
        ResizeWindowForFoldStatus();
        return;
    }
    if (!handler_->PostTask(callback)) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Resize Toast Window failed");
    }
}

void SubwindowOhos::ResizeWindowForFoldStatus()
{
    auto defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_NULL_VOID(defaultDisplay);
    auto ret = window_->Resize(defaultDisplay->GetWidth(), defaultDisplay->GetHeight());
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGW(AceLogTag::ACE_SUB_WINDOW, "Resize window by default display failed with errCode: %{public}d",
            static_cast<int32_t>(ret));
        return;
    }
    TAG_LOGI(AceLogTag::ACE_SUB_WINDOW,
        "SubwindowOhos window rect is resized to x: %{public}d, y: %{public}d, width: %{public}u, height: %{public}u",
        window_->GetRect().posX_, window_->GetRect().posY_, window_->GetRect().width_, window_->GetRect().height_);
}

void SubwindowOhos::MarkDirtyDialogSafeArea()
{
    auto aceContainer = Platform::AceContainer::GetContainer(childContainerId_);
    CHECK_NULL_VOID(aceContainer);
    auto context = DynamicCast<NG::PipelineContext>(aceContainer->GetPipelineContext());
    CHECK_NULL_VOID(context);
    auto rootNode = context->GetRootElement();
    CHECK_NULL_VOID(rootNode);
    auto lastChild = rootNode->GetLastChild();
    CHECK_NULL_VOID(lastChild);
    lastChild->MarkDirtyNode(NG::PROPERTY_UPDATE_MEASURE);
}

bool SubwindowOhos::CheckHostWindowStatus() const
{
    auto parentContainer = Platform::AceContainer::GetContainer(parentContainerId_);
    CHECK_NULL_RETURN(parentContainer, false);
    sptr<OHOS::Rosen::Window> parentWindow = parentContainer->GetUIWindow(parentContainerId_);
    CHECK_NULL_RETURN(parentWindow, false);
    if (parentWindow->GetType() == Rosen::WindowType::WINDOW_TYPE_UI_EXTENSION) {
        auto parentPipeline = parentContainer->GetPipelineContext();
        CHECK_NULL_RETURN(parentPipeline, false);
        auto hostWindowId = parentPipeline->GetFocusWindowId();
        auto hostWindowRect = parentWindow->GetHostWindowRect(hostWindowId);
        auto isValid = GreatNotEqual(hostWindowRect.width_, 0) && GreatNotEqual(hostWindowRect.height_, 0);
        if (!isValid) {
            TAG_LOGW(AceLogTag::ACE_SUB_WINDOW,
                "UIExtension Window failed to obtain host window information. Please check if permissions are enabled");
            return false;
        }
    }
    return true;
}
} // namespace OHOS::Ace
