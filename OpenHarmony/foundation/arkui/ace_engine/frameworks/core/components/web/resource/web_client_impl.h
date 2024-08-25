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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_WEB_RESOURCE_WEBVIEW_CLIENT_IMPL_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_WEB_RESOURCE_WEBVIEW_CLIENT_IMPL_H

#include "foundation/arkui/ace_engine/frameworks/base/memory/referenced.h"
#include "nweb_drag_data.h"
#include "nweb_handler.h"

#include "base/log/log.h"
#include "core/common/container_scope.h"
#include "surface_delegate.h"
#ifdef ENABLE_ROSEN_BACKEND
#include "surface.h"
#endif

namespace OHOS::Ace {
class WebDelegate;

class DownloadListenerImpl : public OHOS::NWeb::NWebDownloadCallback {
public:
    DownloadListenerImpl() = default;
    explicit DownloadListenerImpl(int32_t instanceId) : instanceId_(instanceId) {}
    ~DownloadListenerImpl() = default;

    void OnDownloadStart(const std::string& url, const std::string& userAgent, const std::string& contentDisposition,
        const std::string& mimetype, long contentLength) override;

    void SetWebDelegate(const WeakPtr<WebDelegate>& delegate)
    {
        webDelegate_ = delegate;
    }

private:
    WeakPtr<WebDelegate> webDelegate_;
    int32_t instanceId_ = -1;
};

class AccessibilityEventListenerImpl : public OHOS::NWeb::NWebAccessibilityEventCallback {
public:
    AccessibilityEventListenerImpl() = default;
    explicit AccessibilityEventListenerImpl(int32_t instanceId) : instanceId_(instanceId) {}
    ~AccessibilityEventListenerImpl() = default;

    void OnAccessibilityEvent(int64_t accessibilityId, uint32_t eventType) override;

    void SetWebDelegate(const WeakPtr<WebDelegate>& delegate)
    {
        webDelegate_ = delegate;
    }

private:
    WeakPtr<WebDelegate> webDelegate_;
    int32_t instanceId_ = -1;
};

class ReleaseSurfaceImpl : public OHOS::NWeb::NWebReleaseSurfaceCallback {
public:
    ReleaseSurfaceImpl() = default;
    explicit ReleaseSurfaceImpl(int32_t instanceId) : instanceId_(instanceId) {}
    ~ReleaseSurfaceImpl() = default;

    void ReleaseSurface() override;

    void SetSurfaceDelegate(const sptr<OHOS::SurfaceDelegate> &surfaceDelegate)
    {
        surfaceDelegate_ = surfaceDelegate;
    }

private:
    sptr<OHOS::SurfaceDelegate> surfaceDelegate_ = nullptr;
    int32_t instanceId_ = -1;
};
class FindListenerImpl : public OHOS::NWeb::NWebFindCallback {
public:
    FindListenerImpl() = default;
    explicit FindListenerImpl(int32_t instanceId) : instanceId_(instanceId) {}
    ~FindListenerImpl() = default;

    void OnFindResultReceived(
        const int activeMatchOrdinal, const int numberOfMatches, const bool isDoneCounting) override;

    void SetWebDelegate(const WeakPtr<WebDelegate>& delegate)
    {
        webDelegate_ = delegate;
    }

private:
    WeakPtr<WebDelegate> webDelegate_;
    int32_t instanceId_ = -1;
};

class WebClientImpl :
    public std::enable_shared_from_this<WebClientImpl>,
    public OHOS::NWeb::NWebHandler {
public:
    WebClientImpl() = default;
    explicit WebClientImpl(int32_t instanceId) : instanceId_(instanceId) {}
    ~WebClientImpl() = default;

    void SetNWeb(std::shared_ptr<OHOS::NWeb::NWeb> nweb) override;
    void OnProxyDied() override;
    void OnRouterPush(const std::string& param) override;
    bool OnConsoleLog(std::shared_ptr<OHOS::NWeb::NWebConsoleLog> message) override;
    void OnMessage(const std::string& param) override;
    void OnPageLoadBegin(const std::string& url) override;
    void OnPageLoadEnd(int httpStatusCode, const std::string& url) override;
    void OnLoadingProgress(int newProgress) override;
    void OnPageTitle(const std::string &title) override;
    void OnGeolocationHide() override;
    void OnFullScreenExit() override;
    void OnFullScreenEnter(std::shared_ptr<NWeb::NWebFullScreenExitHandler> handler) override;
    void OnFullScreenEnterWithVideoSize(std::shared_ptr<NWeb::NWebFullScreenExitHandler> handler,
        int videoNaturalWidth, int videoNaturalHeight) override;
    void OnGeolocationShow(const std::string& origin,
        std::shared_ptr<OHOS::NWeb::NWebGeolocationCallbackInterface> callback) override;

    bool OnAlertDialogByJS(const std::string &url,
                           const std::string &message,
                           std::shared_ptr<NWeb::NWebJSDialogResult> result) override;
    bool OnBeforeUnloadByJS(const std::string &url,
                            const std::string &message,
                            std::shared_ptr<NWeb::NWebJSDialogResult> result) override;
    bool OnConfirmDialogByJS(const std::string &url,
                             const std::string &message,
                             std::shared_ptr<NWeb::NWebJSDialogResult> result) override;
    bool OnPromptDialogByJS(const std::string &url,
                             const std::string &message,
                             const std::string &defaultValue,
                             std::shared_ptr<NWeb::NWebJSDialogResult> result) override;
    bool OnFileSelectorShow(std::shared_ptr<NWeb::NWebStringVectorValueCallback> callback,
                            std::shared_ptr<NWeb::NWebFileSelectorParams> params) override;

    bool OnFocus() override;
    void OnResourceLoadError(std::shared_ptr<OHOS::NWeb::NWebUrlResourceRequest> request,
        std::shared_ptr<OHOS::NWeb::NWebUrlResourceError> error) override;
    void OnHttpError(std::shared_ptr<OHOS::NWeb::NWebUrlResourceRequest> request,
        std::shared_ptr<OHOS::NWeb::NWebUrlResourceResponse> response) override;
    void OnRenderExited(OHOS::NWeb::RenderExitReason reason) override;
    void OnRefreshAccessedHistory(const std::string& url, bool isReload) override;
    bool OnHandleInterceptRequest(std::shared_ptr<OHOS::NWeb::NWebUrlResourceRequest> request,
                                  std::shared_ptr<OHOS::NWeb::NWebUrlResourceResponse> response) override;
    bool OnHandleInterceptUrlLoading(std::shared_ptr<OHOS::NWeb::NWebUrlResourceRequest> request) override;
    void OnResource(const std::string& url) override;
    void OnScaleChanged(float oldScaleFactor, float newScaleFactor) override;
    void OnScroll(double xOffset, double yOffset) override;
    bool OnHttpAuthRequestByJS(std::shared_ptr<NWeb::NWebJSHttpAuthResult> result, const std::string &host,
        const std::string &realm) override;
    bool OnSslErrorRequestByJS(std::shared_ptr<NWeb::NWebJSSslErrorResult> result,
        OHOS::NWeb::SslError error) override;
    bool OnAllSslErrorRequestByJS(std::shared_ptr<NWeb::NWebJSAllSslErrorResult> result,
        OHOS::NWeb::SslError error,
        const std::string& url,
        const std::string& originalUrl,
        const std::string& referrer,
        bool isFatalError,
        bool isMainFrame) override;
    bool OnSslSelectCertRequestByJS(
        std::shared_ptr<NWeb::NWebJSSslSelectCertResult> result,
        const std::string& host,
        int32_t port,
        const std::vector<std::string>& keyTypes,
        const std::vector<std::string>& issuers) override;
    void OnPermissionRequest(std::shared_ptr<NWeb::NWebAccessRequest> request) override;
    bool RunContextMenu(std::shared_ptr<NWeb::NWebContextMenuParams> params,
        std::shared_ptr<NWeb::NWebContextMenuCallback> callback) override;
    void UpdateClippedSelectionBounds(int x, int y, int w, int h) override;
    bool RunQuickMenu(std::shared_ptr<NWeb::NWebQuickMenuParams> params,
                      std::shared_ptr<NWeb::NWebQuickMenuCallback> callback) override;
    void OnQuickMenuDismissed() override;
    void OnTouchSelectionChanged(
        std::shared_ptr<OHOS::NWeb::NWebTouchHandleState> insertHandle,
        std::shared_ptr<OHOS::NWeb::NWebTouchHandleState> startSelectionHandle,
        std::shared_ptr<OHOS::NWeb::NWebTouchHandleState> endSelectionHandle) override;
    bool OnDragAndDropData(const void* data, size_t len, std::shared_ptr<NWeb::NWebImageOptions> opt) override;
    bool OnDragAndDropDataUdmf(std::shared_ptr<NWeb::NWebDragData> dragData) override;
    void UpdateDragCursor(NWeb::NWebDragData::DragOperation op) override;
    void OnWindowNewByJS(
        const std::string& targetUrl,
        bool isAlert,
        bool isUserTrigger,
        std::shared_ptr<NWeb::NWebControllerHandler> handler) override;
    void OnWindowExitByJS() override;
    void OnPageVisible(const std::string& url) override;
    void OnDataResubmission(std::shared_ptr<NWeb::NWebDataResubmissionCallback> handler) override;
    void OnNavigationEntryCommitted(std::shared_ptr<NWeb::NWebLoadCommittedDetails> details) override;
    void OnPageIcon(
        const void* data,
        size_t width,
        size_t height,
        NWeb::ImageColorType colorType,
        NWeb::ImageAlphaType alphaType) override;
    void OnDesktopIconUrl(const std::string& icon_url, bool precomposed) override;
    bool OnCursorChange(const NWeb::CursorType& type, std::shared_ptr<NWeb::NWebCursorInfo> info) override;
    void OnSelectPopupMenu(std::shared_ptr<NWeb::NWebSelectPopupMenuParam> params,
                           std::shared_ptr<NWeb::NWebSelectPopupMenuCallback> callback) override;
    void OnAudioStateChanged(bool playing) override;
    void OnFirstContentfulPaint(int64_t navigationStartTick, int64_t firstContentfulPaintMs) override;
    void OnFirstMeaningfulPaint(std::shared_ptr<NWeb::NWebFirstMeaningfulPaintDetails> details) override;
    void OnLargestContentfulPaint(std::shared_ptr<NWeb::NWebLargestContentfulPaintDetails> details) override;
    void OnSafeBrowsingCheckResult(int threat_type) override;
    void OnCompleteSwapWithNewSize() override;
    void OnResizeNotWork() override;
    void OnGetTouchHandleHotZone(std::shared_ptr<NWeb::NWebTouchHandleHotZone> hotZone) override;
    void OnDateTimeChooserPopup(
        std::shared_ptr<NWeb::NWebDateTimeChooser> chooser,
        const std::vector<std::shared_ptr<NWeb::NWebDateTimeSuggestion>>& suggestions,
        std::shared_ptr<NWeb::NWebDateTimeChooserCallback> callback) override;
    void OnDateTimeChooserClose() override;
    void OnOverScroll(float xOffset, float yOffset) override;
    void OnScreenCaptureRequest(std::shared_ptr<NWeb::NWebScreenCaptureAccessRequest> request) override;
    void OnOverScrollFlingVelocity(float xVelocity, float yVelocity, bool isFling) override;
    void OnOverScrollFlingEnd() override;
    void OnScrollState(bool scrollState) override;
    void OnRootLayerChanged(int width, int height) override;
    void ReleaseResizeHold() override;
    bool FilterScrollEvent(const float x, const float y, const float xVelocity, const float yVelocity) override;
    void OnNativeEmbedLifecycleChange(std::shared_ptr<NWeb::NWebNativeEmbedDataInfo> dataInfo) override;
    void OnNativeEmbedGestureEvent(std::shared_ptr<NWeb::NWebNativeEmbedTouchEvent> event) override;
    void OnIntelligentTrackingPreventionResult(
        const std::string& websiteHost, const std::string& trackerHost) override;
    void OnTooltip(const std::string& tooltip) override;
    bool OnHandleOverrideUrlLoading(std::shared_ptr<OHOS::NWeb::NWebUrlResourceRequest> request) override;
    bool OnOpenAppLink(const std::string& url,
                       std::shared_ptr<OHOS::NWeb::NWebAppLinkCallback> callback) override;
    void OnShowAutofillPopup(
        const float offsetX, const float offsetY, const std::vector<std::string>& menu_items) override;
    void OnHideAutofillPopup() override;
    void SetWebDelegate(const WeakPtr<WebDelegate>& delegate)
    {
        webDelegate_ = delegate;
    }

    const RefPtr<WebDelegate> GetWebDelegate() const
    {
        return webDelegate_.Upgrade();
    }

    std::vector<int8_t> GetWordSelection(const std::string& text, int8_t offset) override;
    void OnRenderProcessNotResponding(
        const std::string& jsStack, int pid, OHOS::NWeb::RenderProcessNotRespondingReason reason) override;
    void OnRenderProcessResponding() override;

    void OnViewportFitChange(NWeb::ViewportFit viewportFit) override;
private:
    std::weak_ptr<OHOS::NWeb::NWeb> webviewWeak_;
    WeakPtr<WebDelegate> webDelegate_;
    int32_t instanceId_ = -1;
};
} // namespace OHOS::Ace

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_WEB_RESOURCE_WEBVIEW_CLIENT_IMPL_H
