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

#ifndef ARK_WEB_PREFERENCE_CTOCPP_H_
#define ARK_WEB_PREFERENCE_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_preference_capi.h"
#include "ohos_nweb/include/ark_web_preference.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebPreferenceCToCpp
    : public ArkWebCToCppRefCounted<ArkWebPreferenceCToCpp, ArkWebPreference, ark_web_preference_t> {
public:
    ArkWebPreferenceCToCpp();
    virtual ~ArkWebPreferenceCToCpp();

    // ArkWebPreference methods.
    ArkWebString UserAgent() override;

    void PutUserAgent(const ArkWebString& ua) override;

    ArkWebString DefaultUserAgent() override;

    int CacheMode() override;

    void PutCacheMode(int flag) override;

    bool IsNetworkBlocked() override;

    void PutBlockNetwork(bool flag) override;

    uint32_t GetScrollBarColor() override;

    void PutScrollBarColor(uint32_t color_value) override;

    int GetOverscrollMode() override;

    void PutOverscrollMode(int over_scroll_mode) override;

    int DefaultFontSize() override;

    void PutDefaultFontSize(int size) override;

    bool GetPinchSmoothMode() override;

    void PutPinchSmoothMode(bool flag) override;

    bool IsDataBaseEnabled() override;

    void PutDatabaseAllowed(bool flag) override;

    bool IsMultiWindowAccess() override;

    void PutMultiWindowAccess(bool flag) override;

    bool IsJavaScriptAllowed() override;

    void PutJavaScriptEnabled(bool flag) override;

    int DarkSchemeEnabled() override;

    void PutDarkSchemeEnabled(int dark_scheme) override;

    bool IsDomStorageEnabled() override;

    void PutDomStorageEnabled(bool flag) override;

    int FontSizeLowerLimit() override;

    void PutFontSizeLowerLimit(int size) override;

    bool GeoLocationAllowed() override;

    void PutGeoLocationAllowed(bool flag) override;

    bool IsWebDebuggingAccess() override;

    void PutWebDebuggingAccess(bool flag) override;

    bool EnableContentAccess() override;

    void PutEnableContentAccess(bool flag) override;

    bool EnableRawFileAccess() override;

    void PutEnableRawFileAccess(bool flag) override;

    bool IsImageLoadingAllowed() override;

    void PutImageLoadingAllowed(bool flag) override;

    ArkWebString FixedFontFamilyName() override;

    void PutFixedFontFamilyName(const ArkWebString& font) override;

    ArkWebString SerifFontFamilyName() override;

    void PutSerifFontFamilyName(const ArkWebString& font) override;

    int ZoomingForTextFactor() override;

    void PutZoomingForTextFactor(int text_zoom) override;

    int ForceDarkModeEnabled() override;

    void PutForceDarkModeEnabled(int force_dark) override;

    bool IsLoadWithOverviewMode() override;

    void PutLoadWithOverviewMode(bool flag) override;

    int DefaultFixedFontSize() override;

    void PutDefaultFixedFontSize(int size) override;

    ArkWebString CursiveFontFamilyName() override;

    void PutCursiveFontFamilyName(const ArkWebString& font) override;

    ArkWebString FantasyFontFamilyName() override;

    void PutFantasyFontFamilyName(const ArkWebString& font) override;

    bool ZoomingfunctionEnabled() override;

    void PutZoomingFunctionEnabled(bool flag) override;

    bool GetMediaPlayGestureAccess() override;

    void PutMediaPlayGestureAccess(bool flag) override;

    ArkWebString StandardFontFamilyName() override;

    void PutStandardFontFamilyName(const ArkWebString& font) override;

    ArkWebString SansSerifFontFamilyName() override;

    void PutSansSerifFontFamilyName(const ArkWebString& font) override;

    bool IsVerticalScrollBarAccess() override;

    void PutVerticalScrollBarAccess(bool flag) override;

    bool IsHorizontalScrollBarAccess() override;

    void PutHorizontalScrollBarAccess(bool flag) override;

    int LogicalFontSizeLowerLimit() override;

    void PutLogicalFontSizeLowerLimit(int size) override;

    ArkWebString DefaultTextEncodingFormat() override;

    void PutDefaultTextEncodingFormat(const ArkWebString& encoding) override;

    bool IsLoadImageFromNetworkDisabled() override;

    void PutLoadImageFromNetworkDisabled(bool flag) override;

    bool EnableRawFileAccessFromFileURLs() override;

    void PutEnableRawFileAccessFromFileURLs(bool flag) override;

    bool EnableUniversalAccessFromFileURLs() override;

    void PutEnableUniversalAccessFromFileURLs(bool flag) override;

    bool IsCreateWindowsByJavaScriptAllowed() override;

    void PutIsCreateWindowsByJavaScriptAllowed(bool flag) override;

    int AccessModeForSecureOriginLoadFromInsecure() override;

    void PutAccessModeForSecureOriginLoadFromInsecure(int mode) override;

    int GetCopyOptionMode() override;

    void PutCopyOptionMode(int copyOption) override;

    void SetNativeEmbedMode(bool flag) override;

    bool GetNativeEmbedMode() override;

    void RegisterNativeEmbedRule(const ArkWebString& tag, const ArkWebString& type) override;

    void SetScrollable(bool enable) override;

    bool GetScrollable() override;

    void PutTextAutosizingEnabled(bool flag) override;

    void SetViewportEnable(bool enable) override;

    void SetNativeVideoPlayerConfig(bool enable, bool shouldOverlay) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_PREFERENCE_CTOCPP_H_
