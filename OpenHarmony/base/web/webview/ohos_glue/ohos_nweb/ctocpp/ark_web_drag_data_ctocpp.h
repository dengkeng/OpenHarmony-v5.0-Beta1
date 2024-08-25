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

#ifndef ARK_WEB_DRAG_DATA_CTOCPP_H_
#define ARK_WEB_DRAG_DATA_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_drag_data_capi.h"
#include "ohos_nweb/include/ark_web_drag_data.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebDragDataCToCpp : public ArkWebCToCppRefCounted<ArkWebDragDataCToCpp, ArkWebDragData, ark_web_drag_data_t> {
public:
    ArkWebDragDataCToCpp();
    virtual ~ArkWebDragDataCToCpp();

    // ArkWebDragData methods.
    bool SetFileUri(const ArkWebString& uri) override;

    ArkWebString GetLinkURL() override;

    bool SetLinkURL(const ArkWebString& url) override;

    ArkWebString GetLinkTitle() override;

    bool SetLinkTitle(const ArkWebString& title) override;

    ArkWebString GetFragmentText() override;

    bool SetFragmentText(const ArkWebString& text) override;

    ArkWebString GetFragmentHtml() override;

    bool SetFragmentHtml(const ArkWebString& html) override;

    ArkWebString GetImageFileName() override;

    bool GetPixelMapSetting(const void** data, size_t& len, int& width, int& height) override;

    bool SetPixelMapSetting(const void* data, size_t len, int width, int height) override;

    void ClearImageFileNames() override;

    bool IsSingleImageContent() override;

    void GetDragStartPosition(int& x, int& y) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_DRAG_DATA_CTOCPP_H_
