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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_OVERLAY_SHEET_VIEW_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_OVERLAY_SHEET_VIEW_H

#include "base/memory/ace_type.h"
#include "base/memory/referenced.h"
#include "core/components_ng/base/frame_node.h"
#include "core/components_ng/pattern/overlay/sheet_style.h"

namespace OHOS::Ace::NG {
class ACE_EXPORT SheetView {
public:
    static RefPtr<FrameNode> CreateSheetPage(int32_t targetId, std::string targetTag, RefPtr<FrameNode> builder,
        RefPtr<FrameNode> titleBuilder, std::function<void(const std::string&)>&& callback, NG::SheetStyle& sheetStyle);
    static RefPtr<FrameNode> CreateScrollNode();

private:
    static RefPtr<FrameNode> CreateOperationColumnNode(
        RefPtr<FrameNode> titleBuilder, NG::SheetStyle& sheetStyle, RefPtr<FrameNode> sheetNode);
    static void CreateCloseIconButtonNode(RefPtr<FrameNode> sheetNode, NG::SheetStyle& sheetStyle);
    static void SetSheetOffset(RefPtr<FrameNode> sheetNode);
    static RefPtr<FrameNode> BuildMainTitle(RefPtr<FrameNode> sheetNode, NG::SheetStyle& sheetStyle);
    static RefPtr<FrameNode> BuildSubTitle(RefPtr<FrameNode> sheetNode, NG::SheetStyle& sheetStyle);
    static RefPtr<FrameNode> BuildTitle(RefPtr<FrameNode> sheetNode, NG::SheetStyle& sheetStyle);
    static RefPtr<FrameNode> BuildTitleColumn(RefPtr<FrameNode> sheetNode, NG::SheetStyle& sheetStyle);
};
} // namespace OHOS::Ace::NG

#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_COMPONENTS_NG_PATTERNS_OVERLAY_SHEET_VIEW_H
