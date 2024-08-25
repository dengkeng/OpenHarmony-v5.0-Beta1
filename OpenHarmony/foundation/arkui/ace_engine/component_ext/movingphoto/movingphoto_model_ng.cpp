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

#include "movingphoto_model_ng.h"
#include "movingphoto_node.h"
#include "movingphoto_layout_property.h"
#include "movingphoto_pattern.h"

#include "core/components_ng/base/view_stack_processor.h"
#include "core/components_ng/pattern/image/image_pattern.h"
#include "core/components_ng/pattern/linear_layout/linear_layout_pattern.h"

namespace OHOS::Ace::NG {

void MovingPhotoModelNG::Create(const RefPtr<MovingPhotoController>& controller)
{
    auto* stack = ViewStackProcessor::GetInstance();
    auto nodeId = stack->ClaimNodeId();
    ACE_LAYOUT_SCOPED_TRACE("Create[%s][self:%d]", V2::MOVING_PHOTO_ETS_TAG, nodeId);
    auto movingPhotoNode = MovingPhotoNode::GetOrCreateMovingPhotoNode(
        V2::MOVING_PHOTO_ETS_TAG, nodeId, [controller]() {
            return AceType::MakeRefPtr<MovingPhotoPattern>(controller);
        });
    CHECK_NULL_VOID(movingPhotoNode);
    stack->Push(movingPhotoNode);

    bool hasVideoNode = movingPhotoNode->HasVideoNode();
    if (!hasVideoNode) {
        auto videoId = movingPhotoNode->GetVideoId();
        auto videoNode = FrameNode::GetOrCreateFrameNode(
            V2::COLUMN_ETS_TAG, videoId, []() { return AceType::MakeRefPtr<LinearLayoutPattern>(true); });
        CHECK_NULL_VOID(videoNode);
        movingPhotoNode->AddChild(videoNode);
    }
    bool hasImageNode = movingPhotoNode->HasImageNode();
    if (!hasImageNode) {
        auto imageId = movingPhotoNode->GetImageId();
        auto imageNode = FrameNode::GetOrCreateFrameNode(
            V2::IMAGE_ETS_TAG, imageId, []() { return AceType::MakeRefPtr<ImagePattern>(); });
        CHECK_NULL_VOID(imageNode);
        movingPhotoNode->AddChild(imageNode);
    }
}

void MovingPhotoModelNG::SetImageSrc(const std::string& value)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto layoutProperty = AceType::DynamicCast<MovingPhotoLayoutProperty>(frameNode->GetLayoutProperty());
    CHECK_NULL_VOID(layoutProperty);
    if (layoutProperty->HasMovingPhotoUri()) {
        auto movingPhotoUri = layoutProperty->GetMovingPhotoUri().value();
        if (movingPhotoUri == value) {
            TAG_LOGW(AceLogTag::ACE_MOVING_PHOTO, "src not changed.");
            return;
        }
    }
    ACE_UPDATE_LAYOUT_PROPERTY(MovingPhotoLayoutProperty, MovingPhotoUri, value);

    auto pipeline = PipelineBase::GetCurrentContext();
    CHECK_NULL_VOID(pipeline);
    auto dataProvider = AceType::DynamicCast<DataProviderManagerStandard>(pipeline->GetDataProviderManager());
    CHECK_NULL_VOID(dataProvider);

    std::string imageSrc = dataProvider->GetMovingPhotoImageUri(value);
    ImageSourceInfo src;
    src.SetSrc(imageSrc);
    ACE_UPDATE_LAYOUT_PROPERTY(MovingPhotoLayoutProperty, ImageSourceInfo, src);

    int32_t fd = dataProvider->ReadMovingPhotoVideo(value);
    ACE_UPDATE_LAYOUT_PROPERTY(MovingPhotoLayoutProperty, VideoSource, fd);
}

void MovingPhotoModelNG::SetMuted(bool value)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto movingPhotoPattern = AceType::DynamicCast<MovingPhotoPattern>(frameNode->GetPattern());
    movingPhotoPattern->UpdateMuted(value);
}

void MovingPhotoModelNG::SetObjectFit(ImageFit objectFit)
{
    ACE_UPDATE_LAYOUT_PROPERTY(MovingPhotoLayoutProperty, ObjectFit, objectFit);
}

void MovingPhotoModelNG::SetOnStart(MovingPhotoEventFunc&& onStart)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<MovingPhotoEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnStart(std::move(onStart));
}

void MovingPhotoModelNG::SetOnStop(MovingPhotoEventFunc&& onStop)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<MovingPhotoEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnStop(std::move(onStop));
}

void MovingPhotoModelNG::SetOnPause(MovingPhotoEventFunc&& onPause)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<MovingPhotoEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnPause(std::move(onPause));
}

void MovingPhotoModelNG::SetOnFinish(MovingPhotoEventFunc&& onFinish)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<MovingPhotoEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnFinish(std::move(onFinish));
}

void MovingPhotoModelNG::SetOnError(MovingPhotoEventFunc&& onError)
{
    auto frameNode = ViewStackProcessor::GetInstance()->GetMainFrameNode();
    CHECK_NULL_VOID(frameNode);
    auto eventHub = frameNode->GetEventHub<MovingPhotoEventHub>();
    CHECK_NULL_VOID(eventHub);
    eventHub->SetOnError(std::move(onError));
}
} // namespace OHOS::Ace::NG