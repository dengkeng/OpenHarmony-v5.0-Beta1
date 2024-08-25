/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"

#include "render/rs_motion_blur_filter.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Rosen {

class MotionBlurFilterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void MotionBlurFilterTest::SetUpTestCase() {}
void MotionBlurFilterTest::TearDownTestCase() {}
void MotionBlurFilterTest::SetUp() {}
void MotionBlurFilterTest::TearDown() {}

/**
 * @tc.name: testInterface
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(MotionBlurFilterTest, testInterface, TestSize.Level1)
{
    Vector2f anchor = {0.f, 0.f};
    std::shared_ptr<MotionBlurParam> para = std::make_shared<MotionBlurParam>(10.f, anchor);
    auto filter = std::make_shared<RSMotionBlurFilter>(para);
    EXPECT_TRUE(filter != nullptr);

    Drawing::Canvas canvas;
    Drawing::Rect src;
    Drawing::Rect dst;
    std::shared_ptr<Drawing::Image> image;
    filter->GetDescription();
    filter->DrawImageRect(canvas, image, src, dst);
}

/**
 * @tc.name: ComposeTest
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(MotionBlurFilterTest, ComposeTest, TestSize.Level1)
{
    Vector2f anchor = {0.f, 0.f};
    std::shared_ptr<MotionBlurParam> para = std::make_shared<MotionBlurParam>(10.f, anchor); // 10.f radius
    auto filter = std::make_shared<RSMotionBlurFilter>(para);
    auto filter_ = std::make_shared<RSMotionBlurFilter>(para);

    EXPECT_TRUE(filter->Compose(filter_) == nullptr);
}

/**
 * @tc.name: SetGeometryTest
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(MotionBlurFilterTest, SetGeometryTest, TestSize.Level1)
{
    Vector2f anchor = {0.f, 0.f};
    std::shared_ptr<MotionBlurParam> para = std::make_shared<MotionBlurParam>(10.f, anchor); // 10.f radius
    auto filter = std::make_shared<RSMotionBlurFilter>(para);

    Drawing::Canvas canvas;
    filter->SetGeometry(canvas, 0.f, 0.f);
}
} // namespace Rosen
} // namespace OHOS