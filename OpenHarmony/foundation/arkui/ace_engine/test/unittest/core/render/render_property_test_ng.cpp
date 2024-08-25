/*
 * Copyright (c) 2023 iSoftStone Information Technology (Group) Co.,Ltd.
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
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "base/utils/utils.h"
#define protected public
#define private public
#include "core/components_ng/render/render_property.h"

#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS::Ace {
namespace {
const NG::InspectorFilter filter;
const std::string ZERO_STRING = "0.0px";
const std::string SRC_IMAGES = "images/mmm.jpg";
const std::string BACKGROUND_IMAGES = "images/mmm.jpg, ImageRepeat.NoRepeat";
constexpr char SHADOW_TEST[] = "shadow";

const Dimension POSITION_X { 10.0, DimensionUnit::PX };
const Dimension POSITION_Y { 20.0, DimensionUnit::PX };
const Dimension OFFSET_X { 40.0, DimensionUnit::PX };
const Dimension OFFSET_Y { 80.0, DimensionUnit::PX };
const Dimension ANCHOR_X { 100.0, DimensionUnit::PX };
const Dimension ANCHOR_Y { 200.0, DimensionUnit::PX };
const InvertVariant invert = 0.0f;
const float DYNAMIC_DIMMING = 0.5f;

const float VALUE_TEST = 720.0f;
const Color WHITE = Color(0xffffffff);
const Offset OFFSETS { 2.0, 2.0 };

const NG::VectorF VECTOR_TEST = { 10.0, 20.0 };
const NG::Vector5F VECTOR_5F_TEST = { 20.0f, 40.0f, 60.0f, 80.0f, 0.0f };
const NG::TranslateOptions PTTION_TEST = { OFFSET_X, OFFSET_Y, POSITION_X };
const NG::OffsetT<Dimension> POSITION = { POSITION_X, POSITION_Y };
const NG::OffsetT<Dimension> OFFSET_TEST = { OFFSET_X, OFFSET_Y };
const NG::OffsetT<Dimension> ANCHOR = { ANCHOR_X, ANCHOR_Y };

const BackgroundImageSize BACKGROUND_SIZE { BackgroundImageSizeType::COVER, 1.0 };
const BackgroundImagePosition BACKGROUND_POSITION { BackgroundImagePositionType::PERCENT, -1.0,
    BackgroundImagePositionType::PERCENT, 0.0 };

void MakeGraphicsProperty(NG::GraphicsProperty& graphicsProperty)
{
    graphicsProperty.propFrontGrayScale = POSITION_X;
    graphicsProperty.propFrontBrightness = POSITION_X;
    graphicsProperty.propDynamicDimDegree = DYNAMIC_DIMMING;
    graphicsProperty.propFrontSaturate = POSITION_X;
    graphicsProperty.propFrontContrast = POSITION_X;
    graphicsProperty.propFrontInvert = invert;
    graphicsProperty.propFrontSepia = POSITION_X;
    graphicsProperty.propFrontHueRotate = VALUE_TEST;
    graphicsProperty.propFrontColorBlend = WHITE;
};
} // namespace

class RenderPropertyTestNg : public testing::Test {};

/**
 * @tc.name: RenderPositionPropertyTest001
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, RenderPositionPropertyTest001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object renderPositionProperty.
     */
    NG::RenderPositionProperty renderPositionProperty;
    auto json = JsonUtil::Create(true);

    /**
     * @tc.steps: step2. call ToJsonValue.The propPosition propOffset propMarkAnchor is null.
     */
    renderPositionProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetValue("position")->GetString("x"), "");
    EXPECT_EQ(json->GetValue("position")->GetString("y"), "");
    EXPECT_EQ(json->GetValue("offset")->GetString("x"), ZERO_STRING);
    EXPECT_EQ(json->GetValue("offset")->GetString("y"), ZERO_STRING);
    EXPECT_EQ(json->GetValue("markAnchor")->GetString("x"), ZERO_STRING);
    EXPECT_EQ(json->GetValue("markAnchor")->GetString("y"), ZERO_STRING);

    /**
     * @tc.steps: step3. Build a object renderPosition.
     */
    NG::RenderPositionProperty renderPosition;
    auto jsonTest = JsonUtil::Create(true);

    /**
     * @tc.steps: step4. call ToJsonValue.The propPosition propOffset propMarkAnchor is not null.
     */
    renderPosition.propPosition = POSITION;
    renderPosition.propOffset = OFFSET_TEST;
    renderPosition.propAnchor = ANCHOR;
    renderPosition.ToJsonValue(jsonTest, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(jsonTest->GetValue("position")->GetString("x"), "10.00px");
    EXPECT_EQ(jsonTest->GetValue("position")->GetString("y"), "20.00px");
    EXPECT_EQ(jsonTest->GetValue("offset")->GetString("x"), "40.00px");
    EXPECT_EQ(jsonTest->GetValue("offset")->GetString("y"), "80.00px");
    EXPECT_EQ(jsonTest->GetValue("markAnchor")->GetString("x"), "100.00px");
    EXPECT_EQ(jsonTest->GetValue("markAnchor")->GetString("y"), "200.00px");
}

/**
 * @tc.name: GraphicsPropertyTest001
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, GraphicsPropertyTest001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object graphicsProperty.
     */
    NG::GraphicsProperty graphicsProperty;
    auto json = JsonUtil::Create(true);

    /**
     * @tc.steps: step2. call ToJsonValue.The propBackShadow is null, propFrontColorBlend = WHITE;
     */
    MakeGraphicsProperty(graphicsProperty);
    graphicsProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetString("colorBlend"), "#FFFFFFFF");
    EXPECT_EQ(json->GetValue(SHADOW_TEST)->GetString("radius"), "0.000000");
    EXPECT_EQ(json->GetValue(SHADOW_TEST)->GetString("color"), "#FF000000");
    EXPECT_EQ(json->GetValue(SHADOW_TEST)->GetString("offsetX"), "0.000000");
    EXPECT_EQ(json->GetValue(SHADOW_TEST)->GetString("offsetY"), "0.000000");
    EXPECT_EQ(json->GetDouble("dynamicDimming"), 0.5);
}

/**
 * @tc.name: GraphicsPropertyTest002
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, GraphicsPropertyTest002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object graphicsProperty.
     */
    NG::GraphicsProperty graphicsProperty;
    auto json = JsonUtil::Create(true);
    Shadow shadow(VALUE_TEST, OFFSETS, WHITE, ShadowStyle::None);

    /**
     * @tc.steps: step2. call ToJsonValue.push propBackShadow style_ == ShadowStyle::OuterDefaultXS.
     * @tc.expected: Return expected results.
     */
    shadow.style_ = ShadowStyle::OuterDefaultXS;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetString(SHADOW_TEST), "ShadowStyle.OuterDefaultXS");
    json->Delete(SHADOW_TEST);

    /**
     * @tc.steps: step3. call ToJsonValue.push propBackShadow style_ == ShadowStyle::OuterDefaultSM.
     * @tc.expected: Return expected results.
     */
    shadow.style_ = ShadowStyle::OuterDefaultSM;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetString(SHADOW_TEST), "ShadowStyle.OuterDefaultSM");
    json->Delete(SHADOW_TEST);
    /**
     * @tc.steps: step4. call ToJsonValue.push propBackShadow style_ == ShadowStyle::OuterDefaultMD.
     * @tc.expected: Return expected results.
     */
    shadow.style_ = ShadowStyle::OuterDefaultMD;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetString(SHADOW_TEST), "ShadowStyle.OuterDefaultMD");
    json->Delete(SHADOW_TEST);

    /**
     * @tc.steps: step5. call ToJsonValue.push propBackShadow style_ == ShadowStyle::OuterDefaultLG.
     * @tc.expected: Return expected results.
     */
    shadow.style_ = ShadowStyle::OuterDefaultLG;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetString(SHADOW_TEST), "ShadowStyle.OuterDefaultLG");
    json->Delete(SHADOW_TEST);

    /**
     * @tc.steps: step6. call ToJsonValue.push propBackShadow style_ == ShadowStyle::OuterFloatingSM.
     * @tc.expected: Return expected results.
     */
    shadow.style_ = ShadowStyle::OuterFloatingSM;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetString(SHADOW_TEST), "ShadowStyle.OuterFloatingSM");
    json->Delete(SHADOW_TEST);

    /**
     * @tc.steps: step7. call ToJsonValue.push propBackShadow style_ == ShadowStyle::OuterFloatingMD.
     * @tc.expected: Return expected results.
     */
    shadow.style_ = ShadowStyle::OuterFloatingMD;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetString(SHADOW_TEST), "ShadowStyle.OuterFloatingMD");
    json->Delete(SHADOW_TEST);
}

/**
 * @tc.name: GraphicsPropertyTest003
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, GraphicsPropertyTest003, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object graphicsProperty.
     */
    NG::GraphicsProperty graphicsProperty;
    auto json = JsonUtil::Create(true);
    Shadow shadow(VALUE_TEST, OFFSETS, WHITE, ShadowStyle::None);

    /**
     * @tc.steps: step2. call ToJsonValue.push propBackShadow colorStrategy_ == ShadowColorStrategy::AVERAGE.
     * @tc.expected: Return expected results.
     */
    shadow.colorStrategy_ = ShadowColorStrategy::AVERAGE;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetValue(SHADOW_TEST)->GetString("color"), "ColoringStrategy.AVERAGE");
    json->Delete(SHADOW_TEST);

    /**
     * @tc.steps: step3. call ToJsonValue.push propBackShadow colorStrategy_ == ShadowColorStrategy::PRIMARY.
     * @tc.expected: Return expected results.
     */
    shadow.colorStrategy_ = ShadowColorStrategy::PRIMARY;
    graphicsProperty.propBackShadow = shadow;
    graphicsProperty.ToJsonValue(json, filter);
    EXPECT_EQ(json->GetValue(SHADOW_TEST)->GetString("color"), "ColoringStrategy.PRIMARY");
}

/**
 * @tc.name: BackgroundPropertyTest001
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, BackgroundPropertyTest001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object backgroundProperty.
     */
    NG::BackgroundProperty backgroundProperty;
    auto json = JsonUtil::Create(true);

    /**
     * @tc.steps: step2. call ToJsonValue.push propBackgroundImage is null.
     * @tc.steps: step2. push propBackgroundImageSize is null.
     * @tc.steps: step2. push propBackgroundImagePosition is null.
     */
    backgroundProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetString("backgroundImage"), "NONE");
    EXPECT_EQ(json->GetString("backgroundImageSize"), "ImageSize.Auto");
    EXPECT_EQ(json->GetString("backgroundImagePosition"), "");
}

/**
 * @tc.name: BackgroundPropertyTest002
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, BackgroundPropertyTest002, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object backgroundProperty.
     */
    NG::BackgroundProperty backgroundProperty;
    auto json = JsonUtil::Create(true);

    /**
     * @tc.steps: step2. call ToJsonValue.push propBackgroundImage is imageSourceInfo.
     * @tc.steps: step2. push propBackgroundImageSize is BACKGROUND_SIZE.
     * @tc.steps: step2. push propBackgroundImagePosition is BACKGROUND_POSITION.
     */
    ImageSourceInfo imageSourceInfo;
    imageSourceInfo.src_ = SRC_IMAGES;
    backgroundProperty.propBackgroundImage = imageSourceInfo;
    backgroundProperty.propBackgroundImageSize = BACKGROUND_SIZE;
    backgroundProperty.propBackgroundImagePosition = BACKGROUND_POSITION;
    backgroundProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetString("backgroundImage"), BACKGROUND_IMAGES);
    EXPECT_EQ(json->GetString("backgroundImageSize"), "ImageSize.Cover");
    EXPECT_EQ(json->GetString("backgroundImagePosition"), "Alignment.TopEnd");
}

/**
 * @tc.name: ClipPropertytyTest001
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, ClipPropertytyTest001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object backgroundProperty.
     */
    NG::ClipProperty clipProperty;
    auto json = JsonUtil::Create(true);

    /**
     * @tc.steps: step2. call ToJsonValue.push propClipShape is null.
     * @tc.steps: step2. push propClipMask is null.
     */
    clipProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetString("clip"), "false");
    EXPECT_EQ(json->GetValue("mask")->GetString("shape"), "");
    json->Delete("clip");
    json->Delete("mask");

    /**
     * @tc.steps: step3. call ToJsonValue.push propClipShape is not null.
     * @tc.steps: step3. push propClipMask is not null.
     */
    clipProperty.propClipShape = AceType::MakeRefPtr<BasicShape>();
    clipProperty.propClipMask = AceType::MakeRefPtr<BasicShape>();
    clipProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetString("clip"), "{\"shape\":\"None\"}");
    EXPECT_EQ(json->GetValue("mask")->GetString("shape"), "None");
}

/**
 * @tc.name: GradientPropertyTest001
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, GradientPropertyTest001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object backgroundProperty.
     */
    NG::GradientProperty gradientProperty;
    auto json = JsonUtil::Create(true);

    /**
     * @tc.steps: step2. call ToJsonValue.push propClipShape is null.
     * @tc.steps: step2. push propClipMask is null.
     */
    gradientProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */

    EXPECT_EQ(json->GetString("linearGradient"), "");
    EXPECT_EQ(json->GetString("sweepGradient"), "");
    EXPECT_EQ(json->GetString("radialGradient"), "");
    json->Delete("linearGradient");
    json->Delete("sweepGradient");
    json->Delete("radialGradient");

    /**
     * @tc.steps: step3. call ToJsonValue.push propLinearGradient is not null.
     * @tc.steps: step3. push propSweepGradient is not null.
     * @tc.steps: step3. push propRadialGradient is not null.
     */
    NG::Gradient gradient;
    gradientProperty.propLinearGradient = gradient;
    gradientProperty.propSweepGradient = gradient;
    gradientProperty.propRadialGradient = gradient;
    gradientProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_TRUE(gradientProperty.propLinearGradient.has_value());
    EXPECT_TRUE(gradientProperty.propSweepGradient.has_value());
    EXPECT_TRUE(gradientProperty.propRadialGradient.has_value());
}

/**
 * @tc.name: TransformPropertyTest001
 * @tc.desc: Test cast to RenderPropertyTestNg
 * @tc.type: FUNC
 */
HWTEST_F(RenderPropertyTestNg, TransformPropertyTest001, TestSize.Level1)
{
    /**
     * @tc.steps: step1. Build a object backgroundProperty.
     */
    NG::TransformProperty transformProperty;
    auto json = JsonUtil::Create(true);

    /**
     * @tc.steps: step2. call ToJsonValue.push transformProperty is null.
     */
    transformProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetString("rotate"), "");
    EXPECT_EQ(json->GetString("scale"), "");
    EXPECT_EQ(json->GetString("translate"), "");
    json->Delete("rotate");
    json->Delete("scale");
    json->Delete("translate");

    /**
     * @tc.steps: step3. call ToJsonValue. push propTransformRotate is VECTOR_5F_TEST.
     * @tc.steps: step3. push propTransformScale is VECTOR_TEST.
     * @tc.steps: step3. push propTransformTranslate is PTTION_TEST.
     */
    transformProperty.propTransformRotate = VECTOR_5F_TEST;
    transformProperty.propTransformScale = VECTOR_TEST;
    transformProperty.propTransformTranslate = PTTION_TEST;
    transformProperty.ToJsonValue(json, filter);

    /**
     * @tc.expected: Return expected results.
     */
    EXPECT_EQ(json->GetValue("rotate")->GetString("x"), "20.000000");
    EXPECT_EQ(json->GetValue("rotate")->GetString("y"), "40.000000");
    EXPECT_EQ(json->GetValue("rotate")->GetString("z"), "60.000000");
    EXPECT_EQ(json->GetValue("rotate")->GetString("angle"), "80.000000");

    EXPECT_EQ(json->GetValue("scale")->GetString("centerX"), "5000.00%");
    EXPECT_EQ(json->GetValue("scale")->GetString("centerY"), "5000.00%");

    EXPECT_EQ(json->GetValue("translate")->GetString("x"), "40.00px");
    EXPECT_EQ(json->GetValue("translate")->GetString("y"), "80.00px");
    EXPECT_EQ(json->GetValue("translate")->GetString("z"), "10.00px");
}
} // namespace OHOS::Ace
