/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string>
#include "gtest/gtest.h"
#include "native_avcodec_videodecoder.h"
#include "native_averrors.h"
#include "videodec_ndk_sample.h"
#include "native_avcodec_base.h"
#include "avcodec_codec_name.h"

#ifdef SUPPORT_DRM
#include "native_mediakeysession.h"
#include "native_mediakeysystem.h"
#endif

#define MAX_THREAD 16

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class SwdecFuncNdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    void InputFunc();
    void OutputFunc();
    void Release();
    int32_t Stop();

protected:
    const string CODEC_NAME = "video_decoder.avc";
    const char *INP_DIR_720_30 = "/data/test/media/1280_720_30_10Mb.h264";
    const char *INP_DIR_1080_30 = "/data/test/media/1920_1080_10_30Mb.h264";
};
} // namespace Media
} // namespace OHOS

void SwdecFuncNdkTest::SetUpTestCase() {}
void SwdecFuncNdkTest::TearDownTestCase() {}
void SwdecFuncNdkTest::SetUp() {}
void SwdecFuncNdkTest::TearDown() {}

namespace {
/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_0200
 * @tc.name      : create nonexist decoder
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_0200, TestSize.Level1)
{
    OH_AVCodec *vdec_ = OH_VideoDecoder_CreateByName("OMX.h264.decode.111.222.333");
    ASSERT_EQ(nullptr, vdec_);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_0300
 * @tc.name      : test h264  decode buffer
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_0300, TestSize.Level0)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    ASSERT_EQ(AV_ERR_OK, vDecSample->RunVideoDec("OH.Media.Codec.Decoder.Video.AVC"));
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_0400
 * @tc.name      : test h264  decode surface
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_0400, TestSize.Level0)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->SURFACE_OUTPUT = true;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    ASSERT_EQ(AV_ERR_OK, vDecSample->RunVideoDec_Surface("OH.Media.Codec.Decoder.Video.AVC"));
    vDecSample->WaitForEOS();
    bool isVaild = false;
    OH_VideoDecoder_IsValid(vDecSample->vdec_, &isVaild);
    ASSERT_EQ(false, isVaild);
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_0500
 * @tc.name      : test h264  decode surface
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_0500, TestSize.Level2)
{
    uint32_t errNo = DRM_ERR_OK;
#ifdef SUPPORT_DRM
    std::string uuid;
    if (OH_MediaKeySystem_IsSupported("com.clearplay.drm")) {
        uuid.assign("com.clearplay.drm");
    } else if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        uuid.assign("com.wiseplay.drm");
    }
    errNo = DRM_ERR_INVALID_VAL;
    MediaKeySystem *system = nullptr;
    errNo = OH_MediaKeySystem_Create((const char *)uuid.c_str(), &system);
    EXPECT_NE(system, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    MediaKeySession *session = nullptr;
    errNo = OH_MediaKeySystem_CreateMediaKeySession(system, &contentProtectionLevel, &session);
    EXPECT_NE(session, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);

    OH_AVCodec *vdec = OH_VideoDecoder_CreateByName("OH.Media.Codec.Decoder.Video.AVC");
    errNo = OH_VideoDecoder_SetDecryptionConfig(vdec, session, false);
#endif
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_0700
 * @tc.name      : test set EOS when last frame
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_0700, TestSize.Level1)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_0800
 * @tc.name      : test set EOS before last frame then stop
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_0800, TestSize.Level1)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    vDecSample->BEFORE_EOS_INPUT = true;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}
/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_4000
 * @tc.name      : test set EOS before last frame then stop surface
 * @tc.desc      : function test
 */

HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_4000, TestSize.Level1)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = true;
    vDecSample->BEFORE_EOS_INPUT = true;
    ASSERT_EQ(AV_ERR_OK, vDecSample->RunVideoDec_Surface("OH.Media.Codec.Decoder.Video.AVC"));
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_1000
 * @tc.name      : test reconfigure for new file with one decoder
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_1000, TestSize.Level1)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    vDecSample->AFTER_EOS_DESTORY_CODEC = false;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
    ASSERT_EQ(AV_ERR_OK, vDecSample->Reset());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_1100
 * @tc.name      : test reconfigure for new file with the recreated decoder
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_1100, TestSize.Level1)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_1200
 * @tc.name      : repeat start and stop 5 times before EOS
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_1200, TestSize.Level2)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    vDecSample->REPEAT_START_STOP_BEFORE_EOS = 5;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_1300
 * @tc.name      : repeat start and flush 5 times before EOS
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_1300, TestSize.Level2)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    vDecSample->REPEAT_START_FLUSH_BEFORE_EOS = 5;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_1400
 * @tc.name      : set larger width and height
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_1400, TestSize.Level2)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_720_30;
    vDecSample->DEFAULT_WIDTH = 1920;
    vDecSample->DEFAULT_HEIGHT = 1080;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_1500
 * @tc.name      : set the width and height to a samller value
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_1500, TestSize.Level2)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = INP_DIR_1080_30;
    vDecSample->DEFAULT_WIDTH = 1280;
    vDecSample->DEFAULT_HEIGHT = 720;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}

/**
 * @tc.number    : VIDEO_SWDEC_FUNCTION_1600
 * @tc.name      : resolution change
 * @tc.desc      : function test
 */
HWTEST_F(SwdecFuncNdkTest, VIDEO_SWDEC_FUNCTION_1600, TestSize.Level2)
{
    auto vDecSample = make_shared<VDecNdkSample>();
    vDecSample->INP_DIR = "/data/test/media/resolutionChange.h264";
    vDecSample->DEFAULT_WIDTH = 1104;
    vDecSample->DEFAULT_HEIGHT = 622;
    vDecSample->DEFAULT_FRAME_RATE = 30;
    vDecSample->SURFACE_OUTPUT = false;
    ASSERT_EQ(AV_ERR_OK, vDecSample->CreateVideoDecoder("OH.Media.Codec.Decoder.Video.AVC"));
    ASSERT_EQ(AV_ERR_OK, vDecSample->ConfigureVideoDecoder());
    ASSERT_EQ(AV_ERR_OK, vDecSample->SetVideoDecoderCallback());
    ASSERT_EQ(AV_ERR_OK, vDecSample->StartVideoDecoder());
    vDecSample->WaitForEOS();
    ASSERT_EQ(AV_ERR_OK, vDecSample->errCount);
}
} // namespace