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

#include "boot_compile_progress.h"

#include <chrono>
#include "event_handler.h"
#include "parameter.h"
#include "parameters.h"
#include "platform/common/rs_system_properties.h"
#include "recording/recording_canvas.h"
#ifdef NEW_RENDER_CONTEXT
#include "render_context_factory.h"
#include "rs_surface_factory.h"
#endif
#include "transaction/rs_interfaces.h"
#include "transaction/rs_render_service_client.h"
#include "transaction/rs_transaction.h"
#include "util.h"

namespace OHOS {
namespace {
    constexpr const char* OTA_COMPILE_TIME_LIMIT = "persist.bms.optimizing_apps.timing";
    constexpr int32_t OTA_COMPILE_TIME_LIMIT_DEFAULT = 4 * 60;
    constexpr const char* OTA_COMPILE_DISPLAY_INFO = "const.bms.optimizing_apps.display_info";
    const std::string OTA_COMPILE_DISPLAY_INFO_DEFAULT = "正在优化应用";
    const std::string FONTS_PATH = "/system/fonts/HarmonyOS_Sans_SC_Black.ttf";
    constexpr const int32_t WAITING_SECONDS = 30;
    constexpr const int32_t ONE_HUNDRED_PERCENT = 100;
    constexpr const int32_t SEC_MS = 1000;
    constexpr const int32_t CIRCLE_NUM = 3;
    constexpr const float RADIUS = 10.0f;
    constexpr const float OFFSET_Y_PERCENT = 0.85f;
    constexpr const float HEIGHT_PERCENT = 0.05f;
    constexpr const int TEXT_BLOB_OFFSET = 5;
    constexpr const int FONT_SIZE = 50;
    constexpr const int32_t MAX_RETRY_TIMES = 5;
    constexpr const int32_t WAIT_MS = 500;
}

void BootCompileProgress::Init(const BootAnimationConfig& config)
{
    LOGI("ota compile, screenId: " BPUBU64 "", config.screenId);
    screenId_ = config.screenId;
    rotateDegree_ = config.rotateDegree;
    Rosen::RSInterfaces& interface = Rosen::RSInterfaces::GetInstance();
    Rosen::RSScreenModeInfo modeInfo = interface.GetScreenActiveMode(config.screenId);
    windowWidth_ = modeInfo.GetScreenWidth();
    windowHeight_ = modeInfo.GetScreenHeight();

    timeLimitSec_ = system::GetIntParameter<int32_t>(OTA_COMPILE_TIME_LIMIT, OTA_COMPILE_TIME_LIMIT_DEFAULT);
    tf_ = Rosen::Drawing::Typeface::MakeFromFile(FONTS_PATH.c_str());
    if (!tf_.get()) {
        LOGE("can not read font: %{public}s", FONTS_PATH.c_str());
        return;
    }

    displayInfo_ = system::GetParameter(OTA_COMPILE_DISPLAY_INFO, OTA_COMPILE_DISPLAY_INFO_DEFAULT);
    compileRunner_ = AppExecFwk::EventRunner::Create(false);
    compileHandler_ = std::make_shared<AppExecFwk::EventHandler>(compileRunner_);
    compileHandler_->PostTask(std::bind(&BootCompileProgress::CreateCanvasNode, this));
    compileHandler_->PostTask(std::bind(&BootCompileProgress::RegisterVsyncCallback, this));
    compileRunner_->Run();
}

bool BootCompileProgress::CreateCanvasNode()
{
    struct Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "BootCompileProgressNode";
    surfaceNodeConfig.isSync = true;
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    rsSurfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    if (!rsSurfaceNode_) {
        LOGE("ota compile, SFNode create failed");
        compileHandler_->PostTask(std::bind(&AppExecFwk::EventRunner::Stop, compileRunner_));
        return false;
    }
    float positionZ = MAX_ZORDER + 1;
    rsSurfaceNode_->SetRotation(rotateDegree_);
    rsSurfaceNode_->SetPositionZ(positionZ);
    rsSurfaceNode_->SetBounds(0, 0, windowWidth_, windowHeight_);
    rsSurfaceNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
    rsSurfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT);
    rsSurfaceNode_->SetBootAnimation(true);
    Rosen::RSTransaction::FlushImplicitTransaction();
    rsSurfaceNode_->AttachToDisplay(screenId_);
    Rosen::RSTransaction::FlushImplicitTransaction();

    rsCanvasNode_ = Rosen::RSCanvasNode::Create();
    rsCanvasNode_->SetBounds(0, 0, windowWidth_, windowHeight_);
    rsCanvasNode_->SetFrame(0, windowHeight_ * OFFSET_Y_PERCENT, windowWidth_, windowHeight_ * HEIGHT_PERCENT);
    rsCanvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
    rsCanvasNode_->SetPositionZ(positionZ);
    rsSurfaceNode_->AddChild(rsCanvasNode_, 0);

    LOGI("CreateCanvasNode success");
    return true;
}

bool BootCompileProgress::RegisterVsyncCallback()
{
    if (!WaitBmsStartIfNeeded()) {
        compileHandler_->PostTask(std::bind(&AppExecFwk::EventRunner::Stop, compileRunner_));
        return false;
    }

    if (system::GetParameter(BMS_COMPILE_STATUS, "-1") == BMS_COMPILE_STATUS_END) {
        LOGI("bms compile is already done.");
        return false;
    }

    auto& rsClient = Rosen::RSInterfaces::GetInstance();
    int32_t retry = 0;
    while (receiver_ == nullptr) {
        if (retry++ > MAX_RETRY_TIMES) {
            LOGE("get vsync receiver failed");
            compileHandler_->PostTask(std::bind(&AppExecFwk::EventRunner::Stop, compileRunner_));
            return false;
        }
        if (retry > 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_MS));
        }
        receiver_ = rsClient.CreateVSyncReceiver("BootCompileProgress", compileHandler_);
    }
    VsyncError ret = receiver_->Init();
    if (ret) {
        compileHandler_->PostTask(std::bind(&AppExecFwk::EventRunner::Stop, compileRunner_));
        LOGE("init vsync receiver failed");
        return false;
    }

    Rosen::VSyncReceiver::FrameCallback fcb = {
        .userData_ = this,
        .callback_ = std::bind(&BootCompileProgress::OnVsync, this),
    };
    int32_t changeFreq = static_cast<int32_t> ((1000.0 / freq_) / 16);
    ret = receiver_->SetVSyncRate(fcb, changeFreq);
    if (ret) {
        compileHandler_->PostTask(std::bind(&AppExecFwk::EventRunner::Stop, compileRunner_));
        LOGE("set vsync rate failed");
    }

    startTimeMs_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    endTimePredictMs_ = startTimeMs_ + timeLimitSec_ * SEC_MS;

    LOGI("RegisterVsyncCallback success");
    return true;
}

bool BootCompileProgress::WaitBmsStartIfNeeded()
{
    int waitSeconds = 0;
    while (system::GetParameter(BMS_COMPILE_STATUS, "-1") != BMS_COMPILE_STATUS_BEGIN
        && system::GetParameter(BMS_COMPILE_STATUS, "-1") != BMS_COMPILE_STATUS_END) {
        if (++waitSeconds > WAITING_SECONDS) {
            break;
        }
        LOGE("waiting Bms start ota compile...");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (system::GetParameter(BMS_COMPILE_STATUS, "-1") != BMS_COMPILE_STATUS_BEGIN
        && system::GetParameter(BMS_COMPILE_STATUS, "-1") != BMS_COMPILE_STATUS_END) {
        LOGE("Bms did not start ota compile");
        return false;
    }
    return true;
}

void BootCompileProgress::OnVsync()
{
    if (!isUpdateOptEnd_) {
        compileHandler_->PostTask(std::bind(&BootCompileProgress::DrawCompileProgress, this));
    } else {
        LOGI("ota compile completed");
        compileHandler_->PostTask(std::bind(&AppExecFwk::EventRunner::Stop, compileRunner_));
    }
}

void BootCompileProgress::DrawCompileProgress()
{
    UpdateCompileProgress();
    if (progress_ >= ONE_HUNDRED_PERCENT) {
        isUpdateOptEnd_ = true;
    }

    auto canvas = static_cast<Rosen::Drawing::RecordingCanvas*>(
        rsCanvasNode_->BeginRecording(windowWidth_, windowHeight_ * HEIGHT_PERCENT));

    Rosen::Drawing::Font font;
    font.SetTypeface(tf_);
    font.SetSize(FONT_SIZE);
    char info[64] = {0};
    int ret = sprintf_s(info, sizeof(info), "%s %d%%", displayInfo_.c_str(), progress_);
    if (ret == -1) {
        LOGE("set info failed");
        return;
    }
    std::shared_ptr<Rosen::Drawing::TextBlob> textBlob = Rosen::Drawing::TextBlob::MakeFromString(info, font);

    Rosen::Drawing::Brush whiteBrush;
    whiteBrush.SetColor(0xFFFFFFFF);
    whiteBrush.SetAntiAlias(true);
    canvas->AttachBrush(whiteBrush);

    double scale = windowWidth_ >= windowHeight_ ? 0.55 : 0.6;
    float scalarX = windowWidth_ * scale - textBlob->Bounds()->GetWidth() / NUMBER_TWO;
    float scalarY = TEXT_BLOB_OFFSET + textBlob->Bounds()->GetHeight() / NUMBER_TWO;
    canvas->DrawTextBlob(textBlob.get(), scalarX, scalarY);
    canvas->DetachBrush();

    Rosen::Drawing::Brush grayBrush;
    grayBrush.SetColor(0x40FFFFFF);
    grayBrush.SetAntiAlias(true);

    int whitePos = isBmsCompileDone_ ? ++times_ % CIRCLE_NUM : ++times_/freq_ % CIRCLE_NUM;
    for (int i = 0; i < CIRCLE_NUM; i++) {
        if (i == whitePos) {
            canvas->AttachBrush(whiteBrush);
        } else {
            canvas->AttachBrush(grayBrush);
        }
        int pointX = windowWidth_/ 2.0f + 4 * RADIUS * (i - 1);
        int pointY = rsCanvasNode_->GetPaintHeight() - 2 * RADIUS;
        canvas->DrawCircle({pointX, pointY}, RADIUS);
        canvas->DetachBrush();
    }

    rsCanvasNode_->FinishRecording();
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void BootCompileProgress::UpdateCompileProgress()
{
    if (!isBmsCompileDone_) {
        isBmsCompileDone_ = system::GetParameter(BMS_COMPILE_STATUS, "-1") == BMS_COMPILE_STATUS_END;
        int64_t now =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
        if (endTimePredictMs_ < now) {
            progress_ = ONE_HUNDRED_PERCENT;
            return;
        }
        progress_ = (int32_t)((now - startTimeMs_) * ONE_HUNDRED_PERCENT / (timeLimitSec_ * SEC_MS));
        progress_ = progress_ < 0 ? 0 : progress_ > ONE_HUNDRED_PERCENT ? ONE_HUNDRED_PERCENT: progress_;
    } else {
        progress_++;
    }

    LOGD("update progress: %{public}d", progress_);
}
} // namespace OHOS
