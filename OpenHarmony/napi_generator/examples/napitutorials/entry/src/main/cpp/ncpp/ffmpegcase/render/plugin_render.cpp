/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <complex>
#include <cstdint>
#include <hilog/log.h>
#include <js_native_api.h>
#include <js_native_api_types.h>
#include <string>
#include "common.h"
#include "../common/common.h"
#include "../manager/plugin_manager.h"
#include "libavutil/pixdesc.h"
#include "plugin_render.h"

extern "C" {
    #include "libavformat/avformat.h"
    #include "libavcodec/avcodec.h"
    #include "libavutil/timestamp.h"
    #include "libavutil/pixdesc.h"

    // 自定义 avio_read_packet 函数
    int custom_avio_read_packet(void *opaque, uint8_t *buf, int bufSize)
    {
        FILE *file = ((FILE *)opaque); // 将 void 指针转换为 int 指针，并取得文件描述符
        if (!file) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, 0xFF00, "PluginRender", "custom_avio_read_packet file is null");
            return AVERROR_EOF;
        }
        OH_LOG_Print(LOG_APP, LOG_INFO, 0xFF00, "PluginRender", "read_packet %{public}d", bufSize);
        size_t bytesRead = fread(buf, 1, bufSize, file); // 从文件描述符中读取数据
        if (bytesRead <= 0) {
            if (feof(file)) {
                OH_LOG_Print(LOG_APP, LOG_ERROR, 0xFF00, "PluginRender", "custom_avio_read_packet file eof %{public}zu",
                             bytesRead);
                return AVERROR_EOF;
            } else {
                OH_LOG_Print(LOG_APP, LOG_ERROR, 0xFF00, "PluginRender", "custom_avio_read_packet file eio");
                return AVERROR_EOF;
            }
        }
    
        if (bufSize > bytesRead) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, 0xFF00, "PluginRender", "read end %{public}zu", bytesRead);
            return 0;
        }
        OH_LOG_Print(LOG_APP, LOG_INFO, 0xFF00, "PluginRender", "read_packet bytes[%{public}zu],bufsize[%{public}d]",
                     bytesRead, bufSize);
        return (int)bytesRead;
    }

    int open_codec_context(int *streamIdx, AVCodecContext **decCtx, AVFormatContext *fmtCtx,
        enum AVMediaType type)
    {
        int ret = 0;
        int streamIndex = 0;
        AVStream *st;
        const AVCodec *dec = NULL;

        ret = av_find_best_stream(fmtCtx, type, -1, -1, NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "Could not find %s stream in input file '%s'\n", av_get_media_type_string(type),
                    "srcfile");
            return ret;
        } else {
            streamIndex = ret;
            st = fmtCtx->streams[streamIndex];

            /* find decoder for the stream */
            dec = avcodec_find_decoder(st->codecpar->codec_id);
            if (!dec) {
                fprintf(stderr, "Failed to find %s codec\n", av_get_media_type_string(type));
                return AVERROR(EINVAL);
            }

            /* Allocate a codec context for the decoder */
            *decCtx = avcodec_alloc_context3(dec);
            if (!*decCtx) {
                fprintf(stderr, "Failed to allocate the %s codec context\n", av_get_media_type_string(type));
                return AVERROR(ENOMEM);
            }

            /* Copy codec parameters from input stream to output codec context */
            if ((ret = avcodec_parameters_to_context(*decCtx, st->codecpar)) < 0) {
                fprintf(stderr, "Failed to copy %s codec parameters to decoder context\n",
                        av_get_media_type_string(type));
                return ret;
            }

            /* Init the decoders */
            if ((ret = avcodec_open2(*decCtx, dec, NULL)) < 0) {
                fprintf(stderr, "Failed to open %s codec\n", av_get_media_type_string(type));
                return ret;
            }
            *streamIdx = streamIndex;
        }

        return 0;
    }

    int decode_packet(AVCodecContext *dec, AVFrame *frame, const AVPacket *pkt)
    {
        int ret = 0;

        // submit the packet to the decoder
        ret = avcodec_send_packet(dec, pkt);
        if (ret < 0) {
            fprintf(stderr, "Error submitting a packet for decoding (%s)\n", av_err2str(ret));
            return ret;
        }

        // get all the available frames from the decoder
        while (ret >= 0) {
            ret = avcodec_receive_frame(dec, frame);
            if (ret < 0) {
                // those two return values are special and mean there is no output
                // frame available, but there were no errors during decoding
                if (ret == AVERROR_EOF || ret == AVERROR(EAGAIN)) {
                    return 0;
                }

                fprintf(stderr, "Error during decoding (%s)\n", av_err2str(ret));
                return ret;
            }

            // write the frame data to output file
            if (dec->codec->type == AVMEDIA_TYPE_VIDEO) {
                OH_LOG_Print(LOG_APP, LOG_INFO, 0xFF00, "PluginRender",
                    "decode video format = [%{public}d]", frame->format,
                    "w[%{public}d]:h[%{public}d] w[%{public}d]:h[%{public}d]\n",
                    frame->width, frame->height, dec->width, dec->height);
            } else {
                OH_LOG_Print(LOG_APP, LOG_INFO, 0xFF00, "PluginRender",
                    "decode audio nbs[%{public}d] pts[%{public}s]\n",
                    frame->nb_samples, av_ts2timestr(frame->pts, &dec->time_base));
            }

            av_frame_unref(frame);
            if (ret < 0) {
                return ret;
            }
        }

        return 0;
    }
}

namespace NativeXComponentSample {
namespace {
    constexpr int32_t NUM_9 = 9;
    constexpr int32_t NUM_8 = 8;
    constexpr int32_t NUM_7 = 7;
    constexpr int32_t NUM_6 = 6;
    constexpr int32_t NUM_5 = 5;
    constexpr int32_t NUM_4 = 4;
    constexpr int32_t NUM_3 = 3;
    constexpr int32_t NUM_2 = 2;
    constexpr int32_t NUM_1 = 1;
    constexpr int32_t NUM_1024 = 1024;
    constexpr int32_t NUM_180 = 180;
    constexpr int32_t NUM_72 = 72;
    constexpr int32_t NUM_54 = 54;
    constexpr int32_t NUM_18 = 18;
    void OnSurfaceCreatedCB(OH_NativeXComponent *component, void *window)
    {
        OH_LOG_Print(LOG_APP, LOG_INFO, 0xFF00, "Callback", "OnSurfaceCreatedCB");
        if ((component == nullptr) || (window == nullptr)) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback",
                         "OnSurfaceCreatedCB: component or window is null");
            return;
        }

        char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {'\0'};
        uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
        if (OH_NativeXComponent_GetXComponentId(component, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
            OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback",
                         "OnSurfaceCreatedCB: Unable to get XComponent id");
            return;
        }

        std::string id(idStr);
        auto render = PluginRender::GetInstance(id);
        uint64_t width;
        uint64_t height;
        int32_t xSize = OH_NativeXComponent_GetXComponentSize(component, window, &width, &height);
        if ((xSize == OH_NATIVEXCOMPONENT_RESULT_SUCCESS) && (render != nullptr)) {
            if (render->eglCore_->EglContextInit(window, width, height)) {
                render->eglCore_->Background();
            }
        }
    }

void OnSurfaceChangedCB(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "OnSurfaceChangedCB");
    if ((component == nullptr) || (window == nullptr)) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "OnSurfaceChangedCB: component or window is null");
        return;
    }

    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = { '\0' };
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(component, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "OnSurfaceChangedCB: Unable to get XComponent id");
        return;
    }

    std::string id(idStr);
    auto render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->OnSurfaceChanged(component, window);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "surface changed");
    }
}

void OnSurfaceDestroyedCB(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "OnSurfaceDestroyedCB");
    if ((component == nullptr) || (window == nullptr)) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "OnSurfaceDestroyedCB: component or window is null");
        return;
    }

    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = { '\0' };
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(component, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "OnSurfaceDestroyedCB: Unable to get XComponent id");
        return;
    }

    std::string id(idStr);
    PluginRender::Release(id);
}

void DispatchTouchEventCB(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "DispatchTouchEventCB");
    if ((component == nullptr) || (window == nullptr)) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "DispatchTouchEventCB: component or window is null");
        return;
    }

    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = { '\0' };
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(component, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "DispatchTouchEventCB: Unable to get XComponent id");
        return;
    }

    std::string id(idStr);
    PluginRender* render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->OnTouchEvent(component, window);
    }
}

void DispatchMouseEventCB(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "DispatchMouseEventCB");
    int32_t ret;
    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    ret = OH_NativeXComponent_GetXComponentId(component, idStr, &idSize);
    if (ret != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        return;
    }

    std::string id(idStr);
    auto render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->OnMouseEvent(component, window);
    }
}

void DispatchHoverEventCB(OH_NativeXComponent* component, bool isHover)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "DispatchHoverEventCB");
    int32_t ret;
    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    ret = OH_NativeXComponent_GetXComponentId(component, idStr, &idSize);
    if (ret != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        return;
    }

    std::string id(idStr);
    auto render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->OnHoverEvent(component, isHover);
    }
}

void OnFocusEventCB(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "OnFocusEventCB");
    int32_t ret;
    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    ret = OH_NativeXComponent_GetXComponentId(component, idStr, &idSize);
    if (ret != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        return;
    }

    std::string id(idStr);
    auto render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->OnFocusEvent(component, window);
    }
}

void OnBlurEventCB(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "OnBlurEventCB");
    int32_t ret;
    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    ret = OH_NativeXComponent_GetXComponentId(component, idStr, &idSize);
    if (ret != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        return;
    }

    std::string id(idStr);
    auto render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->OnBlurEvent(component, window);
    }
}

void OnKeyEventCB(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "Callback", "OnKeyEventCB");
    int32_t ret;
    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    ret = OH_NativeXComponent_GetXComponentId(component, idStr, &idSize);
    if (ret != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        return;
    }
    std::string id(idStr);
    auto render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->OnKeyEvent(component, window);
    }
}
} // namespace

std::unordered_map<std::string, PluginRender*> PluginRender::instance_;
int32_t PluginRender::hasDraw_ = 0;
int32_t PluginRender::hasChangeColor_ = 0;

PluginRender::PluginRender(std::string& id)
{
    this->id_ = id;
    this->eglCore_ = new EGLCore();
}

PluginRender* PluginRender::GetInstance(std::string& id)
{
    if (instance_.find(id) == instance_.end()) {
        PluginRender* instance = new PluginRender(id);
        instance_[id] = instance;
        return instance;
    } else {
        return instance_[id];
    }
}

void PluginRender::Export(napi_env env, napi_value exports)
{
    if ((env == nullptr) || (exports == nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "Export: env or exports is null");
        return;
    }

    napi_property_descriptor desc[] = {
        {"drawPattern", nullptr, PluginRender::NapiDrawPattern, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getStatus", nullptr, PluginRender::TestGetXComponentStatus, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"play", nullptr, PluginRender::NapiPlay, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stop", nullptr, PluginRender::NapiStop, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getInfo", nullptr, PluginRender::NapiGetInfo, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    if (napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "Export: napi_define_properties failed");
    }
}

// NAPI registration method type napi_callback. If no value is returned, nullptr is returned.
napi_value PluginRender::NapiPlay(napi_env env, napi_callback_info info)
{
    size_t argc = NUM_3;
    napi_value args[NUM_3];
    uint32_t fd = 0;
    uint32_t foff = 0;
    uint32_t flen = 0;

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern");
    if ((env == nullptr) || (info == nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: env or info is null");
        return nullptr;
    }

    napi_value thisArg;
    if (napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: napi_get_cb_info fail");
        return nullptr;
    }

    napi_get_value_uint32(env, args[0], &fd);
    napi_get_value_uint32(env, args[1], &foff);
    napi_get_value_uint32(env, args[NUM_2], &flen);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
                 "fd:%{public}d, foff:%{public}d, flen:%{public}d!", fd, foff, flen);

    napi_value exportInstance;
    if (napi_get_named_property(env, thisArg, OH_NATIVE_XCOMPONENT_OBJ, &exportInstance) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender",
                     "NapiDrawPattern: napi_get_named_property fail");
        return nullptr;
    }

    OH_NativeXComponent *nativeXComponent = nullptr;
    if (napi_unwrap(env, exportInstance, reinterpret_cast<void **>(&nativeXComponent)) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: napi_unwrap fail");
        return nullptr;
    }

    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {'\0'};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(nativeXComponent, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender",
                     "NapiDrawPattern: Unable to get XComponent id");
        return nullptr;
    }

    std::string id(idStr);
    PluginRender *render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->eglCore_->fd_ = fd;
        render->eglCore_->foff_ = foff;
        render->eglCore_->flen_ = flen;
        render->eglCore_->DrawBmp(fd, foff, flen, hasDraw_);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "render->eglCore_->Draw() executed");
    }
    return nullptr;
}

// NAPI registration method type napi_callback. If no value is returned, nullptr is returned.
napi_value PluginRender::NapiStop(napi_env env, napi_callback_info info)
{
    size_t argc = NUM_3;
    napi_value args[NUM_3];
    uint32_t fd = 0;
    uint32_t foff = 0;
    uint32_t flen = 0;

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern");
    if ((env == nullptr) || (info == nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: env or info is null");
        return nullptr;
    }

    napi_value thisArg;
    if (napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: napi_get_cb_info fail");
        return nullptr;
    }

    napi_get_value_uint32(env, args[0], &fd);
    napi_get_value_uint32(env, args[1], &foff);
    napi_get_value_uint32(env, args[NUM_2], &flen);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
                 "fd:%{public}d, foff:%{public}d, flen:%{public}d!", fd, foff, flen);

    napi_value exportInstance;
    if (napi_get_named_property(env, thisArg, OH_NATIVE_XCOMPONENT_OBJ, &exportInstance) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender",
                     "NapiDrawPattern: napi_get_named_property fail");
        return nullptr;
    }

    OH_NativeXComponent *nativeXComponent = nullptr;
    if (napi_unwrap(env, exportInstance, reinterpret_cast<void **>(&nativeXComponent)) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: napi_unwrap fail");
        return nullptr;
    }

    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {'\0'};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(nativeXComponent, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender",
                     "NapiDrawPattern: Unable to get XComponent id");
        return nullptr;
    }

    std::string id(idStr);
    PluginRender *render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->eglCore_->fd_ = fd;
        render->eglCore_->foff_ = foff;
        render->eglCore_->flen_ = flen;
        render->eglCore_->DrawBmp(fd, foff, flen, hasDraw_);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "render->eglCore_->Draw() executed");
    }
    return nullptr;
}

struct RescontCallbackData {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
    unsigned char *buffer = nullptr;
    uint32_t fd = 0;
    uint32_t foff = 0;
    uint32_t flen = 0;
    uint32_t blen = 0;
    napi_value result = nullptr;
};

static void RescontExecuteCB(napi_env env, void *data)
{
    RescontCallbackData *callbackData = reinterpret_cast<RescontCallbackData *>(data);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
        "RescontExecuteCB blen：%{public}d", callbackData->fd);

    int ret = 0;
    uint32_t fbufLen = 8192;
    unsigned char *fbuf = (unsigned char *)av_malloc(fbufLen);
    char dumpBuf[256];

    uint32_t fd = callbackData->fd;
    uint32_t foff = callbackData->foff;
    uint32_t flen = callbackData->flen;
    
    AVFormatContext *formatContext = NULL;
    AVIOContext *avioContext = nullptr;
    AVCodecContext *videoDecCtx = NULL;
    AVCodecContext *audioDecCtx = NULL;
    AVFrame *frame = NULL;
    AVPacket *pkt = NULL;
    int videoFrameCount = 0;
    int audioFrameCount = 0;
    
    int videoStreamIdx = -1;
    int audioStreamIdx = -1;
    
    FILE *file = fdopen(fd, "r");
    if (file == NULL) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "NapiGetInfo fdopen failed!");
        free(fbuf);
        return;
    }
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "fdopen ");
    // 取文件
    if (fseek(file, foff, SEEK_SET) != 0) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiGetInfo fseek failed!");
        fclose(file);
        free(fbuf);
        return;
    }
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "fseek %{public}ld", foff);
    avioContext = avio_alloc_context(fbuf, fbufLen, 0, (void *)file, &custom_avio_read_packet, NULL, NULL);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "avio_alloc_context");
    if (!avioContext) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "avio_alloc_context failed");
        av_free(avioContext->buffer);
        avio_context_free(&avioContext);
        fclose(file);
        return;
    }
    
    formatContext = avformat_alloc_context();
    if (!formatContext) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "avformat_alloc_context failed");
        av_free(avioContext->buffer);
        avio_context_free(&avioContext);
        fclose(file);
        return;
    }
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "avformat_alloc_context");
    formatContext->pb = avioContext;
    ret = avformat_open_input(&formatContext, NULL, NULL, NULL);
    if (ret < 0) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "avformat_open_input err %{public}d", ret);
        avformat_free_context(formatContext);
        av_free(avioContext->buffer);
        avio_context_free(&avioContext);
        fclose(file);
        return;
    }
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "avformat_open_input");
    // 获取流信息
    ret = avformat_find_stream_info(formatContext, NULL);
    if (ret < 0) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "avformat_find_stream_info err  %{public}d",
                     ret);
        avformat_close_input(&formatContext);
        fclose(file);
        return;
    }

    napi_value videoRes;
    napi_value audioRes;
    if (open_codec_context(&videoStreamIdx, &videoDecCtx, formatContext, AVMEDIA_TYPE_VIDEO) >= 0) {
        avcodec_string(dumpBuf, sizeof(dumpBuf), videoDecCtx, 0);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "video[%{public}s]", dumpBuf);
        napi_create_string_utf8(env, dumpBuf, strlen(dumpBuf), &videoRes);
    }
    if (open_codec_context(&audioStreamIdx, &audioDecCtx, formatContext, AVMEDIA_TYPE_AUDIO) >= 0) {
        avcodec_string(dumpBuf, sizeof(dumpBuf), audioDecCtx, 0);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "audio[%{public}s]", dumpBuf);
        napi_create_string_utf8(env, dumpBuf, strlen(dumpBuf), &audioRes);
    }

    int64_t hours = 0;
    int64_t mins = 0;
    int64_t secs = 0;
    int64_t us = 0;
    int64_t duration = formatContext->duration + (formatContext->duration <= INT64_MAX - 5000 ? 5000 : 0);
    secs = duration / AV_TIME_BASE;
    us = duration % AV_TIME_BASE;
    mins = secs / PARAM60;
    secs %= PARAM60;
    hours = mins / PARAM60;
    mins %= PARAM60;
    int ssecs = 0;
    int sus = 0;
    av_log(NULL, AV_LOG_INFO, ", start: ");
    ssecs = llabs(formatContext->start_time / AV_TIME_BASE);
    sus = llabs(formatContext->start_time % AV_TIME_BASE);
    
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
        "duration[%{public}02d:%{public}02d:%{public}02d.%{public}2d],"
        " start[%{public}d:%{public}06d], bitrate[%{public}d]",
        hours, mins, secs, (PARAM100 * us) / AV_TIME_BASE,
        ssecs, (int) av_rescale(sus, PARAM100W, AV_TIME_BASE), formatContext->bit_rate / PARAM1000);

    frame = av_frame_alloc();
    if (!frame) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "Could not allocate frame\n");
        ret = AVERROR(ENOMEM);
        goto end;
    }

    pkt = av_packet_alloc();
    if (!pkt) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "Could not allocate packet\n");
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* read frames from the file */
    while (av_read_frame(formatContext, pkt) >= 0) {
        // check if the packet belongs to a stream we are interested in, otherwise
        // skip it
        if (pkt->stream_index == videoStreamIdx) {
            ret = decode_packet(videoDecCtx, frame, pkt);
            if (0 && ret == 0) {
                OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "decode video "
                "w[%{public}d]:h[%{public}d] pict_type[%{public}d]]]\n", frame->width, frame->height, frame->pict_type);
            }
        } else if (pkt->stream_index == audioStreamIdx) {
            ret = decode_packet(audioDecCtx, frame, pkt);
            if (0 && ret == 0) {
                OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
                    "decode audio "
                    "nbs[%{public}d]:pts[%{public}d] duration[%{public}d]]]\n",
                    frame->nb_samples, av_ts2timestr(frame->pts, &audioDecCtx->time_base), frame->duration);
            }
        }
        
        av_packet_unref(pkt);
        if (ret < 0) {
            break;
        }
    }
end:
    napi_value instance;
    napi_create_object(env, &instance);
    napi_set_named_property(env, instance, "videoDec", videoRes);
    napi_set_named_property(env, instance, "audioDec", audioRes);
    callbackData->result = instance;
    
    avcodec_free_context(&videoDecCtx);
    avcodec_free_context(&audioDecCtx);
    avformat_close_input(&formatContext);
    av_packet_free(&pkt);
    av_frame_free(&frame);
}

static void RescontCompleteCB(napi_env env, napi_status status, void *data)
{
    RescontCallbackData *callbackData = reinterpret_cast<RescontCallbackData *>(data);
    napi_value result = callbackData->result;
    if (callbackData->result != nullptr) {
        napi_resolve_deferred(env, callbackData->deferred, result);
    } else {
        napi_reject_deferred(env, callbackData->deferred, result);
    }

    napi_delete_async_work(env, callbackData->asyncWork);
    delete callbackData;
}

// NAPI registration method type napi_callback. If no value is returned, nullptr is returned.
napi_value PluginRender::NapiGetInfo(napi_env env, napi_callback_info info)
{
    size_t argc = NUM_3;
    napi_value args[NUM_3];
    uint32_t fd = 0;
    uint32_t foff = 0;
    uint32_t flen = 0;

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "NapiGetInfo");
    if ((env == nullptr) || (info == nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiGetInfo: env or info is null");
        return nullptr;
    }

    napi_value thisArg;
    if (napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiGetInfo: napi_get_cb_info fail");
        return nullptr;
    }

    napi_get_value_uint32(env, args[0], &fd);
    napi_get_value_uint32(env, args[1], &foff);
    napi_get_value_uint32(env, args[NUM_2], &flen);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
                 "fd:%{public}d, foff:%{public}d, flen:%{public}d!", fd, foff, flen);

    napi_value exportInstance;
    if (napi_get_named_property(env, thisArg, OH_NATIVE_XCOMPONENT_OBJ, &exportInstance) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender",
                     "NapiGetInfo: napi_get_named_property fail");
        return nullptr;
    }

    OH_NativeXComponent *nativeXComponent = nullptr;
    if (napi_unwrap(env, exportInstance, reinterpret_cast<void **>(&nativeXComponent)) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiGetInfo: napi_unwrap fail");
        return nullptr;
    }

    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = {'\0'};
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(nativeXComponent, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender",
                     "NapiGetInfo: Unable to get XComponent id");
        return nullptr;
    }

    std::string id(idStr);
    PluginRender *render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->eglCore_->fd_ = fd;
        render->eglCore_->foff_ = foff;
        render->eglCore_->flen_ = flen;
        
        napi_value promise = nullptr;
        napi_deferred deferred = nullptr;
        napi_create_promise(env, &deferred, &promise);

        auto callbackData = new RescontCallbackData();
        callbackData->deferred = deferred;

        void *arrayData = nullptr;
        size_t length = 0;
        napi_valuetype result = napi_undefined;
        napi_typeof(env, args[0], &result);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "napi_valuetype ：%{public}d", result);
        napi_typedarray_type type = napi_int8_array;

        napi_value arraybuffer = nullptr;
        size_t byteOffset = 0;
        napi_get_typedarray_info(env, args[0], &type, &length, &arrayData, &arraybuffer, &byteOffset);

        callbackData->buffer = (unsigned char *)arrayData;
        callbackData->fd = fd;
        callbackData->foff = foff;
        callbackData->flen = flen;
        callbackData->blen = length;
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
            "AsyncRescont buffer：%{public}p", callbackData->buffer);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
            "AsyncRescont blen：%{public}d", callbackData->blen);

        napi_value resourceName = nullptr;
        napi_create_string_utf8(env, "RescontAsyncCallback", NAPI_AUTO_LENGTH, &resourceName);
        // 创建异步任务
        napi_create_async_work(env, nullptr, resourceName, RescontExecuteCB, RescontCompleteCB, callbackData,
            &callbackData->asyncWork);
        // 将异步任务加入队列
        napi_queue_async_work(env, callbackData->asyncWork);

        return promise;
    }
    return nullptr;
}

// NAPI registration method type napi_callback. If no value is returned, nullptr is returned.
napi_value PluginRender::NapiDrawPattern(napi_env env, napi_callback_info info)
{
    size_t argc = NUM_3;
    napi_value args[NUM_3];
    uint32_t fd = 0;
    uint32_t foff = 0;
    uint32_t flen = 0;

    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern");
    if ((env == nullptr) || (info == nullptr)) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: env or info is null");
        return nullptr;
    }

    napi_value thisArg;
    if (napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: napi_get_cb_info fail");
        return nullptr;
    }

    napi_get_value_uint32(env, args[0], &fd);
    napi_get_value_uint32(env, args[1], &foff);
    napi_get_value_uint32(env, args[NUM_2], &flen);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN,
        "PluginRender", "fd:%{public}d, foff:%{public}d, flen:%{public}d!", fd, foff, flen);

    napi_value exportInstance;
    if (napi_get_named_property(env, thisArg, OH_NATIVE_XCOMPONENT_OBJ, &exportInstance) != napi_ok) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender",
            "NapiDrawPattern: napi_get_named_property fail");
        return nullptr;
    }

    OH_NativeXComponent* nativeXComponent = nullptr;
    if (napi_unwrap(env, exportInstance, reinterpret_cast<void**>(&nativeXComponent)) != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: napi_unwrap fail");
        return nullptr;
    }

    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = { '\0' };
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(nativeXComponent, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "NapiDrawPattern: Unable to get XComponent id");
        return nullptr;
    }

    std::string id(idStr);
    PluginRender* render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->eglCore_->fd_ = fd;
        render->eglCore_->foff_ = foff;
        render->eglCore_->flen_ = flen;
        render->eglCore_->DrawBmp(fd, foff, flen, hasDraw_);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "render->eglCore_->Draw() executed");
    }
    return nullptr;
}

void PluginRender::Release(std::string& id)
{
    PluginRender* render = PluginRender::GetInstance(id);
    if (render != nullptr) {
        render->eglCore_->Release();
        delete render->eglCore_;
        render->eglCore_ = nullptr;
        delete render;
        render = nullptr;
        instance_.erase(instance_.find(id));
    }
}

void PluginRender::OnSurfaceChanged(OH_NativeXComponent* component, void* window)
{
    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = { '\0' };
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(component, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "OnSurfaceChanged: Unable to get XComponent id");
        return;
    }

    std::string id(idStr);
    PluginRender* render = PluginRender::GetInstance(id);
    double offsetX;
    double offsetY;
    OH_NativeXComponent_GetXComponentOffset(component, window, &offsetX, &offsetY);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "OH_NativeXComponent_GetXComponentOffset",
        "offsetX = %{public}lf, offsetY = %{public}lf", offsetX, offsetY);
    uint64_t width;
    uint64_t height;
    OH_NativeXComponent_GetXComponentSize(component, window, &width, &height);
    if (render != nullptr) {
        render->eglCore_->UpdateSize(width, height);
    }
}

void PluginRender::OnTouchEvent(OH_NativeXComponent* component, void* window)
{
    char idStr[OH_XCOMPONENT_ID_LEN_MAX + 1] = { '\0' };
    uint64_t idSize = OH_XCOMPONENT_ID_LEN_MAX + 1;
    if (OH_NativeXComponent_GetXComponentId(component, idStr, &idSize) != OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "Callback", "DispatchTouchEventCB: Unable to get XComponent id");
        return;
    }
    OH_NativeXComponent_TouchEvent touchEvent;
    OH_NativeXComponent_GetTouchEvent(component, window, &touchEvent);
    std::string id(idStr);
    PluginRender* render = PluginRender::GetInstance(id);
    if (render != nullptr && touchEvent.type == OH_NativeXComponent_TouchEventType::OH_NATIVEXCOMPONENT_UP) {
        render->eglCore_->ChangeColor(hasChangeColor_);
    }
    float tiltX = 0.0f;
    float tiltY = 0.0f;
    OH_NativeXComponent_TouchPointToolType toolType =
        OH_NativeXComponent_TouchPointToolType::OH_NATIVEXCOMPONENT_TOOL_TYPE_UNKNOWN;
    OH_NativeXComponent_GetTouchPointToolType(component, 0, &toolType);
    OH_NativeXComponent_GetTouchPointTiltX(component, 0, &tiltX);
    OH_NativeXComponent_GetTouchPointTiltY(component, 0, &tiltY);
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "OnTouchEvent",
        "touch info: toolType = %{public}d, tiltX = %{public}lf, tiltY = %{public}lf", toolType, tiltX, tiltY);
}

void PluginRender::RegisterCallback(OH_NativeXComponent* nativeXComponent)
{
    renderCallback_.OnSurfaceCreated = OnSurfaceCreatedCB;
    renderCallback_.OnSurfaceChanged = OnSurfaceChangedCB;
    renderCallback_.OnSurfaceDestroyed = OnSurfaceDestroyedCB;
    renderCallback_.DispatchTouchEvent = DispatchTouchEventCB;
    OH_NativeXComponent_RegisterCallback(nativeXComponent, &renderCallback_);

    mouseCallback_.DispatchMouseEvent = DispatchMouseEventCB;
    mouseCallback_.DispatchHoverEvent = DispatchHoverEventCB;
    OH_NativeXComponent_RegisterMouseEventCallback(nativeXComponent, &mouseCallback_);

    OH_NativeXComponent_RegisterFocusEventCallback(nativeXComponent, OnFocusEventCB);
    OH_NativeXComponent_RegisterKeyEventCallback(nativeXComponent, OnKeyEventCB);
    OH_NativeXComponent_RegisterBlurEventCallback(nativeXComponent, OnBlurEventCB);
}

void PluginRender::OnMouseEvent(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "OnMouseEvent");
    OH_NativeXComponent_MouseEvent mouseEvent;
    int32_t ret = OH_NativeXComponent_GetMouseEvent(component, window, &mouseEvent);
    if (ret == OH_NATIVEXCOMPONENT_RESULT_SUCCESS) {
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
            "MouseEvent Info: x = %{public}f, y = %{public}f, action = %{public}d, button = %{public}d", mouseEvent.x,
            mouseEvent.y, mouseEvent.action, mouseEvent.button);
    } else {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "GetMouseEvent error");
    }
}

void PluginRender::OnHoverEvent(OH_NativeXComponent* component, bool isHover)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "OnHoverEvent isHover_ = %{public}d", isHover);
}

void PluginRender::OnFocusEvent(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "OnFocusEvent");
}

void PluginRender::OnBlurEvent(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "OnBlurEvent");
}

void PluginRender::OnKeyEvent(OH_NativeXComponent* component, void* window)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender", "OnKeyEvent");

    OH_NativeXComponent_KeyEvent* keyEvent = nullptr;
    if (OH_NativeXComponent_GetKeyEvent(component, &keyEvent) >= 0) {
        OH_NativeXComponent_KeyAction action;
        OH_NativeXComponent_GetKeyEventAction(keyEvent, &action);
        OH_NativeXComponent_KeyCode code;
        OH_NativeXComponent_GetKeyEventCode(keyEvent, &code);
        OH_NativeXComponent_EventSourceType sourceType;
        OH_NativeXComponent_GetKeyEventSourceType(keyEvent, &sourceType);
        int64_t deviceId;
        OH_NativeXComponent_GetKeyEventDeviceId(keyEvent, &deviceId);
        int64_t timeStamp;
        OH_NativeXComponent_GetKeyEventTimestamp(keyEvent, &timeStamp);
        OH_LOG_Print(LOG_APP, LOG_INFO, LOG_PRINT_DOMAIN, "PluginRender",
            "KeyEvent Info: action=%{public}d, code=%{public}d, sourceType=%{public}d, deviceId=%{public}ld, "
            "timeStamp=%{public}ld",
            action, code, sourceType, deviceId, timeStamp);
    } else {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "PluginRender", "GetKeyEvent error");
    }
}

napi_value PluginRender::TestGetXComponentStatus(napi_env env, napi_callback_info info)
{
    napi_value hasDraw;
    napi_value hasChangeColor;

    napi_status ret = napi_create_int32(env, hasDraw_, &(hasDraw));
    if (ret != napi_ok) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "TestGetXComponentStatus", "napi_create_int32 hasDraw_ error");
        return nullptr;
    }
    ret = napi_create_int32(env, hasChangeColor_, &(hasChangeColor));
    if (ret != napi_ok) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "TestGetXComponentStatus", "napi_create_int32 hasChangeColor_ error");
        return nullptr;
    }

    napi_value obj;
    ret = napi_create_object(env, &obj);
    if (ret != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "TestGetXComponentStatus", "napi_create_object error");
        return nullptr;
    }
    ret = napi_set_named_property(env, obj, "hasDraw", hasDraw);
    if (ret != napi_ok) {
        OH_LOG_Print(
            LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "TestGetXComponentStatus", "napi_set_named_property hasDraw error");
        return nullptr;
    }
    ret = napi_set_named_property(env, obj, "hasChangeColor", hasChangeColor);
    if (ret != napi_ok) {
        OH_LOG_Print(LOG_APP, LOG_ERROR, LOG_PRINT_DOMAIN, "TestGetXComponentStatus",
            "napi_set_named_property hasChangeColor error");
        return nullptr;
    }
    return obj;
}
} // namespace NativeXComponentSample
