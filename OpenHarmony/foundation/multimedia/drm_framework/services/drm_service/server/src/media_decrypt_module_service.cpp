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

#include <memory>
#include <unistd.h>
#include <securec.h>
#include "ashmem.h"
#include "drm_dfx.h"
#include "drm_trace.h"
#include "drm_dfx_utils.h"
#include "drm_error_code.h"
#include "hitrace/tracechain.h"
#include "ipc_skeleton.h"
#include "media_decrypt_module_service.h"
#include "meta/meta.h"

namespace OHOS {
namespace DrmStandard {
MediaDecryptModuleService::MediaDecryptModuleService(
    sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> hdiMediaDecryptModule)
{
    DRM_DEBUG_LOG("MediaDecryptModuleService::MediaDecryptModuleService");
    hdiMediaDecryptModule_ = hdiMediaDecryptModule;
    int32_t uid = IPCSkeleton::GetCallingUid();
    instanceId_ = HiTraceChain::GetId().GetChainId();
    DrmEvent::GetInstance().CreateMediaInfo(uid, instanceId_);
}

MediaDecryptModuleService::~MediaDecryptModuleService()
{
    DRM_INFO_LOG("MediaDecryptModuleService::~MediaDecryptModuleService enter.");
    std::lock_guard<std::mutex> lock(moduleLock_);
    if (hdiMediaDecryptModule_ != nullptr) {
        Release();
    }
    ReportDecryptionStatisticEvent();
    DRM_INFO_LOG("MediaDecryptModuleService::~MediaDecryptModuleService exit.");
}

int32_t MediaDecryptModuleService::Release()
{
    DrmTrace trace("MediaDecryptModuleService::Release");
    DRM_INFO_LOG("MediaDecryptModuleService::Release enter.");
    int32_t errCode = DRM_OK;
    if (hdiMediaDecryptModule_ != nullptr) {
        DRM_INFO_LOG("hdiMediaDecryptModule_ call Close");
        hdiMediaDecryptModule_ = nullptr;
    }
    DRM_INFO_LOG("MediaDecryptModuleService::Release exit.");
    return errCode;
}

int32_t MediaDecryptModuleService::DecryptMediaData(bool secureDecodrtState,
    IMediaDecryptModuleService::CryptInfo &cryptInfo, IMediaDecryptModuleService::DrmBuffer &srcBuffer,
    IMediaDecryptModuleService::DrmBuffer &dstBuffer)
{
    DrmTrace trace("MediaDecryptModuleService::DecryptMediaData");
    DRM_INFO_LOG("MediaDecryptModuleService::DecryptMediaData enter.");
    int32_t ret = DRM_OK;
    uint32_t bufLen = 0;
    auto timeBefore = std::chrono::system_clock::now();
    OHOS::HDI::Drm::V1_0::CryptoInfo cryptInfoTmp;
    SetCryptInfo(cryptInfoTmp, cryptInfo, bufLen);
    decryptStatustics_.decryptTimes++;
    decryptStatustics_.decryptSumSize += bufLen;
    if (decryptStatustics_.decryptMaxSize < bufLen) {
        decryptStatustics_.decryptMaxSize = bufLen;
    }
    OHOS::HDI::Drm::V1_0::DrmBuffer drmSrcBuffer;
    OHOS::HDI::Drm::V1_0::DrmBuffer drmDstBuffer;
    memset_s(&drmSrcBuffer, sizeof(drmSrcBuffer), 0, sizeof(drmSrcBuffer));
    memset_s(&drmDstBuffer, sizeof(drmSrcBuffer), 0, sizeof(drmDstBuffer));
    SetDrmBufferInfo(&drmSrcBuffer, &drmDstBuffer, srcBuffer, dstBuffer, bufLen);
    ret = hdiMediaDecryptModule_->DecryptMediaData(secureDecodrtState, cryptInfoTmp, drmSrcBuffer, drmDstBuffer);
    auto timeAfter = std::chrono::system_clock::now();
    uint32_t durationAsInt = CalculateTimeDiff(timeBefore, timeAfter);
    errCode_ = ret;
    decryptStatustics_.decryptSumDuration += durationAsInt;
    if (decryptStatustics_.decryptMaxDuration < durationAsInt) {
        decryptStatustics_.decryptMaxDuration = durationAsInt;
    }
    if (ret != DRM_OK) {
        (void)::close(srcBuffer.fd);
        (void)::close(dstBuffer.fd);
        DRM_ERR_LOG("MediaDecryptModuleService::DecryptMediaData failed.");
        std::string decryptKeyId;
        decryptKeyId.assign(cryptInfoTmp.keyId.begin(), cryptInfoTmp.keyId.end());
        std::string decryptKeyIv;
        decryptKeyIv.assign(cryptInfoTmp.iv.begin(), cryptInfoTmp.iv.end());
        ReportDecryptionFaultEvent(ret, "DecryptMediaData failed",
            std::to_string(static_cast<int32_t>(cryptInfoTmp.type)), decryptKeyId, decryptKeyIv);
        return ret;
    }
    (void)::close(srcBuffer.fd);
    (void)::close(dstBuffer.fd);
    errMessage_ = "no error";
    DRM_INFO_LOG("MediaDecryptModuleService::DecryptMediaData exit.");
    return ret;
}

uint32_t MediaDecryptModuleService::CalculateTimeDiff(std::chrono::system_clock::time_point timeBefore,
    std::chrono::system_clock::time_point timeAfter)
{
    auto duration = timeAfter - timeBefore;
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    return static_cast<uint32_t>(milliseconds.count());
}

void MediaDecryptModuleService::SetCryptInfo(OHOS::HDI::Drm::V1_0::CryptoInfo &cryptInfoTmp,
    IMediaDecryptModuleService::CryptInfo &cryptInfo, uint32_t &bufLen)
{
    cryptInfoTmp.type = (OHOS::HDI::Drm::V1_0::CryptoAlgorithmType)cryptInfo.type;
    cryptInfoTmp.keyId.assign(cryptInfo.keyId.begin(), cryptInfo.keyId.end());
    cryptInfoTmp.iv.assign(cryptInfo.iv.begin(), cryptInfo.iv.end());
    cryptInfoTmp.pattern.encryptBlocks = cryptInfo.pattern.encryptBlocks;
    cryptInfoTmp.pattern.skipBlocks = cryptInfo.pattern.skipBlocks;
    cryptInfoTmp.subSamples.resize(cryptInfo.subSample.size());
    for (size_t i = 0; i < cryptInfo.subSample.size(); i++) {
        cryptInfoTmp.subSamples[i].clearHeaderLen = cryptInfo.subSample[i].clearHeaderLen;
        bufLen += cryptInfoTmp.subSamples[i].clearHeaderLen;
        cryptInfoTmp.subSamples[i].payLoadLen = cryptInfo.subSample[i].payLoadLen;
        bufLen += cryptInfoTmp.subSamples[i].payLoadLen;
    }
}

void MediaDecryptModuleService::SetDrmBufferInfo(OHOS::HDI::Drm::V1_0::DrmBuffer* drmSrcBuffer,
    OHOS::HDI::Drm::V1_0::DrmBuffer* drmDstBuffer, IMediaDecryptModuleService::DrmBuffer &srcBuffer,
    IMediaDecryptModuleService::DrmBuffer &dstBuffer, uint32_t bufLen)
{
    DRM_INFO_LOG("MediaDecryptModuleService::SetDrmBufferInfo");
    drmSrcBuffer->bufferType = srcBuffer.bufferType;
    drmSrcBuffer->fd = srcBuffer.fd;
    drmSrcBuffer->bufferLen = bufLen;
    drmSrcBuffer->allocLen = srcBuffer.allocLen;
    drmSrcBuffer->filledLen = srcBuffer.filledLen;
    drmSrcBuffer->offset = srcBuffer.offset;
    drmSrcBuffer->fd = srcBuffer.fd;

    drmDstBuffer->bufferType = dstBuffer.bufferType;
    drmDstBuffer->fd = dstBuffer.fd;
    drmDstBuffer->bufferLen = bufLen;
    drmDstBuffer->allocLen = dstBuffer.allocLen;
    drmDstBuffer->filledLen = dstBuffer.filledLen;
    drmDstBuffer->offset = dstBuffer.offset;
    drmDstBuffer->sharedMemType = dstBuffer.sharedMemType;
}

void MediaDecryptModuleService::ReportDecryptionStatisticEvent()
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    meta->SetData(Media::Tag::DRM_APP_NAME, GetClientBundleName(IPCSkeleton::GetCallingUid()));
    meta->SetData(Media::Tag::DRM_INSTANCE_ID, std::to_string(instanceId_));
    meta->SetData(Media::Tag::DRM_ERROR_CODE, errCode_);
    meta->SetData(Media::Tag::DRM_ERROR_MESG, errMessage_);
    meta->SetData(Media::Tag::DRM_DECRYPT_TIMES, decryptStatustics_.decryptTimes);
    if (decryptStatustics_.decryptTimes != 0) {
        meta->SetData(Media::Tag::DRM_DECRYPT_AVG_SIZE,
            static_cast<uint32_t>(decryptStatustics_.decryptSumSize/decryptStatustics_.decryptTimes));
        meta->SetData(Media::Tag::DRM_DECRYPT_AVG_DURATION,
            static_cast<uint32_t>(decryptStatustics_.decryptSumDuration/decryptStatustics_.decryptTimes));
    } else {
        meta->SetData(Media::Tag::DRM_DECRYPT_AVG_SIZE, 0);
        meta->SetData(Media::Tag::DRM_DECRYPT_AVG_DURATION, 0);
    }
    meta->SetData(Media::Tag::DRM_DECRYPT_MAX_SIZE, decryptStatustics_.decryptMaxSize);
    meta->SetData(Media::Tag::DRM_DECRYPT_MAX_DURATION, decryptStatustics_.decryptMaxDuration);
    DrmEvent::GetInstance().AppendMediaInfo(meta, instanceId_);
    DrmEvent::GetInstance().ReportMediaInfo(instanceId_);
}
} // DrmStandard
} // OHOS