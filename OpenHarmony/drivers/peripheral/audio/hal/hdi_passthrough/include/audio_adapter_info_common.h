/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef AUDIO_ADAPTER_INFO_COMMON_H
#define AUDIO_ADAPTER_INFO_COMMON_H

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "audio_internal.h"
#include "audio_types.h"
#include "securec.h"

#define AUDIO_PRIMARY_ID_MIN        0
#define AUDIO_PRIMARY_ID_MAX        10

#define AUDIO_PRIMARY_EXT_ID_MIN    11
#define AUDIO_PRIMARY_EXT_ID_MAX    20

#define AUDIO_HDMI_ID_MIN    11
#define AUDIO_HDMI_ID_MAX    20

#define AUDIO_USB_ID_MIN            21
#define AUDIO_USB_ID_MAX            30

#define AUDIO_A2DP_ID_MIN           31
#define AUDIO_A2DP_ID_MAX           40

enum AudioAdapterType {
    AUDIO_ADAPTER_PRIMARY = 0,  /* internal sound card */
    AUDIO_ADAPTER_PRIMARY_EXT,  /* extern sound card */
    AUDIO_ADAPTER_HDMI,         /* hdmi sound card */
    AUDIO_ADAPTER_USB,         /* usb sound card */
    AUDIO_ADAPTER_A2DP,         /* blue tooth sound card */
    AUDIO_ADAPTER_MAX,          /* Invalid value. */
};

enum AudioAdapterType MatchAdapterType(const char *adapterName, uint32_t portId);
int32_t AudioAdapterCheckPortId(const char *adapterName, uint32_t portId);

struct AudioAdapterDescriptor *AudioAdapterGetConfigDescs(void);
int32_t AudioAdapterGetAdapterNum(void);
int32_t AudioAdapterExist(const char *adapterName);
int32_t InitPortForCapabilitySub(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex);
int32_t KeyValueListToMap(const char *keyValueList, struct ParamValMap mParamValMap[], int32_t *count);
int32_t AddElementToList(char *keyValueList, int32_t listLenth, const char *key, void *value);
int32_t GetErrorReason(int reason, char* reasonDesc);
int32_t GetCurrentTime(char *currentTime);
int32_t CheckAttrRoute(int32_t param);
int32_t CheckAttrChannel(uint32_t param);
int32_t TransferRoute(const char *value, int32_t *route);
int32_t TransferFormat(const char *value, int32_t *format);
int32_t TransferChannels(const char *value, uint32_t *channels);
int32_t TransferFrames(const char *value, uint64_t *frames);
int32_t TransferSampleRate(const char *value, uint32_t *sampleRate);
int32_t FormatToBits(enum AudioFormat format, uint32_t *formatBits);
int32_t BitsToFormat(enum AudioFormat *format, int32_t formatBits);
int32_t SetExtParam(const char *key, const char *value, struct ExtraParams *mExtraParams);
int32_t AudioSetExtraParams(const char *keyValueList, int32_t *count,
    struct ExtraParams *mExtraParams, int32_t *sumOk);
bool ReleaseAudioManagerObjectComm(const struct AudioManager *object);
void AudioAdapterReleaseDescs(const struct AudioAdapterDescriptor *descs, int32_t adapterNum);
#endif
