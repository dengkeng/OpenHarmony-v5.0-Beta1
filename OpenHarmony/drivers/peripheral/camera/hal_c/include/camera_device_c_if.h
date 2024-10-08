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

#ifndef HOS_CAMERA_DEVICE_C_IF_H
#define HOS_CAMERA_DEVICE_C_IF_H

#include "camera_types_c_if.h"
#include "stream_operator_c_if.h"
#include "camera_metadata_c_if.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CameraDeviceCallbackCIF {
    void (*OnError)(int type, int errorMsg);
    void (*OnResult)(uint64_t timestamp, CameraResultCIF* result);
} CameraDeviceCallbackCIF;

typedef struct CameraDeviceCIF {
    int (*GetStreamOperator)(StreamOperatorCallbackCIF callback, StreamOperatorCIF* op);
    int (*UpdateSettings)(CameraSettingCIF* settings);
    int (*SetResultMode)(int mode);
    int (*GetEnabledResults)(MetaTypeCIF** result, int* count);
    int (*EnableResult)(MetaTypeCIF* results, int count);
    int (*DisableResult)(MetaTypeCIF* results, int count);
    void (*Close)();
} CameraDeviceCIF;

#ifdef __cplusplus
}
#endif

#endif
