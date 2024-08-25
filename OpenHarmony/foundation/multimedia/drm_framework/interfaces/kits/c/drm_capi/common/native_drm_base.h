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

/**
 * @addtogroup Drm
 * @{
 *
 * @brief Provides APIs of Drm.
 * @since 11
 * @version 1.0
 */

/**
 * @file native_drm_base.h
 * @brief Defines the Drm MediaKeySystem and MediaKeySession struct.
 * @library libnative_drm.z.so
 * @Syscap SystemCapability.Multimedia.Drm.Core
 * @since 11
 * @version 1.0
 */

#ifndef NATIVE_DRM_BASE_H
#define NATIVE_DRM_BASE_H

#include <stdint.h>
#include <stdio.h>
#include <refbase.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief MediaKeySystem struct.
 *
 * @since 11
 * @version 1.0
 */
struct MediaKeySystem : public OHOS::RefBase {
    MediaKeySystem() = default;
    virtual ~MediaKeySystem() = default;
};

/**
 * @brief MediaKeySession struct.
 *
 * @since 11
 * @version 1.0
 */
struct MediaKeySession : public OHOS::RefBase {
    MediaKeySession() = default;
    virtual ~MediaKeySession() = default;
};

#ifdef __cplusplus
}
#endif

#endif // NATIVE_DRM_BASE_H