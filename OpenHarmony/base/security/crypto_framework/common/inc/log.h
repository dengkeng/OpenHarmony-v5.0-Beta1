/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCF_LOG_H
#define HCF_LOG_H

#include <stdint.h>
#include <stdlib.h>

#ifdef HILOG_ENABLE

enum HcfLogLevel {
    HCF_LOG_LEVEL_I,
    HCF_LOG_LEVEL_E,
    HCF_LOG_LEVEL_W,
    HCF_LOG_LEVEL_D,
};

#ifdef __cplusplus
extern "C" {
#endif

void HcfLogPrint(uint32_t hcfLogLevel, const char *funcName, uint32_t lineNo, const char *format, ...);

#ifdef __cplusplus
}
#endif

#undef LOG_TAG
#define LOG_TAG "HCF"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F0A /* Security subsystem's domain id */

#define LOGI(...) HcfLogPrint(HCF_LOG_LEVEL_I, __func__, __LINE__, __VA_ARGS__)
#define LOGW(...) HcfLogPrint(HCF_LOG_LEVEL_W, __func__, __LINE__, __VA_ARGS__)
#define LOGE(...) HcfLogPrint(HCF_LOG_LEVEL_E, __func__, __LINE__, __VA_ARGS__)
#define LOGD(...) HcfLogPrint(HCF_LOG_LEVEL_D, __func__, __LINE__, __VA_ARGS__)
#else

#include <stdio.h>

#define LOGD(fmt, ...) printf("[HCF][D][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGI(fmt, ...) printf("[HCF][I][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[HCF][W][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[HCF][E][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)

#endif
#endif
