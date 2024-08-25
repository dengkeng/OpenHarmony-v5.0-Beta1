/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CF_OBJECT_CERT_H
#define CF_OBJECT_CERT_H

#include "cf_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CfCertCreate(const CfEncodingBlob *in, CfBase **obj);

int32_t CfCertGet(const CfBase *obj, const CfParamSet *in, CfParamSet **out);

int32_t CfCertCheck(const CfBase *obj, const CfParamSet *in, CfParamSet **out);

void CfCertDestroy(CfBase **obj);

#ifdef __cplusplus
}
#endif

#endif /* CF_OBJECT_CERT_H */