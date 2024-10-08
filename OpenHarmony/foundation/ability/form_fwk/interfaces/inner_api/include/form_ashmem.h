/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_ASHMEM_H
#define OHOS_FORM_FWK_FORM_ASHMEM_H

#include "ashmem.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormAshmem
 * Defines form ashmem.
 */
class FormAshmem : public Parcelable {
public:
    FormAshmem() = default;
    ~FormAshmem();

    bool WriteToAshmem(std::string name, char *data, int32_t size);
    int32_t GetAshmemSize();
    int32_t GetAshmemFd();

    virtual bool Marshalling(Parcel &parcel) const override;
    static FormAshmem* Unmarshalling(Parcel &parcel);

    sptr<Ashmem> GetAshmem() const;
private:
    bool ReadFromParcel(Parcel &parcel);

    sptr<Ashmem> ashmem_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_ASHMEM_H
