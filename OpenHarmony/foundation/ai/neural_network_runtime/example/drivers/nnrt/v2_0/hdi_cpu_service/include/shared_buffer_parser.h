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

#ifndef OHOS_HDI_NNRT_V2_0_SHARED_BUFFER_PARSER_H
#define OHOS_HDI_NNRT_V2_0_SHARED_BUFFER_PARSER_H

#include "ashmem.h"
#include "v2_0/nnrt_types.h"

namespace OHOS {
namespace HDI {
namespace Nnrt {
namespace V2_0 {
namespace {
const int INVALID_FD = -1;
}

class SharedBufferParser {
public:
    SharedBufferParser() {};
    ~SharedBufferParser();

    int32_t Init(const SharedBuffer& buffer);
    int32_t Init(const std::string& name, int32_t size);
    void* GetBufferPtr();
    SharedBuffer GetBuffer();

private:
    SharedBuffer m_buffer;
    sptr<Ashmem> m_ashptr {nullptr};
    void* m_bufferAddr {nullptr};
};
} // V2_0
} // Nnrt
} // HDI
} // OHOS
#endif // OHOS_HDI_NNR_V2_0_SHARED_BUFFER_PARSER_H