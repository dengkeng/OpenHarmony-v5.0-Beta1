/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hcfrandcreate_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "blob.h"
#include "rand.h"
#include "result.h"

namespace OHOS {
    bool HcfRandCreateFuzzTest(const uint8_t* data, size_t size)
    {
        HcfRand *randObj = nullptr;
        HcfResult res = HcfRandCreate(&randObj);
        if (res != HCF_SUCCESS) {
            return false;
        }
        struct HcfBlob randomBlob = { 0 };
        (void)randObj->generateRandom(randObj, size, &randomBlob);
        struct HcfBlob seedBlob = { 0 };
        (void)randObj->setSeed(randObj, &seedBlob);
        (void)randObj->getAlgoName(randObj);
        HcfBlobDataFree(&randomBlob);
        HcfBlobDataFree(&seedBlob);
        HcfObjDestroy(randObj);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfRandCreateFuzzTest(data, size);
    return 0;
}

