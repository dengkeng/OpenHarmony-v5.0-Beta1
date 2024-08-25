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

#include "hcfmdcreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "blob.h"
#include "md.h"
#include "result.h"

namespace OHOS {
    static const int TEST_DATA_LEN = 12;

    static void TestMd(void)
    {
        HcfMd *mdObj = nullptr;
        HcfResult res = HcfMdCreate("SHA1", &mdObj);
        if (res != HCF_SUCCESS) {
            return;
        }
        char testData[] = "My test data";
        uint32_t testDataLen = TEST_DATA_LEN;
        HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = testDataLen};
        (void)mdObj->update(mdObj, &inBlob);
        HcfBlob outBlob = { 0 };
        (void)mdObj->doFinal(mdObj, &outBlob);
        (void)mdObj->getAlgoName(mdObj);
        (void)mdObj->getMdLength(mdObj);
        HcfBlobDataClearAndFree(&outBlob);
        HcfObjDestroy(mdObj);
    }

    bool HcMdCreateFuzzTest(const uint8_t* data, size_t size)
    {
        TestMd();
        HcfMd *mdObj = nullptr;
        std::string alg(reinterpret_cast<const char *>(data), size);
        HcfResult res = HcfMdCreate(alg.c_str(), &mdObj);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(mdObj);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcMdCreateFuzzTest(data, size);
    return 0;
}
