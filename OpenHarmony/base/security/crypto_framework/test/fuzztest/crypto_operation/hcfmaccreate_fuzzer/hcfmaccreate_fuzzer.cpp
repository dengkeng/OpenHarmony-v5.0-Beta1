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

#include "hcfmaccreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "blob.h"
#include "mac.h"
#include "result.h"
#include "sym_key_generator.h"

namespace OHOS {
    static const int KEY_LEN = 16;
    static const int TEST_DATA_LEN = 12;

    static void TestMac(void)
    {
        HcfMac *macObj = nullptr;
        HcfResult res = HcfMacCreate("SHA1", &macObj);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfSymKeyGenerator *generator = nullptr;
        (void)HcfSymKeyGeneratorCreate("AES128", &generator);
        char testKey[] = "abcdefghijklmnop";
        uint32_t testKeyLen = KEY_LEN;
        HcfSymKey *key = nullptr;
        HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
        generator->convertSymKey(generator, &keyMaterialBlob, &key);

        char testData[] = "My test data";
        uint32_t testDataLen = TEST_DATA_LEN;
        HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = testDataLen};
        (void)macObj->init(macObj, key);
        (void)macObj->update(macObj, &inBlob);
        HcfBlob outBlob = { 0 };
        (void)macObj->doFinal(macObj, &outBlob);
        (void)macObj->getAlgoName(macObj);
        (void)macObj->getMacLength(macObj);
        HcfBlobDataClearAndFree(&outBlob);
        HcfObjDestroy(macObj);
        HcfObjDestroy(key);
        HcfObjDestroy(generator);
    }

    bool HcfMacCreateFuzzTest(const uint8_t* data, size_t size)
    {
        TestMac();
        HcfMac *macObj = nullptr;
        std::string alg(reinterpret_cast<const char *>(data), size);
        HcfResult res = HcfMacCreate(alg.c_str(), &macObj);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(macObj);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfMacCreateFuzzTest(data, size);
    return 0;
}
