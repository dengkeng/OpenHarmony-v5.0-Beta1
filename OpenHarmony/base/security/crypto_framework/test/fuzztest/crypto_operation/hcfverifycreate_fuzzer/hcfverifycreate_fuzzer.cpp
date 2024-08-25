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

#include "hcfverifycreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "asy_key_generator.h"
#include "blob.h"
#include "result.h"
#include "signature.h"

namespace OHOS {
    static char g_mockMessage[] = "hello world";
    const int INPUT_MSG_LEN = 12;

    static void TestVerify(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *ecc224KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &ecc224KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("ECC224|SHA384", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(ecc224KeyPair);
            return;
        }
        static HcfBlob mockInput = {
            .data = reinterpret_cast<uint8_t *>(g_mockMessage),
            .len = INPUT_MSG_LEN
        };
        (void)sign->init(sign, nullptr, ecc224KeyPair->priKey);
        (void)sign->update(sign, &mockInput);

        HcfVerify *verify = nullptr;
        res = HcfVerifyCreate("ECC224|SHA384", &verify);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(ecc224KeyPair);
            HcfObjDestroy(sign);
            return;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        (void)sign->sign(sign, nullptr, &out);
        (void)verify->init(verify, nullptr, ecc224KeyPair->pubKey);
        (void)verify->update(verify, &mockInput);
        (void)verify->verify(verify, nullptr, &out);
        HcfObjDestroy(ecc224KeyPair);
        HcfObjDestroy(sign);
        HcfBlobDataFree(&out);
        HcfObjDestroy(verify);
    }

    static void TestVerifySm2(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *sm2256KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &sm2256KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("SM2_256|SM3", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sm2256KeyPair);
            return;
        }
        static HcfBlob mockInput = {
            .data = reinterpret_cast<uint8_t *>(g_mockMessage),
            .len = INPUT_MSG_LEN
        };
        (void)sign->init(sign, nullptr, sm2256KeyPair->priKey);
        (void)sign->update(sign, &mockInput);

        HcfVerify *verify = nullptr;
        res = HcfVerifyCreate("SM2_256|SM3", &verify);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sm2256KeyPair);
            HcfObjDestroy(sign);
            return;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        (void)sign->sign(sign, nullptr, &out);
        (void)verify->init(verify, nullptr, sm2256KeyPair->pubKey);
        (void)verify->update(verify, &mockInput);
        (void)verify->verify(verify, nullptr, &out);
        HcfObjDestroy(sm2256KeyPair);
        HcfObjDestroy(sign);
        HcfBlobDataFree(&out);
        HcfObjDestroy(verify);
    }

    static void TestVerifyBrainpool(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *brainPoolP160r1KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &brainPoolP160r1KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("ECC_BrainPoolP160r1|SHA1", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(brainPoolP160r1KeyPair);
            return;
        }
        static HcfBlob mockInput = {
            .data = reinterpret_cast<uint8_t *>(g_mockMessage),
            .len = INPUT_MSG_LEN
        };
        (void)sign->init(sign, nullptr, brainPoolP160r1KeyPair->priKey);
        (void)sign->update(sign, &mockInput);

        HcfVerify *verify = nullptr;
        res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA1", &verify);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(brainPoolP160r1KeyPair);
            HcfObjDestroy(sign);
            return;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        (void)sign->sign(sign, nullptr, &out);
        (void)verify->init(verify, nullptr, brainPoolP160r1KeyPair->pubKey);
        (void)verify->update(verify, &mockInput);
        (void)verify->verify(verify, nullptr, &out);
        HcfObjDestroy(brainPoolP160r1KeyPair);
        HcfObjDestroy(sign);
        HcfBlobDataFree(&out);
        HcfObjDestroy(verify);
    }

    static void TestVerifyEd25519(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("Ed25519", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *ed25519KeyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &ed25519KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = nullptr;
        res = HcfSignCreate("Ed25519", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(ed25519KeyPair);
            return;
        }
        static HcfBlob mockInput = {
            .data = reinterpret_cast<uint8_t *>(g_mockMessage),
            .len = INPUT_MSG_LEN
        };
        (void)sign->init(sign, nullptr, ed25519KeyPair->priKey);
        (void)sign->update(sign, &mockInput);

        HcfVerify *verify = nullptr;
        res = HcfVerifyCreate("Ed25519", &verify);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(ed25519KeyPair);
            HcfObjDestroy(sign);
            return;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        (void)sign->sign(sign, nullptr, &out);
        (void)verify->init(verify, nullptr, ed25519KeyPair->pubKey);
        (void)verify->update(verify, &mockInput);
        (void)verify->verify(verify, nullptr, &out);
        HcfObjDestroy(ed25519KeyPair);
        HcfObjDestroy(sign);
        HcfBlobDataFree(&out);
        HcfObjDestroy(verify);
    }

    bool HcfVerifyCreateFuzzTest(const uint8_t* data, size_t size)
    {
        TestVerify();
        TestVerifySm2();
        TestVerifyBrainpool();
        TestVerifyEd25519();
        HcfVerify *verify = nullptr;
        std::string algoName(reinterpret_cast<const char *>(data), size);
        HcfResult res = HcfVerifyCreate(algoName.c_str(), &verify);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(verify);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfVerifyCreateFuzzTest(data, size);
    return 0;
}
