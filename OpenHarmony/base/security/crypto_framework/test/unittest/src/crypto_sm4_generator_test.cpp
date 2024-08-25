/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "securec.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"
#include "cipher.h"
#include "blob.h"
#include "log.h"
#include "memory.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "aes_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int32_t KEY_MATERIAL_LEN = 16;

class CryptoSM4GeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoSM4GeneratorTest::SetUpTestCase() {}
void CryptoSM4GeneratorTest::TearDownTestCase() {}

void CryptoSM4GeneratorTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoSM4GeneratorTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static int32_t GenerateSymKey(const char *algoName, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy((HcfObjectBase *)generator);
    return ret;
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest001, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "SM4_128";
    const char *generatorAlgoName = nullptr;

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    // generator getAlgoName
    generatorAlgoName = generator->getAlgoName(generator);
    if (generatorAlgoName == nullptr) {
        LOGE("generator getAlgoName returns nullptr.");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto CLEAR_UP;
    }

    ret = strcmp(generatorAlgoName, inputAlgoName);
    if (ret != 0) {
        LOGE("generator getAlgoName failed!");
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest002, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "SM4_128";

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }

    // generator getAlgoName
    generatorAlgoName = generator->getAlgoName(nullptr);
    if (generatorAlgoName == nullptr) {
        LOGE("generator getAlgoName failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest003, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "SM4_128";

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    // generator getAlgoName
    generatorAlgoName = generator->getAlgoName(reinterpret_cast<HcfSymKeyGenerator *>(key));
    if (generatorAlgoName == nullptr) {
        LOGE("generator getAlgoName failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest004, TestSize.Level0)
{
    int ret = 0;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "SM4_128";
    const char *keyAlgoName = nullptr;

    ret = GenerateSymKey(inputAlgoName, &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getAlgorithm
    keyAlgoName = key->key.getAlgorithm(nullptr);
    if (keyAlgoName == nullptr) {
        LOGE("key getAlgorithm returns nullptr.");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(key);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest005, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "SM4_128";
    const char *keyAlgoName = nullptr;

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getAlgorithm
    keyAlgoName = key->key.getAlgorithm(reinterpret_cast<HcfKey *>(generator));
    if (keyAlgoName == nullptr) {
        LOGE("key getAlgorithm returns nullptr.");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest006, TestSize.Level0)
{
    int ret = 0;
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getFormat
    retFormat = key->key.getFormat(nullptr);
    if (retFormat == nullptr) {
        LOGE("key GetFormat returns nullptr.");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(key);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest007, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getFormat
    retFormat = key->key.getFormat(reinterpret_cast<HcfKey *>(generator));
    if (retFormat == nullptr) {
        LOGE("key GetFormat returns nullptr.");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest008, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getEncoded
    ret = key->key.getEncoded(nullptr, &encodedBlob);
    if (ret != 0) {
        LOGE("key GetEncoded failed.");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest009, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getEncoded
    ret = key->key.getEncoded(reinterpret_cast<HcfKey *>(generator), &encodedBlob);
    if (ret != 0) {
        LOGE("key GetEncoded failed.");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest010, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    SymKeyImpl *impl = nullptr;
    size_t tmpLen = 0;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }
    impl = reinterpret_cast<SymKeyImpl *>(key);
    tmpLen = impl->keyMaterial.len;
    impl->keyMaterial.len = 0;

    // key getEncoded
    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    impl->keyMaterial.len = tmpLen;
    if (ret != 0) {
        LOGE("key GetEncoded failed.");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest011, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob encodedBlob = { 0 };
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    key->clearMem(nullptr);

    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    if (ret != 0) {
        LOGE("key GetEncoded failed.");
        goto CLEAR_UP;
    }
    if ((encodedBlob.data != nullptr) && (encodedBlob.data[0] != '\0')) {
        LOGE("clearMem failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest012, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select RSA for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest013, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate("", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select empty string for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest014, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate(nullptr, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select nullptr for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest015, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorSpiCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorSpiCreate failed!");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest016, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(nullptr, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest017, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest018, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }

    ret = generator->convertSymKey(nullptr, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest019, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }

    ret = generator->convertSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4GeneratorTest, CryptoSm4GeneratorTest020, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = 0 };

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }

    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}
}