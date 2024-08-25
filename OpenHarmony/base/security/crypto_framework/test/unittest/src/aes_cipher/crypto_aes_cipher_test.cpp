/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "aes_common.h"
#include "aes_openssl.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "log.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAesCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest001, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
    const char *generatorAlgoName = nullptr;

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest002, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "AES128";

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest003, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *generatorAlgoName = nullptr;
    const char *inputAlgoName = "AES128";

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest004, TestSize.Level0)
{
    int ret = 0;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
    const char *keyAlgoName = nullptr;

    ret = GenerateSymKey(inputAlgoName, &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getAlgorithm
    keyAlgoName = key->key.getAlgorithm(&(key->key));
    if (keyAlgoName == nullptr) {
        LOGE("key getAlgorithm returns nullptr.");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto CLEAR_UP;
    }

    ret = strcmp(keyAlgoName, inputAlgoName);
    if (ret != 0) {
        LOGE("key getAlgorithm failed!");
    }
CLEAR_UP:
    HcfObjDestroy(key);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest005, TestSize.Level0)
{
    int ret = 0;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest006, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *inputAlgoName = "AES128";
    const char *keyAlgoName = nullptr;

    ret = HcfSymKeyGeneratorCreate(inputAlgoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest007, TestSize.Level0)
{
    int ret = 0;
    HcfSymKey *key = nullptr;
    const char *keyFormat = "PKCS#8";
    const char *retFormat = nullptr;

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // key GetFormat
    retFormat = key->key.getFormat(&(key->key));
    if (retFormat == nullptr) {
        LOGE("key GetFormat returns nullptr.");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto CLEAR_UP;
    }

    ret = strcmp(retFormat, keyFormat);
    if (ret != 0) {
        LOGE("key GetFormat failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest008, TestSize.Level0)
{
    int ret = 0;
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    ret = GenerateSymKey("AES128", &key);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest009, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    const char *retFormat = nullptr;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest010, TestSize.Level0)
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

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }
    ret = generator->convertSymKey(generator, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    // key getEncoded
    ret = key->key.getEncoded(&(key->key), &encodedBlob);
    if (ret != 0) {
        LOGE("key GetEncoded failed.");
        goto CLEAR_UP;
    }

    if (encodedBlob.len != keyTmpBlob.len) {
        LOGE("key GetEncoded failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto CLEAR_UP;
    }
    ret = memcmp(encodedBlob.data, keyTmpBlob.data, keyTmpBlob.len);

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    if (encodedBlob.data != nullptr) {
        HcfFree(encodedBlob.data);
        encodedBlob.data = nullptr;
    }
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest011, TestSize.Level0)
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

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest012, TestSize.Level0)
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

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest013, TestSize.Level0)
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

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest014, TestSize.Level0)
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

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest015, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate("RSA128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select RSA for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest016, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;

    ret = HcfSymKeyGeneratorCreate("RSA512", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed! Should not select RSA for symKey generator.");
    }

    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest017, TestSize.Level0)
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest018, TestSize.Level0)
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest019, TestSize.Level0)
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest020, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest021, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest022, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = 0 };

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest023, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // allow input without encryption mode. It will pick the last PKCS5, and use default aes128ecb.
    ret = HcfCipherCreate("AES128|NoPadding|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest024, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // allow input without encryption mode. It will use default aes128ecb.
    ret = HcfCipherCreate("AES128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest025, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // allow input without encryption mode. It will use default aes128ecb.
    ret = HcfCipherCreate("AES128", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest026, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest027, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate(nullptr, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest028, TestSize.Level0)
{
    int ret = HcfCipherAesGeneratorSpiCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfCipherAesGeneratorSpiCreate failed!");
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest029, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGeneratorSpi *generator = nullptr;
    HcfSymKey *key = nullptr;
    SymKeyAttr attr = { .algo = HCF_ALG_AES, .keySize = AES_KEY_SIZE };

    ret = HcfSymKeyGeneratorSpiCreate(&attr, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorSpiCreate failed!%d", ret);
        goto CLEAR_UP;
    }
    ret = generator->engineGenerateSymmKey(nullptr, &key);
    if (ret != 0) {
        LOGE("engineGenerateSymmKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoAesCipherTest, CryptoAesCipherTest030, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGeneratorSpi *generator = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = { .data = keyMaterial, .len = KEY_MATERIAL_LEN };
    SymKeyAttr attr = { .algo = HCF_ALG_AES, .keySize = AES_KEY_SIZE };

    ret = HcfSymKeyGeneratorSpiCreate(&attr, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorSpiCreate failed!%d", ret);
        goto CLEAR_UP;
    }
    ret = generator->engineConvertSymmKey(nullptr, &keyTmpBlob, &key);
    if (ret != 0) {
        LOGE("engineConvertSymmKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}
}