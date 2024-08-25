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
#include "sm4_common.h"
#include "sm4_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSM4CfbCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest010, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest011, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest012, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest013, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest014, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest015, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest028, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest029, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest030, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest031, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest032, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest033, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest040, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;
    ret = HcfCipherCreate(cipherName, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    retAlgo = cipher->getAlgorithm(nullptr);
    if (retAlgo == nullptr) {
        LOGE("cipher getAlgorithm failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest041, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate(cipherName, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    retAlgo = cipher->getAlgorithm(reinterpret_cast<HcfCipher *>(generator));
    if (retAlgo == nullptr) {
        LOGE("cipher getAlgorithm failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest042, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM3|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should not select SM3 for CFB generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest043, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    // not allow '|' without content, because findAbility will fail for "" input
    ret = HcfCipherCreate("SM4_128|CFB|", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should select padding mode for SM4_128 generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest047, TestSize.Level0)
{
    int ret = 0;

    ret = HcfCipherCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should not select SM3 for CFB generator.");
    }

    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoAesCipherTest050, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKeyForSm4("SM4_128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed!");
        goto CLEAR_UP;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);

    cipherTextLen -= 12;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed!");
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoAesCipherTest051, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;
    ret = HcfCipherCreate(cipherName, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    retAlgo = cipher->getAlgorithm(cipher);
    if (retAlgo == nullptr) {
        LOGE("cipher getAlgorithm failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto CLEAR_UP;
    }

    ret = strcmp(retAlgo, cipherName);
    if (ret != 0) {
        LOGE("cipher getAlgorithm failed!");
    }
CLEAR_UP:
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest082, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKeyForSm4("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CfbCipherTest, CryptoSm4CipherTest083, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKeyForSm4("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}
}