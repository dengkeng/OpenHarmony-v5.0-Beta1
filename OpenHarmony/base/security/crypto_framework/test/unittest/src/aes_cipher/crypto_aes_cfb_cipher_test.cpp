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
class CryptoAesCfbCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest001, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest002, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest003, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}


HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest004, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB1|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest005, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB1|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest006, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB1|PKCS7", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest007, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|NoPadding", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest008, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS5", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest009, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS7", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest010, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|NoPadding", &cipher);  // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest011, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS5", &cipher);  // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest012, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS7", &cipher);  // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest013, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest014, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest015, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}


HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest016, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB1|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest017, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

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

    ret = HcfCipherCreate("AES128|CFB1|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest018, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB1|PKCS7", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest019, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|NoPadding", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest020, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS5", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest021, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS7", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest022, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|NoPadding", &cipher);  // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest023, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS5", &cipher);  // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest024, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS7", &cipher);  // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest025, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = GeneratorFile("/data/test_aes.txt", 10 * FILE_BLOCK_SIZE);
    if (ret != 0) {
        LOGE("GeneratorFile failed!");
        goto CLEAR_UP;
    }

    ret = AesMultiBlockEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesMultiBlockDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto CLEAR_UP;
    }
    ret = CompareFileContent();
    if (ret != 0) {
        LOGE("CompareFileContent failed!");
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest026, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES192", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES192|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest027, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES256|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest028, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES192", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES192|CFB1|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}


HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest029, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES256|CFB1|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest030, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES192", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES192|CFB8|PKCS5", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest031, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES256|CFB8|PKCS5", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest032, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES192", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES192|CFB128|PKCS5", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest033, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("AES256|CFB128|PKCS5", &cipher);    // CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = AesEncrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = AesDecrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest034, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    const char *cipherName = "AES128|CFB|NoPadding";
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

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest035, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    const char *cipherName = "AES128|CFB|NoPadding";
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

HWTEST_F(CryptoAesCfbCipherTest, CryptoAesCfbCipherTest036, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    const char *cipherName = "AES128|CFB|NoPadding";
    const char *retAlgo = nullptr;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
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
}