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
#include "cstring"
#include "securec.h"
#include "asy_key_generator.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_common.h"
#include "md.h"
#include "signature.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaOnlySignAndVerifyRecoverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaOnlySignAndVerifyRecoverTest::SetUp() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::TearDown() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::SetUpTestCase() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::TearDownTestCase() {}

static void RsaOnlySignCreateTest(const char *algoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

static void RsaOnlySignCreateIncorrectTest(const char *algoName, HcfResult ret)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, ret);
    EXPECT_EQ(sign, nullptr);
}

static void RsaOnlySignTest(const char *keyAlgoName, const char *algoName, const char *plan)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen(plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void RsaOnlySignIncorrectTest(const char *keyAlgoName, const char *algoName, const char *plan)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen(plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfSignCreate OnlySign correct_case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest100, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA512|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA512|PKCS1|SHA384|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest110, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA768|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA768|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest120, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA1024|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest130, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA2048|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA2048|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest140, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA3072|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA3072|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest150, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA4096|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA4096|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest160, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA8192|PKCS1|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|MD5|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA1|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA224|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA256|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA384|OnlySign");
    RsaOnlySignCreateTest("RSA8192|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest170, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA512|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA768|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA1024|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA2048|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA3072|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA4096|NoPadding|NoHash|OnlySign");
    RsaOnlySignCreateTest("RSA8192|NoPadding|NoHash|OnlySign");
}

// HcfSignCreate OnlySign Incorrect case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest180, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024aa|PKCS1|SHA256|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1aa|SHA256|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256aa|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256|OnlySignaa", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256|123123123123123123212312312321"
        "123123123123213asdasdasdasdasdasdasdasdasdasdasdasdasdsasdasds12|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("RSA1024|PSS|SHA256|MGF1_SHA256|OnlySign", HCF_INVALID_PARAMS);
    RsaOnlySignCreateIncorrectTest("DSA1024|PKCS1|SHA256|OnlySign", HCF_NOT_SUPPORT);
}

// incorrect case : OnlySign init signer with nullptr private key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

// incorrect case : OnlySign init signer with public Key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = keyPair->pubKey;

    res = sign->init(sign, nullptr, (HcfPriKey *)pubKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : OnlySign use update function.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest290, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : use OnlySign sign function before intialize.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest291, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &input, &signatureData);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

// incorrect case : OnlySign sign with nullptr outputBlob.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest292, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: OnlySign init and sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest300, TestSize.Level0)
{
    RsaOnlySignTest("RSA512|PRIMES_2", "RSA512|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA2048|PRIMES_2", "RSA2048|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA4096|PRIMES_2", "RSA4096|PKCS1|NoHash|OnlySign", "01234567890123456789");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest310, TestSize.Level0)
{
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|NoPadding|NoHash|OnlySign",
        "0123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest320, TestSize.Level0)
{
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|MD5|OnlySign", "0123456789012345");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA1|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA224|OnlySign",
        "0123456789012345678901234567");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA256|OnlySign",
        "01234567890123456789012345678901");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA384|OnlySign",
        "012345678901234567890123456789012345678901234567");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA512|OnlySign",
        "0123456789012345678901234567890123456789012345678901234567890123");
}

// incorrect case: OnlySign init and sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest330, TestSize.Level0)
{
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|MD5|OnlySign", "012345678901234");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|MD5|OnlySign", "01234567890123456");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA1|OnlySign", "0123456789012345678");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA1|OnlySign", "012345678901234567890");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA224|OnlySign",
        "012345678901234567890123456");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA224|OnlySign",
        "01234567890123456789012345678");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA256|OnlySign",
        "0123456789012345678901234567890");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA256|OnlySign",
        "012345678901234567890123456789012");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA384|OnlySign",
        "01234567890123456789012345678901234567890123456");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA384|OnlySign",
        "0123456789012345678901234567890123456789012345678");

    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA512|OnlySign",
        "012345678901234567890123456789012345678901234567890123456789012");
    RsaOnlySignIncorrectTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|SHA512|OnlySign",
        "01234567890123456789012345678901234567890123456789012345678901234");
}

// incorrect case: OnlySign double init sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest500, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA512|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static void CryptoRsaVerifyRecoverCreateTest(const char *algoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(algoName, &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(verify, nullptr);
    EXPECT_NE(verify->base.getClass(), nullptr);
    EXPECT_NE(verify->base.destroy, nullptr);
    EXPECT_NE(verify->init, nullptr);
    EXPECT_NE(verify->update, nullptr);
    EXPECT_NE(verify->verify, nullptr);
    EXPECT_NE(verify->recover, nullptr);
    HcfObjDestroy(verify);
}

static void RsaVerifyRecoverIncorrectTest(const char *algoName, HcfResult ret)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(algoName, &verify);
    EXPECT_EQ(res, ret);
    EXPECT_EQ(verify, nullptr);
}

// HcfVerifyCreate Recover correct_case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest100, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA512|PKCS1|SHA384|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest110, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest120, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest130, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest140, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest150, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest160, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|MD5|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA1|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA224|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA256|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA384|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|PKCS1|SHA512|Recover");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest170, TestSize.Level0)
{
    CryptoRsaVerifyRecoverCreateTest("RSA512|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA768|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA1024|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA2048|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA3072|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA4096|NoPadding|NoHash|Recover");
    CryptoRsaVerifyRecoverCreateTest("RSA8192|NoPadding|NoHash|Recover");
}

// HcfVerifyCreate OnlySign Incorrect case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest180, TestSize.Level0)
{
    RsaVerifyRecoverIncorrectTest("RSA1024aa|PKCS1|SHA256|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1aa|SHA256|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1|SHA256aa|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1|SHA256|Recoveraa", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PKCS1|SHA256|123123123123123123212312312321"
        "123123123123213asdasdasdasdasdasdasdasdasdasdasdasdasdsasdasds12|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("RSA1024|PSS|SHA256|MGF1_SHA256|Recover", HCF_INVALID_PARAMS);
    RsaVerifyRecoverIncorrectTest("DSA1024|PKCS1|SHA256|Recover", HCF_NOT_SUPPORT);
}

// incorrect case : Recover init signer with nullptr public key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|NoHash|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

// incorrect case : Recover init verifyer with private Key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|NoHash|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = keyPair->priKey;

    res = verify->init(verify, nullptr, (HcfPubKey *)priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : use Recover recover function before intialize.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest291, TestSize.Level0)
{
    uint8_t plan[] = "01234567890123456789012345678901";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, &verifyData, &rawSignatureData);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : Recover recover with nullptr outputBlob.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest292, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;

    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, nullptr, &rawSignatureData);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case: recover double init verify
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest293, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case : sign and recover
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest300, TestSize.Level0)
{
    uint8_t plan[] = "01234567890123456789012345678901";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, &verifyData, &rawSignatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(verify);
    int resCmp = memcmp(input.data, rawSignatureData.data, rawSignatureData.len);
    EXPECT_EQ(resCmp, HCF_SUCCESS);

    HcfFree(verifyData.data);
    HcfFree(rawSignatureData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaVerifyRecoverTest310, TestSize.Level0)
{
    uint8_t plan[] = "01234567890123456789012345678901";
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfBlob rawSignatureData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA1024|PKCS1|SHA256|Recover", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, pubkey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->recover(verify, &verifyData, &rawSignatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(verify);

    uint32_t SHA256_LEN = 32;
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->update(mdObj, &input);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA256_LEN);

    int resCmp = memcmp(outBlob.data, rawSignatureData.data, rawSignatureData.len);
    EXPECT_EQ(resCmp, HCF_SUCCESS);

    HcfObjDestroy(mdObj);
    HcfFree(verifyData.data);
    HcfFree(rawSignatureData.data);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
