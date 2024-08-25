/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "securec.h"

#include "asy_key_generator.h"
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "memory.h"
#include "params_parser.h"
#include "rsa_asy_key_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaAsyKeyGeneratorTest::SetUpTestCase() {}
void CryptoRsaAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoRsaAsyKeyGeneratorTest::SetUp() {}
void CryptoRsaAsyKeyGeneratorTest::TearDown() {}

constexpr int32_t OPENSSL_RSA_KEY_SIZE_2048 = 2048;
constexpr int32_t OPENSSL_RSA_KEY_SIZE_4096 = 4096;
constexpr int32_t OPENSSL_RSA_KEY_SIZE_ABNORMAL = 1;
constexpr int32_t OPENSSL_RSA_PRIMES_ABNORMAL = 1;
constexpr size_t RSA_CORRECT_PUBKEY_LEN = 162;
constexpr size_t RSA_ERROR_PUBKEY_LEN = 1;
uint8_t g_rsaCorrectPkData[] = {
    48, 129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48, 129,
    137, 2, 129, 129, 0, 174, 203, 113, 83, 113, 3, 143, 213, 194, 79, 91, 9, 51, 142, 87, 45, 97,
    65, 136, 24, 166, 35, 5, 179, 42, 47, 212, 79, 111, 74, 134, 120, 73, 67, 21, 19, 235, 80, 46,
    152, 209, 133, 232, 87, 192, 140, 18, 206, 27, 106, 106, 169, 106, 46, 135, 111, 118, 32, 129,
    27, 89, 255, 183, 116, 247, 38, 12, 7, 238, 77, 151, 167, 6, 102, 153, 126, 66, 28, 253, 253, 216,
    64, 20, 138, 117, 72, 15, 216, 178, 37, 208, 179, 63, 204, 39, 94, 244, 170, 48, 190, 21, 11,
    73, 169, 156, 104, 193, 3, 17, 100, 28, 60, 50, 92, 235, 218, 57, 73, 119, 19, 101, 164, 192,
    161, 197, 106, 105, 73, 2, 3, 1, 0, 1
};

HcfBlob g_rsaCorrectPubKeyBlob = {
    .data = g_rsaCorrectPkData,
    .len = RSA_CORRECT_PUBKEY_LEN
};
HcfBlob g_rsaErrorPubKeyBlob = {
    .data = g_rsaCorrectPkData,
    .len = RSA_ERROR_PUBKEY_LEN
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};
// HcfAsyKeyGeneratorCreate correct case: no primes
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest100, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest110, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest120, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest130, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest140, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest150, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: with primes
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest200, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest210, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest220, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest230, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest240, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest250, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest260, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest270, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_4", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate Incorrect case : algname is null
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest300, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(nullptr, &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest301, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest310, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111111111111111111111111111111111", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest320, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest330, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA12315", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest340, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_777", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest350, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_3", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest360, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_3", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest370, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_4", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest380, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_4", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest381, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest390, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_5", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest391, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA8192|PRIMES_5", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest400, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    HcfObjDestroy(generator);
    generator = nullptr;
    HcfObjDestroy(generator);
    HcfObjDestroy(nullptr);
}

// generateKeyPair correct case
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest500, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);
    EXPECT_NE(keyPair->base.getClass(), nullptr);
    EXPECT_NE(keyPair->base.destroy, nullptr);

    HcfPubKey *pubkey = keyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = keyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest510, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);
    EXPECT_NE(keyPair->base.getClass(), nullptr);
    EXPECT_NE(keyPair->base.destroy, nullptr);

    HcfPubKey *pubkey = keyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = keyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest511, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_3", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfBlob pubKeyBlob;
    HcfBlob priKeyBlob;
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfPriKey *priKey = keyPair->priKey;

    res = pubKey->base.getEncoded((HcfKey *)priKey, &pubKeyBlob);
    EXPECT_NE(res, HCF_SUCCESS);
    res = priKey->base.getEncoded((HcfKey *)pubKey, &priKeyBlob);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest512, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfPubKey *pubKey = keyPair->pubKey;
    HcfPriKey *priKey = keyPair->priKey;

    res = pubKey->base.getEncoded((HcfKey *)priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    res = priKey->base.getEncoded((HcfKey *)pubKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// generateKeyPair conrrect case: use getEncode encode pubkey and prikey
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest520, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

// Test muliti getEncoded and convertKey
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest521, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob1 = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob1 = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob1);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob1);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair1 = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob1, &priKeyBlob1, &dupKeyPair1);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair2 = nullptr;
    HcfBlob pubKeyBlob2 = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob2 = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob2);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob2);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = generator->convertKey(generator, nullptr, &pubKeyBlob2, &priKeyBlob2, &dupKeyPair2);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfFree(pubKeyBlob1.data);
    HcfFree(priKeyBlob1.data);
    HcfFree(pubKeyBlob2.data);
    HcfFree(priKeyBlob2.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair1);
    HcfObjDestroy(dupKeyPair2);
}

// generateKeyPair correct case: getEncode encode pubkey
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest530, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

// generateKeyPair correct case: getEncode encode prikey
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest540, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest550, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest560, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest570, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest580, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

// generateKeyPair incorrect case: user wrong ECC class, ignore in this version
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest600, TestSize.Level0)
{
    HcfAsyKeyGenerator *eccGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC224", &eccGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(eccGenerator, nullptr);

    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // innerkit调用，在framework层中，指针无法判断eccGenerator调用的self，所以keypair实际不为空。
    // 会调到ecc的generatekeyPair，生成ecc的keypair对象（class为ecckeypair）
    // 对js调用，能否防范？
    res = rsaGenerator->generateKeyPair(eccGenerator, nullptr, &keyPair);
    // 经验证，keypair不为空,且为ecc的keypair
    EXPECT_NE(keyPair, nullptr);
    EXPECT_STREQ("OPENSSL.ECC.KEY_PAIR", keyPair->base.getClass());

    HcfObjDestroy(keyPair);
    HcfObjDestroy(eccGenerator);
    HcfObjDestroy(rsaGenerator);
}

// generateKeyPair incorrect case: generator class is null
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest610, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = rsaGenerator->generateKeyPair(nullptr, nullptr, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(rsaGenerator);
}

// generateKeyPair incorrect case: keypair is null
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest620, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    res = rsaGenerator->generateKeyPair(rsaGenerator, nullptr, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(rsaGenerator);
}

// convertKey correct case
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest700, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

// convertKey incorrect case: input ECC class
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest710, TestSize.Level0)
{
    HcfAsyKeyGenerator *eccGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC224", &eccGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(eccGenerator, nullptr);

    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = rsaGenerator->convertKey(eccGenerator, nullptr, nullptr, nullptr, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfObjDestroy(eccGenerator);
    HcfObjDestroy(rsaGenerator);
}


// convertKey incorrect case: input null generator
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest720, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = rsaGenerator->generateKeyPair(rsaGenerator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = rsaGenerator->convertKey(nullptr, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(rsaGenerator);
}

// convertKey incorrect case: input null dupkeypair
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest730, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = rsaGenerator->generateKeyPair(rsaGenerator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = rsaGenerator->convertKey(rsaGenerator, nullptr, &pubKeyBlob, &priKeyBlob, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(rsaGenerator);
}

// convertKey incorrect case: input blob with null data
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest740, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};

    HcfKeyPair *dupKeyPair = nullptr;
    res = rsaGenerator->convertKey(rsaGenerator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfObjDestroy(rsaGenerator);
}

// convertKey incorrect case: input blob with zero len
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest750, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfBlob pubKeyBlob = {.data = g_rsaCorrectPkData, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};

    HcfKeyPair *dupKeyPair = nullptr;
    res = rsaGenerator->convertKey(rsaGenerator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfObjDestroy(rsaGenerator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest760, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfBlob priKeyBlob = {.data = g_rsaCorrectPkData, .len = 0};

    HcfKeyPair *dupKeyPair = nullptr;
    res = rsaGenerator->convertKey(rsaGenerator, nullptr, nullptr, &priKeyBlob, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfObjDestroy(rsaGenerator);
}

// convertKey incorrect case: input blob with error data
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest770, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = rsaGenerator->convertKey(rsaGenerator, nullptr, &g_rsaErrorPubKeyBlob, &g_rsaErrorPubKeyBlob, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfObjDestroy(rsaGenerator);
}

// Incorrect case: use wrong bits or primes
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest800, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1111", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest810, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|Primessf", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

// 测试异常释放
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest820, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|Primessf", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

// prikey clear mem
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest830, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    keyPair->priKey->clearMem(nullptr);

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest840, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest850, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// correct case: use destroy function inclass(not HcfObjDestroy)
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest900, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfPubKey *pubkey = keyPair->pubKey;
    HcfPriKey *prikey = keyPair->priKey;

    EXPECT_EQ(pubkey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_EQ(prikey->base.getFormat((HcfKey *)pubkey), nullptr);

    EXPECT_EQ(pubkey->base.getFormat(nullptr), nullptr);
    EXPECT_EQ(prikey->base.getFormat(nullptr), nullptr);

    EXPECT_EQ(pubkey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_EQ(prikey->base.getAlgorithm((HcfKey *)pubkey), nullptr);

    EXPECT_EQ(pubkey->base.getAlgorithm(nullptr), nullptr);
    EXPECT_EQ(prikey->base.getAlgorithm(nullptr), nullptr);

    prikey->base.base.destroy(nullptr);
    pubkey->base.base.destroy(nullptr);
    keyPair->base.destroy(nullptr);

    prikey->base.base.destroy((HcfObjectBase *)pubkey);
    pubkey->base.base.destroy((HcfObjectBase *)prikey);
    keyPair->base.destroy((HcfObjectBase *)prikey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest901, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest902, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
}

// test RSA key pair get
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest903, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// spi create
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(nullptr, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest002, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest003, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_ABNORMAL,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest004, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = OPENSSL_RSA_PRIMES_ABNORMAL,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest005, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_4096,
        .primes = OPENSSL_RSA_PRIMES_ABNORMAL,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

// spi gen keyPair
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest006, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPair((HcfAsyKeyGeneratorSpi *)&g_obj, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest007, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    res = spiObj->engineGenerateKeyPair(nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

// spi destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest008, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest009, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);
    HcfObjDestroy(spiObj);
}

// spi convert
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest010, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey((HcfAsyKeyGeneratorSpi *)&g_obj,
        nullptr, &g_rsaCorrectPubKeyBlob, nullptr, &keyPair);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest011, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey(nullptr, nullptr, &g_rsaCorrectPubKeyBlob, nullptr, &keyPair);
    HcfObjDestroy(spiObj);
}

// spi destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest012, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);
    EXPECT_NE(spiObj, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest013, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_RSA,
        .bits = OPENSSL_RSA_KEY_SIZE_2048,
        .primes = 0,
    };

    HcfResult res = HcfAsyKeyGeneratorSpiRsaCreate(&params, &spiObj);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);
    EXPECT_NE(spiObj, nullptr);
    HcfObjDestroy(spiObj);
}
}
