/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "md.h"
#include "md_openssl.h"

#include "log.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

constexpr uint32_t MAX_MD_BLOB_LEN = 5000;
constexpr uint32_t INVALID_LEN = 0;
constexpr uint32_t SHA1_LEN = 20;
constexpr uint32_t SHA224_LEN = 28;
constexpr uint32_t SHA256_LEN = 32;
constexpr uint32_t SHA384_LEN = 48;
constexpr uint32_t SHA512_LEN = 64;
constexpr uint32_t MD5_LEN = 16;

static char g_testBigData[] = "VqRH5dzdeeturr5zN5vE77DtqjV7kNKbDJqk4mNqyYRTXymhjR\r\n"
"Yz8c2pNvJiCxyFwvLvWfPh2Y2eDAuxbdm2Dt4UzKJtNqEpNYKVZLiyH4a4MhR4BpFhvhJVHy2ALbYq2rW\r\n"
"LqJfNzA6v8kHNaFypNDMgX35kifyCiYkq85XUKDJCdewUzCZ2N8twC8Z9kL37K67bkL35VYFZSXyrNTdV\r\n"
"pB6kqPjwZYrjx5tXzMMgJW8ePqmAhZUVjtPGXTLVt8BUnaVRuWjD97xjS3VH9EwFeyrqJ46B92rkuGexY\r\n"
"cjXuvhHTnQNPbYfake7KMEWG2wgGLmZmjnakULhFgjt6TQhvCWMJAHYn8Zgczd3C3HkPrQgUXJgAiwf3r\r\n"
"jJbgbBpQkkbcfMBZZ3SSLe2J9jw6MkdEf3eBQX9rFVQSgBQgZ9KEW8XLb5kCTcyhRZPBbiHD4qQRyrwKT\r\n"
"mnGZqP5Aru6GDkhFk78jfjtk35HyB7AY7UZXkczRfVYAxa5Mk256MhAHkE3uAvPZTyY7N3qk9U7cLTrce\r\n"
"wJLH6wrymrMvQWgpvrBevMghnURZUcZAWUznDn56WnwGAzYAWmJqdXqAfcvgZwCFTjxdiaEZGpEyUrcS8\r\n"
"nr48ZeXS5aytz5Y7RnU5SxcHbgF8PerWVdftxmghPAvGkQ6f3dcXr9w9bbGqg5KJHyQCxabp8bjZpyFdb\r\n"
"VTq8DpQ6AJjxdjn8cuLTf9giGFxDjtQncicUdqP7YvVDr5AFgWc83cddyryVLZEBGAFfqbbKWF9KnPjRZ\r\n"
"AbuZ7SqrkxhQHu87Hxh3xHUHB8Lb3DGZ4vhnqaLnJBxFK8Ve4F2FfbgfHfQtALFDUWp6dSz8Hvdpj4CGw\r\n"
"FaSb8b5hTemaQRguYAqaUwJVvZ7G2AwkFnV9PHUngmybAFxg8HMAT3K7yAiQJWWqPxdGq8jXPAqZFNkGu\r\n"
"2mnJ5xfnY3z63PFk6TXU9Ga2YmHvtycXxwqMBEctQRa3zVWGVSrh3NF6jXa\r\n";

void CryptoMdTest::SetUpTestCase() {}
void CryptoMdTest::TearDownTestCase() {}

void CryptoMdTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoMdTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static void PrintfBlobInHex(uint8_t *data, size_t dataLen)
{
    for (size_t i = 0; i < dataLen; i++) {
        printf("%02hhX", data[i]);
    }
    printf("\n");
}

/**
 * @tc.name: CryptoFrameworkMdTest.CryptoFrameworkMdCreateTest001
 * @tc.desc: Verify that the creation of the SHA1 Md obj is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEM
 */
HWTEST_F(CryptoMdTest, CryptoFrameworkMdCreateTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfResult ret = HcfMdCreate("SHA1", nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoSuppTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoSuppTest002, TestSize.Level0)
{
    // create a SHA3 obj (not supported)
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA3", &mdObj);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(mdObj, nullptr);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoSuppTest003, TestSize.Level0)
{
    // create an obj with null algoInput (not supported)
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate(nullptr, &mdObj);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(mdObj, nullptr);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoNameTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  mdObj->getAlgoName(mdObj);
    int32_t cmpRes = strcmp(algoName, "SHA1");
    EXPECT_EQ(cmpRes, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdUpdateTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // define input and output data in blob form
    HcfBlob *inBlob = nullptr;
    // test api functions
    ret = mdObj->update(mdObj, inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdUpdateTest002, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdDoFinalTest001, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdDoFinalTest002, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdDoFinalTest003, TestSize.Level0)
{
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // define input and output data in blob form
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    inBlob.data = reinterpret_cast<uint8_t *>(g_testBigData);
    inBlob.len = strnlen(g_testBigData, MAX_MD_BLOB_LEN);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    PrintfBlobInHex(outBlob.data, outBlob.len);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdLenTest001, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // test api functions
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA1_LEN);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest001, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA1", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    struct HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA1_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest002, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA224", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    struct HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA224_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest003, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    struct HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA256_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest004, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA384", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    struct HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA384_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest005, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA512", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    struct HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, SHA512_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest006, TestSize.Level0)
{
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("MD5", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    // set input and output buf
    uint8_t testData[] = "My test data";
    // define input and output data in blob form
    struct HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    struct HcfBlob outBlob = { .data = nullptr, .len = 0 };
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, MD5_LEN);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

static const char *GetInvalidMdClass(void)
{
    return "INVALID_MD_CLASS";
}

HWTEST_F(CryptoMdTest, InvalidInputMdTest001, TestSize.Level0)
{
    HcfResult ret = OpensslMdSpiCreate("SHA256", nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMdTest, NullParamMdTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("MD5", &mdObj);
    ret = mdObj->update(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(nullptr);
    EXPECT_EQ(len, HCF_OPENSSL_INVALID_MD_LEN);
    const char *algoName = mdObj->getAlgoName(nullptr);
    EXPECT_EQ(algoName, nullptr);
    mdObj->base.destroy(nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, InvalidFrameworkClassMdTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfMd invalidMdObj = {{0}};
    invalidMdObj.base.getClass = GetInvalidMdClass;
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->update(&invalidMdObj, &inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = mdObj->doFinal(&invalidMdObj, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(&invalidMdObj);
    EXPECT_EQ(len, HCF_OPENSSL_INVALID_MD_LEN);
    const char *algoName = mdObj->getAlgoName(&invalidMdObj);
    EXPECT_EQ(algoName, nullptr);
    HcfBlobDataClearAndFree(&outBlob);
    mdObj->base.destroy(&(invalidMdObj.base));
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, InvalidSpiClassMdTest001, TestSize.Level0)
{
    HcfMdSpi *spiObj = nullptr;
    HcfMdSpi invalidSpi = {{0}};
    invalidSpi.base.getClass = GetInvalidMdClass;
    // set input and output blob
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = OpensslMdSpiCreate("SHA256", &spiObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);
    (void)spiObj->base.destroy(nullptr);
    (void)spiObj->base.destroy(&(invalidSpi.base));
    ret = spiObj->engineUpdateMd(&invalidSpi, &inBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    ret = spiObj->engineDoFinalMd(&invalidSpi, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    uint32_t len = spiObj->engineGetMdLength(&invalidSpi);
    EXPECT_EQ(len, INVALID_LEN);
    HcfObjDestroy(spiObj);
}
}