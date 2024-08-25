/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except", "in compliance with the License.
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
#ifndef OHOS_GLOBAL_I18N_VERIFY_SIGN_TOOL_H
#define OHOS_GLOBAL_I18N_VERIFY_SIGN_TOOL_H

#include <openssl/rsa.h>
#include <string>
#include <vector>
#include "preferences.h"
#include "preferences_helper.h"

namespace OHOS {
namespace Global {
namespace I18n {
enum VerifyStatus {
    VERIFY_FAILED = 0,
    VERIFY_START = 1,
    VERIFY_SUCCESS = 2
};

class VerifySignTool {
public:
    static std::pair<int, int> Parse();

private:
    static VerifyStatus Verify();
    static bool VerifyCertFile();
    static bool VerifyConfigFiles();
    static bool VerifyDigest();
    static std::string VerifyParamFile(const std::string& filePath);
    static VerifyStatus VerifyCertAndConfig(std::string& version);
    static VerifyStatus GetVerifyInfo();

    static bool VerifyFileSign(const std::string& pubkeyPath, const std::string& signPath,
        const std::string& digestPath);
    static bool VerifyRsa(RSA* pubkey, const std::string& digest, const std::string& sign);
    static std::string CalcFileSha256Digest(const std::string& path);
    static void CalcBase64(uint8_t* input, int inputLen, std::string& encodedStr);
    static int CalcFileShaOriginal(const std::string& filePath, unsigned char* hash, size_t len);

    static std::string LoadFileVersion(std::string& versionPath);
    static int CompareVersion(std::string& preVersion, std::string& curVersion);

    static bool IsLegalPath(const std::string& path);
    static void Split(const std::string &src, const std::string &sep, std::vector<std::string> &dest);
    static std::string trim(std::string &s);
    static std::string GetFileStream(const std::string& filePath);
    static bool FileExist(const std::string& path);
    static const int HASH_BUFFER_SIZE;
    static const int MIN_SIZE;
    static const int VERSION_SIZE;
    static const std::string VERSION_FILE;
    static const std::string METADATA_FILE;
    static const std::string GEOCODING_FILE;
    static const std::string CERT_FILE;
    static const std::string VERIFY_FILE;
    static const std::string MANIFEST_FILE;
    static const std::string CONFIG_TYPE;
    static const std::string SUB_TYPE;
    static const std::string CFG_PATH;
    static const std::string LOCALE_PATH;
    static const std::string PUBKEY_NAME;
    static const std::string PREFERENCE_PATH;
    static const std::string VERSION_NAME;
    static const std::string VERIFY_CERT_NAME;
    static const std::string METADATA_DIGEST_NAME;
    static const std::string GEOCODING_DIGEST_NAME;
    static std::shared_ptr<NativePreferences::Preferences> preferences;
};
} // namespace I18n
} // namespace Global
} // namespace OHOS
#endif