/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <climits>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <sstream>
#include <unistd.h>
#include "i18n_hilog.h"
#include "verify_sign_tool.h"
#include "utils.h"

namespace OHOS {
namespace Global {
namespace I18n {
namespace {
    const int32_t BASE64_ENCODE_PACKET_LEN = 3;
    const int32_t BASE64_ENCODE_LEN_OF_EACH_GROUP_DATA = 4;
}

const int VerifySignTool::HASH_BUFFER_SIZE = 4096;
const int VerifySignTool::MIN_SIZE = 2;
const int VerifySignTool::VERSION_SIZE = 4;
const std::string VerifySignTool::VERSION_FILE = "version.txt";
const std::string VerifySignTool::METADATA_FILE = "MetadataInfo";
const std::string VerifySignTool::GEOCODING_FILE = "GeocodingInfo";
const std::string VerifySignTool::CERT_FILE = "CERT.ENC";
const std::string VerifySignTool::VERIFY_FILE = "CERT.SF";
const std::string VerifySignTool::MANIFEST_FILE = "MANIFEST.MF";
const std::string VerifySignTool::CONFIG_TYPE = "LIBPHONENUMBER";
const std::string VerifySignTool::SUB_TYPE = "generic";
const std::string VerifySignTool::CFG_PATH =
    "/data/service/el1/public/update/param_service/install/system/etc/LIBPHONENUMBER/generic/";
const std::string VerifySignTool::LOCALE_PATH = "/system/etc/LIBPHONENUMBER/generic/";
const std::string VerifySignTool::PUBKEY_NAME = "hota_i18n_upgrade_v1.pem";
const std::string VerifySignTool::PREFERENCE_PATH = "/data/service/el1/public/i18n/libphonenumber";
const std::string VerifySignTool::VERSION_NAME = "version";
const std::string VerifySignTool::VERIFY_CERT_NAME = "verify_cert";
const std::string VerifySignTool::METADATA_DIGEST_NAME = "metadata_digest";
const std::string VerifySignTool::GEOCODING_DIGEST_NAME = "geocoding_digest";
std::shared_ptr<NativePreferences::Preferences> VerifySignTool::preferences = nullptr;

std::pair<int, int> VerifySignTool::Parse()
{
    std::pair<int, int> fds = {-1, -1};
    VerifyStatus status = Verify();
    if (status == VERIFY_FAILED) {
        return fds;
    } else if (status == VERIFY_START) {
        if (!VerifyDigest()) {
            return fds;
        }
    }
    std::string metadataPath = CFG_PATH + METADATA_FILE;
    int metadataFd = open(metadataPath.c_str(), O_RDONLY);
    std::string geocodingPath = CFG_PATH + GEOCODING_FILE;
    int geocodingFd = open(geocodingPath.c_str(), O_RDONLY);
    fds.first = metadataFd;
    fds.second = geocodingFd;
    return fds;
}

// verify MetadataInfo/GeocodingInfo digest
bool VerifySignTool::VerifyDigest()
{
    std::string metadataDigest = preferences->GetString(METADATA_DIGEST_NAME, "");
    if (metadataDigest.length() != 0) {
        std::string metadataPath = CFG_PATH + METADATA_FILE;
        if (CalcFileSha256Digest(metadataPath) != metadataDigest) {
            return false;
        }
    }
    std::string geocodingDigest = preferences->GetString(GEOCODING_DIGEST_NAME, "");
    if (geocodingDigest.length() != 0) {
        std::string geocodingPath = CFG_PATH + GEOCODING_FILE;
        if (CalcFileSha256Digest(geocodingPath) != geocodingDigest) {
            return false;
        }
    }
    return true;
}

// verify all update file
VerifyStatus VerifySignTool::Verify()
{
    std::string versionUpdatePath = CFG_PATH + VERSION_FILE;
    std::string versionUpdate = LoadFileVersion(versionUpdatePath);
    if (versionUpdate.length() == 0) {
        return VERIFY_FAILED;
    }
    std::string versionLocalePath = LOCALE_PATH + VERSION_FILE;
    std::string versionLocale = LoadFileVersion(versionLocalePath);
    if (versionLocale.length() == 0) {
        return VERIFY_FAILED;
    }
    int status;
    if (preferences == nullptr) {
        OHOS::NativePreferences::Options opt(PREFERENCE_PATH);
        preferences = NativePreferences::PreferencesHelper::GetPreferences(opt, status);
        if (status != 0) {
            preferences = nullptr;
        }
    }
    status = CompareVersion(versionLocale, versionUpdate);
    if (status <= 0) {
        return VERIFY_FAILED;
    } else {
        std::string versionPrefer = preferences->GetString(VERSION_NAME, "");
        status = CompareVersion(versionPrefer, versionUpdate);
        if (versionPrefer == "" || status > 0) {
            return VerifyCertAndConfig(versionUpdate);
        } else if (status == 0) {
            return GetVerifyInfo();
        }
    }
    return VERIFY_FAILED;
}

std::string VerifySignTool::LoadFileVersion(std::string& versionPath)
{
    std::string version;
    if (!FileExist(versionPath.c_str())) {
        return version;
    }
    if (!CheckTzDataFilePath(versionPath)) {
        return version;
    }
    std::ifstream file(versionPath);
    std::string line;
    std::vector<std::string> strs;
    while (std::getline(file, line)) {
        Split(line, "=", strs);
        if (strs.size() < MIN_SIZE) {
            continue;
        }
        if (strs[0] == VERSION_NAME) {
            version = trim(strs[1]);
            break;
        }
    }
    file.close();
    return version;
}

// compare version
int VerifySignTool::CompareVersion(std::string& preVersion, std::string& curVersion)
{
    std::vector<std::string> preVersionstr;
    std::vector<std::string> curVersionstr;
    Split(preVersion, ".", preVersionstr);
    Split(curVersion, ".", curVersionstr);
    if (curVersionstr.size() != VERSION_SIZE || preVersionstr.size() != VERSION_SIZE) {
        return -1;
    }
    for (int i = 0; i < VERSION_SIZE; i++) {
        if (atoi(preVersionstr.at(i).c_str()) < atoi(curVersionstr.at(i).c_str())) {
            return 1;
        } else if (atoi(preVersionstr.at(i).c_str()) > atoi(curVersionstr.at(i).c_str())) {
            return -1;
        }
    }
    return 0;
}

// determine if the certificate file has been verified
VerifyStatus VerifySignTool::GetVerifyInfo()
{
    bool isVerifyCert = false;
    if (preferences != nullptr) {
        isVerifyCert = preferences->GetBool(VERIFY_CERT_NAME, false);
    }
    return isVerifyCert ? VERIFY_START : VERIFY_FAILED;
}

// verify certificate file and config file
VerifyStatus VerifySignTool::VerifyCertAndConfig(std::string& version)
{
    int status;
    if (VerifyCertFile() && VerifyConfigFiles()) {
        if (preferences != nullptr) {
            status = preferences->PutBool(VERIFY_CERT_NAME, true);
            if (status == 0) {
                preferences->PutString(VERSION_NAME, version);
            }
            preferences->Flush();
        }
        return VERIFY_SUCCESS;
    } else {
        if (preferences != nullptr) {
            status = preferences->PutBool(VERIFY_CERT_NAME, false);
            if (status == 0) {
                preferences->PutString(VERSION_NAME, version);
            }
            preferences->Flush();
        }
        return VERIFY_FAILED;
    }
}

// // verify certificate file
bool VerifySignTool::VerifyCertFile()
{
    std::string certPath = CFG_PATH + CERT_FILE;
    std::string verifyPath = CFG_PATH + VERIFY_FILE;
    std::string pubkeyPath = LOCALE_PATH + PUBKEY_NAME;
    if (!VerifyFileSign(pubkeyPath, certPath, verifyPath)) {
        return false;
    }
    std::ifstream file(verifyPath);
    if (!file.good()) {
        return false;
    }
    std::string line;
    std::string sha256Digest;
    std::getline(file, line);
    file.close();
    std::vector<std::string> strs;
    Split(line, ":", strs);
    if (strs.size() < MIN_SIZE) {
        return false;
    }
    sha256Digest = strs[1];
    sha256Digest = trim(sha256Digest);
    std::string manifestPath = CFG_PATH + MANIFEST_FILE;
    std::string manifestDigest = CalcFileSha256Digest(manifestPath);
    if (sha256Digest == manifestDigest) {
        return true;
    }
    return false;
}

// verify config file
bool VerifySignTool::VerifyConfigFiles()
{
    std::string versionPath = CFG_PATH + VERSION_FILE;
    if (!FileExist(versionPath.c_str())) {
        return false;
    }
    if (VerifyParamFile(VERSION_FILE).length() == 0) {
        return false;
    }
    std::string metadataPath = CFG_PATH + METADATA_FILE;
    std::string metadataDigest = VerifyParamFile(METADATA_FILE);
    if (FileExist(metadataPath.c_str()) && metadataDigest.length() == 0) {
        return false;
    }
    std::string geocodingDigest = VerifyParamFile(GEOCODING_FILE);
    std::string geocodingPath = CFG_PATH + GEOCODING_FILE;
    if (FileExist(geocodingPath.c_str()) && geocodingDigest.length() == 0) {
        return false;
    }
    if (preferences != nullptr) {
        if (metadataDigest.length() != 0) {
            preferences->PutString(METADATA_DIGEST_NAME, metadataDigest);
        }
        if (geocodingDigest.length() != 0) {
            preferences->PutString(GEOCODING_DIGEST_NAME, geocodingDigest);
        }
        preferences->Flush();
    }
    return true;
}

// verify param file digest
std::string VerifySignTool::VerifyParamFile(const std::string& filePath)
{
    std::string manifestPath = CFG_PATH + MANIFEST_FILE;
    std::ifstream file(manifestPath);
    if (!file.good()) {
        return "";
    }
    std::string absFilePath = CFG_PATH + filePath;
    if (!CheckTzDataFilePath(absFilePath)) {
        return "";
    }
    std::string sha256Digest;
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("Name: " + filePath) != std::string::npos) {
            std::string nextLine;
            std::getline(file, nextLine);
            std::vector<std::string> strs;
            Split(nextLine, ":", strs);
            if (strs.size() < MIN_SIZE) {
                return "";
            }
            sha256Digest = strs[1];
            sha256Digest = trim(sha256Digest);
            break;
        }
    }
    if (sha256Digest.empty()) {
        return "";
    }
    std::string fileDigest = CalcFileSha256Digest(absFilePath);
    if (fileDigest == sha256Digest) {
        return fileDigest;
    }
    return "";
}

std::string VerifySignTool::trim(std::string &s)
{
    if (s.empty()) {
        return s;
    }
    s.erase(0, s.find_first_not_of(" "));
    s.erase(s.find_last_not_of(" ") + 1);
    return s;
}

// verify cert file sign
bool VerifySignTool::VerifyFileSign(const std::string& pubkeyPath, const std::string& signPath,
    const std::string& digestPath)
{
    if (!FileExist(pubkeyPath.c_str())) {
        return false;
    }

    if (!FileExist(signPath.c_str())) {
        return false;
    }

    if (!FileExist(digestPath.c_str())) {
        return false;
    }
    std::string signStr = GetFileStream(signPath);
    std::string digestStr = GetFileStream(digestPath);
    RSA* pubkey = RSA_new();
    bool verify = false;
    if (pubkey != nullptr && !signStr.empty() && !digestStr.empty()) {
        BIO* bio = BIO_new_file(pubkeyPath.c_str(), "r");
        if (PEM_read_bio_RSA_PUBKEY(bio, &pubkey, nullptr, nullptr) == nullptr) {
            BIO_free(bio);
            return false;
        }
        verify = VerifyRsa(pubkey, digestStr, signStr);
        BIO_free(bio);
    }
    RSA_free(pubkey);
    return verify;
}

bool VerifySignTool::VerifyRsa(RSA* pubkey, const std::string& digest, const std::string& sign)
{
    EVP_PKEY* evpKey = EVP_PKEY_new();
    if (evpKey == nullptr) {
        return false;
    }
    if (EVP_PKEY_set1_RSA(evpKey, pubkey) != 1) {
        return false;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    if (ctx == nullptr) {
        EVP_PKEY_free(evpKey);
        return false;
    }
    if (EVP_VerifyInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_VerifyUpdate(ctx, digest.c_str(), digest.size()) != 1) {
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    char* signArr = const_cast<char*>(sign.c_str());
    if (EVP_VerifyFinal(ctx, reinterpret_cast<unsigned char *>(signArr), sign.size(), evpKey) != 1) {
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_free(evpKey);
    EVP_MD_CTX_free(ctx);
    return true;
}

std::string VerifySignTool::CalcFileSha256Digest(const std::string& path)
{
    unsigned char res[SHA256_DIGEST_LENGTH] = {0};
    CalcFileShaOriginal(path, res, SHA256_DIGEST_LENGTH);
    std::string dist;
    CalcBase64(res, SHA256_DIGEST_LENGTH, dist);
    return dist;
}

void VerifySignTool::CalcBase64(uint8_t* input, int inputLen, std::string& encodedStr)
{
    size_t base64Len = static_cast<size_t>(ceil(static_cast<long double>(inputLen) / BASE64_ENCODE_PACKET_LEN) *
        BASE64_ENCODE_LEN_OF_EACH_GROUP_DATA + 1);
    std::unique_ptr<unsigned char[]> base64Str = std::make_unique<unsigned char[]>(base64Len);
    int encodeLen = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(base64Str.get()), input, inputLen);
    size_t outLen = static_cast<size_t>(encodeLen);
    encodedStr = std::string(reinterpret_cast<char*>(base64Str.get()), outLen);
}

int VerifySignTool::CalcFileShaOriginal(const std::string& filePath, unsigned char* hash, size_t len)
{
    if (filePath.empty() || hash == nullptr || !IsLegalPath(filePath) || len < SHA256_DIGEST_LENGTH) {
        return -1;
    }
    FILE* fp = fopen(filePath.c_str(), "rb");
    if (fp == nullptr) {
        return -1;
    }
    size_t n;
    char buffer[HASH_BUFFER_SIZE] = {0};
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    while ((n = fread(buffer, 1, sizeof(buffer), fp))) {
        SHA256_Update(&ctx, reinterpret_cast<unsigned char*>(buffer), n);
    }
    SHA256_Final(hash, &ctx);
    if (fclose(fp) == -1) {
        return -1;
    }
    return 0;
}

// load file content
std::string VerifySignTool::GetFileStream(const std::string& filePath)
{
    if (filePath.length() >= PATH_MAX) {
        return "";
    }
    char* resolvedPath = new char[PATH_MAX + 1];
    if (realpath(filePath.c_str(), resolvedPath) == nullptr) {
        delete[] resolvedPath;
        return "";
    }
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.good()) {
        delete[] resolvedPath;
        return "";
    }
    std::stringstream inFile;
    inFile << file.rdbuf();
    delete[] resolvedPath;
    return inFile.str();
}

bool VerifySignTool::IsLegalPath(const std::string& path)
{
    if (path.find("./") != std::string::npos ||
        path.find("../") != std::string::npos) {
        return false;
    }
    return true;
}

void VerifySignTool::Split(const std::string &src, const std::string &sep, std::vector<std::string> &dest)
{
    if (src == "") {
        return;
    }
    std::string::size_type begin = 0;
    std::string::size_type end = src.find(sep);
    while (end != std::string::npos) {
        dest.push_back(src.substr(begin, end - begin));
        begin = end + sep.size();
        end = src.find(sep, begin);
    }
    if (begin != src.size()) {
        dest.push_back(src.substr(begin));
    }
}

bool VerifySignTool::FileExist(const std::string& path)
{
    bool status = false;
    try {
        status = std::filesystem::exists(path.c_str());
    } catch (const std::filesystem::filesystem_error &except) {
        HILOG_ERROR_I18N("FileExist failed because filesystem_error, error message: %{public}s.",
            except.code().message().c_str());
        return false;
    } catch (const std::__h::__fs::filesystem::filesystem_error &except) {
        HILOG_ERROR_I18N("FileExist failed because filesystem_error, error message: %{public}s.",
            except.code().message().c_str());
        return false;
    } catch (const std::bad_alloc &except) {
        HILOG_ERROR_I18N("FileExist failed because bad_alloc, error message: %{public}s.",
            except.what());
        return false;
    }
    return status;
}
}
}
}
