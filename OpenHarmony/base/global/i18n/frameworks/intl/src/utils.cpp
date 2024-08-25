/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <climits>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include "i18n_hilog.h"
#include "locale_config.h"
#include "parameter.h"
#include "unicode/localebuilder.h"
#include "utils.h"

namespace OHOS {
namespace Global {
namespace I18n {
using namespace std;
static const std::string PSEUDO_LOCALE_TAG = "en-XA";
static const std::string PSEUDO_START_TAG = "{";
static const std::string PSEUDO_END_TAG = "}";

void Split(const string &src, const string &sep, vector<string> &dest)
{
    if (src == "") {
        return;
    }
    string::size_type begin = 0;
    string::size_type end = src.find(sep);
    while (end != string::npos) {
        dest.push_back(src.substr(begin, end - begin));
        begin = end + sep.size();
        end = src.find(sep, begin);
    }
    if (begin != src.size()) {
        dest.push_back(src.substr(begin));
    }
}

std::string ReadSystemParameter(const char *paramKey, const int paramLength)
{
    char param[paramLength];
    int status = GetParameter(paramKey, "", param, paramLength);
    if (status > 0) {
        return param;
    }
    return "";
}

int32_t ConvertString2Int(const string &numberStr, int32_t& status)
{
    if (!numberStr.empty() && std::all_of(numberStr.begin(), numberStr.end(), ::isdigit)) {
        try {
            return std::stoi(numberStr);
        } catch (const std::invalid_argument &except) {
            status = -1;
            return -1;
        } catch (const std::out_of_range &except) {
            status = -1;
            return -1;
        } catch (...) {
            status = -1;
            HILOG_ERROR_I18N("ConvertString2Int: unknow error. numberStr: %{public}s.", numberStr.c_str());
            return -1;
        }
    } else {
        status = -1;
        return -1;
    }
}

bool IsValidLocaleTag(icu::Locale &locale)
{
    static std::unordered_set<std::string> allValidLocalesLanguageTag;
    GetAllValidLocalesTag(allValidLocalesLanguageTag);
    std::string languageTag = locale.getLanguage();
    if (allValidLocalesLanguageTag.find(languageTag) == allValidLocalesLanguageTag.end()) {
        HILOG_ERROR_I18N("GetTimePeriodName does not support this languageTag: %{public}s", languageTag.c_str());
        return false;
    }
    return true;
}

void GetAllValidLocalesTag(std::unordered_set<std::string>& allValidLocalesLanguageTag)
{
    static bool init = false;
    if (init) {
        return;
    }
    int32_t validCount = 1;
    const icu::Locale *validLocales = icu::Locale::getAvailableLocales(validCount);
    for (int i = 0; i < validCount; i++) {
        allValidLocalesLanguageTag.insert(validLocales[i].getLanguage());
    }
    init = true;
}

bool CheckTzDataFilePath(const std::string &filePath)
{
    char *realpathRes = nullptr;
    realpathRes = realpath(filePath.c_str(), nullptr);
    if (realpathRes == nullptr) {
        return false;
    }
    std::ifstream file(filePath.c_str());
    if (!file.good()) {
        file.close();
        free(realpathRes);
        return false;
    }
    file.close();
    free(realpathRes);
    realpathRes = nullptr;
    return true;
}

bool GetPseudoLocalizationEnforce()
{
    std::string systemLocale = LocaleConfig::GetSystemLocale();
    if (systemLocale.compare(PSEUDO_LOCALE_TAG) == 0) {
        return true;
    }
    return false;
}

std::string PseudoLocalizationProcessor(const std::string &input)
{
    return PseudoLocalizationProcessor(input, GetPseudoLocalizationEnforce());
}

std::string PseudoLocalizationProcessor(const std::string &input, bool ifEnforce)
{
    if (ifEnforce) {
        return PSEUDO_START_TAG + input + PSEUDO_END_TAG;
    }
    return input;
}

std::string StrReplaceAll(const std::string& str,
    const std::string& target, const std::string& replace)
{
    std::string::size_type pos = 0;
    std::string result = str;
    if (replace.empty() || target.compare(replace) == 0) {
        return result;
    }
    while ((pos = result.find(target)) != std::string::npos) {
        result.replace(pos, target.length(), replace);
    }
    return result;
}

std::string GetISO3Language(const string& language)
{
    UErrorCode icuStatus = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(language.data(), icuStatus);
    if (U_FAILURE(icuStatus) || !IsValidLocaleTag(locale)) {
        return "";
    }
    return locale.getISO3Language();
}

std::string GetISO3Country(const string& country)
{
    UErrorCode icuStatus = U_ZERO_ERROR;
    icu::Locale locale;
    if (LocaleConfig::IsValidRegion(country)) {
        locale = icu::LocaleBuilder().setLanguage("zh").setRegion(country).build(icuStatus);
    } else if (LocaleConfig::IsValidTag(country)) {
        locale = icu::Locale::forLanguageTag(country.data(), icuStatus);
    } else {
        return "";
    }
    if (U_FAILURE(icuStatus) || !IsValidLocaleTag(locale)) {
        return "";
    }
    return locale.getISO3Country();
}

} // namespace I18n
} // namespace Global
} // namespace OHOS