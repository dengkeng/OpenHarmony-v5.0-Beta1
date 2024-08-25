/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at 
*
* http://www.apache.org/licenses/LICENSE-2.0 
*
* Unless required by applicable law or agreed to in writing, software 
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License. 
*/
const { writeFile } = require("./Tool");
const re = require("./re");

let commonH = `
#ifndef [h_define_replace]
#define [h_define_replace]

#include <js_native_api.h>
#include <js_native_api_types.h>
#include <string>
#include <stdio.h>
#include <vector>
#include "hilog/log.h"
#include "napi/native_api.h"
#include "[business_include_replace]"

#define GLOBAL_RESMGR (0xFFEE)
const unsigned int LOG_PRINT_DOMAIN = 0xFF00;

constexpr int32_t STR_MAX_SIZES = 200;
constexpr int32_t LONG_STR_MAX_SIZES = 1024;
constexpr uint8_t PARAMS0 = 0;
constexpr uint8_t PARAMS1 = 1;
constexpr uint8_t PARAMS2 = 2;
constexpr uint8_t PARAMS3 = 3;
constexpr uint8_t PARAMS4 = 4;
constexpr uint8_t PARAMS5 = 5;
constexpr uint8_t PARAMS6 = 6;
constexpr uint8_t PARAMS7 = 7;
constexpr uint8_t PARAMS8 = 8;
constexpr uint8_t PARAMS9 = 9;
constexpr uint8_t PARAMS10 = 10;
constexpr uint8_t PARAMS11 = 11;
constexpr uint8_t PARAMS12 = 12;
constexpr uint8_t PARAMS100 = 100;

void getErrMessage(napi_status &status, napi_env &env, const napi_extended_error_info *&extended_error_info,
    const char *info, const char *tag);

#endif //[h_define_replace]
`

let commonCpp = `
#include "[include_name]common.h"

/*[NAPI_GEN]:错误处理,获取错误详细信息*/
void getErrMessage(napi_status &status, napi_env &env, const napi_extended_error_info *&extended_error_info,
    const char *info, const char *tag)
{
    status = napi_get_last_error_info(env, &extended_error_info);
    if (status == napi_ok && extended_error_info != NULL) {
        const char *errorMessage =
            extended_error_info->error_message != NULL ? extended_error_info->error_message : "Unknown error";
        OH_LOG_Print(LOG_APP, LOG_ERROR, GLOBAL_RESMGR, tag, "errmsg %{public}s!, engine_err_code %{public}d!.",
        std::to_string(extended_error_info->engine_error_code).c_str(), extended_error_info->error_code);
        std::string myInfo = info;
        std::string res = "Failed to " + myInfo + " em = " + errorMessage +
            ", eec = " + std::to_string(extended_error_info->engine_error_code) +
            ", ec = " + std::to_string(extended_error_info->error_code);
        napi_throw_error(env, NULL, res.c_str());
    }
}
`

function generateBase(destDir, license, hFilePath) {
  let index = hFilePath.lastIndexOf("\\");
  let indexH = hFilePath.lastIndexOf(".h");
  let hFileName = hFilePath.substring(index + 1, indexH).toLowerCase();
  // [h_define_replace]
  let hDefine = "NAPITUTORIALS_" + hFileName.toLocaleUpperCase() + "COMMON_H"
  commonH = replaceAll(commonH, "[h_define_replace]", hDefine)
  // [business_include_replace]
  let businessInclude = hFilePath.substring(index + 1, hFilePath.length)
  commonH = replaceAll(commonH, "[business_include_replace]", businessInclude)
  commonCpp = replaceAll(commonCpp, "[include_name]", hFileName)
  writeFile(re.pathJoin(destDir, hFileName + "common.h"), null != license ? (license + "\n" + commonH) : commonH)
  writeFile(re.pathJoin(destDir, hFileName + "common.cpp"), null != license ? (license + "\n" + commonCpp): commonCpp)
}

function replaceAll(s, sfrom, sto) {
  while (s.indexOf(sfrom) >= 0) {
      s = s.replace(sfrom, sto)
  }
  return s;
}

module.exports = {
  generateBase
}