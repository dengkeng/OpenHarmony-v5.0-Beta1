/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/** 修改 build.json, 同一份代码编译不同版本 */
module.exports = function (content, map, meta) {
  const buildConfig = JSON.parse(content);
  if (buildConfig.hasOwnProperty('isBundle') && buildConfig.isBundle === false) {
    if (process.env.npm_config_bundle) {
      buildConfig.isBundle = process.env.npm_config_bundle;
      return JSON.stringify(buildConfig);
    }
  }
  return content;
};