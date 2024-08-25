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

import { JSDocModifierImpl } from './core/entry';
import type { IJSDocModifier } from './core/typedef';
import { ConstantValue, StringResourceId } from './utils/constant';
import { StringResource, StringUtils } from './utils/stringUtils';

function main(): void {
  checkEnvVersion();
  const jsDocModifier: IJSDocModifier = new JSDocModifierImpl();
  jsDocModifier.start();
}

function checkEnvVersion(): void {
  const version = process.version;
  const versionRegExp = /^v(\d+)\.(\d+)\.(\d+).*/;
  const matchArray = version.match(versionRegExp);
  const requiredVersions = [ConstantValue.MAJOR_V, ConstantValue.MINOR_V, ConstantValue.PATCH_V];
  let showVersionWarning = true;
  const MAX_LENGTH = 4;
  const LOOP_MAX_LENGTH = 3;
  if (matchArray && matchArray.length === MAX_LENGTH) {
    for (let index = 0; index < LOOP_MAX_LENGTH; index++) {
      const curV = Number(matchArray[index + 1]);
      const requiredV = requiredVersions[index];
      if (curV > requiredV || curV < requiredV) {
        showVersionWarning = curV > requiredV;
        break;
      } else {
        continue;
      }
    }
  }
  if (showVersionWarning) {
    return;
  }
  let hintMessage = StringResource.getString(StringResourceId.VERSION_HINT);
  hintMessage = StringUtils.formatString(hintMessage, requiredVersions);
  console.warn('jsdoc-tool:', hintMessage);
}

main();