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
import { LogUtil } from './logUtil';

export class StringUtils {
  static hasSubstring(str: string, sub: string | RegExp): boolean {
    let flag = false;
    try {
      flag = str.search(sub) !== -1;
    } catch (error) {
      LogUtil.e('StringUtils.hasSubstring', error);
    } 
    return flag;
  }

  static transformBooleanToTag(isCard: boolean, tagName: string): string {
    return isCard.toString() === 'true' ? tagName : 'NA';
  }
}
