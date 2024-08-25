/**
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

import util from '@ohos.util';
import resmgr from '@ohos.resourceManager';
import Logger from './Logger';

const TAG: string = 'RawFileUtil';
const UNICODE: string = 'utf-8';

/**
 * RawFile utility class
 */
export class RawFileUtil {
  /**
   * Get the object of the specified JSON file
   *
   * @param resourceManager Resource Manager
   * @param fileName file name
   * @returns The file content in string format
   */
  public static async getStringByFile(resourceManager: resmgr.ResourceManager, fileName: string): Promise<string> {
    Logger.info(TAG, `getFileContent. fileName: ${fileName}`);
    if (resourceManager === null || fileName === null) {
      Logger.error(TAG, `getFileContent failed.resourceManager or fileName is null.fileName:${fileName}`);
      return '';
    }
    try {
      let value: Uint8Array = await resourceManager.getRawFileContent(fileName);
      let content = util.TextDecoder.create(UNICODE).decodeWithStream(value);
      return content;
    } catch (jsonError) {
      Logger.error(TAG, `JSON parse error: ${jsonError?.code} ${jsonError?.message}`);
    }
    return '';
  }

  /**
   * Get the object of the specified JSON file
   *
   * @param context context
   * @param fileName file name
   * @return The file content in string format
   */
  public static async getRawFileByContext(context: Context, fileName: string): Promise<string> {
    Logger.info(TAG, `getFileContent. fileName: ${fileName}`);
    if (context === null || fileName === null) {
      Logger.error(TAG, `getFileContent failed.resourceManager or fileName is null.fileName:${fileName}`);
      return '';
    }
    try {
      let value: Uint8Array = await context.resourceManager.getRawFileContent(fileName);
      let content = util.TextDecoder.create('utf-8').decodeWithStream(value);
      return content;
    } catch (jsonError) {
      Logger.error(TAG, `JSON parse error: ${jsonError?.code} ${jsonError?.message}`);
    }
    return '';
  }
}