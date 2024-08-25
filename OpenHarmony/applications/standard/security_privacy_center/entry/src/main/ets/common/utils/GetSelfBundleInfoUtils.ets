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

import bundleManager from '@ohos.bundle.bundleManager';
import HiSysEventConstant from '../constants/HiSysEventConstant';
import Logger from './Logger';
import { BusinessError } from '@ohos.base';

const TAG = 'SPS';

class GetSelfBundleInfoUtils {
  private versionName: string = '';

  /**
   * Obtains the version name of SecurityPrivacyCenter
   *
   * @returns Promise<string> versionName
   */
  getVersionName(): Promise<string> {
    return new Promise<string>(async (resolve) => {
      if (this.versionName !== '') {
        Logger.info(TAG, `get versionName from object variable : ${this.versionName}`);
        resolve(this.versionName)
      } else {
        try {
          await bundleManager.getBundleInfo(HiSysEventConstant.BUNDLE_NAME,
            bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT).then((data) => {
            this.versionName = data.versionName;
            Logger.info(TAG, `get versionName from BMS : ${this.versionName}`);
            resolve(this.versionName);
          }).catch((err: BusinessError) => {
            Logger.error(TAG, `getBundleInfo failed, BusinessError: ${err.message}`);
          })
        } catch (err) {
          Logger.error(TAG, `getBundleInfo failed: ${err.message}`)
        }
      }
    })
  }
}

let getSelfBundleInfoUtils = new GetSelfBundleInfoUtils();

export default getSelfBundleInfoUtils as GetSelfBundleInfoUtils;