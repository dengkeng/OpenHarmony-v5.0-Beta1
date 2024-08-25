/**
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
import bundleResManager from '@ohos.bundle.bundleResourceManager';
import { CMModelErrorCode } from '../model/CertMangerModel';
import { AppInfoVo } from './CertManagerVo/AppInfoVo';
import { BusinessError } from '@ohos.base';

const TAG = 'certManager BUNDLE:';

export class BundleNameModel {
  async getAppInfoList(appUid: number, callback: Function): Promise<void> {
    console.log(TAG + 'getAppInfoList enter uid: ' + appUid);
    try {
      let appInfo: AppInfoVo = {
        appImage: '',
        appName: '',
      };

      let appBundleName = await bundleManager.getBundleNameByUid(appUid);
      console.log(TAG + 'appBundleName: ' + appBundleName);

      let bundleFlags = bundleResManager.ResourceFlag.GET_RESOURCE_INFO_ALL;
      let resourceInfo = bundleResManager.getBundleResourceInfo(appBundleName, bundleFlags);
      appInfo.appName = resourceInfo.label;
      appInfo.appImage = resourceInfo.icon;
      console.log(TAG + 'get bundle info success');

      callback(CMModelErrorCode.CM_MODEL_ERROR_SUCCESS, appInfo);
    } catch (err) {
      let e: BusinessError = err as BusinessError;
      console.error(TAG + 'getAppInfoList failed, message: ' + e.message + ', code: ' + e.code);
      callback(CMModelErrorCode.CM_MODEL_ERROR_EXCEPTION, undefined);
    }
  }
}

let bundleNameModel = new BundleNameModel();

export default bundleNameModel as BundleNameModel;
