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

import resourceManager from '@ohos.resourceManager';
import common from '@ohos.app.ability.common';
import { StringUtil } from './StringUtil';
import Logger from './Logger';

const TAG = 'ResourceUtil'

class ResourceUtil {
  /**
   * Obtains the resource name
   * @param resource Resource file
   * @returns Resource File Name
   */

  getResourceString(context: object, resource: Resource, params?: Array<string | number>): string {
    let resourceString: string = '';
    try {
      if (params && params.length) {
        resourceString = getContext(context).resourceManager.getStringSync(resource.id, ...params);
      } else {
        resourceString = getContext(context).resourceManager.getStringSync(resource.id);
      }
    } catch (error) {
      Logger.error(TAG, `getResourceString error = ${JSON.stringify(error)}`)
    }
    return resourceString
  }

  /**
   * Get the specified package name resource manager
   * @params bundleName Application package name
   * @params context context
   */

  getBundleResourceManager(bundleName: string, context: common.Context | null): resourceManager.ResourceManager | null {
    if (context === null || StringUtil.isEmpty(bundleName)) {
      Logger.error(TAG, 'getBundleResourceManager error');
      return null;
    }
    try {
      let bundleContext = context.createBundleContext(bundleName);
      if (bundleContext === null || bundleContext === undefined) {
        Logger.error(TAG, 'get bundleContext failed')
        return null;
      }
      return bundleContext.resourceManager;
    } catch (error) {
      Logger.error(TAG, `get bundleContext faild, error message : ${JSON.stringify(error)}}`)
      return null;
    }
  }

  getFloatNumber(resource: Resource): number {
    let context = getContext(this) as common.UIAbilityContext;
    return px2vp(context.resourceManager.getNumber(resource.id))
  }
}

let resourceUtil = new ResourceUtil();

export default resourceUtil as ResourceUtil;