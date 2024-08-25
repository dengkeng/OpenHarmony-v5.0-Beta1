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

import UIExtensionAbility from '@ohos.app.ability.UIExtensionAbility';
import logger from '../common/logger';
import Want from '@ohos.app.ability.Want';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import configPolicy from '@ohos.configPolicy';
import fs from '@ohos.file.fs';
import adminManager from '@ohos.enterprise.adminManager';
import { BusinessError } from '@ohos.base';

const TAG = 'AutoDeployAbility';

export default class AutoDeployAbility extends UIExtensionAbility {
  private localStorage: LocalStorage = new LocalStorage();

  async onSessionCreate(want: Want, session: UIExtensionContentSession): Promise<void> {
    logger.info(TAG, 'onSessionCreate');
    let admin: Want = {
      bundleName: '',
      abilityName: ''
    };
    let enterpriseInfo: adminManager.EnterpriseInfo = {
      name: '',
      description: ''
    };
    let adminType: adminManager.AdminType;
    try {
      let realpath = 'etc/edm/edm_provision_config.json';
      await configPolicy.getOneCfgFile(realpath).then((value: string) => {
        logger.info(TAG, 'getOneCfgFile value is : ' + value);
        let configStr = fs.readTextSync(value);
        logger.info(TAG, 'getOneCfgFile configStr is ' + JSON.stringify(configStr));
        if (configStr) {
          let jsonArray = JSON.parse(configStr);
          admin.abilityName = jsonArray.admin_info[0].admin.abilityName;
          admin.bundleName = jsonArray.admin_info[0].admin.bundleName;
          enterpriseInfo.name = jsonArray.enterprise_info.organization_name;
          enterpriseInfo.description = jsonArray.enterprise_info.description;
          if (jsonArray.admin_info[0].admin_type == 'SDA') {
            adminType = adminManager.AdminType.ADMIN_TYPE_SUPER;
          }
          this.localStorage.setOrCreate('adminInfo', admin);
          this.localStorage.setOrCreate('enterpriseInfo', enterpriseInfo);
          this.localStorage.setOrCreate('adminType', adminType);
        }
      }).catch((err: BusinessError) => {
        logger.error(`getOneCfgFile edm_provision_config.json fail, errCode: ${err.code}, errMessage: ${err.message}`);
      })
    } catch (error) {
      let code = (error as BusinessError).code;
      let message = (error as BusinessError).message;
      logger.info(TAG, 'getOneCfgFile error: ' + code + message);
    }
    this.localStorage.setOrCreate('session', session);
    session.loadContent('pages/custProvisioning/custProvisioning', this.localStorage);
  }

  onDestroy(): void {
    logger.info(TAG, 'onDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    logger.info(TAG, 'onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    logger.info(TAG, 'onBackground');
  }
};
