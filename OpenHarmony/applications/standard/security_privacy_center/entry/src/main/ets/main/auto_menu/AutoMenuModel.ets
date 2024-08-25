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

import { BaseModel } from '../../common/base/BaseModel';
import { MenuConfig } from '../../common/bean/MenuConfig';
import { AutoMenuManager } from '../../common/utils/AutoMenuManager';
import resourceUtil from '../../common/utils/ResourceUtil';
import osAccount from '@ohos.account.osAccount';
import { RdbManager } from '../../common/utils/RdbManager';
import relationalStore from '@ohos.data.relationalStore';
import DataShareConstants from '../../common/constants/DataShareConstant';
import MenuInfo from '../../common/bean/MenuInfo';
import router from '@ohos.router';
import { BusinessError } from '@ohos.base';
import HiSysEventUtil from '../../common/utils/HiSysEventUtil';
import Logger from '../../common/utils/Logger';
import common from '@ohos.app.ability.common';

const TAG = 'AutoMenu';
// This ability pattern needs to inherit from UIExtensionAbility
const DST_ABILITY_MODE = 1;
// this mode is jump page
const DST_PAGE_MODE = 2;
//UIAbility access method
const DST_UIABILITY_MODE = 0;

export class AutoMenuModel extends BaseModel {
  async getMenuInfoListFromRdb(context: Context): Promise<MenuInfo[]> {
    Logger.info(TAG, 'getMenuInfoListFromRdb start.');
    let menuInfoList: MenuInfo[] = [];
    let predicates = new relationalStore.RdbPredicates(DataShareConstants.ANTO_MENU_TABLE_V2.tableName);
    let resultSet: relationalStore.ResultSet | undefined = await RdbManager.getInstance().query(context, predicates);
    if (resultSet === undefined) {
      Logger.info(TAG, 'getMenuInfoListFromRdb menuInfo undefined');
      return menuInfoList;
    }
    let count: number = resultSet.rowCount;
    if (count === 0 || typeof count === 'string' || count === -1) {
      Logger.info(TAG, 'getMenuInfoListFromRdb no result!');
      return menuInfoList;
    }
    resultSet.goToFirstRow();
    for (let i = 0; i < count; i++) {
      const bundleName: string = resultSet.getString(resultSet.getColumnIndex('bundleName'));
      const mainTitleResource: string = resultSet.getString(resultSet.getColumnIndex('mainTitleResource'));
      const subTitleResource: string = resultSet.getString(resultSet.getColumnIndex('subTitleResource'));
      const templeData: MenuInfo = {
        businessId: resultSet.getString(resultSet.getColumnIndex('businessId')),
        intents: resultSet.getString(resultSet.getColumnIndex('intents')),
        userId: resultSet.getDouble(resultSet.getColumnIndex('userId')),
        iconBackgroundColorResource: resultSet.getString(resultSet.getColumnIndex('iconBackgroundColorResource')),
        priority: resultSet.getDouble(resultSet.getColumnIndex('priority')),
        isSupport: resultSet.getDouble(resultSet.getColumnIndex('isSupport')),
        isClickable: resultSet.getDouble(resultSet.getColumnIndex('isClickable')),
        displayedMode: resultSet.getString(resultSet.getColumnIndex('displayedMode')),
        iconResource: resultSet.getString(resultSet.getColumnIndex('iconResource')),
        mainTitleResource: mainTitleResource,
        subTitleResource: resultSet.getString(resultSet.getColumnIndex('subTitleResource')),
        showControlAbilityUri: resultSet.getString(resultSet.getColumnIndex('showControlAbilityUri')),
        dstAbilityMode: resultSet.getDouble(resultSet.getColumnIndex('dstAbilityMode')),
        dstAbilityName: resultSet.getString(resultSet.getColumnIndex('dstAbilityName')),
        dstBundleName: resultSet.getString(resultSet.getColumnIndex('dstBundleName')),
        bundleName: bundleName,
        titleString: await this._getConfigResString(context, bundleName, mainTitleResource),
        subTitleString: await this._getConfigResString(context, bundleName, subTitleResource)
      };
      menuInfoList[i] = templeData;
      resultSet.goToNextRow();
    }
    Logger.info(TAG, 'getMenuInfoListFromRdb: ' + JSON.stringify(menuInfoList));
    return menuInfoList;
  }

  async getMenuInfoListFromBms(context: Context): Promise<MenuInfo[]> {
    let userId: number = await this._getUserId();
    //   Obtain configuration data
    let menuConfigs: MenuConfig[] = await AutoMenuManager.getInstance().getMenuConfigFromBms(context, userId);
    Logger.info(TAG, 'getMenuInfoList menuConfigList: ' + JSON.stringify(menuConfigs));
    //   Convert to actual data that needs to be displayed
    let menuInfoList: MenuInfo[] = await this._convertMenuConfigToMenuInfo(context, menuConfigs, userId);
    Logger.info(TAG, 'getMenuInfoList menuInfoList: ' + JSON.stringify(menuInfoList));
    //   sort
    menuInfoList.sort((left: MenuInfo, right: MenuInfo) => {
      if (left.priority !== right.priority) {
        return right.priority - left.priority;
      } else {
        return left.bundleName.localeCompare(right.bundleName);
      }
    })
    //   Write to database cache
    this._refreshDb(context, menuInfoList);
    return menuInfoList;
  }

  handleMenuClick(menuInfo: MenuInfo) {
    // Accessing the framework through UIAbility
    if (menuInfo.dstAbilityMode === DST_UIABILITY_MODE) {
      let context = getContext() as common.UIAbilityContext;
      context.startAbility({
        bundleName: menuInfo.dstBundleName,
        abilityName: menuInfo.dstAbilityName
      }).then((data) => {
        Logger.info(TAG, `${menuInfo.dstBundleName} start successful.data: ${JSON.stringify(data)}`)
      }).catch((err: BusinessError) => {
        Logger.error(TAG, `${menuInfo.dstBundleName} start failed. Cause: ${JSON.stringify(err)}`)
      })
    }
    //   jump page
    if (menuInfo.dstAbilityMode === DST_PAGE_MODE) {
      router.pushUrl({
        url: menuInfo.dstAbilityName
      }, router.RouterMode.Single).then(() => {
        Logger.info(TAG, 'Succeeded in jumping to the dst page.')
      }).catch((err: BusinessError) => {
        Logger.error(TAG, `Failed to jump to the second page.Code is ${err.code},message is ${err.message}`);
      })
    }
    //   Jump UIExtensionAbility
    HiSysEventUtil.reportAccessClick(menuInfo.dstBundleName)
    if (menuInfo.dstAbilityMode === DST_ABILITY_MODE) {
      router.pushUrl({
        url: 'pages/UiExtensionPage',
        params: {
          'dstBundleName': menuInfo.dstBundleName,
          'dstAbilityName': menuInfo.dstAbilityName
        }
      }, router.RouterMode.Single).then(() => {
        Logger.info(TAG, 'Succeeded in jumping to the second page.')
      }).catch((err: BusinessError) => {
        Logger.error(TAG, `Failed to jump to the second page.Code is ${err.code},message is ${err.message}`);
      })
    }
  }

  private async _refreshDb(context: Context, menuInfoList: MenuInfo[]) {
    let predicates = new relationalStore.RdbPredicates(DataShareConstants.ANTO_MENU_TABLE_V2.tableName);
    let deleteResult: number = await RdbManager.getInstance().delete(context, predicates);
    Logger.info(TAG, 'Delete menuInfo Result: ' + deleteResult);
    for (let index = 0; index < menuInfoList.length; index++) {
      const element = menuInfoList[index];
      const valueBucket: relationalStore.ValuesBucket = this._generateBucket(element);
      await RdbManager.getInstance().insert(context, DataShareConstants.ANTO_MENU_TABLE_V2.tableName, valueBucket);
    }
    Logger.info(TAG, '_refreshDb end.')
  }

  //   MenuConfig[] to MenuInfo[]
  private async _convertMenuConfigToMenuInfo(context: Context, menuConfigList: MenuConfig[],
    userId: number): Promise<MenuInfo[]> {
    let menuInfoList: MenuInfo[] = [];
    for (let i = 0; i < menuConfigList.length; i++) {
      const menuConfig: MenuConfig = menuConfigList[i];
      let menuInfo: MenuInfo = {
        businessId: menuConfig.businessId,
        intents: menuConfig.dstBundleName + '-' + menuConfig.dstAbilityName,
        userId: userId,
        iconBackgroundColorResource: '',
        isClickable: 1,
        displayedMode: menuConfig.displayedMode,
        iconResource: menuConfig.iconResource,
        mainTitleResource: menuConfig.mainTitleResource,
        subTitleResource: menuConfig.subTitleResource,
        showControlAbilityUri: menuConfig.showControlAbilityUri,
        dstAbilityMode: menuConfig.dstAbilityMode,
        dstAbilityName: menuConfig.dstAbilityName,
        dstBundleName: menuConfig.dstBundleName,
        bundleName: menuConfig.bundleName,
        priority: await AutoMenuManager.getInstance().getMenuPriority(context, menuConfig),
        isSupport: await AutoMenuManager.getInstance().isSupportMenu(context, menuConfig),
        titleString: await this._getConfigResString(context, menuConfig.bundleName, menuConfig.mainTitleResource),
        subTitleString: await this._getConfigResString(context, menuConfig.bundleName, menuConfig.subTitleResource)
      }
      menuInfoList.push(menuInfo);
    }
    return menuInfoList;
  }

  private async _getUserId(): Promise<number> {
    const accountManager: osAccount.AccountManager = osAccount.getAccountManager();
    let userIdList: number[] = await accountManager.getActivatedOsAccountLocalIds();
    const userId: number = userIdList[0];
    return userId;
  }

  //   Get the configured title string resource
  private async _getConfigResString(context: Context, bundleName: string, res: string): Promise<string> {
    if (res === null || res === undefined) {
      return '';
    }
    let resourceManager = resourceUtil.getBundleResourceManager(bundleName, context);
    if (resourceManager === null) {
      return '';
    }
    let titleResList = res.split(':');
    if (titleResList.length >= 2) {
      let title = titleResList[1];
      return await resourceManager.getStringByName(title);
    }
    return '';
  }

  private _generateBucket(menuInfo: MenuInfo): relationalStore.ValuesBucket {
    let obj: relationalStore.ValuesBucket = {};
    obj.businessId = menuInfo.intents;
    obj.intents = menuInfo.intents;
    obj.userId = menuInfo.userId;
    obj.iconBackgroundColorResource = menuInfo.iconBackgroundColorResource;
    obj.priority = menuInfo.priority;
    obj.isSupport = menuInfo.isSupport;
    obj.isClickable = menuInfo.isClickable;
    obj.displayedMode = menuInfo.displayedMode;
    obj.iconResource = menuInfo.iconResource;
    obj.mainTitleResource = menuInfo.mainTitleResource;
    obj.subTitleResource = menuInfo.subTitleResource;
    obj.showControlAbilityUri = menuInfo.showControlAbilityUri;
    obj.dstAbilityMode = menuInfo.dstAbilityMode;
    obj.dstAbilityName = menuInfo.dstAbilityName;
    obj.dstBundleName = menuInfo.dstBundleName;
    obj.bundleName = menuInfo.bundleName;
    return obj;
  }
}
