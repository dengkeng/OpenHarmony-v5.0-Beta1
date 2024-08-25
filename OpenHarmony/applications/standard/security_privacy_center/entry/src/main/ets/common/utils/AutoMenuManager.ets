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

import Logger from '../utils/Logger';
import dataShare from '@ohos.data.dataShare';
import { MenuConfig } from '../bean/MenuConfig';
import DataShareResultSet from '@ohos.data.DataShareResultSet';
import { StringUtil } from './StringUtil';
import resourceUtil from './ResourceUtil';
import { RawFileUtil } from './RawFileUtil';
import DefaultMenuConfig from '../bean/DefaultMenuConfig';
import HashMap from '@ohos.util.HashMap';
import common from '@ohos.app.ability.common';
import bundleManager from '@ohos.bundle.bundleManager';
import BundleInfoModel from '../../model/bundleInfo/BundleInfoModel';
import abilityAccessCtrl, { Permissions } from '@ohos.abilityAccessCtrl';
import resourceManager from '@ohos.resourceManager';
import dataSharePredicates from '@ohos.data.dataSharePredicates';

const TAG = 'AutoMenu';
const DST_ABILITY_MODE = 1;
// UIAbility access method
const DST_UIABILITY_MODE = 0;

// Database unique identifier
const DISPLAY_ONLY_PRIMARY_USER = 'ONLY_PRIMARY_USER';
const DISPLAY_ONLY_SUB_USER = 'ONLY_SUB_USER';
const MAIN_USER_ID = 100;

const CHECK_ACCESS_TOKEN_PERMISSION: Permissions = 'ohos.permission.ACCESS_SECURITY_PRIVACY_CENTER';
const PRIVACY_CENTER = 'metadata.access.privacy.center';
const ORDERING_RULE_FILE = 'menu_list_rule.json';
const DISPLAY_MODEL_CARD = 'card';
const DISPLAY_MODEL_LIST = 'list';

export class AutoMenuManager {
  //   Default configuration information，key is bundle name, value is config
  private _defaultMenuConfigMap: HashMap<string, DefaultMenuConfig> = new HashMap();

  //   key is bundle name, value is id.
  private _defaultBusinessIdMap: HashMap<string, string> = new HashMap();

  private _predicates: dataSharePredicates.DataSharePredicates = new dataSharePredicates.DataSharePredicates();

  private _shareArray = ['*'];

  private static _INSTANCE: AutoMenuManager;

  /**
   * To get single instance
   * @returns The single instance
   */
  public static getInstance(): AutoMenuManager {
    if (!AutoMenuManager._INSTANCE) {
      AutoMenuManager._INSTANCE = new AutoMenuManager();
    }
    return AutoMenuManager._INSTANCE;
  }

  /**
   * To get all config in system
   * @param context The context
   * @param userId The user id
   * @returns The all menu config
   */
  async getMenuConfigFromBms(context: Context, userId: number): Promise<MenuConfig[]> {
    //   Obtain all configuration information and internally check permissions
    let allPkgConfigList: MenuConfig[] = await this._readConfigFromBms(context);
    //   Adapt to businessId
    for (let index = 0; index < allPkgConfigList.length; index++) {
      const item = allPkgConfigList[index];
      if (item.businessId === null || item.businessId === undefined || item.businessId.length === 0) {
        item.businessId = await this._getDefaultBusinessId(context, item.bundleName);
      }
    }
    Logger.info(TAG, 'getMenuConfigFromBms allPkgConfigList: ' + JSON.stringify(allPkgConfigList));
    //   Filter illegal configuration information
    let verifiedPkgConfigList: MenuConfig[] = [];
    for (let index = 0; index < allPkgConfigList.length; index++) {
      const menuConfig = allPkgConfigList[index];
      let isVerifyPass: boolean = await this._verifyMenuConfig(context, menuConfig, userId);
      if (isVerifyPass) {
        verifiedPkgConfigList.push(menuConfig);
      } else {
        Logger.error(TAG, 'Not verify pass. ' + menuConfig.businessId);
      }
    }
    Logger.info(TAG, 'getMenuConfigFromBms result: ' + JSON.stringify(verifiedPkgConfigList));
    return verifiedPkgConfigList;
  }

  /**
   * To judge this menu is support or not
   * @param context The context
   * @param item The menu id
   * @returns True is support
   */
  async isSupportMenu(context: Context, item: MenuConfig): Promise<number> {
    let isSupport: number = 0;
    const uri = item.showControlAbilityUri;
    if (uri === undefined) {
      isSupport = 1;
    } else {
      let value: string = await this._verificationUri(context, item.showControlAbilityUri);
      if (value === '0x55') {
        isSupport = 1;
      } else if (value === '0xaa') {
        isSupport = 0;
      }
    }
    return isSupport;
  }

  /**
   * To get menu priority
   * @param context The context
   * @param menuConfig The menu config
   * @returns The menu priority
   */
  async getMenuPriority(context: Context, menuConfig: MenuConfig): Promise<number> {
    if (this._defaultBusinessIdMap.length === 0) {
      await this._initDefaultMenuConfig(context);
    }
    try {
      let defaultMenuConfig: DefaultMenuConfig = this._defaultMenuConfigMap.get(menuConfig.businessId);
      if (defaultMenuConfig === undefined) {
        return 0;
      }
      return defaultMenuConfig.priority;
    } catch (err) {
      Logger.info(TAG, 'get menu priority error.')
    }
    return 0;
  }

  private async _getDefaultBusinessId(context: Context, bundleName: string): Promise<string> {
    if (this._defaultBusinessIdMap.length === 0) {
      await this._initDefaultMenuConfig(context);
    }
    try {
      return this._defaultBusinessIdMap.get(bundleName)
    } catch (err) {
      Logger.info(TAG, 'get menu priority error.')
    }
    return '';
  }

  private async _initDefaultMenuConfig(context: Context) {
    try {
      let jsonStr: string = await RawFileUtil.getRawFileByContext(context, ORDERING_RULE_FILE);
      let defaultMenuConfigList: DefaultMenuConfig[] = JSON.parse(jsonStr);
      for (let index = 0; index < defaultMenuConfigList.length; index++) {
        const item = defaultMenuConfigList[index];
        this._defaultMenuConfigMap.set(item.businessId, item);
        this._defaultBusinessIdMap.set(item.bundleName, item.businessId);
      }
    } catch (e) {
      Logger.error(TAG, 'error when parse advice config.')
    }
  }

  //   Query Ability information with functional access
  private async _readConfigFromBms(context: Context): Promise<MenuConfig[]> {
    let abilityInfoList: bundleManager.ExtensionAbilityInfo[] = [];
    let uiAbilityInfoList: bundleManager.AbilityInfo[] = [];
    try {
      abilityInfoList = await BundleInfoModel.queryExtensionAbilityInfoOther()
    } catch (err) {
      Logger.error(TAG, 'queryExtensionAbilityInfoOther error.')
    }
    // Query information accessed through uiAbility
    try {
      uiAbilityInfoList = await BundleInfoModel.queryAbilityInfoOther()
    } catch (err) {
      Logger.error(TAG, 'queryAbilityInfoOther error.')
    }
    if (abilityInfoList.length === 0 && uiAbilityInfoList.length === 0) {
      return [];
    }
    //   Check the Ability permissions for feature access
    let atManage: abilityAccessCtrl.AtManager = abilityAccessCtrl.createAtManager();
    let pkgConfigList: MenuConfig[] = [];
    for (let index = 0; index < abilityInfoList.length; index++) {
      const abilityInfo = abilityInfoList[index];
      try {
        let data: abilityAccessCtrl.GrantStatus = await atManage.checkAccessToken(
          abilityInfo.applicationInfo.accessTokenId, CHECK_ACCESS_TOKEN_PERMISSION);
        if (data !== abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED) {
          continue;
        }
        let singlePkgConfigList: MenuConfig[] = await this._readConfigFromSingleAbilityInfo(context, abilityInfo);
        pkgConfigList = pkgConfigList.concat(singlePkgConfigList);
      } catch (err) {
        Logger.info(TAG, 'checkAccessToken error: ' + abilityInfo.bundleName);
      }
    }
    // Check the Ability permissions of the function accessed through uiAbility method
    for (let index = 0; index < uiAbilityInfoList.length; index++) {
      const uiAbilityInfo = uiAbilityInfoList[index];
      try {
        let data: abilityAccessCtrl.GrantStatus = await atManage.checkAccessToken(
          uiAbilityInfo.applicationInfo.accessTokenId, CHECK_ACCESS_TOKEN_PERMISSION);
        if (data !== abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED) {
          continue;
        }
        let singlePkgConfigList: MenuConfig[] = await this._readConfigFromSingleAbilityInfo(context, uiAbilityInfo);
        pkgConfigList = pkgConfigList.concat(singlePkgConfigList);
      } catch (err) {
        Logger.info(TAG, 'uiAbilityInfoList checkAccessToken error: ' + uiAbilityInfo.bundleName);
      }
    }
    return pkgConfigList;
  }

  //   Read access method configuration information and convert it to the corresponding data class
  private async _readConfigFromSingleAbilityInfo(context: Context,
    abilityInfo: bundleManager.ExtensionAbilityInfo | bundleManager.AbilityInfo): Promise<MenuConfig[]> {
    //   Get MetaData data
    let singleAbilityMenuConfigList: MenuConfig[] = [];
    for (let index = 0; index < abilityInfo.metadata.length; index++) {
      const metaData = abilityInfo.metadata[index];
      if (metaData.name !== PRIVACY_CENTER) {
        continue;
      }
      let bundleName = abilityInfo.bundleName;
      let fileName = metaData.value;
      //   Retrieve JSON files based on metaData
      let content: string = await this._getFileByMetaData(context, bundleName, fileName);
      if (StringUtil.isEmpty(content)) {
        continue;
      }
      let menuConfig: MenuConfig = JSON.parse(content);
      menuConfig.bundleName = bundleName;
      singleAbilityMenuConfigList.push(menuConfig);
    }
    Logger.info(TAG, 'readConfigFromSingleAbilityInfo: ' + JSON.stringify(singleAbilityMenuConfigList));
    return singleAbilityMenuConfigList;
  }

  // Query the JSON data of metaData based on the package name
  private async _getFileByMetaData(context: Context, bundleName: string, fileName: string): Promise<string> {
    let resourceManager = resourceUtil.getBundleResourceManager(bundleName, context) as resourceManager.ResourceManager;
    return await RawFileUtil.getStringByFile(resourceManager, fileName);
  }

  private async _verifyMenuConfig(context: Context, menuConfig: MenuConfig, userId: number): Promise<boolean> {
    // Classification verification based on card or list mode, currently only list mode is supported
    try {
      if (menuConfig.displayedMode === DISPLAY_MODEL_CARD || menuConfig.displayedMode === DISPLAY_MODEL_LIST) {
        return await this._verificationListContent(context, userId, menuConfig);
      }
    } catch (err) {
      Logger.error(TAG, 'verifyMenuConfig error.');
    }
    return false;
  }

  //   Verify showControlAbilityUri
  private async _verificationUri(context: Context, uri: string): Promise<string> {
    try {
      let data: dataShare.DataShareHelper = await dataShare.createDataShareHelper(context, uri, { isProxy: false });
      if (data !== undefined) {
        let resultSet: DataShareResultSet = await data.query(uri, this._predicates, this._shareArray);
        resultSet.goToFirstRow();
        let showResult = resultSet.getString(resultSet.getColumnIndex('SHOW_RESULT'));
        if (StringUtil.isEmpty(showResult)) {
          return '';
        }
        if (showResult === '0x55' || showResult === '0xaa') {
          Logger.info(TAG, 'verificationUri showResult: ' + showResult);
          return showResult;
        } else {
          Logger.info(TAG, 'showResult: ' + showResult);
          return '';
        }
      }
    } catch (err) {
      Logger.error(TAG, 'verificationUri createDataShareHelper error: ' + JSON.stringify(err));
    }
    return '';
  }

  private async _verificationListContent(context: common.Context, userId: number,
    menuConfig: MenuConfig): Promise<boolean> {
    if (menuConfig === undefined || menuConfig === null) {
      return false;
    }
    if (this._isValidAccessMode(menuConfig.dstAbilityMode, menuConfig.dstBundleName)) {
      Logger.error(TAG, 'verificationListContent dstAbilityMode error.')
      return false;
    }
    if (StringUtil.isEmpty(menuConfig.dstBundleName)) {
      Logger.error(TAG, 'verificationListContent dstBundleName error.');
      return false;
    }
    if (StringUtil.isEmpty(menuConfig.dstAbilityName)) {
      Logger.error(TAG, 'verificationListContent dstAbilityName error.');
      return false;
    }
    let _isValidResourceWithList: boolean = await this._isValidResourceWithList(context, menuConfig);
    if (!_isValidResourceWithList) {
      return false;
    }
    //   Verify the configuration of primary and secondary users, optional fields
    if (menuConfig.displayUserConfig !== undefined) {
      let displayUserConfigRes = this._verificationPrimaryUser(menuConfig.displayUserConfig, userId);
      Logger.info(TAG, `displayUserConfigRes value is: ${displayUserConfigRes}`);
      if (displayUserConfigRes === false) {
        return displayUserConfigRes;
      }
    }
    //  Verify uri, optional fields
    let showControlAbilityUri = menuConfig.showControlAbilityUri;
    if (showControlAbilityUri !== undefined) {
      let _verificationUriResult: string = await this._verificationUri(context, showControlAbilityUri);
      Logger.info(TAG, 'verificationListContent verificationUri: ' + showControlAbilityUri);
      Logger.info(TAG, 'verificationListContent verificationUri value: ' + _verificationUriResult);
      if ('' === _verificationUriResult) {
        Logger.error(TAG, 'verificationListContent verificationUri error.')
        return false;
      } else {
        return true;
      }
    }
    return true;
  }

  private async _isValidResourceWithList(context: common.Context, menuConfig: MenuConfig): Promise<boolean> {
    let resourceManager = resourceUtil.getBundleResourceManager(menuConfig.bundleName, context);
    if (resourceManager === null || resourceManager === undefined) {
      return false;
    }
    if (StringUtil.isEmpty(menuConfig.mainTitleResource)) {
      return false;
    }
    //   title
    let titleResList = menuConfig.mainTitleResource.split(':');
    if (titleResList.length < 2) {
      Logger.error(TAG, 'titleResList length is error.')
      return false;
    }
    //   Verify title
    let value: string = await resourceManager?.getStringByName(titleResList[1]);
    if (value === '') {
      Logger.error(TAG, 'titlePromise is error.')
      return false;
    }
    return true;
  }

  //   Whether the access mode is valid
  private _isValidAccessMode(dstAbilityMode: number, dstBundleName: string): boolean {
    return dstAbilityMode !== DST_ABILITY_MODE && dstAbilityMode !== DST_UIABILITY_MODE
  }

  //   Verify sub users
  private _verificationPrimaryUser(displayUserConfig: string, userId: number): boolean {
    let isPrimaryUser: boolean = userId === MAIN_USER_ID;
    Logger.info(TAG, `verificationSubUser, displayUser: ${displayUserConfig}, isPrimaryUser: ${isPrimaryUser}`);
    if ((isPrimaryUser && displayUserConfig === DISPLAY_ONLY_PRIMARY_USER) ||
      (!isPrimaryUser && displayUserConfig === DISPLAY_ONLY_SUB_USER)) {
      return true;
    } else {
      return false;
    }
  }
}
