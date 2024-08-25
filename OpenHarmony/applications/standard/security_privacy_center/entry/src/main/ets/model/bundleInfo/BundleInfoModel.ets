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

import i18n from '@ohos.i18n';
import bundleManager from '@ohos.bundle.bundleManager';
import { BundleInfoBean } from '../../common/bean/BundleInfoBean';
import common from '@ohos.app.ability.common';
import Want from '@ohos.app.ability.Want';
import Logger from '../../common/utils/Logger';
import { StringUtil } from '../../common/utils/StringUtil';
import resourceManager from '@ohos.resourceManager';

const USER_ID = 100;
const TAG = 'BundleInfoModel';
const ACTION = 'action.access.privacy.center';

class BundleInfoModel {
  private context = getContext(this) as common.UIAbilityContext;

  getAllBundleLabelAndIcon(allBundleInfo: bundleManager.ApplicationInfo[]) {
    let bundleInfoList: BundleInfoBean[] = []
    return new Promise<BundleInfoBean[]>(async (resolve, reject) => {
      try {
        allBundleInfo = allBundleInfo.filter((item, index, arr) => {
          return arr.findIndex(t => t.name === item.name) === index;
        });
        for (let index = 0; index < allBundleInfo.length; index++) {
          const info = allBundleInfo[index];
          let bundleInfo: BundleInfoBean = {
            bundleName: info.name,
            icon: '',
            iconId: info.iconId,
            label: '',
            labelId: info.labelId,
            permissionName: '',
            permissionLabel: '',
            checkedState: '',
            checkedStateLabel: '',
            zhTag: '',
            indexTag: '',
            language: '',
            labelResource: info.labelResource,
            iconResource: info.iconResource,
          }
          await this.updateAppLabelAndIcon(bundleInfo);
          if (bundleInfo.label && bundleInfo.icon) {
            bundleInfoList.push(bundleInfo)
          }
        }
      } catch (error) {
        Logger.error(TAG, `getAllBundleLabelAndIcon error: ${JSON.stringify(error)}`)
      }
      resolve(bundleInfoList);
    })
  }

  queryExtensionAbilityInfo(bundleName: string) {
    Logger.info(TAG, `queryExtensionAbilityInfo bundleName: ${bundleName}`);
    let extensionAbilityType = bundleManager.ExtensionAbilityType.UNSPECIFIED;
    let extensionFlags = bundleManager.ExtensionAbilityFlag.GET_EXTENSION_ABILITY_INFO_WITH_METADATA;
    let userId = USER_ID;
    let want: Want = {
      bundleName: bundleName,
      action: ACTION,
    }

    return new Promise<bundleManager.ExtensionAbilityInfo[]>((resolve) => {
      bundleManager.queryExtensionAbilityInfo(want, extensionAbilityType, extensionFlags, userId, (err, data) => {
        if (err) {
          Logger.error(TAG, `queryExtensionAbilityInfo failed: ${err.message}`)
        } else {
          resolve(data);
          Logger.info(TAG, `queryExtensionAbilityInfo successfully: ${JSON.stringify(data)}`)
        }
      })
    })
  }

  async queryExtensionAbilityInfoOther() {
    Logger.info(TAG, 'queryExtensionAbilityInfoOther');
    let extensionAbilityType = bundleManager.ExtensionAbilityType.UNSPECIFIED;
    let extensionFlags = bundleManager.ExtensionAbilityFlag.GET_EXTENSION_ABILITY_INFO_WITH_METADATA |
    bundleManager.ExtensionAbilityFlag.GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION;
    let userId = USER_ID;
    let want: Want = {
      action: ACTION,
    };
    let result: bundleManager.ExtensionAbilityInfo[] = [];
    try {
      result = await bundleManager.queryExtensionAbilityInfo(want, extensionAbilityType, extensionFlags, userId)
    } catch (err) {
      Logger.error(TAG, `queryExtensionAbilityInfoOther fail: ${JSON.stringify(err)}`);
    }
    return result;
  }

  async queryAbilityInfoOther() {
    Logger.info(TAG, 'queryAbilityInfoOther');
    let extensionFlags = bundleManager.ExtensionAbilityFlag.GET_EXTENSION_ABILITY_INFO_WITH_METADATA |
    bundleManager.ExtensionAbilityFlag.GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION;
    let userId = USER_ID;
    let want: Want = {
      action: ACTION,
    };
    let result: bundleManager.AbilityInfo[] = [];
    try {
      result = await bundleManager.queryAbilityInfo(want, extensionFlags, userId)
    } catch (err) {
      Logger.error(TAG, `queryExtensionAbilityInfoOther fail: ${JSON.stringify(err)}`);
    }
    return result;
  }

  //   Get all application information about feature access
  getAllBundleInfoByFunctionAccess() {
    let modelFlags = bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_METADATA |
    bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION |
    bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_HAP_MODULE |
    bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_ABILITY |
    bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_ABILITY;
    return new Promise<bundleManager.BundleInfo[]>((resolve) => {
      bundleManager.getAllBundleInfo(modelFlags).then((data) => {
        resolve(data)
      }).catch((error: Error) => {
        resolve([])
        Logger.error(TAG, `getAllBundleInfo error: ${JSON.stringify(error)}`)
      })
    })
  }

  /**
   * Get app label and icon resources
   * @param {Number} index index of all app permissions array
   * @param {String} bundleName Package names
   */
  async updateAppLabelAndIcon(info: BundleInfoBean): Promise<void> {
    let resourceManager: resourceManager.ResourceManager = this.context.createBundleContext(info.bundleName)
      .resourceManager;
    return new Promise<void>(async (resolve, reject) => {
      try {
        await resourceManager.getStringValue(info.labelId).then(value => {
          info.label = value;
        }).catch((error: Error) => {
          Logger.error(TAG, `${info.bundleName} getStringValue by ${info.labelId} error=${JSON.stringify(error)}`);
        })
        try {
          let iconDescriptor = resourceManager.getDrawableDescriptor(info.iconId);
          info.icon = iconDescriptor?.getPixelMap();
        } catch (exception) {
          Logger.warn(TAG, `get adaptive icon exception: ${JSON.stringify(exception)}`)
        }
        if (!info.icon) {
          info.icon = await resourceManager.getMediaContentBase64(info.iconId) || $r('app.media.icon');
        }
      } catch (error) {
        Logger.error(TAG, `updateAppLabelAndIcon error: ${JSON.stringify(error)}`)
      }
      resolve();
    })
  }

  public static readonly zh: string = '';
  public static readonly en: string = '';
  public indexValue: string[] = []

  getStringZh(input: string): string {
    let result: string = '';
    let upperCaseStr = input.toLocaleUpperCase();
    let regex: RegExp = new RegExp('[A-Z]');
    for (let i = 0; i < input.length; i++) {
      if (upperCaseStr[i].match(regex)) {
        let index = upperCaseStr.charCodeAt(i) - 'A'.charCodeAt(0);
        let ch = BundleInfoModel.zh.charAt(index);
        result += ch;
      } else {
        result += upperCaseStr[i];
      }
    }
    return result;
  }

  findZhIndex(zhCharacter: string): string {
    if (StringUtil.isEmpty(zhCharacter) || zhCharacter.localeCompare(BundleInfoModel.zh[0], 'zh') < 0) {
      return '#';
    }
    for (let left = 0; left < BundleInfoModel.zh.length - 1; left++) {
      let next = left + 1;
      if (zhCharacter.localeCompare(BundleInfoModel.zh[left], 'zh') >= 0 && zhCharacter.localeCompare(BundleInfoModel.zh[next], 'zh') < 0) {
        return BundleInfoModel.en[left];
      }
      if (next === BundleInfoModel.zh.length - 1 && zhCharacter.localeCompare(BundleInfoModel.zh[next], 'zh') >= 0) {
        return BundleInfoModel.en[next];
      }
    }
    return '';
  }

  sortByName(appArray: BundleInfoBean[]): BundleInfoBean[] {
    let enComparator = new Intl.Collator('en');
    let zhComparator = new Intl.Collator('zh-Hans-CN');
    try {
      return appArray.sort((item1: BundleInfoBean, item2: BundleInfoBean) => {
        if (item1.indexTag !== item2.indexTag) {
          return enComparator.compare(item1.indexTag, item2.indexTag);
        }
        let isEn1 = item1.language === 'EN';
        let isEn2 = item2.language === 'EN';
        if (isEn1 && isEn2) {
          return enComparator.compare(item1.label, item2.label)
        } else if (isEn1 && !isEn2) {
          return 1;
        } else if (!isEn1 && isEn2) {
          return -1;
        } else {
          return zhComparator.compare(item1.zhTag, item2.zhTag);
        }
      })
    } catch (error) {
      Logger.error(TAG, `sortByName error: ${JSON.stringify(error)}`)
      return [];
    }
  }

  addLocalTag(info: BundleInfoBean) {
    let isZh = i18n.System.getSystemLanguage().indexOf('zh') >= 0;
    let appName: string = info.label;
    let upperCase = StringUtil.isEmpty(appName) ? '' : appName[0].toLocaleUpperCase();
    let regexEn: RegExp = new RegExp('[A-Z]');
    let regexNm: RegExp = new RegExp('[0-9]');

    if (isZh) {
      if (upperCase.match(regexEn)) {
        info.zhTag = this.getStringZh(appName);
        info.indexTag = upperCase;
        info.language = 'EN';
      } else {
        info.zhTag = appName;
        info.language = 'CN';
        if (upperCase.match(regexNm)) {
          info.indexTag = '#';
        } else {
          info.indexTag = this.findZhIndex(upperCase);
        }
      }
    } else {
      if (upperCase.match(regexEn)) {
        info.zhTag = appName;
        info.indexTag = upperCase;
        info.language = 'EN';
      } else {
        info.zhTag = appName;
        info.indexTag = '#';
        info.language = 'CN';
      }
    }
  }
}

let bundleInfoModel = new BundleInfoModel();

export default bundleInfoModel as BundleInfoModel;
