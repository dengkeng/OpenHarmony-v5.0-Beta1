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

import hiSysEvent from '@ohos.hiSysEvent';
import { BusinessError } from '@ohos.base';
import Logger from './Logger';
import HiSysEventConstant from '../constants/HiSysEventConstant';
import GetSelfBundleInfoUtils from './GetSelfBundleInfoUtils';

const TAG = 'HiSysEventUtil';

export default class HiSysEventUtil {
  private constructor() {
  }

  /**
   * Access framework access application click event management
   *
   * @params { clickedBundleName } Click on the application package name
   */
  static async reportAccessClick(clickedBundleName: string): Promise<void> {
    Logger.info(TAG, 'reportAccessClick start.')
    let versionName: string = await GetSelfBundleInfoUtils.getVersionName();
    let eventParams: Record<string, string | number> = {
      'PNAMEID': HiSysEventConstant.BUNDLE_NAME,
      'PVERSIONID': versionName,
      'CLICK_ITEM': clickedBundleName,
    };
    HiSysEventUtil.report(HiSysEventConstant.EVENT_DOMAIN,
      HiSysEventConstant.ACCESS_CLICK_EVENT_NAME, hiSysEvent.EventType.BEHAVIOR, eventParams);
  }

  /**
   * Access my location information and click on the management event
   * @params { operation } LOCATION
   */
  static async reportLocationClick(operation: string): Promise<void> {
    Logger.info(TAG, 'reportLocationClick start.')
    let versionName: string = await GetSelfBundleInfoUtils.getVersionName();
    let eventParams: Record<string, string | number> = {
      'PNAMEID': HiSysEventConstant.BUNDLE_NAME,
      'PVERSIONID': versionName,
      'OPERATION': operation,
    };
    HiSysEventUtil.report(HiSysEventConstant.EVENT_DOMAIN,
      HiSysEventConstant.MAIN_PERMISSION_LIST_EVENT_NAME, hiSysEvent.EventType.BEHAVIOR, eventParams);
  }

  /**
   *  Access My Location Information Switch Click on Dotting Event
   * @params { checkedState } Position information switch status; 1: On 0: Off
   */
  static async reportLocationFlagClick(checkedState: number) {
    let versionName: string = await GetSelfBundleInfoUtils.getVersionName();
    let eventParams: Record<string, string | number> = {
      'PNAMEID': HiSysEventConstant.BUNDLE_NAME,
      'PVERSIONID': versionName,
      'NEW_CHECKED_STATE': checkedState,
    };
    HiSysEventUtil.report(HiSysEventConstant.EVENT_DOMAIN,
      HiSysEventConstant.PERMISSION_PAGE_LOCATION_EVENT_NAME, hiSysEvent.EventType.BEHAVIOR, eventParams);
  }

  /**
   * Click on the interface to operate the dots
   *
   * @param eventName Event Name
   * @param params parameter
   */
  static async reportClick(eventName: string, params: Record<string, string | number>): Promise<void> {
    let versionName: string = await GetSelfBundleInfoUtils.getVersionName();
    params['PNAMEID'] = HiSysEventConstant.BUNDLE_NAME;
    params['PVERSIONID'] = versionName;
    let eventParams: Record<string, string | number> = params;
    HiSysEventUtil.report(HiSysEventConstant.EVENT_DOMAIN, eventName, hiSysEvent.EventType.BEHAVIOR, eventParams);
  }

  private static report(domain: string, name: string, eventType: hiSysEvent.EventType, params: Object): void {
    Logger.info(
      TAG, `start to report domain: ${domain},eventName: ${name},eventType: ${eventType}, reportData: ${params}`);
    const sysEventInfo: hiSysEvent.SysEventInfo = {
      domain: domain,
      name: name,
      eventType: eventType,
      params: params
    };
    hiSysEvent.write(sysEventInfo).then(
      () => {
        Logger.info(TAG, `HiSysEventUtil reportHiSysEvent ${sysEventInfo.name} success.`);
      }
    ).catch(
      (err: BusinessError) => {
        Logger.error(TAG, `error code: ${err.code}, error msg: ${err.message}`);
      }
    )
  }
}
