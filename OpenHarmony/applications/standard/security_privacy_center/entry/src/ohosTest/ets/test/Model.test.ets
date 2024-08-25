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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium'
import bundleManager from '@ohos.bundle.bundleManager';
import BundleInfoModel from '../../../main/ets/model/bundleInfo/BundleInfoModel';
import { BundleInfoBean } from '../../../main/ets/common/bean/BundleInfoBean';
import { MenuConfig } from '../../../main/ets/common/bean/MenuConfig';
import AccessTypedef from '../../../main/ets/common/bean/MenuInfo';
import Logger from '../../../main/ets/common/utils/Logger';
import { AutoMenuViewModel } from '../../../main/ets/main/auto_menu/AutoMenuViewModel';
import { AutoMenuInitIntent, AutoMenuRefreshIntent } from '../../../main/ets/main/auto_menu/AutoMenuIntent';
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { ProcessResult } from '../../../main/ets/common/base/BaseViewModel';

const TAG = 'ModelTest';

export default function ModelTest() {
  describe('ModelTest', () => {
    // Defines a test suite. Two parameters are supported: test suite name and test suite function.
    beforeAll(() => {
      // Presets an action, which is performed only once before all test cases of the test suite start.
      // This API supports only one parameter: preset action function.
    })
    beforeEach(() => {
      // Presets an action, which is performed before each unit test case starts.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: preset action function.
    })
    afterEach(() =>  {
      // Presets a clear action, which is performed after each unit test case ends.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: clear action function.
    })
    afterAll(() =>  {
      // Presets a clear action, which is performed after all test cases of the test suite end.
      // This API supports only one parameter: clear action function.
    })

    it('BundleInfoModelTest_01', 0, async () => {
      let bundleName: string = 'com.ohos.certmanager'
      await bundleManager.getApplicationInfo(bundleName, bundleManager.ApplicationFlag.GET_APPLICATION_INFO_DEFAULT)
        .then((data) => {
          BundleInfoModel.getAllBundleLabelAndIcon([data]).then((value) => {
            expect(value).not().assertNull()
          })
        })
    })
    it('BundleInfoModelTest_03', 0, async () => {
      let bundleName: string = 'com.ohos.certmanager'
      await bundleManager.getApplicationInfo(bundleName, bundleManager.ApplicationFlag.GET_APPLICATION_INFO_DEFAULT)
        .then((info) => {
          let bundleInfo: BundleInfoBean = {
            bundleName: info.name,
            icon: '',
            iconId: info.iconId,
            label: '',
            labelId: info.labelId,
            permissionName: '',
            permissionLabel: '',
            zhTag: '',
            indexTag: '',
            language: '',
            labelResource: info.labelResource,
            iconResource: info.iconResource,
            checkedState: '',
            checkedStateLabel: ''
          }
          BundleInfoModel.updateAppLabelAndIcon(bundleInfo).then(() => {
          })
        })
    })
    it('BundleInfoModelTest_04', 0, async () => {
      let bundleName: string = ''
      await BundleInfoModel.getAllBundleInfoByFunctionAccess().then(data => {
        expect(data).not().assertNull()
      })
    })
    it('BundleInfoModelTest_05', 0, async () => {
      let bundleName: string = 'com.ohos.certmanager'
      await bundleManager.getApplicationInfo(bundleName, bundleManager.ApplicationFlag.GET_APPLICATION_INFO_DEFAULT)
        .then((info) => {
          let bundleInfo: BundleInfoBean = {
            bundleName: info.name,
            icon: '',
            iconId: info.iconId,
            label: '',
            labelId: info.labelId,
            permissionName: '',
            permissionLabel: '',
            zhTag: '',
            indexTag: '',
            language: '',
            labelResource: info.labelResource,
            iconResource: info.iconResource,
            checkedState: '',
            checkedStateLabel: ''
          }
          BundleInfoModel.addLocalTag(bundleInfo)
        })
    })
    it('AutoMenuTest_01', 0, async () => {
      Logger.info(TAG, 'AutoMenuTest_01 is start')
      let autoMenuViewModel: AutoMenuViewModel = new AutoMenuViewModel();
      let context: Context = abilityDelegatorRegistry.getAbilityDelegator().getAppContext();
      let processResult: ProcessResult = await autoMenuViewModel.processIntent(new AutoMenuInitIntent(context.getApplicationContext()))
      expect(processResult).assertEqual(ProcessResult.SUCCESS)
      processResult = await autoMenuViewModel.processIntent(new AutoMenuRefreshIntent(context.getApplicationContext()))
      expect(processResult).assertEqual(ProcessResult.SUCCESS)
      processResult = await autoMenuViewModel.processIntent(new AutoMenuInitIntent(context.getApplicationContext()))
      expect(processResult).assertEqual(ProcessResult.SUCCESS)
      Logger.info(TAG, 'AutoMenuTest_01 is end')
    })
  })
}