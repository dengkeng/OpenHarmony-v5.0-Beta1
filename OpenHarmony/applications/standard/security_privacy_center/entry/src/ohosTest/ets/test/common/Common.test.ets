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
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import HiSysEventConstant from '../../../../main/ets/common/constants/HiSysEventConstant';
import getSelfBundleInfoUtils from '../../../../main/ets/common/utils/GetSelfBundleInfoUtils';
import HiSysEventUtil from '../../../../main/ets/common/utils/HiSysEventUtil';
import { RawFileUtil } from '../../../../main/ets/common/utils/RawFileUtil';
import ResourceUtil from '../../../../main/ets/common/utils/ResourceUtil';
import { StringUtil } from '../../../../main/ets/common/utils/StringUtil';
import Logger from '../../../../main/ets/common/utils/Logger';
import Constants from '../../../../main/ets/common/constants/ComConstant';
import DataShareConstants from '../../../../main/ets/common/constants/DataShareConstant';
import RouterConstant from '../../../../main/ets/common/constants/RouterConstant';

export default function BundleInfoBeanTest() {
  describe('CommonTest', () => {
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
    afterEach(() => {
      // Presets a clear action, which is performed after each unit test case ends.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: clear action function.
    })
    afterAll(() => {
      // Presets a clear action, which is performed after all test cases of the test suite end.
      // This API supports only one parameter: clear action function.
    })
    it('getSelfBundleInfoUtilsTest', 0, () => {
      getSelfBundleInfoUtils.getVersionName()
    })
    it('HiSysEventUtilTest', 0, () => {
      HiSysEventUtil.reportAccessClick('com.example.test');
      HiSysEventUtil.reportLocationClick('LOCATION');
      HiSysEventUtil.reportLocationFlagClick(1);
      HiSysEventUtil.reportLocationFlagClick(0);
      let eventParams: Record<string, string> = {
        "PERMISSION_GROUP": 'ohos.permission.Location'
      }
      HiSysEventUtil.reportClick(HiSysEventConstant.PERMISSION_PAGE_LOCATION_EVENT_NAME, eventParams)

    })
    it('RawfileUtilTest', 0, () => {
      RawFileUtil.getStringByFile(abilityDelegatorRegistry.getAbilityDelegator()
        .getAppContext()
        .resourceManager, 'test')
      RawFileUtil.getRawFileByContext(getContext(), 'test')
    })
    it('ResourceUtilTest', 0, () => {
      ResourceUtil.getResourceString(abilityDelegatorRegistry.getAbilityDelegator()
        .getAppContext(), $r('app.media.ic_back'))
      ResourceUtil.getBundleResourceManager('', abilityDelegatorRegistry.getAbilityDelegator().getAppContext())
      expect(ResourceUtil.getBundleResourceManager('', null)).assertNull()
      ResourceUtil.getBundleResourceManager('com.ohos.certmanager', abilityDelegatorRegistry.getAbilityDelegator()
        .getAppContext())
    })
    it('StringUtilTest', 0, () => {
      StringUtil.isEmpty('')
      StringUtil.isEmpty('111')
      StringUtil.isNotEmpty('')
      StringUtil.isNotEmpty('111')
    })
    it('LoggerTest', 0, () => {
      Logger.info('LOGGER_TEST', 'logger info test')
      Logger.debug('LOGGER_TEST', 'logger debug test')
      Logger.warn('LOGGER_TEST', 'logger warn test')
      Logger.error('LOGGER_TEST', 'logger error test')
    })
    it('ConstantsTest', 0, () => {
      expect(Constants.TITLE_BAR_HEIGHT).assertEqual(56)
      expect(DataShareConstants.STORE_CONFIG.name).assertEqual('access.db')
      expect(HiSysEventConstant.BUNDLE_NAME).assertEqual('com.ohos.certmanager')
      expect(RouterConstant.INDEX_URL).assertEqual('pages/Index')
    })

  })
}