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

import router from '@ohos.router';
import Constants from '../common/constants/ComConstant';
import Logger from '../common/utils/Logger';

const TAG = 'UiExtensionPage'

@Entry
@Component
struct UiExtensionPage {
  @State routerParma: Record<string, string> = router.getParams() as Record<string, string>;
  @State dstBundleName: string = this.routerParma['dstBundleName'];
  @State dstAbilityName: string = this.routerParma['dstAbilityName'];

  build() {
    Row() {
      UIExtensionComponent({
        bundleName: this.dstBundleName,
        abilityName: this.dstAbilityName,
        parameters: {
          'ability.want.params.uiExtensionType': 'sys/commonUI',
        }
      })
        .onRemoteReady((data) => {
          Logger.debug(TAG, 'UiExtensionPage onRemoteReady: ' + JSON.stringify(data));
        })
        .onResult((data) => {
          Logger.debug(TAG, 'UiExtensionPage onResult: ' + JSON.stringify(data));
        })
        .onRelease((code) => {
          Logger.debug(TAG, 'UiExtensionPage code: ' + JSON.stringify(code));
        })
        .onReceive((data) => {
          //   update message
          Logger.debug(TAG, 'UiExtensionPage onReceive: ' + JSON.stringify(data));
          if (data['action'] === 'exit') {
            router.back();
          }
        })
        .height(Constants.WIDTH_HEIGHT_FULL_SCREEN)
        .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
    }
    .height(Constants.WIDTH_HEIGHT_FULL_SCREEN)
    .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
  }
}