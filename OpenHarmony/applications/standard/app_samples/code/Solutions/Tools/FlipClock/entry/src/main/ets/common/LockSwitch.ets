/*
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

import lock from '@ohos.runningLock'
import Logger from '../model/Logger'

const HIDE_TIME = 86400000

@Component
export struct LockSwitch {
  private isLock: boolean = false
  @Link isComTime: boolean

  build() {
    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
      Text($r('app.string.screenLight')).fontSize(18)

      Toggle({ type: ToggleType.Switch, isOn: this.isLock })
        .id('screenLight')
        .onChange(() => {
          this.isLock = !(this.isLock)
          lock.createRunningLock('running_lock_test', lock.RunningLockType.PROXIMITY_SCREEN_CONTROL)
            .then(lock => {
              lock.isHolding()
              if (this.isLock === true) {
                this.isComTime = false
                lock.hold(HIDE_TIME)
              } else {
                lock.unhold()
                this.isComTime = true
              }
            })
            .catch(error => {
              Logger.info(`create runningLock test error: ${error}`)
            })
        })
    }
    .width('100%')
    .margin({ top: 10 })
  }
}