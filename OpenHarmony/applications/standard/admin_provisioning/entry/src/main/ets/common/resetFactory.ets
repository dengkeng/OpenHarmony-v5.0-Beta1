/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

import update from '@ohos.update';
import logger from './logger'
import { BusinessError } from '@ohos.base';

const TAG = 'ResetFactory';

export class ResetFactory {
  rebootAndCleanUserData() {
    let restorer = update.getRestorer();
    restorer.factoryReset().then(() => {
      logger.info(TAG, 'rebootAndCleanUserData factoryReset success')
    }).catch((err: BusinessError) => {
      logger.error(TAG, 'rebootAndCleanUserData err=' + JSON.stringify(err))
    })
  }
}

let resetFactory = new ResetFactory();

export default resetFactory as ResetFactory;