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

import LocationService from './LocationService';
import Logger from '../../common/utils/Logger';

const TAG: string = 'LocationViewModel'

export const locationServiceOpenStatusKey = 'LocationServiceStatus';

export class LocationVM {
  public mIsStart: boolean = false;

  initViewModel() {
    if (this.mIsStart) {
      return;
    }
    Logger.info(TAG, 'init location view model')
    this.mIsStart = true;
    LocationService.registerListener(this);
    LocationService.startService();
    LocationService.getServiceState();
  }

  updateServiceState(state: boolean) {
    Logger.info(TAG, `update location service state, state: ${state} `)
    AppStorage.setOrCreate(locationServiceOpenStatusKey, state);
  }

  enableLocation() {
    Logger.info(TAG, 'enable location')
    LocationService.enableLocation();
  }

  disableLocation() {
    Logger.info(TAG, 'disable location')
    LocationService.disableLocation();
  }
}

let locationVM = new LocationVM();

export default locationVM as LocationVM;