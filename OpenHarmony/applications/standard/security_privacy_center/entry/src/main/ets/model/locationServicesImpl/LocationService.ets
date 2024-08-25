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

import geolocation from '@ohos.geoLocationManager';
import Logger from '../../common/utils/Logger';
import { BusinessError } from '@ohos.base';
import { ListenerBean } from './ListenerBean';

const TAG:string = 'LocationService'

export class LocationService {
  public mIsStart: boolean = false;
  public mListener: ListenerBean = new ListenerBean(() => {
  });

  startService() {
    if (this.mIsStart) {
      return;
    }
    Logger.info(TAG, 'start location service')
    this.mIsStart = true;
    geolocation.on('locationEnabledChange', (isChanged: boolean) => {
      Logger.info(TAG, `start location service isChanged: ${JSON.stringify(isChanged)}`)
      this.getServiceState();
    });
  }

  registerListener(listener: ListenerBean) {
    Logger.info(TAG, `register locations listener : ${listener}`)
    this.mListener = listener;
  }

  async getServiceState(): Promise<void> {
    Logger.info(TAG, 'get location state');
    try {
      let state: boolean = await geolocation.isLocationEnabled();
      Logger.info(TAG, `get location state, data: ${JSON.stringify(state)}`);
      this.mListener?.updateServiceState(state);
    } catch (error) {
      Logger.info(TAG, `get location state, data: ${error}`);
    }

  }

  enableLocation() {
    Logger.info(TAG, 'enable location');
    try {
      geolocation.enableLocation()
        .then((res): void => Logger.info(TAG, `enable location, result: ${JSON.stringify(res)}`))
        .catch((error: BusinessError): void => Logger.info(TAG, `enable location, result: ${error}`));
    } catch (err) {
      Logger.info(TAG, `enable location, result: ${err}`);
    }

  }

  disableLocation() {
    Logger.info(TAG, 'disable location');
    try {
      geolocation.disableLocation();
    } catch (err) {
      Logger.info(TAG, `disenable location, result: ${err}`);
    }
  }
}

let locationService = new LocationService();

export default locationService as LocationService;