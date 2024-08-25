/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import { Log } from '@ohos/common';
import { P2PDiscovery } from '../discovery/P2pDiscovery';
import type DiscoveredPrinter from '../discovery/DiscoveredPrinter';

const TAG = 'P2PUtils';

export default class P2PUtils {
  private static readonly connected: number = 0;
  private static readonly unavailable: number = 4;

  public static isOnConnected(printer: DiscoveredPrinter): boolean {
    return printer.getDeviceStatus() === P2PUtils.connected;
  }

  public static isUnavailable(printer: DiscoveredPrinter): boolean {
    return printer.getDeviceStatus() === P2PUtils.unavailable;
  }

  public static isP2p(printer: DiscoveredPrinter): boolean {
    if (printer === undefined) {
      Log.error(TAG, 'printer is undefined');
      return false;
    }
    if (printer.getPath().indexOf(P2PDiscovery.schemeP2p) >= 0) {
      return true;
    }
    return false;
  }
}