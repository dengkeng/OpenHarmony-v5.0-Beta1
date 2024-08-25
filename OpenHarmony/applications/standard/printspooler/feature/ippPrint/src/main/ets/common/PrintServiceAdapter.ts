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

import type { P2PDiscovery } from './discovery/P2pDiscovery';
import type { P2PMonitor } from './discovery/P2pMonitor';
import type { MdnsDiscovery } from './discovery/MdnsDiscovery';
import { Log } from '@ohos/common';
import type { Backend } from './ipp/Backend';
import type { CapabilitiesCache } from './ipp/CapabilitiesCache';
import type { WifiModel } from './model/WifiModel';
import type { LocalDiscoverySession } from './LocalDiscoverySession';
import CheckEmptyUtils from '@ohos/common';

const TAG = 'PrintServiceAdapter';

export class PrintServiceAdapter {
  private static instance: PrintServiceAdapter;
  private _p2pDiscovery: P2PDiscovery;
  private _mdnsDiscovery: MdnsDiscovery;
  private _p2pMonitor: P2PMonitor;
  private _backend: Backend;
  private _capabilitiesCache: CapabilitiesCache;
  private _wifiModel: WifiModel;
  private _localDiscoverySession: LocalDiscoverySession;


  public static getInstance(): PrintServiceAdapter {
    Log.info(TAG, 'getInstance enter');
    if (CheckEmptyUtils.isEmpty(this.instance)) {
      this.instance = new PrintServiceAdapter();
    }
    return this.instance;
  }

  private constructor() {

  }

  get localDiscoverySession(): LocalDiscoverySession {
    return this._localDiscoverySession;
  }

  set localDiscoverySession(localDiscoverySession: LocalDiscoverySession) {
    this._localDiscoverySession = localDiscoverySession;
  }

  /**
   * get P2pMonitor
   *
   * @return P2pMonitor P2pMonitor
   */
  get wifiModel(): WifiModel {
    return this._wifiModel;
  }

  /**
   * set P2pMonitor
   *
   * @param p2pMonitor P2pMonitor
   */
  set wifiModel(wifiModel: WifiModel) {
    this._wifiModel = wifiModel;
  }


  /**
   * get CapabilitiesCache
   *
   * @return getCapabilitiesCache getCapabilitiesCache
   */
  get capabilitiesCache(): CapabilitiesCache {
    return this._capabilitiesCache;
  }

  /**
   * set CapabilitiesCache
   *
   * @param capabilitiesCache CapabilitiesCache
   */
  set capabilitiesCache(capabilitiesCache: CapabilitiesCache) {
    this._capabilitiesCache = capabilitiesCache;
  }

  /**
  * get P2pDiscovery
  *
  * @return P2pDiscovery P2pDiscovery
  */
  get p2pDiscovery(): P2PDiscovery {
    return this._p2pDiscovery;
  }

  /**
   * set P2pDiscovery
   *
   * @param p2pDiscovery P2pDiscovery
   */
  set p2pDiscovery(p2pDiscovery: P2PDiscovery) {
    this._p2pDiscovery = p2pDiscovery;
  }

  /**
   * get Backend
   *
   * @return Backend Backend
   */
  get backend(): Backend {
    return this._backend;
  }

  /**
   * set Backend
   *
   * @param backend Backend
   */
  set backend(backend: Backend) {
    this._backend = backend;
  }

  /**
   * get MdnsDiscovery
   *
   * @return MdnsDiscovery
   */
  get mdnsDiscovery(): MdnsDiscovery {
    return this._mdnsDiscovery;
  }

  /**
   * set MdnsDiscovery
   *
   * @param MdnsDiscovery
   */
  set mdnsDiscovery(mdnsDiscovery: MdnsDiscovery) {
    this._mdnsDiscovery = mdnsDiscovery;
  }


  /**
   * get MdnsDiscovery
   *
   * @return MdnsDiscovery
   */
  get p2pMonitor(): P2PMonitor {
    return this._p2pMonitor;
  }

  /**
   * set MdnsDiscovery
   *
   * @param MdnsDiscovery
   */
  set p2pMonitor(p2pMonitor: P2PMonitor) {
    this._p2pMonitor = p2pMonitor;
  }
}