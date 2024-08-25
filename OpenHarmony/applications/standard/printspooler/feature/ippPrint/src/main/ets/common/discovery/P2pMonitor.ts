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

import ArrayList from '@ohos.util.ArrayList';
import type { MessageEvent } from '@ohos/common';
import { Log } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import type { P2PDiscoveryListener } from './Discovery';
import worker from '@ohos.worker';
import { WorkerUtil } from '../utils/WorkerUtil';
import { WorkerRequest, RequestCode, ResponseCode } from '../model/WorkerData';
import type { WorkerResponse } from '../model/WorkerData';

const TAG = 'P2pMonitor';

export class P2PMonitor {
  private readonly _listeners: ArrayList<P2PDiscoveryListener> = new ArrayList<P2PDiscoveryListener>();
  private _worker: worker.ThreadWorker;

  constructor() {
    this.initDiscoveryWorker();
  }

  public discovery(listener: P2PDiscoveryListener): void {
    Log.debug(TAG, 'start discovery enter');
    if (this._listeners.isEmpty()) {
      Log.info(TAG, '_listeners is empty, start discover');
      this._listeners.add(listener);
      let discoverRequest: WorkerRequest = new WorkerRequest(RequestCode.P2P_START_DISCOVERY);
      WorkerUtil.postMessageToWorkerThread(this._worker, discoverRequest);
    } else {
      Log.info(TAG, '_listeners is not empty ignore');
    }
  }

  public stopDiscover(listener: P2PDiscoveryListener): void {
    Log.debug(TAG, 'remove discovery listener');
    this._listeners.remove(listener);
    if (this._listeners.isEmpty()) {
      Log.debug(TAG, 'stop discovery');
      let initRequest: WorkerRequest = new WorkerRequest(RequestCode.P2P_CANCEL_DISCOVERY);
      WorkerUtil.postMessageToWorkerThread(this._worker, initRequest);
    }
  }

  handleP2pDiscoveryResult(responseCode: ResponseCode, data): void {
    if (ResponseCode.ERROR === responseCode) {
      Log.error(TAG, 'handleP2pDiscoveryResult ResponseCode is error');
      return;
    }
    if (data.found) {
      for (let listener of this._listeners) {
        listener.onPeerFound(data.p2pDevice);
      }
    } else {
      for (let listener of this._listeners) {
        listener.onPeerLost(data.p2pDevice);
      }
    }
  }

  private initDiscoveryWorker(): boolean {
    if (this._worker === undefined) {
      this._worker = new worker.ThreadWorker('entry/ets/workers/DiscoveryWorker.ts', { type: 'classic', name: 'DiscoveryWorkerOfExtension' });
      if (this._worker === undefined) {
        Log.error(TAG, 'initWorker failed');
        return false;
      }
      this._worker.onmessage = this.onMessage;
      this._worker.onmessageerror = (messageEvent: MessageEvent<object>): void => {
        Log.error(TAG, 'onMessageError : ' + JSON.stringify(messageEvent));
      };
      this._worker.onerror = (errorEvent: object): void => {
        Log.error(TAG, 'onError : ' + JSON.stringify(errorEvent));
      };
      this._worker.onexit = (code: number): void => {
        Log.info(TAG, 'onExit : ' + code);
        this._worker = undefined;
      };
      Log.info(TAG, 'initDiscoveryWorker success');
      return true;
    }
    return false;
  }

  private onMessage = (messageEvent: MessageEvent<WorkerResponse>): void => {
    if (CheckEmptyUtils.isEmpty(messageEvent)) {
      Log.error(TAG, 'discovery worker response is empty');
      return;
    }
    if (!messageEvent.hasOwnProperty('data')) {
      Log.error(TAG, 'messageEvent has not data');
      return;
    }
    let workerResponse: WorkerResponse = messageEvent.data;
    if (workerResponse === undefined || workerResponse === null) {
      Log.error(TAG, 'workerResponse is empty');
      return;
    }
    if (!workerResponse.hasOwnProperty('requestCode') || !workerResponse.hasOwnProperty('responseCode')) {
      Log.error(TAG, 'workerResponse is error');
      return;
    }
    let requestCode = workerResponse.requestCode;
    let responseCode = workerResponse.responseCode;
    Log.debug(TAG, `requestCode: ${WorkerUtil.getStringByWorkerCode(requestCode)}, responseCode: ${responseCode}`);
    switch (requestCode) {
      case RequestCode.P2P_START_DISCOVERY:
        this.handleP2pDiscoveryResult(responseCode, <object>workerResponse.data);
        break;
      default:
        Log.error(TAG, 'onMessage response. error code');
    }
  };
}