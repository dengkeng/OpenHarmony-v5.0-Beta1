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

import {WorkerUtil} from '@ohos/ippprint';
import worker from '@ohos.worker';
import { Log } from '@ohos/common';
import {WorkerResponse, RequestCode, ResponseCode } from '@ohos/ippprint';
import {P2PDiscoveryChannel} from '@ohos/ippprint';

const parentPort = worker.workerPort;
const p2pDiscoveryChannel = P2PDiscoveryChannel.getInstance();
const TAG = 'DiscoveryWorker';

parentPort.onerror = function (e) {
  Log.error(TAG, 'worker on error ' + JSON.stringify(e));
};

parentPort.onmessage = function (messageEvent) {
  Log.info(TAG, 'parent port on message enter');
  let message = parseMessage(messageEvent);
  if (!Object.prototype.hasOwnProperty.call(message, "requestCode")) {
    Log.error(TAG, 'requestCode is not in message');
    return;
  }
  let requestCode = message.requestCode;
  Log.info(TAG, `request code is ${WorkerUtil.getStringByWorkerCode(requestCode)}`);
  switch (requestCode) {
    case RequestCode.P2P_START_DISCOVERY:
      startP2pDiscovery();
      break;
    case RequestCode.P2P_CANCEL_DISCOVERY:
      stopP2pDiscovery();
      break;
    default:
      Log.error(TAG, 'onMessage. error code');
  }
};

function startP2pDiscovery() {
  p2pDiscoveryChannel.startDiscovery(p2pDiscoveryResult);
}

function p2pDiscoveryResult(found, p2pDevice) {
  Log.info(TAG, 'p2pDiscoveryResult enter ');
  let p2pDiscoveryResponse = new WorkerResponse(RequestCode.P2P_START_DISCOVERY, ResponseCode.OK);
  p2pDiscoveryResponse.data = { 'found': found, 'p2pDevice': p2pDevice };
  postMessageToMainThread(parentPort, p2pDiscoveryResponse);
}

function stopP2pDiscovery() {
  p2pDiscoveryChannel.cancel();
}


function parseMessage(event) {
  if (event === null || event.data === null) {
    Log.error(TAG, 'worker receive an event but null');
    return undefined;
  }
  return event.data;
}

function postMessageToMainThread(parentPort, data) {
  if (parentPort === undefined || parentPort === null) {
    Log.error(TAG, 'parentPort is null, cannot post message');
  }
  parentPort.postMessage(data);
}

