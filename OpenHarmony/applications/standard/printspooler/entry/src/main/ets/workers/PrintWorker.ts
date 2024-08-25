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

import { WorkerUtil } from '@ohos/ippprint';
import worker from '@ohos.worker';
import { Log } from '@ohos/common';
import {WorkerResponse, RequestCode, ResponseCode } from '@ohos/ippprint';
import { NativeApi } from '@ohos/ippprint';

const parentPort = worker.workerPort;
const nativeApi = NativeApi.getInstance();
const TAG = 'PrintWorker';

parentPort.onerror = function (e) {
  Log.error(TAG, 'worker on error ' + JSON.stringify(e));
};

parentPort.onmessage = function (messageEvent) {
  Log.info(TAG, 'parent port on message enter');
  let message = parseMessage(messageEvent);
  let requestCode = message.requestCode;
  let requestData = undefined;
  if (message !== undefined && message !== null && Object.prototype.hasOwnProperty.call(message, "data")) {
    requestData = message.data;
  }
  let responseMessage = undefined;
  Log.info(TAG, `request code is ${WorkerUtil.getStringByWorkerCode(requestCode)}`);
  switch (requestCode) {
    case RequestCode.GET_CAPS:
      getCapabilities(requestData);
      break;
    default:
      Log.error(TAG, 'onMessage. error code');
  }
};

function getCapabilities(data) {
  Log.debug(TAG, 'data: ' + JSON.stringify(data));
  nativeApi.getCapabilities(data.uri, data.printerName, (result) => {
    let response;
    if (typeof result === 'number') {
      response = new WorkerResponse(RequestCode.GET_CAPS, ResponseCode.ERROR);
    } else {
      Log.info(TAG, 'getCapabilities success');
      response = new WorkerResponse(RequestCode.GET_CAPS, ResponseCode.OK);
      response.data = result;
    }
    postMessageToMainThread(parentPort, response);
  });
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

