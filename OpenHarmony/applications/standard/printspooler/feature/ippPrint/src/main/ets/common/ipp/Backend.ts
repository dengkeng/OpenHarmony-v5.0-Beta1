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

import type { MessageEvent } from '@ohos/common';
import CheckEmptyUtils, {
  GET_CAPS_ERROR,
  Log,
} from '@ohos/common';
import LocalPrinterCapabilities from '../napi/LocalPrinterCapabilities';
import type { OnLocalPrinterCapabilities } from '../ipp/CapabilitiesCache';
import type uri from '@ohos.uri';
// @ts-ignore
import print from '@ohos.print';
import CommonUtils from '../utils/CommonUtils';
import { WorkerUtil } from '../utils/WorkerUtil';
import type { WorkerResponse } from '../model/WorkerData';
import { RequestCode, ResponseCode, WorkerRequest } from '../model/WorkerData';
import worker from '@ohos.worker';
import { PrinterCapability } from '@ohos/common';

const TAG = 'Backend';

export class Backend {
  private requestCallback: () => void;
  private mWorker: worker.ThreadWorker;
  private onCapabilitiesCallback: OnLocalPrinterCapabilities;

  constructor() {
    let initResult: boolean = this.initPrintWorker();
    if (!initResult) {
      return;
    }
  }

  /**
   * 获取打印机能力
   *
   * @param uri
   * @param timeout
   * @param onLocalPrinterCapabilities
   */
  public getCapabilities(uri: uri.URI, printerName: string, onLocalPrinterCapabilities: OnLocalPrinterCapabilities, requestCallback: () => void): void {
    Log.debug(TAG, `getCapabilities, uri is: ${uri.scheme}://${CommonUtils.getSecurityIp(uri.host)}:**${uri.path}`);
    if (uri === undefined) {
      Log.error(TAG, 'uri is undefined');
      return;
    }
    this.onCapabilitiesCallback = onLocalPrinterCapabilities;
    this.requestCallback = requestCallback;
    let getCapsRequest: WorkerRequest = new WorkerRequest(RequestCode.GET_CAPS);
    getCapsRequest.data = {
      uri: uri.toString(),
      printerName: printerName
    };
    WorkerUtil.postMessageToWorkerThread(this.mWorker, getCapsRequest);
  }

  /**
   * 退出程序, 释放资源
   */
  public close(): void {
    Log.info(TAG, 'close');
    this.mWorker.terminate();
  }

  private handleGetCapsResult(responseCode: ResponseCode, result: PrinterCapability): void {
    Log.debug(TAG, 'handleGetCapsResult enter');
    if (ResponseCode.ERROR === responseCode) {
      //获取打印机能力失败，上报错误
      this.onCapabilitiesCallback.onCapabilities(null);
      this.requestCallback();
      return;
    }
    this.onCapabilitiesCallback.onCapabilities(result);
    this.requestCallback();
  }

  /**
   * init print worker
   */
  private initPrintWorker(): boolean {
    if (this.mWorker === undefined) {
      this.mWorker = new worker.ThreadWorker('entry/ets/workers/PrintWorker.ts', {
        type: 'classic',
        name: 'PrintWorkerOfExtension'
      });
      if (this.mWorker === undefined) {
        Log.error(TAG, 'initWorker failed');
        return false;
      }
      this.mWorker.onmessage = this.onMessage;
      this.mWorker.onmessageerror = (messageEvent: MessageEvent<object>): void => {
        Log.error(TAG, 'onMessageError : ' + JSON.stringify(messageEvent));
      };
      this.mWorker.onerror = (errorEvent: object): void => {
        Log.error(TAG, 'onError : ' + JSON.stringify(errorEvent));
      };
      this.mWorker.onexit = (code: number): void => {
        Log.info(TAG, 'onExit : ' + code);
        this.mWorker = undefined;
      };
      Log.info(TAG, 'initWorker success');
      return true;
    }
    return false;
  }

  /**
   * receive message from worker thread
   *
   * @param messageEvent
   */
  private onMessage = (messageEvent: MessageEvent<WorkerResponse>): void => {
    Log.info(TAG, 'printWorker response');
    if (CheckEmptyUtils.isEmpty(messageEvent)) {
      Log.error(TAG, 'print worker response is empty');
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
    Log.info(TAG, `requestCode: ${WorkerUtil.getStringByWorkerCode(requestCode)}, responseCode: ${responseCode}`);
    switch (requestCode) {
      case RequestCode.GET_CAPS:
        this.handleGetCapsResult(<ResponseCode> responseCode, <PrinterCapability> workerResponse.data);
        break;
      default:
        Log.error(TAG, 'onMessage response. error code');
    }
  };
}