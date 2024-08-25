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

import type worker from '@ohos.worker';
import { Log } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import type { WorkerRequest } from '../model/WorkerData';
import { RequestCode } from '../model/WorkerData';

const TAG = 'WorkerUtil';

export class WorkerUtil {

  public static readonly sCodeToStringMap: Map<RequestCode, string> = new Map([
    [RequestCode.P2P_START_DISCOVERY, 'start p2p discovery'],
    [RequestCode.P2P_CANCEL_DISCOVERY, 'cancel p2p discovery'],
    [RequestCode.GET_CAPS, 'get caps'],
  ]);

  /**
   * send request to print worker
   *
   * @param printWorker: worker object
   * @param request: request
   */
  public static postMessageToWorkerThread(worker: worker.ThreadWorker, request: WorkerRequest): void {
    if (CheckEmptyUtils.isEmpty(worker)) {
      Log.error(TAG, 'worker is undefined');
      return;
    }
    try {
      worker.postMessage(request);
    } catch (error) {
      Log.error(TAG, 'postMessageToWorkerThread error : ' + error);
    }
  }

  public static getStringByWorkerCode(code: RequestCode): string {
    if (code === undefined ) {
      return '';
    }
    return WorkerUtil.sCodeToStringMap.get(code);
  }
}