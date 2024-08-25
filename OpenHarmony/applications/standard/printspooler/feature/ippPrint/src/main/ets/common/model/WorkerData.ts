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

/**
 * Request from the main thread send to worker thread
 */
export class WorkerRequest {
  requestCode: RequestCode;
  data: Object;

  constructor(requestCode: RequestCode) {
    this.requestCode = requestCode;
  }
}

/**
 * Response from worker thread send to the main thread
 */
export class WorkerResponse {
  requestCode: RequestCode;
  responseCode: ResponseCode;
  data: Object;

  constructor(requestCode: RequestCode, responseCode: ResponseCode) {
    this.requestCode = requestCode;
    this.responseCode = responseCode;
  }
}

/**
 * Request Code
 */
export enum RequestCode {
  P2P_START_DISCOVERY,
  P2P_CANCEL_DISCOVERY,
  GET_CAPS,
}

/**
 * Response Code
 */
export enum ResponseCode {
  OK,
  ERROR
}