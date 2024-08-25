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

export enum ErrorCode {
  INIT_WFDS_ERROR = 0,
  WIFI_INACTIVE,
  IPP_CONNECT_ERROR,
  GET_CAPS_ERROR,
  LOCATION_CLOSED,
  CONNECTION_POP,
  P2P_SERVICE_ERROR
}

enum ErrorTxt {
  INIT_WFDS_ERROR = 'init wfds error',
  WIFI_INACTIVE = 'wifi in active',
  IPP_CONNECT_ERROR = 'ipp connect error',
  GET_CAPS_ERROR = 'get caps error',
  LOCATION_CLOSED = 'location is closed',
  CONNECTION_POP = 'connection pop-up window',
  P2P_SERVICE_ERROR = 'P2pService is not running'
}

export class ErrorMessage {
  constructor(public code: ErrorCode, public message: ErrorTxt) {
    this.code = code;
    this.message = message;
  }
}

export const CONNECTION_POP = new ErrorMessage(ErrorCode.CONNECTION_POP, ErrorTxt.CONNECTION_POP);
export const INIT_ERROR = new ErrorMessage(ErrorCode.INIT_WFDS_ERROR, ErrorTxt.INIT_WFDS_ERROR);
export const WIFI_INACTIVE = new ErrorMessage(ErrorCode.WIFI_INACTIVE, ErrorTxt.WIFI_INACTIVE);
export const IPP_CONNECT_ERROR = new ErrorMessage(ErrorCode.IPP_CONNECT_ERROR, ErrorTxt.IPP_CONNECT_ERROR);
export const GET_CAPS_ERROR = new ErrorMessage(ErrorCode.GET_CAPS_ERROR, ErrorTxt.GET_CAPS_ERROR);
export const LOCATION_CLOSED = new ErrorMessage(ErrorCode.LOCATION_CLOSED, ErrorTxt.LOCATION_CLOSED);
export const P2P_SERVICE_ERROR = new ErrorMessage(ErrorCode.P2P_SERVICE_ERROR, ErrorTxt.P2P_SERVICE_ERROR);

