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

export class MessageEvent<T> {
  data: T;
}

export enum PrinterFoundType {
  FROM_P2P = 0,
  FROM_EPRINT = 1,
  FROM_LOCAL_NET = 2,
  FROM_USB = 3
}

export enum DateTimeFormat {
  DATE = 0,
  DATE_TIME = 1,
  TIME = 2
}

export enum CustomPrintJobState {
  PRINT_JOB_CANCELLING = 6,  // canceling state of print job
  PRINT_JOB_UNKNOWN = 100, // unknown state of print job
}