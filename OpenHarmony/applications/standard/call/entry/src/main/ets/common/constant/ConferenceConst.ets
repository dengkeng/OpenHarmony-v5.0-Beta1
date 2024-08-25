/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 * @file: Conference call status
 */
export default class ConferenceConst {
  // Free conference call
  public static TEL_CONFERENCE_IDLE: number = 0;

  // Conference call activation
  public static TEL_CONFERENCE_ACTIVE: number = 1;

  // The conference call is disconnecting
  public static TEL_CONFERENCE_DISCONNECTING: number = 2;

  // Conference call disconnected
  public static TEL_CONFERENCE_DISCONNECTED: number = 3;
  public static conferenceStateObj = {
    TEL_CONFERENCE_IDLE: ConferenceConst.TEL_CONFERENCE_IDLE,
    TEL_CONFERENCE_ACTIVE: ConferenceConst.TEL_CONFERENCE_ACTIVE,
    TEL_CONFERENCE_DISCONNECTING: ConferenceConst.TEL_CONFERENCE_DISCONNECTING,
    TEL_CONFERENCE_DISCONNECTED: ConferenceConst.TEL_CONFERENCE_DISCONNECTED
  };
}

