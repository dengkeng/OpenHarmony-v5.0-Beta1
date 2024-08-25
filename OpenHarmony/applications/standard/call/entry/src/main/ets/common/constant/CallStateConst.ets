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
 * @file: Call status
 */
const callStateTxtList = ['calling', 'callHold', 'dialing', 'partyIsRinging', '', 'thirdPartyCalls', 'hangUpCompleted',
  'hangingUp', 'callIdle'];

export default class CallStateConst {
  // calling
  public static CALL_STATUS_ACTIVE: number = 0;

  // State keeping
  public static CALL_STATUS_HOLDING: number = 1;

  // Dialing
  public static CALL_STATUS_DIALING: number = 2;

  // The other party is ringing
  public static CALL_STATUS_ALERTING: number = 3;

  // Call from the other party
  public static CALL_STATUS_INCOMING: number = 4;

  // Waiting for third-party calls
  public static CALL_STATUS_WAITING: number = 5;

  // Hung up
  public static CALL_STATUS_DISCONNECTED: number = 6;

  // Hanging up
  public static CALL_STATUS_DISCONNECTING: number = 7;

  // Idle state
  public static CALL_STATUS_IDLE: number = 8;
  public static callStateObj = {
    CALL_STATUS_ACTIVE: CallStateConst.CALL_STATUS_ACTIVE,
    CALL_STATUS_HOLDING: CallStateConst.CALL_STATUS_HOLDING,
    CALL_STATUS_DIALING: CallStateConst.CALL_STATUS_DIALING,
    CALL_STATUS_ALERTING: CallStateConst.CALL_STATUS_ALERTING,
    CALL_STATUS_INCOMING: CallStateConst.CALL_STATUS_INCOMING,
    CALL_STATUS_WAITING: CallStateConst.CALL_STATUS_WAITING,
    CALL_STATUS_DISCONNECTED: CallStateConst.CALL_STATUS_DISCONNECTED,
    CALL_STATUS_DISCONNECTING: CallStateConst.CALL_STATUS_DISCONNECTING,
    CALL_STATUS_IDLE: CallStateConst.CALL_STATUS_IDLE
  };

  public static callStateTextMap = {
    [CallStateConst.CALL_STATUS_ACTIVE]: '',
    [CallStateConst.CALL_STATUS_HOLDING]: $r('app.string.callHold'),
    [CallStateConst.CALL_STATUS_DIALING]: $r('app.string.dialing'),
    [CallStateConst.CALL_STATUS_ALERTING]: $r('app.string.partyIsRinging'),
    [CallStateConst.CALL_STATUS_INCOMING]: '',
    [CallStateConst.CALL_STATUS_WAITING]: '',
    [CallStateConst.CALL_STATUS_DISCONNECTED]: $r('app.string.hangUpCompleted'),
    [CallStateConst.CALL_STATUS_DISCONNECTING]: $r('app.string.hangingUp'),
    [CallStateConst.CALL_STATUS_IDLE]: ''
  };

  public static defaultCallData = {
    callId: 0,
    callState: CallStateConst.CALL_STATUS_IDLE,
    accountNumber: '',
    videoState: 0,
    callType: 0,
    conferenceState: 0
  };

  public getCallStateText = (state) => callStateTxtList[state] !== undefined ? callStateTxtList[state] : '';
}