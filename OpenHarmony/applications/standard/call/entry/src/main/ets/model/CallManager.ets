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
 * @file: Call management
 */
import CallDataManager from './CallDataManager';
import CallUtils from '../common/utils/CallUtils';
import Utils from '../common/utils/utils';
import CallServiceProxy from './CallServiceProxy';
import LogUtils from '../common/utils/LogUtils'
import call from '@ohos.telephony.call';
import CallStateConst from '../common/constant/CallStateConst';
import DefaultCallData from '../common/struct/TypeUtils';
import CallListStruct from '../common/struct/CallListStruct';
import VibrationAndProximityUtils from '../common/utils/VibrationAndProximityUtils';

const TAG = 'CallManager';
const TIMING = 1000;

/**
 * class CallManager
 */
export default class CallManager {
  private callData: DefaultCallData = new DefaultCallData();
  private callList: Array<CallListStruct> = [];
  private timer = null;
  public callTimeList = [];
  private ctx = [];
  private sendNotificationHandle: Function;
  private mCallDataManager: CallDataManager;
  private mCallServiceProxy: CallServiceProxy;
  private mUtils: Utils;
  private diffSeconds
  private mTimeMeter;
  private isServiceConnected: boolean = false;

  public static getInstance(): CallManager {
    if (globalThis.callManager == null) {
      globalThis.callManager = new CallManager();
    }
    return globalThis.callManager;
  }

  private constructor() {
    this.mCallServiceProxy = CallServiceProxy.getInstance();
    this.mUtils = Utils.getInstance();
    this.timer = null;
    this.mCallDataManager = CallDataManager.getInstance();
  }

  init(ctx) {
    this.callData = ctx.callData;
    this.ctx = ctx;
    this.callTimeList = ctx.callTimeList;
    this.mCallDataManager?.init(ctx.callData, ctx.callList, ctx.callTimeList);
    this.openTimer();
    this.sendNotificationHandle = (arg) => arg;
    this.initCallData();
  }

  /**
   * init CallData
   */
  private initCallData() {
    if (globalThis.abilityWant && globalThis.abilityWant.parameters && ('callState' in globalThis.abilityWant.parameters)) {
      if (!this.isServiceConnected) {
        globalThis.calluiAbilityContext?.terminateSelf().then((data) => {
          LogUtils.i(TAG, 'calluiAbility terminateSelf because service disconnected');
        });
        return;
      }
      let callData = this.getCallDataFromWant(globalThis.abilityWant.parameters);
      this.update(callData);
      LogUtils.i(TAG, 'initCallData featureAbility.getWant :')
    } else {
      this.mCallServiceProxy.publish({
        key: 'getInitCallData',
        params: []
      });
    }
  }

  setServiceConnected(isServiceConnected: boolean): void {
      this.isServiceConnected = isServiceConnected;
  }

  /**
   * get callData from want parameters
   */
  private getCallDataFromWant(parameters) {
    return Object.assign({}, {
      accountId: parameters.accountId,
      accountNumber: parameters.accountNumber,
      callId: parameters.callId,
      callState: parameters.callState,
      callType: parameters.callType,
      conferenceState: parameters.conferenceState,
      isEcc: parameters.isEcc,
      startTime: parameters.startTime,
      videoState: parameters.videoState});
  }

  /**
   * update callData callBack
   *
   * @param { Object } callData -Object
   */
  async update(callData) {
    LogUtils.i(TAG, 'update calldata:')
    if (this.callData != undefined && this.callData.callId === callData.callId) {
      const { callState } = this.callData;
      if (callState === 6 && this.callList.length === 1) {
        globalThis.calluiAbilityContext?.terminateSelf().then((data) => {
          LogUtils.i(TAG, 'calluiAbility terminateSelf because service disconnected');
        });
        // remove Proximity Listener
        VibrationAndProximityUtils.wakeupScreen();
        VibrationAndProximityUtils.stopVibration();
        return;
      }
    }
    this.callData = callData;
    this.mCallDataManager.update(callData);
    call.formatPhoneNumber(callData.accountNumber, (err, data) => {
      if (err) {
        LogUtils.i(TAG, 'updata calldata formatPhoneNumber err:' + JSON.stringify(err));
      } else if (data === undefined) {
        AppStorage.SetOrCreate('AccountNumber', callData.accountNumber);
      } else {
        LogUtils.i(TAG, 'updata calldata formatPhoneNumber success:' + JSON.stringify(data));
        AppStorage.SetOrCreate('AccountNumber', data);
      }
    });
    CallUtils.isEmergencyPhoneNumber(callData.accountNumber);
    LogUtils.i(TAG, 'update :');
  }

  /**
   * update call time list
   */
  updateCallTimeList() {
    if (!this.mCallDataManager.hasActiveCall()) {
      LogUtils.i(TAG, 'no active calls to update');
      return;
    }

    this.callTimeList = AppStorage.Get('CallTimeList');
    this.callTimeList.forEach((item, i) => {
      if (this.mCallDataManager.isActiveCall(item.callId)) {
        item.endTimestamp = new Date().valueOf();
        const diffSeconds = item.endTimestamp - item.startTimestamp;
        this.diffSeconds = diffSeconds
        item.callTime = this.mUtils.formatTime(diffSeconds);
        this.callTimeList.splice(i, 1, {
          ...item,
        });
        AppStorage.SetOrCreate('CallTimeList', this.callTimeList);
      }
    });
    this.mTimeMeter = setTimeout(() => {
      this.updateCallTimeList();
    }, 1000 - this.diffSeconds % 1000);

  }

  /**
   * open timer
   *
   * @param { Function } callBack - add updateCallTimeList callBack
   */
  openTimer() {
    this.timer = setInterval(() => {
      this.updateCallTimeList();
      if (this.callData.callState === CallStateConst.CALL_STATUS_ACTIVE && this.callList.length === 1) {
        clearInterval(this.timer);
      }
    }, TIMING);
  }

  /**
   * clear timer
   */
  clearTimer() {
    clearInterval(this.timer);
  }
}
