/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @file: Call data management
 */
import CallStateManager from './CallStateManager';
import CallStateConst from '../common/constant/CallStateConst';
import ContactManager from './ContactManager';
import NotificationManager from '../model/NotificationManager';
import LogUtils from '../common/utils/LogUtils';
import CallTimeListStruct from '../common/struct/CallTimeListStruct';
import CallListStruct from '../common/struct/CallListStruct';
import DefaultCallData from '../common/struct/TypeUtils';
import VibrationAndProximityUtils from '../common/utils/VibrationAndProximityUtils';

const TAG = 'CallDataManager';
/**
 * class CallDataManager
 */
export default class CallDataManager {
  public callData: DefaultCallData = new DefaultCallData();
  public callList: Array<CallListStruct> = [];
  public callTimeList: Array<CallTimeListStruct> = [];
  private callStateChange: Function;
  private mCallStateManager: CallStateManager;
  private mNotificationManager;
  private contactManager;
  private static sCallDataManager: CallDataManager;

  public static getInstance(): CallDataManager {
    if (!CallDataManager.sCallDataManager) {
      CallDataManager.sCallDataManager = new CallDataManager();
    }
    return CallDataManager.sCallDataManager;
  }

  /**
   * Init data.
   */
  public init(callData, callList, callTimeList) {
    this.mNotificationManager = new NotificationManager();
    this.contactManager = new ContactManager();
    this.mCallStateManager = CallStateManager.getInstance()
    if (this.callData == null) {
      this.callData = callData;
    } else {
      let oldCallData = this.callData;
      this.callData = callData;
      Object.assign(this.callData, {
        ...oldCallData
      });
    }
    if (this.callList.length === 0) {
      LogUtils.i(TAG, 'init callList: undefined');
      this.callList = callList;
    } else {
      let oldCallList = this.callList;
      this.callList = callList;
      Object.assign(this.callList, {
        ...oldCallList
      });
    }
    if (this.callTimeList.length === 0) {
      LogUtils.i(TAG, 'init callTimeList: undefined');
      this.callTimeList = callTimeList;
    } else {
      let oldCallTimeList = this.callTimeList;
      this.callTimeList = callTimeList;
      Object.assign(this.callTimeList, {
        ...oldCallTimeList
      });
    }
    this.callStateChange = (arg) => arg;
    this.mCallStateManager = new CallStateManager(this.callData);
  }

  /**
   * update callList and callData callTimeList
   *`
   * @param { object } callData
   */
  public update(callData) {
    const { callState, callId } = callData;
    if (callId === undefined || callId === null) {
      LogUtils.i(TAG, 'callId is not exist');
      return;
    }
    const targetObj = this.callList.find((v) => v.callId === callId);
    LogUtils.i(TAG, 'update :')
    if (targetObj) {
      const { oldCallState } = targetObj;
      Object.assign(targetObj, {
        ...callData
      });
      if (oldCallState != callState) {
        AppStorage.Get<NotificationManager>('notificationManager').sendCapsuleNotification(callData,
          globalThis.appInactiveState);
      }
    } else {
      this.addCallList({
        ...callData
      });

      // use setTimeout to avoid block ui show
      setTimeout(() => {
        if (this.contactManager != undefined) {
          this.contactManager.getContactInfo(callData)
        }
      }, 0);
    }

    if (callData.callState === CallStateConst.CALL_STATUS_ACTIVE) {
      this.updateCallTimeList(callData);
    }
    const singleCallState = callState === CallStateConst.CALL_STATUS_ACTIVE ||
    callState === CallStateConst.CALL_STATUS_WAITING || this.callList.length === 1;
    const multiCallState = (callState === CallStateConst.CALL_STATUS_DIALING ||
    callState === CallStateConst.CALL_STATUS_ALERTING) && this.callList.length > 1;
    if (singleCallState || multiCallState) {
      this.mCallStateManager.update(callData);
      this.callStateChange(callState);
    }

    if (callState === CallStateConst.CALL_STATUS_DISCONNECTED) {
      if (this.callList.length === 1) {
        if (!AppStorage.Get('AirplaneMode')) {
          this.clearCall(callData);
        }
      } else {
        this.removeCallById(callId);
        const activeCallData = this.callList.find((v) => v.callState === CallStateConst.CALL_STATUS_ACTIVE);
        if (activeCallData) {
          this.mCallStateManager.update(activeCallData);
          this.callStateChange(activeCallData);
          this.sendNotification(activeCallData);
        } else if (this.callList[0]) {
          this.mCallStateManager.update(this.callList[0]);
          this.callStateChange(this.callList[0].callState);
          this.sendNotification(this.callList[0]);
        }
      }
    }
  }

  public clearCall(callData) {
    this.mNotificationManager.cancelNotification();
    AppStorage.Get<NotificationManager>('notificationManager').sendCapsuleNotification(callData, true);
    AppStorage.Delete('CallTimeList');
    this.clearData();
    globalThis.calluiAbilityContext?.terminateSelf().then((data) => {
      LogUtils.i(TAG, 'calluiAbility terminateSelf');
    });
    // remove Proximity Listener
    VibrationAndProximityUtils.wakeupScreen();
    VibrationAndProximityUtils.stopVibration();
  }

  sendNotification(callData) {
    if (globalThis.appInactiveState && callData) {
      AppStorage.Get<NotificationManager>('notificationManager')?.sendNotification(callData);
      AppStorage.Get<NotificationManager>('notificationManager')?.sendCapsuleNotification(callData,
        globalThis.appInactiveState);
    }
  }

  /**
   * Judge whether the call exists.
   */
  public hasAliveCall() {
    const callData = this.callList.find((call) => call.callState !== CallStateConst.CALL_STATUS_DISCONNECTED &&
      call.callState !== CallStateConst.CALL_STATUS_DISCONNECTING);
    LogUtils.i(TAG, 'hasAliveCall:' + JSON.stringify(callData !== undefined));
    return callData !== undefined;
  }

  /**
   * Judge whether the call exists.
   */
  public hasActiveCall(): boolean {
    const callData = this.callList.find((call) => (call.callState === CallStateConst.CALL_STATUS_ACTIVE ||
      call.callState === CallStateConst.CALL_STATUS_HOLDING));
    return callData !== undefined;
  }

  /**
   * Judge whether the call is active or holding.
   */
  public isActiveCall(callId): boolean {
    const callData = this.callList.find((call) => call.callId === callId && (call.callState ===
      CallStateConst.CALL_STATUS_ACTIVE || call.callState === CallStateConst.CALL_STATUS_HOLDING));
    return callData !== undefined;
  }

  /**
   * addCallList
   *
   * @param { object } callData
   */
  private addCallList(callData) {
    this.callList.push(callData);
  }

  /**
   * remove call by call id
   *
   * @param { object } callId - call id
   */
  private removeCallById(callId) {
    const index = this.callList.findIndex((v) => v.callId === callId);
    this.callList.splice(index, 1);
    if (this.callTimeList.find((v) => v.callId === callId)) {
      this.callTimeList.splice(index, 1);
    }
  }

  /**
   * update callTimeList
   *
   * @param { object } callData
   */
  updateCallTimeList(callData) {
    const callTimeObj = this.callTimeList.find((v) => v.callId === callData.callId);
    LogUtils.i(TAG, 'updateCallTimeList : ' + JSON.stringify(callTimeObj));
    if (!callTimeObj && callData.callState === CallStateConst.CALL_STATUS_ACTIVE) {
      const obj = {
        callId: callData.callId,
        callTime: '00:00',
        startTimestamp: (callData.startTime * 1000).valueOf() || new Date().valueOf(),
        endTimestamp: 0,
      };
      this.callTimeList.push(obj);
      AppStorage.SetOrCreate('CallTimeList', this.callTimeList)
      LogUtils.i(TAG, 'updateCallTimeList : ' + JSON.stringify(this.callTimeList))
    }
  }

  clearData() {
    this.callList.splice(0, this.callList.length);
    LogUtils.i(TAG, 'clearData: ' + JSON.stringify(this.callList));
    let inputvalue = AppStorage.Delete('TextInputValue');
    LogUtils.i(TAG, 'clearData:TextInputValue ' + JSON.stringify(inputvalue));
    let textinput = AppStorage.Delete('TextInput');
    AppStorage.Delete('CallTimeList');
    AppStorage.Delete('notificationManager');
    AppStorage.Delete('currentAudioDeviceIcon');
    AppStorage.Delete('datalist');
  }
}