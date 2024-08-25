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

import FuncBtn from './FuncBtn';
import InComDialog from './InComDialog';
import ImagePathConst from '../constant/ImagePathConst';
import CallStateConst from '../constant/CallStateConst';
import CallServiceProxy from '../../model/CallServiceProxy';
import sms from '@ohos.telephony.sms';
import resourceManager from '@ohos.resourceManager';
import prompt from '@system.prompt';
import LogUtils from '../utils/LogUtils';
import DefaultCallData from '../struct/TypeUtils';
import CallListStruct from '../struct/CallListStruct'
import VibrationAndProximityUtils from '../utils/VibrationAndProximityUtils';

const TAG = 'IncomingCom';
const SMS_REJECTION = `${ImagePathConst.BASE_URL}ic_public_message.svg`;

/**
 * SMS sent successfully
 */
const SEND_SMS_SUCCESS = 0;

/**
 * Failed to send SMS for unknown reason
 */
const SEND_SMS_FAILURE_UNKNOWN = 1;

/**
 * The wireless module for sending text messages is turned off
 */
const SEND_SMS_FAILURE_RADIO_OFF = 2;

/**
 * The network sending the text message is unavailable
 */
const SEND_SMS_FAILURE_SERVICE_UNAVAILABLE = 3;

@Component
export default struct IncomingCom {
  @Link callList: Array<CallListStruct>;
  @Link callData: DefaultCallData;
  @Link hangup: boolean;
  private btnList = [];
  private msgList = [];
  mCallServiceProxy: CallServiceProxy = null;
  msgDialogController: CustomDialogController = new CustomDialogController ({
    builder: InComDialog({
      cancel: () => {},
      confirm: (item) => {
        this.msgItemClick(item);
      },
      cancelHandle: () => {},
      // @ts-ignore
      list: this.msgList
    }),
    cancel: () => {},
    customStyle: true
  });

  aboutToAppear() {
    this.mCallServiceProxy = CallServiceProxy.getInstance();
    this.getMsgList();
    this.getBtnList();
  }

  aboutToDisappear() {
    this.msgDialogController = null;
  }

  /**
   * send Message   slotId : card slot, destinationHost : accountNumber ,content: content
   *
   * @param obj
   */
  private sendMessage(obj) {
    let slotId = this.callData.accountId;
    let destinationHost = this.callData.accountNumber
    let contactName = this.callData.contactName
    globalThis.calluiAbilityContext?.resourceManager.getString(obj.msg.id, (err, typeName) => {
      LogUtils.i(TAG, 'sendMessage');
      sms.sendMessage({
        slotId: slotId,
        destinationHost: destinationHost,
        content: typeName,
        sendCallback: (err, sendResult) => {
          if (err) {
            return;
          }
          if (sendResult.result === SEND_SMS_SUCCESS) {
            globalThis.calluiAbilityContext?.resourceManager.getString($r('app.string.SMS_Sent')
              .id, (err, typeName) => {
              if (err) {
                return;
              }
              prompt.showToast({
                message: contactName ? typeName + `${contactName}` : typeName + `${destinationHost}`,
                duration: 2000,
              });
            })
          } else {
            globalThis.calluiAbilityContext?.resourceManager.getString($r('app.string.message_Failed')
              .id, (err, typeName) => {
              if (err) {
                return;
              }
              prompt.showToast({
                message: typeName,
                duration: 2000,
              });
            })
          }
        }
      });
    })
  }

  private getMsgList() {
    this.msgList = [
      {
        id: 1,
        msg: $r('app.string.backLater')
      },
      {
        id: 2,
        msg: $r('app.string.answerThePhone')
      },
      {
        id: 3,
        msg: $r('app.string.contactMeLater')
      },
      {
        id: 4,
        msg: $r('app.string.beThereSoon')
      },
    ];
  }

  private getBtnList() {
    this.btnList = [
      {
        type: 'msg',
        iconText: $r('app.string.sms'),
        iconDefaultUrl: SMS_REJECTION,
        iconDisableUrl: SMS_REJECTION,
        isDisable: false
      },
    ];
  }

  /**
   * Call rejection interface
   *
   * @param {string} msg - Send SMS content
   */
  private msgItemClick(obj) {
    LogUtils.i(TAG, 'msgItemClick rejectCall');
    this.mCallServiceProxy.rejectCall(this.callData.callId, obj.msg);
    this.sendMessage(obj);
  }

  /**
   * Handling interface call hangup and rejection
   */
  private async onReject() {
    if (this.callList.length > 1) {
      const incomingData = this.callList.find((v) => v.callState === CallStateConst.callStateObj.CALL_STATUS_WAITING ||
        v.callState === CallStateConst.callStateObj.CALL_STATUS_INCOMING);
      Object.assign(this.callData, {
        ...incomingData
      });
    }
    const {callId, callState} = this.callData;
    if (callState !== CallStateConst.CALL_STATUS_WAITING) {
      this.mCallServiceProxy.rejectCall(callId);
      LogUtils.i(TAG, 'onReject this.mCallServiceProxy.rejectCall :');
    } else {
      this.mCallServiceProxy.hangUpCall(callId);
      LogUtils.i(TAG, 'onReject this.mCallServiceProxy.hangUpCall :');
    }
    if (this.callList.length === 1) {
      this.hangup = true;
      globalThis.calluiAbilityContext?.terminateSelf().then((data) => {
        LogUtils.i(TAG, 'onReject terminateSelfCallBack');
      });
    }
  }

  /**
   * Enable the SMS reply pop-up
   */
  private btnClick(type) {
    LogUtils.i(TAG, 'btnClick : %s' + JSON.stringify(type));
    if (type === 'msg') {
      this.msgDialogController.open();
    }
  }

  /**
   * Answer the phone interface
   */
  private onAnswer() {
    LogUtils.i(TAG, 'onAnswer :');
    const incomingData = this.callList.find((v) => v.callState === CallStateConst.callStateObj.CALL_STATUS_WAITING ||
      v.callState === CallStateConst.callStateObj.CALL_STATUS_INCOMING);
    if (incomingData !== undefined) {
      this.mCallServiceProxy.acceptCall(incomingData.callId);
    } else {
      this.mCallServiceProxy.acceptCall(this.callData.callId);
    }
    VibrationAndProximityUtils.suspendScreen();
    VibrationAndProximityUtils.stopVibration();
  }

  build() {
    GridRow({ columns: { sm: 4, md: 8, lg: 12 }, gutter: 24 }) {
      GridCol({ span: { sm: 4, md: 6, lg: 6 }, offset: { sm: 0, md: 1, lg: 3 } }) {
        Column() {
          Row() {
            ForEach(this.btnList, (item) => {
              Column() {
                FuncBtn({
                  btnType: item.type,
                  iconDisableUrl: item.iconDefaultUrl,
                  iconDefaultUrl: item.iconDefaultUrl,
                  iconText: item.iconText,
                  isDisable: item.isDisable,
                  btnClick: (type) => {
                    this.btnClick(type)
                  }
                })
              }
            })
          }
          .height(51)

          Row() {
            Column() {
              Image($r('app.media.ic_public_ring_off'))
                .width(56)
                .height(56)
                .onClick(() => {
                  this.onReject()
                })
            }.layoutWeight(1)

            Column() {
              Image($r('app.media.ic_public_answer'))
                .width(56)
                .height(56)
                .onClick(() => {
                  this.onAnswer()
                })
            }.layoutWeight(1)
          }
          .margin({ top: 32 })
        }
      }
    }
    .width('100%')
    .margin({ left: 24, right: 24 })
  }
}
