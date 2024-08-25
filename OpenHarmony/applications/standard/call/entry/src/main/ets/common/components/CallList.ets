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
 * @file: User list component
 */

import CallStateConst from '../constant/CallStateConst';
import CallServiceProxy from '../../model/CallServiceProxy';
import LogUtils from '../utils/LogUtils';
import DefaultCallData from '../struct/TypeUtils';
import CallListStruct from '../struct/CallListStruct'
import CallTimeListStruct from '../struct/CallTimeListStruct'

const TAG = 'CallList';

@Component
export default struct CallList {
  @Link callList: Array<CallListStruct>;
  @Link callData: DefaultCallData;
  @StorageLink('CallTimeList') callTimeList: Array<CallTimeListStruct> = [];
  private mCallStateConst: CallStateConst;
  private mCallServiceProxy: CallServiceProxy;

  public aboutToAppear(): void {
    LogUtils.i(TAG, 'aboutToAppear');
    this.mCallStateConst = new CallStateConst();
    this.mCallServiceProxy = CallServiceProxy.getInstance();
  }

  /**
   * Three-way call list
   *
   * @return {boolean} - Three-way call list
   */
  getCallList() {
    let arr = this.callList.map((item) => {
      const obj = {};
      return Object.assign({}, {
        ...obj,
        ...item
      });
    });
    return arr.filter((v) => v.callState !== CallStateConst.CALL_STATUS_WAITING);
  }

  /**
   * Phone number display
   *
   * @return {string} Phone number
   */
  public getContactName(item) {
    return (item.contactName ? item.contactName : item.accountNumber) || $r('app.string.unknownNumber');
  }

  /**
   * Phone number display
   *
   * @return {string} Phone number
   */
  public getCallTime(item) {
    let callTimeObj = this.callTimeList.find((o) => o.callId === item.callId);
    return callTimeObj ? callTimeObj.callTime : null;
  }

  /**
   * Call status
   *
   * @return {number} -  callState
   */
  private callState() {
    return this.callData.callState;
  }

  /**
   * Hang up call
   *
   * @param {number} callId - callId
   */
  public onHangUp(callId) {
    LogUtils.i(TAG, 'onHangUp : ' + callId);
    this.mCallServiceProxy.hangUpCall(callId);
    if (this.callList.length === 1) {
      globalThis.calluiAbilityContext?.terminateSelf().then((data) => {
        LogUtils.i(TAG, 'onHangUp terminateSelfCallBack');
      });
    }
  }

  /**
   * UnHold call
   *
   * @param {number} callId - callId
   */
  public onUnHold(callId) {
    LogUtils.i(TAG, 'onUnHold : ' + callId);

    this.getCallList().forEach((item) => {
      if (item.callState === CallStateConst.CALL_STATUS_HOLDING) {
        this.mCallServiceProxy.unHoldCall(item.callId);
        return;
      }
    });
  }

  getInComingCallState() {
    let incomingState = false;
    this.callList.forEach((v) => {
      if (v.callState === CallStateConst.callStateObj.CALL_STATUS_WAITING ||
        v.callState === CallStateConst.callStateObj.CALL_STATUS_INCOMING) {
        incomingState = true;
      }
    });
    LogUtils.i(TAG, 'getInComingCallState incomingState:' + JSON.stringify(incomingState));
    return incomingState;
  }

  build() {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Center }) {
      List() {
        ForEach(this.getCallList(), (item) => {
          ListItem() {
            Column() {
              Row() {
                Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                  Text(this.getContactName(item))
                    .fontColor('#FFFFFF')
                    .fontSize(16)
                    .height(21)
                    .lineHeight(19)

                  Row() {
                    if (item.callState === CallStateConst.callStateObj.CALL_STATUS_ACTIVE) {
                      Text(this.getCallTime(item))
                        .fontSize(14)
                        .fontColor('#FFFFFF')
                        .height(19)
                        .lineHeight(19)
                        .opacity(0.60)
                    } else {
                      Text(CallStateConst.callStateTextMap[item.callState])
                        .fontSize(14)
                        .fontColor('#FFFFFF')
                        .height(19)
                        .lineHeight(19)
                        .opacity(0.60)
                    }

                    if (this.getInComingCallState()) {
                      Image($r('app.media.ic_hangup_list'))
                        .width(30)
                        .height(30)
                        .onClick(() => {
                          this.onHangUp(item.callId);
                        })
                        .margin({ left: 16 })
                    }
                  }
                }
              }
              .onClick(() => {
                this.onUnHold(item.callId);
              })
              .height(64)
            }
          }
        })
      }
      .divider({ strokeWidth: 1, color: $r('app.color.divider_calllist') })
      .margin({ left: 24, right: 24 })
      .width('100%')
      .listDirection(Axis.Vertical)

      Divider()
        .color($r('app.color.divider_calllist'))
        .strokeWidth(1)
    }
    .height(128)
  }
}