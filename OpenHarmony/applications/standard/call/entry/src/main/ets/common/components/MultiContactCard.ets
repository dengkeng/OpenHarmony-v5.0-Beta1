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
 * @file: Header information display component
 */
import LogUtils from '../utils/LogUtils';
import CallStateConst from '../constant/CallStateConst';
import Utils from '../utils/utils'
import CallList from './CallList'
import callStateConst from '../constant/CallStateConst';
import CallUtils from '../utils/CallUtils'
import DefaultCallData from '../struct/TypeUtils'
import CallListStruct from '../struct/CallListStruct'
import CallTimeListStruct from '../struct/CallTimeListStruct'

const TAG = 'MultiContactCard';

@Component
export default struct MultiContactCard {
  @State callStateText: string = '';
  @State dialing: string = '.';
  @Prop isShowKeyboard: boolean;
  @Link callList: Array<CallListStruct>;
  @Link callData: DefaultCallData;
  @Link incomingData: DefaultCallData;
  @StorageLink('TextInput') textInput: string = '';
  @StorageLink('TextInputValue') textInputValue: string = '';
  @StorageLink('CallTimeList') callTimeList: Array<CallTimeListStruct> = [];
  @StorageLink('AccountNumber') accountNumber: string = '';
  @StorageLink('IsEmergencyPhoneNumber') isEmergencyPhoneNumber: boolean = false;
  @StorageLink('hasSimCard1') hasSimCard1: boolean = false;
  @StorageLink('hasSimCard2') hasSimCard2: boolean = false;
  @State multiContactName: string = '';
  @State multiContactNumber: string = '';
  private mUtils: Utils;
  private timer;
  private emergency = $r('app.string.emergency');

  public aboutToAppear(): void {
    LogUtils.i(TAG, 'aboutToAppear');
    this.mUtils = Utils.getInstance();
    this.timer = setInterval(() => {
      if (this.dialing === '...') {
        this.dialing = '';
      }
      this.dialing += '.';
    }, 500)
    if (this.callData.callState === 3) {
      clearInterval(this.timer)
    }

    if (this.callData.callState === 4 || this.callData.callState === 5) {
      CallUtils.hasSimeCard(0);
      CallUtils.hasSimeCard(1);
    }
  }

  private isShowSim() {
    return (this.callData.callState === CallStateConst.callStateObj.CALL_STATUS_WAITING || this.callData.callState ===
      CallStateConst.callStateObj.CALL_STATUS_INCOMING) && this.hasSimCard1 && this.hasSimCard2;
  }

  getInComingCallState() {
    if (this.callList.length > 1) {
      let incomingState = false;
      this.callList.forEach((v) => {
        if (v.callState === CallStateConst.callStateObj.CALL_STATUS_WAITING || v.callState ===
          CallStateConst.callStateObj.CALL_STATUS_INCOMING) {
          this.incomingData = v;
          this.multiContactName = v.contactName;
          this.multiContactNumber = v.accountNumber;
          incomingState = true;
        }
      });
      LogUtils.i(TAG, 'getInComingCallState incomingState:' + JSON.stringify(incomingState));
      return incomingState;
    } else {
      return this.callData.callState;
    }
  }

  build() {
    GridRow({ columns: { sm: 4, md: 8, lg: 12 }, gutter: 24 }) {
      GridCol({ span: { sm: 4, md: 6, lg: 6 }, offset: { md: 1, lg: 3 } }) {
        Column() {
          if (!(this.isShowKeyboard && this.textInput.length != 0)) {
            CallList({
              callList: $callList,
              callData: $callData
            })

            if (this.getInComingCallState()) {
              Column() {
                if (!this.isShowKeyboard || this.isShowKeyboard && this.textInput.length === 0) {
                  Text(this.isEmergencyPhoneNumber ? this.emergency : this.multiContactName ? this.multiContactName :
                    this.multiContactNumber)
                    .fontSize(30)
                    .height(40)
                    .lineHeight(40)
                    .fontWeight(FontWeight.Medium)
                    .fontColor('#FFFFFF')
                    .margin({ bottom: 8 })

                  Text((this.multiContactName || this.isEmergencyPhoneNumber) ? this.multiContactNumber : '')
                    .fontSize(14)
                    .height(19)
                    .lineHeight(19)
                    .fontColor('#FFFFFF')
                    .opacity(0.60)
                    .visibility((this.multiContactName || this.isEmergencyPhoneNumber) && !this.isShowKeyboard ?
                      Visibility.Visible : Visibility.None)
                }
              }
              .margin({ top: 56 })

              if (this.isShowSim()) {
                Image(this.callData.accountId == 1 ? $r('app.media.ic_public_phone_sim2') :
                  $r('app.media.ic_public_phone_sim1'))
                  .margin({ right: 4 })
                  .width(12)
                  .height(12)
                  .opacity(0.6)
              }
            }


          } else if (this.isShowKeyboard && this.textInput.length != 0) {
            Scroll() {
              Text(this.textInputValue)
                .height(40)
                .fontSize(30)
                .lineHeight(40)
                .fontWeight(FontWeight.Medium)
                .margin({ bottom: 8 })
                .fontColor('#FFFFFF')
                .onTouch((event: TouchEvent) => {
                  if (event.type === TouchType.Move) {
                    this.textInputValue = this.textInput
                  }
                })
            }
            .scrollable(ScrollDirection.Horizontal)
            .scrollBar(BarState.Off)
            .width('100%')
          }
        }
      }
    }
    .margin({ left: 24, right: 24 })
  }
}