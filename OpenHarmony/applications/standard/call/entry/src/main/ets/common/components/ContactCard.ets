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
 * @file: Header information display component
 */
import LogUtils from '../utils/LogUtils';
import callStateConst from '../constant/CallStateConst';
import Utils from '../utils/utils'
import CallUtils from '../utils/CallUtils'
import DefaultCallData from '../struct/TypeUtils'
import CallListStruct from '../struct/CallListStruct'
import CallTimeListStruct from '../struct/CallTimeListStruct'

const TAG = 'contactCard';

@Component
export default struct ContactCard {
  @State callStateText: string = '';
  @State dialing: string = '.';
  @Prop isShowKeyboard: boolean;
  @Link callList: Array<CallListStruct>;
  @Link callData: DefaultCallData;
  @StorageLink('TextInput') textInput: string = '';
  @StorageLink('TextInputValue') textInputValue: string = '';
  @StorageLink('CallTimeList') callTimeList: Array<CallTimeListStruct> = [];
  @StorageLink('AccountNumber') accountNumber: string = '';
  @StorageLink('IsEmergencyPhoneNumber') isEmergencyPhoneNumber: boolean = false;
  @StorageLink('hasSimCard1') hasSimCard1: boolean = false;
  @StorageLink('hasSimCard2') hasSimCard2: boolean = false;
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
    if (this.callData.callState === 4) {
      CallUtils.hasSimeCard(0);
      CallUtils.hasSimeCard(1);
    }
  }

  /**
   * Determine whether to display the call list or the input box
   *
   * @return {boolean} - return success true fail false
   */
  private isShowCard() {
    return this.callList.length === 1 || (this.callList.length > 1 && this.callList.some((v) =>
    v.callState === callStateConst.CALL_STATUS_WAITING));
  }

  /**
   * Call status
   *
   * @return {number} - Call status
   */
  public callState() {
    return this.callData.callState;
  }

  /**
   * Whether to display the time
   *
   * @return {boolean} - return success true fail false
   */
  private isShowTime() {
    return this.callState() === callStateConst.CALL_STATUS_ACTIVE && this.callList.length === 1;
  }

  private isShowSim() {
    return this.callState() === callStateConst.CALL_STATUS_INCOMING && this.hasSimCard1 && this.hasSimCard2;
  }

  build() {
    GridRow({ columns: { sm: 4, md: 8, lg: 12 }, gutter: 24 }) {
      GridCol({ span: { sm: 4, md: 6, lg: 6 }, offset: { md: 1, lg: 3 } }) {
        Column() {
          if (!this.isShowKeyboard) {
            Image($r('app.media.ic_public_avatar'))
              .width(110)
              .height(110)
              .borderRadius(55)
              .margin({ bottom: 18 })
          }

          if (this.isShowKeyboard && this.textInput.length === 0) {
            Text(this.callData.contactName ? this.callData.contactName : this.callData.accountNumber)
              .fontSize(30)
              .height(40)
              .lineHeight(40)
              .fontWeight(FontWeight.Medium)
              .fontColor('#FFFFFF')
              .margin({ bottom: 8 })
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
          } else if (!this.isShowKeyboard) {
            Text(this.isEmergencyPhoneNumber ? this.emergency : this.callData.contactName ?
              this.callData.contactName : this.callData.accountNumber)
              .fontSize(30)
              .height(40)
              .lineHeight(40)
              .fontWeight(FontWeight.Medium)
              .fontColor('#FFFFFF')
              .margin({ bottom: 8 })
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
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

          Row() {
            if (!this.isShowKeyboard || this.isShowKeyboard && this.textInput.length === 0) {
              Text((this.callData.contactName || this.isEmergencyPhoneNumber) ? this.callData.accountNumber : '')
                .fontSize(14)
                .height(19)
                .lineHeight(16)
                .fontColor('#FFFFFF')
                .margin({ bottom: 8 })
                .visibility((this.callData.contactName || this.isEmergencyPhoneNumber) && !this.isShowKeyboard ?
                  Visibility.Visible : Visibility.None)
            }
          }

          if (this.callData.callState === 1) {
            Row() {
              Text($r('app.string.callHold'))
                .fontSize(14)
                .height(19)
                .lineHeight(19)
                .fontColor('#FFFFFF')
                .fontWeight(FontWeight.Medium)
            }
          }

          if (this.callData.callState === 2) {
            Row() {
              Text($r('app.string.dialing'))
                .fontSize(14)
                .height(19)
                .lineHeight(16)
                .fontColor('#FFFFFF')
                .align(Alignment.Start)

              Text(this.dialing)
                .fontColor('#FFFFFF')
            }
            .width(60)
          }

          if (this.callData.callState === 3) {
            Text($r('app.string.partyIsRinging'))
              .fontSize(14)
              .height(19)
              .lineHeight(16)
              .fontColor('#FFFFFF')
          }

          if (this.isShowSim()) {
            Image(this.callData.accountId == 1 ? $r('app.media.ic_public_phone_sim2') :
              $r('app.media.ic_public_phone_sim1'))
              .margin({ right: 4 })
              .width(12)
              .height(12)
              .opacity(0.6)
          }

          if (this.isShowTime()) {
            Row() {
              if (this.callData.callType === 1) {
                Image($r('app.media.ic_public_phone_HD'))
                  .margin({ right: 4 })
                  .width(12)
                  .height(12)
                  .opacity(0.6)
              }

              Text(this.callTimeList[0]?.callTime)
                .fontSize(14)
                .height(19)
                .lineHeight(19)
                .fontColor('#FFFFFF')
            }
          }
        }
      }
    }
    .margin({ left: 24, right: 24 })
  }
}