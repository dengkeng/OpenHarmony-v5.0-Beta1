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

import CallServiceProxy from '../../model/CallServiceProxy';
import LogUtils from '../utils/LogUtils';
import DefaultCallData from '../struct/TypeUtils';

const TAG = 'DtmfBtn';

class DataListStruct {
  public value: string
  public sign: string
}

@Component
export default struct DtmfBtn {
  @State color: string = 'rgba(255, 255, 255, 0)';
  @State subStr:string = '';
  @Link dataList: Array<DataListStruct>;
  @Link textInput: string;
  @Link textInputValue: string;
  private item: DataListStruct;
  private mCallServiceProxy;
  callData: DefaultCallData;

  public aboutToAppear(): void {
    this.mCallServiceProxy = new CallServiceProxy();
  }

  /**
   * Call and press the DTMF interface
   *
   * @param {Object} obj - Object
   */
  onBtnTouchStart(obj) {
    this.mCallServiceProxy.startDTMF(this.callData.callId, String(obj.value));
    LogUtils.i(TAG, 'onBtnTouchStart :');
  }

  /**
   * Call release and send DTMF interface
   *
   * @param {Object} obj - Incoming value
   */
  onBtnTouchEnd() {
    this.mCallServiceProxy.stopDTMF(this.callData.callId);
    LogUtils.i(TAG, 'onBtnTouchEnd :');
  }

  build() {
    Row() {
      Column() {
        if (this.item.value == '*') {
          Image($r('app.media.ic_star'))
            .width(24)
            .height(30)
            .margin({ bottom:10 })
            .padding({ top: 8 })
        } else if (this.item.value == '#') {
          Image($r('app.media.ic_pound'))
            .width(24)
            .height(30)
            .margin({ bottom:10 })
            .padding({ top: 8 })
        } else {
          Text(this.item.value)
            .fontSize(30)
            .height(40)
            .lineHeight(40)
            .fontWeight(FontWeight.Medium)
            .fontColor('#FFFFFF')
            .margin(0.5)
        }

        if (this.item.sign == '+') {
          Text(this.item.sign)
            .fontSize(20)
            .height(24)
            .lineHeight(16)
            .opacity(0.6)
            .fontWeight(FontWeight.Regular)
            .fontColor('#FFFFFF')
        } else {
          Text(this.item.sign)
            .fontSize(12)
            .height(16)
            .lineHeight(16)
            .opacity(0.6)
            .fontWeight(FontWeight.Regular)
            .fontColor('#FFFFFF')
        }
      }
      .width(56.5)
      .height(56.5)
      .backgroundColor(this.color)
      .borderRadius(28.25)
      .onTouch((event: TouchEvent) => {
        if (event.type === TouchType.Down) {
          this.color = 'rgba(255, 255, 255, 0.4)';
          this.textInput = this.textInput + this.item.value;
          if (this.textInput.length > 19) {
            this.subStr = this.textInput.substr(this.textInput.length - 19, this.textInput.length - 1);
            this.textInputValue = this.subStr;
          } else {
            this.textInputValue = this.textInput;
          }
          AppStorage.SetOrCreate('TextInputValue', this.textInputValue);
          AppStorage.SetOrCreate('TextInput', this.textInput);
          LogUtils.i(TAG, 'textInputValue + TextInput : %s' + JSON.stringify(AppStorage.Get('TextInputValue')) +
            JSON.stringify(AppStorage.Get('TextInput')));
          this.onBtnTouchStart(this.item);
        }
        if (event.type === TouchType.Up) {
          this.color = 'rgba(255, 255, 255, 0)';
          this.onBtnTouchEnd();
        }
      })
    }
  }
}
