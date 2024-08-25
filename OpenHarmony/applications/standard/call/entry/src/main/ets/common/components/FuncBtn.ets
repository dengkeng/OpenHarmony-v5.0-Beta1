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

import Method from '../utils/Method';
import LogUtils from '../utils/LogUtils';

const TAG = 'FuncBtn';

@Component
export default struct FuncBtn {
  @State btnType: string = '';
  @State iconDisableUrl: string = '';
  @State iconDefaultUrl: string = '';
  @State iconActiveUrl: string = '';
  @State @Watch('iconClassName') isActive: boolean = false;
  @State @Watch('iconClassName') isDisable: boolean = false;
  @State iconText: string = '';
  @State textColor: string = 'rgb(255, 255, 255)';
  btnClick: Function = null;

  /**
   * Button group picture change control
   *
   * @return {string} - return iconUrl
   */
  iconUrl() {
    if (this.isDisable && this.iconDisableUrl) {
      LogUtils.i(TAG, 'iconUrl this.isDisable : ' + this.isDisable);
      return this.iconDisableUrl;
    }
    return this.isActive && this.iconDefaultUrl ? this.iconActiveUrl : this.iconDefaultUrl;
  }

  /**
   * Button group  change picture
   */
  changeBtn(type) {
    LogUtils.i(TAG, 'changeBtn type : ' + type);
    const btnName = ['record', 'video', 'mute'];
    if (Method.includes(btnName, type)) {
      this.isActive = !this.isActive;
    }
  }

  /**
   * Button group style display
   *
   * @return {string} - Button group style display
   */
  iconClassName() {
    if (this.isDisable) {
      this.textColor = '#8c8c8c';
      return 'disable';
    }
    if (this.isActive) {
      this.textColor = '#007DFF';
      return 'enable';
    }
    if (this.btnType == 'msg') {
      this.textColor = '#8c8c8c';
      return '';
    }
    this.textColor = 'rgb(255, 255, 255)';
    LogUtils.i(TAG, 'iconClassName this.isDisable :');
    return 'default';
  }

  aboutToAppear() {
    LogUtils.i(TAG, 'aboutToAppear');
    this.iconClassName();
  }

  build() {
    Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
      Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
        Column() {
          Column() {
            Image(this.iconUrl())
          }
          .width(30)
          .height(30)

          Column() {
            Text(this.iconText)
              .fontColor(this.textColor)
              .fontSize(14)
              .height(19.5)
              .lineHeight(19.5)
          }
          .margin({ top: 2 })
        }
        .enabled(!this.isDisable)
        .onClick(() => {
          this.changeBtn(this.btnType)
          this.btnClick(this.btnType);
        })
      }
    }
  }
}