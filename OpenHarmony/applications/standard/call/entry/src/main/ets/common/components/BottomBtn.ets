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
 * @file: bottom button component
 */

import CallServiceProxy from '../../model/CallServiceProxy';
import LogUtils from '../utils/LogUtils';
import DefaultCallData from '../struct/TypeUtils';
import CallListStruct from '../struct/CallListStruct'

const TAG = 'BottomBtn';

@Component
export default struct BottomBtn {
  onItemClick: Function = null;
  @Link callData: DefaultCallData;
  @Link callList: Array<CallListStruct>;
  @Link hangup: boolean;
  private mCallServiceProxy: CallServiceProxy;
  private imageList;

  public aboutToAppear() {
    LogUtils.i(TAG, 'aboutToAppear :');
    this.getImageList();
    this.mCallServiceProxy = CallServiceProxy.getInstance();
  }

  /**
   * get Image List
   */
  private getImageList() {
    this.imageList = [
      {
        type: 'keyboard',
        img: $r('app.media.ic_public_DTFS')
      },
      {
        type: 'hangUP',
        img: $r('app.media.ic_public_ring_off')
      },
      {
        type: 'speakerphone',
        img: $r('app.media.ic_public_sound_louder')
      },
    ]
  }

  /**
   * this method is to call the hangup interface
   */
  onHangUp() {
    this.mCallServiceProxy.hangUpCall(this.callData.callId);
    if (this.callList.length === 1) {
      this.hangup = true;
      globalThis.calluiAbilityContext?.terminateSelf().then((data) => {
        LogUtils.i(TAG, 'onHangUp terminateSelfCallBack');
      });
    }
    LogUtils.i(TAG, 'onHangUp this.callData.callId : ' + this.callData.callId);
  }

  /**
   * Image size
   */
  imgSizes(type) {
    if (type == 'keyboard') {
      return 30;
    }
    if (type == 'speakerphone') {
      return 30;
    }
    if (type == 'hangUP') {
      return 56;
    }
  }

  /**
   * Button Event
   */
  onImgClick(type) {
    if (type == 'keyboard') {
      this.onItemClick();
    }
    if (type == 'hangUP') {
      this.onHangUp();
    }
    if (type == 'speakerphone') {
      this.onSpeakerButtonClicked();
    }
  }

  onSpeakerButtonClicked() {
  }
  build() {
    GridRow({ columns: { sm: 4, md: 8, lg: 12 }, gutter: 24 }) {
      GridCol({ span: { sm: 4, md: 6, lg: 6 }, offset: { md: 1, lg: 3 } }) {
        Grid() {
          ForEach(this.imageList, (item,) => {
            GridItem() {
              Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
                Image(item.img)
                  .width(this.imgSizes(item.type))
                  .height(this.imgSizes(item.type))
              }
              .width(56)
              .height(56)
              .onClick(() => {
                this.onImgClick(item.type)
              })
            }
          })
        }
        .columnsGap(24)
        .height(56)
        .columnsTemplate('1fr 1fr 1fr')
        .rowsTemplate('1fr')
      }
    }
    .margin({ left: 24, right: 24 })
  }
}
