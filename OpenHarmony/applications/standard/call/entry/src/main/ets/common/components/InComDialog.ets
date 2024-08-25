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

import LogUtils from '../utils/LogUtils';

const TAG = 'InComDialog';

@CustomDialog
export default struct InComDialog {
  @StorageLink('curBp') curBp: string = 'md'
  controller: CustomDialogController;
  cancel: () => void;
  confirm: (msg) => void;
  cancelHandle: () => void;
  list: [];

  build() {
    GridRow({ columns: { xs: 4, sm: 4, md: 8, lg: 12 }, gutter: 12 }) {
      GridCol({ span: 4, offset: { md: 2, lg: 4 } }) {
        Column() {
          Column() {
            Flex({ justifyContent: FlexAlign.Start, alignItems: ItemAlign.Start }) {
              Text($r('app.string.hangUpReply'))
                .fontSize(20)
                .fontWeight(FontWeight.Medium)
                .fontColor('#182431')
                .height(56)
            }
            .onClick(() => {
              return;
            })

            Column() {
              ForEach(this.list, (item) => {
                Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
                  Text(item.msg)
                    .width('100%')
                    .fontSize(16)
                    .height(48)
                    .fontColor('#182431')
                    .fontWeight(FontWeight.Medium)
                }
                .onClick(() => {
                  this.controller.close();
                  this.confirm(item)
                  LogUtils.i(TAG, 'onClick and confirm');
                })

                if (item.id !== 4) {
                  Divider()
                    .color($r('app.color.divider_gray'))
                    .height(0.5)
                }
              })
            }

            Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
              Text($r('app.string.cancel'))
                .fontColor('#00CB87')
                .fontSize(16)
                .height(40)
                .fontWeight(FontWeight.Medium)
            }
            .margin({ top: 8, bottom: 16 })
            .onClick(() => {
              LogUtils.i(TAG, 'onClick');
              this.controller.close();
            })
          }
          .padding({ left: 24, right: 24 })
          .backgroundColor(Color.White)
          .borderRadius(32)
        }
        .height('100%')
        .justifyContent(this.curBp === 'sm' ? FlexAlign.End : FlexAlign.Center)
      }
    }
    .margin({ left: 12, right: 12, bottom: this.curBp === 'sm' ? 16 : 0 })
    .onClick(() => {
      this.controller.close();
    })
  }
}