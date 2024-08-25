/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

import router from '@ohos.router';
import image from '@ohos.multimedia.image';
import Logger from '../../../util/Logger';
import { TitleBar } from '../../../common/TitleBar'
import hilog from '@ohos.hilog';
import {XComponentContext} from "../../../interface/XComponentContext.d"
import resourceManager from '@ohos.resourceManager';

const TAG: string = 'napi_ffmpegcase';

@Entry
@Component
struct eglfuncs {
  private btnFontColor: Resource = $r('app.color.white');
  @State isSetInstance: Boolean = false;
  @State currentStatus: string = "init";
  private xComponentContext: XComponentContext | undefined = undefined;
  private resfname: string = 'tj.bmp'
  private mp4fname: string = 'test1.mp4'

  build() {
    Column() {
      Row() {
        Text('EGL Texture Render Sample')
          .fontSize('24fp')
          .fontWeight(500)
          .margin({
            left: 24,
            top: 12
          })
      }
      .margin({ top: 24 })
      .width('100%')
      .height(56)

      Column({ space: 10 }) {
        XComponent({
          id: 'xcomponentId',
          type: XComponentType.SURFACE,
          libraryname: 'entry'
        })
          .onLoad((xComponentContext) => {
            this.xComponentContext = xComponentContext as XComponentContext;
            this.currentStatus = "index";
          })
          .onDestroy(() => {
            console.log('onDestroy');
          })
          .id("xcomponent")

        Text(this.currentStatus)
          .fontSize('24fp')
          .fontWeight(500)
      }
      .onClick(() => {
        let hasChangeColor: boolean = false;
        if (this.xComponentContext && this.xComponentContext.getStatus()) {
          hasChangeColor = this.xComponentContext.getStatus().hasChangeColor;
        }
        if (hasChangeColor) {
          this.currentStatus = "change color";
        }
      })
      .margin({
        top: 27,
        left: 12,
        right: 12
      })
      .height('40%')
      .width('90%')

      Row() {
        Column() {
          Button('Draw BMP')
            .fontSize('16fp')
            .fontWeight(500)
            .margin({ bottom: 24 })
            .onClick(() => {
              getContext().resourceManager.getRawFd(this.resfname)
                .then((value: resourceManager.RawFileDescriptor) => {
                  let fd = value.fd;
                  let offset = value.offset;
                  let length = value.length;
                  hilog.info(0x0000, 'testTag', `getRawFd ${fd} ${offset} ${length}`);

                  if (this.xComponentContext) {
                    this.xComponentContext.drawPattern(fd, offset, length);

                    let hasDraw: boolean = false;
                    if (this.xComponentContext.getStatus()) {
                      hasDraw = this.xComponentContext.getStatus().hasDraw;
                    }
                    if (hasDraw) {
                      this.currentStatus = "draw bmp";
                    }
                  }
                })

            })
            .width('53.6%')
            .height(40)
        }
      }
      .width('100%')
      .justifyContent(FlexAlign.Center)
      .alignItems(VerticalAlign.Bottom)
      .layoutWeight(1)
    }
    .width('100%')
    .height('100%')
  }
}
