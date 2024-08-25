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
import testNapi, { PixelInfo } from 'libentry.so';
import { TitleBar } from '../../../common/TitleBar'
import hilog from '@ohos.hilog';

const TAG: string = 'napi_roi';

@Entry
@Component
struct imageRoi {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isRoi: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.enum_napi_valuetype') })

      Column() {
        Column() {
          if (this.isRoi == false) {
            Image($rawfile('lena.jpg'))
              .margin({ left: 24, right: 24 })
              .objectFit(ImageFit.Contain)
              .id('backBtn')
          } else {
            Image(this.imagePixelMap)
              .margin({ left: 24, right: 24 })
              .objectFit(ImageFit.Contain)
              .id('backBtn')
          }
        }
        .width('100%')
        .height(480)
        .alignItems(HorizontalAlign.Center)
        .justifyContent(FlexAlign.Start)

        Row() {
          if (this.isRoi) {
            Button($r('app.string.enum_napi_valuetype'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Gray)
              .width(120)
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('imageGray')
              .enabled(false)

          } else {
            Button($r('app.string.enum_napi_valuetype'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width(120)
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('imageGray')
              .onClick(() => {
                getContext().resourceManager.getRawFileContent('lena.jpg')
                  .then((value: Uint8Array) => {
                    hilog.info(0x0000, 'testTag', `getRawFileContent ${value.length} `);
                    testNapi.roi(value).then((res:testNapi.PixelInfo) => {
                      hilog.info(0x0000, 'testTag', 'Test asyncRescont = %{public}d', res.buffSize);
                      let opts: image.InitializationOptions = {
                        editable: true,
                        pixelFormat: this.pixelMapFormat,
                        size: { height: res.rows, width: res.cols }
                      }
                      image.createPixelMap(res.byteBuffer, opts, (error, pixelmap) => {
                        if (error) {
                          Logger.error(TAG, `Failed to create pixelmap error_code ${error.code}`);
                        } else {
                          Logger.info(TAG, 'Succeeded in creating pixelmap.');
                          this.imagePixelMap = pixelmap;
                          this.isRoi = true;
                        }
                      })
                    })
                  })
              })
          }
          Button($r('app.string.image_recover'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width(120)
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ right: 24 })
            .id('imageRecover')
            .onClick(() => {
              this.isRoi = false;
            })
        }
        .width('100%')
        .height(48)
        .alignItems(VerticalAlign.Center)
        .justifyContent(FlexAlign.SpaceBetween)
      }
      .width('100%')
    }
    .height('100%')
    .width('100%')
    .backgroundColor($r('app.color.background_shallow_grey'))
  }
}
