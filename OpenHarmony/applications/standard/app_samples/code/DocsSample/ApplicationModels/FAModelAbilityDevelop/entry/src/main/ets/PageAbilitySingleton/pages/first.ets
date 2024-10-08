/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Want from '@ohos.app.ability.Want';
import router from '@ohos.router';
import { GlobalContext } from '../../utils/GlobalContext';

@Entry
@Component
struct First {
  onPageShow() {
    let newWant = GlobalContext.getContext().getObject('newWant') as Want;
    if (newWant) {
      if (newWant.parameters) {
        if (newWant.parameters.page) {
          router.push({ url: newWant.parameters.page as string});
          GlobalContext.getContext().setObject("newWant", undefined);
        }
      }
    }
  }
  build() {
    Column() {
      Row() {
        Text($r('app.string.singleton_first_title'))
          .fontSize(24)
          .fontWeight(FontWeight.Bold)
          .textAlign(TextAlign.Start)
          .margin({ top: 12, bottom: 11, right: 24, left: 24 })
      }
      .width('100%')
      .height(56)
      .justifyContent(FlexAlign.Start)

      Image($r('app.media.pic_empty'))
        .width(120)
        .height(120)
        .margin({ top: 224 })

      Text($r('app.string.no_content'))
        .fontSize(14)
        .margin({ top: 8, bottom: 317, right: 152, left: 152 })
        .fontColor($r('app.color.text_color'))
        .opacity(0.4)
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.backGrounding'))
  }
}