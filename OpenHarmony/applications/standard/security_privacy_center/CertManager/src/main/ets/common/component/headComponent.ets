/**
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
import ComponentConfig from './ComponentConfig';
import Router from '@ohos.router';
import { GlobalContext } from '../GlobalContext';

const TAG = 'CertManager HeadComponent: ';

/**
 * head custom component
 */
@Component
export default struct HeadComponent {
  private icBackIsVisibility: boolean = true;
  private headName: string | Resource = '';
  @State isTouch: boolean = false;

  build() {
    Row() {
      Stack({ alignContent: Alignment.Center }) {
        Image($r('app.media.ic_back'))
          .width($r('app.float.wh_value_24'))
          .height($r('app.float.wh_value_24'))
          .fillColor($r('sys.color.ohos_id_color_primary'))
      }
      .margin({ right: $r('app.float.wh_value_16') })
      .backgroundColor(this.isTouch ? $r('sys.color.ohos_id_color_click_effect')
        : $r('sys.color.ohos_id_color_sub_background'))
      .visibility(this.icBackIsVisibility ? Visibility.Visible : Visibility.None)
      .onClick(() => {
        let length = Router.getLength();
        console.log(TAG + 'router length: ' + Number(length));
        if (GlobalContext.getContext().getFlag()) {
          Number(length) == 1 ? GlobalContext.getContext().getSession().sendData({'action': 'exit'}) : Router.back();
        } else {
          Number(length) == 1 ? GlobalContext.getContext().getCmContext().terminateSelf() : Router.back();
        }
      })
      .onTouch((event?: TouchEvent) => {
        if (event?.type === TouchType.Down) {
          this.isTouch = true;
        }
        if (event?.type === TouchType.Up) {
          this.isTouch = false;
        }
      });

      Text(this.headName)
        .fontSize($r('app.float.head_font_20'))
        .lineHeight($r('app.float.wh_value_33'))
        .fontFamily('HarmonyHeiTi-Bold')
        .fontWeight(FontWeight.Regular)
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .maxLines(ComponentConfig.MAX_LINES_1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .textAlign(TextAlign.Start)
        .margin({ top: $r('app.float.wh_value_13'), bottom: $r('app.float.wh_value_15') });
    }
    .width(ComponentConfig.WH_100_100)
    .padding({ left: $r('app.float.wh_value_12') })
    .height($r('app.float.wh_value_56'))
    .alignItems(VerticalAlign.Center)
    .align(Alignment.Start)
  }
}
