/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

/**
 * Sub-Page Entry Component
 */
@Component
export struct SubEntryComponent {
  @State isTouched: boolean = false;
  private targetPage: string = '';
  private title: string | Resource = '';

  build() {
    Navigator({ target: this.targetPage }) {
      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Row() {
          Text(this.title)
            .fontSize($r('app.float.font_16'))
            .lineHeight($r('app.float.wh_value_22'))
            .fontColor($r('app.color.font_color_182431'))
            .fontWeight(FontWeight.Medium)
            .margin({ left: $r('app.float.distance_8') })
            .textAlign(TextAlign.Start);
        }

        Image('/res/image/ic_settings_arrow.svg')
          .width($r('app.float.wh_value_12'))
          .height($r('app.float.wh_value_24'))
          .margin({ right: $r('app.float.distance_8') })
          .fillColor($r("sys.color.ohos_id_color_primary"))
          .opacity($r("app.float.opacity_0_2"))
      }
      .height(ComponentConfig.WH_100_100)
      .width(ComponentConfig.WH_100_100)
      .borderRadius($r('app.float.radius_16'))
      .linearGradient(this.isTouched ? {
        angle: 90,
        direction: GradientDirection.Right,
        colors: [[$r("app.color.DCEAF9"), 0.0], [$r("app.color.FAFAFA"), 1.0]]
      } : {
        angle: 90,
        direction: GradientDirection.Right,
        colors: [[$r("sys.color.ohos_id_color_foreground_contrary"), 1], [$r("sys.color.ohos_id_color_foreground_contrary"), 1]]
      })
      .onTouch((event?: TouchEvent | undefined) => {
        if (event?.type === TouchType.Down) {
          this.isTouched = true;
        }
        if (event?.type === TouchType.Up) {
          this.isTouched = false;
        }
      })
    }
    .padding($r('app.float.distance_4'))
    .height($r('app.float.wh_value_56'))
    .borderRadius($r('app.float.radius_16'))
    .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"));
  }
}


/**
 * Sub-Page Entry Component with EndText
 */
@Component
export struct SubEntryComponentWithEndText {
  @State isTouched: boolean = false;
  @Link endText: string;
  private targetPage: string = '';
  private title: string | Resource = '';

  build() {
    Navigator({ target: this.targetPage }) {
      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Row() {
          Text(this.title)
            .fontSize($r('app.float.font_16'))
            .lineHeight($r('app.float.wh_value_22'))
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.font_color_182431'))
            .margin({ left: $r('app.float.distance_8') })
            .textAlign(TextAlign.Start);
        }

        Row() {
          Text(this.endText)
            .fontSize($r('app.float.font_14'))
            .lineHeight($r('app.float.wh_value_19'))
            .fontWeight(FontWeight.Regular)
            .fontColor($r('sys.color.ohos_id_color_text_secondary'))
            .margin({ right: $r('app.float.distance_4') })
            .textAlign(TextAlign.End);
          Image('/res/image/ic_settings_arrow.svg')
            .width($r('app.float.wh_value_12'))
            .height($r('app.float.wh_value_24'))
            .margin({ right: $r('app.float.distance_8') })
            .fillColor($r("sys.color.ohos_id_color_primary"))
            .opacity($r("app.float.opacity_0_2"))
        }
      }
      .height(ComponentConfig.WH_100_100)
      .width(ComponentConfig.WH_100_100)
      .borderRadius($r('app.float.radius_20'))
      .linearGradient(this.isTouched ? {
        angle: 90,
        direction: GradientDirection.Right,
        colors: [[$r("app.color.DCEAF9"), 0.0], [$r("app.color.FAFAFA"), 1.0]]
      } : {
        angle: 90,
        direction: GradientDirection.Right,
        colors: [[$r("sys.color.ohos_id_color_foreground_contrary"), 1], [$r("sys.color.ohos_id_color_foreground_contrary"), 1]]
      })
      .onTouch((event?: TouchEvent | undefined) => {
        if (event?.type === TouchType.Down) {
          this.isTouched = true;
        }
        if (event?.type === TouchType.Up) {
          this.isTouched = false;
        }
      });
    }
    .padding($r('app.float.distance_4'))
    .height($r('app.float.wh_value_56'))
    .borderRadius($r('app.float.radius_24'))
    .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"));
  }
}