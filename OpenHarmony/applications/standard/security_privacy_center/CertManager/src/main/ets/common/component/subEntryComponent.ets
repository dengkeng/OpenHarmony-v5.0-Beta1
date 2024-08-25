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

/**
 * Sub-Page Entry Component
 */
@Component
export struct SubEntryComponent {
  private targetPage: string = '';
  private title: string | Resource = '';

  @Styles normalStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
  };

  @Styles pressedStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
  };

  build() {
    Navigator({ target: this.targetPage }) {
      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Row() {
          Text(this.title)
            .fontSize($r('app.float.font_16'))
            .lineHeight($r('app.float.wh_value_22'))
            .fontColor($r('sys.color.ohos_id_color_text_primary'))
            .fontWeight(FontWeight.Medium)
            .margin({ left: $r('app.float.wh_value_8') })
            .textAlign(TextAlign.Start);
        }

        Image($r('app.media.ic_settings_arrow'))
          .width($r('app.float.wh_value_12'))
          .height($r('app.float.wh_value_24'))
          .fillColor($r('sys.color.ohos_id_color_primary'))
          .opacity($r('app.float.opacity_0_2'))
          .margin({ right: $r('app.float.wh_value_8') });
      }
      .borderRadius($r('app.float.radius_20'))
      .height(ComponentConfig.WH_100_100)
      .width(ComponentConfig.WH_100_100)
      .stateStyles({
        normal: this.normalStyle,
        pressed: this.pressedStyle
      })
    }
    .height($r('app.float.wh_value_48'))
    .backgroundColor($r('sys.color.ohos_id_color_foreground_contrary'));
  }
}


/**
 * Sub-Page Entry Component with EndText
 */
@Component
export struct SubEntryComponentWithEndText {
  @Prop endText: string = '';
  private targetPage: string = '';
  private title: string | Resource = '';

  @Styles normalStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
  };

  @Styles pressedStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
  };

  build() {
    Navigator({ target: this.targetPage }) {
      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Row() {
          Text(this.title)
            .fontSize($r('app.float.font_16'))
            .lineHeight($r('app.float.wh_value_22'))
            .fontWeight(FontWeight.Medium)
            .fontColor($r('sys.color.ohos_id_color_text_primary'))
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
            .fillColor($r('sys.color.ohos_id_color_primary'))
            .opacity($r('app.float.opacity_0_2'))
        }
      }
      .height(ComponentConfig.WH_100_100)
      .width(ComponentConfig.WH_100_100)
      .borderRadius($r('app.float.radius_20'))
      .stateStyles({
        normal: this.normalStyle,
        pressed: this.pressedStyle
      })
    }
    .padding($r('app.float.distance_4'))
    .height($r('app.float.wh_value_56'))
    .borderRadius($r('app.float.radius_24'))
    .backgroundColor($r('sys.color.ohos_id_color_foreground_contrary'));
  }
}
