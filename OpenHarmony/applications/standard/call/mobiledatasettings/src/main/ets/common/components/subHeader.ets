/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
@Component
export struct SubHeader {
  @State titleContent: Resource = $r('app.string.mobile_data_card1');
  @Prop subTitleContent: string;

  titleContenet() {
    return this.titleContenet()
  }

  build() {
    Row() {
      Text(this.titleContent)
        .fontSize(14)
        .fontColor($r('sys.color.ohos_id_color_text_secondary'))
        .fontFamily('HarmonyHeiTi')
        .fontWeight(FontWeight.Medium)
      Text(this.subTitleContent)
        .fontSize(14)
        .fontColor($r('sys.color.ohos_id_color_text_secondary'))
        .fontFamily('HarmonyHeiTi')
        .fontWeight(FontWeight.Medium)
    }
    .width('100%')
    .height(48)
    .alignItems(VerticalAlign.Bottom)
    .padding({
      bottom: 9,
      top: 19.5,
      left: $r('sys.float.ohos_id_card_margin_start'),
      right: $r('sys.float.ohos_id_card_margin_end')
    })
  }
}