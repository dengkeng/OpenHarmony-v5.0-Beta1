/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

@Styles
function pressStyles() {
  .backgroundColor($r('app.color.button_pressStyles'))
}

@Styles
function normalStyles() {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.transparent_color'))
}

@Component
export struct DialogTitle {
  title: Resource;

  build() {
    Text(this.title)
      .fontSize($r('app.float.common_font_size20'))
      .fontColor($r('app.color.dialog_title_font_color'))
      .fontWeight(FontWeight.Medium)
      .width('100%')
      .padding({
        top: $r('app.float.common_padding14'),
        bottom: $r('app.float.common_padding14')
      })
  }
}

@Component
export struct DialogButton {
  text: Resource;
  color: Resource = $r('app.color.dialog_button_blue');
  bgColor: Resource = $r('app.color.transparent_color');
  @Prop isDisabled: boolean;
  click: Function;

  build() {
    Row() {
      Row() {
        Text(this.text)
          .fontSize($r('app.float.common_font_size16'))
          .fontColor(this.color)
          .fontWeight(FontWeight.Medium)
      }.height('100%')
      .width('100%')
      .justifyContent(FlexAlign.Center)
      .onClick(() => {
        if (!this.click || this.isDisabled) {
          return
        }
        this.click()
      })
    }
    .height($r('app.float.common_line_height36'))
    .layoutWeight(1)
    .backgroundColor(this.bgColor)
    .stateStyles({
      pressed: pressStyles,
      normal: normalStyles
    })
    .opacity(this.isDisabled ? $r('app.float.common_opacity5') : $r('app.float.common_opacity10'))
    .borderRadius($r('app.float.common_borderRadius18'))
  }
}

@Component
export struct DialogButtonDivider {
  build() {
    Divider().vertical(true)
      .margin({ left: $r('app.float.common_margin10'), right: $r('app.float.common_margin10') })
      .height($r('app.float.divider_height24'))
      .color($r('app.color.dialog_button_divider_color'))
  }
}
