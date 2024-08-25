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
function pressedStyles() {
  .borderRadius($r('app.float.common_borderRadius10'))
  .backgroundColor($r('app.color.hicloud_hmos_bg'))
}

@Styles
function normalStyles() {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.transparent_color'))
}

@Component
export struct TopOperateBar {
  public addFolder: () => void; // 点击新建的事件回调
  // 是否可用
  @Prop isDisabled: boolean = false;
  // 列表或宫格
  @Consume isList: boolean;

  getUsageHabitsKey(prefix: string, suffix: string): string {
    return prefix + suffix.charAt(0).toLocaleUpperCase() + suffix.substring(1);
  }

  build() {
    Row() {
      Column() {
        Image($r('app.media.hidisk_ic_add_folder'))
          .objectFit(ImageFit.Contain)
          .width($r('app.float.common_size24'))
          .height($r('app.float.common_size24'))
      }.padding({
        left: $r('app.float.common_padding12'),
        right: $r('app.float.common_padding12'),
        top: $r('app.float.common_padding10'),
        bottom: $r('app.float.common_padding10')
      })
      .stateStyles({
        pressed: pressedStyles,
        normal: normalStyles
      })
      .onClick(() => {
        if (this.isDisabled) {
          return;
        }
        this.addFolder.call(this);
      })

      Column() {
        if (this.isList) {
          Image($r('app.media.hidisk_switch_grid'))
            .width($r('app.float.common_size24'))
            .height($r('app.float.common_size24'))
        } else {
          Image($r('app.media.hidisk_switch_list'))
            .width($r('app.float.common_size24'))
            .height($r('app.float.common_size24'))
        }
      }.padding({
        top: $r('app.float.common_padding10'),
        bottom: $r('app.float.common_padding10'),
        left: $r('app.float.common_padding12'),
        right: $r('app.float.common_padding12')
      })
      .onClick(() => {
        if (this.isDisabled) {
          return;
        }
        this.isList = !this.isList;
      }).stateStyles({
        pressed: pressedStyles,
        normal: normalStyles
      })
    }
    .width('100%')
    .padding({
      left: $r('app.float.common_padding4'),
      right: $r('app.float.common_padding4'),
      top: $r('app.float.common_padding10'),
      bottom: $r('app.float.common_padding10')
    })
    .justifyContent(FlexAlign.SpaceBetween)
    .alignItems(VerticalAlign.Center)
    .opacity(this.isDisabled ? $r('app.float.common_opacity4') : $r('app.float.common_opacity10'))
  }
}