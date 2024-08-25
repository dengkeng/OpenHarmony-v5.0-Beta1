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

import context from '@ohos.app.ability.common';
import { renderSize } from '../../../base/utils/Tools';
import AbilityCommonUtil from '../../../base//utils/AbilityCommonUtil';

@Styles
function pressedStyles() {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.hicloud_hmos_bg'))
}

@Styles
function normalStyles () {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.transparent_color'))
}

@Extend(Text)
function subtitleStyles(fontSize: Resource) {
  .fontSize(fontSize)
  .alignSelf(ItemAlign.Start)
}

const filePickerViewFlag = globalThis.filePickerViewFlag;

@Component
export struct TopBar {
  private title?: string = '';
  private subtitle?: string = '';
  private fileSize?: number = 0;
  @Prop selectAll: boolean;
  @Prop isMulti: boolean;
  @Link checkedNum: number;
  @Link checkedList: any[];
  @State active: boolean = false;
  @State rActive: boolean = false;
  public backCallback: () => void; // 点击返回键的事件回调
  public menuCallback: () => void; // 点击全选的事件回调
  filterCallBack: Function;

  aboutToAppear() {

  }

  initTitle(): string | Resource {
    if (this.isMulti && !filePickerViewFlag) {
      return this.checkedNum === 0 ? $r('app.string.selected_none') : this.checkedNum === 1 ?
      $r('app.string.selected_items_singular', this.checkedNum) : $r('app.string.selected_items_plural', this.checkedNum);
    } else {
      return this.title;
    }
  }

  filePickerTitle() {
    if (this.isMulti) {
      return this.checkedNum === 0 ? $r('app.string.selected_none') : $r('app.string.selected', this.checkedNum, globalThis.filePickNum);
    } else {
      return this.title;
    }
  }

  checkSelectedFileList(): boolean {
    if (!this.checkedNum) {
      return false;
    }
    if (this.checkedList.some(item => item.isFolder)) {
      return false;
    }
    return true;
  }

  terminate(): void {
    if (!this.checkSelectedFileList()) {
      return;
    }
    const uriList = this.checkedList.map(item => item.uri);
    const fileNameList = this.checkedList.map(item => item.fileName);
    AbilityCommonUtil.terminateFilePicker(uriList, fileNameList);
  }

  build() {
    Flex({ alignItems: ItemAlign.Center, justifyContent: FlexAlign.Start }) {
      Column() {
        Image(this.isMulti ? $r('app.media.hidisk_cancel_normal') : $r('app.media.hidisk_ic_return'))
          .objectFit(ImageFit.Contain)
          .width($r('app.float.common_size24'))
          .height($r('app.float.common_size24'))
          .interpolation(ImageInterpolation.Medium)
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
        this.backCallback.call(this);
      })

      Column() {
        Text(filePickerViewFlag ? this.filePickerTitle() : this.initTitle())
          .fontColor($r('app.color.black'))
          .fontSize($r('app.float.common_font_size20'))
          .fontWeight(FontWeight.Medium)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        if (this.fileSize && this.isMulti) {
          Text($r('app.string.choose_size', renderSize(this.fileSize)))
            .fontColor($r('app.color.black'))
            .subtitleStyles($r('app.float.common_font_size14'))
        }
        if (this.subtitle !== '' && !this.isMulti) {
          Text(this.subtitle)
            .fontColor($r('app.color.black'))
            .subtitleStyles($r('app.float.common_font_size14'))
        }
      }
      .padding({ left: $r('app.float.common_margin6') })
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)

      if (filePickerViewFlag) {
        if (!this.isMulti) {
          Column() {
            Image($r('app.media.hidisk_cancel_normal'))
              .objectFit(ImageFit.Contain)
              .width($r('app.float.common_size24'))
              .height($r('app.float.common_size24'))
              .interpolation(ImageInterpolation.Medium)
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
            let abilityContext = getContext(this) as context.UIAbilityContext;
            abilityContext.terminateSelf();
          })
        } else {
          Column() {
            Image($r('app.media.ic_ok'))
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
            this.terminate();
          })
          .opacity(this.checkSelectedFileList() ? $r('app.float.common_opacity10') : $r('app.float.common_opacity4'))
        }
      }
    }
    .height($r('app.float.common_mark_y50'))
    .padding({
      left: $r('app.float.common_padding12'),
      right: $r('app.float.common_padding4')
    })
    .backgroundColor($r('app.color.white'))
  }
}