/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
export struct CancelButton {
  cancelLabel?: ResourceStr;
  cancelWidth?: Length;
  cancelHeight?: Length;
  cancelClick?: (event?: ClickEvent) => void;
  build() {
    Button(this.cancelLabel)
      .width(this.cancelWidth)
      .height(this.cancelHeight)
      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
      .backgroundColor($r('sys.color.ohos_id_color_button_normal'))
      .onClick(this.cancelClick);
  }
}

@Component
export struct ClickableImage {
  imageSrc?: ResourceStr;
  imageWidth?: Length;
  imageHeight?: Length;
  clickEvent?: (event?: ClickEvent) => void;
  isHoverEnable: boolean = false;
  isHover: boolean = false;
  @State bckColor: Resource | undefined = undefined;
  build() {
    Image(this.imageSrc)
      .width(this.imageWidth)
      .height(this.imageHeight)
      .backgroundColor(this.bckColor)
      .borderRadius($r('sys.float.ohos_id_corner_radius_clicked'))
      .onClick(this.clickEvent)
      .onHover((isHover) => {
        if (this.isHoverEnable && this.isHover != isHover) {
          if (isHover) {
            this.bckColor = $r('sys.color.ohos_id_color_hover')
          } else {
            this.bckColor = $r('sys.color.ohos_id_color_background');
          }
        }
        this.isHover = isHover;
      })
      .onTouch((event) => {
        if (event.type === TouchType.Down) {
          this.isHover = false;
          this.bckColor = $r('sys.color.ohos_fa_click_effect')
        } else if (event.type === TouchType.Up) {
          this.bckColor = $r('sys.color.ohos_id_color_background');
        }
      })
  }
}


