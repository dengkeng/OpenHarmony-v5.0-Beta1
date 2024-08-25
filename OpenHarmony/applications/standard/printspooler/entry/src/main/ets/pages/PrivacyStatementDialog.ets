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

import {CancelButton} from './component/BaseComponent';

const TAG = 'PrivacyStatementDialog';

@CustomDialog
export struct PrivacyStatementDialog {
  controller: CustomDialogController;
  build() {
    Column() {
      Text($r('app.string.print_permissions_notice'))
        .fontSize($r('sys.float.ohos_id_text_size_headline8'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .margin({
          top: $r('app.float.privacy_statement_text_tertiary_height')
        })
      Text($r('app.string.permissions_notice_content'))
        .margin({
          top: $r('app.float.privacy_statement_text_relative_img_margin_top')
        })
        .fontSize($r('sys.float.ohos_id_text_size_sub_title3'))
        .fontWeight(FontWeight.Regular)
      Column() {
        Text($r('app.string.location_information'))
          .fontSize($r('sys.float.ohos_id_text_size_sub_title2'))
          .fontColor($r('sys.color.ohos_id_color_text_primary'))
          .fontWeight(FontWeight.Medium)
        Text($r('app.string.permission_location_content'))
          .fontColor($r('sys.color.ohos_id_color_text_secondary'))
          .fontSize($r('sys.float.ohos_id_text_size_sub_title3'))
          .margin({top: $r('app.float.privacy_statement_text_relative_img_margin_top')})
          .fontWeight(FontWeight.Regular)
      }
      .margin({
        top: $r('app.float.privacy_statement_dialog_item_margin_top')
      })
      .alignItems(HorizontalAlign.Start)
      CancelButton({
        cancelLabel: $r('app.string.JobManagerPage_ok'),
        cancelWidth: $r('app.float.dialog_button_width'),
        cancelHeight: $r('app.float.dialog_button_height'),
        cancelClick: () => {
          this.controller.close();
        }
      })
      .alignSelf(ItemAlign.Center)
      .margin({
        top: $r('app.float.privacy_statement_button_to_text_margin_top'),
        bottom: $r('app.float.privacy_statement_text_tertiary_height')
      })
    }
    .alignItems(HorizontalAlign.Start)
    .width($r('app.float.dialog_width'))
    .backgroundColor(Color.White)
    .borderRadius($r('app.float.radius_l'))
    .padding({
      left: $r('app.float.connect_dialog_text_margin_left'),
      right: $r('app.float.connect_dialog_text_margin_right')
    })
  }
}