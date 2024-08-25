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

import router from '@ohos.router';
import {CancelButton} from './component/BaseComponent';
import AppStorageHelper from '../Common/Adapter/AppStorageHelper';
import { AppStorageKeyName, Constants } from '@ohos/common';

const TAG = 'AboutPage';

@Entry
@Component
struct AboutPage {
  @State versionName: string = Constants.STRING_NONE;

  aboutToAppear() {
    this.versionName = AppStorageHelper.getValue<string>(AppStorageKeyName.APP_VERSION);
  }

  build() {
    Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
      Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Column() {
          Image($r('app.media.logo'))
            .width($r('app.float.privacy_statement_print_log_width_height'))
            .height($r('app.float.privacy_statement_print_log_width_height'))
            .margin({top: $r('app.float.about_print_log_width_height')})
          Text($r('app.string.MainAbility_label'))
            .fontSize($r('sys.float.ohos_id_text_size_headline7'))
            .fontColor($r('sys.color.ohos_id_color_text_primary'))
            .fontWeight(FontWeight.Bolder)
            .margin({top: $r('app.float.about_text_relative_img_margin_top')})
          Text(this.versionName)
            .margin({ top: $r('app.float.privacy_statement_text_relative_text_margin_top')})
            .fontColor($r('sys.color.ohos_fa_text_tertiary'))
            .fontWeight(FontWeight.Regular)
        }
        Column() {
          Text($r('app.string.about_privacy_statement_text'))
            .fontColor($r('sys.color.ohos_id_color_text_hyperlink'))
            .onClick(() => {
              router.pushUrl({
                url: 'pages/PrivacyStatementWebPage',
                params: {
                  info: false
                }
              });
            })
            .margin({
              left: $r('app.float.privacy_statement_text_margin_left_right'),
              right: $r('app.float.privacy_statement_text_margin_left_right')
            })
          CancelButton({
            cancelLabel: $r('app.string.Cancel'),
            cancelWidth: $r('app.float.about_button_width'),
            cancelHeight: $r('app.float.privacy_statement_button_height'),
            cancelClick: () => {
              router.back({ url: 'pages/PrintPage' });
            }
          })
          .margin({
            top: $r('app.float.privacy_statement_button_to_text_margin_top')
          })
        }
        .margin({bottom: $r('app.float.privacy_statement_button_margin_bottom')})
      }
    }
    .width('100%')
    .height('100%')
  }
}