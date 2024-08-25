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
import CheckEmptyUtils, { Log } from '@ohos/common';
import common from '@ohos.app.ability.common';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';
import { PreferencesKey} from '@ohos/common';
import PreferencesAdapter from '../Common/Adapter/PreferencesAdapter';
import {PrivacyStatementDialog} from './PrivacyStatementDialog';
import {CancelButton} from './component/BaseComponent';

const TAG = 'PrivacyStatementPage';

let storage = LocalStorage.getShared();
@Entry(storage)
@Component
struct PrivacyStatementPage {
  private readonly PRIVACY_STATEMENT_STORE: string = 'privacyStatementStore';
  private abilityContext: common.UIAbilityContext | undefined = undefined
  private dialogController: CustomDialogController = new CustomDialogController({
    builder: PrivacyStatementDialog(),
    autoCancel: false,
    customStyle: true,
  })

  aboutToAppear() {
    this.abilityContext = GlobalThisHelper.getValue<common.UIAbilityContext>(
      GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT)
  }

  build() {
    Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
      Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Column() {
          Image($r('app.media.logo'))
            .width($r('app.float.privacy_statement_print_log_width_height'))
            .height($r('app.float.privacy_statement_print_log_width_height'))
            .margin({top: $r('app.float.print_log_margin_top')})
          Text($r('app.string.welcome'))
            .margin({ top: $r('app.float.privacy_statement_text_relative_img_margin_top')})
            .fontColor($r('sys.color.ohos_id_color_text_tertiary'))
            .fontSize($r('sys.float.ohos_id_text_size_over_line'))
            .fontWeight(FontWeight.Regular)
            .height($r('app.float.privacy_statement_text_tertiary_height'))
          Text($r('app.string.MainAbility_label'))
            .fontSize($r('sys.float.ohos_id_text_size_headline7'))
            .fontColor($r('sys.color.ohos_id_color_text_primary'))
            .fontWeight(FontWeight.Bolder)
            .height($r('app.float.privacy_statement_text_headline_height'))
            .margin({top: $r('app.float.privacy_statement_text_relative_text_margin_top')})
          Text($r('app.string.print_slogan'))
            .fontColor($r('sys.color.ohos_id_color_text_tertiary'))
            .fontSize($r('sys.float.ohos_id_text_size_over_line'))
            .fontWeight(FontWeight.Regular)
            .margin({top: $r('app.float.privacy_statement_text_relative_text_margin_top')})
            .height($r('app.float.privacy_statement_text_tertiary_height'))
        }

        Column() {
          Image($r('app.media.ic_public_shield'))
            .width($r('app.float.shield_width_height'))
            .height($r('app.float.shield_width_height'))
          Text() {
            ForEach(this.getPrivacyStatementText(), (privacyStatementText: string) => {
              if (privacyStatementText === this.abilityContext?.resourceManager.getStringByNameSync('location_information') ||
                privacyStatementText === this.abilityContext?.resourceManager.getStringByNameSync('print_permission_network')) {
                Span(privacyStatementText).fontWeight(FontWeight.Bolder)
              } else {
                Span(privacyStatementText)
              }
            })
            Span($r('app.string.about_privacy_statement_text'))
              .onClick(() => {
                router.replaceUrl({
                  url: 'pages/PrivacyStatementWebPage',
                  params: {
                    info: true
                  }
                });
              })
              .fontColor($r('sys.color.ohos_id_color_text_hyperlink'))
              .fontSize($r('sys.float.ohos_id_text_size_body3'))
            Span('、')
            Span($r('app.string.permissions_notice'))
              .fontColor($r('sys.color.ohos_id_color_text_hyperlink'))
              .fontSize($r('sys.float.ohos_id_text_size_body3'))
              .onClick(() => {
                this.dialogController.open();
              })
            Span('。')
          }
          .fontColor($r('sys.color.ohos_id_color_text_primary'))
          .fontSize($r('sys.float.ohos_id_text_size_body3'))
          .margin({
            top: $r('app.float.privacy_statement_text_relative_img_margin_top'),
            left: $r('app.float.privacy_statement_text_margin_left_right'),
            right: $r('app.float.privacy_statement_text_margin_left_right')
          })
          Row() {
            CancelButton({
              cancelLabel: $r('app.string.Cancel'),
              cancelWidth: $r('app.float.privacy_statement_button_width'),
              cancelHeight: $r('app.float.privacy_statement_button_height'),
              cancelClick: () => {
                this.abilityContext?.terminateSelf();
              }
            })
              .margin({right: $r('app.float.privacy_statement_button_space')})
            Button($r('app.string.Agree'))
              .onClick(() => {
                this.agreePrivacyStatement();
                router.replaceUrl({url: 'pages/PrintPage', params: storage});
              })
              .width($r('app.float.privacy_statement_button_width'))
              .height($r('app.float.privacy_statement_button_height'))
          }
          .margin({
            top: $r('app.float.privacy_statement_button_to_text_margin_top'),
            bottom: $r('app.float.privacy_statement_button_margin_bottom'),
          })
        }
      }
    }
    .width('100%')
    .height('100%')
  }

  async agreePrivacyStatement() {
    Log.info(TAG, 'agreePrivacyStatement');
    PreferencesAdapter.getInstance().getOrCreatePreferencesSync(this.PRIVACY_STATEMENT_STORE).then((successGet) => {
      Log.info(TAG, 'agreePrivacyStatement getOrCreatePreferencesSync successGet: ' + successGet);
      if (successGet) {
        PreferencesAdapter.getInstance().putValue(PreferencesKey.KEY_PRIVACY_STATEMENT_PREFERENCES, true)
          .then((successPut) => {
            Log.info(TAG, 'agreePrivacyStatement putValue successPut: ' + successPut);
            if (successPut) {
              PreferencesAdapter.getInstance().flush();
            }
          })
      }
    });
  }

  private getPrivacyStatementText() : Array<string> {
    let privacyStatementTextList: string[] = [];
    if (CheckEmptyUtils.isEmpty(this.abilityContext)) {
      Log.warn(TAG, 'getPrivacyStatementText abilityContext is invalid.');
      return privacyStatementTextList;
    }
    let privacyStatementText = this.abilityContext!.resourceManager.getStringByNameSync('privacy_statement_text');
    let printPermissionNetwork = this.abilityContext!.resourceManager.getStringByNameSync('print_permission_network');
    let locationInformation = this.abilityContext!.resourceManager.getStringByNameSync('location_information');

    let privacyStatementTexts = privacyStatementText.split(printPermissionNetwork);
    privacyStatementTextList.push(privacyStatementTexts[0]);
    privacyStatementTextList.push(printPermissionNetwork);
    privacyStatementTexts = privacyStatementTexts[1].split(locationInformation);
    privacyStatementTextList.push(privacyStatementTexts[0]);
    privacyStatementTextList.push(locationInformation);
    privacyStatementTextList.push(privacyStatementTexts[1]);
    return privacyStatementTextList;
  }
}