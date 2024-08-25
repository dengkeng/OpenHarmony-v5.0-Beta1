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

import HeadComponent from '../common/component/headComponent';
import { WidthPercent, ConfigValue } from '../common/util/ConfigData';
import router from '@ohos.router';
import CmInstallPresenter from '../presenter/CmInstallPresenter';
import CmFaPresenter from '../presenter/CmFaPresenter';
import { GlobalContext } from '../common/GlobalContext';
import { RouterFileVo, RouterParams } from '../model/CertManagerVo/RouterInfoVo';
import { CMModelErrorCode } from '../model/CertMangerModel';

@Entry
@Component
struct CertInstallAliasInput {
  @State mAppCredAuthPresenter: CmInstallPresenter = CmInstallPresenter.getInstance();
  @State mFaPresenter: CmFaPresenter = CmFaPresenter.getInstance();
  @State certAlias: string = '';
  @State isCertLong: boolean = false;

  onPageShow() {
    let uri = GlobalContext.getContext().getAbilityWant().uri;
    GlobalContext.getContext().clearAbilityWantUri();

    if (uri === 'certInstall') {
      router.pushUrl({
        url: 'pages/certInstallFromStorage'
      })
    } else if (uri === 'requestAuthorize') {
      this.mFaPresenter.startRequestAuth(GlobalContext.getContext().getAbilityWant().parameters?.appUid as string);
    } else {
      console.info('The want type is not supported');
    }
  }

  build() {
    Column() {
      Column() {
        HeadComponent({ headName: $r('app.string.certificateAliasTab') });
        Text($r('app.string.certificateAliasInfo'))
          .fontColor($r('sys.color.ohos_id_color_text_primary'))
          .fontSize($r('sys.float.ohos_id_text_size_body1'))
          .fontWeight(FontWeight.Medium)
          .margin({
            top: $r('app.float.distance_24'),
            left: $r('app.float.distance_24')
          })
          .alignSelf(ItemAlign.Start)

        TextInput({ text: this.certAlias })
          .type(InputType.Normal)
          .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
          .enterKeyType(EnterKeyType.Done)
          .fontSize($r('sys.float.ohos_id_text_size_body1'))
          .fontWeight(FontWeight.Medium)
          .defaultFocus(true)
          .fontColor($r('sys.color.ohos_id_color_text_hint'))
          .onChange((value: string) => {
            this.certAlias = value;
            if (value.length === 0) {
              this.isCertLong = false;
            }
          })
          .maxLength(ConfigValue.ALIAS_MAX_LENGTH)
          .margin({
            left: $r('app.float.distance_24'),
            right: $r('app.float.distance_24')
          })
          .height($r('app.float.distance_48'))

        Row() {
          Divider().color($r('sys.color.ohos_id_color_list_separator'))
        }
        .margin({
          left: $r('app.float.distance_24'),
          right: $r('app.float.distance_24'),
        })

        Text(this.isCertLong ? $r('app.string.inputAliasWarn') : $r('app.string.installAliasInputInfo'))
          .fontColor(this.isCertLong ? $r('sys.color.ohos_id_color_warning')
            : $r('sys.color.ohos_id_color_text_primary'))
          .fontWeight(FontWeight.Regular)
          .fontSize($r('sys.float.ohos_id_text_size_body2'))
          .margin({
            left: $r('app.float.distance_24'),
            top: $r('app.float.distance_16')
          })
          .alignSelf(ItemAlign.Start)
          .opacity($r('app.float.opacity_100_60'))
      }
      .width(WidthPercent.WH_100_100)
      .height(WidthPercent.WH_75_100);

      Column() {
        Row() {
          Button() {
            Text($r('app.string.installAliasInputCancel'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontWeight(FontWeight.Medium)
              .fontColor($r('sys.color.ohos_id_color_text_hyperlink'))
          }
          .type(ButtonType.Capsule)
          .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
          .width($r('app.float.component_button_width_phone'))
          .height($r('app.float.application_button_height'))
          .margin({
            left: $r('app.float.distance_24'),
          })
          .onClick(() => {
            router.back();
          })

          if ((this.certAlias.length > 0) && (this.certAlias[0] != ' ')) {
            Button() {
              Text($r('app.string.installAliasInputConfirm'))
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontWeight(FontWeight.Medium)
                .fontColor($r('app.color.install_confirm_bt_font_color'))
            }
            .type(ButtonType.Capsule)
            .backgroundColor($r('app.color.install_confirm_bt_bg_color'))
            .width($r('app.float.component_button_width_phone'))
            .height($r('app.float.application_button_height'))
            .margin({
              left: $r('app.float.distance_16'),
              right: $r('app.float.distance_24'),
            })
            .onClick(() => {
              let routerParams: RouterParams = router.getParams() as RouterParams;
              let fileInfo: RouterFileVo = routerParams?.fileInfo as RouterFileVo;
              let pwd: string = routerParams.pwd || '';
              this.mAppCredAuthPresenter.checkCertNameLength(fileInfo.uri, this.certAlias, fileInfo.suffix, pwd)
                .then((result: number) => {
                  if (result !== CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
                    console.info('CertNameLength reached limit!');
                    this.isCertLong = true;
                  } else {
                    console.info('CertNameLength is within the limit!');
                    this.isCertLong = false;
                    this.mAppCredAuthPresenter.installCert(fileInfo.uri, this.certAlias, fileInfo.suffix);
                  }
                })
            })
          } else {
            Button() {
              Text($r('app.string.installAliasInputConfirm'))
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontWeight(FontWeight.Medium)
                .fontColor($r('app.color.install_confirm_bt_font_color'))
            }
            .type(ButtonType.Capsule)
            .backgroundColor($r('app.color.install_confirm_bt_bg_color'))
            .width($r('app.float.component_button_width_phone'))
            .height($r('app.float.application_button_height'))
            .margin({
              left: $r('app.float.distance_16'),
              right: $r('app.float.distance_24'),
            })
          }
        }
        .margin({ bottom: $r('app.float.wh_value_24') })
      }
      .justifyContent(FlexAlign.End)
      .height(WidthPercent.WH_25_100);
    }
    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
    .width(WidthPercent.WH_100_100)
    .height(WidthPercent.WH_100_100);
  }
}
