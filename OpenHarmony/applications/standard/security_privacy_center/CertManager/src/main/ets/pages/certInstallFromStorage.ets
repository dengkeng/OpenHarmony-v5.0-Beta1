/**
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

import { WidthPercent } from '../common/util/ConfigData';
import HeadComponent from '../common/component/headComponent';
import CmFaPresenter from '../presenter/CmFaPresenter';
import { GlobalContext } from '../common/GlobalContext';
import ComponentConfig from '../common/component/ComponentConfig';
import router from '@ohos.router';
import { CustomContentDialog } from '@ohos.arkui.advanced.Dialog';
import checkUserAuthModel from '../model/CheckUserAuthModel';

const COPIES_NUM: number = 12;

@Entry
@Component
struct CertificateComponent {
  @State columnMargin: string = '12vp';
  @State mFaPresenter: CmFaPresenter = CmFaPresenter.getInstance();
  @State installCertFlag: boolean = false;

  @Styles normalStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
  };
  @Styles pressedStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
  };

  rootCertificateDialog: CustomDialogController = new CustomDialogController({
    alignment: DialogAlignment.Center,
    builder: CustomContentDialog({
      contentBuilder: () => {
        this.rootCertificateContent();
      },
      contentAreaPadding: { right: $r('app.float.wh_value_0') },
      buttons: [
        {
          value: $r('app.string.root_certificate_cancel'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
          }
        },
        {
          value: $r('app.string.root_certificate_continue'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.installCertFlag = true;
            this.checkUserAuth();
          }
        }
      ]
    })
  })

  @Builder
  rootCertificateContent(): void {
    Column() {
      Text($r('app.string.root_certificate'))
        .height($r('app.float.wh_value_56'))
        .fontSize($r('sys.float.ohos_id_text_size_dialog_tittle'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .margin({
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      Text($r('app.string.root_certificate_message'))
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .fontWeight(FontWeight.Regular)
        .fontColor($r('sys.color.ohos_id_color_primary'))
        .margin({
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)
    }
    .width(WidthPercent.WH_100_100)
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
    .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
  }

  checkUserAuth() {
    let titleStr = getContext().resourceManager.getStringSync($r('app.string.Identity_Authentication'));
    checkUserAuthModel.auth(titleStr, (authResult: boolean) => {
      if (authResult) {
        console.log('checkUserAuth success');
        if (this.installCertFlag) {
          this.mFaPresenter.startInstallCert();
        } else {
          this.mFaPresenter.startInstallEvidence();
        }
      }
    })
  }

  build() {
    Column() {
      GridRow({
        columns: COPIES_NUM,
        gutter: vp2px(1) === 2 ? $r('app.float.wh_value_12') : $r('app.float.wh_value_0')
      }) {
        GridCol({ span: COPIES_NUM }) {
          Row({}) {
            Column({ space: this.columnMargin }) {
              HeadComponent({ headName: $r('app.string.installInStorageDevice') })
              Column({ space: this.columnMargin }) {
                Column() {
                  Row() {
                    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                      Text($r('app.string.CA_cert'))
                        .fontSize($r('sys.float.ohos_id_text_size_body1'))
                        .fontColor($r('sys.color.ohos_id_color_text_primary'))
                        .fontWeight(FontWeight.Medium)
                        .margin({ left: $r('app.float.wh_value_12') })
                        .textAlign(TextAlign.Start)
                    }
                  }
                  .stateStyles({
                    normal: this.normalStyle,
                    pressed: this.pressedStyle
                  })
                  .margin({ top: $r('app.float.wh_value_4') })
                  .height($r('app.float.wh_value_48'))
                  .onClick(() => {
                    this.rootCertificateDialog.open();
                  })

                  Divider()
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .margin({
                      left: $r('app.float.wh_value_12'),
                      right: $r('app.float.wh_value_12')
                    })

                  Row() {
                    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                      Text($r('app.string.system_credentials'))
                        .fontSize($r('sys.float.ohos_id_text_size_body1'))
                        .fontColor($r('sys.color.ohos_id_color_text_primary'))
                        .fontWeight(FontWeight.Medium)
                        .margin({ left: $r('app.float.wh_value_12') })
                        .textAlign(TextAlign.Start)
                    }
                    .onClick(() => {
                      this.installCertFlag = false;
                      AppStorage.setOrCreate('installSystemCred', true);
                      AppStorage.setOrCreate('installUserCred',false);
                      this.mFaPresenter.startInstallEvidence();
                    })
                  }
                  .stateStyles({
                    normal: this.normalStyle,
                    pressed: this.pressedStyle
                  })
                  .height($r('app.float.wh_value_48'))


                  Divider()
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .margin({
                      left: $r('app.float.wh_value_12'),
                      right: $r('app.float.wh_value_12')
                    })

                  Row() {
                    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                      Text($r('app.string.user_certificate_credentials'))
                        .fontSize($r('sys.float.ohos_id_text_size_body1'))
                        .fontColor($r('sys.color.ohos_id_color_text_primary'))
                        .fontWeight(FontWeight.Medium)
                        .margin({ left: $r('app.float.wh_value_12') })
                        .textAlign(TextAlign.Start)
                    }
                    .onClick(() => {
                      this.installCertFlag = false;
                      AppStorage.setOrCreate('installUserCred', true);
                      AppStorage.setOrCreate('installSystemCred',false);
                      this.mFaPresenter.startInstallEvidence();
                    })
                  }
                  .stateStyles({
                    normal: this.normalStyle,
                    pressed: this.pressedStyle
                  })
                  .height($r('app.float.wh_value_48'))
                }
                .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
                .borderRadius($r('app.float.radius_20'))
                .height(ComponentConfig.WH_100_100)
                .width(ComponentConfig.WH_100_100)
                .height($r('app.float.wh_value_152'))
              }
              .width(WidthPercent.WH_100_100)
            }
            .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
            .padding({ left: $r('app.float.wh_value_16'), right: $r('app.float.wh_value_16') })
            .width(WidthPercent.WH_100_100)
            .height(WidthPercent.WH_100_100)

          }
          .width(WidthPercent.WH_100_100)
          .height(WidthPercent.WH_100_100);
        }
      }
      .margin(vp2px(1) === 2 ? $r('app.float.item_common_horizontal_margin') : $r('app.float.wh_value_0'))
      .width(WidthPercent.WH_100_100)
      .height(WidthPercent.WH_100_100);
    }
    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
    .width(WidthPercent.WH_100_100)
    .height(WidthPercent.WH_100_100);
  }

  onPageShow() {
    let uiExtensionFlag = GlobalContext.getContext().getFlag();
    let installType: string = GlobalContext.getContext().getAbilityWant().parameters?.installType as string;
    let uri = GlobalContext.getContext().getAbilityWant().uri ||
      GlobalContext.getContext().getAbilityWant().parameters?.uri;
    GlobalContext.getContext().clearAbilityWantUri();
    GlobalContext.getContext().clearAbilityWantParamsUri();
    if (uri === 'certInstall') {
      router.pushUrl({
        url: 'pages/certInstallFromStorage'
      })
    } else if (uri === 'requestAuthorize') {
      this.mFaPresenter.startRequestAuth(GlobalContext.getContext().getAbilityWant().parameters?.appUid as string);
    } else if (uiExtensionFlag && uri === 'systemCredInstall' && installType === 'systemCred') {
      AppStorage.setOrCreate('installSystemCred', true);
      AppStorage.setOrCreate('installUserCred', false);
      this.mFaPresenter.startInstallEvidence();
    } else if (uiExtensionFlag && uri === 'specifyInstall') {
      let fileUri = GlobalContext.getContext().getAbilityWant().parameters?.fileUri as string;
      this.mFaPresenter.startInstall(installType, fileUri);
    } else {
      console.info('The want type is not supported');
    }
  }
}