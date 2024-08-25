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

import { WidthPercent } from '../common/util/ConfigData';
import HeadComponent from '../common/component/headComponent';
import { SubEntryComponent } from '../common/component/subEntryComponent';
import CmFaPresenter from '../presenter/CmFaPresenter';
import { GlobalContext } from '../common/GlobalContext';
import router from '@ohos.router';
import promptAction from '@ohos.promptAction';
import { CustomContentDialog } from '@ohos.arkui.advanced.Dialog';

const DISPLAY_DURATION: number = 2000;
const COPIES_NUM: number = 12;

class CertListItem {
  public targetPage: string = '';
  public title: Resource = $r('app.string.CA_cert');
};

@Entry
@Component
struct CertificateComponent {
  @State columnMargin: string = '12vp';
  @State mFaPresenter: CmFaPresenter = CmFaPresenter.getInstance();
  private listItems: Array<CertListItem> = [
    { targetPage: 'pages/trustedCa', title: $r('app.string.CA_cert') },
    { targetPage: 'pages/cerEvidenceFa', title: $r('app.string.userEvidence') }
  ];
  @Styles normalStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
  };
  @Styles pressedStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
  };

  build() {
    Column() {
      GridRow({
        columns: COPIES_NUM,
        gutter: vp2px(1) === 2 ? $r('app.float.wh_value_12') : $r('app.float.wh_value_0')
      }) {
        GridCol({ span: COPIES_NUM }) {
          Column({ space: this.columnMargin }) {
            HeadComponent({ headName: $r('app.string.certificateTab') })
            Column({ space: this.columnMargin }) {
              List() {
                ForEach(this.listItems, (item: CertListItem) => {
                  ListItem() {
                    SubEntryComponent({ targetPage: item.targetPage, title: item.title })
                  }
                  .stateStyles({
                    normal: this.normalStyle,
                    pressed: this.pressedStyle
                  });
                }, (item: CertListItem) => JSON.stringify(item))
              }
              .padding($r('app.float.wh_value_4'))
              .divider({
                strokeWidth: $r('app.float.sys_list_divider_strokeWidth_value'),
                color: $r('sys.color.ohos_id_color_list_separator'),
                startMargin: $r('app.float.wh_value_8'),
                endMargin: $r('app.float.wh_value_8')
              })
              .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
              .backgroundColor($r('sys.color.ohos_id_color_list_card_bg'))

              CertInstallComponent({ mFaPresenter: $mFaPresenter })

              DeleteAll({ mFaPresenter: $mFaPresenter })
            }
            .width(WidthPercent.WH_100_100)
          }
          .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
          .padding({ left: $r('app.float.wh_value_12'), right: $r('app.float.wh_value_12') })
          .width(WidthPercent.WH_100_100)
          .height(WidthPercent.WH_100_100)
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
}

@Component
struct DeleteAll {
  @Link mFaPresenter: CmFaPresenter;
  @Styles normalStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
  };
  @Styles pressedStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
  };

  deleteWarnDialog: CustomDialogController = new CustomDialogController({
    builder: CustomContentDialog({
      contentBuilder: () => {
        this.deleteWarnContent();
      },
      contentAreaPadding: {right: $r('app.float.wh_value_0')},
      buttons: [
        {
          value: $r('app.string.deleteAllCredCancel'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.deleteWarnDialog?.close();
          }
        },
        {
          value: $r('app.string.deleteAllCredDelete'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.mFaPresenter.uninstallAllCert();
            this.deleteWarnDialog?.close();
            promptAction.showToast({
              message: $r('app.string.delete_success'),
              duration: DISPLAY_DURATION,
            })
          },
          role: ButtonRole.ERROR
        }
      ]
    }),
  })

  @Builder
  deleteWarnContent(): void {
    Column() {
      Text($r('app.string.deleteAllCredDialogTitle'))
        .height($r('app.float.wh_value_56'))
        .fontSize($r('sys.float.ohos_id_text_size_dialog_tittle'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .margin({
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      Text($r('app.string.deleteAllCredDialogMessage'))
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .fontWeight(FontWeight.Regular)
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .margin({
          top: $r('app.float.wh_value_16'),
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)
    }
    .width(WidthPercent.WH_100_100)
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
  }

  build() {
    Row() {
      Text($r('app.string.deleteAllCred'))
        .fontSize($r('app.float.font_16'))
        .lineHeight($r('app.float.wh_value_22'))
        .fontWeight(FontWeight.Medium)
        .fontColor($r('sys.color.ohos_id_color_text_hyperlink'))
        .padding({ left: $r('app.float.distance_8') })
        .stateStyles({
          normal: this.normalStyle,
          pressed: this.pressedStyle
        })
        .height(WidthPercent.WH_100_100)
        .borderRadius($r('app.float.radius_20'))
        .width(WidthPercent.WH_100_100)
        .textAlign(TextAlign.Start);
    }
    .padding($r('app.float.distance_4'))
    .height($r('app.float.wh_value_56'))
    .width(WidthPercent.WH_100_100)
    .borderRadius($r('app.float.radius_24'))
    .backgroundColor($r('sys.color.ohos_id_color_foreground_contrary'))
    .onClick(() => {
      this.deleteWarnDialog.open();
    })
  }
}

@Component
export struct CertInstallComponent {
  @Link mFaPresenter: CmFaPresenter;
  @Styles normalStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
  };
  @Styles pressedStyle() {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
  };

  build() {
    Column() {
      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Row() {
          Text($r('app.string.installInStorageDevice'))
            .fontSize($r('app.float.font_16'))
            .lineHeight($r('app.float.wh_value_22'))
            .fontColor($r('sys.color.ohos_id_color_text_primary'))
            .fontWeight(FontWeight.Medium)
            .margin({ left: $r('app.float.wh_value_8') });
        }

        Image($r('app.media.ic_settings_arrow'))
          .width($r('app.float.wh_value_12'))
          .height($r('app.float.wh_value_24'))
          .fillColor($r('sys.color.ohos_id_color_primary'))
          .opacity($r('app.float.opacity_0_2'))
          .margin({ right: $r('app.float.wh_value_8') });
      }
      .borderRadius($r('app.float.radius_20'))
      .height(WidthPercent.WH_100_100)
      .width(WidthPercent.WH_100_100)
      .stateStyles({
        normal: this.normalStyle,
        pressed: this.pressedStyle
      })
    }
    .backgroundColor($r('sys.color.ohos_id_color_foreground_contrary'))
    .padding($r('app.float.distance_4'))
    .height($r('app.float.wh_value_56'))
    .borderRadius($r('app.float.radius_24'))
    .onClick(() => {
      router.pushUrl({
        url: 'pages/certInstallFromStorage'
      }, router.RouterMode.Standard)
    });
  }
}
