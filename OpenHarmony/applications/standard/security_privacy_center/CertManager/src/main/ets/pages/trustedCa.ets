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
import CmShowSysCaPresenter from '../presenter/CmShowSysCaPresenter';
import CMShowUserCaPresenter from '../presenter/CmShowUserCaPresenter';
import CmFaPresenter from '../presenter/CmFaPresenter';
import { GlobalContext } from '../common/GlobalContext';
import { CertAbstractVo } from '../model/CertManagerVo/CertAbstractVo';
import ComponentConfig from '../common/component/ComponentConfig';
import router from '@ohos.router';
import { CustomContentDialog } from '@ohos.arkui.advanced.Dialog';

const COPIES_NUM: number = 12;

@Component
struct DialogSubjectComponent {
  private map?: Map<string, string>;
  private subjectNameCN: string = '';
  private subjectNameO: string = '';
  private subjectNameOU: string = '';
  private serial: string = '';

  aboutToAppear() {
    if (this.map != null) {
      let subjectNameCN = this.map.get('常用名称:');
      if (subjectNameCN !== undefined) {
        this.subjectNameCN = subjectNameCN;
      }

      let subjectNameO = this.map.get('组织:');
      if (subjectNameO !== undefined) {
        this.subjectNameO = subjectNameO;
      }

      let subjectNameOU = this.map.get('组织单位:');
      if (subjectNameOU !== undefined) {
        this.subjectNameOU = subjectNameOU;
      }

      let serial = this.map.get('序列号:');
      if (serial !== undefined) {
        this.serial = serial;
      }
    }
  }

  build() {
    Column() {
      Text($r('app.string.DialogSubjectComponent_firText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_l')
        })
      Text(this.subjectNameCN)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
      Text($r('app.string.DialogSubjectComponent_secText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_m')
        })
      Text(this.subjectNameO)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
      Text($r('app.string.DialogSubjectComponent_thdText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_m')
        })
      Text(this.subjectNameOU)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
      Text($r('app.string.DialogSubjectComponent_fouText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_m')
        })
      Text(this.serial)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
    }.alignItems(HorizontalAlign.Start);
  }
}

@Component
struct DialogIssuerComponent {
  private map?: Map<string, string>;
  private issuerNameCN: string = '';
  private issuerNameO: string = '';
  private issuerNameOU: string = '';

  aboutToAppear() {
    if (this.map != null) {
      let issuerNameCN = this.map.get('常用名称:');
      if (issuerNameCN !== undefined) {
        this.issuerNameCN = issuerNameCN;
      }

      let issuerNameO = this.map.get('组织:');
      if (issuerNameO !== undefined) {
        this.issuerNameO = issuerNameO;
      }

      let issuerNameOU = this.map.get('组织单位:');
      if (issuerNameOU !== undefined) {
        this.issuerNameOU = issuerNameOU;
      }
    }
  }

  build() {
    Column() {
      Text($r('app.string.DialogSubjectComponent_firText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_l')
        })
      Text(this.issuerNameCN)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
      Text($r('app.string.DialogSubjectComponent_secText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_m')
        })
      Text(this.issuerNameO)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
      Text($r('app.string.DialogSubjectComponent_thdText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_m')
        })
      Text(this.issuerNameOU)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
    }.alignItems(HorizontalAlign.Start);
  }
}

@Component
struct DialogDateComponent {
  private map?: Map<string, string>;
  private notBefore: string = '';
  private notAfter: string = '';

  aboutToAppear() {
    if (this.map != null) {
      let notBefore = this.map.get('颁发时间:');
      if (notBefore != undefined) {
        this.notBefore = notBefore;
      }

      let notAfter = this.map.get('有效期至:');
      if (notAfter != undefined) {
        this.notAfter = notAfter;
      }
    }
  }

  build() {
    Column() {
      Text($r('app.string.DialogSubjectComponent_fifText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_l')
        })
      Text(this.notBefore)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
      Text($r('app.string.DialogSubjectComponent_sixText'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_m')
        })
      Text(this.notAfter)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
    }.alignItems(HorizontalAlign.Start);
  }
}

@Component
struct DialogFingerPrintComponent {
  private fingerprintSha256: string = '';

  build() {
    Column() {
      Text($r('app.string.CustomDialogExample_FingerPrint_text'))
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          top: $r('app.float.sys_elements_margin_vertical_l')
        })
      Text(this.fingerprintSha256)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          right: $r('app.float.wh_value_24')
        })
    }.alignItems(HorizontalAlign.Start);
  }
}

@Component
struct ComponentSystem {
  private certAlias: string = '';
  private subjectName: string = '';
  private uri: string = '';
  @Link setStatus: CmShowSysCaPresenter;
  private sysCaScroller: Scroller = new Scroller();

  @State isHoverBackgroundColor: ResourceColor = '';
  @Styles pressedStyles(): void {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
  }
  @Styles normalStyles(): void {
    .backgroundColor(this.isHoverBackgroundColor)
  }

  systemDetailsDialog: CustomDialogController = new CustomDialogController({
    alignment: DialogAlignment.Center,
    builder: CustomContentDialog({
      contentBuilder: () => {
        this.systemDetailContent();
      },
      contentAreaPadding: { right: $r('app.float.wh_value_0') },
      buttons: [{
        value: $r('app.string.CustomDialogExample_Button_text'),
        buttonStyle: ButtonStyleMode.TEXTUAL,
        action: () => {
          this.systemDetailsDialog?.close();
        }
      }]
    })
  })

  @Builder
  systemDetailContent(): void {
    Column() {
      Text($r('app.string.CustomDialogExample_firText'))
        .fontSize($r('sys.float.ohos_id_text_size_dialog_tittle'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .height($r('app.float.wh_value_56'))
        .margin({
          bottom: $r('app.float.wh_value_8'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      Text(this.setStatus.certInfo.certAlias)
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .margin({
          bottom: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      Scroll(this.sysCaScroller) {
        List() {
          ListItem() {
            Text($r('app.string.CustomDialogExample_firListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            DialogSubjectComponent({ map: this.setStatus.certInfo.subjectNameMap });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            Text($r('app.string.CustomDialogExample_secListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)
          .margin({
            top: $r('app.float.wh_value_24')
          })

          ListItem() {
            DialogIssuerComponent({ map: this.setStatus.certInfo.issuerNameMap });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            Text($r('app.string.CustomDialogExample_thdListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)
          .margin({
            top: $r('app.float.wh_value_24')
          })

          ListItem() {
            DialogDateComponent({ map: this.setStatus.certInfo.dateMap });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            Text($r('app.string.CustomDialogExample_fouListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)
          .margin({
            top: $r('app.float.wh_value_24')
          })

          ListItem() {
            DialogFingerPrintComponent({ fingerprintSha256: this.setStatus.certInfo.fingerprintSha256 });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)
        }
        .margin({ right: $r('app.float.wh_value_24') })
        .scrollBar(BarState.Off)
      }
      .scrollable(ScrollDirection.Vertical)
      .scrollBarWidth('3vp')
      .height($r('app.float.CustomDialogExample_list_height_value'))
    }
    .padding({
      left: $r('app.float.wh_value_24'),
    })
    .width(WidthPercent.WH_100_100)
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
    .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
  }

  build() {
    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
      Column() {
        Text(this.certAlias)
          .fontSize($r('sys.float.ohos_id_text_size_body1'))
          .fontColor($r('sys.color.ohos_id_color_text_primary'))
          .fontWeight(FontWeight.Medium)
          .textAlign(TextAlign.Start)
          .margin({ top: $r('app.float.wh_value_10') });
        Text(this.subjectName)
          .fontSize($r('sys.float.ohos_id_text_size_body2'))
          .fontColor($r('sys.color.ohos_id_color_text_secondary'))
          .fontWeight(FontWeight.Regular)
          .textAlign(TextAlign.Start)
          .margin({ top: $r('app.float.wh_value_2'), bottom: $r('app.float.wh_value_11') });
      }.alignItems(HorizontalAlign.Start);
    }
    .onHover((isHover?: boolean) => {
      this.isHoverBackgroundColor = isHover ? $r('sys.color.ohos_id_color_hover') : ''
    })
    .backgroundColor(this.isHoverBackgroundColor)
    .stateStyles({
      pressed: this.pressedStyles,
      normal: this.normalStyles
    })
    .padding({
      left: $r('app.float.wh_value_8'),
      right: $r('app.float.wh_value_8')
    })
    .borderRadius($r('app.float.wh_value_20'))
    .onClick(() => {
      this.setStatus.getSystemTrustedCertificate(this.uri, () => {
        console.info('this.setStatus.certInfo.status is:' + JSON.stringify(this.setStatus.certInfo));
        this.systemDetailsDialog.open();
      });
    })
  }
}

@Component
struct ComponentUser {
  private certAlias: string = '';
  private subjectName: string = '';
  private indexNum: number = -1;
  private uri: string = '';
  @State statusText: Resource = $r('app.string.CustomDialogExampleUser_Status_false');
  @Link setStatus: CMShowUserCaPresenter;
  @State mUserCaPresenterDetail: CMShowUserCaPresenter = CMShowUserCaPresenter.getInstance();
  private userCaScroller: Scroller = new Scroller();

  @State isHoverBackgroundColor: ResourceColor = '';
  @Styles pressedStyles(): void {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
  }
  @Styles normalStyles(): void {
    .backgroundColor(this.isHoverBackgroundColor)
  }

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
            this.setStatus.updateUserTrustedCertificateList();
          }
        },
        {
          value: $r('app.string.root_certificate_continue'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.setStatus.setUserCertificateStatus(this.mUserCaPresenterDetail.certInfo.uri, true);
            this.setStatus.updateUserTrustedCertificateList();
          }
        }
      ]
    })
  })

  userDetailsDialog: CustomDialogController = new CustomDialogController({
    alignment: DialogAlignment.Center,
    builder: CustomContentDialog({
      contentBuilder: () => {
        this.userDetailContent(this.setStatus.certList[this.indexNum].status);
      },
      contentAreaPadding: { right: $r('app.float.wh_value_0') },
      buttons: [
        {
          value: $r('app.string.CustomDialogExampleUser_Flex_firButton_text'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.setStatus.updateUserTrustedCertificateList();
            this.userDetailsDialog?.close();
          }
        },
        {
          value: $r('app.string.CustomDialogExampleUser_Flex_secButton_text'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.setStatus.updateUserTrustedCertificateList();
            this.onShowDeleteWarnDialog();
          },
          role: ButtonRole.ERROR
        }
      ]
    })
  })

  deleteCertWarnDialog: CustomDialogController = new CustomDialogController({
    builder: CustomContentDialog({
      contentBuilder: () => {
        this.deleteWarnContent();
      },
      contentAreaPadding: { right: $r('app.float.wh_value_0') },
      buttons: [
        {
          value: $r('app.string.deleteAllCredCancel'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.setStatus.updateUserTrustedCertificateList();
            this.deleteCertWarnDialog?.close();
          }
        },
        {
          value: $r('app.string.deleteAllCredDelete'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.setStatus.deleteUserCertificate(this.mUserCaPresenterDetail.certInfo.uri, () => {
              this.setStatus.updateUserTrustedCertificateList();
              this.deleteCertWarnDialog?.close();
            })
          },
          role: ButtonRole.ERROR
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

  @Builder
  deleteWarnContent(): void {
    Column() {
      Text($r('app.string.CustomDialogExampleUser_warning_Button_title_text'))
        .height($r('app.float.wh_value_56'))
        .fontSize($r('sys.float.ohos_id_text_size_dialog_tittle'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .margin({
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      Text($r('app.string.CustomDialogExampleUser_warning_Button_message_text'))
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

  @Builder
  userDetailContent($$: boolean): void {
    Column() {
      Text($r('app.string.CustomDialogExample_firText'))
        .fontSize($r('sys.float.ohos_id_text_size_dialog_tittle'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .height($r('app.float.wh_value_56'))
        .margin({
          bottom: $r('app.float.wh_value_8'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Column() {
          Text(this.mUserCaPresenterDetail.certInfo.certAlias)
            .fontSize($r('sys.float.ohos_id_text_size_body1'))
            .fontColor($r('sys.color.ohos_id_color_text_primary'))
            .fontWeight(FontWeight.Medium)
        }.alignItems(HorizontalAlign.Start);

        Toggle({ type: ToggleType.Switch, isOn: $$ })
          .margin({
            left: $r('app.float.wh_value_16'),
            right: $r('app.float.wh_value_24')
          })
          .flexShrink(0)
          .width($r('app.float.CustomDialogExampleUser_Flex_Toggle_width_value'))
          .height($r('app.float.CustomDialogExampleUser_Flex_Toggle_height_value'))
          .selectedColor($r('app.color.CustomDialogExampleUser_Flex_Toggle_selectedColor_007DFF'))
          .onChange((isOn: boolean) => {
            if (isOn) {
              this.onShowRootCertificateDialog();
            } else {
              this.setStatus.setUserCertificateStatus(this.mUserCaPresenterDetail.certInfo.uri, false);
            }
          });
      }

      Scroll(this.userCaScroller) {
        List() {
          ListItem() {
            Text($r('app.string.CustomDialogExample_firListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
              .margin({
                top: $r('app.float.wh_value_24')
              })
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            DialogSubjectComponent({ map: this.mUserCaPresenterDetail.certInfo.subjectNameMap });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            Text($r('app.string.CustomDialogExample_secListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
              .margin({
                top: $r('app.float.wh_value_24')
              })
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            DialogIssuerComponent({ map: this.mUserCaPresenterDetail.certInfo.issuerNameMap });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            Text($r('app.string.CustomDialogExample_thdListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
              .margin({
                top: $r('app.float.wh_value_24')
              })
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            DialogDateComponent({ map: this.mUserCaPresenterDetail.certInfo.dateMap });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            Text($r('app.string.CustomDialogExample_fouListItem_text'))
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontWeight(FontWeight.Medium)
              .margin({
                top: $r('app.float.wh_value_24')
              })
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)

          ListItem() {
            DialogFingerPrintComponent({
              fingerprintSha256: this.mUserCaPresenterDetail.certInfo.fingerprintSha256
            });
          }.width(ComponentConfig.WH_100_100).align(Alignment.Start)
        }
        .margin({
          right: $r('app.float.wh_value_24')
        })
        .scrollBar(BarState.Off)
      }
      .height($r('app.float.CustomDialogExample_list_height_value'))
      .scrollable(ScrollDirection.Vertical)
      .scrollBarWidth('3vp')
    }
    .padding({
      left: $r('app.float.wh_value_24')
    })
    .width(WidthPercent.WH_100_100)
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
    .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
  }

  onShowRootCertificateDialog() {
    this.userDetailsDialog?.close();
    this.rootCertificateDialog.open();
  }

  onShowDeleteWarnDialog() {
    this.deleteCertWarnDialog.open();
    this.userDetailsDialog?.close();
  }

  aboutToAppear() {
    console.info('in ComponentUser aboutToAppear');
    if (this.setStatus.certList[this.indexNum].status == true) {
      this.statusText = $r('app.string.CustomDialogExampleUser_Status_true');
    } else {
      this.statusText = $r('app.string.CustomDialogExampleUser_Status_false');
    }
  }

  build() {
    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
      Column() {
        Text(this.certAlias)
          .fontSize($r('sys.float.ohos_id_text_size_body1'))
          .fontColor($r('sys.color.ohos_id_color_text_primary'))
          .fontWeight(FontWeight.Medium)
          .textAlign(TextAlign.Start)
          .margin({ top: $r('app.float.wh_value_10') })
        Text(this.subjectName)
          .fontSize($r('sys.float.ohos_id_text_size_body2'))
          .fontColor($r('sys.color.ohos_id_color_text_primary'))
          .fontWeight(FontWeight.Regular)
          .textAlign(TextAlign.Start)
          .margin({ top: $r('app.float.wh_value_2'), bottom: $r('app.float.wh_value_11') });
      }
      .alignItems(HorizontalAlign.Start);
      Row() {
        Text(this.statusText)
          .fontSize($r('sys.float.ohos_id_text_size_body2'))
          .fontColor($r('sys.color.ohos_id_color_text_secondary'))
          .textAlign(TextAlign.End)
          .margin({
            right: $r('app.float.componentUser_thdText_margin_value')
          })
        Image($r('app.media.ic_settings_arrow'))
          .width($r('app.float.componentUser_image_width_value'))
          .height($r('app.float.componentUser_image_height_value'))
          .fillColor($r('sys.color.ohos_id_color_primary'))
          .opacity($r('app.float.componentUser_image_opacity_value'));
      }
      .flexShrink(0)
      .margin($r('app.float.wh_value_12'))
    }
    .onHover((isHover?: boolean) => {
      this.isHoverBackgroundColor = isHover ? $r('sys.color.ohos_id_color_hover') : ''
    })
    .backgroundColor(this.isHoverBackgroundColor)
    .stateStyles({
      pressed: this.pressedStyles,
      normal: this.normalStyles
    })
    .padding({
      left: $r('app.float.wh_value_8'),
      right: $r('app.float.wh_value_8')
    })
    .borderRadius($r('app.float.wh_value_20'))
    .onClick(() => {
      this.mUserCaPresenterDetail.getUserTrustedCertificate(this.uri, () => {
        console.info('userCerInfo is:' + JSON.stringify(this.setStatus.certInfo));
        this.userDetailsDialog.open();
      });
    });
  }
}

@Entry
@Component
struct TrustedEvidence {
  @State mShowSysCaPresenter: CmShowSysCaPresenter = CmShowSysCaPresenter.getInstance();
  @State mShowUserCaPresenter: CMShowUserCaPresenter = CMShowUserCaPresenter.getInstance();
  @State mFaPresenter: CmFaPresenter = CmFaPresenter.getInstance();
  @State currentIndex: number = 0;
  @State fontColor: Resource = $r('app.color.TrustedEvidence_TabBuilder_fontColor_182431');
  @State selectedFontColor: Resource = $r('app.color.font_color_007DFF');
  private controller: TabsController = new TabsController();
  private sysCaScroller: Scroller = new Scroller();
  private userCaScroller: Scroller = new Scroller();
  @State animationDurationNum: number = 400;

  @Builder
  TabBuilder(index: number) {
    Column() {
      Text(index == 0 ? $r('app.string.system') : $r('app.string.user'))
        .fontColor(this.currentIndex === index ? this.selectedFontColor : this.fontColor)
        .fontSize($r('app.float.TrustedEvidence_TabBuilder_Text_fontSize_value'))
        .fontWeight(this.currentIndex === index ? FontWeight.Medium : FontWeight.Regular)
        .alignSelf(ItemAlign.Center)
        .margin({
          top: $r('app.float.TrustedEvidence_TabBuilder_Text_padding_top_value')
        })
      if (this.currentIndex === index) {
        Divider()
          .width($r('app.float.TrustedEvidence_TabBuilder_Divider_width_value'))
          .margin({ top: $r('app.float.TrustedEvidence_TabBuilder_Divider_padding_top_value') })
          .color(this.selectedFontColor)
          .alignSelf(ItemAlign.Center)
      }
    }
    .width(WidthPercent.WH_100_100)
  }

  aboutToAppear() {
    this.mShowSysCaPresenter.updateSystemTrustedCertificateList();
    this.mShowUserCaPresenter.updateUserTrustedCertificateList();
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

  build() {
    Column() {
      GridRow({ columns: COPIES_NUM, gutter: vp2px(1) === 2 ? $r('app.float.wh_value_12') : $r('app.float.wh_value_0') }) {
        GridCol({ span: COPIES_NUM }) {
          Row() {
            Column() {
              HeadComponent({ headName: $r('app.string.CA_cert') })
                .margin({
                  left: $r('app.float.wh_value_12')
                })

              Column() {
                Tabs({ barPosition: BarPosition.Start, index: 0, controller: this.controller }) {
                  TabContent() {
                    Stack({ alignContent: Alignment.End }) {
                      Scroll(this.sysCaScroller) {
                        List() {
                          ForEach(this.mShowSysCaPresenter.certList, (item: CertAbstractVo) => {
                            ListItem() {
                              ComponentSystem({
                                certAlias: item.certAlias,
                                subjectName: item.subjectNameCN,
                                uri: item.uri,
                                setStatus: $mShowSysCaPresenter,
                              })
                            }
                          }, (item: CertAbstractVo) => JSON.stringify(item))
                        }
                        .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
                        .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
                        .scrollBar(BarState.Off)
                        .padding({
                          right: $r('app.float.wh_value_4'),
                          left: $r('app.float.wh_value_4'),
                          top: $r('app.float.wh_value_4'),
                          bottom: $r('app.float.wh_value_4')
                        })
                        .divider({
                          strokeWidth: $r('app.float.sys_list_divider_strokeWidth_value'),
                          color: $r('sys.color.ohos_id_color_list_separator'),
                          startMargin: $r('app.float.wh_value_8'),
                          endMargin: $r('app.float.wh_value_8')
                        })
                        .visibility(this.mShowSysCaPresenter.certList.length > 0
                          ? Visibility.Visible : Visibility.None)
                      }
                      .position({ y: $r('app.float.wh_value_0') })
                      .scrollable(ScrollDirection.Vertical)
                      .scrollBar(BarState.Off)
                      .margin({
                        left: $r('app.float.wh_value_12'),
                        right: $r('app.float.wh_value_12')
                      })
                      .backgroundColor($r('sys.color.ohos_id_color_sub_background'))

                      ScrollBar({ scroller: this.sysCaScroller, direction: ScrollBarDirection.Vertical,
                        state: BarState.Auto }) {
                        Text()
                          .width($r('app.float.wh_value_3'))
                          .height($r('app.float.wh_value_50'))
                          .borderRadius($r('app.float.wh_value_10'))
                          .backgroundColor($r('sys.color.ohos_id_color_foreground'))
                          .opacity($r('app.float.text_opacity_0_4'))
                      }
                      .width($r('app.float.wh_value_3'))
                      .margin({
                        right: $r('app.float.wh_value_3')
                      })
                      .visibility(this.mShowSysCaPresenter.certList.length > 0 ? Visibility.Visible : Visibility.None)
                    }
                    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
                  }
                  .tabBar(this.TabBuilder(0))

                  TabContent() {
                    Stack({ alignContent: Alignment.End }) {
                      Scroll(this.userCaScroller) {
                        List() {
                          ForEach(this.mShowUserCaPresenter.certList, (item: CertAbstractVo, index) => {
                            ListItem() {
                              ComponentUser({
                                certAlias: item.certAlias,
                                subjectName: item.subjectNameCN,
                                uri: item.uri,
                                setStatus: $mShowUserCaPresenter,
                                indexNum: index
                              })
                            }
                          }, (item: CertAbstractVo) => JSON.stringify(item))
                        }
                        .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
                        .backgroundColor($r('sys.color.ohos_id_color_card_bg'))
                        .divider({
                          strokeWidth: $r('app.float.sys_list_divider_strokeWidth_value'),
                          color: $r('sys.color.ohos_id_color_list_separator'),
                          startMargin: $r('app.float.wh_value_8'),
                          endMargin: $r('app.float.wh_value_8')
                        })
                        .scrollBar(BarState.Off)
                        .padding({
                          left: $r('app.float.wh_value_4'),
                          right: $r('app.float.wh_value_4'),
                          top: $r('app.float.wh_value_4'),
                          bottom: $r('app.float.wh_value_4')
                        })
                        .visibility(this.mShowUserCaPresenter.certList.length > 0
                          ? Visibility.Visible : Visibility.None)
                      }
                      .position({ y: $r('app.float.wh_value_0') })
                      .scrollable(ScrollDirection.Vertical)
                      .scrollBar(BarState.Off)
                      .margin({
                        left: $r('app.float.wh_value_12'),
                        right: $r('app.float.wh_value_12')
                      })

                      ScrollBar({ scroller: this.userCaScroller, direction: ScrollBarDirection.Vertical,
                        state: BarState.Auto }) {
                        Text()
                          .width($r('app.float.wh_value_3'))
                          .height($r('app.float.wh_value_50'))
                          .borderRadius($r('app.float.wh_value_10'))
                          .backgroundColor($r('sys.color.ohos_id_color_foreground'))
                          .opacity($r('app.float.text_opacity_0_4'))
                      }
                      .width($r('app.float.wh_value_3'))
                      .margin({
                        right: $r('app.float.wh_value_3')
                      })
                      .visibility(this.mShowUserCaPresenter.certList.length > 0 ? Visibility.Visible : Visibility.None)
                    }
                    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
                  }
                  .tabBar(this.TabBuilder(1))
                }
                .vertical(false)
                .scrollable(true)
                .barMode(BarMode.Fixed)
                .barWidth($r('app.float.tabs_barWidth_value'))
                .barHeight($r('app.float.tabs_barHeight_value'))
                .animationDuration(this.animationDurationNum)
                .width(WidthPercent.WH_100_100)
                .margin({
                  bottom: $r('app.float.wh_value_24')
                })
                .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
                .onChange((index: number) => {
                  this.currentIndex = index;
                });
              }
              .height(WidthPercent.WH_94_100)
              .width(WidthPercent.WH_100_100)
            }
            .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
            .width(WidthPercent.WH_100_100)
            .height(WidthPercent.WH_100_100)
          }
          .width(WidthPercent.WH_100_100)
          .height(WidthPercent.WH_100_100);
        }
      }
      .margin(vp2px(1) === 2 ? $r('app.float.item_common_horizontal_margin') : $r('app.float.wh_value_0'))
      .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
      .width(WidthPercent.WH_100_100)
      .height(WidthPercent.WH_100_100);
    }
  }
}