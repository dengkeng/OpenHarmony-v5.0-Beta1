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

import CmAppCredAuthPresenter from '../presenter/CmAppCredAuthPresenter';
import router from '@ohos.router';
import { WidthPercent, ConfigValue } from '../common/util/ConfigData';
import { CredentialAbstractVo } from '../model/CertManagerVo/CredentialAbstractVo';
import { RouterAppUidVo } from '../model/CertManagerVo/RouterInfoVo';
import { CustomContentDialog } from '@ohos.arkui.advanced.Dialog';

@Entry
@Component
struct RadioAuth {
  @State mAppCredAuthPresenter: CmAppCredAuthPresenter = CmAppCredAuthPresenter.getInstance();
  selectUri: string = '';
  private authScroller: Scroller = new Scroller();

  dialogController: CustomDialogController = new CustomDialogController({
    cancel: () => {
      this.mAppCredAuthPresenter.cancelProcess();
    },
    builder: CustomContentDialog({
      contentBuilder: () => {
        this.dialogControllerContent();
      },
      contentAreaPadding: {right: $r('app.float.wh_value_0')},
      buttons: [
        {
          value: $r('app.string.requestAuthCancel'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            this.mAppCredAuthPresenter.cancelProcess();
            this.dialogController?.close();
          }
        },
        {
          value: $r('app.string.requestAuthFinish'),
          buttonStyle: ButtonStyleMode.TEXTUAL,
          action: () => {
            console.debug('requestAuthorize uri: ' + this.selectUri);
            let appUidInfo: RouterAppUidVo = router.getParams() as RouterAppUidVo;
            if (appUidInfo !== undefined && appUidInfo.appUid != undefined) {
              console.debug('requestAuthorize appUid: ' + appUidInfo.appUid);
              this.mAppCredAuthPresenter.requestAuthorize(this.selectUri, appUidInfo.appUid);
              this.dialogController?.close();
            } else {
              console.info('requestAuthorize fail');
            }
          }
        }
      ]
    }),
  })

  @Builder
  dialogControllerContent(): void {
    Column() {
      Text($r('app.string.pickCredToAuth'))
        .fontSize($r('sys.float.ohos_id_text_size_dialog_tittle'))
        .height($r('app.float.wh_value_56'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .margin({
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      Text($r('app.string.requestAuthMsg', this.mAppCredAuthPresenter.appName))
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Regular)
        .margin({
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .alignSelf(ItemAlign.Start)

      if (this.mAppCredAuthPresenter.credList.length > ConfigValue.REQUEST_AUTH_MAX_LENGTH) {
        Stack({ alignContent: Alignment.End }) {
          Scroll(this.authScroller) {
            List() {
              ForEach(this.mAppCredAuthPresenter.credList, (item: CredentialAbstractVo, index: number) => {
                ListItem() {
                  Column() {
                    Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                      Column() {
                        Text(item.alias)
                          .fontSize($r('app.float.font_18'))
                          .fontColor($r('sys.color.ohos_id_color_text_primary'))
                          .fontWeight(FontWeight.Medium)
                          .textAlign(TextAlign.Start);
                      }
                      .alignItems(HorizontalAlign.Start)

                      Column() {
                        Radio({ value: item.alias, group: 'appCredGroup' })
                          .checked(false)
                          .onChange((value: boolean) => {
                            console.log(item.alias + ' status is ' + value);
                            if (value) {
                              this.selectUri = item.keyUri;
                            }
                          })
                      }
                      .alignItems(HorizontalAlign.End)
                    }
                    .width(WidthPercent.WH_100_100)

                    Divider()
                      .color($r('sys.color.ohos_id_color_list_separator'))
                      .margin({
                        top: $r('app.float.distance_12')
                      })
                      .visibility(index === (this.mAppCredAuthPresenter.credList.length - 1)
                        ? Visibility.None : Visibility.Visible)
                  }
                }
                .height($r('app.float.wh_value_64'))
              }, (item: CredentialAbstractVo) => JSON.stringify(item))
            }
            .scrollBar(BarState.Off)
            .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
            .visibility(this.mAppCredAuthPresenter.credList.length > 0 ? Visibility.Visible : Visibility.None)
          }
          .scrollBar(BarState.Off)
          .margin({
            left: $r('app.float.wh_value_24'),
            right: $r('app.float.wh_value_24')
          })

          ScrollBar({ scroller: this.authScroller, direction: ScrollBarDirection.Vertical,
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
        }
        .height(WidthPercent.WH_50_100)
      } else {
        List() {
          ForEach(this.mAppCredAuthPresenter.credList, (item: CredentialAbstractVo, index: number) => {
            ListItem() {
              Column() {
                Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
                  Column() {
                    Text(item.alias)
                      .fontSize($r('app.float.font_18'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary'))
                      .fontWeight(FontWeight.Medium)
                      .textAlign(TextAlign.Start);
                  }
                  .alignItems(HorizontalAlign.Start)

                  Column() {
                    Radio({ value: item.alias, group: 'appCredGroup' })
                      .checked(false)
                      .onChange((value: boolean) => {
                        console.log(item.alias + ' status is ' + value);
                        if (value) {
                          this.selectUri = item.keyUri;
                        }
                      })
                  }
                  .alignItems(HorizontalAlign.End)
                }
                .width(WidthPercent.WH_100_100)

                Divider()
                  .color($r('sys.color.ohos_id_color_list_separator'))
                  .margin({
                    top: $r('app.float.distance_12')
                  })
                  .visibility(index === (this.mAppCredAuthPresenter.credList.length - 1)
                    ? Visibility.None : Visibility.Visible)
              }
            }
            .height($r('app.float.wh_value_64'))
          }, (item: CredentialAbstractVo) => JSON.stringify(item))
          ListItem() {
            Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
              Column() {
                Text()
              }
              .alignItems(HorizontalAlign.Start)

              Column() {
                Radio({ value: 'null', group: 'appCredGroup' })
                  .checked(false)
                  .onChange((value: boolean) => {
                    if (value) {
                      this.selectUri = 'null';
                    }
                  })
              }
            }
            .visibility(Visibility.None)
          }
        }
        .margin({
          left: $r('app.float.wh_value_24'),
          right: $r('app.float.wh_value_24')
        })
        .scrollBar(BarState.Off)
        .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
        .visibility(this.mAppCredAuthPresenter.credList.length > 0 ? Visibility.Visible : Visibility.None)
      }
    }
    .width(WidthPercent.WH_100_100)
    .borderRadius($r('app.float.user_list_divider_borderRadius_value'))
    .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
  }

  aboutToAppear() {
    console.debug('enter requestAuth page');
    let appUidInfo: RouterAppUidVo = router.getParams() as RouterAppUidVo;
    if (appUidInfo !== undefined && appUidInfo.appUid != undefined) {
      this.mAppCredAuthPresenter.updateAppNameFromUid(appUidInfo.appUid as string);
      this.mAppCredAuthPresenter.updateAppCredList();
      this.dialogController.open();
    } else {
      console.error('requestAuth appear failed');
      router.pushUrl({ url: 'pages/certManagerFa' });
    }
  }

  build() {

  }
}
