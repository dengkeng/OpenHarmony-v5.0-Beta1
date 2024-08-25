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

import webview from '@ohos.web.webview';
import CheckEmptyUtils, { configMgr, Constants, Log } from '@ohos/common';
import router from '@ohos.router';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';
import common from '@ohos.app.ability.common';
import {CancelButton, ClickableImage} from './component/BaseComponent';
import { Configuration } from '@ohos.app.ability.Configuration';

const TAG = 'PrivacyStatementWebPage';

@Entry
@Component
struct PrivacyStatementWebPage {
  @State @Watch('languageChange') language: string = configMgr.getConfiguration().language ?? '';
  private abilityContext: common.UIAbilityContext = GlobalThisHelper
    .getValue<common.UIAbilityContext>(GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT);
  private webController: webview.WebviewController = new webview.WebviewController();
  private privacyStatementFlag: boolean = false;
  private baseUrl: string = Constants.STRING_NONE;
  private url: string = Constants.STRING_NONE;

  aboutToAppear() {
    const hideCancel = router.getParams() as boolean;
    if (hideCancel) {
      this.privacyStatementFlag = hideCancel;
    }
    Log.info(TAG, 'privacyStatementFlag: ' + this.privacyStatementFlag);
    this.languageToWebUrl();
    configMgr.registerConfigManager(TAG, this);
  }

  aboutToDisappear() {
    configMgr.unregisterConfigManager(TAG);
  }

  notifyConfigurationChanged(config: Configuration): void {
    this.language = config.language?.substr(0, 2) ?? '';
    Log.info(TAG, 'notifyConfigurationChanged language: ' + JSON.stringify((this.language)));
  }

  build() {
    Flex({ justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center, direction: FlexDirection.Column }) {
      Column() {
        ClickableImage({
          imageSrc: $r('app.media.ic_back'),
          imageHeight: $r('app.float.privacy_statement_text_headline_height'),
          imageWidth: $r('app.float.privacy_statement_text_headline_height'),
          isHoverEnable: true,
          clickEvent: () => {
            this.onBack();
          }
        }).margin({left: $r('app.float.shield_width_height')})
      }
      .margin({top: $r('app.float.privacy_statement_text_headline_height')})
      .alignItems(HorizontalAlign.Start)
      .width('100%')
      .height($r('app.float.privacy_statement_text_margin_left_right'))
      Column() {
        Column() {
          Web({src: this.url, controller: this.webController})
            .width('100%')
            .height('100%')
        }
        .height(600)
        .width('100%')
        if (!this.privacyStatementFlag) {
          Column() {
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
          .width('100%')
          .alignItems(HorizontalAlign.Center)
        }
      }
      .margin({
        bottom: this.privacyStatementFlag ? 0
          : $r('app.float.privacy_statement_button_margin_bottom')
      })
      .width('100%')
      .height('100%')
    }
  }


  private onBack() {
    try {
      let result = this.webController.accessBackward();
      if (result) {
        this.webController.backward();
      } else {
        let page = router.getState();
        Log.info(TAG, 'page index = ' + page.index);
        Log.info(TAG, 'page name = ' + page.name);
        Log.info(TAG, 'page path = ' + page.path);
        Log.info(TAG, 'onBack parseInt(router.getLength()): ' + parseInt(router.getLength()));
        if (parseInt(router.getLength()) > 1) {
          router.back({url: 'pages/AboutPage'})
        } else {
          router.replaceUrl({ url: 'pages/PrivacyStatementPage' })
        }
      }
    } catch (error) {
      console.error(`Errorcode: ${error.code}, Message: ${error.message}`);
    }
  }

  private languageChange():void {
    Log.info(TAG, 'languageChange language: ' + this.language);
    this.languageToWebUrl();
    Log.info(TAG, 'languageChange url: ' + this.url);
    this.webController.loadUrl(this.url);
    Log.info(TAG, 'web url: ' + this.webController.getUrl());
  }

  private languageToWebUrl() {
    let languageCode = 'en-US';
    if (CheckEmptyUtils.checkStrIsEmpty(this.language) || this.language.substr(0, 2) === 'zh') {
      languageCode = 'zh-CN';
    }
    this.baseUrl = this.abilityContext.resourceManager.getStringByNameSync('privacy_statement_web_base_url');
    Log.info(TAG, 'languageToWebUrl baseUrl: ' + this.baseUrl);
    this.url = this.baseUrl + languageCode;
  }
}