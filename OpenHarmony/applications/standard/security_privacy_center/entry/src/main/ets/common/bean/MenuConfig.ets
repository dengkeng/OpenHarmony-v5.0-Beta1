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

export interface MenuConfig {
  businessId: string,

  //   card|list（card代表卡片方式接入，list代表列表方式接入）
  displayedMode: string;

  //   卡片式菜单显示时的图标
  iconResource: string;

  //   入口菜单显示的主标题字串的资源名
  mainTitleResource: string;

  //   入口菜单显示的副标题字串的资源名
  subTitleResource: string;

  /**
   * uri路径，该ability继承自DataShareExtensionAbility，接入方可覆写其query函数，通过query函数返回的结果集告知安全隐私中心，是否需要展示该菜单
   * query结果集为KEY_VALUE形式
   * key： SHOW_RESULT
   * Value：
   * 0x55,展示
   * 0xaa,不展示
   */
  showControlAbilityUri: string;
  displayUserConfig: string;

  /**
   * 0: 表示被拉起的ability为UiAbility
   * 1: 表示被拉起的ability为UiextensionAbility
   */
  dstAbilityMode: number;

  /**
   * 跳转的目的ability
   * dstAbilityMode为0时，该ability为UiAbility
   * dstAbilityMode为1时，该ability需继承自UIExtensionAbility,接入方在此ability中加载自身页面
   */
  dstAbilityName: string;

  //   跳转的目的bundle名
  dstBundleName: string;

  //   应用的包名
  bundleName: string;
}