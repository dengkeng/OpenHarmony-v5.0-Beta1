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

export default interface MenuInfo {
  businessId: string;
  intents: string;

  // 用户id
  userId: number;

  //图标背景颜色
  iconBackgroundColorResource: string;

  // 优先级
  priority: number;

  //是否展示（0： 不支持， 1：支持）
  isSupport: number;

  //是否可点击（0：不可点击， 1： 可点击）
  isClickable: number;
  displayedMode: string;
  iconResource: string;
  mainTitleResource: string;
  subTitleResource: string;
  showControlAbilityUri: string;
  dstAbilityMode: number;
  dstAbilityName: string;
  dstBundleName: string;
  bundleName: string;
  titleString: string;
  subTitleString: string;
}