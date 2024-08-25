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

import relationalStore from '@ohos.data.relationalStore';
import { AccessTableTypedef } from '../bean/AccessTableTypedef';

/**
 * Rdb database config
 */
export default class DataShareConstants {
  public static readonly STORE_CONFIG: relationalStore.StoreConfig = {
    name: 'access.db',
    securityLevel: relationalStore.SecurityLevel.S1
  };

  /**
   * Access table config
   */
  public static readonly ACCESS_TABLE: AccessTableTypedef = {
    tableName: 'functionAccessTable',
    sqlCreate: `CREATE TABLE IF NOT EXISTS functionAccessTable(intents TEXT PRIMARY KEY,
      userId INTEGER,
      iconBackgroundColorResource TEXT,
      priority INTEGER,
      isSupport INTEGER, isClickable INTEGER,
      displayedMode TEXT,
      iconResource TEXT,
      mainTitleResource TEXT,
      subTitleResource TEXT,
      showControlAbilityuri TEXT,
      dstAbilityMode INTEGER,
      dstAbilityName TEXT,
      dstBundleName TEXT,
      bundleName TEXT
    )`,
    columns: ['intents', 'userId', 'iconBackgroundColorResource',
      'priority', 'isSupport', 'isClickable', 'displayedMode', 'iconResource',
      'mainTitleResource', 'subTitleResource', 'showControlAbility',
      'dstAbilityMode', 'dstAbilityName', 'dstBundleName', 'bundleName'
    ]
  };

  /**
   * Access table config
   */
  public static readonly ANTO_MENU_TABLE_V2: AccessTableTypedef = {
    tableName: 'auto_menu_table',
    sqlCreate: `CREATE TABLE IF NOT EXISTS auto_menu_table(
    businessId TEXT PRIMARY KEY,
    intents TEXT,
    userId INTEGER,
    iconBackgroundColorResource TEXT,
    priority INTEGER,
    isSupport INTEGER,
    isClickable INTEGER,
    displayedMode TEXT,
    iconResource TEXT,
    mainTitleResource TEXT,
    subTitleResource TEXT,
    showControlAbilityUri TEXT,
    dstAbilityMode INTEGER,
    dstAbilityName TEXT,
    dstBundleName TEXT,
    bundleName TEXT
    )`,
    columns: ['businessId', 'intents', 'userId', 'iconBackgroundColorResource',
      'priority', 'isSupport', 'isClickable', 'displayedMode', 'iconResource',
      'mainTitleResource', 'subTitleResource', 'showControlAbilityUri',
      'dstAbilityMode', 'dstAbilityName', 'dstBundleName', 'bundleName'

    ]
  }
}