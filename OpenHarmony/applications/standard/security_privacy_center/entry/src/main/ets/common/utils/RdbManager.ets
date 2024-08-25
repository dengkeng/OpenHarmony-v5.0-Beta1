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
import Logger from '../utils/Logger';
import DataShareConstants from '../constants/DataShareConstant';

const TAG = 'RdbManager';
const OPT_ERROR = -1;

export class RdbManager {
  private _rdbStore: relationalStore.RdbStore | undefined = undefined;

  private constructor() {
  }

  private static instance: RdbManager;

  /**
   * To get single instance
   * @returns The single instance
   */
  public static getInstance(): RdbManager {
    if (!RdbManager.instance) {
      RdbManager.instance = new RdbManager();
    }
    return RdbManager.instance;
  }

  async getRdbStore(context: Context): Promise<relationalStore.RdbStore | undefined> {
    if (this._rdbStore) {
      return this._rdbStore;
    }
    try {
      this._rdbStore = await relationalStore.getRdbStore(context, DataShareConstants.STORE_CONFIG);
      if (this._rdbStore === undefined) {
        return this._rdbStore;
      }
      await this._rdbStore.executeSql(DataShareConstants.ANTO_MENU_TABLE_V2.sqlCreate);
      Logger.info(TAG, 'getRdbStore() finished.')
    } catch (error) {
      Logger.info(TAG, 'getRdbStore() error.')
    }
    return this._rdbStore;
  }

  async insert(context: Context, table: string, values: relationalStore.ValuesBucket): Promise<number> {
    try {
      let rdbStore: relationalStore.RdbStore | undefined = await this.getRdbStore(context);
      if (rdbStore === undefined) {
        return OPT_ERROR;
      }
      const result: number = await rdbStore.insert(table, values);
      return result;
    } catch (err) {
      Logger.error(TAG, 'insert error.')
    }
    return OPT_ERROR;
  }


  async delete(context: Context, predicates: relationalStore.RdbPredicates): Promise<number> {
    try {
      let rdbStore: relationalStore.RdbStore | undefined = await this.getRdbStore(context);
      if (rdbStore === undefined) {
        return OPT_ERROR;
      }
      const result: number = await rdbStore.delete(predicates);
      return result;
    } catch (err) {
      Logger.error(TAG, 'delete error.')
    }
    return OPT_ERROR;
  }

  async query(context: Context, predicates: relationalStore.RdbPredicates,
    columns?: Array<string>): Promise<relationalStore.ResultSet | undefined> {
    try {
      let rdbStore: relationalStore.RdbStore | undefined = await this.getRdbStore(context);
      if (rdbStore === undefined) {
        return undefined;
      }
      const result: relationalStore.ResultSet = await rdbStore.query(predicates, columns);
      return result;
    } catch (err) {
      Logger.error(TAG, 'query error.')
    }
    return undefined;
  }
}