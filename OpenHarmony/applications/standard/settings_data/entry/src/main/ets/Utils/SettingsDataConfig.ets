/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

interface SettingsDataBaseConfig {
  DB_NAME: string;
  TABLE_NAME: string;
  USER_TABLE_NAME: string;
  FIELD_ID: string;
  FIELD_KEYWORD: string;
  FIELD_VALUE: string;
}
const SettingsDataConfig: SettingsDataBaseConfig = {
  DB_NAME: 'settingsdata.db',
  TABLE_NAME: 'SETTINGSDATA',
  USER_TABLE_NAME: 'USER_SETTINGSDATA',
  FIELD_ID: 'ID',
  FIELD_KEYWORD: 'KEYWORD',
  FIELD_VALUE: 'VALUE'
};

export default SettingsDataConfig;
