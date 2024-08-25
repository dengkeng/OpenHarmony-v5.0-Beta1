/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

class ReporterFormat {
  static FLAG_JSON = 0;
  static FLAG_EXCEL = 1;
  static FLAG_DEBUG = 2;
  static formatMap = new Map([
    ['json', this.FLAG_JSON],
    ['excel', this.FLAG_EXCEL],
    ['debug', this.FLAG_DEBUG]
  ]);

  static getFlag(format) {
    return format && this.formatMap.has(format) ? this.formatMap.get(format) : this.FLAG_EXCEL;
  }
}

module.exports.ReporterFormat = ReporterFormat;