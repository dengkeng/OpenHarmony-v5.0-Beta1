/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

export class BaseData {
  public MAX_LEN = 30;
  public EMPTY_STR = '';
  public DEFAULT_USER_ID = 100;
  public HTTPS = 'https';
  public OOBE_NEXT_STEP_CODE = 100;
  public OOBE_PRE_STEP_CODE = 101;
  public ENABLE_ADMIN_FAILED = 102;
}

let baseData = new BaseData();

export default baseData as BaseData;