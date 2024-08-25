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

import path from 'path';

//开发及本地运行环境变量
export default {
  NODE_ENV: 'development',
  EVN_CONFIG: 'dev',
  DIR_NAME: path.resolve(__dirname, '../..'), //项目根目录地址
  NEED_DETECTION: '',
  IS_OH: '',
};
