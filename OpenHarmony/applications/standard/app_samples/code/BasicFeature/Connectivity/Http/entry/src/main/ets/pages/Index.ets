/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

import router from '@ohos.router'
import { setting } from '@ohos/http'

@Entry
@Component
struct Index {
  @State url: string = ''
  @State option?: object = undefined

  aboutToAppear() {
    try {
      let params = router.getParams() as Record<string, string | object>;
      this.url = params['url'] as string
      this.option = params['option'] as object
    } catch (err) {
      this.url = ''
      this.option = undefined
    }
  }

  build() {
    Column() {
      setting({ getUri: this.url, getOption: this.option })
    }
    .id('mainPage')
  }
}