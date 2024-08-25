/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
import { NODE_API_CATEGORIES } from '../pages/nodeapi/NodeApi'
import { JAVASCRIPT_API_CATEGORIES } from '../pages/javascript/JavaScriptApi'
import { OTHER_CATEGORIES } from '../pages/other/OtherMgr'
import { NCPP_CATEGORIES } from '../pages/ncpp/NcppMgr'
import { FirstLevelCategory } from '../model/CategoricalDataType'
import { ASYNC_CATEGORIES } from '../pages/async/AsyncMgr'

// The component collection classifies the data as a whole
export const NAPI_SAMPLE_CATEGORIES: FirstLevelCategory[] =
  [
    {
      childNodes: NODE_API_CATEGORIES,
      selectedImage: $r('app.media.ic_select_component'),
      unselectedImage: $r('app.media.ic_unselect_component'),
      tabBarName: $r('app.string.node_api')
    },
    {
      childNodes: JAVASCRIPT_API_CATEGORIES,
      selectedImage: $r('app.media.ic_select_global'),
      unselectedImage: $r('app.media.ic_unselect_global'),
      tabBarName: $r('app.string.javascript_api')
    },
    {
      childNodes: ASYNC_CATEGORIES,
      selectedImage: $r('app.media.ic_select_universal'),
      unselectedImage: $r('app.media.ic_unselect_universal'),
      tabBarName: $r('app.string.async_mgr')
    },
    {
      childNodes: OTHER_CATEGORIES,
      selectedImage: $r('app.media.ic_select_animation'),
      unselectedImage: $r('app.media.ic_unselect_animation'),
      tabBarName: $r('app.string.other_mgr')
    },
    {
      childNodes: NCPP_CATEGORIES,
      selectedImage: $r('app.media.ic_select_component'),
      unselectedImage: $r('app.media.ic_unselect_component'),
      tabBarName: $r('app.string.thirdparty_management')
    }
  ]

export const fruitArray: Resource[] = []