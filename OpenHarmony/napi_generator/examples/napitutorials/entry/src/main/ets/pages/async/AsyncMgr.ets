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

import { ThirdLevelCategory } from '../../model/CategoricalDataType'

const SIMPLE_ASYNCRONOUS_OPERATIONS: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.simple_asyncronous_operations'),
    childNodes: [
      {
        title: $r('app.string.napi_create_async_work'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_delete_async_work'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_queue_async_work'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_cancel_async_work'),
        url: 'pages/image/basicSample/image2Gray'
      }
    ]
  }
const CUSTOM_ASYNCRONOUS_OPERATIONS: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.custom_asyncronous_operations'),
    childNodes: [
      {
        title: $r('app.string.napi_async_init'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_async_destroy'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_make_callback'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_open_callback_scope'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_close_callback_scope'),
        url: 'pages/image/basicSample/image2Gray'
      }

    ]
  }


export const ASYNC_CATEGORIES: ThirdLevelCategory[] =
  [
    SIMPLE_ASYNCRONOUS_OPERATIONS,
    CUSTOM_ASYNCRONOUS_OPERATIONS
  ]
