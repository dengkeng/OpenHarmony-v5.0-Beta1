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

const VERSION_MANAGEMENT: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.version_management'),
    childNodes: [
      {
        title: $r('app.string.napi_get_node_version'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_get_version'),
        url: 'pages/image/basicSample/image2Gray'
      }
    ]
  }
const MEMORY_MANAGEMENT: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.memory_management'),
    childNodes: [
      {
        title: $r('app.string.napi_adjust_external_memory'),
        url: 'pages/image/basicSample/image2Gray'
      }

    ]
  }
const PROMISE: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.promise'),
    childNodes: [
      {
        title: $r('app.string.napi_create_promise'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_resolve_deferred'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_reject_deferred'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_promise'),
        url: 'pages/image/basicSample/image2Gray'
      }
    ]
  }
const SCRIPT_EXECUTION: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.script_execution'),
    childNodes: [
      {
        title: $r('app.string.napi_run_script'),
        url: 'pages/image/basicSample/image2Gray'
      }

    ]
  }
const LIBUV_EVENT_LOOP: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.libuv_event_loop'),
    childNodes: [
      {
        title: $r('app.string.napi_get_uv_event_loop'),
        url: 'pages/image/basicSample/image2Gray'
      }

    ]
  }
const ASYNCRONOUS_THREAD_SAFE_FUNCTION_CALL: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.asyncronous_thread_safe_function_call'),
    childNodes: [
      {
        title: $r('app.string.calling_a_thread_safe_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.refrence_counting_of_thread_safe_functions'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.deciding_whether_to_keep_the_process_running'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_create_threadsafe_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_get_threadsafe_function_context'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_call_threadsafe_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_acquire_threadsafe_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_release_threadsafe_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_ref_threadsafe_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_unref_threadsafe_function'),
        url: 'pages/image/basicSample/image2Gray'
      }
    ]
  }
const MISCELLANEOUS_UTILITIES: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.miscellaneous_utilities'),
    childNodes: [
      {
        title: $r('app.string.node_api_get_module_file_name'),
        url: 'pages/image/basicSample/image2Gray'
      }

    ]
  }

export const OTHER_CATEGORIES: ThirdLevelCategory[] =
  [
    VERSION_MANAGEMENT,
    MEMORY_MANAGEMENT,
    PROMISE,
    SCRIPT_EXECUTION,
    LIBUV_EVENT_LOOP,
    ASYNCRONOUS_THREAD_SAFE_FUNCTION_CALL,
    MISCELLANEOUS_UTILITIES
  ]
