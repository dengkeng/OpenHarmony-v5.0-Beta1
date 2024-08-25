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

const ENVIRONMENT_LIFE_CYCLE_APIS: ThirdLevelCategory =
  {
    image: $r('app.media.ic_button_and_selection'),
    title: $r('app.string.environment_life_cycle_apis'),
    childNodes: [
      {
        title: $r('app.string.napi_set_instance_data'),
        url: 'pages/nodeapi/envlifecycleapis/napisetinstancedata'
      },
      {
        title: $r('app.string.napi_get_instance_data'),
        url: 'pages/nodeapi/envlifecycleapis/napigetinstancedata'
      }
    ]
  }

const BASIC_NODE_API_DATA_TYPES: ThirdLevelCategory =
  {
    image: $r('app.media.ic_button_click'),
    title: $r('app.string.basic_node_api_data_types'),
    childNodes: [
      {
        title: $r('app.string.napi_status'),
        url: 'pages/nodeapi/datatypes/napistatus'
      },
      {
        title: $r('app.string.napi_extended_error_info'),
        url: 'pages/nodeapi/datatypes/napiextendederrorinfo'
      },
      {
        title: $r('app.string.napi_env'),
        url: 'pages/nodeapi/datatypes/napienv'
      },
      {
        title: $r('app.string.napi_value'),
        url: 'pages/nodeapi/datatypes/napivalue'
      },
      {
        title: $r('app.string.napi_threadsafe_function'),
        url: 'pages/nodeapi/datatypes/napithreadsafefunc'
      },
      {
        title: $r('app.string.napi_threadsafe_function_release_mode'),
        url: 'pages/nodeapi/datatypes/napithreadsafefuncrel'
      },
      {
        title: $r('app.string.napi_threadsafe_function_call_mode'),
        url: 'pages/nodeapi/datatypes/napithreadsafefuncall'
      }
    ]
  }
const NODE_API_MEMORY_MANAGEMENT_TYPES: ThirdLevelCategory =
  {
    image: $r('app.media.ic_prop_size'),
    title: $r('app.string.node_api_memory_management_types'),
    childNodes: [
      {
        title: $r('app.string.napi_handle_scope'),
        url: 'pages/nodeapi/memmgrtyps/napihandlescope'
      },
      {
        title: $r('app.string.napi_escapable_handle_scope'),
        url: 'pages/nodeapi/memmgrtyps/napiescapablehandlescope'
      },
      {
        title: $r('app.string.napi_ref'),
        url: 'pages/nodeapi/memmgrtyps/napiref'
      },
      {
        title: $r('app.string.napi_type_tag'),
        url: 'pages/nodeapi/memmgrtyps/napitypetag'
      },
      {
        title: $r('app.string.napi_async_cleanup_hook_handle'),
        url: 'pages/nodeapi/memmgrtyps/napiasynccleanuphookhandle'
      }
    ]
  }
const NODE_API_CALLBACK_TYPES: ThirdLevelCategory =
  {
    image: $r('app.media.ic_event_load_and_hide'),
    title: $r('app.string.node_api_callback_types'),
    childNodes: [
      {
        title: $r('app.string.napi_callback_info'),
        url: 'pages/nodeapi/callbacktypes/napicallbackinfo'
      },
      {
        title: $r('app.string.napi_callback'),
        url: 'pages/nodeapi/callbacktypes/napicallback'
      },
      {
        title: $r('app.string.napi_finalize'),
        url: 'pages/nodeapi/callbacktypes/napifinalize'
      },
      {
        title: $r('app.string.napi_async_execute_callback'),
        url: 'pages/nodeapi/callbacktypes/napiasyncexecutecallback'
      },
      {
        title: $r('app.string.napi_async_complete_callback'),
        url: 'pages/nodeapi/callbacktypes/napiasynccompletecallback'
      },
      {
        title: $r('app.string.napi_threadsafe_function_call_js'),
        url: 'pages/nodeapi/callbacktypes/napithreadsafefunctioncalljs'
      },
      {
        title: $r('app.string.napi_cleanup_hook'),
        url: 'pages/nodeapi/callbacktypes/napicleanuphook'
      },
      {
        title: $r('app.string.napi_async_cleanup_hook'),
        url: 'pages/nodeapi/callbacktypes/napiasynccleanuphook'
      }
    ]
  }
const NODE_API_ERROR_HANDLING_RETURN_VALUES: ThirdLevelCategory =
  {
    image: $r('app.media.ic_other'),
    title: $r('app.string.node_api_error_handling_return_values'),
    childNodes: [
      {
        title: $r('app.string.napi_get_last_error_info'),
        url: 'pages/nodeapi/errretvalues/napigetlasterrorinfo'
      }
    ]
  }
const NODE_API_ERROR_HANDLING_EXCEPTIONS: ThirdLevelCategory =
  {
    image: $r('app.media.ic_select_option_collection'),
    title: $r('app.string.node_api_error_handling_exception'),
    childNodes: [
      {
        title: $r('app.string.napi_throw'),
        url: 'pages/nodeapi/errretexceptions/napithrow'
      },
      {
        title: $r('app.string.napi_throw_error'),
        url: 'pages/nodeapi/errretexceptions/napithrowerror'
      },
      {
        title: $r('app.string.napi_throw_type_error'),
        url: 'pages/nodeapi/errretexceptions/napithrowtypeerror'
      },
      {
        title: $r('app.string.napi_throw_range_error'),
        url: 'pages/nodeapi/errretexceptions/napithrowrangeerror'
      },
      {
        title: $r('app.string.node_api_throw_syntax_error'),
        url: 'pages/nodeapi/errretexceptions/napithrowsyntaxerror'
      },
      {
        title: $r('app.string.napi_is_error'),
        url: 'pages/nodeapi/errretexceptions/napiiserror'
      },
      {
        title: $r('app.string.napi_create_error'),
        url: 'pages/nodeapi/errretexceptions/napicreateerror'
      },
      {
        title: $r('app.string.napi_create_type_error'),
        url: 'pages/nodeapi/errretexceptions/napicreatetypeerror'
      },
      {
        title: $r('app.string.napi_create_range_error'),
        url: 'pages/nodeapi/errretexceptions/napicreaterangeerror'
      },
      {
        title: $r('app.string.node_api_create_syntax_error'),
        url: 'pages/nodeapi/errretexceptions/napicreatesyntaxrror'
      },
      {
        title: $r('app.string.napi_get_and_clear_last_exception'),
        url: 'pages/nodeapi/errretexceptions/napigetandclearlastexception'
      },
      {
        title: $r('app.string.napi_is_exception_pending'),
        url: 'pages/nodeapi/errretexceptions/napiisexceptionpending'
      },
      {
        title: $r('app.string.napi_fatal_exception'),
        url: 'pages/nodeapi/errretexceptions/napifatalexception'
      }
    ]
  }
const NODE_API_ERROR_HANDLING_FATAL_ERRORS: ThirdLevelCategory =
  {
    image: $r('app.media.ic_select_option_gesture'),
    title: $r('app.string.node_api_error_handling_fatal_errors'),
    childNodes: [
      {
        title: $r('app.string.napi_fatal_error'),
        url: 'pages/nodeapi/errretfatalerrors/napifatalerror'
      }
    ]
  }
const NODE_API_OBJECT_LIFETIME_MANAGEMENT: ThirdLevelCategory =
  {
    image: $r('app.media.ic_select_option_picture'),
    title: $r('app.string.node_api_object_lifetime_management'),
    childNodes: [
      {
        title: $r('app.string.Making_handle_lifespan_shorter_than_that_of_the_native_method'),
        url: 'pages/nodeapi/objlifetimemgr/makingthannativemethod'
      },
      {
        title: $r('app.string.napi_open_handle_scope'),
        url: 'pages/nodeapi/objlifetimemgr/napiopenhandlescope'
      },
      {
        title: $r('app.string.napi_close_handle_scope'),
        url: 'pages/nodeapi/objlifetimemgr/napiclosehandlescope'
      },
      {
        title: $r('app.string.napi_open_escapable_handle_scope'),
        url: 'pages/nodeapi/objlifetimemgr/napiopenescapablehandlescope'
      },
      {
        title: $r('app.string.napi_close_escapable_handle_scope'),
        url: 'pages/nodeapi/objlifetimemgr/napicloseescapablehandlescope'
      },
      {
        title: $r('app.string.napi_escape_handle'),
        url: 'pages/nodeapi/objlifetimemgr/napiescapehandle'
      },
      {
        title: $r('app.string.references_to_values_with_a_lifespan_longer_than_that_of_the_native_method'),
        url: 'pages/nodeapi/objlifetimemgr/reftovaluelongerthannativemethod'
      },
      {
        title: $r('app.string.napi_create_reference'),
        url: 'pages/nodeapi/objlifetimemgr/napicreatereference'
      },
      {
        title: $r('app.string.napi_delete_reference'),
        url: 'pages/nodeapi/objlifetimemgr/napideletereference'
      },
      {
        title: $r('app.string.napi_reference_ref'),
        url: 'pages/nodeapi/objlifetimemgr/napireferenceref'
      },
      {
        title: $r('app.string.napi_reference_unref'),
        url: 'pages/nodeapi/objlifetimemgr/napireferenceunref'
      },
      {
        title: $r('app.string.napi_get_reference_value'),
        url: 'pages/nodeapi/objlifetimemgr/napigetreferencevalue'
      },
      {
        title: $r('app.string.cleanup_on_exit_of_the_current_nodejs_environment'),
        url: 'pages/nodeapi/objlifetimemgr/cleanuponexit'
      },
      {
        title: $r('app.string.napi_add_env_cleanup_hook'),
        url: 'pages/nodeapi/objlifetimemgr/napiaddenvcleanuphook'
      },
      {
        title: $r('app.string.napi_remove_env_cleanup_hook'),
        url: 'pages/nodeapi/objlifetimemgr/napiremoveenvcleanuphook'
      },
      {
        title: $r('app.string.napi_add_async_cleanup_hook'),
        url: 'pages/nodeapi/objlifetimemgr/napiaddasynccleanuphook'
      },
      {
        title: $r('app.string.napi_remove_async_cleanup_hook'),
        url: 'pages/nodeapi/objlifetimemgr/napiremoveasynccleanuphook'
      },
      {
        title: $r('app.string.finalization_on_the_exit_of_the_nodejs_environment'),
        url: 'pages/nodeapi/objlifetimemgr/finalizationlonexit'
      }
    ]
  }
const NODE_API_MODULE_REGISTRATION: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.node_api_module_registration'),
    childNodes: [
      {
        title: $r('app.string.node_api_module_registration'),
        url: 'pages/nodeapi/modregisteration/nodeapimoduleregistration'
      }
    ]
  }
export const NODE_API_CATEGORIES: ThirdLevelCategory[] =
  [
    ENVIRONMENT_LIFE_CYCLE_APIS,
    BASIC_NODE_API_DATA_TYPES,
    NODE_API_MEMORY_MANAGEMENT_TYPES,
    NODE_API_CALLBACK_TYPES,
    NODE_API_ERROR_HANDLING_RETURN_VALUES,
    NODE_API_ERROR_HANDLING_EXCEPTIONS,
    NODE_API_ERROR_HANDLING_FATAL_ERRORS,
    NODE_API_OBJECT_LIFETIME_MANAGEMENT,
    NODE_API_MODULE_REGISTRATION
  ]
