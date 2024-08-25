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

const WORK_WITH_JAVASCRIPT_VALUES: ThirdLevelCategory =
  {
    image: $r('app.media.ic_button_and_selection'),
    title: $r('app.string.work_with_javascript_values'),
    childNodes: [
      {
        title: $r('app.string.enum_napi_key_collection_mode'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.enum_napi_key_filter'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.enum_napi_key_conversion'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.enum_napi_valuetype'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.enum_napi_typedarray_type'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_array'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_array_with_length'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_arraybuffer'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_buffer'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_buffer_copy'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_date'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_external'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_external_arraybuffer'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_external_buffer'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_object'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_symbol'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.node_api_symbol_for'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_typedarray'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_dataview'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_int32'),
        url: 'pages/javascript/jsvalues/napicreateint32'
      },
      {
        title: $r('app.string.napi_create_uint32'),
        url: 'pages/javascript/jsvalues/napicreateuint32'
      },
      {
        title: $r('app.string.napi_create_int64'),
        url: 'pages/javascript/jsvalues/napicreateint64'
      },
      {
        title: $r('app.string.napi_create_double'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_bigint_int64'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_bigint_uint64'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_bigint_words'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_string_latin1'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.node_api_create_external_string_latin1'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_string_utf16'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.node_api_create_external_string_utf16'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_create_string_utf8'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_array_length'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_arraybuffer_info'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_buffer_info'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_prototype'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_typedarray_info'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_dataview_info'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_date_value'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_bool'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_double'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_bigint_int64'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_bigint_uint64'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_bigint_words'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_external'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_int32'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_int64'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_string_latin1'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_string_utf8'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_string_utf16'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_value_uint32'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_boolean'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_global'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_null'),
        url: 'pages/image/basicSample/edgeDetection'
      },
      {
        title: $r('app.string.napi_get_undefined'),
        url: 'pages/image/basicSample/edgeDetection'
      }
    ]
  }

const WORK_WITH_JAVASCRIPT_VALUES_AND_ABSTRACT_OPERATIONS: ThirdLevelCategory =
  {
    image: $r('app.media.ic_information_presentation_and_dynamic_effects'),
    title: $r('app.string.work_with_javascript_values_and_abstract_operations'),
    childNodes: [
      {
        title: $r('app.string.napi_coerce_to_bool'),
        url: 'pages/javascript/jsabstractops/napicoercetobool'
      },
      {
        title: $r('app.string.napi_coerce_to_number'),
        url: 'pages/javascript/jsabstractops/napicoercetonumber'
      },
      {
        title: $r('app.string.napi_coerce_to_object'),
        url: 'pages/javascript/jsabstractops/napicoercetoobject'
      },
      {
        title: $r('app.string.napi_coerce_to_string'),
        url: 'pages/javascript/jsabstractops/napicoercetostring'
      },
      {
        title: $r('app.string.napi_typeof'),
        url: 'pages/javascript/jsabstractops/napitypeof'
      },
      {
        title: $r('app.string.napi_instanceof'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_array'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_arraybuffer'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_buffer'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_date'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_error'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_typedarray'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_dataview'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_strict_equals'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_detach_arraybuffer'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_is_detached_arraybuffer'),
        url: 'pages/image/basicSample/image2Gray'
      }
    ]
  }
const WORK_WITH_JAVASCRIPT_PROPERTIES: ThirdLevelCategory =
  {
    image: $r('app.media.ic_text_and_input'),
    title: $r('app.string.work_with_javascript_properties'),
    childNodes: [
      {
        title: $r('app.string.napi_property_attributes'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_property_descriptor'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_get_property_names'),
        url: 'pages/javascript/jsproperties/napigetpropertynames'
      },
      {
        title: $r('app.string.napi_get_all_property_names'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_set_property'),
        url: 'pages/javascript/jsproperties/napisetproperty'
      },
      {
        title: $r('app.string.napi_get_property'),
        url: 'pages/javascript/jsproperties/napigetproperty'
      },
      {
        title: $r('app.string.napi_has_property'),
        url: 'pages/javascript/jsproperties/napihasproperty'
      },
      {
        title: $r('app.string.napi_delete_property'),
        url: 'pages/javascript/jsproperties/napideleteproperty'
      },
      {
        title: $r('app.string.napi_has_own_property'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_set_named_property'),
        url: 'pages/javascript/jsproperties/napisetnamedproperty'
      },
      {
        title: $r('app.string.napi_get_named_property'),
        url: 'pages/javascript/jsproperties/napigetnamedproperty'
      },
      {
        title: $r('app.string.napi_has_named_property'),
        url: 'pages/javascript/jsproperties/napihasnamedproperty'
      },
      {
        title: $r('app.string.napi_set_element'),
        url: 'pages/javascript/jsproperties/napisetelement'
      },
      {
        title: $r('app.string.napi_get_element'),
        url: 'pages/javascript/jsproperties/napigetelement'
      },
      {
        title: $r('app.string.napi_has_element'),
        url: 'pages/javascript/jsproperties/napihaselement'
      },
      {
        title: $r('app.string.napi_delete_element'),
        url: 'pages/javascript/jsproperties/napideleteelement'
      },
      {
        title: $r('app.string.napi_define_properties'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_object_freeze'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_object_seal'),
        url: 'pages/image/basicSample/image2Gray'
      }
    ]
  }
const WORK_WITH_JAVASCRIPT_FUNCTIONS: ThirdLevelCategory =
  {
    image: $r('app.media.ic_rows_and_columns'),
    title: $r('app.string.work_with_javasript_functions'),
    childNodes: [
      {
        title: $r('app.string.napi_call_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_create_function'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_get_cb_info'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_get_new_target'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_new_instance'),
        url: 'pages/image/basicSample/image2Gray'
      }

    ]
  }
const OBJECT_WRAP: ThirdLevelCategory =
  {
    image: $r('app.media.ic_rows_and_columns'),
    title: $r('app.string.object_wrap'),
    childNodes: [
      {
        title: $r('app.string.napi_define_class'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_wrap'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_unwrap'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_remove_wrap'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_type_tag_object'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_check_object_type_tag'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.napi_add_finalizer'),
        url: 'pages/image/basicSample/image2Gray'
      },
      {
        title: $r('app.string.node_api_post_finalizer'),
        url: 'pages/image/basicSample/image2Gray'
      }

    ]
  }

export const JAVASCRIPT_API_CATEGORIES: ThirdLevelCategory[] =
  [
    WORK_WITH_JAVASCRIPT_VALUES,
    WORK_WITH_JAVASCRIPT_VALUES_AND_ABSTRACT_OPERATIONS,
    WORK_WITH_JAVASCRIPT_PROPERTIES,
    WORK_WITH_JAVASCRIPT_FUNCTIONS,
    OBJECT_WRAP
  ]
