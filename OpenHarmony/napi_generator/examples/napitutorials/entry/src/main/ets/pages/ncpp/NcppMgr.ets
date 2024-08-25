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

const CJSON_MANAGEMENT: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.cjson_management'),
    childNodes: [
      {
        title: $r('app.string.napi_get_node_version'),
        url: 'pages/ncpp/cjsonfuncs/cjsonfuncs'
      },
      {
        title: $r('app.string.napi_parse_json_string'),
        url: 'pages/ncpp/cjsonfuncs/cjsonparse'
      },
      {
        title: $r('app.string.napi_print_json_string'),
        url: 'pages/ncpp/cjsonfuncs/cjsonprint'
      },
      {
        title: $r('app.string.napi_create_json_string'),
        url: 'pages/ncpp/cjsonfuncs/cjsoncreatestring'
      },
      {
        title: $r('app.string.napi_create_json_object'),
        url: 'pages/ncpp/cjsonfuncs/cjsoncreateobject'
      },
      {
        title: $r('app.string.napi_add_string_to_object'),
        url: 'pages/ncpp/cjsonfuncs/cjsonaddstringtoobject'
      },
      {
        title: $r('app.string.napi_add_number_to_object'),
        url: 'pages/ncpp/cjsonfuncs/cjsonaddnumbertoobject'
      },
      {
        title: $r('app.string.napi_add_false_to_object'),
        url: 'pages/ncpp/cjsonfuncs/cjsonaddfalsetoobject'
      },
      {
        title: $r('app.string.napi_add_item_to_object'),
        url: 'pages/ncpp/cjsonfuncs/cjsonadditemtoobject'
      },
      {
        title: $r('app.string.napi_cjson_sample_test1'),
        url: 'pages/ncpp/cjsonfuncs/cjsonsampletest1'
      },
      {
        title: $r('app.string.napi_create_json_array'),
        url: 'pages/ncpp/cjsonfuncs/cjsoncreatearray'
      },
      {
        title: $r('app.string.napi_create_json_int_array'),
        url: 'pages/ncpp/cjsonfuncs/cjsoncreateintarray'
      },
      {
        title: $r('app.string.napi_add_item_to_array'),
        url: 'pages/ncpp/cjsonfuncs/cjsonadditemtoarray'
      },
      {
        title: $r('app.string.napi_cjson_sample_test2'),
        url: 'pages/ncpp/cjsonfuncs/cjsonsampletest2'
      },
      {
        title: $r('app.string.napi_cjson_sample_test3'),
        url: 'pages/ncpp/cjsonfuncs/cjsonsampletest3'
      },
    ]
  }

const FFMPEG_MANAGEMENT: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.ffmpeg_management'),
    childNodes: [
      {
        title: $r('app.string.napi_egl_texture_bmp'),
        url: 'pages/ncpp/ffmpegfuncs/eglfuncs'
      },
      {
        title: $r('app.string.napi_ffmpeg_decode'),
        url: 'pages/ncpp/ffmpegfuncs/ffmpegfuncs'
      }
    ]
  }

const OPENCV_MANAGEMENT: ThirdLevelCategory =
  {
    image: $r('app.media.ic_list_and_grid'),
    title: $r('app.string.opencv_management'),
    childNodes: [
      {
        title: $r('app.string.napi_opencv_gray'),
        url: 'pages/ncpp/opencvfuncs/opencvfuncs'
      }
    ]
  }


export const NCPP_CATEGORIES: ThirdLevelCategory[] =
  [
    CJSON_MANAGEMENT,
    FFMPEG_MANAGEMENT,
    OPENCV_MANAGEMENT
  ]
