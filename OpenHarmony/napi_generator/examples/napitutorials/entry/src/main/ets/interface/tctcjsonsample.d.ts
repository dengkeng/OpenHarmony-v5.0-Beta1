/*
 * Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { TcBase } from './tctbase'

type cJSON_bool = number;
// 对应cJSON.h中: typedef struct cJSON {}
export interface cJSON {
  next: cJSON | null;
  prev: cJSON | null;
  child: cJSON | null;
  type: number;
  valuestring: string;
  valueint: number;
  valuedouble: number;
  string: string;
}

export interface TcCJsonSample extends TcBase {
  name: string;
  cjson_version: () => string;

  // 对应cJSON.h中: CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value); 方法的dts接口
  KH418_cJSON_Parse: (value: string) => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(int) cJSON_GetArraySize(const cJSON *array); 方法的dts接口
  KH373_cJSON_GetArraySize: (array: cJSON) => number;
  // 对应cJSON.h中: CJSON_PUBLIC(char *) cJSON_Print(const cJSON *item); 方法的dts接口
  KH735_cJSON_Print: (item: cJSON) => string;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void); 方法的dts接口
  KH361_cJSON_CreateObject: () => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string); 方法的dts接口
  KH515_cJSON_CreateString: (string: string) => cJSON;
  // 对应cJSON.h中:CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string); 方法的dts接口
  KH526_cJSON_AddStringToObject: (object: cJSON, name: string, string: string) => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number); 方法的dts接口
  KH206_cJSON_AddNumberToObject: (object: cJSON, name: string, number: number) => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name); 方法的dts接口
  KH545_cJSON_AddFalseToObject: (object: cJSON, name: string) => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item); 方法的dts接口
  KH180_cJSON_AddItemToObject:(object: cJSON, string: string, item: cJSON) => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void); 方法的dts接口
  KH386_cJSON_CreateArray:() => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON *) cJSON_CreateIntArray(const int *numbers, int count); 方法的dts接口
  KH203_cJSON_CreateIntArray:(numbers: number[], count: number) => cJSON;
  // 对应cJSON.h中: CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item); 方法的dts接口
  KH802_cJSON_AddItemToArray:(array: cJSON, item: cJSON) => cJSON;
}