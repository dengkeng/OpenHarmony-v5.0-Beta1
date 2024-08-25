/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

/**
 * the ut for parent node has two or more JsDoc, some child nodes have two or more JsDoc
 * 
 * @since 7
 */
/**
 * @since 8
 */
export enum Test {
  /**
   * @since 6
   */
  /**
   * @since 7
   */
  id,
  
  /**
   * @since 7
   */
  /**
   * @since 8
   */
  name,

  /**
   * @since 7
   */
  age = 4,

  /**
   * @since 9
   */
  address,

  /**
   * @since 9
   */
  school = 5,

  /**
   * @since 9
   */
  city,
}