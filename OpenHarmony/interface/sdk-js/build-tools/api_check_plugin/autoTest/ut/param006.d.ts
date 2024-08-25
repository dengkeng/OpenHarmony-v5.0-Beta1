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
 * @namespace dataUriUtils
 * @syscap SystemCapability.Ability.AbilityRuntime.Core
 * @since 7
 */
declare namespace dataUriUtils {

  /**
   * A test case for param tag's legal -more
   *
   * @param { string } uri Indicates the uri string from which the ID is to be obtained.
   * @param { number } id Indicates the ID to attach.
   * @param { test34 } test34 Indicates the ID to attach.
   * @syscap SystemCapability.Ability.AbilityRuntime.Core
   * @since 7
   * @deprecated since 9
   * @useinstead ohos.app.ability.dataUriUtils/dataUriUtils#attachId
   */
  function attachId(uri: string, id: number): void;
}