/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
 * @typedef Configuration
 * @syscap SystemCapability.Ability.AbilityBase
 * @since 10
 */
export interface Configuration {
  /**
   * A test case for any keyword legal
   * @param { object } options - Indicates the authenticator-specific options for the request.
   * @syscap SystemCapability.Account.AppAccount
   * @since 10
   */
  addAccountImplicitly(options: { [key: string]: any }): void;
}