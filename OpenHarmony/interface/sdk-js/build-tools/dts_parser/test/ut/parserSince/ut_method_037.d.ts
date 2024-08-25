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
 * the ut for method in interface, method is promise
 */
export interface Test {
  /**
   * the ut for method in interface, method has permission
   * 
   * @permission ohos.permission.GRANT_SENSITIVE_PERMISSIONS
   */
  test(param1: string): Promise<Want>;

  /**
   * the ut for method in interface, method has permissions
   * 
   * @permission ohos.permission.GET_SENSITIVE_PERMISSIONS or ohos.permission.GRANT_SENSITIVE_PERMISSIONS or ohos.permission.REVOKE_SENSITIVE_PERMISSIONS
   */
  test(param1: string): Promise<Want>;

  /**
   * the ut for method in interface, method has permissions
   * 
   * @permission
   */
  test(param1: string): Promise<Want>;
}