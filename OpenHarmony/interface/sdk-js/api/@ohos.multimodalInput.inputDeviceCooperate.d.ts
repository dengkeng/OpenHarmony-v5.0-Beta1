/*
* Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

/**
 * @file
 * @kit InputKit
 */

import { AsyncCallback } from "./@ohos.base";

/**
 * Events for input devices
 * 
 * @since 9
 * @syscap SystemCapability.MultimodalInput.Input.Cooperator
 */


declare namespace inputDeviceCooperate {
  /**
   * Enumerates mouse traversal events.
   * 
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use.
   */
  enum EventMsg {
    /**
     * Mouse traversal message: mouse traversal is enabled.
     *
     * @since 9
    */
    MSG_COOPERATE_INFO_START = 200,

    /**
     * Mouse traversal message: mouse traversal is successful.
     *
     * @since 9
    */
    MSG_COOPERATE_INFO_SUCCESS = 201,

    /**
     * Mouse traversal message: mouse traversal fails.
     *
     * @since 9
    */
    MSG_COOPERATE_INFO_FAIL = 202,

    /**
     * Mouse traversal status: mouse traversal is enabled.
     *
     * @since 9
    */
    MSG_COOPERATE_STATE_ON = 500,

    /**
     * Mouse traversal status: mouse traversal is disabled.
     *
     * @since 9
    */
    MSG_COOPERATE_STATE_OFF = 501,
  }

  /**
   * Enable or disable the mouse traversal.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param enable Whether to enable mouse traversal.
   * @param callback Asynchronous callback function.
   * @throws {BusinessError} 401 - Parameter error.
   */
  function enable(enable: boolean, callback: AsyncCallback<void>): void;

  /**
   * Enable or disable the mouse traversal.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param enable Whether to enable mouse traversal.
   * @throws {BusinessError} 401 - Parameter error.
   */
  function enable(enable: boolean): Promise<void>;

  /**
   * Starts mouse traversal.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param sinkDeviceDescriptor Descriptor of the target network for mouse traversal.
   * @param srcInputDeviceId Identifier of the peripheral device for mouse traversal.
   * @param callback Asynchronous callback function.
   * @throws {BusinessError} 401 - Parameter error.
   * @throws {BusinessError} 4400001 - Incorrect descriptor for the target device.
   * @throws {BusinessError} 4400002 - Screen hop failed.
   */
  function start(sinkDeviceDescriptor: string, srcInputDeviceId: number, callback: AsyncCallback<void>): void;

  /**
   * Starts mouse traversal.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param sinkDeviceDescriptor Descriptor of the target network for mouse traversal.
   * @param srcInputDeviceId Identifier of the peripheral device for mouse traversal.
   * @throws {BusinessError} 401 - Parameter error.
   * @throws {BusinessError} 4400001 - Incorrect descriptor for the target device.
   * @throws {BusinessError} 4400002 - Screen hop failed.
   */
  function start(sinkDeviceDescriptor: string, srcInputDeviceId: number): Promise<void>;

  /**
   * Stops mouse traversal.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param callback Asynchronous callback function.
   * @throws {BusinessError} 401 - Parameter error.
   */
  function stop(callback: AsyncCallback<void>): void;

  /**
   * Stops mouse traversal.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   */
  function stop(): Promise<void>;

  /**
   * Obtains the status of the mouse traversal switch.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param deviceDescriptor Descriptor of the target network for mouse traversal.
   * @param callback Asynchronous callback used to receive the status of the mouse traversal switch.
   * @throws {BusinessError} 401 - Parameter error.
   */
  function getState(deviceDescriptor: string, callback: AsyncCallback<{ state: boolean }>): void;

  /**
   * Obtains the status of the mouse traversal switch.
   *
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param deviceDescriptor Descriptor of the target network for mouse traversal.
   * @throws {BusinessError} 401 - Parameter error.
   */
  function getState(deviceDescriptor: string): Promise<{ state: boolean }>;

  /**
   * Enables listening for mouse traversal events.
   * 
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param type Registration type.
   * @param callback Asynchronous callback used to receive mouse traversal events.
   * @returns Callback for the input device event.
   * @throws {BusinessError} 401 - Parameter error.
   */
  function on(type: 'cooperation', callback: AsyncCallback<{ deviceDescriptor: string, eventMsg: EventMsg }>): void;

  /**
   * Disables listening for mouse traversal events.
   * 
   * @since 9
   * @syscap SystemCapability.MultimodalInput.Input.Cooperator
   * @systemapi hide for inner use
   * @param type Registration type.
   * @param callback Asynchronous callback used to return the result.
   * @throws {BusinessError} 401 - Parameter error.
   */
  function off(type: 'cooperation', callback?: AsyncCallback<void>): void;

}

export default inputDeviceCooperate;