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
 * @file
 * @kit InputKit
 */

import { Callback } from './@ohos.base';
import { MouseEvent } from './@ohos.multimodalInput.mouseEvent';
import type display from './@ohos.display';
import type { TouchEvent } from './@ohos.multimodalInput.touchEvent';
import type { Rotate, Pinch, ThreeFingersSwipe, FourFingersSwipe } from './@ohos.multimodalInput.gestureEvent';
import type { ThreeFingersTap } from './@ohos.multimodalInput.gestureEvent';
import type { FingerprintEvent } from './@ohos.multimodalInput.shortKey';

/**
 * Global input event listener
 * System API, available only to system processes
 *
 * @namespace inputMonitor
 * @permission ohos.permission.INPUT_MONITORING
 * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
 * @systemapi hide for inner use
 * @since 7
 */
declare namespace inputMonitor {
  /**
   * Callback used to receive touch input events. If **true** is returned, the touch input is consumed,
   * and the system performs the closing operation.
   *
   * @interface TouchEventReceiver
   * @permission ohos.permission.INPUT_MONITORING
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 7
   */
  interface TouchEventReceiver {
    /**
     * Callback used to receive touch input events.
     *
     * @param { TouchEvent } touchEvent - the reported touch event.
     * @returns { Boolean } Returns true indicates the touch input is consumed, the value false indicates opposite.
     * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
     * @systemapi hide for inner use
     * @since 7
     */
    (touchEvent: TouchEvent): Boolean;
  }

  /**
   * Listens for touch input events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'touch' } type - Event type, which is **touch**.
   * @param { TouchEventReceiver } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @throws { BusinessError } 201 - Permission denied.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 7
   */
  function on(type: 'touch', receiver: TouchEventReceiver): void;

  /**
   * Listens for mouse input events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'mouse' } type - Event type, which is **mouse**.
   * @param { Callback<MouseEvent> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @throws { BusinessError } 201 - Permission denied.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 9
   */
  function on(type: 'mouse', receiver: Callback<MouseEvent>): void;

  /**
   * Listens for mouse input events when the mouse arrow is within the specified rectangular area.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'mouse' } type - Event type, which is **mouse**.
   * @param { display.Rect[] } rect - A specified rectangular area that can trigger a callback, with a maximum of two.
   * @param { Callback<MouseEvent> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 11
   */
  function on(type: 'mouse', rect: display.Rect[], receiver: Callback<MouseEvent>): void;

  /**
   * Cancel listening for touch input events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'touch' } type - Event type, which is **touch**.
   * @param { TouchEventReceiver } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @throws { BusinessError } 201 - Permission denied.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 7
   */
  function off(type: 'touch', receiver?: TouchEventReceiver): void;

  /**
   * Cancel listening for mouse input events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'mouse' } type - Event type, which is **mouse**.
   * @param { Callback<MouseEvent> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @throws { BusinessError } 201 - Permission denied.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 9
   */
  function off(type: 'mouse', receiver?: Callback<MouseEvent>): void;

  /**
   * Listens for touchPad pinch events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'pinch' } type - Event type, which is **pinch**.
   * @param { Callback<Pinch> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 10
   */
  function on(type: 'pinch', receiver: Callback<Pinch>): void;

  /**
   * Cancel listening for touchPad pinch events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'pinch' } type - Event type, which is **pinch**.
   * @param { Callback<Pinch> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 10
   */
  function off(type: 'pinch', receiver?: Callback<Pinch>): void;

  /**
   * Listens for touchPad fingers pinch events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'pinch' } type - Event type, which is **pinch**.
   * @param { number } fingers - the number of fingers.
   * @param { Callback<Pinch> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 11
   */
  function on(type: 'pinch', fingers: number, receiver: Callback<Pinch>): void;

  /**
   * Cancel listening for touchPad fingers pinch events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'pinch' } type - Event type, which is **pinch**.
   * @param { number } fingers - the number of fingers.
   * @param { Callback<Pinch> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 11
   */
  function off(type: 'pinch', fingers: number, receiver?: Callback<Pinch>): void;

  /**
   * Listens for touchPad fingers rotate events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'rotate' } type - Event type, which is **rotate**.
   * @param { number } fingers - the number of fingers.
   * @param { Callback<Rotate> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 11
   */
  function on(type: 'rotate', fingers: number, receiver: Callback<Rotate>): void;

  /**
   * Cancel listening for touchPad fingers rotate events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'rotate' } type - Event type, which is **rotate**.
   * @param { number } fingers - the number of fingers.
   * @param { Callback<Rotate> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 11
   */
  function off(type: 'rotate', fingers: number, receiver?: Callback<Rotate>): void;

  /**
   * Listens for touchPad three fingers swipe events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'threeFingersSwipe' } type - Event type, which is **threeFingersSwipe**.
   * @param { Callback<ThreeFingersSwipe> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 10
   */
  function on(type: 'threeFingersSwipe', receiver: Callback<ThreeFingersSwipe>): void;

  /**
   * Cancel listening touchPad three fingers swipe events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'threeFingersSwipe' } type - Event type, which is **threeFingersSwipe**.
   * @param { Callback<ThreeFingersSwipe> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 10
   */
  function off(type: 'threeFingersSwipe', receiver?: Callback<ThreeFingersSwipe>): void;

  /**
   * Listens for touchPad four fingers swipe events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'fourFingersSwipe' } type - Event type, which is **fourFingersSwipe**..
   * @param { Callback<FourFingersSwipe> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 10
   */
  function on(type: 'fourFingersSwipe', receiver: Callback<FourFingersSwipe>): void;

  /**
   * Cancel listening touchPad four finger swipe events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'fourFingersSwipe' } type - Event type, which is **fourFingersSwipe**.
   * @param { Callback<FourFingersSwipe> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 10
   */
  function off(type: 'fourFingersSwipe', receiver?: Callback<FourFingersSwipe>): void;

  /**
   * Listens for touchPad three fingers tap events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'threeFingersTap' } type - Event type, which is **threeFingersTap**.
   * @param { Callback<ThreeFingersTap> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 11
   */
  function on(type: 'threeFingersTap', receiver: Callback<ThreeFingersTap>): void;

  /**
   * Cancel listening touchPad three fingers tap events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'threeFingersTap' } type - Event type, which is **threeFingersTap**.
   * @param { Callback<ThreeFingersTap> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 11
   */
  function off(type: 'threeFingersTap', receiver?: Callback<ThreeFingersTap>): void;

  /**
   * Enables listening for fingerprint key events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'fingerprint' } type - Event type, which is **fingerprint**.
   * @param { Callback<FingerprintEvent> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 12
   */
  function on(type: 'fingerprint', receiver: Callback<FingerprintEvent>): void;

  /**
   * Cancels listening for fingerprint key events.
   *
   * @permission ohos.permission.INPUT_MONITORING
   * @param { 'fingerprint' } type - Event type, which is **fingerprint**.
   * @param { Callback<FingerprintEvent> } receiver - Callback used to receive the reported data.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - SystemAPI permit error.
   * @throws { BusinessError } 401 - Parameter error.
   * @syscap SystemCapability.MultimodalInput.Input.InputMonitor
   * @systemapi hide for inner use
   * @since 12
   */
  function off(type: 'fingerprint', receiver?: Callback<FingerprintEvent>): void;
}
export default inputMonitor;
