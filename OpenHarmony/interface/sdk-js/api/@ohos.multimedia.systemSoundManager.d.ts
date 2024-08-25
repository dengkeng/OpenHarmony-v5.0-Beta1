/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @kit AudioKit
 */

import type { AsyncCallback } from './@ohos.base';
import type Context from './application/Context';
import type BaseContext from './application/BaseContext';
import type { RingtonePlayer as _RingtonePlayer } from './multimedia/ringtonePlayer';
import type { RingtoneOptions as _RingtoneOptions } from './multimedia/ringtonePlayer';
import type { SystemTonePlayer as _SystemTonePlayer } from './multimedia/systemTonePlayer';
import type { SystemToneOptions as _SystemToneOptions } from './multimedia/systemTonePlayer';

/**
 * Provides ringtone player interfaces.
 *
 * @namespace systemSoundManager
 * @syscap SystemCapability.Multimedia.SystemSound.Core
 * @systemapi
 * @since 10
 */
declare namespace systemSoundManager {
  /**
   * Enum for ringtone type.
   * @enum { number }
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 10
   */
  enum RingtoneType {
    /**
     * Default type.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.RingtoneType#RINGTONE_TYPE_SIM_CARD_0
     */
    RINGTONE_TYPE_DEFAULT = 0,

    /**
     * Ringtone type for sim card 0.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    RINGTONE_TYPE_SIM_CARD_0 = 0,

    /**
     * Multi-sim type.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.RingtoneType#RINGTONE_TYPE_SIM_CARD_1
     */
    RINGTONE_TYPE_MULTISIM = 1,

    /**
     * Ringtone type for sim card 1.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    RINGTONE_TYPE_SIM_CARD_1 = 1,
  }

  /**
   * Enum for system tone type.
   * @enum { number }
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 11
   */
  enum SystemToneType {
    /**
     * System tone type for sim card 0.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    SYSTEM_TONE_TYPE_SIM_CARD_0 = 0,

    /**
     * System tone type for sim card 1.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    SYSTEM_TONE_TYPE_SIM_CARD_1 = 1,

    /**
     * System tone type notification.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    SYSTEM_TONE_TYPE_NOTIFICATION = 32,
  }

  /**
   * Gets system sound manager for all type sound.
   * @returns { SystemSoundManager } SystemSoundManager instance.
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 10
   */
  function getSystemSoundManager(): SystemSoundManager;

  /**
   * System sound manager object.
   * @typedef SystemSoundManager
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 10
   */
  interface SystemSoundManager {
    /**
     * Sets the ringtone uri to system.
     * @param { Context } context - Current application context.
     * @param { string } uri - Ringtone uri to set.
     * @param { RingtoneType } type - Ringtone type to set.
     * @param { AsyncCallback<void> } callback - Callback used to return the set uri result.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.SystemSoundManager#setRingtoneUri
     */
    setSystemRingtoneUri(context: Context, uri: string, type: RingtoneType, callback: AsyncCallback<void>): void;

    /**
     * Sets the ringtone uri to system.
     * @param { Context } context - Current application context.
     * @param { string } uri - Ringtone uri to set.
     * @param { RingtoneType } type - Ringtone type to set.
     * @returns { Promise<void> } Promise used to return the set uri result.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.SystemSoundManager#setRingtoneUri
     */
    setSystemRingtoneUri(context: Context, uri: string, type: RingtoneType): Promise<void>;

    /**
     * Sets the ringtone uri to system.
     * @param { BaseContext } context - Current application context.
     * @param { string } uri - Ringtone uri to set.
     * @param { RingtoneType } type - Ringtone type to set.
     * @returns { Promise<void> } Promise used to return the set uri result.
     * @throws { BusinessError } 202 - Caller is not a system application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     *         1.Mandatory parameters are left unspecified;
     *         2.Incorrect parameter types.
     * @throws { BusinessError } 5400103 - I/O error.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    setRingtoneUri(context: BaseContext, uri: string, type: RingtoneType): Promise<void>;

    /**
     * Gets the ringtone uri.
     * @param { Context } context - Current application context.
     * @param { RingtoneType } type - Ringtone type to get.
     * @param { AsyncCallback<string> } callback - Callback used to return the ringtone uri maintained in system.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.SystemSoundManager#getRingtoneUri
     */
    getSystemRingtoneUri(context: Context, type: RingtoneType, callback: AsyncCallback<string>): void;

    /**
     * Gets the ringtone uri.
     * @param { Context } context - Current application context.
     * @param { RingtoneType } type - Ringtone type to get.
     * @returns { Promise<string> } Promise used to return the ringtone uri maintained in system.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.SystemSoundManager#getRingtoneUri
     */
    getSystemRingtoneUri(context: Context, type: RingtoneType): Promise<string>;

    /**
     * Gets the ringtone uri.
     * @param { BaseContext } context - Current application context.
     * @param { RingtoneType } type - Ringtone type to get.
     * @returns { Promise<string> } Promise used to return the ringtone uri maintained in system.
     * @throws { BusinessError } 202 - Caller is not a system application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     *                                 1.Mandatory parameters are left unspecified;
     *                                 2.Incorrect parameter types.
     * @throws { BusinessError } 5400103 - I/O error.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    getRingtoneUri(context: BaseContext, type: RingtoneType): Promise<string>;

    /**
     * Gets the ringtone player.
     * @param { Context } context - Current application context.
     * @param { RingtoneType } type - Ringtone type to get.
     * @param { AsyncCallback<RingtonePlayer> } callback - Callback used to return a ringtone player instance.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.SystemSoundManager#getRingtonePlayer
     */
    getSystemRingtonePlayer(context: Context, type: RingtoneType, callback: AsyncCallback<RingtonePlayer>): void;

    /**
     * Gets the ringtone player.
     * @param { Context } context - Current application context.
     * @param { RingtoneType } type - Ringtone type to get.
     * @returns { Promise<RingtonePlayer> } Promise used to return a ringtone player instance.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 10
     * @deprecated since 11
     * @useinstead systemSoundManager.SystemSoundManager#getRingtonePlayer
     */
    getSystemRingtonePlayer(context: Context, type: RingtoneType): Promise<RingtonePlayer>;

    /**
     * Gets the ringtone player.
     * @param { BaseContext } context - Current application context.
     * @param { RingtoneType } type - Ringtone type to get.
     * @returns { Promise<RingtonePlayer> } Promise used to return a ringtone player instance.
     * @throws { BusinessError } 202 - Caller is not a system application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     *                                 1.Mandatory parameters are left unspecified;
     *                                 2.Incorrect parameter types.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    getRingtonePlayer(context: BaseContext, type: RingtoneType): Promise<RingtonePlayer>;

    /**
     * Sets the system tone uri to system.
     * @param { BaseContext } context - Current application context.
     * @param { string } uri - Ringtone uri to set.
     * @param { SystemToneType } type - System tone type to set.
     * @returns { Promise<void> } Promise used to return the result of set system tone uri.
     * @throws { BusinessError } 202 - Caller is not a system application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     *                                 1.Mandatory parameters are left unspecified;
     *                                 2.Incorrect parameter types.
     * @throws { BusinessError } 5400103 - I/O error.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    setSystemToneUri(context: BaseContext, uri: string, type: SystemToneType): Promise<void>;

    /**
     * Gets the system tone uri.
     * @param { BaseContext } context - Current application context.
     * @param { SystemToneType } type - System tone type to get.
     * @returns { Promise<string> } Promise used to return the system tone maintained in system.
     * @throws { BusinessError } 202 - Caller is not a system application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     *                                 1.Mandatory parameters are left unspecified;
     *                                 2.Incorrect parameter types.
     * @throws { BusinessError } 5400103 - I/O error.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    getSystemToneUri(context: BaseContext, type: SystemToneType): Promise<string>;

    /**
     * Gets the system tone player.
     * @param { BaseContext } context - Current application context.
     * @param { SystemToneType } type - System tone type to get.
     * @returns { Promise<SystemTonePlayer> } Promise used to return the SystemTonePlayer.
     * @throws { BusinessError } 202 - Caller is not a system application.
     * @throws { BusinessError } 401 - Parameter error. Possible causes:
     *                                 1.Mandatory parameters are left unspecified;
     *                                 2.Incorrect parameter types.
     * @syscap SystemCapability.Multimedia.SystemSound.Core
     * @systemapi
     * @since 11
     */
    getSystemTonePlayer(context: BaseContext, type: SystemToneType): Promise<SystemTonePlayer>;
  }

  /**
   * Ringtone player object.
   * @typedef { _RingtonePlayer } RingtonePlayer
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 10
   */
  type RingtonePlayer = _RingtonePlayer;

  /**
   * SystemTone player object.
   * @typedef { _SystemTonePlayer } SystemTonePlayer
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 11
   */
  type SystemTonePlayer = _SystemTonePlayer;

  /**
   * Interface for ringtone options.
   * @typedef { _RingtoneOptions } RingtoneOptions
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 10
   */
  type RingtoneOptions = _RingtoneOptions;

  /**
   * System tone options.
   * @typedef { _SystemToneOptions } SystemToneOptions
   * @syscap SystemCapability.Multimedia.SystemSound.Core
   * @systemapi
   * @since 11
   */
  type SystemToneOptions = _SystemToneOptions;
}

export default systemSoundManager;