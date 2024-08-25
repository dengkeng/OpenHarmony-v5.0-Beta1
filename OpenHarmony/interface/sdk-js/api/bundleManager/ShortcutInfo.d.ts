/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
 * @kit AbilityKit
 */

/**
 * Provides information about a shortcut, including the shortcut ID and label.
 *
 * @typedef ShortcutInfo
 * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
 * @systemapi
 * @since 9
 */
export interface ShortcutInfo {
  /**
   * Indicates the ID of the application to which this shortcut belongs
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly id: string;

  /**
   * Indicates the name of the bundle containing the shortcut
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly bundleName: string;

  /**
   * Indicates the moduleName of the shortcut
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly moduleName: string;

  /**
   * Indicates the host ability of the shortcut
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly hostAbility: string;

  /**
   * Indicates the icon of the shortcut
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly icon: string;

  /**
   * Indicates the icon id of the shortcut
   *
   * @type { number }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly iconId: number;

  /**
   * Indicates the label of the shortcut
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly label: string;

  /**
   * Indicates the label id of the shortcut
   *
   * @type { number }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly labelId: number;

  /**
   * Indicates the wants of the shortcut
   *
   * @type { Array<ShortcutWant> }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly wants: Array<ShortcutWant>;
}

/**
 * Obtains information about the ability that a shortcut will start.
 *
 * @typedef ShortcutWant
 * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
 * @systemapi
 * @since 9
 */
export interface ShortcutWant {
  /**
   * Indicates the target bundle of the shortcut want
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly targetBundle: string;

  /**
   * Indicates the target module of the shortcut want
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly targetModule: string;

  /**
   * Indicates the target ability of the shortcut want
   *
   * @type { string }
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 9
   */
  readonly targetAbility: string;

  /**
   * Indicates the parameters of the shortcut want
   *
   * @type { Array<ParameterItem> }
   * @readonly
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 12
   */
  readonly parameters: Array<ParameterItem>;
}

/**
 * Obtains information about the ability that a shortcut will start.
 *
 * @typedef ParameterItem
 * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
 * @systemapi
 * @since 12
 */
export interface ParameterItem {
  /**
   * Indicates the key of the parameter item.
   *
   * @type { string }
   * @readonly
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 12
   */
  readonly key: string;

  /**
   * Indicates the value of the parameter item.
   *
   * @type { string }
   * @readonly
   * @syscap SystemCapability.BundleManager.BundleFramework.Launcher
   * @systemapi
   * @since 12
   */
  readonly value: string;
}
