/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
 * @kit NetworkKit
 */

import type { AsyncCallback, Callback } from './@ohos.base';
import type connection from './@ohos.net.connection';
import type _AbilityContext from './application/UIAbilityContext';

/**
 * Provides VPN related interfaces.
 * @namespace vpn
 * @syscap SystemCapability.Communication.NetManager.Vpn
 * @since 10
 */
declare namespace vpn {
  /**
   * Get network link information.
   * @syscap SystemCapability.Communication.NetManager.Core
   * @since 10
   */
  export type LinkAddress = connection.LinkAddress;

  /**
   * Get network route information.
   * @syscap SystemCapability.Communication.NetManager.Core
   * @since 10
   */
  export type RouteInfo = connection.RouteInfo;

  /**
   * The context of an ability. It allows access to ability-specific resources.
   * @syscap SystemCapability.Ability.AbilityRuntime.Core
   * @since 10
   */
  export type AbilityContext = _AbilityContext;

  /**
   * Create a VPN connection using the AbilityContext.
   * @param { AbilityContext } context - Indicates the context of application or capability.
   * @returns { VpnConnection } the VpnConnection of the construct VpnConnection instance.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @syscap SystemCapability.Communication.NetManager.Vpn
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function createVpnConnection(context: AbilityContext): VpnConnection;
 
  /**
   * Defines a VPN connection.
   * @interface VpnConnection
   * @syscap SystemCapability.Communication.NetManager.Vpn
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export interface VpnConnection {
    /**
     * Create a VPN network using the VpnConfig.
     * @permission ohos.permission.MANAGE_VPN
     * @param { VpnConfig } config - Indicates the {@link VpnConfig} configuration of the VPN network.
     * @param { AsyncCallback<number> } callback - The callback is used to return file descriptor of VPN interface.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 2200001 - Invalid parameter value.
     * @throws { BusinessError } 2200002 - Operation failed. Cannot connect to service.
     * @throws { BusinessError } 2200003 - System internal error.
     * @throws { BusinessError } 2203001 - VPN creation denied. Check the user type.
     * @throws { BusinessError } 2203002 - VPN already exists.
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    setUp(config: VpnConfig, callback: AsyncCallback<number>): void;
 
    /**
     * Create a VPN network using the VpnConfig.
     * @permission ohos.permission.MANAGE_VPN
     * @param { VpnConfig } config - Indicates the {@link VpnConfig} configuration of the VPN network.
     * @returns { Promise<number> } The promise returns file descriptor of VPN interface.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 2200001 - Invalid parameter value.
     * @throws { BusinessError } 2200002 - Operation failed. Cannot connect to service.
     * @throws { BusinessError } 2200003 - System internal error.
     * @throws { BusinessError } 2203001 - VPN creation denied. Check the user type.
     * @throws { BusinessError } 2203002 - VPN already exists.
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    setUp(config: VpnConfig): Promise<number>;
 
    /**
     * Protect a socket from VPN connections. After protecting, data sent through this socket will go directly to the
     * underlying network so its traffic will not be forwarded through the VPN.
     * @permission ohos.permission.MANAGE_VPN
     * @param { number } socketFd - File descriptor of socket, this socket from @ohos.net.socket.
     * @param { AsyncCallback<void> } callback - The callback of protect.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 2200001 - Invalid parameter value.
     * @throws { BusinessError } 2200002 - Operation failed. Cannot connect to service.
     * @throws { BusinessError } 2200003 - System internal error.
     * @throws { BusinessError } 2203004 - Invalid socket file descriptor.
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    protect(socketFd: number, callback: AsyncCallback<void>): void;
 
    /**
     * Protect a socket from VPN connections. After protecting, data sent through this socket will go directly to the
     * underlying network so its traffic will not be forwarded through the VPN.
     * @permission ohos.permission.MANAGE_VPN
     * @param { number } socketFd - File descriptor of socket, this socket from @ohos.net.socket.
     * @returns { Promise<void> } The promise returned by the function.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 2200001 - Invalid parameter value.
     * @throws { BusinessError } 2200002 - Operation failed. Cannot connect to service.
     * @throws { BusinessError } 2200003 - System internal error.
     * @throws { BusinessError } 2203004 - Invalid socket file descriptor.
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    protect(socketFd: number): Promise<void>;
 
    /**
     * Destroy the VPN network.
     * @permission ohos.permission.MANAGE_VPN
     * @param { AsyncCallback<void> } callback - The callback of destroy.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 2200002 - Operation failed. Cannot connect to service.
     * @throws { BusinessError } 2200003 - System internal error.
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    destroy(callback: AsyncCallback<void>): void;
 
    /**
     * Destroy the VPN network.
     * @permission ohos.permission.MANAGE_VPN
     * @returns { Promise<void> } The promise returned by the function.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 2200002 - Operation failed. Cannot connect to service.
     * @throws { BusinessError } 2200003 - System internal error.
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    destroy(): Promise<void>;
  }

  /**
   * Define configuration of the VPN network.
   * @interface VpnConfig
   * @syscap SystemCapability.Communication.NetManager.Vpn
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export interface VpnConfig {
    /**
     * The array of addresses for VPN interface.
     * @type {Array<LinkAddress>}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    addresses: Array<LinkAddress>;
 
    /**
     * The array of routes for VPN interface.
     * @type {?Array<RouteInfo>}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    routes?: Array<RouteInfo>;

    /**
     * The array of DNS servers for the VPN network.
     * @type {?Array<string>}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    dnsAddresses?: Array<string>;
 
    /**
     * The array of search domains for the DNS resolver.
     * @type {?Array<string>}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    searchDomains?: Array<string>;
 
    /**
     * The maximum transmission unit (MTU) for the VPN interface.
     * @type {?number}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    mtu?: number;
 
    /**
     * Whether ipv4 is supported. The default value is true.
     * @type {?boolean}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    isIPv4Accepted?: boolean;
 
    /**
     * Whether ipv6 is supported. The default value is false.
     * @type {?boolean}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    isIPv6Accepted?: boolean;
 
    /**
     * Whether to use the built-in VPN. The default value is false.
     * @type {?boolean}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    isLegacy?: boolean;
 
    /**
     * Whether the VPN interface's file descriptor is in blocking/non-blocking mode. The default value is false.
     * @type {?boolean}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    isBlocking?: boolean;
 
    /**
     * The array of trustlist for the VPN network. The string indicates package name.
     * @type {?Array<string>}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    trustedApplications?: Array<string>;
 
    /**
     * The array of blocklist for the VPN network. The string indicates package name.
     * @type {?Array<string>}
     * @syscap SystemCapability.Communication.NetManager.Vpn
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    blockedApplications?: Array<string>;
  }
}
export default vpn;
 
