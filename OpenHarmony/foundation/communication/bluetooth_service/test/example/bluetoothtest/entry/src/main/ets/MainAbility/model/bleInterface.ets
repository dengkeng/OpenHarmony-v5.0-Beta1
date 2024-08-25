/**
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
 * BLE Test interface Of Bluetooth test
 */

import BluetoothModel from './BluetoothModel'
import bluetooth from '@ohos.bluetooth';
import promptAction from '@ohos.promptAction';
import { BleScanFilter , CurScanOptions } from '../../Utils/common'

let gattServerInstance: bluetooth.GattServer;

export function testCreateGattServerDevice(): string {
  try {
    let message = "createGattServerDevice test"
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      message = "createGattServer starts";
      if ( !gattServerInstance ) {
        gattServerInstance = BluetoothModel.createGattServer();
        message = "createGattServer: succeeds.";
      } else {
        message = "GattServer existed!";
      }
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testCreateGattServerDevice. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testCreateGattServerDevice. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

let gattClientDeviceInstance: bluetooth.GattClientDevice

export function testCreateGattClientDevice(): string {
  try {
    let message = "test createGattClientDevice"
    let btState = bluetooth.getState();
    let peripheralDeviceId: string = AppStorage.get('peripheralDeviceId') !;
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      message = "createGattClient start"
      if ( !gattClientDeviceInstance ) {
        gattClientDeviceInstance = BluetoothModel.createGattClient(peripheralDeviceId);
        message = "createGattClient:succeeds.";
      } else {
        message = "gattClient existed!";
      }
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testCreateGattClientDevice. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testCreateGattClientDevice. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGetConnectedBLEDevices(): string {
  try {
    let connectedBleDevices = BluetoothModel.getConnectedBLEDevices();
    let message = "getConnectedBLEDevices" + JSON.stringify(connectedBleDevices);
    console.log("getConnectedBLEDevices" + JSON.stringify(connectedBleDevices))
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGetConnectedBLEDevices. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetConnectedBLEDevices. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testStartBLEScan(): string {
  try {
    console.log("StartBLEScan -------------------------------")
    let btState = bluetooth.getState();
    let message = "test startBLEScan"
    if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      return message;
    }
    let txtScanFilter_deviceId: string = AppStorage.get('txtScanFilterDeviceId') !;
    let txtScanFilter_name: string = AppStorage.get('txtScanFilterName') !;
    let txtScanFilter_serviceUuid: string = AppStorage.get('txtScanFilterServiceUuid') !;
    let txtScanOptions_interval: string = AppStorage.get('txtScanOptions_interval') !;
    let txtScanOptions_dutyMode: string = AppStorage.get('txtScanOptionsDutyMode') !;
    let txtScanOptions_matchMode: string = AppStorage.get('txtScanOptionsMatchMode') !;
    let cbxBleScanFilter: boolean = AppStorage.get('cbxBleScanFilter') !;
    let cbxBleScanOptions: boolean = AppStorage.get('cbxBleScanOptions') !;
    let curScanFilters: Array<bluetooth.ScanFilter> = [];
    let bleScanFilter: BleScanFilter = {
      deviceId : txtScanFilter_deviceId ,
      name : txtScanFilter_name ,
      serviceUuid : txtScanFilter_serviceUuid
    }
    let curScanOptions: CurScanOptions = {
      interval : parseInt(txtScanOptions_interval) ,
      dutyMode : parseInt(txtScanOptions_dutyMode) ,
      matchMode : parseInt(txtScanOptions_matchMode)
    }
    if ( cbxBleScanFilter ) {
      curScanFilters.push(bleScanFilter);
    }

    if ( !cbxBleScanOptions ) {
      if ( cbxBleScanFilter ) {
        BluetoothModel.startBLEScan(curScanFilters);
        message = "startBLEScan Filters:" + JSON.stringify(curScanFilters);
      } else {
        BluetoothModel.startBLEScan(null);
        message = "startBLEScan(null)";
      }
    } else {
      BluetoothModel.startBLEScan(curScanFilters , curScanOptions);
      message = "startBLEScan Filters:" + JSON.stringify(curScanFilters) + "\n" + "Options:" + JSON.stringify(curScanOptions);
    }
    console.log("StartBLEScan end-------------------------------")
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testStartBLEScan. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testStartBLEScan. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testStopBLEScan(): string {
  try {
    BluetoothModel.stopBLEScan();
    let message = "stopBLEScan OK!";
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testStopBLEScan. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testStopBLEScan. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

let bleDeviceFind = false

export function testOnBLEDeviceFind(): string {
  try {
    let message = "onBLEDeviceFind test"
    if ( bleDeviceFind ) {
      BluetoothModel.unsubscribeBLEDeviceFind();
      message = '关闭BLE查找状态变化'
      promptAction.showToast({ message : message })
    } else {
      BluetoothModel.subscribeBLEDeviceFind((deviceItems: Array<bluetooth.ScanResult>) => {
        console.log("BLE Test:" + 'available ble devices changed.');
        let message = ""
        let availBleDeviceIds: Array<string> = []
        deviceItems?.forEach(deviceItem => {
          let newDevice = deviceItem.deviceId;
          message += "mac:" + newDevice;
          console.log("BLE Test:" + 'available bluetooth new device : ' + newDevice);
          availBleDeviceIds.push(newDevice);
        })
        AppStorage.setOrCreate('bluetoothAvailableDevices' , availBleDeviceIds);
        promptAction.showToast({ message : message })
      })
      message = "打开BLE查找状态变化"
      promptAction.showToast({ message : message })
    }
    bleDeviceFind = !bleDeviceFind
    return message
  } catch( e ) {
    console.log(`Failed to testOnBLEDeviceFind. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnBLEDeviceFind. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}
