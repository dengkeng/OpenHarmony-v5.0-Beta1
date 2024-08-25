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
 * GattClient Interface Of Bluetooth test
 */

import bluetooth from '@ohos.bluetooth';
import BluetoothModel from './BluetoothModel'
import { BusinessError } from '@ohos.base';
import promptAction from '@ohos.promptAction';

interface Descriptor {
  serviceUuid: string;
  characteristicUuid: string;
  descriptorUuid: string;
  descriptorValue: ArrayBufferLike;
}

interface BleCharacteristicDataIn {
  serviceUuid: string;
  characteristicUuid: string;
  characteristicValue: ArrayBuffer;
  descriptors: Descriptor[];
}

interface Characteristic {
  serviceUuid: string;
  characteristicUuid: string;
  characteristicValue: ArrayBufferLike;
}

let gattClientInstance: bluetooth.GattClientDevice

export function testCreateGattClient(): string {
  try {
    let message = "createGattClient test "
    let peripheralDeviceId: string = AppStorage.get('peripheralDeviceId') !;
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_ON || btState === bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( gattClientInstance ) {
        message = "GattClient exists!";
        promptAction.showToast({ message : message })
        return message;
      }
      //注册回调
      bluetooth.BLE.on("BLEDeviceFind" , (scanResult) => {
        scanResult.forEach(device => {
          let devId = device.deviceId; //6c:96:d7:3d:87:6f
          let rssi = device.rssi;
          let data = device.data;
          promptAction.showToast({ message : "findDevice:" + devId })
          if ( devId == peripheralDeviceId ) {
            bluetooth.BLE.stopBLEScan();
            // create ble client instance
            if ( !gattClientInstance ) {
              gattClientInstance = BluetoothModel.createGattClient(devId);
              message = "createGattClient succeeds ";
              console.log("createGattClient succeeds----------")
            }
          }
        })
      })
      if ( peripheralDeviceId && peripheralDeviceId.length > 15 ) {
        gattClientInstance = BluetoothModel.createGattClient(peripheralDeviceId.toUpperCase());
        if ( gattClientInstance ) {
          message = "createGattClient: " + peripheralDeviceId;
          console.log("createGattClient peripheralDeviceId succeeds----------")
        } else {
          message = "createGattClient:fail ";
        }
      } else {
        message = "peripheralDeviceId invalid! ";
      }
      promptAction.showToast({ message : message })
    } else if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
    } else {
      message = "switching,please wait"
      promptAction.showToast({ message : message })
    }
    return message
  } catch( e ) {
    console.log(`Failed to testCreateGattClient. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testCreateGattClient. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

let bleConnectionState = 0;

export function testConnect(): string {
  try {
    let message = "connect test";
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_ON || btState === bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( gattClientInstance ) {
        if ( bleConnectionState == 0 ) {
          console.log("GattClient.connect: start----------------")
          let ret: boolean = gattClientInstance.connect();
          message = "GattClient.connect: " + ret;
          console.log("GattClient.connect: end----------------" + ret)
          bleConnectionState = 2
        } else {
          message = "this device is not disconnected!";
        }
      } else {
        message = "NO_GATT_CLIENT_OBJECT";
      }
    } else if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testConnect. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testConnect. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testDisconnect(): string {
  try {
    let message = "test disconnect";
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( !gattClientInstance ) {
        message = "NO_GATT_CLIENT_OBJECT";
        promptAction.showToast({ message : message })
        return message;
      }
      if ( bleConnectionState == 2 ) {
        let ret: boolean = gattClientInstance.disconnect();
        message = "GattClient.disconnect: " + ret;
      } else {
        message = " BLE is not connected and no need to disconnect it ";
      }
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testDisconnect. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testDisconnect. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

let BLEConnectionStateChange = false

export function testOnBLEConnectionStateChange(): string {
  try {
    let message = "onBLEConnectionStateChange test";
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    message = " HAVE_GATT_CLIENT_OBJECT "
    if ( BLEConnectionStateChange ) {
      gattClientInstance.off('BLEConnectionStateChange' , () => {
        promptAction.showToast({ message : "off:BLEConnectionStateChange" })
      })
      message = "关闭BLE连接状态变化"
    } else {
      let bleConnectionStateInfo = "xxxx"
      gattClientInstance.on('BLEConnectionStateChange' , (bleConnectionState: bluetooth.BLEConnectChangedState) => {
        switch ( bleConnectionState.state ) {
          case bluetooth.ProfileConnectionState.STATE_DISCONNECTED:
            bleConnectionStateInfo = "DISCONNECTED";
            break;
          case bluetooth.ProfileConnectionState.STATE_CONNECTING:
            bleConnectionStateInfo = "CONNECTING";
            break;
          case bluetooth.ProfileConnectionState.STATE_CONNECTED:
            bleConnectionStateInfo = "STATE_CONNECTED";
            break;
          case bluetooth.ProfileConnectionState.STATE_DISCONNECTING:
            bleConnectionStateInfo = "STATE_DISCONNECTING";
            break;
          default:
            bleConnectionStateInfo = "UNDEFINED!";
            break;
        }
        console.log("gattClientInstance.onBLEConnectionStateChange is ------- " + JSON.stringify(bleConnectionState))
        AppStorage.setOrCreate('bleConnectionStateInfo' , bleConnectionStateInfo);
        promptAction.showToast({ message : "状态:" + bleConnectionStateInfo })
      })
      message = "打开BLE连接状态变化"
    }
    BLEConnectionStateChange = !BLEConnectionStateChange
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testOnBLEConnectionStateChange. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnBLEConnectionStateChange. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGattClientClose(): string {
  try {
    let message = "gattClientClose test"
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( !gattClientInstance ) {
        message = "NO_GATT_CLIENT_OBJECT";
        promptAction.showToast({ message : message })
        return message;
      }
      let ret: boolean = gattClientInstance.close();
      // if ( ret ) {
      //   gattClientInstance = null;
      // }
      message = "GattClient.close:" + ret;
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGattClientClose. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGattClientClose. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGetServicesCallback(): string {
  try {
    let message = "getServicesCallback test"
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( !gattClientInstance ) {
        message = "NO_GATT_CLIENT_OBJECT";
        promptAction.showToast({ message : message })
        return message;
      }
      console.log("connectState ")
      console.log("getServices(call back) start-----------------")
      gattClientInstance.getServices((err: BusinessError , gattServices: Array<bluetooth.GattService>) => {
        if ( err.code != 0 ) {
          message = "getServices(call back) error code:" + err.code + ",services :" + gattServices;
          console.log("getServices(call back) error code:-----------------" + err.code + ",services :" + gattServices)
          promptAction.showToast({ message : message })
          //        return message;
        } else {
          let services: Array<bluetooth.GattService> = gattServices;
          message = "getServices(Callback):invoke succeeds! " + "\n"
          console.log("bluetooth services size is " , services.length)
          message += "bluetooth services size is " + services.length + '\n';
          for ( let i = 0 ; i < services.length ; i ++ ) {
            message += 'serviceUuid is ' + services[ i ].serviceUuid + '\n';
          }
          promptAction.showToast({ message : message })
          AppStorage.setOrCreate("getServices" , message)
          console.log("getServices(Callback)----------" + message)
        }
      })
      console.log("getServices(call back) end-----------------")
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGetServicesCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetServicesCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGetServicesPromise(): string {
  try {
    let message = "getServicesPromise test"
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    message = "getServices promise:starts";
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      console.log("gattClientInstance.getServices,promise start----------")
      gattClientInstance.getServices().then((result: Array<bluetooth.GattService>) => {
        console.log("getServices(): Promise<Array<GattService>> start --------------")
        message = "getServicesPromise successfully:\n"
        console.info("getServices successfully:" + JSON.stringify(result));
        let services: Array<bluetooth.GattService> = result;
        message = "bluetooth services size is " + services.length + "\n";
        console.log("bluetooth services size is " + services.length)
        for ( let i = 0 ; i < services.length ; i ++ ) {
          message += 'serviceUuid is ' + services[ i ].serviceUuid + '\n';
        }
        console.log("getServices(): Promise<Array<GattService>> end --------------")
        promptAction.showToast({ message : message })
      }).catch((err: BusinessError) => {
        console.log("testGetServicesPromise err:" + err)
      })
      console.log("gattClientInstance.getServices,promise end----------")
      message = "getServices(promise):invoke succeeds!";
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGetServicesPromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetServicesPromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testReadCharacteristicValueCallback(): string {
  try {
    let serviceUUID: string = AppStorage.get('serviceUUID') !;
    let characteristicUUID: string = AppStorage.get('characteristicUUID') !;
    let descriptorUUID: string = AppStorage.get('descriptorUUID') !;
    let descriptorValue: string = AppStorage.get('descriptorValue') !;
    let message = "readCharacteristicValueCallback test"
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    let descriptors: Array<bluetooth.BLEDescriptor> = [];
    let bufferCCC = new ArrayBuffer(8);
    let cccV = new Uint8Array(bufferCCC);
    cccV[ 0 ] = 66;
    let descriptor: Descriptor = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      descriptorUuid : descriptorUUID ,
      descriptorValue : string2ArrayBuffer(descriptorValue)
    }
    descriptors.push(descriptor);
    let bleCharacteristicDataIn: BleCharacteristicDataIn = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      characteristicValue : bufferCCC ,
      descriptors : descriptors
    };
    console.log("gattClientInstance.readCharacteristicValue ,callback start--------------")
    gattClientInstance.readCharacteristicValue(bleCharacteristicDataIn , (err: BusinessError , bleCharacteristicDataOut: bluetooth.BLECharacteristic) => {
      if ( err.code != 0 ) {
        message = "readCharacteristicValue error code:" + err.code + ",id:" + serviceUUID;
        console.log(message)
        promptAction.showToast({ message : message })
      }
      message = "callback success!:" + "\n";
      message += 'characteristic uuid:' + bleCharacteristicDataOut.characteristicUuid + "\n";
      console.log(message)
      let value = new Uint8Array(bleCharacteristicDataOut.characteristicValue);
      for ( let i = 0 ; i < bleCharacteristicDataOut.characteristicValue.byteLength ; i ++ ) {
        message += 'characteristic value: ' + value[ i ] + "\n";
      }
      AppStorage.setOrCreate("read_CharacteristicValue" , message)
      promptAction.showToast({ message : message })
    });
    console.log("gattClientInstance.readCharacteristicValue ,callback end--------------")
    message = 'readCharacteristicValue(callback):invoke succeeds!';
    console.log(message)
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testReadCharacteristicValueCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testReadCharacteristicValueCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testReadCharacteristicValuePromise(): string {
  try {
    let serviceUUID: string = AppStorage.get('serviceUUID') !;
    let characteristicUUID: string = AppStorage.get('characteristicUUID') !;
    let descriptorUUID: string = AppStorage.get('descriptorUUID') !;
    let descriptorValue: string = AppStorage.get('descriptorValue') !;
    let message = "readCharacteristicValuePromise test"
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    let descriptors: Array<bluetooth.BLEDescriptor> = [];
    let bufferCCC = new ArrayBuffer(8);
    let cccV = new Uint8Array(bufferCCC);
    cccV[ 0 ] = 66;
    let descriptor: bluetooth.BLEDescriptor = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      descriptorUuid : descriptorUUID ,
      descriptorValue : string2ArrayBuffer(descriptorValue)
    }
    descriptors.push(descriptor);
    let bleCharacteristicDataIn: bluetooth.BLECharacteristic = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      characteristicValue : bufferCCC ,
      descriptors : descriptors
    };
    console.log("gattClientInstance.readCharacteristicValue ,promise start--------------")
    gattClientInstance.readCharacteristicValue(bleCharacteristicDataIn)
      .then((bleCharacteristicDataOut: bluetooth.BLECharacteristic) => {
        message = "promise success!:\n"
        message += 'characteristic uuid:' + bleCharacteristicDataOut.characteristicUuid + "\n";
        console.log(message)
        let value = new Uint8Array(bleCharacteristicDataOut.characteristicValue);
        for ( let i = 0 ; i < bleCharacteristicDataOut.characteristicValue.byteLength ; i ++ ) {
          message += 'characteristic value: ' + value[ i ] + "\n";
        }
        promptAction.showToast({ message : message })
      })
      .catch((err: BusinessError) => {
        console.log("testReadCharacteristicValuePromise error :" + err)
      });
    console.log("gattClientInstance.readCharacteristicValue ,promise end--------------")
    message = 'readCharacteristicValue(promise):invoke succeeds!';
    console.log(message)
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testReadCharacteristicValuePromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testReadCharacteristicValuePromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testReadDescriptorValueCallback(): string {
  try {
    let serviceUUID: string = AppStorage.get('serviceUUID') !;
    let characteristicUUID: string = AppStorage.get('characteristicUUID') !;
    let descriptorUUID: string = AppStorage.get('descriptorUUID') !;
    let descriptorValue: string = AppStorage.get('descriptorValue') !;
    let message = "readDescriptorValueCallback test"
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
    }
    let bufferDesc = new ArrayBuffer(8);
    let descV = new Uint8Array(bufferDesc);
    descV[ 0 ] = 88;
    let descriptorIn: Descriptor = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      descriptorUuid : descriptorUUID ,
      descriptorValue : string2ArrayBuffer(descriptorValue)
    };
    console.log("gattClientInstance.readDescriptorValue,callback start--------------")
    gattClientInstance.readDescriptorValue(descriptorIn , (err: BusinessError , descriptorOut: bluetooth.BLEDescriptor) => {
      let message = ""
      if ( err.code != 0 ) {
        message = "readDescriptorValue error:" + err.code.toString()
        console.log(message)
        promptAction.showToast({ message : message })
      }
      message = "\n" + "callback:descriptor uuid=" + descriptorOut.descriptorUuid + "\n";
      let value = new Uint8Array(descriptorOut.descriptorValue);
      for ( let i = 0 ; i < descriptorOut.descriptorValue.byteLength ; i ++ ) {
        message += 'descriptor value: ' + value[ i ] + "\n";
      }
      AppStorage.setOrCreate("read_DescriptorValue" , message)
      promptAction.showToast({ message : message })
    });
    console.log("gattClientInstance.readDescriptorValue ,callback end--------------")
    message = 'readDescriptorValue(callback):invoke succeeds!';
    console.log(message)
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testReadDescriptorValueCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testReadDescriptorValueCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testReadDescriptorValuePromise(): string {
  try {
    let serviceUUID: string = AppStorage.get('serviceUUID') !;
    let characteristicUUID: string = AppStorage.get('characteristicUUID') !;
    let descriptorUUID: string = AppStorage.get('descriptorUUID') !;
    let descriptorValue: string = AppStorage.get('descriptorValue') !;
    let message = "readDescriptorValuePromise test "
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    let bufferDesc = new ArrayBuffer(8);
    let descV = new Uint8Array(bufferDesc);
    descV[ 0 ] = 99;
    let descriptorIn: Descriptor = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      descriptorUuid : descriptorUUID ,
      //    descriptorValue: bufferDesc
      descriptorValue : string2ArrayBuffer(descriptorValue)
    };
    console.log("gattClientInstance.readDescriptorValue,promise start--------------")
    gattClientInstance.readDescriptorValue(descriptorIn).then((descriptorOut: bluetooth.BLEDescriptor) => {
      message = "\n" + 'promise:descriptor uuid=' + descriptorOut.descriptorUuid + "\n";
      let value = new Uint8Array(descriptorOut.descriptorValue);
      for ( let i = 0 ; i < descriptorOut.descriptorValue.byteLength ; i ++ ) {
        message += 'descriptor value: ' + value[ i ] + "\n";
      }
      AppStorage.setOrCreate("read_DescriptorValue" , message)
      promptAction.showToast({ message : message })
    }).catch((err: BusinessError) => {
      console.log("testReadDescriptorValuePromise error :" + err)
    });
    console.log("gattClientInstance.readDescriptorValue,promise end--------------")
    message = 'readDescriptorValue(promise):invoke succeeds!';
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testReadDescriptorValuePromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testReadDescriptorValuePromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testWriteCharacteristicValue(): string {
  try {
    let serviceUUID: string = AppStorage.get('serviceUUID') !;
    let characteristicUUID: string = AppStorage.get('characteristicUUID') !;
    let descriptorUUID: string = AppStorage.get('descriptorUUID') !;
    let descriptorValue: string = AppStorage.get('descriptorValue') !;
    let message: string = "writeCharacteristicValue test"
    let btState: number = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    let descriptors: Array<bluetooth.BLEDescriptor> = [];
    let bufferCCC = new ArrayBuffer(8);
    let cccV = new Uint8Array(bufferCCC);
    cccV[ 0 ] = 66;
    let descriptor: Descriptor = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      descriptorUuid : descriptorUUID ,
      descriptorValue : string2ArrayBuffer(descriptorValue)
    }
    descriptors.push(descriptor);
    let bleCharacteristicDataIn: BleCharacteristicDataIn = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      characteristicValue : bufferCCC ,
      descriptors : descriptors
    };
    if ( gattClientInstance.writeCharacteristicValue(bleCharacteristicDataIn) ) {
      message = 'writeCharacteristicValue succeeds.';
    } else {
      message = 'writeCharacteristicValue failed!';
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testWriteCharacteristicValue. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testWriteCharacteristicValue. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function string2ArrayBuffer(str: string) {
  let array = new Uint8Array(str.length);
  for ( let i = 0 ; i < str.length ; i ++ ) {
    array[ i ] = str.charCodeAt(i);
  }
  return array.buffer
}

export function testWriteDescriptorValue(): string {
  try {
    let serviceUUID: string = AppStorage.get('serviceUUID') !;
    let characteristicUUID: string = AppStorage.get('characteristicUUID') !;
    let descriptorUUID: string = AppStorage.get('descriptorUUID') !;
    let descriptorValue: string = AppStorage.get('descriptorValue') !;
    let message = "writeDescriptorValue test"
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    let bufferDesc = string2ArrayBuffer(descriptorValue);
    let descriptor: Descriptor = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      descriptorUuid : descriptorUUID ,
      descriptorValue : bufferDesc
    };
    if ( gattClientInstance.writeDescriptorValue(descriptor) ) {
      message = 'writeDescriptorValue succeeds.';
    }
    else {
      message = 'writeDescriptorValue,failed!';
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testWriteDescriptorValue. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testWriteDescriptorValue. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//回调函数
let BLECharacteristicChange = false

export function testOnBLECharacteristicChange(): string {
  try {
    let message = "onBLECharacteristicChange test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }

    if ( BLECharacteristicChange ) {
      gattClientInstance.off('BLECharacteristicChange' , () => {
        message = "off BLECharacteristicChange"
        promptAction.showToast({ message : message })
      })
    } else {
      gattClientInstance.on('BLECharacteristicChange' , (data: bluetooth.BLECharacteristic) => {
        let serviceUuid: string = data.serviceUuid;
        let characteristicUuid: string = data.characteristicUuid;
        let bleCharacteristicChangeInfo = "serviceUuid:" + serviceUuid + "\n";
        bleCharacteristicChangeInfo += "characteristicUuid:" + characteristicUuid + "\n";
        let value = new Uint8Array(data.characteristicValue);
        for ( let i = 0 ; i < data.characteristicValue.byteLength ; i ++ ) {
          bleCharacteristicChangeInfo += "\n" + 'value:' + value[ i ]
        }
        AppStorage.setOrCreate("bleCharacteristicChangeInfo" , bleCharacteristicChangeInfo)
        promptAction.showToast({ message : "on:BLECharacteristicChange" })
      })
      message = "On BLECharacteristicChange"
    }
    BLECharacteristicChange = !BLECharacteristicChange
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testOnBLECharacteristicChange. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnBLECharacteristicChange. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSetBLEMtuSize(): String {
  try {
    let message = "setBLEMtuSize test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }

    message = 'setBLEMtuSize: \n';
    let mtuSize = 256;
    let ret: boolean = gattClientInstance.setBLEMtuSize(mtuSize);
    message += "result : " + ret;
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSetBLEMtuSize. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSetBLEMtuSize. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSetNotifyCharacteristicChanged(): String {
  try {
    let serviceUUID: string = AppStorage.get('serviceUUID') !;
    let characteristicUUID: string = AppStorage.get('characteristicUUID') !;
    let descriptorUUID: string = AppStorage.get('descriptorUUID') !;
    let descriptorValue: string = AppStorage.get('descriptorValue') !;
    let message = "setNotifyCharacteristicChanged test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message;
    }
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }

    let descriptors: Array<bluetooth.BLEDescriptor> = [];
    let bufferCCC = new ArrayBuffer(8);
    let cccV = new Uint8Array(bufferCCC);
    cccV[ 0 ] = 66;
    let descriptor: Descriptor = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      descriptorUuid : descriptorUUID ,
      descriptorValue : string2ArrayBuffer(descriptorValue)
    }
    descriptors.push(descriptor);
    let characteristicIn: BleCharacteristicDataIn = {
      serviceUuid : serviceUUID ,
      characteristicUuid : characteristicUUID ,
      characteristicValue : bufferCCC ,
      descriptors : descriptors
    };
    if ( gattClientInstance.setNotifyCharacteristicChanged(characteristicIn , true) ) {
      message = "setNotifyCharacteristicChanged(true):succeeds."
    } else {
      message = "setNotifyCharacteristicChanged(true):failed!"
      if ( gattClientInstance.setNotifyCharacteristicChanged(characteristicIn , false) ) {
        message = "setNotifyCharacteristicChanged(false):true!"
      } else {
        message = "setNotifyCharacteristicChanged(false):false!"
      }
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSetNotifyCharacteristicChanged. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSetNotifyCharacteristicChanged. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGetDeviceNameCallback(): String {
  try {
    let deviceName = ""
    let message = "getDeviceNameCallback test"
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    //currentClick = 15;
    console.log("gattClientInstance.getDeviceName,callback start-----------------")
    gattClientInstance.getDeviceName((err: BusinessError , asyncRemoteDeviceName: string) => {
      message = "return code:"
      message += JSON.stringify(err);
      message += ",and DeviceName is: "
      message += JSON.stringify(asyncRemoteDeviceName);
      deviceName = JSON.stringify(asyncRemoteDeviceName)
      AppStorage.setOrCreate("deviceName" , deviceName)
      promptAction.showToast({ message : message })
    });
    console.log("gattClientInstance.getDeviceName,callback end-----------------")
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGetDeviceNameCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetDeviceNameCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGetDeviceNamePromise(): String {
  try {
    let deviceName = ""
    let message = "getDeviceNamePromise test"
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    console.log("gattClientInstance.getDeviceName,promise start-----------------")
    gattClientInstance.getDeviceName().then((peripheralDeviceName: string) => {
      message = "getDeviceName()Promise:" + peripheralDeviceName;
      deviceName = peripheralDeviceName
      AppStorage.setOrCreate("deviceName" , deviceName)
      promptAction.showToast({ message : message })
    }).catch((err: BusinessError) => {
      console.log("testGetDeviceNamePromise error :" + err)
    });
    console.log("gattClientInstance.getDeviceName,promise end-----------------")
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGetDeviceNamePromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetDeviceNamePromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGetRssiValueCallback(): String {
  try {
    let Rssi = ""
    let message = "getRssiValueCallback test"
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }

    message = "getRssiValue callback";
    console.log("gattClientInstance.getRssiValue,callback start-----------------")
    gattClientInstance.getRssiValue((err: BusinessError , cbRssi: number) => {
      message = "return code:"
      message += JSON.stringify(err);
      message += ",and RSSI="
      message += JSON.stringify(cbRssi);
      Rssi = JSON.stringify(cbRssi);
      AppStorage.setOrCreate("Rssi" , Rssi)
      promptAction.showToast({ message : message })
    });
    console.log("gattClientInstance.getRssiValue,callback end-----------------")
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGetRssiValueCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetRssiValueCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGetRssiValuePromise(): String {
  try {
    let Rssi = ""
    let message = "getRssiValuePromise test"
    if ( !gattClientInstance ) {
      message = "NO_GATT_CLIENT_OBJECT";
      promptAction.showToast({ message : message })
      return message;
    }
    message = "getRssiValue promise:";
    console.log("gattClientInstance.getRssiValue,promise start-----------------")
    gattClientInstance.getRssiValue().then((rssiValue: number) => {
      message += 'rssi' + JSON.stringify(rssiValue)
      Rssi = JSON.stringify(rssiValue)
      AppStorage.setOrCreate("Rssi" , Rssi)
      promptAction.showToast({ message : message })
    }).catch((err: BusinessError) => {
      console.log("testGetRssiValuePromise error :" + err)
    });
    console.log("gattClientInstance.getRssiValue,promise  end-----------------")
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGetRssiValuePromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetRssiValuePromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}