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
 * GattServer Interface Of Bluetooth test
 */

import bluetooth from '@ohos.bluetooth';
import BluetoothModel from './BluetoothModel'
import {
  Descriptor ,
  Characteristic ,
  CurGattService ,
  CurAdvSettings ,
  AdvDataManufactureDataInstance ,
  AdvDataServiceDataInstance ,
  CurAdvData ,
  AdvResponseManufactureDataInstance ,
  AdvResponseServiceDataInstance ,
  CurAdvResponse ,
  ServerResponse ,
  NotifyCharacteristic
} from '../../Utils/common'
import promptAction from '@ohos.promptAction';

let gattServerInstance :bluetooth.GattServer

export function testCreateGattServer(): string {
  try {
    let btState = bluetooth.getState();
    let message = "createGattServer test"
    if ( btState === bluetooth.BluetoothState.STATE_ON || btState === bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( gattServerInstance ) {
        message = "GattServer exists!";
        promptAction.showToast({ message : message })
        return message
      }
      console.log("CreateGattServer start -----------")
      gattServerInstance = BluetoothModel.createGattServer();
      message = "CreateGattServer:succeeds!";
      console.log("CreateGattServer:succeeds!-----------")
      promptAction.showToast({ message : message })
      return message
    } else if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testCreateGattServer. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testCreateGattServer. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testAddService(): string {
  try {
    let message = "addService test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message
    }
    if ( !gattServerInstance ) {
      message = "NO_GATT_Server_OBJECT";
      promptAction.showToast({ message : message })
      return message
    }
    // build service
    // 调这个本地函数 buildGattService();
    let curServiceUUID: string = AppStorage.get("curServiceUUID") !
    let curCharacteristicUUID: string = AppStorage.get("curCharacteristicUUID") !
    let curDescriptorUUID: string = AppStorage.get("curDescriptorUUID") !
    let curDescriptorValue: string = AppStorage.get("curDescriptorValue") !
    let curCharacteristicValue: string = AppStorage.get("curCharacteristicValue") !
    let isPrimary: boolean = AppStorage.get("isPrimary") !
    let descriptors : Array<bluetooth.BLEDescriptor>= [];
    let descriptor: Descriptor = {
      serviceUuid : curServiceUUID ,
      characteristicUuid : curCharacteristicUUID ,
      descriptorUuid : curDescriptorUUID ,
      descriptorValue : string2ArrayBuffer(curDescriptorValue)
    };
    descriptors.push(descriptor);

    // build characteristics
    let characteristics : Array<bluetooth.BLECharacteristic>= [];
    let characteristic: Characteristic = {
      serviceUuid : curServiceUUID ,
      characteristicUuid : curCharacteristicUUID ,
      characteristicValue : string2ArrayBuffer(curCharacteristicValue) ,
      descriptors : descriptors
    };
    characteristics.push(characteristic);
    let curGattService: bluetooth.GattService = {
      serviceUuid : curServiceUUID ,
      isPrimary : isPrimary ,
      characteristics : characteristics ,
      includeServices : []
    }
    console.log("gattServerInstance.addService start -----------")
    let ret: boolean = gattServerInstance!.addService(curGattService);
    message = "result: addService," + ret;
    console.log("服务的参数为：" + JSON.stringify(curGattService))
    console.log("gattServerInstance.addService succeeds!-----------" + message)
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testAddService. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testAddService. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testRemoveService(): string {
  try {
    let message = "removeService test"
    let curServiceUUID: string = AppStorage.get("curServiceUUID") !
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( !gattServerInstance ) {
        message = "NO_GATT_Server_OBJECT";
        promptAction.showToast({ message : message })
        return message
      }
      message = "result: removeService ";
      if ( gattServerInstance!.removeService(curServiceUUID) ) {
        message += 'true';
      } else {
        message += 'false';
      }
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testRemoveService. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveService. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

let curAdvData: bluetooth.AdvertiseData = {
  serviceUuids : [
    "00003344-0000-1000-8000-00805f9b34fb",
    "00008899-0000-1000-8000-00805f9b34fb"
  ] ,
  manufactureData : [ {
    manufactureId : 7456 ,
    manufactureValue : string2ArrayBuffer("OHOS CHN")
  } ] ,
  serviceData : [ {
    serviceUuid : "000054F6-0000-1000-8000-00805f9b34fb" ,
    serviceValue : string2ArrayBuffer("OhosBle!")
  }, {
    serviceUuid : "00009999-0000-1000-8000-00805f9b34fb" ,
    serviceValue : string2ArrayBuffer("dudu_tiger")
  } ]
};

let curAdvResponse: bluetooth.AdvertiseData = {
  serviceUuids : [
  //"000054F6-0000-1000-8000-00805f9b34fb",
    "00009999-0000-1000-8000-00805f9b34fb"
  ] ,
  manufactureData : [ {
    manufactureId : 6547 ,
    manufactureValue : string2ArrayBuffer("OHOS CHN")
  } ] ,
  serviceData : [ {
    serviceUuid : "000054F6-0000-1000-8000-00805f9b34fb" ,
    serviceValue : string2ArrayBuffer("OhosBle!")
  }, {
    serviceUuid : "00007456-0000-1000-8000-00805f9b34fb" ,
    serviceValue : string2ArrayBuffer("OhosBle")
  } ]
};

export function testStartAdvertising(): string {
  try {
    let message = "startAdvertising test"
    let btState = bluetooth.getState();
    if ( btState === bluetooth.BluetoothState.STATE_ON || btState === bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( !gattServerInstance ) {
        message = "NO_GATT_Server_OBJECT";
        promptAction.showToast({ message : message })
        return message
      }
      message = "startAdvertising:build input parameter In!";
      // 调三个本地函数
      // buildAdvSettings();
      let cbxAdvSettings: boolean = AppStorage.get("cbxAdvSettings") !
      let cbxInterval: boolean = AppStorage.get("cbxInterval") !
      let cbxTxPower: boolean = AppStorage.get("cbxTxPower") !
      let curAdvSettings: CurAdvSettings = {
        interval : 800 , //500ms
        txPower : - 7 ,
        connectable : true
      }
      if ( cbxAdvSettings ) {
        if ( cbxInterval ) {
          let advSettings_interval: string = AppStorage.get("advSettings_interval") !
          curAdvSettings.interval = parseInt(advSettings_interval)
        }
        if ( cbxTxPower ) {
          let advSettings_txPower: string = AppStorage.get("advSettings_txPower") !
          curAdvSettings.txPower = parseInt(advSettings_txPower)
        }
        let advSettings_connectable: boolean = AppStorage.get("advSettings_connectable") !
        curAdvSettings.connectable = advSettings_connectable
      }

      //    buildAdvData();
      let advDataServiceUuids_serviceUuid: string = AppStorage.get("advDataServiceUuids_serviceUuid") !
      let advDataManufactureData_manufactureId: string = AppStorage.get("advDataManufactureData_manufactureId") !
      let advDataManufactureData_manufactureValue: string = AppStorage.get("advDataManufactureData_manufactureValue") !
      let advDataServiceData_serviceUuid: string = AppStorage.get("advDataServiceData_serviceUuid") !
      let advDataServiceData_serviceValue: string = AppStorage.get("advDataServiceData_serviceValue") !
      let advDataServiceUuidList :Array<string> = []
      let advDataManufactureDataList : Array<bluetooth.ManufactureData>= []
      let advDataServiceDataList : Array<bluetooth.ServiceData>= []
      let advDataManufactureDataInstance: AdvDataManufactureDataInstance = {
        manufactureId : parseInt(advDataManufactureData_manufactureId) ,
        manufactureValue : string2ArrayBuffer(advDataManufactureData_manufactureValue)
      }
      let advDataServiceDataInstance: AdvDataServiceDataInstance = {
        serviceUuid : advDataServiceData_serviceUuid ,
        serviceValue : string2ArrayBuffer(advDataServiceData_serviceValue)
      }

      advDataServiceUuidList.push(advDataServiceUuids_serviceUuid)
      advDataManufactureDataList.push(advDataManufactureDataInstance)
      advDataServiceDataList.push(advDataServiceDataInstance)

      let curAdvData: CurAdvData = {
        serviceUuids : advDataServiceUuidList ,
        manufactureData : advDataManufactureDataList ,
        serviceData : advDataServiceDataList
      }

      //    buildAdvResponse();
      let advResponseServiceUuids_serviceUuid: string = AppStorage.get("advResponseServiceUuids_serviceUuid") !
      let advResponseManufactureData_manufactureId: string = AppStorage.get("advResponseManufactureData_manufactureId") !
      let advResponseManufactureData_manufactureValue: string = AppStorage.get("advResponseManufactureData_manufactureValue") !
      let advResponseServiceData_serviceUuid: string = AppStorage.get("advResponseServiceData_serviceUuid") !
      let advResponseServiceData_serviceValue: string = AppStorage.get("advResponseServiceData_serviceValue") !
      let advResponseServiceUuidList: Array<string> = []
      let advResponseManufactureDataList: Array<bluetooth.ManufactureData> = []
      let advResponseServiceDataList : Array<bluetooth.ServiceData>= []
      let advResponseManufactureDataInstance: AdvResponseManufactureDataInstance = {
        manufactureId : parseInt(advResponseManufactureData_manufactureId) ,
        manufactureValue : string2ArrayBuffer(advResponseManufactureData_manufactureValue)
      }
      let advResponseServiceDataInstance: AdvResponseServiceDataInstance = {
        serviceUuid : advResponseServiceData_serviceUuid ,
        serviceValue : string2ArrayBuffer(advResponseServiceData_serviceValue)
      }

      advResponseServiceUuidList.push(advResponseServiceUuids_serviceUuid)
      advResponseManufactureDataList.push(advResponseManufactureDataInstance)
      advResponseServiceDataList.push(advResponseServiceDataInstance)

      let curAdvResponse: CurAdvResponse = {
        serviceUuids : advResponseServiceUuidList ,
        manufactureData : advResponseManufactureDataList ,
        serviceData : advResponseServiceDataList
      }

      let setting = curAdvSettings;
      let advData = curAdvData;
      let advResponse = curAdvResponse;
      let cbxAdvResponse: boolean = AppStorage.get("cbxAdvResponse") !
      message = "startAdvertising:build input parameter Out!";

      if ( !cbxAdvResponse ) {
        console.log("advData.serviceUuids:" + advData.serviceUuids + "\n")
        console.log("advData.manufactureData:" + advData.manufactureData + (typeof advData.manufactureData) + "\n")
        console.log("advData.serviceData:" + advData.serviceData + "\n")
        gattServerInstance!.startAdvertising(setting , advData);
        console.log("startAdvertising(setting,advData)-----------")
      } else {
        console.log("advResponse.serviceUuids:" + advResponse.serviceUuids + "\n")
        console.log("advResponse.manufactureData:" + advResponse.manufactureData + "\n")
        console.log("advResponse.serviceData:" + advResponse.serviceData + "\n")
        gattServerInstance!.startAdvertising(setting , advData , advResponse);
        console.log("startAdvertising(setting,advData,advResponse)-----------")
      }
      console.log("cbxAdvSettings:" + cbxAdvSettings + "\n")
      console.log("cbxAdvResponse:" + cbxAdvResponse + "\n")
      message = "startAdvertising succeeds!" + cbxAdvSettings + "," + cbxAdvResponse;
    } else if ( btState === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testStartAdvertising. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testStartAdvertising. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testStopAdvertising(): String {
  try {
    let message = "stopAdvertising test"
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( !gattServerInstance ) {
        message = "NO_GATT_Server_OBJECT";
        promptAction.showToast({ message : message })
        return message
      }
      gattServerInstance!.stopAdvertising();
      message = "stopAdvertising succeeds.";
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testStopAdvertising. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testStopAdvertising. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testGattServerClose(): String {
  try {
    let message = "gattServerClose test"
    let btState = bluetooth.getState();
    if ( btState == bluetooth.BluetoothState.STATE_ON || btState == bluetooth.BluetoothState.STATE_BLE_ON ) {
      if ( !gattServerInstance ) {
        message = "NO_GATT_Server_OBJECT";
        promptAction.showToast({ message : message })
        return message
      }
      gattServerInstance!.close();
      message = "GattServer closed: succeeds";
    } else if ( btState == bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
    } else {
      message = "switching,please wait!";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testGattServerClose. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGattServerClose. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//回调函数
let connectStateChange = false

export function testOnConnectStateChange(): String {
  try {
    let message = "onConnectStateChange test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message
    }
    if ( connectStateChange ) {
      gattServerInstance!.off("connectStateChange" , () => {
      })
      message = "关闭连接状态变化 "
      promptAction.showToast({ message : message })
      return message
    } else {
      gattServerInstance!.on('connectStateChange' , (data: bluetooth.BLEConnectChangedState) => {
        let connectStateMsg = "deviceId:" + data.deviceId + ",connectState:" + data.state;
        let connect_StateMsg = ""
        if ( data.state == 0 ) {
          connect_StateMsg = "STATE_DISCONNECTED"
        } else if ( data.state == 1 ) {
          connect_StateMsg = "STATE_CONNECTING"
        } else if ( data.state == 2 ) {
          connect_StateMsg = "STATE_CONNECTED"
        } else {
          connect_StateMsg = "STATE_DISCONNECTING"
        }
        AppStorage.setOrCreate("connect_StateMsg" , connect_StateMsg)
        console.log("connectStateChange:" + JSON.stringify(data))
        promptAction.showToast({ message : connectStateMsg })
      })
      message = '打开连接状态变化'
    }
    connectStateChange = !connectStateChange
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testOnConnectStateChange. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnConnectStateChange. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//回调函数
let characteristicRead = false

export function testOnCharacteristicRead(): String {
  try {
    let message = "onCharacteristicRead test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message
    }
    if ( characteristicRead ) {
      gattServerInstance!.off("characteristicRead" , () => {
      })
      message = "特征值读取 关闭"
      promptAction.showToast({ message : message })
      return message
    } else {
      gattServerInstance.on('characteristicRead' , (characteristicReadReq: bluetooth.CharacteristicReadReq) => {

        let characteristicReadMsg = 'characteristicRead received!';
        // client address
        let clientDeviceId: string = characteristicReadReq.deviceId;
        // transId
        let transId: number = characteristicReadReq.transId;
        // the byte offset of the start position for reading characteristic value
        let offset: number = characteristicReadReq.offset;
        // service/characteristic Uuid
        let characteristicUuid: string = characteristicReadReq.characteristicUuid;
        let serviceUuid: string = characteristicReadReq.serviceUuid;

        characteristicReadMsg += 'characteristicRead input parameters: deviceId = ' + clientDeviceId + '\n';
        characteristicReadMsg += 'transId = ' + transId + '\n';
        characteristicReadMsg += "characteristicUuid = " + characteristicUuid + '\n';
        characteristicReadMsg += "serviceUuid = " + serviceUuid + '\n';
        AppStorage.setOrCreate("characteristicReadMsg" , characteristicReadMsg) // build data for response
        let arrayBufferCCC = string2ArrayBuffer('DaYuBlue');

        let serverResponse: ServerResponse = {
          deviceId : clientDeviceId ,
          transId : transId ,
          status : 0 ,
          offset : offset ,
          value : arrayBufferCCC
        }

        let ret: boolean = gattServerInstance!.sendResponse(serverResponse)
        message = 'characteristicRead sendResponse:' + ret
        promptAction.showToast({ message : message })
      })
      message = '特征值读取 打开'
    }
    characteristicRead = !characteristicRead
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testOnCharacteristicRead. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnCharacteristicRead. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//回调函数
let characteristicWrite = false

export function testOnCharacteristicWrite(): String {
  try {
    let message = "onCharacteristicWrite test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message
    }
    if ( characteristicWrite ) {
      gattServerInstance!.off("characteristicWrite" , () => {
      });
      message = "特征值写入 关闭"
      promptAction.showToast({ message : message })
      return message
    } else {
      gattServerInstance!.on('characteristicWrite' , (characteristicWriteReq: bluetooth.CharacteristicWriteReq) => {
        let btOnCharacteristicWrite = 'on characteristicWrite'
        let characteristicWriteMsg = '';

        let arrayBufferCCC = string2ArrayBuffer("characteristicWriteForResponse");

        // client address
        let deviceId: string = characteristicWriteReq.deviceId;
        let transId: number = characteristicWriteReq.transId;
        let offset: number = characteristicWriteReq.offset;
        /** Whether this request should be pending for later operation */
        let isPrep: boolean = characteristicWriteReq.isPrep;
        /** Whether the remote client need a response */
        let needRsp: boolean = characteristicWriteReq.needRsp;
        /** Indicates the value to be written */
        let value = new Uint8Array(characteristicWriteReq.value);
        let characteristicUuid: string = characteristicWriteReq.characteristicUuid;
        let serviceUuid: string = characteristicWriteReq.serviceUuid;


        characteristicWriteMsg += "The characteristicWriteReq input parameters: deviceId =" + deviceId;
        characteristicWriteMsg += "transId =" + transId;
        characteristicWriteMsg += "offset =" + offset;
        characteristicWriteMsg += "isPrep =" + isPrep;
        characteristicWriteMsg += "needRsp =" + needRsp;
        characteristicWriteMsg += "value =" + JSON.stringify(value);
        characteristicWriteMsg += "characteristicUuid =" + characteristicUuid;
        characteristicWriteMsg += "serviceUuid =" + serviceUuid;
        AppStorage.setOrCreate("characteristicWriteMsg" , characteristicWriteMsg)
        let serverResponse: ServerResponse = {
          deviceId : deviceId ,
          transId : transId ,
          status : 0 ,
          offset : offset ,
          value : arrayBufferCCC
        };
        // sendResponse
        if ( needRsp ) {
          let ret: boolean = gattServerInstance!.sendResponse(serverResponse);
          message = 'characteristicWrite sendResponse:' + ret;
          promptAction.showToast({ message : message })
        }
        let notifyCharacteristic_notifyCharacteristic: NotifyCharacteristic = {
          serviceUuid : serviceUuid ,
          characteristicUuid : characteristicUuid ,
          characteristicValue : string2ArrayBuffer("Value4notifyCharacteristic") ,
          confirm : true //notification:true; indication:false;
        }
        let notifyCharacteristic = notifyCharacteristic_notifyCharacteristic;
        if ( gattServerInstance!.notifyCharacteristicChanged(deviceId , notifyCharacteristic) ) {
          message = "notifyCharacteristicChanged successfully!";
        } else {
          message = "notifyCharacteristicChanged failed!";
        }
      })
      message = '特征值写入 打开';
    }
    characteristicWrite = !characteristicWrite
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testOnCharacteristicWrite. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnCharacteristicWrite. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//回调函数
let descriptorRead = false

export function testOnDescriptorRead(): String {
  try {
    let message = "onDescriptorRead test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      return message;
    }
    if ( descriptorRead ) {
      gattServerInstance!.off("descriptorRead" , () => {
      });
      message = '描述符读取 关闭';
      promptAction.showToast({ message : message })
      return message
    } else {
      gattServerInstance!.on('descriptorRead' , (descriptorReadReq: bluetooth.DescriptorReadReq) => {
        let btOnDescriptorRead = 'on:descriptorRead'
        let descriptorReadMsg = "descriptorReadIn!!";
        let deviceId: string = descriptorReadReq.deviceId;
        let transId: number = descriptorReadReq.transId;
        /** Indicates the byte offset of the start position for reading characteristic value */
        let offset: number = descriptorReadReq.offset;
        let descriptorUuid: string = descriptorReadReq.descriptorUuid;
        let characteristicUuid: string = descriptorReadReq.characteristicUuid;
        let serviceUuid: string = descriptorReadReq.serviceUuid;
        let arrayBufferDesc = string2ArrayBuffer("Response4descriptorRead");
        let serverResponse: ServerResponse = {
          deviceId : deviceId ,
          transId : transId ,
          status : 0 ,
          offset : offset ,
          value : arrayBufferDesc
        }
        let ret: boolean = gattServerInstance!.sendResponse(serverResponse);
        message = 'descriptorRead sendResponse:' + ret;
        descriptorReadMsg += message
        AppStorage.setOrCreate("descriptorReadMsg" , descriptorReadMsg)
        promptAction.showToast({ message : message })
      })
      message = '描述符读取 打开';
    }
    descriptorRead = !descriptorRead
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testOnDescriptorRead. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnDescriptorRead. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

//回调函数
let descriptorWrite = false

export function testOnDescriptorWrite(): String {
  try {
    let message = "onDescriptorWrite test"
    let btStatus = bluetooth.getState();
    if ( btStatus === bluetooth.BluetoothState.STATE_OFF ) {
      message = "BT is not enabled!";
      promptAction.showToast({ message : message })
      return message
    }
    if ( descriptorWrite ) {
      gattServerInstance!.off("descriptorWrite" , () => {
      });
      message = '描述符写入 关闭';
      promptAction.showToast({ message : message })
      return message
    } else {
      gattServerInstance!.on('descriptorWrite' , (descriptorWriteReq: bluetooth.DescriptorWriteReq) => {
        let btOnDescriptorWrite = 'on:descriptorWrite'
        let descriptorWriteMsg = "descriptorWriteIn";
        descriptorWriteMsg += "The descriptorWriteReq client address: deviceId is " + descriptorWriteReq.deviceId;
        let deviceId: string = descriptorWriteReq.deviceId;
        let transId: number = descriptorWriteReq.transId;
        /** Indicates the byte offset of the start position for writing descriptor value */
        let offset: number = descriptorWriteReq.offset;
        /** Whether this request should be pending for later operation */
        let isPrep: boolean = descriptorWriteReq.isPrep;
        /** Whether the remote client need a response */
        let needRsp: boolean = descriptorWriteReq.needRsp;
        /** Indicates the value to be written */
        let value = new Uint8Array(descriptorWriteReq.value);
        let descriptorUuid: string = descriptorWriteReq.descriptorUuid;
        let characteristicUuid: string = descriptorWriteReq.characteristicUuid;
        let serviceUuid: string = descriptorWriteReq.serviceUuid;

        let arrayBufferDesc = new ArrayBuffer(8);
        let descValue = new Uint8Array(arrayBufferDesc);
        descValue[ 0 ] = value[ 0 ];
        let serverResponse: ServerResponse = {
          deviceId : deviceId ,
          transId : transId ,
          status : 0 ,
          offset : offset ,
          value : arrayBufferDesc
        };

        if ( needRsp ) {
          let ret: boolean = gattServerInstance!.sendResponse(serverResponse);
          message = 'descriptorWrite sendResponse:' + ret;
          promptAction.showToast({ message : message })
        }
        descriptorWriteMsg += 'descriptorWrite Callback finished!';
      })
      message = '描述符写入 打开';
    }
    descriptorWrite = !descriptorWrite
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testOnDescriptorWrite. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnDescriptorWrite. message: ${ e.message }, code: ${ e.code }`
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