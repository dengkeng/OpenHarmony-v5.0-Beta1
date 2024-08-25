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

import bluetoothManager from '@ohos.bluetoothManager';
import promptAction from '@ohos.promptAction';

let clientNumber = - 1

export function testSppClientConnectSafeManager(): string {
  try {
    let message = "sppClientConnectSafe test"
    console.log('testSppClientConnectSafe create! ');
    let uuid: string = AppStorage.get('inputUuid') !
    let deviceId: string = AppStorage.get('inputDeviceId') !
    console.log('bluetoothManager sppConnect: ' + deviceId);
    bluetoothManager.sppConnect(deviceId , {
      uuid : uuid ,
      secure : true ,
      type : 0
    } , (code , socketID) => {
      console.log("spp client code:" + JSON.stringify(code))
      if ( code.code != 0  ) {
        message = "客户端连接失败!";
        console.log('bluetoothManager sppConnect callback socketNumber(safe mode): ' + JSON.stringify(code));
        promptAction.showToast({ message : message })
        return message;
      }
      acceptClientSocketManager(socketID);
      console.log('bluetoothManager sppConnect callback socketNumber(safe mode): ' + socketID);
      message = "客户端连接成功!";
      AppStorage.setOrCreate("clientNumber" , clientNumber)
      promptAction.showToast({ message : message })
      return message
    })
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientConnectSafeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientConnectSafeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientConnectUnSafeManager(): string {
  try {
    let message = "sppClientConnectUnSafe test"
    console.log('testSppClientConnectUnSafe create! ');
    let uuid: string = AppStorage.get('inputUuid') !
    let deviceId: string = AppStorage.get('inputDeviceId') !
    console.log('bluetoothManager sppConnect: ' + deviceId);
    bluetoothManager.sppConnect(deviceId , {
      uuid : uuid ,
      secure : false ,
      type : 0
    } , (code , socketID) => {
      if ( code ) {
        message = "客户端连接失败!";
        console.log('bluetoothManager sppConnect callback socketNumber(non-safe mode): ' + socketID);
        promptAction.showToast({ message : message })
        return message;
      }
      acceptClientSocketManager(socketID);
      console.log('bluetoothManager sppConnect callback socketNumber(non-safe mode): ' + socketID);
      message = "客户端连接成功!";
      promptAction.showToast({ message : message })
      return message
    });
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientConnectUnSafeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientConnectUnSafeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientWriteManager(): string {
  try {
    let message = "sppClientWrite test"
    console.log('bluetoothManager sppWrite clientNumber1: ' + JSON.stringify(clientNumber));
    let writeClientData: string = AppStorage.get("writeClientData") !
    let writeArrayBuffer: ArrayBuffer = strToArrayBuffer(writeClientData) as ArrayBuffer;
    bluetoothManager.sppWrite(clientNumber , writeArrayBuffer);
    AppStorage.setOrCreate("clientNumber" , clientNumber)
    console.log('sppWrite successfully');
    message = "写入成功 ";
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientWriteManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientWriteManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientReadOnManager(): string {
  try {
    let message = "sppClientReadOn test"
    bluetoothManager.on('sppRead' , clientNumber , (dataBuffer: ArrayBuffer) => {
      const data = new Uint8Array(dataBuffer);
      console.log('spp bluetoothManager read is: ' + data);
      if ( data != null ) {
        message = "读取成功" + JSON.stringify(data);
      } else {
        message = "读取失败";
      }
      AppStorage.setOrCreate("dataReadMessage" , message)
      promptAction.showToast({ message : message })
      return message
    });
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientReadOnManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientReadOnManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientReadOffManager(): string {
  try {
    let message = "sppClientReadOff test"
    bluetoothManager.off('sppRead' , clientNumber , (dataBuffer: ArrayBuffer) => {
      const data = new Uint8Array(dataBuffer);
      console.log('spp bluetoothManager read is: ' + data);
      if ( data != null ) {
        message = "读取成功" + JSON.stringify(data);
      } else {
        message = "读取失败";
      }
      AppStorage.setOrCreate("dataReadMessage" , message)
      promptAction.showToast({ message : message })
      return message
    });
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientReadOffManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientReadOffManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientCloseManager(): string {
  try {
    let message = "sppClientClose test"
    sppClientCloseManager()
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientCloseManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientCloseManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function acceptClientSocketManager(number: number) {
  console.log('spp clientSocket socketID: ' + number);
  // 获取的clientNumber用作服务端后续读/写操作socket的id。
  clientNumber = number;
  AppStorage.setOrCreate("clientNumber" , clientNumber)
}

export function sppClientCloseManager() {
  try {
    console.log('bluetoothModel sppCloseClientSocket clientNumber: ' + JSON.stringify(clientNumber))
    bluetoothManager.sppCloseClientSocket(clientNumber);
    let message = '关闭成功 clientNumber' + clientNumber;
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to sppClientCloseManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to sppClientCloseManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function strToArrayBuffer(str: string) {
  let array = new Uint8Array(str.length);
  for ( let i = 0 ; i < str.length ; i ++ ) {
    array[ i ] = str.charCodeAt(i);
  }
  return array.buffer
}

export function dataRead(dataBuffer: ArrayBuffer) {
  let dataReadMessage = ''
  const data = new Uint8Array(dataBuffer);
  console.log('spp bluetoothManager read is: ' + data);
  if ( data != null ) {
    dataReadMessage = "读取成功" + JSON.stringify(data);
  } else {
    dataReadMessage = "读取失败";
  }
}