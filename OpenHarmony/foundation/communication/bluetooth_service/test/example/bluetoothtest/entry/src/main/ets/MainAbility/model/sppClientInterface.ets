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

import bluetooth from '@ohos.bluetooth';
import promptAction from '@ohos.promptAction';

let clientNumber = - 1

export function testSppClientConnectSafe(): string {
  try {
    let message = "sppClientConnectSafe test"
    console.log('testSppClientConnectSafe create! ');
    let uuid: string = AppStorage.get('inputUuid') !
    let deviceId: string = AppStorage.get('inputDeviceId') !
    console.log('bluetoothModel sppConnect: ' + deviceId);
    bluetooth.sppConnect(deviceId , {
      uuid : uuid ,
      secure : true ,
      type : 0
    } , (code , socketID) => {
      console.log("spp client code:" + JSON.stringify(code))
      if ( code.code != 0 ) {
        message = "客户端连接失败!";
        console.log('bluetoothModel sppConnect callback socketNumber(safe mode): ' + JSON.stringify(code));
        promptAction.showToast({ message : message })
        return message;
      }
      acceptClientSocket(socketID);
      console.log('bluetoothModel sppConnect callback socketNumber(safe mode): ' + socketID);
      message = "客户端连接成功!";
      AppStorage.setOrCreate("clientNumber" , clientNumber)
      promptAction.showToast({ message : message })
      return message
    })
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientConnectSafe. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientConnectSafe. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientConnectUnSafe(): string {
  try {
    let message = "sppClientConnectUnSafe test"
    console.log('testSppClientConnectUnSafe create! ');
    let uuid: string = AppStorage.get('inputUuid') !
    let deviceId: string = AppStorage.get('inputDeviceId') !
    console.log('bluetoothModel sppConnect: ' + deviceId);
    bluetooth.sppConnect(deviceId , {
      uuid : uuid ,
      secure : false ,
      type : 0
    } , (code , socketID) => {
      console.log("spp client unsafe code:" + JSON.stringify(code))
      if ( code.code != 0 ) {
        message = "客户端连接失败!";
        console.log('bluetoothModel sppConnect callback socketNumber(non-safe mode): ' + socketID);
        promptAction.showToast({ message : message })
        return message;
      }
      acceptClientSocket(socketID);
      console.log('bluetoothModel sppConnect callback socketNumber(non-safe mode): ' + socketID);
      message = "客户端连接成功!";
      promptAction.showToast({ message : message })
      return message
    });
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientConnectUnSafe. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientConnectUnSafe. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientWrite(): string {
  try {
    let message = "sppClientWrite test"
    console.log('bluetoothModel sppWrite clientNumber1: ' + JSON.stringify(clientNumber));
    let writeClientData: string = AppStorage.get("writeClientData") !
    let writeArrayBuffer: ArrayBuffer = strToArrayBuffer(writeClientData) as ArrayBuffer;
    const sppWriteSuccess = bluetooth.sppWrite(clientNumber , writeArrayBuffer);
    AppStorage.setOrCreate("clientNumber" , clientNumber)
    if ( sppWriteSuccess ) {
      console.log('sppWrite successfully');
      message = "写入成功 ";
    } else {
      console.log('sppWrite failed');
      message = "写入失败";
    }
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientWrite. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientWrite. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientReadOn(): string {
  try {
    let message = "sppClientReadOn test"
    bluetooth.on('sppRead' , clientNumber , (dataBuffer: ArrayBuffer) => {
      const data = new Uint8Array(dataBuffer);
      console.log('spp bluetooth read is: ' + data);
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
    console.log(`Failed to testSppClientReadOn. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientReadOn. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientReadOff(): string {
  try {
    let message = "sppClientReadOff test"
    bluetooth.off('sppRead' , clientNumber , (dataBuffer: ArrayBuffer) => {
      const data = new Uint8Array(dataBuffer);
      console.log('spp bluetooth read is: ' + data);
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
    console.log(`Failed to testSppClientReadOff. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientReadOff. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function testSppClientClose(): string {
  try {
    let message = "sppClientClose test"
    sppClientClose()
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to testSppClientClose. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testSppClientClose. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message : message })
    return message
  }
}

export function acceptClientSocket(number: number) {
  console.log('spp clientSocket socketID: ' + number);
  // 获取的clientNumber用作服务端后续读/写操作socket的id。
  clientNumber = number;
  AppStorage.setOrCreate("clientNumber" , clientNumber)
}

export function sppClientClose() {
  try {
    console.log('bluetoothModel sppCloseClientSocket clientNumber: ' + JSON.stringify(clientNumber))
    bluetooth.sppCloseClientSocket(clientNumber);
    let message = '关闭成功 clientNumber' + clientNumber;
    promptAction.showToast({ message : message })
    return message
  } catch( e ) {
    console.log(`Failed to sppClientClose. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to sppClientClose. message: ${ e.message }, code: ${ e.code }`
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
  let dataReadMessage: string = ''
  const data = new Uint8Array(dataBuffer);
  console.log('spp bluetooth read is: ' + data);
  if ( data != null ) {
    dataReadMessage = "读取成功" + JSON.stringify(data);
  } else {
    dataReadMessage = "读取失败";
  }
}